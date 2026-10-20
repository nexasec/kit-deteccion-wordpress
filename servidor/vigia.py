#!/usr/bin/env python3
"""Vigia: comprueba lo que el watchdog no ve y lo empuja a n8n.

Dos chequeos, cada uno con su propio cron:

  --origen   El origen sigue cerrado: pedir directo a la IP del hosting debe dar
             403 y pedir por Cloudflare debe dar 200. Si alguien restaura un
             .htaccess viejo, borra la Transform Rule o pausa Cloudflare, se nota.

  --plugins  Inventario de core, plugins y temas cruzado con el feed de
             Wordfence Intelligence. Cuando las versiones ya no se ven desde
             fuera, este es el unico lugar donde se comparan contra CVEs.
             Opcionalmente incluye la fecha de vencimiento de un dominio .cl
             en NIC Chile.

Push, como el watchdog y el escalador: n8n nunca entra al servidor. n8n decide
cuando avisar (cambios de estado, recordatorios) y alerta si este script deja
de reportar.

Configuracion (config.json, ver nxconfig): dominio, origen_ip, raiz_web, wp_cli,
wordfence_api_key, webhook_vigia, headers, whois_nic_chile, dir_estado.

Uso:
  vigia.py --origen [--simular] [--prueba]
  vigia.py --plugins [--simular] [--prueba]
"""

import argparse
import datetime
import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request

import nxconfig

# Sin User-Agent explicito, el Browser Integrity Check de Cloudflare responde 1010.
AGENTE = "NexaSec-Vigia/1.0 (+https://nexasec.cl)"

FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner"
FEED_MAX_EDAD_H = 20


def ahora():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- origen

def pedir_directo(ip, dominio, ruta):
    # --resolve manda el SNI correcto. En algunos hosting compartidos pedir a la
    # IP a secas da 421, y por HTTP redirige a HTTPS antes de llegar al
    # .htaccess: ninguno de los dos prueba nada.
    cmd = ["curl", "-sk", "--max-time", "15", "-A", AGENTE,
           "--resolve", "%s:443:%s" % (dominio, ip),
           "-o", "-", "-w", "\n%{http_code}", "https://%s%s" % (dominio, ruta)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=25).stdout
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc)
    cuerpo, _, codigo = out.rpartition("\n")
    return int(codigo or 0), cuerpo[:60]


def pedir_cloudflare(dominio):
    req = urllib.request.Request("https://%s/" % dominio, headers={"User-Agent": AGENTE})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.headers.get("Server", ""), "<html" in r.read(4000).decode(errors="replace").lower()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Server", ""), False
    except Exception:  # noqa: BLE001
        return 0, "", False


def chequeo_origen(cfg, prueba=False):
    dominio = (cfg.get("dominio") or "").strip()
    ip = (cfg.get("origen_ip") or "").strip()
    resultado = {"tipo": "origen", "host": dominio or "-", "ts": ahora(), "prueba": prueba,
                 "directo": {}, "cloudflare": {}}

    # Sin valores por defecto a proposito: probar contra una IP equivocada da un
    # "todo bien" falso, que es peor que un error.
    faltan = nxconfig.requerir(cfg, "dominio", "origen_ip")
    if faltan:
        resultado.update(ok=False, fallos=["falta %s en config.json" % c for c in faltan])
        return resultado

    fallos = []
    for ruta in ("/", "/wp-login.php"):
        codigo, cuerpo = pedir_directo(ip, dominio, ruta)
        resultado["directo"][ruta] = codigo
        # "Forbidden" a secas es nuestro ErrorDocument: distingue el bloqueo propio de
        # un 403 de otro origen (p. ej. si el hosting cambia la IP del sitio).
        if codigo != 403 or cuerpo.strip() != "Forbidden":
            fallos.append("directo %s respondio %s (se esperaba 403 Forbidden)" % (ruta, codigo or "sin respuesta"))
    cf_codigo, cf_server, cf_html = pedir_cloudflare(dominio)
    resultado["cloudflare"] = {"codigo": cf_codigo, "server": cf_server}
    if cf_codigo != 200 or "cloudflare" not in cf_server.lower() or not cf_html:
        fallos.append("por Cloudflare respondio %s, Server=%s" % (cf_codigo or "sin respuesta", cf_server or "?"))
    if prueba:
        fallos.append("PRUEBA: fallo sintetico, ignorar")
    resultado.update(ok=not fallos, fallos=fallos)
    return resultado


# --------------------------------------------------------------------------- plugins

# Port de version_compare() de PHP: es como compara WordPress y como publica
# Wordfence los rangos. Un orden lexicografico diria que 4.10 < 4.9.
_ESPECIALES = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "RC": 3, "rc": 3, "#": 4, "pl": 5, "p": 5}


def _canon(v):
    v = re.sub(r"[-_+]", ".", str(v).strip())
    v = re.sub(r"(?<=\d)(?=[^\d.])|(?<=[^\d.])(?=\d)", ".", v)
    return [p for p in v.split(".") if p]


def _cmp_parte(a, b):
    if a.isdigit() and b.isdigit():
        return (int(a) > int(b)) - (int(a) < int(b))
    ra = _ESPECIALES["#"] if a.isdigit() else _ESPECIALES.get(a, -1)
    rb = _ESPECIALES["#"] if b.isdigit() else _ESPECIALES.get(b, -1)
    return (ra > rb) - (ra < rb)


def vcmp(a, b):
    pa, pb = _canon(a), _canon(b)
    for i in range(max(len(pa), len(pb))):
        if i >= len(pa):
            return -1 if pb[i].isdigit() else _cmp_parte("#", pb[i])
        if i >= len(pb):
            return 1 if pa[i].isdigit() else _cmp_parte(pa[i], "#")
        c = _cmp_parte(pa[i], pb[i])
        if c:
            return c
    return 0


def en_rango(version, r):
    desde, hasta = str(r.get("from_version", "*")), str(r.get("to_version", "*"))
    if desde not in ("*", ""):
        c = vcmp(version, desde)
        if c < 0 or (c == 0 and not r.get("from_inclusive", True)):
            return False
    if hasta not in ("*", ""):
        c = vcmp(version, hasta)
        if c > 0 or (c == 0 and not r.get("to_inclusive", True)):
            return False
    return True


def wp_json(cfg, *args):
    raiz = os.path.expanduser(cfg.get("raiz_web") or "")
    out = subprocess.run([cfg.get("wp_cli") or "wp", *args, "--skip-plugins", "--skip-themes", "--path=" + raiz],
                         capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError("wp %s: %s" % (" ".join(args), out.stderr.strip()[:200]))
    return out.stdout


def inventario(cfg):
    if nxconfig.requerir(cfg, "raiz_web"):
        raise RuntimeError("falta raiz_web en config.json")
    plugins = [p for p in json.loads(wp_json(cfg, "plugin", "list", "--fields=name,status,version,update_version", "--format=json"))
               if p.get("status") in ("active", "inactive") and p.get("version")]
    temas = [t for t in json.loads(wp_json(cfg, "theme", "list", "--fields=name,status,version,update_version", "--format=json"))
             if t.get("version")]
    core = wp_json(cfg, "core", "version").strip()
    return core, plugins, temas


def descargar_feed(feed, clave):
    fresco = os.path.exists(feed) and time.time() - os.path.getmtime(feed) < FEED_MAX_EDAD_H * 3600
    if fresco:
        return None
    req = urllib.request.Request(FEED_URL, headers={"User-Agent": AGENTE, "Authorization": "Bearer " + clave})
    tmp = feed + ".tmp"
    try:
        with urllib.request.urlopen(req, timeout=180) as r, open(tmp, "wb") as fh:
            while True:
                bloque = r.read(1 << 20)
                if not bloque:
                    break
                fh.write(bloque)
        os.chmod(tmp, 0o600)
        os.replace(tmp, feed)
    except urllib.error.HTTPError as exc:
        return "feed de Wordfence respondio HTTP %d: %s" % (exc.code, exc.read(160).decode(errors="replace"))
    except Exception as exc:  # noqa: BLE001
        return "no se pudo descargar el feed de Wordfence: %s" % exc
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return None


def cruzar(feed, core, plugins, temas):
    with open(feed, encoding="utf-8") as fh:
        datos = json.load(fh)
    registros = datos.values() if isinstance(datos, dict) else datos

    instalado = {("core", "wordpress"): core}
    instalado.update({("plugin", p["name"]): p["version"] for p in plugins})
    instalado.update({("theme", t["name"]): t["version"] for t in temas})
    cubiertos = set()
    vulnerables = []
    n = 0
    for v in registros:
        n += 1
        for sw in v.get("software") or []:
            clave = (sw.get("type"), sw.get("slug"))
            if clave not in instalado:
                continue
            cubiertos.add(clave)
            version = instalado[clave]
            rangos = (sw.get("affected_versions") or {}).values()
            if not any(en_rango(version, r) for r in rangos):
                continue
            cvss = v.get("cvss") or {}
            refs = v.get("references") or []
            vulnerables.append({
                "id": v.get("id"),
                "tipo": clave[0], "slug": clave[1], "version": version,
                "titulo": v.get("title", "")[:220],
                "cve": v.get("cve"),
                "cvss": cvss.get("score"), "severidad": cvss.get("rating"),
                "parche": sw.get("patched_versions") or [],
                "informativo": bool(v.get("informational")),
                "ref": refs[0] if refs else None,
            })
    sin_cobertura = sorted("%s:%s" % k for k in instalado if k not in cubiertos)
    return n, vulnerables, sin_cobertura


def parsear_whois_nic(texto):
    m = re.search(r"Expiration date:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", texto)
    if not m:
        raise RuntimeError("whois de NIC Chile sin fecha de expiracion")
    return m.group(1).replace(" ", "T") + "-03:00"


def vencimiento_dominio(dominio):
    # NIC Chile no publica RDAP: solo whois por el puerto 43. Por eso esto corre aqui y no en n8n,
    # que no tiene un nodo para conexiones TCP crudas.
    with socket.create_connection(("whois.nic.cl", 43), timeout=15) as s:
        s.sendall((dominio + "\r\n").encode())
        datos = b""
        while True:
            bloque = s.recv(4096)
            if not bloque:
                break
            datos += bloque
    return parsear_whois_nic(datos.decode("utf-8", "replace"))


def chequeo_plugins(cfg, prueba=False):
    dominio = (cfg.get("dominio") or "").strip()
    payload = {"tipo": "plugins", "host": dominio or "-", "ts": ahora(), "prueba": prueba, "errores": []}
    if cfg.get("whois_nic_chile") is True and dominio:
        try:
            payload["dominio_vence"] = vencimiento_dominio(dominio)
        except Exception as exc:  # noqa: BLE001
            payload["errores"].append("no se pudo consultar el vencimiento del dominio: %s" % exc)
    try:
        core, plugins, temas = inventario(cfg)
    except Exception as exc:  # noqa: BLE001
        payload["errores"].append(str(exc))
        return payload
    payload.update({
        "core": core,
        "plugins": [{"slug": p["name"], "version": p["version"], "estado": p["status"],
                     "actualizacion": p.get("update_version") or None} for p in plugins],
        "temas": [{"slug": t["name"], "version": t["version"], "estado": t["status"],
                   "actualizacion": t.get("update_version") or None} for t in temas],
    })
    feed = os.path.join(nxconfig.dir_estado(cfg), "wf-scanner.json")
    clave = (cfg.get("wordfence_api_key") or "").strip()
    if not clave:
        payload["errores"].append("falta wordfence_api_key en config.json")
    else:
        error = descargar_feed(feed, clave)
        if error:
            payload["errores"].append(error)
        if os.path.exists(feed):
            try:
                n, vulnerables, sin_cobertura = cruzar(feed, core, plugins, temas)
                payload.update({"feed_registros": n, "vulnerables": vulnerables, "sin_cobertura": sin_cobertura,
                                "feed_actualizado": datetime.datetime.fromtimestamp(
                                    os.path.getmtime(feed), datetime.timezone.utc).isoformat(timespec="minutes")})
            except Exception as exc:  # noqa: BLE001
                payload["errores"].append("no se pudo leer el feed: %s" % exc)
    if prueba:
        payload.setdefault("vulnerables", []).append({
            "id": "prueba-nexasec", "tipo": "plugin", "slug": "plugin-de-prueba", "version": "1.0.0",
            "titulo": "PRUEBA: vulnerabilidad sintetica, ignorar", "cve": None, "cvss": 9.8,
            "severidad": "Critical", "parche": ["1.0.1"], "informativo": False, "ref": None,
        })
    return payload


# --------------------------------------------------------------------------- envio

def enviar(cfg, payload):
    url = (cfg.get("webhook_vigia") or "").strip()
    if not url:
        return False, "sin webhook_vigia en config.json"
    cab = {"Content-Type": "application/json", "User-Agent": AGENTE}
    cab.update(cfg.get("headers") or {})
    req = urllib.request.Request(url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                 headers=cab, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            cuerpo = r.read(300).decode(errors="replace")
            tipo = r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        return False, "HTTP %d: %s" % (exc.code, exc.read(200).decode(errors="replace").replace("\n", " "))
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    # Un 200 con HTML es una intercepcion (login de Access), no una entrega.
    if "json" not in tipo:
        return False, "respuesta inesperada: " + cuerpo[:80].replace("\n", " ")
    return True, "entregado"


def main():
    ap = argparse.ArgumentParser()
    grupo = ap.add_mutually_exclusive_group(required=True)
    grupo.add_argument("--origen", action="store_true")
    grupo.add_argument("--plugins", action="store_true")
    ap.add_argument("--simular", action="store_true", help="muestra el payload sin enviarlo")
    ap.add_argument("--prueba", action="store_true", help="agrega un fallo sintetico para probar las alertas")
    args = ap.parse_args()
    cfg = nxconfig.cargar_config()

    payload = chequeo_origen(cfg, args.prueba) if args.origen else chequeo_plugins(cfg, args.prueba)
    if args.simular:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    ok, detalle = enviar(cfg, payload)
    resumen = ("ok" if payload.get("ok") else "FALLA") if args.origen else \
        "%d vulnerables, %d errores" % (len(payload.get("vulnerables") or []), len(payload["errores"]))
    print("%s %s %s -> %s" % (ahora(), payload["tipo"], resumen, detalle))


if __name__ == "__main__":
    main()
