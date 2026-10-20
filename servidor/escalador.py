#!/usr/bin/env python3
"""Escalador: propone llevar al borde de Cloudflare a las IPs hostiles.

Wordfence bloquea en PHP: cuando actua, la peticion ya llego al servidor y
arranco WordPress. Este script junta las IPs que Wordfence bloqueo y las que
tocaron el canary de forma significativa, y le PROPONE a n8n un bloqueo en
Cloudflare. Nada se bloquea sin que una persona lo apruebe en Telegram, y todo
bloqueo vence solo a los N dias.

Push, como el watchdog: n8n nunca entra al servidor.

Configuracion (config.json, ver nxconfig): dominio, raiz_web, wp_cli,
prefijo_tabla, webhook_escalar, headers, escalar_ventana_h, escalar_dias,
escalar_excluir, dir_estado.

Uso:
  escalador.py                  recolecta y envia
  escalador.py --simular        muestra los candidatos sin enviar ni recordar nada
  escalador.py --ventana 72     amplia la ventana de busqueda (horas)
  escalador.py --prueba         envia un candidato sintetico (203.0.113.50, vence hoy)
"""

import argparse
import collections
import datetime
import ipaddress
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request

import nxconfig

# Sin User-Agent explicito, urllib manda "Python-urllib/3.x" y el Browser
# Integrity Check de Cloudflare responde 1010.
AGENTE = "NexaSec-Escalador/1.0 (+https://nexasec.cl)"

VENTANA_H = 24
NO_REPROPONER_DIAS = 7
DIAS_BLOQUEO = 7
MAX_POR_CORRIDA = 5
UMBRAL_WFSN = 5      # bloqueos por la red de reputacion de Wordfence en la ventana
UMBRAL_SENUELOS = 3  # senuelos distintos tocados por la misma IP

# Cuanto pesa cada motivo al ordenar: lo dirigido va antes que el ruido.
PRIORIDAD = {
    "senuelo_critico": 100,
    "cabecera_falsificada": 90,
    "origen_directo": 80,
    "waf": 70,
    "wfsn": 50,
    "escaneo_senuelos": 40,
}

# Rangos publicados de Cloudflare: bloquear uno de ellos no tiene sentido.
CLOUDFLARE = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)]


def normalizar(ip):
    try:
        a = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a


def excluida(a, excluir):
    # Solo direcciones publicas: fuera privadas, reservadas y de documentacion.
    if not a.is_global:
        return True
    if any(a in n for n in CLOUDFLARE if n.version == a.version):
        return True
    return any(a in n for n in excluir if n.version == a.version)


def sql_wordfence(ventana_s, dominio, prefijo):
    # El dominio y el prefijo van dentro del SQL: se validan en vez de escaparlos.
    if not re.match(r"^[A-Za-z0-9_]+$", prefijo or ""):
        raise ValueError("prefijo_tabla invalido: %r" % prefijo)
    if not re.match(r"^[A-Za-z0-9.-]+$", dominio or ""):
        raise ValueError("dominio invalido: %r" % dominio)
    # Cada acierto aparece duplicado en wfhits: se cuentan marcas de tiempo distintas.
    return (
        "SELECT INET6_NTOA(IP), action, COUNT(DISTINCT ctime), MIN(ctime), MAX(ctime), "
        "SUBSTRING_INDEX(GROUP_CONCAT(DISTINCT SUBSTRING_INDEX(URL,'%s',-1) SEPARATOR '|'),'|',3), "
        "SUBSTRING_INDEX(GROUP_CONCAT(DISTINCT actionDescription SEPARATOR '|'),'|',3) "
        "FROM %swfhits WHERE ctime > UNIX_TIMESTAMP() - %d "
        "AND (action LIKE 'blocked:%%' OR action = 'lockedOut') "
        "GROUP BY IP, action;" % (dominio, prefijo, int(ventana_s))
    )


def consulta(cfg, sql):
    raiz = os.path.expanduser(cfg.get("raiz_web") or "")
    r = subprocess.run(
        [cfg.get("wp_cli") or "wp", "db", "query", sql, "--skip-column-names",
         "--skip-plugins", "--skip-themes", "--path=" + raiz],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        raise RuntimeError("wp db query fallo: " + r.stderr.strip()[:200])
    return [l.split("\t") for l in r.stdout.splitlines() if l.strip()]


def iso(ts):
    return datetime.datetime.fromtimestamp(float(ts), datetime.timezone.utc).isoformat(timespec="seconds")


def nuevo():
    return {"motivos": {}, "eventos": 0, "rutas": set(), "reglas": set(),
            "primera": None, "ultima": None}


def anotar(c, motivo, texto, n, rutas=(), reglas=(), primera=None, ultima=None):
    c["motivos"][motivo] = texto
    c["eventos"] += n
    c["rutas"].update(r for r in rutas if r)
    c["reglas"].update(r for r in reglas if r)
    for ts in (primera, ultima):
        if ts is None:
            continue
        c["primera"] = ts if c["primera"] is None else min(c["primera"], ts)
        c["ultima"] = ts if c["ultima"] is None else max(c["ultima"], ts)


def desde_wordfence(cfg, cands, ventana_s):
    filas = consulta(cfg, sql_wordfence(ventana_s, cfg.get("dominio"), cfg.get("prefijo_tabla") or "wp_"))
    por_ip = collections.defaultdict(lambda: {"waf": [], "wfsn": []})
    for ip, accion, n, t0, t1, rutas, reglas in (f + [""] * (7 - len(f)) for f in filas):
        clave = "waf" if accion == "blocked:waf" else "wfsn"
        por_ip[ip][clave].append((int(n), float(t0), float(t1), rutas.split("|"), reglas.split("|")))

    for ip, grupos in por_ip.items():
        a = normalizar(ip)
        if a is None:
            continue
        for clave, lista in grupos.items():
            if not lista:
                continue
            n = sum(x[0] for x in lista)
            if clave == "wfsn" and n < UMBRAL_WFSN:
                continue
            texto = ("el WAF de Wordfence bloqueo %d intento(s) de explotacion" % n if clave == "waf"
                     else "%d bloqueos por la red de reputacion de Wordfence (fuerza bruta)" % n)
            c = cands.setdefault(str(a), nuevo())
            for _, t0, t1, rutas, reglas in lista:
                anotar(c, clave, texto, 0, rutas, reglas if clave == "waf" else (), t0, t1)
            c["eventos"] += n


def desde_canary(cands, ventana_s, log_ruta):
    limite = time.time() - ventana_s
    senuelos = collections.defaultdict(set)
    try:
        fh = open(log_ruta, encoding="utf-8")
    except OSError:
        return
    with fh:
        for linea in fh:
            try:
                e = json.loads(linea)
                ts = datetime.datetime.fromisoformat(e["ts"]).timestamp()
            except (ValueError, KeyError, TypeError):
                continue
            if ts < limite:
                continue
            a = normalizar(e.get("ip", ""))
            if a is None:
                continue
            ip, uri = str(a), e.get("uri", "").split("?")[0]
            senuelos[ip].add(uri)

            # Los registros sin via_cloudflare se asumen legitimos para no
            # inventar sondeos directos.
            if e.get("severidad") == "critico":
                anotar(cands.setdefault(ip, nuevo()), "senuelo_critico",
                       "toco el senuelo critico (la URL exacta de un archivo que estuvo expuesto)", 1, [uri], (), ts, ts)
            if e.get("cabecera_falsificada"):
                anotar(cands.setdefault(ip, nuevo()), "cabecera_falsificada",
                       "falsifico la cabecera CF-Connecting-IP contra el origen", 1, [uri], (), ts, ts)
            if e.get("via_cloudflare", True) is False:
                anotar(cands.setdefault(ip, nuevo()), "origen_directo",
                       "sondeo el origen directo, saltandose Cloudflare", 1, [uri], (), ts, ts)

    for ip, uris in senuelos.items():
        if len(uris) >= UMBRAL_SENUELOS:
            anotar(cands.setdefault(ip, nuevo()), "escaneo_senuelos",
                   "toco %d senuelos distintos (escaneo de respaldos)" % len(uris), 0, sorted(uris))


def prioridad(c):
    return (max(PRIORIDAD[m] for m in c["motivos"]), c["eventos"])


def seleccionar(cands, estado, es_excluida, ahora, maximo):
    """(a_enviar, excluidas, recientes, pendientes). a_enviar: [(ip, candidato)] por prioridad."""
    elegibles, excluidas, recientes = [], [], []
    for ip, c in cands.items():
        if es_excluida(ip):
            excluidas.append(ip)
        elif ahora - estado.get(ip, 0) < NO_REPROPONER_DIAS * 86400:
            recientes.append(ip)
        else:
            elegibles.append((ip, c))
    elegibles.sort(key=lambda x: prioridad(x[1]), reverse=True)
    return elegibles[:maximo], sorted(excluidas), sorted(recientes), max(0, len(elegibles) - maximo)


def enviar(cfg, payload):
    url = (cfg.get("webhook_escalar") or "").strip()
    if not url:
        return False, "sin webhook_escalar en config.json"
    cab = {"Content-Type": "application/json", "User-Agent": AGENTE}
    cab.update(cfg.get("headers") or {})
    req = urllib.request.Request(url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                 headers=cab, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            cuerpo = r.read(300).decode(errors="replace")
            tipo = r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        # El cuerpo distingue a quien rechaza: "Authorization data is wrong!"
        # es n8n (credencial del webhook); "error code: 1010" es Cloudflare.
        cuerpo = exc.read(200).decode(errors="replace").replace("\n", " ")
        return False, "HTTP %d: %s" % (exc.code, cuerpo)
    except Exception as exc:  # noqa: BLE001 - el cron no debe morir por esto
        return False, str(exc)
    # Un 200 con HTML es una intercepcion (login de Access, pagina de error), no una entrega.
    if "json" not in tipo:
        return False, "respuesta inesperada: " + cuerpo[:80].replace("\n", " ")
    return True, "entregado"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--simular", action="store_true")
    ap.add_argument("--prueba", action="store_true")
    ap.add_argument("--ventana", type=int, default=None, help="horas")
    args = ap.parse_args()
    cfg = nxconfig.cargar_config()

    if args.prueba:
        hoy = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        ok, det = enviar(cfg, {
            "origen": "escalador", "prueba": True, "ip": "203.0.113.50", "version": 4,
            "motivos": ["PRUEBA de instalacion: IP de documentacion (RFC 5737), no pertenece a nadie"],
            "eventos": 0, "rutas": [], "reglas": [], "primera": hoy, "ultima": hoy,
            "dias": 0, "pendientes": 0,
        })
        print(json.dumps({"origen": "escalador", "prueba": True, "entregado": ok, "detalle": det}))
        return

    ventana_h = args.ventana or int(cfg.get("escalar_ventana_h") or VENTANA_H)
    excluir = []
    for n in cfg.get("escalar_excluir") or []:
        try:
            excluir.append(ipaddress.ip_network(n, strict=False))
        except ValueError:
            pass

    estado_dir = nxconfig.dir_estado(cfg)
    errores = []
    cands = {}
    # Sin raiz_web o dominio no se puede leer Wordfence, pero el canary si:
    # se avisa del faltante y se sigue con lo que hay.
    faltan = nxconfig.requerir(cfg, "raiz_web", "dominio")
    if faltan:
        errores.append("falta %s en config.json: se omite Wordfence" % ", ".join(faltan))
    else:
        try:
            desde_wordfence(cfg, cands, ventana_h * 3600)
        except Exception as exc:  # noqa: BLE001 - el cron no debe morir por esto
            errores.append("Wordfence: %s" % exc)
    desde_canary(cands, ventana_h * 3600, os.path.join(estado_dir, "canary.log"))

    ruta_estado = os.path.join(estado_dir, "escalador-estado.json")
    try:
        with open(ruta_estado, encoding="utf-8") as fh:
            estado = json.load(fh)
    except (OSError, ValueError):
        estado = {}
    ahora = time.time()
    estado = {ip: t for ip, t in estado.items() if ahora - t < 30 * 86400}

    def es_excluida(ip):
        a = normalizar(ip)
        return a is None or excluida(a, excluir)

    a_enviar, excluidas, recientes, pendientes = seleccionar(cands, estado, es_excluida, ahora, MAX_POR_CORRIDA)

    resumen = {"origen": "escalador", "ventana_h": ventana_h, "candidatos": len(cands),
               "excluidas": excluidas, "ya_propuestas_hace_poco": recientes,
               "a_proponer": [], "pendientes_para_la_proxima": pendientes, "errores": errores}

    for ip, c in a_enviar:
        a = normalizar(ip)
        payload = {
            "origen": "escalador", "prueba": False, "ip": ip, "version": a.version,
            "motivos": [c["motivos"][m] for m in sorted(c["motivos"], key=PRIORIDAD.get, reverse=True)],
            "eventos": c["eventos"],
            "rutas": sorted(c["rutas"])[:5],
            "reglas": sorted(c["reglas"])[:3],
            "primera": iso(c["primera"]) if c["primera"] else None,
            "ultima": iso(c["ultima"]) if c["ultima"] else None,
            "dias": int(cfg.get("escalar_dias") or DIAS_BLOQUEO),
            "pendientes": pendientes,
        }
        if args.simular:
            resumen["a_proponer"].append({"ip": ip, "motivos": payload["motivos"], "eventos": c["eventos"]})
            continue
        ok, det = enviar(cfg, payload)
        resumen["a_proponer"].append({"ip": ip, "entregado": ok, "detalle": det})
        # Solo se recuerda lo que llego de verdad: un fallo de entrega se reintenta.
        if ok:
            estado[ip] = ahora

    if not args.simular:
        with open(ruta_estado, "w", encoding="utf-8") as fh:
            json.dump(estado, fh, indent=1, sort_keys=True)
        os.chmod(ruta_estado, 0o600)

    print(json.dumps(resumen, ensure_ascii=False, indent=None if not args.simular else 1))


if __name__ == "__main__":
    main()
