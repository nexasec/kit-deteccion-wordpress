#!/usr/bin/env python3
"""Watchdog del web root: detecta archivos nuevos o modificados.

Corre por cron y EMPUJA los hallazgos a n8n. Push y no pull a proposito: asi
n8n no necesita una llave SSH hacia produccion, y un compromiso de n8n no se
traduce en acceso al servidor.

Vigila tres cosas:
  1. Archivos de respaldo/volcado en los primeros niveles del web root.
     Es el control que falta cuando una migracion deja un respaldo completo
     descargable desde internet.
  2. PHP dentro de uploads a cualquier profundidad: el patron clasico de webshell.
  3. Las zonas de persistencia, con hash: mu-plugins, drop-ins de wp-content,
     wp-config.php y los .htaccess. WordPress carga todo eso sin preguntar, y
     tamano + fecha no bastan porque se falsifican con `touch -r`.

Ademas late contra Uptime Kuma en CADA corrida. Ese latido es el dead-man's
switch: si el cron muere, si el servidor se cae o si la entrega a n8n falla,
Kuma lo nota y avisa por un canal que no depende de n8n.

Configuracion (config.json, ver nxconfig): raiz_web, dominio, webhook_watchdog,
headers, push_url, dir_estado.
"""

import hashlib
import json
import os
import urllib.parse
import urllib.request

import nxconfig

# v2: las entradas criticas llevan hash. Cambiar el nombre fuerza una linea
# base nueva y silenciosa, en vez de reportar como "modificado" todo lo que
# cambio de formato.
BASE = "inventory-v2.json"

SOSPECHOSAS = (".zip", ".sql", ".wpress", ".tar", ".gz", ".tgz",
               ".bak", ".old", ".log", ".sh", ".7z", ".rar")
MAX_PROFUNDIDAD = 3
CRITICOS_FIJOS = ("wp-config.php", ".htaccess", "wp-content/uploads/.htaccess")

# Sin User-Agent explicito, urllib manda "Python-urllib/3.x" y el Browser
# Integrity Check de Cloudflare responde 1010: la peticion se pierde en silencio.
AGENTE = "NexaSec-Watchdog/1.0 (+https://nexasec.cl)"


def _sha256(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as fh:
        for bloque in iter(lambda: fh.read(65536), b""):
            h.update(bloque)
    return h.hexdigest()


def _registrar(inv, raiz, ruta, con_hash=False):
    try:
        st = os.stat(ruta)
        entrada = [st.st_size, int(st.st_mtime)]
        if con_hash:
            entrada.append(_sha256(ruta))
    except OSError:
        return
    inv[os.path.relpath(ruta, raiz)] = entrada


def inventario(raiz):
    """ruta relativa -> [bytes, mtime] o [bytes, mtime, sha256]."""
    inv = {}
    wp_content = os.path.join(raiz, "wp-content")

    # Respaldos y volcados en los primeros niveles.
    for dirpath, dirnames, filenames in os.walk(raiz):
        rel = os.path.relpath(dirpath, raiz)
        profundidad = 0 if rel == "." else rel.count(os.sep) + 1
        if profundidad >= MAX_PROFUNDIDAD:
            dirnames[:] = []
        for fn in filenames:
            if fn.lower().endswith(SOSPECHOSAS):
                _registrar(inv, raiz, os.path.join(dirpath, fn))

    # PHP en uploads, a cualquier profundidad.
    for dirpath, _, filenames in os.walk(os.path.join(wp_content, "uploads")):
        for fn in filenames:
            if fn.lower().endswith((".php", ".phtml", ".php5", ".phar")):
                _registrar(inv, raiz, os.path.join(dirpath, fn))

    # Zonas de persistencia, con hash. Van al final para que su entrada
    # (con hash) prevalezca si algun archivo ya entro por otra regla.
    for dirpath, _, filenames in os.walk(os.path.join(wp_content, "mu-plugins")):
        for fn in filenames:
            _registrar(inv, raiz, os.path.join(dirpath, fn), con_hash=True)

    try:
        for fn in os.listdir(wp_content):
            ruta = os.path.join(wp_content, fn)
            if fn.lower().endswith(".php") and os.path.isfile(ruta):
                _registrar(inv, raiz, ruta, con_hash=True)
    except OSError:
        pass

    for rel in CRITICOS_FIJOS:
        ruta = os.path.join(raiz, rel)
        if os.path.isfile(ruta):
            _registrar(inv, raiz, ruta, con_hash=True)

    return inv


def comparar(previo, actual):
    return {
        "nuevos": sorted(k for k in actual if k not in previo),
        "modificados": sorted(k for k in actual if k in previo and actual[k] != previo[k]),
        "eliminados": sorted(k for k in previo if k not in actual),
    }


def construir_evento(host, actual, diff):
    return {
        "origen": "watchdog",
        "severidad": "critico" if diff["nuevos"] or diff["modificados"] else "ok",
        "host": host,
        "nuevos": [{"ruta": k, "bytes": actual[k][0]} for k in diff["nuevos"]],
        "modificados": [{"ruta": k, "bytes": actual[k][0]} for k in diff["modificados"]],
        "eliminados": diff["eliminados"],
        "vigilados": len(actual),
    }


def enviar_a_n8n(cfg, evento):
    """Devuelve (ok, detalle). ok=True tambien si no hay webhook configurado."""
    webhook = (cfg.get("webhook_watchdog") or "").strip()
    if not webhook:
        return True, "sin webhook configurado"

    cabeceras = {"Content-Type": "application/json", "User-Agent": AGENTE}
    cabeceras.update(cfg.get("headers") or {})

    req = urllib.request.Request(
        webhook,
        data=json.dumps(evento, ensure_ascii=False).encode("utf-8"),
        headers=cabeceras,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            cuerpo = r.read(300).decode(errors="replace")
            tipo = r.headers.get("Content-Type", "")
    except Exception as exc:  # noqa: BLE001 - el cron no debe morir por esto
        return False, "fallo entrega a n8n: %s" % exc
    # Un 200 con HTML es una intercepcion (login de Access), no una entrega.
    if "json" not in tipo:
        return False, "respuesta inesperada de n8n: " + cuerpo[:80].replace("\n", " ")
    return True, "entregado"


def latir(cfg, estado, mensaje):
    """Latido a Uptime Kuma. Un fallo aqui nunca debe romper el cron."""
    url = (cfg.get("push_url") or "").strip()
    if not url:
        return

    # Kuma copia la URL con parametros de ejemplo (?status=up&msg=OK&ping=).
    # Descartamos su query y ponemos la nuestra.
    partes = urllib.parse.urlsplit(url)
    destino = urllib.parse.urlunsplit((
        partes.scheme, partes.netloc, partes.path,
        urllib.parse.urlencode({"status": estado, "msg": mensaje[:180]}),
        "",
    ))

    req = urllib.request.Request(destino, headers={"User-Agent": AGENTE})
    try:
        cuerpo = urllib.request.urlopen(req, timeout=10).read(400).decode(errors="replace")
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"origen": "watchdog", "error_heartbeat": str(exc)}))
        return

    # Kuma responde JSON {"ok":true}. Un 200 con HTML significa que algo
    # intercepto la peticion por el camino -- tipicamente el login de
    # Cloudflare Access. Sin esta comprobacion el latido parece exitoso
    # y nunca llega: justo el modo de fallo que este vigilante existe
    # para detectar.
    if '"ok"' not in cuerpo:
        print(json.dumps({
            "origen": "watchdog",
            "error_heartbeat": "respuesta inesperada, el latido no llego a Kuma",
            "recibido": cuerpo[:100].replace("\n", " "),
        }))


def guardar_base(ruta, inv):
    with open(ruta, "w", encoding="utf-8") as fh:
        json.dump(inv, fh, indent=1, sort_keys=True)


def main():
    cfg = nxconfig.cargar_config()
    faltan = nxconfig.requerir(cfg, "raiz_web")
    if faltan:
        # Sin raiz no hay nada que vigilar: se avisa por el latido, que es el
        # canal que no depende de n8n.
        msg = "falta %s en config.json" % ", ".join(faltan)
        print(json.dumps({"origen": "watchdog", "error": msg}))
        latir(cfg, "down", msg)
        return

    raiz = os.path.expanduser(cfg["raiz_web"])
    # Una raiz equivocada (mal escrita, movida, sin permisos) da un inventario
    # vacio que se ve igual que "no paso nada": se trata como falla del sensor.
    if not os.path.isdir(os.path.join(raiz, "wp-content")):
        msg = "raiz_web no es un WordPress legible: %s" % raiz
        print(json.dumps({"origen": "watchdog", "error": msg}))
        latir(cfg, "down", msg)
        return

    base = os.path.join(nxconfig.dir_estado(cfg), BASE)
    actual = inventario(raiz)

    try:
        with open(base, encoding="utf-8") as fh:
            previo = json.load(fh)
    except (OSError, ValueError):
        previo = None

    # Primera ejecucion: se establece la linea base sin alertar.
    if previo is None:
        guardar_base(base, actual)
        print(json.dumps({"origen": "watchdog", "estado": "baseline_creada",
                          "vigilados": len(actual)}))
        latir(cfg, "up", "baseline creada, %d vigilados" % len(actual))
        return

    evento = construir_evento(cfg.get("dominio") or "-", actual, comparar(previo, actual))
    print(json.dumps(evento, ensure_ascii=False))

    entrega_ok, detalle = True, "sin hallazgos"
    if evento["severidad"] != "ok":
        entrega_ok, detalle = enviar_a_n8n(cfg, evento)

    # El latido lleva el resultado de la entrega: si n8n esta inalcanzable,
    # Kuma se pone en rojo y avisa por su propio canal. Sin esto, un fallo de
    # entrega se veria igual que "no ha pasado nada".
    # La base solo avanza si el hallazgo llego: si n8n no respondio, la proxima
    # corrida vuelve a reportar los mismos archivos en vez de perderlos.
    if entrega_ok:
        guardar_base(base, actual)
        latir(cfg, "up", "ok, %d vigilados, %s" % (len(actual), detalle))
    else:
        latir(cfg, "down", detalle)


if __name__ == "__main__":
    main()
