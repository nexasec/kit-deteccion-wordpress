"""Carga de la configuracion compartida por los scripts del kit.

Todos los scripts leen el mismo config.json. Su ruta sale de la variable
NX_CONFIG o, si no esta, de ~/nx-kit/config.json. El archivo lleva secretos
(webhooks, service token de Access, clave de Wordfence): debe quedar fuera del
web root y con permisos 600.

Ningun fallo de lectura lanza excepcion: un script de cron que muere con un
traceback es un sensor que deja de reportar sin que nadie lo note. Cada script
decide que hacer con una config vacia o incompleta.
"""

import json
import os

POR_DEFECTO = "~/nx-kit/config.json"


def ruta_config():
    return os.environ.get("NX_CONFIG") or os.path.expanduser(POR_DEFECTO)


def cargar_config(ruta=None):
    try:
        with open(ruta or ruta_config(), encoding="utf-8") as fh:
            datos = json.load(fh)
    except (OSError, ValueError):
        return {}
    return datos if isinstance(datos, dict) else {}


def dir_estado(cfg, ruta=None):
    """Carpeta para logs, lineas base y estado. Se crea con permisos 700."""
    d = (cfg.get("dir_estado") or "").strip()
    d = os.path.expanduser(d) if d else os.path.dirname(os.path.abspath(ruta or ruta_config()))
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def requerir(cfg, *claves):
    """Claves ausentes o vacias, en el orden pedido."""
    return [c for c in claves if cfg.get(c) in (None, "", [], {})]
