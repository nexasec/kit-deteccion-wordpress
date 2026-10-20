#!/usr/bin/env python3
"""Sanea un workflow exportado de n8n para publicarlo.

Un export de n8n arrastra mas de lo que parece: IDs de credenciales, de la
instancia y del workflow de errores, webhookId, datos fijados de ejecuciones
reales (pinData), chat IDs de Telegram y, dentro del codigo de los nodos, IDs
de cuenta y de zona de Cloudflare, dominios y nombres de personas.

Dos pasadas:
  1. Estructural: quita o reemplaza por marcadores los campos que n8n usa para
     identificar cosas de la instancia.
  2. Textual: reemplaza literalmente cada valor de un archivo de reemplazos
     (valor real -> marcador) en TODO el JSON, incluidos jsCode y URLs, y al
     final cualquier hexadecimal de 32 caracteres que quede (el formato de los
     IDs de Cloudflare) pasa a <CF_ID>.

El archivo de reemplazos tiene los valores reales: vive fuera del repositorio.
El resultado hay que leerlo igual antes de publicarlo; esto reduce el error
humano, no lo reemplaza.

Uso:
  sanear_n8n.py entrada.json salida.json --reemplazos ../privado/reemplazos.json
"""

import argparse
import copy
import json
import re

QUITAR = ("id", "versionId", "meta", "pinData", "staticData", "tags", "triggerCount", "shared")
HEX32 = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{32}(?![0-9a-fA-F])")
NOMBRES_POR_TIPO = {"telegramApi": "Telegram"}
NOMBRES_POR_SERVICIO = (("cloudflare", "Cloudflare"), ("abuseipdb", "AbuseIPDB"), ("greynoise", "GreyNoise"))


def _nombre_credencial(tipo, nombre):
    if tipo in NOMBRES_POR_TIPO:
        return NOMBRES_POR_TIPO[tipo]
    bajo = (nombre or "").lower()
    for clave, generico in NOMBRES_POR_SERVICIO:
        if clave in bajo:
            return generico
    return "Header Auth" if tipo == "httpHeaderAuth" else tipo


def sanear(wf, reemplazos):
    wf = copy.deepcopy(wf)
    for clave in QUITAR:
        wf.pop(clave, None)
    wf["active"] = False
    if (wf.get("settings") or {}).get("errorWorkflow"):
        wf["settings"]["errorWorkflow"] = "<ID_WORKFLOW_ERRORES>"

    for nodo in wf.get("nodes") or []:
        nodo.pop("webhookId", None)
        for tipo, cred in (nodo.get("credentials") or {}).items():
            cred["id"] = "<ID_CREDENCIAL>"
            cred["name"] = _nombre_credencial(tipo, cred.get("name"))
        params = nodo.get("parameters") or {}
        if "chatId" in params:
            params["chatId"] = "<TELEGRAM_CHAT_ID>"

    # Los valores mas largos primero: si uno contiene a otro, gana el especifico.
    texto = json.dumps(wf, ensure_ascii=False)
    for real in sorted(reemplazos, key=len, reverse=True):
        # Se reemplaza tambien la forma escapada, por si el valor tiene comillas o barras.
        escapado = json.dumps(real, ensure_ascii=False)[1:-1]
        marcador = json.dumps(reemplazos[real], ensure_ascii=False)[1:-1]
        texto = texto.replace(escapado, marcador)
    texto = HEX32.sub("<CF_ID>", texto)
    return json.loads(texto)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("entrada")
    ap.add_argument("salida")
    ap.add_argument("--reemplazos", required=True, help="JSON {valor real: marcador}, fuera del repo")
    args = ap.parse_args()
    with open(args.entrada, encoding="utf-8") as fh:
        wf = json.load(fh)
    with open(args.reemplazos, encoding="utf-8") as fh:
        reemplazos = json.load(fh)
    with open(args.salida, "w", encoding="utf-8") as fh:
        json.dump(sanear(wf, reemplazos), fh, ensure_ascii=False, indent=2)
        fh.write("\n")


if __name__ == "__main__":
    main()
