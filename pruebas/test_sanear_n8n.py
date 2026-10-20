import copy
import json
import os
import subprocess
import sys

import sanear_n8n

DATOS = os.path.join(os.path.dirname(__file__), "datos", "workflow-ejemplo.json")
REEMPLAZOS = {
    "sitio-real.example": "<DOMINIO>",
    "Persona Real": "el responsable",
    "0123456789abcdef0123456789abcdef": "<CF_ZONE_ID>",
}


def _wf():
    with open(DATOS, encoding="utf-8") as fh:
        return json.load(fh)


def test_quita_identificadores():
    s = sanear_n8n.sanear(_wf(), REEMPLAZOS)
    for clave in ("id", "versionId", "meta", "pinData", "tags", "staticData"):
        assert clave not in s
    assert s["active"] is False
    assert all("webhookId" not in n for n in s["nodes"])
    creds = [c for n in s["nodes"] for c in (n.get("credentials") or {}).values()]
    assert creds and all(c["id"] == "<ID_CREDENCIAL>" for c in creds)


def test_nombres_de_credencial_genericos():
    s = sanear_n8n.sanear(_wf(), REEMPLAZOS)
    nombres = {n["name"]: n["credentials"] for n in s["nodes"] if n.get("credentials")}
    assert nombres["Webhook"]["httpHeaderAuth"]["name"] == "Header Auth"
    assert nombres["Notificar"]["telegramApi"]["name"] == "Telegram"
    assert nombres["Cloudflare"]["httpHeaderAuth"]["name"] == "Cloudflare"


def test_chat_id_y_error_workflow():
    s = sanear_n8n.sanear(_wf(), REEMPLAZOS)
    notificar = [n for n in s["nodes"] if n["name"] == "Notificar"][0]
    assert notificar["parameters"]["chatId"] == "<TELEGRAM_CHAT_ID>"
    assert s["settings"]["errorWorkflow"] == "<ID_WORKFLOW_ERRORES>"


def test_reemplazo_dentro_de_jscode_y_url():
    texto = json.dumps(sanear_n8n.sanear(_wf(), REEMPLAZOS))
    assert "sitio-real.example" not in texto and "Persona Real" not in texto
    assert "0123456789abcdef0123456789abcdef" not in texto
    assert "zones/<CF_ZONE_ID>/rulesets" in texto
    assert "el responsable" in texto


def test_hex32_residual():
    texto = json.dumps(sanear_n8n.sanear(_wf(), REEMPLAZOS))
    assert "fedcba9876543210fedcba9876543210" not in texto
    assert "<CF_ID>" in texto


def test_conexiones_intactas():
    original = _wf()
    s = sanear_n8n.sanear(copy.deepcopy(original), REEMPLAZOS)
    assert [n["name"] for n in s["nodes"]] == [n["name"] for n in original["nodes"]]
    assert s["connections"] == original["connections"]


def test_no_modifica_la_entrada():
    original = _wf()
    respaldo = copy.deepcopy(original)
    sanear_n8n.sanear(original, REEMPLAZOS)
    assert original == respaldo


def test_cli(tmp_path):
    rep = tmp_path / "reemplazos.json"
    rep.write_text(json.dumps(REEMPLAZOS))
    salida = tmp_path / "salida.json"
    script = os.path.join(os.path.dirname(os.path.dirname(__file__)), "herramientas", "sanear_n8n.py")
    r = subprocess.run([sys.executable, script, DATOS, str(salida), "--reemplazos", str(rep)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(salida.read_text())["active"] is False
