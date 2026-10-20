import json
import os
import shutil
import subprocess

import pytest

RAIZ = os.path.dirname(os.path.dirname(__file__))


def _codigo(workflow, nodo):
    with open(os.path.join(RAIZ, "n8n", workflow), encoding="utf-8") as fh:
        wf = json.load(fh)
    return [n for n in wf["nodes"] if n["name"] == nodo][0]["parameters"]["jsCode"]


def _ejecutar(codigo, entrada, tmp_path):
    js = tmp_path / "nodo.js"
    js.write_text("const $json = %s;\n(async () => {\nconst r = await (async () => {\n%s\n})();\n"
                  "console.log(JSON.stringify(r));\n})();\n" % (json.dumps(entrada), codigo))
    out = subprocess.run(["node", str(js)], capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="node no esta instalado")
def test_watchdog_escapa_html_en_rutas_y_host(tmp_path):
    entrada = {"body": {"host": "a&b", "vigilados": 3,
                        "nuevos": [{"ruta": "wp-content/uploads/a<b>.php", "bytes": 5}], "modificados": []}}
    r = _ejecutar(_codigo("watchdog-del-web-root.json", "Componer alerta"), entrada, tmp_path)[0]["json"]
    assert "a&lt;b&gt;.php" in r["mensaje"]
    assert "a&amp;b" in r["mensaje"]
    assert "<b>.php" not in r["mensaje"]
    assert r["webshell"] is True


def test_canary_no_delata_el_tipo_de_archivo_expuesto():
    assert "wpress" not in _codigo("canary-a-alerta-enriquecida.json", "Componer alerta")
    with open(os.path.join(RAIZ, "servidor", "nx-canary.php"), encoding="utf-8") as fh:
        assert ".wpress con sufijo" not in fh.read()
