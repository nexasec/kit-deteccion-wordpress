import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest

AQUI = os.path.dirname(__file__)
RAIZ = os.path.dirname(AQUI)
CANARY = os.path.join(RAIZ, "servidor", "nx-canary.php")
ARNES = os.path.join(AQUI, "datos", "arnes_canary.php")

pytestmark = pytest.mark.skipif(shutil.which("php") is None, reason="php no esta instalado")


def llamar(funcion, *args):
    out = subprocess.run(["php", ARNES, funcion, json.dumps(list(args))],
                         capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr + out.stdout
    return json.loads(out.stdout)


def test_remote_addr_ignora_cabecera():
    r = llamar("nx_ip_cliente", {"REMOTE_ADDR": "203.0.113.9", "HTTP_CF_CONNECTING_IP": "198.51.100.1"}, "remote_addr")
    assert r == {"ip": "203.0.113.9", "via_cloudflare": False, "cabecera_falsificada": "198.51.100.1"}


def test_remote_addr_coincide_es_cloudflare():
    r = llamar("nx_ip_cliente", {"REMOTE_ADDR": "203.0.113.9", "HTTP_CF_CONNECTING_IP": "203.0.113.9"}, "remote_addr")
    assert r == {"ip": "203.0.113.9", "via_cloudflare": True, "cabecera_falsificada": False}


def test_sin_cabecera_no_es_cloudflare_ni_falsa():
    r = llamar("nx_ip_cliente", {"REMOTE_ADDR": "203.0.113.9"}, "remote_addr")
    assert r == {"ip": "203.0.113.9", "via_cloudflare": False, "cabecera_falsificada": False}


def test_modo_cf_acepta_cabecera_desde_rango_cloudflare():
    r = llamar("nx_ip_cliente", {"REMOTE_ADDR": "172.64.0.5", "HTTP_CF_CONNECTING_IP": "203.0.113.9"},
               "cf_connecting_ip_si_viene_de_cloudflare")
    assert r == {"ip": "203.0.113.9", "via_cloudflare": True, "cabecera_falsificada": False}


def test_modo_cf_acepta_cabecera_desde_rango_cloudflare_ipv6():
    r = llamar("nx_ip_cliente", {"REMOTE_ADDR": "2606:4700::1", "HTTP_CF_CONNECTING_IP": "2001:db8::9"},
               "cf_connecting_ip_si_viene_de_cloudflare")
    assert r["ip"] == "2001:db8::9" and r["via_cloudflare"] is True


def test_modo_cf_rechaza_cabecera_fuera_de_rango():
    r = llamar("nx_ip_cliente", {"REMOTE_ADDR": "203.0.113.9", "HTTP_CF_CONNECTING_IP": "198.51.100.1"},
               "cf_connecting_ip_si_viene_de_cloudflare")
    assert r == {"ip": "203.0.113.9", "via_cloudflare": False, "cabecera_falsificada": "198.51.100.1"}


def test_modo_cf_rechaza_cabecera_que_no_es_ip():
    r = llamar("nx_ip_cliente", {"REMOTE_ADDR": "172.64.0.5", "HTTP_CF_CONNECTING_IP": "<script>"},
               "cf_connecting_ip_si_viene_de_cloudflare")
    assert r["ip"] == "172.64.0.5" and r["cabecera_falsificada"] == "<script>"


def test_critico_vacio_nunca_dispara():
    assert llamar("nx_es_critico", "/cualquier.wpress", "") is False
    assert llamar("nx_es_critico", "/respaldo-abc123.wpress", "abc123") is True
    assert llamar("nx_es_critico", "/respaldo.wpress", "abc123") is False


def test_php_lint():
    for nombre in os.listdir(os.path.join(RAIZ, "servidor")):
        if nombre.endswith(".php"):
            out = subprocess.run(["php", "-l", os.path.join(RAIZ, "servidor", nombre)], capture_output=True, text=True)
            assert out.returncode == 0, out.stdout + out.stderr


@pytest.fixture
def servidor(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    puerto = s.getsockname()[1]
    s.close()
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"senuelo_critico": "abc123", "dir_estado": str(tmp_path / "estado")}))
    env = dict(os.environ, NX_CONFIG=str(cfg))
    proc = subprocess.Popen(["php", "-S", "127.0.0.1:%d" % puerto, CANARY], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", puerto), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield "http://127.0.0.1:%d" % puerto, tmp_path / "estado" / "canary.log"
    proc.terminate()
    proc.wait(5)


def pedir(url, cabeceras=None):
    req = urllib.request.Request(url, headers=cabeceras or {})
    try:
        urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers
    raise AssertionError("el canary debe responder 404")


def test_punta_a_punta_registra_y_responde_404_no_cacheable(servidor):
    base, log = servidor
    codigo, cab = pedir(base + "/respaldo-abc123.wpress", {"CF-Connecting-IP": "198.51.100.1", "User-Agent": "escaner"})
    assert codigo == 404
    assert "no-store" in cab.get("Cache-Control", "")
    assert "no-store" in cab.get("Cloudflare-CDN-Cache-Control", "")
    e = json.loads(log.read_text().splitlines()[-1])
    assert e["severidad"] == "critico"
    assert e["ip"] == "127.0.0.1"
    assert e["cabecera_falsificada"] == "198.51.100.1"
    assert e["via_cloudflare"] is False


def test_punta_a_punta_recorta_uri_larga(servidor):
    base, log = servidor
    pedir(base + "/backup.zip?" + "a" * 5000)
    e = json.loads(log.read_text().splitlines()[-1])
    assert len(e["uri"]) == 1000
    assert e["severidad"] == "informativo"
