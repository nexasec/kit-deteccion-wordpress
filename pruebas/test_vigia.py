import os

import pytest

import vigia

FEED = os.path.join(os.path.dirname(__file__), "datos", "feed-wordfence.json")


def test_vcmp_bordes():
    assert vigia.vcmp("4.10", "4.9") == 1
    assert vigia.vcmp("1.0", "1.0.0") == -1
    assert vigia.vcmp("1.0RC1", "1.0") == -1
    assert vigia.vcmp("2.0.1", "2.0.1") == 0
    assert vigia.vcmp("1.0-beta", "1.0-alpha") == 1


def test_en_rango_inclusivo_y_exclusivo():
    r = {"from_version": "1.0", "to_version": "2.0", "from_inclusive": True, "to_inclusive": False}
    assert vigia.en_rango("1.0", r)
    assert not vigia.en_rango("2.0", r)
    assert vigia.en_rango("1.9.9", r)
    assert not vigia.en_rango("0.9", r)
    assert vigia.en_rango("99", {"from_version": "*", "to_version": "*"})


def test_cruzar_detecta_vulnerable_y_sin_cobertura():
    plugins = [{"name": "formularios", "version": "1.1.0"},
               {"name": "galeria", "version": "3.0.1"},
               {"name": "propio", "version": "1.0"}]
    n, vulnerables, sin_cobertura = vigia.cruzar(FEED, "6.8", plugins, [])
    assert n == 2
    assert [v["slug"] for v in vulnerables] == ["formularios"]
    assert vulnerables[0]["cve"] == "CVE-2026-00001"
    assert vulnerables[0]["parche"] == ["1.2.1"]
    assert "plugin:propio" in sin_cobertura
    assert "plugin:galeria" not in sin_cobertura


def test_parsear_whois_nic():
    texto = "Domain name: ejemplo.cl\nExpiration date: 2027-01-15 12:00:00 CLST\n"
    assert vigia.parsear_whois_nic(texto) == "2027-01-15T12:00:00-03:00"
    with pytest.raises(RuntimeError):
        vigia.parsear_whois_nic("No match for domain")


def test_origen_sin_ip_falla_explicito(monkeypatch):
    def no_llamar(*a, **k):
        raise AssertionError("no debe pedir nada sin origen_ip")
    monkeypatch.setattr(vigia, "pedir_directo", no_llamar)
    monkeypatch.setattr(vigia, "pedir_cloudflare", no_llamar)
    r = vigia.chequeo_origen({"dominio": "ejemplo.cl"})
    assert r["ok"] is False
    assert any("origen_ip" in f for f in r["fallos"])


def test_origen_sin_dominio_falla_explicito(monkeypatch):
    monkeypatch.setattr(vigia, "pedir_directo", lambda *a: (_ for _ in ()).throw(AssertionError()))
    r = vigia.chequeo_origen({"origen_ip": "198.51.100.10"})
    assert r["ok"] is False
    assert any("dominio" in f for f in r["fallos"])


def test_origen_cerrado_ok(monkeypatch):
    monkeypatch.setattr(vigia, "pedir_directo", lambda ip, dom, ruta: (403, "Forbidden"))
    monkeypatch.setattr(vigia, "pedir_cloudflare", lambda dom: (200, "cloudflare", True))
    r = vigia.chequeo_origen({"dominio": "ejemplo.cl", "origen_ip": "198.51.100.10"})
    assert r["ok"] is True and r["fallos"] == []


def test_plugins_sin_whois_no_consulta(tmp_path, monkeypatch):
    def no_llamar(*a):
        raise AssertionError("no debe consultar whois")
    monkeypatch.setattr(vigia, "vencimiento_dominio", no_llamar)
    monkeypatch.setattr(vigia, "inventario", lambda cfg: ("6.8", [], []))
    r = vigia.chequeo_plugins({"dominio": "ejemplo.cl", "dir_estado": str(tmp_path)})
    assert "dominio_vence" not in r
    assert any("wordfence_api_key" in e for e in r["errores"])


def test_plugins_con_whois_consulta(tmp_path, monkeypatch):
    monkeypatch.setattr(vigia, "vencimiento_dominio", lambda d: "2027-01-15T12:00:00-03:00")
    monkeypatch.setattr(vigia, "inventario", lambda cfg: ("6.8", [], []))
    r = vigia.chequeo_plugins({"dominio": "ejemplo.cl", "dir_estado": str(tmp_path), "whois_nic_chile": True})
    assert r["dominio_vence"] == "2027-01-15T12:00:00-03:00"
