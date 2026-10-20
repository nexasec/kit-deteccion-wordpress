import datetime
import ipaddress
import json
import time

import escalador


def _ts(hace_s):
    return datetime.datetime.fromtimestamp(time.time() - hace_s, datetime.timezone.utc).isoformat(timespec="seconds")


def _log(tmp_path, eventos, extra=()):
    ruta = tmp_path / "canary.log"
    lineas = [json.dumps(e) for e in eventos] + list(extra)
    ruta.write_text("\n".join(lineas) + "\n")
    return str(ruta)


def test_excluye_privadas_cloudflare_y_config():
    excluir = [ipaddress.ip_network("192.0.2.0/24")]
    n = escalador.normalizar
    assert escalador.excluida(n("10.0.0.1"), excluir)
    assert escalador.excluida(n("104.16.0.1"), excluir)
    assert escalador.excluida(n("203.0.113.7"), excluir)
    assert escalador.excluida(n("192.0.2.5"), excluir)
    assert not escalador.excluida(n("8.8.8.8"), excluir)


def test_desde_canary_motivos(tmp_path):
    eventos = [
        {"ts": _ts(60), "ip": "203.0.113.1", "uri": "/respaldo-x.wpress", "severidad": "critico"},
        {"ts": _ts(60), "ip": "203.0.113.2", "uri": "/backup.zip", "cabecera_falsificada": "198.51.100.1"},
        {"ts": _ts(60), "ip": "203.0.113.3", "uri": "/backup.zip", "via_cloudflare": False},
        {"ts": _ts(60), "ip": "203.0.113.4", "uri": "/a.zip"},
        {"ts": _ts(60), "ip": "203.0.113.4", "uri": "/b.sql?x=1"},
        {"ts": _ts(60), "ip": "203.0.113.4", "uri": "/c.wpress"},
        {"ts": _ts(5 * 86400), "ip": "203.0.113.5", "uri": "/viejo.zip", "severidad": "critico"},
    ]
    ruta = _log(tmp_path, eventos, extra=["{linea rota"])
    cands = {}
    escalador.desde_canary(cands, 24 * 3600, ruta)
    assert "senuelo_critico" in cands["203.0.113.1"]["motivos"]
    assert "cabecera_falsificada" in cands["203.0.113.2"]["motivos"]
    assert "origen_directo" in cands["203.0.113.3"]["motivos"]
    assert "escaneo_senuelos" in cands["203.0.113.4"]["motivos"]
    assert "203.0.113.5" not in cands


def test_dos_senuelos_no_es_escaneo(tmp_path):
    ruta = _log(tmp_path, [{"ts": _ts(60), "ip": "203.0.113.4", "uri": "/a.zip"},
                           {"ts": _ts(60), "ip": "203.0.113.4", "uri": "/b.zip"}])
    cands = {}
    escalador.desde_canary(cands, 24 * 3600, ruta)
    assert "203.0.113.4" not in cands


def test_log_ausente_no_falla(tmp_path):
    cands = {}
    escalador.desde_canary(cands, 3600, str(tmp_path / "no-existe.log"))
    assert cands == {}


def test_prioridad_dirigido_antes_que_ruido():
    dirigido = escalador.nuevo()
    escalador.anotar(dirigido, "senuelo_critico", "x", 1)
    ruido = escalador.nuevo()
    escalador.anotar(ruido, "wfsn", "y", 500)
    assert escalador.prioridad(dirigido) > escalador.prioridad(ruido)


def test_no_repropone_en_7_dias_y_tope_5():
    ahora = time.time()
    cands = {}
    for i in range(1, 8):
        c = escalador.nuevo()
        escalador.anotar(c, "waf", "w", i)
        cands["203.0.113.%d" % i] = c
    estado = {"203.0.113.7": ahora - 2 * 86400}
    a_enviar, excluidas, recientes, pendientes = escalador.seleccionar(
        cands, estado, lambda ip: False, ahora, 5)
    assert len(a_enviar) == 5
    assert recientes == ["203.0.113.7"]
    assert excluidas == []
    assert pendientes == 1
    # Ordenados por prioridad: mas eventos primero entre motivos iguales.
    assert a_enviar[0][0] == "203.0.113.6"


def test_sql_usa_dominio_y_prefijo():
    sql = escalador.sql_wordfence(3600, "ejemplo.cl", "wpx_")
    assert "'ejemplo.cl'" in sql
    assert "wpx_wfhits" in sql
    assert "nexasec" not in sql


def test_sql_rechaza_prefijo_inseguro():
    import pytest
    with pytest.raises(ValueError):
        escalador.sql_wordfence(3600, "ejemplo.cl", "wp_; DROP TABLE x;--")
    with pytest.raises(ValueError):
        escalador.sql_wordfence(3600, "ejemplo.cl'--", "wp_")


def test_main_sin_config_no_lanza(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.json"
    cfg.write_text("{}")
    monkeypatch.setenv("NX_CONFIG", str(cfg))
    monkeypatch.setattr("sys.argv", ["escalador.py", "--simular"])
    escalador.main()
    salida = capsys.readouterr().out
    assert "raiz_web" in salida
