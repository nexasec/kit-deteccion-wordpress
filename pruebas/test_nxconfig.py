import json
import os

import nxconfig


def test_ruta_por_variable(monkeypatch):
    monkeypatch.setenv("NX_CONFIG", "/tmp/x.json")
    assert nxconfig.ruta_config() == "/tmp/x.json"


def test_ruta_por_defecto(monkeypatch):
    monkeypatch.delenv("NX_CONFIG", raising=False)
    assert nxconfig.ruta_config() == os.path.expanduser("~/nx-kit/config.json")


def test_config_ausente_es_vacia(tmp_path):
    assert nxconfig.cargar_config(str(tmp_path / "no-existe.json")) == {}


def test_config_invalida_es_vacia(tmp_path):
    ruta = tmp_path / "config.json"
    ruta.write_text("{no json")
    assert nxconfig.cargar_config(str(ruta)) == {}


def test_config_valida(tmp_path):
    ruta = tmp_path / "config.json"
    ruta.write_text(json.dumps({"dominio": "ejemplo.cl"}))
    assert nxconfig.cargar_config(str(ruta)) == {"dominio": "ejemplo.cl"}


def test_dir_estado_por_defecto_es_la_carpeta_del_config(tmp_path):
    ruta = tmp_path / "kit" / "config.json"
    d = nxconfig.dir_estado({}, str(ruta))
    assert d == str(tmp_path / "kit")
    assert os.path.isdir(d)


def test_dir_estado_explicito(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    d = nxconfig.dir_estado({"dir_estado": "~/estado"}, str(tmp_path / "config.json"))
    assert d == str(tmp_path / "estado")
    assert oct(os.stat(d).st_mode & 0o777) == "0o700"


def test_requerir_lista_faltantes():
    assert nxconfig.requerir({"a": "", "b": "x"}, "a", "b", "c") == ["a", "c"]
