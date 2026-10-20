import json
import os

import watchdog


def _sitio(tmp_path):
    raiz = tmp_path / "sitio"
    (raiz / "wp-content" / "uploads" / "2026" / "10").mkdir(parents=True)
    (raiz / "wp-content" / "mu-plugins").mkdir(parents=True)
    (raiz / "wp-config.php").write_text("<?php // config")
    (raiz / "wp-content" / "mu-plugins" / "propio.php").write_text("<?php // aaaa")
    return raiz


def test_php_en_uploads_es_nuevo(tmp_path):
    raiz = _sitio(tmp_path)
    previo = watchdog.inventario(str(raiz))
    (raiz / "wp-content" / "uploads" / "2026" / "10" / "x.php").write_text("<?php system($_GET['c']);")
    diff = watchdog.comparar(previo, watchdog.inventario(str(raiz)))
    assert diff["nuevos"] == ["wp-content/uploads/2026/10/x.php"]


def test_mu_plugin_modificado_con_mismo_tamano_y_fecha(tmp_path):
    raiz = _sitio(tmp_path)
    ruta = raiz / "wp-content" / "mu-plugins" / "propio.php"
    previo = watchdog.inventario(str(raiz))
    st = os.stat(ruta)
    ruta.write_text("<?php // bbbb")  # mismo tamano
    os.utime(ruta, (st.st_atime, st.st_mtime))  # como `touch -r`
    diff = watchdog.comparar(previo, watchdog.inventario(str(raiz)))
    assert diff["modificados"] == ["wp-content/mu-plugins/propio.php"]


def test_respaldo_profundo_se_ignora(tmp_path):
    raiz = _sitio(tmp_path)
    (raiz / "a" / "b" / "c" / "d").mkdir(parents=True)
    (raiz / "a" / "b" / "c" / "d" / "backup.zip").write_text("x")
    (raiz / "wp-content" / "backup.zip").write_text("x")
    inv = watchdog.inventario(str(raiz))
    assert "wp-content/backup.zip" in inv
    assert "a/b/c/d/backup.zip" not in inv


def test_eliminado(tmp_path):
    raiz = _sitio(tmp_path)
    previo = watchdog.inventario(str(raiz))
    (raiz / "wp-config.php").unlink()
    diff = watchdog.comparar(previo, watchdog.inventario(str(raiz)))
    assert diff["eliminados"] == ["wp-config.php"]


def test_severidad():
    actual = {"a": [1, 1]}
    vacio = {"nuevos": [], "modificados": [], "eliminados": []}
    assert watchdog.construir_evento("ejemplo.cl", actual, dict(vacio, nuevos=["a"]))["severidad"] == "critico"
    assert watchdog.construir_evento("ejemplo.cl", actual, dict(vacio, modificados=["a"]))["severidad"] == "critico"
    assert watchdog.construir_evento("ejemplo.cl", actual, dict(vacio, eliminados=["b"]))["severidad"] == "ok"


def test_host_sale_de_config():
    vacio = {"nuevos": [], "modificados": [], "eliminados": []}
    evento = watchdog.construir_evento("ejemplo.cl", {}, vacio)
    assert evento["host"] == "ejemplo.cl"
    assert evento["origen"] == "watchdog"


def test_sin_raiz_web_late_down(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    cfg.write_text('{"push_url": "https://kuma.ejemplo.cl/api/push/x"}')
    monkeypatch.setenv("NX_CONFIG", str(cfg))
    latidos = []
    monkeypatch.setattr(watchdog, "latir", lambda c, estado, msg: latidos.append((estado, msg)))
    watchdog.main()
    assert len(latidos) == 1
    assert latidos[0][0] == "down"
    assert "raiz_web" in latidos[0][1]


def test_primera_corrida_crea_base_sin_alertar(tmp_path, monkeypatch):
    raiz = _sitio(tmp_path)
    cfg = tmp_path / "config.json"
    cfg.write_text('{"raiz_web": "%s", "dominio": "ejemplo.cl"}' % raiz)
    monkeypatch.setenv("NX_CONFIG", str(cfg))
    enviados, latidos = [], []
    monkeypatch.setattr(watchdog, "enviar_a_n8n", lambda c, e: enviados.append(e) or (True, "ok"))
    monkeypatch.setattr(watchdog, "latir", lambda c, estado, msg: latidos.append(estado))
    watchdog.main()
    assert (tmp_path / "inventory-v2.json").exists()
    assert enviados == [] and latidos == ["up"]
    (raiz / "wp-content" / "uploads" / "shell.php").write_text("<?php")
    watchdog.main()
    assert enviados[0]["nuevos"] == [{"ruta": "wp-content/uploads/shell.php", "bytes": 5}]


def _config(tmp_path, **valores):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(valores))
    return str(cfg)


def test_raiz_inexistente_late_down(tmp_path, monkeypatch):
    monkeypatch.setenv("NX_CONFIG", _config(tmp_path, raiz_web=str(tmp_path / "no-existe")))
    latidos = []
    monkeypatch.setattr(watchdog, "latir", lambda c, estado, msg: latidos.append((estado, msg)))
    watchdog.main()
    assert latidos and latidos[-1][0] == "down"
    assert "raiz_web" in latidos[-1][1]
    assert not (tmp_path / "inventory-v2.json").exists()


def test_raiz_sin_wp_content_late_down(tmp_path, monkeypatch):
    (tmp_path / "otra-cosa").mkdir()
    monkeypatch.setenv("NX_CONFIG", _config(tmp_path, raiz_web=str(tmp_path / "otra-cosa")))
    latidos = []
    monkeypatch.setattr(watchdog, "latir", lambda c, estado, msg: latidos.append((estado, msg)))
    watchdog.main()
    assert latidos[-1][0] == "down"


class _Respuesta:
    def __init__(self, tipo, cuerpo):
        self.headers = {"Content-Type": tipo}
        self._cuerpo = cuerpo

    def read(self, *a):
        return self._cuerpo

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_entrega_que_devuelve_html_no_cuenta(monkeypatch):
    monkeypatch.setattr(watchdog.urllib.request, "urlopen",
                        lambda req, timeout=None: _Respuesta("text/html; charset=utf-8", b"<html>login</html>"))
    ok, detalle = watchdog.enviar_a_n8n({"webhook_watchdog": "https://n8n.ejemplo.cl/webhook/x"}, {"a": 1})
    assert ok is False
    assert "inesperada" in detalle


def test_entrega_json_cuenta(monkeypatch):
    monkeypatch.setattr(watchdog.urllib.request, "urlopen",
                        lambda req, timeout=None: _Respuesta("application/json", b'{"ok":true}'))
    ok, _ = watchdog.enviar_a_n8n({"webhook_watchdog": "https://n8n.ejemplo.cl/webhook/x"}, {"a": 1})
    assert ok is True


def test_fallo_de_entrega_conserva_la_base(tmp_path, monkeypatch):
    raiz = _sitio(tmp_path)
    monkeypatch.setenv("NX_CONFIG", _config(tmp_path, raiz_web=str(raiz)))
    monkeypatch.setattr(watchdog, "latir", lambda c, estado, msg: None)
    watchdog.main()  # linea base
    (raiz / "wp-content" / "uploads" / "shell.php").write_text("<?php")
    monkeypatch.setattr(watchdog, "enviar_a_n8n", lambda c, e: (False, "n8n caido"))
    watchdog.main()
    enviados = []
    monkeypatch.setattr(watchdog, "enviar_a_n8n", lambda c, e: enviados.append(e) or (True, "entregado"))
    watchdog.main()
    assert enviados and enviados[0]["nuevos"][0]["ruta"] == "wp-content/uploads/shell.php"
