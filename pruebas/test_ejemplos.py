import os
import re

RAIZ = os.path.dirname(os.path.dirname(__file__))


def _leer(*ruta):
    with open(os.path.join(RAIZ, *ruta), encoding="utf-8") as fh:
        return fh.read()


def test_bloque_de_origen_viene_comentado():
    # Pegado sin editar, el marcador <NOMBRE_CABECERA> deja todo el sitio en 403.
    t = _leer("servidor", "htaccess.ejemplo")
    bloque = t.split("# BEGIN NexaSec Origen", 1)[1].split("# END NexaSec Origen", 1)[0]
    activas = [l for l in bloque.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    assert activas == []


def test_readme_nombra_las_versiones_de_python_del_ci():
    ci = _leer(".github", "workflows", "ci.yml")
    versiones = re.findall(r'"(3\.\d+)"', ci.split("python:", 1)[1].split("\n")[0])
    linea = [l for l in _leer("README.md").splitlines() if "El CI corre" in l][0]
    assert versiones and all(v in linea for v in versiones)
