"""Fixtures compartidas: cada prueba usa una base de datos nueva y aislada."""
import importlib.util
import os
import pathlib
import re
import sys

import pytest

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_DIR))

ADMIN = (os.environ.get("TEST_ADMIN_USER", "admin"), os.environ.get("TEST_ADMIN_PASS", "admin123"))
ALUMNO = (os.environ.get("TEST_ALUMNO_USER", "alumno"), os.environ.get("TEST_ALUMNO_PASS", "12345"))


def _cargar(nombre, archivo):
    spec = importlib.util.spec_from_file_location(nombre, APP_DIR / archivo)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "securedev.db"))
    _cargar("init_db", "init_db.py").crear_base_de_datos()
    app = _cargar("securedev_app", "app.py").app
    app.config.update(TESTING=True)
    return app.test_client()


def csrf(client, ruta):
    """Obtiene el token CSRF del formulario si la app lo implementa ('' si no)."""
    r = client.get(ruta)
    m = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', r.data)
    return m.group(1).decode() if m else ""


def login(client, usuario, password):
    return client.post("/login", data={"username": usuario, "password": password,
                                       "csrf_token": csrf(client, "/login")})


def actualizar_bio(client, texto):
    return client.post("/update_bio", data={"nueva_bio": texto,
                                            "csrf_token": csrf(client, "/dashboard")})
