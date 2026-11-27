"""Pruebas funcionales: deben pasar tanto en la versión vulnerable como en la corregida."""
from conftest import ADMIN, ALUMNO, actualizar_bio, login


def test_raiz_redirige_a_login(client):
    r = client.get("/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_formulario_login_disponible(client):
    r = client.get("/login")
    assert r.status_code == 200 and b"Login" in r.data


def test_login_valido_redirige_al_dashboard(client):
    r = login(client, *ADMIN)
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")


def test_login_invalido_es_rechazado(client):
    assert login(client, ADMIN[0], "incorrecta").status_code == 401


def test_dashboard_muestra_datos_del_usuario(client):
    login(client, *ALUMNO)
    r = client.get("/dashboard")
    assert r.status_code == 200 and ALUMNO[0].encode() in r.data


def test_actualizar_biografia(client):
    login(client, *ALUMNO)
    actualizar_bio(client, "Biografia de prueba")
    assert b"Biografia de prueba" in client.get("/dashboard").data


def test_logout_cierra_la_sesion(client):
    login(client, *ALUMNO)
    client.get("/logout")
    r = client.get("/dashboard")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")
