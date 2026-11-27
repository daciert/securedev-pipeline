"""Pruebas de regresión de seguridad (una por vulnerabilidad identificada).
Fallan en la versión vulnerable (v1.0) y deben pasar tras las correcciones."""
import os
import sqlite3

from conftest import ADMIN, ALUMNO, actualizar_bio, login


def test_v01_login_resiste_sql_injection(client):
    """V-01 SQL Injection en login (CWE-89)."""
    assert login(client, "admin' --", "x").status_code == 401
    assert login(client, "admin", "' OR '1'='1").status_code == 401


def test_v02_cookie_de_sesion_no_falsificable(client):
    """V-02 Autenticación rota: cookie con el usuario en texto plano (CWE-565)."""
    atacante = client.application.test_client(use_cookies=False)
    r = atacante.get("/dashboard", headers={"Cookie": "user_session=admin"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_v03_plantilla_no_evalua_ssti(client):
    """V-03 Server-Side Template Injection (CWE-1336)."""
    login(client, *ALUMNO)
    actualizar_bio(client, "{{7*7}}")
    assert b"49" not in client.get("/dashboard").data


def test_v04_xss_almacenado_escapado(client):
    """V-04 Cross-Site Scripting almacenado (CWE-79)."""
    login(client, *ALUMNO)
    actualizar_bio(client, "<script>alert(1)</script>")
    assert b"<script>alert(1)</script>" not in client.get("/dashboard").data


def test_v05_update_bio_exige_token_csrf(client):
    """V-05 Cross-Site Request Forgery (CWE-352)."""
    login(client, *ALUMNO)
    client.post("/update_bio", data={"nueva_bio": "CUENTA HACKEADA"})
    assert b"CUENTA HACKEADA" not in client.get("/dashboard").data


def test_v06_cookie_de_sesion_con_flags(client):
    """V-06 Cookie sin HttpOnly / SameSite (CWE-1004)."""
    r = login(client, *ADMIN)
    cookies = " ".join(r.headers.getlist("Set-Cookie"))
    assert "HttpOnly" in cookies and "SameSite" in cookies


def test_v07_contrasenas_no_en_texto_plano(client):
    """V-07 Contraseñas almacenadas en texto plano (CWE-256)."""
    db = os.environ["DB_PATH"] if os.path.exists(os.environ["DB_PATH"]) else "vulnerable.db"
    with sqlite3.connect(db) as conn:
        guardada = conn.execute("SELECT password FROM usuarios WHERE username = ?", (ADMIN[0],)).fetchone()[0]
    assert guardada != ADMIN[1]


def test_v08_cabeceras_de_seguridad(client):
    """V-08 Ausencia de cabeceras de seguridad (CWE-693 / CWE-1021)."""
    h = client.get("/login").headers
    for cabecera in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"):
        assert cabecera in h, f"Falta la cabecera {cabecera}"


def test_v09_fuerza_bruta_limitada(client):
    """V-09 Sin límite de intentos de login (CWE-307)."""
    codigos = [login(client, ALUMNO[0], f"mala{i}").status_code for i in range(6)]
    assert codigos[-1] == 429
