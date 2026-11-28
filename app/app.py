"""SecureDev - versión corregida (v2.0).

Mitigaciones aplicadas (ver docs/trazabilidad.md):
  V-01 SQL Injection          -> consultas parametrizadas (placeholders ?)
  V-02 Sesión falsificable    -> sesión firmada de Flask con SECRET_KEY
  V-03 SSTI / V-04 XSS        -> plantillas en archivos con autoescape de Jinja2
  V-05 CSRF                   -> token CSRF por sesión, validado en cada POST
  V-06 Cookie sin flags       -> HttpOnly + SameSite=Strict (+ Secure configurable)
  V-07 Contraseñas planas     -> hash con werkzeug.security (scrypt)
  V-08 Cabeceras ausentes     -> CSP, X-Frame-Options, nosniff y políticas cross-origin
  V-09 Fuerza bruta           -> bloqueo temporal tras 5 intentos fallidos (HTTP 429)
  V-10 Modo debug             -> sin debug; ejecución con gunicorn
"""
import logging
import os
import secrets
import sqlite3
import time

from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

app = Flask(__name__, root_path=os.path.dirname(os.path.abspath(__file__)))
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=1800,
)

DB_PATH = os.environ.get("DB_PATH", "securedev.db")
MAX_INTENTOS = 5          # intentos fallidos permitidos
VENTANA_BLOQUEO = 300     # segundos de bloqueo
MAX_BIO = 280             # largo máximo de la biografía

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("securedev")
_fallidos = {}            # (ip, usuario) -> [timestamps de intentos fallidos]


def db_query(query, params=()):
    """V-01: siempre con parámetros, nunca concatenando la entrada del usuario."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(query, params).fetchall()


# --- V-05: protección CSRF ---------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def validar_csrf():
    if request.method == "POST":
        esperado = session.get("_csrf", "")
        recibido = request.form.get("csrf_token", "")
        if not esperado or not secrets.compare_digest(esperado, recibido):
            log.warning("CSRF rechazado ip=%s ruta=%s", request.remote_addr, request.path)
            abort(400)


# --- V-08: cabeceras de seguridad --------------------------------------------
@app.after_request
def cabeceras_seguridad(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --- V-09: limitación de intentos ---------------------------------------------
def _bloqueado(clave):
    ahora = time.time()
    _fallidos[clave] = [t for t in _fallidos.get(clave, []) if ahora - t < VENTANA_BLOQUEO]
    return len(_fallidos[clave]) >= MAX_INTENTOS


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        clave = (request.remote_addr, user)
        if _bloqueado(clave):
            log.warning("Login BLOQUEADO ip=%s usuario=%r", request.remote_addr, user)
            return render_template("login.html", error="Demasiados intentos. Intente más tarde."), 429

        filas = db_query("SELECT username, password FROM usuarios WHERE username = ?", (user,))
        if filas and check_password_hash(filas[0]["password"], pw):
            _fallidos.pop(clave, None)
            session.clear()                      # evita fijación de sesión
            session["user"] = filas[0]["username"]
            log.info("Login OK ip=%s usuario=%r", request.remote_addr, user)
            return redirect(url_for("dashboard"))

        _fallidos.setdefault(clave, []).append(time.time())
        log.warning("Login FALLIDO ip=%s usuario=%r", request.remote_addr, user)
        return render_template("login.html", error="Acceso denegado"), 401

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    username = session.get("user")              # V-02: sesión firmada, no una cookie editable
    if not username:
        return redirect(url_for("login"))
    datos = db_query("SELECT username, rol, bio FROM usuarios WHERE username = ?", (username,))
    if not datos:
        session.clear()
        return redirect(url_for("login"))
    return render_template("dashboard.html", datos=datos[0])   # V-03/V-04: autoescape


@app.route("/update_bio", methods=["POST"])
def update_bio():
    username = session.get("user")
    if not username:
        return redirect(url_for("login"))
    nueva_bio = request.form.get("nueva_bio", "")[:MAX_BIO]
    db_query("UPDATE usuarios SET bio = ? WHERE username = ?", (nueva_bio, username))
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    return redirect(url_for("login"))


if __name__ == "__main__":
    # V-10: sin debug; en producción se ejecuta con gunicorn (ver Dockerfile)
    app.run(host="127.0.0.1", port=5000)
