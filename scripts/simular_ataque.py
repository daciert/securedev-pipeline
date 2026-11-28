"""Simula incidentes de seguridad contra producción para validar la monitorización.

Uso:  python scripts/simular_ataque.py --url http://localhost:5000
  1) Fuerza bruta: intentos de login con contraseñas de un diccionario.
  2) Inyección SQL: payloads clásicos en el formulario de login.
  3) CSRF: peticiones POST forjadas sin token.
Solo para el entorno de laboratorio propio.
"""
import argparse
import collections
import http.cookiejar
import re
import urllib.error
import urllib.parse
import urllib.request


def nuevo_cliente():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def pedir(cliente, url, datos=None):
    cuerpo = urllib.parse.urlencode(datos).encode() if datos is not None else None
    try:
        with cliente.open(url, data=cuerpo, timeout=10) as r:
            return r.status, r.read().decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="ignore")


def token_csrf(cliente, base):
    _, html = pedir(cliente, base + "/login")
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost:5000")
    p.add_argument("--intentos", type=int, default=25)
    a = p.parse_args()
    base = a.url.rstrip("/")

    print(f"[1] Fuerza bruta contra 'admin' ({a.intentos} intentos)")
    cliente = nuevo_cliente()
    codigos = collections.Counter()
    for i in range(a.intentos):
        codigo, _ = pedir(cliente, base + "/login", {"username": "admin", "password": f"clave{i:03d}",
                                                     "csrf_token": token_csrf(cliente, base)})
        codigos[codigo] += 1
    print("    respuestas:", dict(codigos), "(401 = rechazado, 429 = bloqueado)")

    print("[2] Inyección SQL en el login")
    codigos = collections.Counter()
    for payload in ["admin' --", "' OR '1'='1", "admin' OR 1=1 --", "x' UNION SELECT 1,2,3,4,5 --"]:
        cliente = nuevo_cliente()
        codigo, _ = pedir(cliente, base + "/login", {"username": payload, "password": payload,
                                                     "csrf_token": token_csrf(cliente, base)})
        codigos[codigo] += 1
    print("    respuestas:", dict(codigos), "(ninguna debe ser 302 = acceso concedido)")

    print("[3] CSRF: POST forjados sin token")
    codigos = collections.Counter()
    for _ in range(6):
        codigo, _ = pedir(nuevo_cliente(), base + "/update_bio", {"nueva_bio": "CUENTA HACKEADA"})
        codigos[codigo] += 1
    print("    respuestas:", dict(codigos), "(400 = rechazado por falta de token)")


if __name__ == "__main__":
    main()
