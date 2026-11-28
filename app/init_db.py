"""Inicializa la base de datos con contraseñas hasheadas (V-07).
Las contraseñas iniciales se reciben por variables de entorno (nunca en el código)."""
import os
import sqlite3

from werkzeug.security import generate_password_hash

LARGO_MINIMO = 12


def _password(variable):
    valor = os.environ.get(variable, "")
    if len(valor) < LARGO_MINIMO:
        raise SystemExit(f"Defina {variable} con al menos {LARGO_MINIMO} caracteres.")
    return valor


def crear_base_de_datos():
    usuarios = [
        ("admin", generate_password_hash(_password("ADMIN_PASSWORD")), "admin",
         "Cuenta de administrador del sistema."),
        ("alumno", generate_password_hash(_password("ALUMNO_PASSWORD")), "user",
         "Soy un estudiante aprendiendo hacking."),
    ]
    with sqlite3.connect(os.environ.get("DB_PATH", "securedev.db")) as conn:
        conn.execute("DROP TABLE IF EXISTS usuarios")
        conn.execute("""
            CREATE TABLE usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                rol TEXT NOT NULL,
                bio TEXT
            )""")
        conn.executemany("INSERT INTO usuarios (username, password, rol, bio) VALUES (?, ?, ?, ?)", usuarios)
    print("Base de datos inicializada (contraseñas con hash).")


if __name__ == "__main__":
    crear_base_de_datos()
