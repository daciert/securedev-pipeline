"""Pruebas de monitorización: los eventos de seguridad quedan registrados en /metrics."""
from conftest import ALUMNO, login


def test_metricas_registran_eventos_de_seguridad(client):
    login(client, ALUMNO[0], "incorrecta")                          # login fallido
    client.post("/update_bio", data={"nueva_bio": "sin token"})     # POST sin token CSRF
    metricas = client.get("/metrics").data.decode()
    assert 'securedev_login_intentos_total{resultado="fallido"} 1.0' in metricas
    assert "securedev_csrf_rechazos_total 1.0" in metricas


def test_metricas_registran_login_exitoso(client):
    login(client, *ALUMNO)
    metricas = client.get("/metrics").data.decode()
    assert 'securedev_login_intentos_total{resultado="exito"} 1.0' in metricas
