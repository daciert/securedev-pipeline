# SecureDev – Pipeline DevSecOps (OCY1102 EV3)

Pipeline CI/CD con Jenkins + Docker que integra SAST (Bandit), SCA (pip-audit + Dependabot),
DAST (OWASP ZAP) y monitorización (Prometheus + Grafana) sobre una app Flask vulnerable.

| Carpeta | Contenido |
|---|---|
| `app/` | Aplicación Flask (versión vulnerable en `v1.0-vulnerable`, corregida en `v2.0-secure`) |
| `poc/` | Pruebas de concepto de explotación |
| `monitoring/` | Configuración de Prometheus / Grafana |
| `docs/` | Bitácora de seguridad y matriz de trazabilidad |
| `.github/dependabot.yml` | Gestión automática de dependencias |
