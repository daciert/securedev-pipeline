# Trazabilidad de seguridad – SecureDev (OCY1102 EV3)

Registro de auditoría de las prácticas de seguridad aplicadas en el SDLC: revisiones, pruebas
automatizadas, gestión de dependencias, despliegue y monitorización.

## 1. Controles del pipeline (Jenkinsfile)

| Etapa SDLC | Etapa Jenkins | Herramienta | Criterio de bloqueo |
|---|---|---|---|
| Código | SAST – Bandit | Bandit | Hallazgos de severidad media o alta |
| Dependencias | SCA – pip-audit | pip-audit + Dependabot (GitHub) | Cualquier CVE conocida |
| Pruebas | Pruebas | pytest (7 funcionales, 9 de seguridad, 2 de monitoreo) | Cualquier prueba fallida |
| Despliegue | Despliegue (staging) | Docker | La app no responde |
| Verificación | DAST – OWASP ZAP | zap-full-scan (reglas en `zap/rules.tsv`) | Alertas WARN/FAIL no justificadas |
| Liberación | Security Gate | Jenkins | Build distinto de SUCCESS |
| Operación | Despliegue (producción) + monitorización | Docker, Prometheus, Grafana | Alertas en `monitoring/alertas.yml` |

## 2. Vulnerabilidades identificadas y mitigadas

| ID | Vulnerabilidad (CWE) | Detectada por | Mitigación | Verificación |
|---|---|---|---|---|
| V-01 | SQL Injection (CWE-89) | Bandit B608, ZAP 40018, test_v01, PoC | Consultas parametrizadas | test_v01, ZAP limpio (build #7) |
| V-02 | Sesión falsificable (CWE-565) | test_v02, PoC cookie | Sesión firmada (SECRET_KEY) | test_v02 |
| V-03 | SSTI (CWE-1336) | test_v03, PoC `{{7*7}}` | `render_template` con archivos | test_v03 |
| V-04 | XSS almacenado (CWE-79) | test_v04 | Autoescape Jinja2 + CSP | test_v04 |
| V-05 | CSRF (CWE-352) | test_v05, `poc/csrf_poc.html` | Token CSRF por sesión | test_v05, ataque simulado (400) |
| V-06 | Cookie sin flags (CWE-1004) | test_v06 | HttpOnly + SameSite=Strict | test_v06 |
| V-07 | Contraseñas en texto plano (CWE-256) | test_v07 | Hash scrypt + credenciales Jenkins | test_v07 |
| V-08 | Cabeceras ausentes (CWE-693/1021) | ZAP 10038, 10020, 10021, 10063, 90004 | CSP, XFO, nosniff, COOP/CORP/COEP | test_v08, ZAP 0 Medium |
| V-09 | Fuerza bruta (CWE-307) | test_v09 | Bloqueo 5 min tras 5 intentos (429) | test_v09, ataque simulado (429) |
| V-10 | Debug activo y root (CWE-94/250) | Bandit B201 | gunicorn, `USER appuser` | Bandit 0 hallazgos |
| V-11 | 17 CVE en dependencias (CWE-1395) | pip-audit, Dependabot | PR #9 (grupo pip) y PR #8 (imagen) | pip-audit 0 |
| V-12 | SECRET_KEY en log (CWE-532) | Revisión log build #8 | Clave generada en el contenedor | Log build #9 |

**Excepción aceptada:** ZAP 90027 *Cookie Slack Detector* (Low) en `/login`: falso positivo, la
página es pública y el token CSRF cambia por diseño. Registrada en `zap/rules.tsv`.

**Riesgos aceptados (laboratorio):** Jenkins corre como root para usar `docker.sock`;
`/metrics` es accesible en el puerto publicado (en producción real se restringiría con un proxy).

## 3. Gestión de dependencias

| Componente | Inicial | Final | Avisos resueltos |
|---|---|---|---|
| Flask | 2.2.2 | 3.1.3 | 2 |
| Werkzeug | 2.2.2 | 3.1.9 | 10 |
| Jinja2 | 3.1.2 | 3.1.6 | 5 |
| MarkupSafe / itsdangerous / click | 2.1.1 / 2.1.2 / 8.1.3 | 3.0.4 / 2.2.0 / 8.5.1 | preventivo |
| Imagen base | python:3.11.4-slim | python:3.15.1-slim | parches SO |
| gunicorn / prometheus-client | — | 27.0.1 / 0.26.0 | nuevas, auditadas |

Política: Dependabot revisa pip a diario y Docker semanalmente; las librerías interdependientes se
agrupan en un solo PR; todo merge a `main` dispara el pipeline, que vuelve a auditar con pip-audit y
ejecuta las pruebas antes de desplegar.

## 4. Matriz build ↔ commit

| Build | Commit | Disparo | Cambio | Resultado |
|---|---|---|---|---|
| #1 | 4b876cb | Manual | Jenkinsfile y pruebas | FAILURE (staging) |
| #2 | e0f611d | Manual | Corrige CMD Dockerfile | FAILURE esperado (vulnerable) |
| #3 | e0f611d | Manual | Re-ejecución | FAILURE (reporte ZAP) |
| #4 | 1c98e3b | SCM | Códigos de salida y logs | FAILURE esperado – línea base en `docs/evidencias/build-04-v1.0-vulnerable` |
| #5 | d81bdaf | SCM | Grupo Dependabot | FAILURE esperado |
| #6 | 83d10e3 | SCM | Merge PR #9 y #8 | SCA OK |
| #7 | b7c17f9 | SCM | Correcciones V-01 a V-10 | 16/16 pruebas; ZAP 1 Low (FP) |
| #8 | 97cb3e2 | SCM | Excepción ZAP 90027 | SUCCESS – producción |
| #9 | 9350087 | SCM | Monitorización + V-12 | SUCCESS – producción con /metrics |

## 5. Incidente simulado (monitorización)

| Fase | Registro |
|---|---|
| Detección | Alertas `FuerzaBrutaLogin` (critical) y `AtaqueCSRF` (warning) en Prometheus/Grafana |
| Análisis | Logs de la app (`Login FALLIDO/BLOQUEADO`, `CSRF rechazado`) con IP de origen |
| Contención | Automática: bloqueo 429 tras 5 intentos y rechazo 400 sin token CSRF |
| Verificación | 0 logins exitosos durante el ataque; servicio en línea; sin errores 5xx |
| Cierre | Alertas resueltas automáticamente; evidencias en el informe |
