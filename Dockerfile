# SecureDev v2.0 - imagen endurecida
FROM python:3.15.1-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 appuser
COPY app/ .
RUN chown -R appuser:appuser /app
# V-10: el proceso no corre como root
USER appuser
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/login')"
# V-10: servidor de producción (gunicorn), sin modo debug
CMD ["sh", "-c", "python init_db.py && exec gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 4 --access-logfile - app:app"]
