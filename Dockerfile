# Línea base VULNERABLE (se corrige en commits posteriores)
FROM python:3.11.4-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .
EXPOSE 5000
CMD ["sh", "-c", "python init_db.py && flask --app app run --host=0.0.0.0 --port=5000 --debug"]
