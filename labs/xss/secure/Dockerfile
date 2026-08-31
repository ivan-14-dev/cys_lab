FROM python:3.11-slim

LABEL lab="xss-secure" \
      description="XSS Secure Lab - Educational Use Only"

RUN useradd -r -u 1000 -s /sbin/nologin labuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

USER labuser

EXPOSE 5000

ENV FLASK_APP=src/app.py \
    FLASK_ENV=development \
    FLASK_DEBUG=0 \
    PYTHONUNBUFFERED=1

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
