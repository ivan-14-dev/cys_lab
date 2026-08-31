FROM python:3.11-slim

LABEL lab="xss-vulnerable" \
      description="XSS Vulnerable Lab - Educational Use Only" \
      maintainer="Injection Security Lab"

# Create non-root user
RUN useradd -r -u 1000 -s /sbin/nologin labuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Drop to non-root
USER labuser

EXPOSE 5000

ENV FLASK_APP=src/app.py \
    FLASK_ENV=development \
    FLASK_DEBUG=0 \
    PYTHONUNBUFFERED=1

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
