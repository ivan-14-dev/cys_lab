FROM python:3.11-slim
LABEL lab="xpath-vulnerable"
RUN useradd -r -u 1000 -s /sbin/nologin labuser && \
    apt-get update && apt-get install -y --no-install-recommends libxml2 libxslt1.1 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
RUN chown -R labuser:labuser /app
USER labuser
EXPOSE 5000
ENV FLASK_APP=src/app.py FLASK_DEBUG=0 PYTHONUNBUFFERED=1
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
