FROM python:3.11-slim
LABEL lab="pathtraversal-vulnerable"
RUN useradd -r -u 1000 -s /sbin/nologin labuser
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
RUN mkdir -p /app/files && \
    echo "Rapport Q1 2024 - Revenus: 1.2M EUR" > /app/files/report-q1.txt && \
    echo "Rapport Q2 2024 - Revenus: 1.5M EUR" > /app/files/report-q2.txt && \
    echo "Guide utilisateur - Version 3.2" > /app/files/manual.txt && \
    chown -R labuser:labuser /app
USER labuser
EXPOSE 5000
ENV FLASK_APP=src/app.py FLASK_DEBUG=0 PYTHONUNBUFFERED=1
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
