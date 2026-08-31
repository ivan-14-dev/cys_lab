FROM python:3.11-slim

LABEL lab="cmd-vulnerable"

RUN useradd -r -u 1000 -s /sbin/nologin labuser && \
    apt-get update && apt-get install -y --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Create lab data file for demonstration
RUN mkdir -p /app/data && \
    echo "LAB_FLAG: COMMAND_INJECTION_DEMONSTRATED\nThis file is for lab demonstration only." \
    > /app/data/lab-secret.txt

# Give labuser read access to the data dir
RUN chown -R labuser:labuser /app

USER labuser

EXPOSE 5000

ENV FLASK_APP=src/app.py \
    FLASK_DEBUG=0 \
    PYTHONUNBUFFERED=1

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
