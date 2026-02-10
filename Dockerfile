FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src /app/src
COPY templates /app/templates
COPY scripts /app/scripts

ENV PYTHONPATH=/app/src

RUN mkdir -p /app/data /app/runs

EXPOSE 8000

CMD ["python", "-m", "awsas.core.webapp"]