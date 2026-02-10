FROM python:3.12-slim

# (opcjonalnie) systemowe zależności do budowania paczek
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1) requirements
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 2) kod + dane + templates
COPY src /app/src
COPY data /app/data
COPY templates /app/templates

# python ma widzieć src/
ENV PYTHONPATH=/app/src

EXPOSE 8000

# start aplikacji FastAPI
CMD ["python", "-m", "awsas.core.webapp"]