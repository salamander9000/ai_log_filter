FROM python:3.12-slim

WORKDIR /app

# Corporate pip config (optional)
COPY pip.conf* /etc/

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

# librdkafka is required by confluent-kafka Python package
RUN apt-get update && apt-get install -y --no-install-recommends \
    librdkafka-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Don't buffer stdout/stderr so logs appear immediately
ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
