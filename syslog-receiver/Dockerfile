FROM python:3.12-slim

WORKDIR /app

# Corporate pip config (optional)
COPY pip.conf* /etc/

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY receiver.py .

ENV PYTHONUNBUFFERED=1

EXPOSE 5514/tcp
EXPOSE 5514/udp

CMD ["python", "receiver.py"]
