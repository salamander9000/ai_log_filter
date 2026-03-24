FROM python:3.12-slim

WORKDIR /app

COPY generate_syslog.py .

ENV PYTHONUNBUFFERED=1
ENV OUTPUT_FILE=/var/log/synthetic/syslog
ENV EVENTS_PER_SEC=5
ENV ANOMALY_RATIO=0.05

CMD ["python", "generate_syslog.py"]
