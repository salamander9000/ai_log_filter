FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Don't buffer stdout/stderr so logs appear immediately
ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
