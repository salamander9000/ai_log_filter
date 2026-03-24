FROM python:3.12-slim

WORKDIR /app

# Corporate pip config (optional - copy your pip.conf here for internal mirrors)
# Uses glob so the build won't fail if the file doesn't exist
COPY pip.conf* /etc/

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Don't buffer stdout/stderr so logs appear immediately
ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
