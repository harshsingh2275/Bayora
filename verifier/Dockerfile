# SECURITY: Pinned base Python version 3.12-slim
FROM python:3.12-slim

# SECURITY SI-02: Create unprivileged user (UID/GID 10001) — non-root, no shell
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

WORKDIR /app

# Install dependencies as root before dropping privileges
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code and trusted public key
COPY app/ /app/app/
COPY trusted_pubkey.pem /app/trusted_pubkey.pem

# SECURITY SI-02: Create log mount point and ensure non-root ownership
RUN mkdir -p /app/log-data && chown -R 10001:10001 /app

USER 10001:10001

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 8002

CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002", "--workers", "1"]
