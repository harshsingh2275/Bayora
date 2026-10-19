# gateway/Dockerfile
# SECURITY: Pinned Python 3.12-slim base; no latest tag (AGENTS.md §7)
FROM python:3.12-slim

# SECURITY SI-02: Create unprivileged user (UID/GID 10001) — non-root, no shell
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

WORKDIR /app

# Install dependencies as root before dropping privileges
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY app/ /app/app/

# SECURITY SI-02: Create the data directory for the SQLite volume mount
# and transfer ownership so the non-root user can write to it
RUN mkdir -p /app/data && chown -R 10001:10001 /app

# SECURITY SI-02: Drop to non-root user for all subsequent commands
USER 10001:10001

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Expose internal port only (no published port; handled by docker-compose)
EXPOSE 8000

# Run uvicorn with the FastAPI app; single worker (one DB connection)
CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
