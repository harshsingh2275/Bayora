# SECURITY: Pinned base Python version 3.12-slim
FROM python:3.12-slim

# SECURITY: Create unprivileged user (UID/GID 10001) per SI-02
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

WORKDIR /app
COPY . /app

# Ensure mount point exists and provide symlink for /data/pool.jsonl
RUN mkdir -p /data/red && ln -s /data/red/pool.jsonl /data/pool.jsonl
RUN chown -R 10001:10001 /app

USER 10001:10001

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

CMD ["python3", "agent.py"]
