# Stage 1: Ephemeral Node build environment
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Hardened Caddy runtime (preserving all existing hardening settings)
# SECURITY: Pinned base Caddy version 2.9-alpine
FROM caddy:2.9-alpine

# SECURITY: Install python3 for healthcheck, remove binary cap on caddy so it executes under no-new-privs, and create user 10001
RUN apk add --no-cache python3 libcap && \
    setcap -r /usr/bin/caddy && \
    apk del libcap && \
    addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup

COPY Caddyfile /etc/caddy/Caddyfile
COPY --from=build --chown=10001:10001 /app/dist /srv

# SECURITY: Ensure unprivileged user owns configuration, data, and server root
RUN mkdir -p /data /config && chown -R 10001:10001 /etc/caddy /srv /data /config

USER 10001:10001

EXPOSE 8080

# SECURITY: Healthcheck using Python standard library
HEALTHCHECK --interval=5s --timeout=3s --retries=3 --start-period=5s \
    CMD ["python3", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/health', timeout=2)"]

ENV PYTHONDONTWRITEBYTECODE=1
