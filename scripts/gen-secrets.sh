#!/usr/bin/env bash
# scripts/gen-secrets.sh: Generate tokens and cryptographic keys for Bayora
# SECURITY: Secrets are mode 0644 inside 0700 secrets/ so unprivileged container
# users (10001) can read mounted secrets while host users cannot access the directory.
# Values are never printed or logged.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SECRETS_DIR="$REPO_ROOT/secrets"
VERIFIER_DIR="$REPO_ROOT/verifier"

FORCE=false
for arg in "$@"; do
    if [ "$arg" == "--force" ]; then
        FORCE=true
    fi
done

# Check if secrets already exist
if [ -d "$SECRETS_DIR" ] && [ -n "$(ls -A "$SECRETS_DIR" 2>/dev/null)" ] && [ "$FORCE" = false ]; then
    echo "Error: Secrets already exist in $SECRETS_DIR. Use --force to overwrite." >&2
    exit 1
fi

mkdir -p "$SECRETS_DIR"
chmod 0700 "$SECRETS_DIR"
mkdir -p "$VERIFIER_DIR"

echo "Generating tenant, admin, and logger tokens..."

# Red token and hash
red_token=$(openssl rand -hex 32)
printf "%s\n" "$red_token" > "$SECRETS_DIR/red_token"
printf "%s\n" "$(printf "%s" "$red_token" | sha256sum | awk '{print $1}')" > "$SECRETS_DIR/red_token_sha256"

# Blue token and hash
blue_token=$(openssl rand -hex 32)
printf "%s\n" "$blue_token" > "$SECRETS_DIR/blue_token"
printf "%s\n" "$(printf "%s" "$blue_token" | sha256sum | awk '{print $1}')" > "$SECRETS_DIR/blue_token_sha256"

# Admin token and hash (admin plain token is for operator only, never mounted into containers)
admin_token=$(openssl rand -hex 32)
printf "%s\n" "$admin_token" > "$SECRETS_DIR/admin_token"
printf "%s\n" "$(printf "%s" "$admin_token" | sha256sum | awk '{print $1}')" > "$SECRETS_DIR/admin_token_sha256"

# Logger shared secret token
logger_token=$(openssl rand -hex 32)
printf "%s\n" "$logger_token" > "$SECRETS_DIR/logger_token"

echo "Generating Ed25519 log signing keypair..."
openssl genpkey -algorithm ed25519 -out "$SECRETS_DIR/log_signing_key" 2>/dev/null
openssl pkey -in "$SECRETS_DIR/log_signing_key" -pubout -out "$VERIFIER_DIR/trusted_pubkey.pem" 2>/dev/null

# SECURITY: File mode 0644 required so non-root container user (10001:10001) can read mounted file secrets
chmod 0644 "$SECRETS_DIR"/*
chmod 0644 "$VERIFIER_DIR/trusted_pubkey.pem"
chmod 0700 "$SECRETS_DIR"

echo "Secrets generated successfully:"
echo " - $SECRETS_DIR/red_token"
echo " - $SECRETS_DIR/red_token_sha256"
echo " - $SECRETS_DIR/blue_token"
echo " - $SECRETS_DIR/blue_token_sha256"
echo " - $SECRETS_DIR/admin_token"
echo " - $SECRETS_DIR/admin_token_sha256"
echo " - $SECRETS_DIR/logger_token"
echo " - $SECRETS_DIR/log_signing_key"
echo " - $VERIFIER_DIR/trusted_pubkey.pem"
