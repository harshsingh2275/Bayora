#!/usr/bin/env bash
# scripts/backup.sh: Archive Bayora audit log and gateway database with SHA-256 checksums
# Architecture references: §4, §8
# Task reference: T12 (Production deployment)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$REPO_ROOT/backups}"
PROJECT="${COMPOSE_PROJECT_NAME:-bayora}"

# Identify volume names
LOG_VOL="${PROJECT}_log-data"
GATEWAY_VOL="${PROJECT}_gateway-data"

if ! docker volume inspect "$LOG_VOL" >/dev/null 2>&1; then
    if docker volume inspect "log-data" >/dev/null 2>&1; then
        LOG_VOL="log-data"
    else
        echo "ERROR: Log volume '$LOG_VOL' not found. Is compose running?" >&2
        exit 1
    fi
fi

if ! docker volume inspect "$GATEWAY_VOL" >/dev/null 2>&1; then
    if docker volume inspect "gateway-data" >/dev/null 2>&1; then
        GATEWAY_VOL="gateway-data"
    else
        echo "ERROR: Gateway volume '$GATEWAY_VOL' not found. Is compose running?" >&2
        exit 1
    fi
fi

mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

TIMESTAMP="$(date -u +"%Y%m%d_%H%M%SZ")"
LOG_ARCHIVE="bayora-log-data-${TIMESTAMP}.tar.gz"
GATEWAY_ARCHIVE="bayora-gateway-data-${TIMESTAMP}.tar.gz"
CHECKSUM_FILE="SHA256SUMS-${TIMESTAMP}.txt"

echo "======================================================================"
echo "Bayora Volume Backup ($TIMESTAMP)"
echo "Destination: $BACKUP_DIR"
echo "Log Volume:  $LOG_VOL"
echo "GW Volume:   $GATEWAY_VOL"
echo "======================================================================"

# 1. Archive log-data (read-only mount in hardened container)
echo "[*] Archiving log volume ($LOG_VOL)..."
docker run --rm \
    --user 10001:10001 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    -v "${LOG_VOL}:/source:ro" \
    python:3.12-slim \
    tar -czf - -C /source . > "${BACKUP_DIR}/${LOG_ARCHIVE}"

# 2. Archive gateway-data (read-only mount in hardened container)
echo "[*] Archiving gateway volume ($GATEWAY_VOL)..."
docker run --rm \
    --user 10001:10001 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    -v "${GATEWAY_VOL}:/source:ro" \
    python:3.12-slim \
    tar -czf - -C /source . > "${BACKUP_DIR}/${GATEWAY_ARCHIVE}"

# 3. Compute SHA-256 checksums
echo "[*] Generating SHA-256 checksums..."
(
    cd "$BACKUP_DIR"
    sha256sum "$LOG_ARCHIVE" "$GATEWAY_ARCHIVE" > "$CHECKSUM_FILE"
    # Also append to master checksum ledger
    cat "$CHECKSUM_FILE" >> "SHA256SUMS"
)

# 4. Verify archive integrity
echo "[*] Verifying archive checksums..."
(
    cd "$BACKUP_DIR"
    sha256sum -c "$CHECKSUM_FILE"
)

echo ""
echo "======================================================================"
echo "Backup Completed Successfully"
echo "======================================================================"
echo "Archives created:"
ls -lh "${BACKUP_DIR}/${LOG_ARCHIVE}" "${BACKUP_DIR}/${GATEWAY_ARCHIVE}"
echo ""
echo "Checksums (${CHECKSUM_FILE}):"
cat "${BACKUP_DIR}/${CHECKSUM_FILE}"
echo "======================================================================"
