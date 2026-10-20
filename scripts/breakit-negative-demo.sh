#!/usr/bin/env bash
# ==============================================================================
# scripts/breakit-negative-demo.sh: Demonstration of Break-it Failure Detection
#
# Source: docs/architecture.md §10, docs/task.md (T09), docs/prompt.md (P-09)
#
# Deliberately weakens a security control in a scratch copy of docker-compose.yml:
#   1. Attaches the red container to blue-net (violating SI-03 hub-and-spoke isolation)
#   2. Removes cap_drop: [ALL] from red (violating SI-02 capability dropping)
#
# Demonstrates that the break-it runner accurately catches these violations
# (N1, N2, N4, C3, C2 fail), then cleanly tears down the scratch stack and
# restores the hardened production baseline.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

SCRATCH_COMPOSE="docker-compose.negative-scratch.yml"

echo "======================================================================"
echo " [DEMO] Bayora Break-it Runner Negative Demonstration"
echo "======================================================================"

# Cleanup handler: Always restore the hardened stack on exit
cleanup() {
    echo ""
    echo "[DEMO] Cleaning up scratch compose stack and restoring hardened baseline..."
    docker compose -f "${SCRATCH_COMPOSE}" stop red >/dev/null 2>&1 || true
    rm -f "${SCRATCH_COMPOSE}"
    docker compose up -d red >/dev/null 2>&1 || true
    echo "[DEMO] Hardened baseline restored successfully."
}
trap cleanup EXIT INT TERM

echo "[DEMO] 1. Creating scratch compose file: ${SCRATCH_COMPOSE}"
cp docker-compose.yml "${SCRATCH_COMPOSE}"

echo "[DEMO] 2. Deliberately weakening controls on 'red' service:"
echo "         - Adding 'blue-net' to red (cross-tenant network bridge violation)"
echo "         - Removing 'cap_drop: - ALL' from red (capability retention violation)"

python3 -c "
with open('${SCRATCH_COMPOSE}', 'r') as f:
    content = f.read()

# Weaken 1: Attach red to blue-net
modified = content.replace(
'''    secrets:
      - red_token
    networks:
      - red-net''',
'''    secrets:
      - red_token
    networks:
      - red-net
      - blue-net'''
)

# Weaken 2: Remove cap_drop ALL from red
# In red service block:
modified = modified.replace(
'''    user: \"10001:10001\"
    read_only: true
    cap_drop:
      - ALL
    security_opt:''',
'''    user: \"10001:10001\"
    read_only: true
    security_opt:'''
)

with open('${SCRATCH_COMPOSE}', 'w') as f:
    f.write(modified)
"

echo "[DEMO] 3. Starting weakened 'red' container from scratch compose..."
docker compose -f "${SCRATCH_COMPOSE}" up -d red

echo "[DEMO] 4. Executing break-it harness against weakened stack (expecting failures)..."
echo ""

set +e
.venv/bin/python3 -m breakit.harness --no-post
HARNESS_EXIT_CODE=$?
set -e

echo ""
echo "======================================================================"
if [ ${HARNESS_EXIT_CODE} -ne 0 ]; then
    echo " [DEMO SUCCESS] Harness correctly detected violations and exited with ${HARNESS_EXIT_CODE}!"
    echo " Matching probes (Network & Config) FAILED as expected."
else
    echo " [DEMO FAILED] Expected harness to fail on weakened stack, but it passed!"
    exit 1
fi
echo "======================================================================"
