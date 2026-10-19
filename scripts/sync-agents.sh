#!/usr/bin/env bash
# scripts/sync-agents.sh: Keep AGENTS.md synchronized with docs/agents.md
# SECURITY: AGENTS.md enforces the security invariants for any agent session.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SOURCE="$REPO_ROOT/docs/agents.md"
TARGET="$REPO_ROOT/AGENTS.md"

if [ ! -f "$SOURCE" ]; then
    echo "Error: Source file $SOURCE does not exist." >&2
    exit 1
fi

cp "$SOURCE" "$TARGET"
echo "Synchronized: $SOURCE -> $TARGET"

if cmp -s "$SOURCE" "$TARGET"; then
    echo "Verification passed: AGENTS.md matches docs/agents.md"
else
    echo "Error: Verification failed after copying." >&2
    exit 1
fi
