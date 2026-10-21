#!/usr/bin/env bash
# scripts/model-smoke.sh: Smoke test for Bayora model service
# Sends one chat request from a throwaway container attached to model-net
# and prints the reply and latency.
set -euo pipefail

TARGET="${1:-red}"
if [ "$TARGET" = "blue" ]; then
    NETWORK_NAME="${COMPOSE_PROJECT_NAME:-bayora}_model-blue-net"
    MODEL_HOST="${MODEL_HOST:-model-blue}"
else
    NETWORK_NAME="${COMPOSE_PROJECT_NAME:-bayora}_model-red-net"
    MODEL_HOST="${MODEL_HOST:-model-red}"
fi
MODEL_PORT="${MODEL_PORT:-8080}"

echo "=== Bayora Model Smoke Test (${MODEL_HOST}) ==="
echo "Target Network: ${NETWORK_NAME}"
echo "Target Endpoint: http://${MODEL_HOST}:${MODEL_PORT}/v1/chat/completions"

# Verify network exists
if ! docker network inspect "${NETWORK_NAME}" >/dev/null 2>&1; then
    echo "ERROR: Docker network '${NETWORK_NAME}' not found. Is compose running?" >&2
    exit 1
fi

echo "Running smoke request from throwaway container..."

docker run --rm \
    --network "${NETWORK_NAME}" \
    --user 10001:10001 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    python:3.12-slim python3 -c "
import urllib.request
import json
import time
import sys

url = 'http://${MODEL_HOST}:${MODEL_PORT}/v1/chat/completions'
payload = {
    'messages': [
        {'role': 'user', 'content': 'What is 2+2? Answer in one short sentence.'}
    ],
    'max_tokens': 32,
    'temperature': 0
}

data = json.dumps(payload).encode('utf-8')
headers = {'Content-Type': 'application/json'}
req = urllib.request.Request(url, data=data, headers=headers, method='POST')

t0 = time.perf_counter()
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        body = json.loads(resp.read().decode('utf-8'))
except Exception as e:
    print(f'ERROR: Request to model failed: {e}', file=sys.stderr)
    sys.exit(1)

content = body.get('choices', [{}])[0].get('message', {}).get('content', '').strip()
usage = body.get('usage', {})
timings = body.get('timings', {})

print('----------------------------------------')
print('MODEL REPLY:')
print(content)
print('----------------------------------------')
print(f'Wall Latency:        {elapsed_ms:.2f} ms')
if usage:
    print(f'Prompt Tokens:       {usage.get(\"prompt_tokens\", \"N/A\")}')
    print(f'Completion Tokens:   {usage.get(\"completion_tokens\", \"N/A\")}')
    print(f'Total Tokens:        {usage.get(\"total_tokens\", \"N/A\")}')
if timings:
    pred_s = timings.get('predicted_per_second')
    if pred_s is not None:
        print(f'Generation Speed:    {pred_s:.2f} tokens/s')
print('----------------------------------------')
print('STATUS: SMOKE TEST PASSED')
"
