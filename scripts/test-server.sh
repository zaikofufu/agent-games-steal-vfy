#!/usr/bin/env bash
# Smoke-test the built server locally:
#  - GET /agent (health)
#  - POST /agent with an INVALID signature (expect 403)
#  - POST /agent with a VALID signature + a turn envelope
#    (expect 200 EXTRACT; proof is null without circuit artifacts,
#    unless VFY_POLICY_WASM/VFY_POLICY_ZKEY point at real files)
# Usage: AGENT_SECRET=<redacted>
# Exits non-zero if any check fails.
set -euo pipefail
cd "$(dirname "$0")/.."
npm run build

export AGENT_SECRET=test-secret-for-steal-vfy
export PORT="${PORT:-3457}"
node dist/index.js &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

# Wait for the health endpoint (up to 10s); fail loudly if it never comes up.
for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:$PORT/agent" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$PORT/agent" >/dev/null || { echo "FAIL: server did not come up"; exit 1; }

check() { # check <label> <expected-status> <curl-args...>
  local label="$1" expected="$2"; shift 2
  local got
  got=$(curl -sS -o /tmp/sv-resp.json -w "%{http_code}" "$@")
  echo "== $label (expect $expected, got $got) =="
  cat /tmp/sv-resp.json; echo
  [ "$got" = "$expected" ] || { echo "FAIL: $label"; exit 1; }
}

echo "== GET /agent =="
check "GET /agent" 200 "http://127.0.0.1:$PORT/agent"

BODY='{"type":"agent-games.steal-the-vfy.v1","matchId":1,"turn":1,"myBalance":100,"opponentBalance":100}'
SIG_BAD=$(node -e "console.log(require('node:crypto').createHmac('sha256','wrong-secret').update(process.argv[1]).digest('hex'))" "$BODY")
check "POST /agent, invalid signature" 403 -X POST "http://127.0.0.1:$PORT/agent" \
  -H 'content-type: application/json' -H "x-agent-games-signature: $SIG_BAD" -d "$BODY"

SIG_OK=$(node -e "console.log(require('node:crypto').createHmac('sha256',process.env.AGENT_SECRET).update(process.argv[1]).digest('hex'))" "$BODY")
check "POST /agent, valid signature" 200 -X POST "http://127.0.0.1:$PORT/agent" \
  -H 'content-type: application/json' -H "x-agent-games-signature: $SIG_OK" -d "$BODY"
node -e "const r=require('/tmp/sv-resp.json'); if (r.action!=='EXTRACT') { console.error('FAIL: expected EXTRACT, got', r.action); process.exit(1); } console.log('action EXTRACT confirmed')"

echo "== all smoke checks passed =="
