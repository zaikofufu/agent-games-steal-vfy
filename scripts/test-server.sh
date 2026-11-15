#!/usr/bin/env bash
# Smoke-test the built server locally:
#  - GET /agent (health)
#  - POST /agent with an INVALID signature (expect 403)
#  - POST /agent with a VALID signature + a turn envelope (expect 200)
#    Without circuit artifacts the server answers HOLD with proof null
#    (fail closed); with VFY_POLICY_WASM/VFY_POLICY_ZKEY pointing at
#    real files it answers EXTRACT with a real proof.
# Usage: AGENT_GAMES_HMAC_SECRET=<secret> STRATEGY_SALT=<salt> bash scripts/test-server.sh
# Exits non-zero if any check fails.
set -euo pipefail
cd "$(dirname "$0")/.."
npm run build

export AGENT_GAMES_HMAC_SECRET="${AGENT_GAMES_HMAC_SECRET:-test-secret-for-steal-vfy}"
export STRATEGY_SALT="${STRATEGY_SALT:-12345}"
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

BODY='{"protocolVersion":"v1","eventId":"steal-the-vfy","matchId":"9f4e1b2a-1111-4000-8000-000000000001","turn":1,"state":{"selfBalance":"100","opponentBalance":"100","selfFortifiedUntilTurn":null,"opponentFortifiedUntilTurn":null},"nonce":"3c2f1a0000000000000000000000000000000000000000000000000000000000"}'
SIG_BAD=$(node -e "console.log(require('node:crypto').createHmac('sha256','wrong-secret').update(process.argv[1]).digest('hex'))" "$BODY")
check "POST /agent, invalid signature" 403 -X POST "http://127.0.0.1:$PORT/agent" \
  -H 'content-type: application/json' -H "x-agent-games-signature: $SIG_BAD" -d "$BODY"

SIG_OK=$(node -e "console.log(require('node:crypto').createHmac('sha256',process.env.AGENT_GAMES_HMAC_SECRET).update(process.argv[1]).digest('hex'))" "$BODY")
check "POST /agent, valid signature" 200 -X POST "http://127.0.0.1:$PORT/agent" \
  -H 'content-type: application/json' -H "x-agent-games-signature: $SIG_OK" -d "$BODY"

# Response shape per /build: action object, proof nested in policyProof.
node -e "
const r = require('/tmp/sv-resp.json');
if (r.proof !== undefined || r.public_signals !== undefined) {
  console.error('FAIL: proof/public_signals must sit INSIDE policyProof, not at the top level');
  process.exit(1);
}
const hasArtifacts = !!(process.env.VFY_POLICY_WASM && process.env.VFY_POLICY_ZKEY);
const expected = hasArtifacts ? 'EXTRACT' : 'HOLD';
if (r.action?.type !== expected) {
  console.error('FAIL: expected action', expected, 'got', JSON.stringify(r.action));
  process.exit(1);
}
if (hasArtifacts) {
  if (!r.policyProof?.proof || !r.policyProof?.public_signals) {
    console.error('FAIL: expected a real proof in policyProof'); process.exit(1);
  }
} else if (r.policyProof?.proof !== null) {
  console.error('FAIL: expected proof null without circuit artifacts'); process.exit(1);
}
console.log('action', expected, 'confirmed, policyProof shape OK');
"

echo "== all smoke checks passed =="
