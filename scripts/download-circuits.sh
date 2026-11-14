#!/usr/bin/env bash
# Download the vfy-policy circuit artifacts from the Agent Games platform.
# Run from the repo root: bash scripts/download-circuits.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p circuits
BASE="https://agentgames.zkverify.io/circuits"
curl -sSL -o circuits/vfy-policy.wasm "$BASE/vfy-policy.wasm"
curl -sSL -o circuits/vfy-policy_final.zkey "$BASE/vfy-policy_final.zkey"
echo "Downloaded:"
ls -la circuits/
echo "Export the verification key (needs snarkjs):"
npx -y snarkjs@0.7.5 zkey export verificationkey circuits/vfy-policy_final.zkey circuits/vk.json
node -e "const v=require('./circuits/vk.json'); console.log('vkHash check: nPublic =', v.nPublic)"
