# Steal the VFY agent — zkVerify Agent Games

An agent for the **Steal the VFY** track of zkVerify's Agent Games
(competition 21 Oct – 21 Nov 2026, free entry, 100,000 VFY per track).
It plays a 20-turn head-to-head match from a committed strategy,
proving every move with a Groth16 policy proof.

**Status: built and tested locally. NOT deployed, NOT registered, NOT
submitted.** The remaining steps are listed at the bottom.

## How it works

```
platform --POST /agent--> agent
  header: x-agent-games-signature: <hmac-sha256-hex of raw body>
  body:   turn envelope (matchId, turn, balances, commitment hash)
agent --> move + Groth16 policy proof
  header: x-agent-games-signature: <hmac-sha256-hex of raw response>
  body:   {matchId, turn, action, amount?, circuitVersion,
           proof, public_signals, publicInputsHash}
```

- Match: 20 turns, starting balance 100 VFY each (simulated, no real
  value). Highest balance wins: win +18, draw +9, loss +3, verified-
  turn reliability bonus +0…+2, timeout (no response) −1/turn,
  invalid policy proof −2/turn. Swiss 5 rounds → Top 16 knockout.
- Turn deadline is 5 minutes; the platform waits ~30s per push. The
  server races move+proof against a 20s internal budget and answers
  503 if it cannot respond in time.
- `amount` is sent ONLY for EXTRACT. The schema rejects the field for
  HOLD/FORTIFY even when it is 0.
- Fail closed: if no proof can be produced (no circuit artifacts,
  proving assert failure, commitment mismatch with the envelope),
  the server answers HOLD with `proof: null` and no `public_signals`
  — per /build that is treated as HOLD with no proof. It never
  invents a proof, and never returns a bogus one (an invalid proof
  costs −2; a HOLD costs a turn).

## Strategy

**Live policy: always EXTRACT 10 VFY** (`steal-vfy-always-extract-v1`,
`src/strategy.ts`).

This is not laziness — it is what the published circuit provably
accepts. The circuit's policy was reverse-engineered empirically
(~300 witness-oracle probes, `scripts/probe-*.mjs`); see "Verified
circuit findings" below. With
`strategyParams = [10, 0, 0, 0, 0, 0, 0, 0]`, EXTRACT with
`amount == params[0]` satisfies the circuit in every probed state
(turns 1, 2, 5, 10, 19, 20; leads from −100 to +100), and the real
Groth16 proof verifies against the published VK.

The richer threshold policy (FORTIFY when behind, HOLD when ahead,
EXTRACT otherwise) exists as `decideTurnThreshold` in
`src/strategy.ts` — deterministic, documented, but NOT wired into
the live path, because its exact boundary formulas were not fully
pinned down (see spec gaps). A wrong boundary means an invalid proof
(−2/turn). Enable it only after confirming it against a practice
turn.

Commitment: `Poseidon(strategyParams, salt)`, salt derived
deterministically as SHA-256(strategy id) mod the BN128 prime
(`src/strategy.ts:deriveSalt`). The salt must never change after
registration — the registered commitment binds it. Print it with:

```bash
npm run commitment
```

## Files

| File | What it does |
| --- | --- |
| `src/server.ts` | HTTP server (Node built-in `http`, no framework). HMAC verify **before** parsing, response signing, 20s internal budget, 401/403/503 handling, idempotency cache, commitment-mismatch and no-proof HOLD fallbacks. |
| `src/strategy.ts` | Live always-extract policy + committed params/salt + the (unverified) threshold-policy reference implementation. |
| `src/proof.ts` | Policy-proof generation with the real vfy-policy circuit (snarkjs `fullProve`), circuit constants, input mapping, Poseidon commitment. |
| `src/index.ts` | Entry point; refuses to start without `AGENT_SECRET`; prints the commitment on startup. |
| `src/commitment.ts` | `npm run commitment`: prints the commitment to register. |
| `test/strategy.test.ts` | Live policy determinism/shape; threshold-policy reference behaviour. |
| `test/proof.test.ts` | Proof wiring with a MOCKED prover (labelled); commitment reference value. |
| `test/proof.real.test.ts` | **REAL** Groth16: fullProve + verify against the published circuit. Skipped if `circuits/` is absent. |
| `test/server.test.ts` | Live HTTP: health, HMAC 401/403, valid turn → EXTRACT, replay/idempotency, commitment mismatch → HOLD, no-artifacts → HOLD. |
| `circuits/` | Published vfy-policy `vfy-policy.wasm`, `vfy-policy_final.zkey`, exported `vk.json` (nPublic 9). |
| `scripts/probe-*.mjs` | The oracle probes that mapped the circuit (signal names, commitment formula, policy branches, public-signal order). |
| `Dockerfile`, `fly.toml` | Fly.io deployment (keeps 1 machine awake — a sleeping machine forfeits turns). |

## Spec sources (fetched 14 Nov 2026)

- https://agentgames.zkverify.io/build (§06 Steal the VFY)
- https://agentgames.zkverify.io/guide
- https://agentgames.zkverify.io/events/steal-the-vfy (actions, scoring, format)
- https://agentgames.zkverify.io/api/circuit-info — mainnet, vfyPolicy vkHash `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`

## Verified circuit findings (probed live, not assumed)

The published wasm/zkey were downloaded and exercised with snarkjs:

- Exported VK: Groth16/BN128, **nPublic = 9**.
- Circuit inputs (17 total), recovered by FNV-hash oracle probing:
  9 scalars — `action, amount, selfBalance, opponentBalance,
  turnNumber, matchId, commitment, salt, circuitVersion` — plus
  `strategyParams[8]`.
- **commitment = Poseidon(strategyParams[0..7], salt)** (salt LAST —
  salt-first fails the line-72 assert; salt-last passes it).
- Public signals (9), order verified live by fullProve + vary-one-
  input-at-a-time:
  `[publicInputsHash, commitment, matchId, turnNumber, selfBalance,
  opponentBalance, action, amount, circuitVersion]`
  - `[1]` is the commitment (direct value match).
  - `[2]` is matchId, `[3]` turnNumber, `[4]` selfBalance,
    `[5]` opponentBalance, `[7]` amount (each confirmed by varying
    exactly one input and diffing).
  - `[0]` changes with matchId/turnNumber, so it is the
    public-inputs hash — but its hash function was NOT identified
    (Poseidon over the obvious tuples did not match). The agent
    forwards it verbatim from fullProve and also sends it as
    `publicInputsHash`; it never computes it locally.
  - `[8]` is circuitVersion by elimination.
- **The circuit enforces the policy** (template `VfyPolicyProof`):
  fullProve FAILS unless the move matches the committed policy.
  Mapped branches (params = `[p0, p1, p2, p3, 0, 0, 0, 0]`):
  - `p0` = extract amount; for action EXTRACT the circuit enforces
    `amount == p0` (line 149).
  - FORTIFY (action 1) satisfies when behind and the deficit is
    within p1 (boundary involves turnNumber and/or an off-by-one —
    not fully pinned down).
  - HOLD (action 0) satisfies when ahead and the lead is within p2
    (same boundary caveat).
  - `p3 = 1` forces HOLD in every tested state; `p3 > 1` makes NO
    action satisfiable (params validation fails at line 90).
  - `p4..p7` must be 0 — any nonzero value makes NO action
    satisfiable (lines 75–78).
  - Real fullProve + `groth16.verify` against the published VK
    returns **true** for the live policy.
- Action codes: 2 = EXTRACT (verified — the only amount-bearing
  action). 0/1 = HOLD/FORTIFY (inferred, see spec gaps).

## Spec gaps — read before deploying

1. **Turn-envelope field names are unpublished.** /build renders them
   in interactive sections the text crawl collapses. This server
   accepts both the flat shape
   (`matchId, turn, myBalance, opponentBalance, commitmentHash`)
   and a nested `state`/`gameState` shape, plus common aliases
   (`match_id`, `turnNumber`, `selfBalance`, …). If the platform
   sends a field this code does not recognise, the turn is answered
   400 — check the first practice turn's payload and extend
   `normaliseTurn` if needed.
2. **The `type` string is an assumption.** The server accepts
   `agent-games.steal-the-vfy.v1` (by analogy with the gatekeeper
   envelope) or no type at all, and rejects only envelopes clearly
   for another track. Confirm the real value on the first practice
   turn.
3. **publicInputsHash function is unidentified.** `publicSignals[0]`
   is forwarded verbatim and sent as `publicInputsHash`. If the
   platform computes it differently from the circuit, it will reject
   the proof — confirm on the first practice turn; if it diverges,
   the field may need to be omitted (it is listed as optional in
   one place, and as required in another — see gap 4).
4. **/build contradicts itself on publicInputsHash.** §06 says it is
   an "optional on-chain audit pointer", but the common-mistakes list
   says skipping it (or computing it with the wrong field order)
   gets the proof "rejected immediately". This code includes it
   (from the circuit). Watch the first practice turn's verdict.
5. **Threshold-policy boundaries are not fully pinned down.** The
   fortify/hold thresholds involve turnNumber and/or an off-by-one
   that probes at a single turn could not distinguish. The live
   always-extract policy avoids the question entirely; do not switch
   to the threshold policy without practice-turn confirmation.
6. **HOLD vs FORTIFY codes (0 vs 1) are inferred, not verified.**
   Only action 2 (EXTRACT) is certain. The live policy never sends
   0/1 with a proof, so this does not affect the live path — but the
   HOLD fallback sends action `"HOLD"` as a string, and the platform
   maps the string itself.
7. **Strategy commitment registration flow is undocumented.** The
   dashboard asks for a "registered strategy commitment and
   compatible circuit version" before Swiss Round 1. This code
   assumes you register the Poseidon commitment printed by
   `npm run commitment` (with `circuitVersion: 1`). If the dashboard
   instead derives the commitment from parameters you type in, make
   sure the salt matches (`STRATEGY_SALT`, default derived from the
   strategy id).
8. **No on-chain submission.** The agent returns the Groth16 proof
   in its HTTP response; it does **not** submit proofs to zkVerify
   via Kurier or zkVerifyJS. The platform's docs present that as a
   separate verification path — if the platform expects the agent to
   submit the proof itself, that is a follow-up feature.
9. **Response signing.** /build says every response is signed with
   `x-agent-games-signature` over the raw response body. This server
   does that. The health endpoint is signed too.
10. **Replay store is in-memory.** A restart clears the
    matchId:turn cache. The platform also tracks idempotency keys,
    so this is a second line of defence, not the only one.

## Run locally

```bash
npm install
npm run build
cp .env.example .env   # then set AGENT_SECRET to a test value
npm run commitment     # print the commitment to register
npm start              # listens on :3000 (or $PORT)
curl http://127.0.0.1:3000/agent
# {"status":"ok","agent":"steal-vfy","version":"1.0.0"}
```

To generate **real** policy proofs locally, point the server at the
bundled artifacts (or run `bash scripts/download-circuits.sh` to
re-fetch them from the platform):

```bash
VFY_POLICY_WASM=circuits/vfy-policy.wasm \
VFY_POLICY_ZKEY=circuits/vfy-policy_final.zkey \
AGENT_SECRET=<redacted>
```

Without those env vars the agent still answers every turn with HOLD
and `proof: null` — it never invents a proof.

## Tests

```bash
npm test                          # unit + HTTP tests (mocked prover, labelled)
npm test -- test/proof.real.test.ts   # REAL Groth16 prove+verify (~10s, needs circuits/)
bash scripts/test-server.sh       # live smoke test: GET health, POST 403, POST 200 EXTRACT
```

Test labelling: the policy proof is **mocked** in `proof.test.ts` /
`server.test.ts` (an injected stub prover) so those suites run fast
without the circuit. The **real** proof is exercised in
`test/proof.real.test.ts` (actual `fullProve` + `groth16.verify`
against the published vfy-policy circuit).

## Deploy

```bash
fly launch --no-deploy   # set app name when prompted
fly secrets set AGENT_SECRET=<redacted>
fly deploy
```

Then register the agent on the Agent Games dashboard (name, Steal
the VFY track, public GitHub repo from github.com/zaikofufu,
endpoint URL), register the commitment printed by
`npm run commitment` with circuit version 1, run preflight, then a
practice turn. **Preflight must pass before Swiss Round 1 — the
platform cannot pair the agent without an active commitment.**

## Remaining before the agent can compete (not done here)

1. Public GitHub repo under github.com/zaikofufu with this code
   (no secrets committed).
2. Deploy to a public HTTPS host (Fly.io config in `fly.toml`).
3. Register the agent + commitment on the dashboard; set the issued
   HMAC secret as `AGENT_SECRET` on the host (never in the repo).
4. Preflight + at least one practice turn — and confirm the open
   spec gaps above (envelope field names, `type`, publicInputsHash,
   HOLD/FORTIFY codes) against the practice verdict.
5. A wallet address on the Agent Games account (required to claim
   VFY prizes; not required to register or play).
