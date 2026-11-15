# Steal the VFY agent — zkVerify Agent Games

An agent for the **Steal the VFY** track of zkVerify's Agent Games
(competition 21 Oct – 21 Nov 2026, free entry, 100,000 VFY per track).
It plays a 20-turn head-to-head match from a committed strategy,
proving every move with a Groth16 policy proof.

**Status: built and tested locally against the /build spec (15 Nov
2026). NOT deployed, NOT registered. The strategy is a TODO for the
owner (see below) — this repo ships the harness, not a strategy.**

**Tournament status (checked live 15 Nov 2026, 23:20 WIB): Steal the
VFY entries are locked for the current tournament** — the server
rejects registration with "Steal the VFY entries are locked for the
current tournament" (confirmed 3×). The tournament is paired and
runs to Round 7 on 19 Nov. This agent can only enter a future
tournament/reset, when entries reopen.

## How it works

```
platform --POST /agent--> agent
  header: x-agent-games-signature: <hmac-sha256-hex of raw body>
  body:   turn envelope (see src/server.ts: protocolVersion,
          eventId, matchId UUID, turn, state {selfBalance,
          opponentBalance}, strategyCommitment {hash}, nonce)
agent --> move + Groth16 policy proof
  header: x-agent-games-signature: <hmac-sha256-hex of raw response>
  body:   {
            matchId, turn,
            action: { type: "EXTRACT", amount: 5 },   // amount ONLY
                          // for EXTRACT — omitted for HOLD/FORTIFY
            policyProof: {
              circuitVersion: "v1",
              proof: { pi_a, pi_b, pi_c, protocol, curve },  // raw
                          // snarkjs Groth16 proof — MUST sit INSIDE
                          // policyProof, never at the top level
              public_signals: [...],        // decimal strings,
                          // circuit output-then-public order
              publicInputsHash: "0x..."     // optional audit pointer:
                          // the /build keccak256 value
            },
            agentTimestamp: "<ISO-8601>",
            idempotencyKey: "<uuid>"
          }
```

- Match: 20 turns, starting balance 100 VFY each. Highest balance
  wins the match. Swiss, 7 rounds (checked live on the event page).
  Invalid policy proof −2/turn; timeout (no response) −1/turn.
- Turn deadline is ~5 minutes; the platform waits ~30s per push.
  The server races move+proof against a 20s internal budget and
  answers 503 if it cannot respond in time.
- Fail closed: if no proof can be produced (no circuit artifacts,
  proving assert failure, commitment mismatch with the envelope),
  the server answers HOLD with `proof: null` and no
  `public_signals` — per /build that is treated as HOLD with no
  proof. It never invents a proof, and never returns a bogus one
  (an invalid proof costs −2; a HOLD costs a turn).
- On-chain zkVerify submission is NOT done by this agent: the
  platform re-verifies the raw proof offline against its own VK.
  `proofReference` is therefore omitted (optional audit pointer
  only). If an audit submission is wanted later, `KURIER_API_KEY`
  / wallet env vars are reserved in `.env.example` — the response
  is never blocked on it.

## Strategy — YOURS (TODO)

**`STRATEGY_PARAMS` in `src/strategy.ts` is a clearly-marked TODO
placeholder (`[0,0,0,0,0,0,0,0]`). This repo deliberately ships no
strategy.** The harness proves whatever params the owner fills in;
it never invents, suggests, or hardcodes a competitive strategy.

What the 8 params mean (established by oracle-probing the published
circuit, ~300 probes, `scripts/probe-*.mjs`):

```
params = [extractAmount, fortifyThreshold, holdThreshold,
          passiveMode, 0, 0, 0, 0]
```

- `params[0]` = extract amount (the circuit enforces
  `amount == params[0]` for EXTRACT).
- `params[1]` = fortify threshold (FORTIFY satisfies when behind
  and the deficit is within it).
- `params[2]` = hold threshold (HOLD satisfies when ahead and the
  lead is within it).
- `params[3]` = passive mode: 0 = play the thresholds, 1 = always
  HOLD, > 1 = no action satisfiable.
- `params[4..7]` MUST be 0.

`policy(state, params)` in `src/strategy.ts` is the generic,
deterministic implementation of those branches. Which thresholds to
commit is the owner's call.

The salt comes ONLY from the `STRATEGY_SALT` environment variable
(a decimal field element, secret, never derived from anything
public, never logged). The server refuses to start without it.

Commitment: `Poseidon(strategyParams, salt)`. Print it with
(`STRATEGY_SALT` set) — the script prints ONLY the commitment, the
strategy id and the circuit version; it NEVER prints the salt or
the params:

```bash
STRATEGY_SALT=<your secret salt> npm run commitment
```

Register it on the dashboard BEFORE Swiss Round 1 opens:
**Dashboard → My Agents → Edit agent (the Steal the VFY
section)**. The platform freezes it when matches are paired. Do NOT
change the params or the salt after registering.

> The commitment `16558278792999601739528827900028539763998923485550243417577873933892175672347`
> from the earlier always-extract build is **VOID** — it was computed
> for params `[10,0,0,0,0,0,0,0]` and a salt that no longer exists
> in this repo. Do not register it.

## Files

| File | What it does |
| --- | --- |
| `src/server.ts` | HTTP server (Node built-in `http`, no framework). HMAC verify **before** parsing, response signing, 20s internal budget, 401/403/503 handling, idempotency cache, commitment-mismatch and no-proof HOLD fallbacks. Builds the exact /build response shape (action object, `policyProof` nesting, `agentTimestamp`, `idempotencyKey`). |
| `src/strategy.ts` | `STRATEGY_PARAMS` TODO + `STRATEGY_ID` TODO, generic `policy(state, params)`, `validateParams`/`validateSalt`, `loadStrategy` (env salt only). |
| `src/proof.ts` | Policy-proof generation with the real vfy-policy circuit (snarkjs `fullProve`), circuit constants, input mapping (UUID matchId as hex), Poseidon commitment, and `computePublicInputsHash` (the /build keccak256 audit formula via viem). |
| `src/index.ts` | Entry point; refuses to start without `AGENT_GAMES_HMAC_SECRET` and `STRATEGY_SALT`; prints the commitment on startup (never the params/salt). |
| `src/commitment.ts` | `npm run commitment`: prints the commitment to register — never the salt or params. |
| `test/strategy.test.ts` | Generic policy behaviour with injected params; placeholder + salt validation. |
| `test/proof.test.ts` | Proof wiring with a MOCKED prover (labelled); commitment reference value; keccak audit-hash vector + field-sensitivity. |
| `test/proof.real.test.ts` | **REAL** Groth16: fullProve + verify against the published circuit (test fixture params only). Skipped if `circuits/` is absent. |
| `test/server.test.ts` | Live HTTP: health, HMAC 401/403, valid turn → EXTRACT with `policyProof` nesting, FORTIFY without amount, replay/idempotency, commitment mismatch → HOLD, no-artifacts → HOLD. |
| `circuits/` | Published vfy-policy `vfy-policy.wasm`, `vfy-policy_final.zkey`, exported `vk.json` (nPublic 9). |
| `scripts/probe-*.mjs` | The oracle probes that mapped the circuit (signal names, commitment formula, policy branches, public-signal order, hash identification). |
| `Dockerfile`, `fly.toml` | Fly.io deployment. |

## Spec sources (fetched 14–15 Nov 2026)

- https://agentgames.zkverify.io/build (§06 Steal the VFY — including
  the embedded response + `publicInputsHash` code blocks, read from
  the page HTML on 15 Nov 2026)
- https://agentgames.zkverify.io/guide
- https://agentgames.zkverify.io/events/steal-the-vfy (actions, format)
- https://agentgames.zkverify.io/api/circuit-info — mainnet, vfyPolicy vkHash `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`

## Verified circuit findings (probed live, not assumed)

The published wasm/zkey were downloaded and exercised with snarkjs:

- Exported VK: Groth16/BN128, **nPublic = 9**.
- Circuit inputs (17 total), recovered by oracle probing:
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
  - `[2]` is matchId (UUID ids as their hex value — verified live),
    `[3]` turnNumber, `[4]` selfBalance, `[5]` opponentBalance,
    `[7]` amount (each confirmed by varying exactly one input and
    diffing).
  - `[0]` is the circuit's own public-inputs hash. Its function is
    NOT the /build keccak256 formula: verified live
    (`scripts/probe-hash.mjs`, `probe-hash2.mjs`) — for a real
    proof the keccak256 value differs from `publicSignals[0]`, and
    so do Poseidon over the same tuples in several field orders.
    The agent therefore forwards `[0]` verbatim from fullProve
    and uses the keccak256 value ONLY for the optional
    `policyProof.publicInputsHash` audit field. Never confuse the
    two.
  - `[8]` is circuitVersion by elimination.
- **`computePublicInputsHash`** (src/proof.ts) implements the /build
  formula exactly: keccak256 of ABI-packed fields, each 32 bytes
  big-endian, in the order
  `[commitment, matchId, turn, selfBalance, opponentBalance,
  action, amount, circuitVersion]`, matchId as UUID-hex, action
  HOLD 0 / FORTIFY 1 / EXTRACT 2, amount 0 for HOLD/FORTIFY,
  circuitVersion "v1" as 1. Pinned by a test vector
  (`test/proof.test.ts`).
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
    returns **true** for the test fixture.
- Action codes: 2 = EXTRACT (verified — the only amount-bearing
  action). 0/1 = HOLD/FORTIFY (inferred from the event page and
  the threshold behaviour — see spec gaps).

## Spec gaps — read before deploying

1. **Threshold-policy boundaries are not fully pinned down.** The
   fortify/hold thresholds involve turnNumber and/or an off-by-one
   that probes at a single turn could not distinguish. The policy
   uses the conservative form (`deficit <= threshold`). Confirm
   the exact boundary against a practice turn before registering
   a threshold-based commitment.
2. **HOLD vs FORTIFY codes (0 vs 1) are inferred, not verified.**
   Only action 2 (EXTRACT) is certain. Confirm on the first
   practice turn; if the mapping is swapped, swap the two constants
   in `src/strategy.ts`.
3. **The circuit's publicSignals[0] hash function is unidentified.**
   It is not the /build keccak256 formula and not Poseidon over the
   obvious tuples. It does not affect the response (the proof
   carries it verbatim), but do not use it as the audit field.
4. **The turn envelope's `strategyCommitment.hash` format.** /build
   shows it as a `0x...` hex hash; the server parses hex or decimal
   via `parseFieldElement`. If the platform ever sends a different
   encoding, the mismatch check ignores unparseable values rather
   than failing the turn.
5. **Replay store is in-memory.** A restart clears the
   matchId:turn cache. The platform also tracks idempotency keys,
   so this is a second line of defence, not the only one.
6. **No on-chain submission.** The agent returns the Groth16 proof
   in its HTTP response; it does **not** submit proofs to zkVerify
   via Kurier or zkVerifyJS. Per /build that submission is an
   optional audit path — the platform re-verifies the raw proof
   offline. If the platform ever requires agent-side submission,
   that is a follow-up feature.

## Run locally

```bash
npm install
npm run build
cp .env.example .env   # then set AGENT_GAMES_HMAC_SECRET + STRATEGY_SALT
STRATEGY_SALT=<your secret salt> npm run commitment   # commitment to register
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
AGENT_GAMES_HMAC_SECRET=<redacted> \
STRATEGY_SALT=<decimal field element> \
npm start
```

Without those env vars the agent still answers every turn with HOLD
and `proof: null` — it never invents a proof.

## Tests

```bash
npm test                              # 50 tests: unit + HTTP (mocked prover) + REAL Groth16
npm test -- test/proof.real.test.ts   # REAL Groth16 prove+verify only (needs circuits/)
bash scripts/test-server.sh           # live smoke test: GET health, POST 403, POST 200
```

Test labelling: the policy proof is **mocked** in `proof.test.ts` /
`server.test.ts` (an injected stub prover) so those suites run fast
without the circuit. The **real** proof is exercised in
`test/proof.real.test.ts` (actual `fullProve` + `groth16.verify`
against the published vfy-policy circuit). Strategy tests use
explicit test-fixture params — never the owner's TODO values.

## Deploy

```bash
fly launch --no-deploy   # set app name when prompted
fly secrets set AGENT_GAMES_HMAC_SECRET=<redacted>
fly secrets set STRATEGY_SALT=<decimal field element>
fly deploy
```

Then register the agent on the Agent Games dashboard (name, Steal
the VFY track, public GitHub repo from github.com/zaikofufu,
endpoint URL), register the commitment printed by
`npm run commitment` (Dashboard → My Agents → Edit agent, Steal the
VFY section), run preflight, then a practice turn. **Preflight must
pass before Swiss Round 1 — the platform cannot pair the agent
without an active commitment.**

## Remaining before the agent can compete (not done here)

1. **Owner fills in the strategy** (`STRATEGY_ID` + `STRATEGY_PARAMS`
   in `src/strategy.ts`) and a secret `STRATEGY_SALT`, then runs
   `npm run commitment` and registers that commitment.
2. Public GitHub repo under github.com/zaikofufu with this code
   (no secrets committed).
3. Deploy to a public HTTPS host (Fly.io config in `fly.toml`).
4. Register the agent + commitment on the dashboard **when Steal
   entries reopen** (locked for the current tournament); set the
   issued HMAC secret as `AGENT_GAMES_HMAC_SECRET` on the host
   (never in the repo).
5. Preflight + at least one practice turn — and confirm the open
   spec gaps above (threshold boundaries, HOLD/FORTIFY codes)
   against the practice verdict.
6. A wallet address on the Agent Games account (required to claim
   VFY prizes; not required to register or play).
