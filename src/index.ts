/**
 * Entry point. Reads configuration from the environment and starts the
 * Steal the VFY agent. The HMAC secret and the strategy salt are
 * required: the server refuses to start without them, so a
 * misconfigured deploy fails loudly instead of answering turns
 * unsigned or proving against the wrong commitment.
 *
 * Required env:
 *   AGENT_GAMES_HMAC_SECRET  secret issued by the platform at registration
 *                            ("Rotate Secret" in agent settings)
 *   STRATEGY_SALT            secret salt for the committed strategy
 *                            (Poseidon(strategyParams, salt)); only set
 *                            BEFORE registering the commitment
 * Optional env:
 *   PORT           default 3000 (Fly.io sets this automatically)
 *   AGENT_NAME     default "steal-vfy"
 *   VFY_POLICY_WASM / VFY_POLICY_ZKEY
 *                  local circuit artifact paths (see README). Without
 *                  them the agent answers every turn with HOLD and
 *                  proof: null — see src/server.ts.
 *
 * The strategy params themselves live in src/strategy.ts as a TODO
 * for the owner to fill in — they are NOT read from the environment,
 * and they are NEVER logged.
 */
import { createApp } from "./server.js";
import { computeCommitment } from "./proof.js";
import { loadStrategy } from "./strategy.js";

const secret = process.env.AGENT_GAMES_HMAC_SECRET;
if (!secret) {
  console.error("FATAL: AGENT_GAMES_HMAC_SECRET is not set. Refusing to start.");
  process.exit(1);
}

const port = Number(process.env.PORT ?? "3000");
const strategy = loadStrategy(process.env.STRATEGY_SALT);
const app = createApp({
  secret,
  agentName: process.env.AGENT_NAME ?? "steal-vfy",
  strategy,
  wasmPath: process.env.VFY_POLICY_WASM || undefined,
  zkeyPath: process.env.VFY_POLICY_ZKEY || undefined,
});

app.listen(port, async () => {
  const commitment = await computeCommitment(strategy.params, strategy.salt);
  console.log(`steal-vfy agent listening on :${port} (GET /agent for health)`);
  console.log(`strategy ${strategy.id} (commitment: ${commitment})`);
});
