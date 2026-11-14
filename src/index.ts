/**
 * Entry point. Reads configuration from the environment and starts the
 * Steal the VFY agent. The HMAC secret is required: the server
 * refuses to start without AGENT_SECRET, so a misconfigured deploy
 * fails loudly instead of answering turns unsigned.
 *
 * Required env:
 *   AGENT_SECRET   32-byte secret issued by the platform at registration
 * Optional env:
 *   PORT           default 3000 (Fly.io sets this automatically)
 *   AGENT_NAME     default "steal-vfy"
 *   VFY_POLICY_WASM / VFY_POLICY_ZKEY
 *                  local circuit artifact paths (see README). Without
 *                  them the agent answers every turn with HOLD and
 *                  proof: null — see src/server.ts.
 *   STRATEGY_SALT  override the deterministic strategy salt. Only set
 *                  BEFORE registering the commitment: the registered
 *                  commitment is Poseidon(strategyParams, salt).
 */
import { createApp } from "./server.js";
import { computeCommitment } from "./proof.js";
import { liveStrategy } from "./strategy.js";

const secret = process.env.AGENT_SECRET;
if (!secret) {
  console.error("FATAL: AGENT_SECRET is not set. Refusing to start.");
  process.exit(1);
}

const port = Number(process.env.PORT ?? "3000");
const strategy = liveStrategy(process.env.STRATEGY_SALT || undefined);
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
  console.log(`strategy ${strategy.id} params=[${strategy.params.join(", ")}]`);
  console.log(`commitment (register this value): ${commitment}`);
});
