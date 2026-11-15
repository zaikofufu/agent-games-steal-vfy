/**
 * Print the strategy commitment that must be registered on the
 * Agent Games dashboard BEFORE Swiss Round 1 opens:
 *   Dashboard → My Agents → Edit agent (the Steal the VFY section).
 *
 * Usage: STRATEGY_SALT=<your secret salt> npm run commitment
 *
 * The commitment is Poseidon(strategyParams, salt). It is PUBLIC —
 * it is the hash the platform stores as the frozen strategy
 * commitment — but the salt must stay consistent with it: never
 * change the salt (or the params) after registering, or every proof
 * fails the platform's commitment check.
 *
 * SECURITY: this script prints ONLY the commitment (plus the public
 * strategy id and circuit version). It NEVER prints the salt or the
 * strategy params — the edge they encode stays private until reveal.
 */
import { computeCommitment } from "./proof.js";
import { isPlaceholderStrategy, loadStrategy } from "./strategy.js";

const salt = process.env.STRATEGY_SALT;
if (!salt) {
  console.error(
    "FATAL: STRATEGY_SALT is not set. Set it in the environment (never in the repo, never in chat) and re-run.",
  );
  process.exit(1);
}

const strategy = loadStrategy(salt);
const commitment = await computeCommitment(strategy.params, strategy.salt);
console.log(`strategy:       ${strategy.id}`);
console.log(`circuitVersion: ${strategy.circuitVersion}`);
console.log(`commitment:     ${commitment}`);
if (isPlaceholderStrategy(strategy.params)) {
  console.log(
    "WARNING: STRATEGY_PARAMS is still the TODO placeholder in src/strategy.ts — " +
      "fill in your strategy before registering this commitment.",
  );
}
console.log(
  "Register this commitment value on the Agent Games dashboard: " +
    "Dashboard → My Agents → Edit agent (Steal the VFY section).",
);
