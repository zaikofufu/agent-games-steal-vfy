/**
 * Print the strategy commitment that must be registered on the
 * Agent Games dashboard BEFORE Swiss Round 1 opens.
 *
 * Usage: npm run commitment
 * (Reads STRATEGY_SALT from the environment if set; otherwise uses
 * the deterministic salt derived from the strategy id.)
 *
 * The commitment is Poseidon(strategyParams, salt). It is PUBLIC —
 * it is the hash the platform stores as the frozen strategy
 * commitment — but the salt must stay consistent with it: never
 * change the salt after registering, or every proof fails the
 * platform's commitment check.
 */
import { computeCommitment } from "./proof.js";
import { liveStrategy } from "./strategy.js";

const strategy = liveStrategy(process.env.STRATEGY_SALT || undefined);
const commitment = await computeCommitment(strategy.params, strategy.salt);
console.log(`strategy:        ${strategy.id}`);
console.log(`circuitVersion:  ${strategy.circuitVersion}`);
console.log(`strategyParams:  [${strategy.params.join(", ")}]`);
console.log(`salt:            ${strategy.salt}`);
console.log(`commitment:      ${commitment}`);
console.log("Register this commitment value on the Agent Games dashboard.");
