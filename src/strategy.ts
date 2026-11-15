/**
 * Strategy for the Steal the VFY track.
 *
 * >>> THE STRATEGY IS THE OWNER'S — THIS FILE SHIPS A TODO, NOT A STRATEGY. <<<
 *
 * STRATEGY_PARAMS below is a clearly-marked TODO placeholder. The harness
 * in this repo PROVES whatever strategy is filled in — it never invents,
 * suggests, or hardcodes a competitive strategy. Fill it in only with
 * values the owner explicitly provides.
 *
 * What the 8 params mean (established by oracle-probing the published
 * vfy-policy circuit, ~300 probes, scripts/probe-*.mjs; see README
 * "Verified circuit findings"):
 *
 *   params = [extractAmount, fortifyThreshold, holdThreshold, passiveMode,
 *             0, 0, 0, 0]
 *   - params[0] = extract amount. For action EXTRACT the circuit enforces
 *     amount == params[0] (line 149).
 *   - params[1] = fortify threshold. Action FORTIFY satisfies when behind
 *     and the deficit is within this threshold.
 *   - params[2] = hold threshold. Action HOLD satisfies when ahead and the
 *     lead is within this threshold.
 *   - params[3] = passive mode. 0 = play the thresholds, 1 = always HOLD,
 *     > 1 = NO action is satisfiable (params validation fails).
 *   - params[4..7] MUST be 0. Any nonzero value makes NO action
 *     satisfiable.
 *
 * OPEN QUESTIONS (do NOT register a commitment until these are resolved
 * against a practice turn — see README):
 *   1. Exact boundary formula: is it `deficit <= p1`, `deficit <= p1 +
 *      turnNumber`, or something else? Probes at turn 5 could not
 *      distinguish them. The policy below uses the conservative form
 *      (`deficit <= threshold`).
 *   2. Same for the HOLD boundary (lead vs p2).
 *   3. Whether params[3] == 1 means "always HOLD" or "HOLD when tied"
 *      (it forced HOLD in every tested state).
 *   4. HOLD (0) vs FORTIFY (1) mapping is inferred from the event page
 *      (HOLD is the passive, amountless action; FORTIFY is defensive)
 *      and from the threshold behaviour (action 1 fires when behind).
 *      If a practice turn shows the mapping is swapped, swap the two
 *      constants below — the circuit input uses the numbers.
 *
 * The envelope also carries selfFortifiedUntilTurn /
 * opponentFortifiedUntilTurn, but the circuit has NO input for them, so
 * the committed policy CANNOT condition on fortification state. The
 * policy below only uses what the circuit sees: balances, turn,
 * matchId, and the params.
 *
 * Action encoding (EXTRACT verified; HOLD/FORTIFY inferred as above):
 *   0 = HOLD, 1 = FORTIFY, 2 = EXTRACT.
 */

export type ActionName = "HOLD" | "FORTIFY" | "EXTRACT";

/** Numeric action codes as the circuit expects them. */
export const ACTION_CODE: Record<ActionName, number> = {
  HOLD: 0,
  FORTIFY: 1,
  EXTRACT: 2,
};

export const ACTION_NAME: Record<number, ActionName> = {
  0: "HOLD",
  1: "FORTIFY",
  2: "EXTRACT",
};

/** Total turns per match (event page). */
export const MATCH_TURNS = 20;
/** Starting balance per agent (event page). */
export const STARTING_BALANCE = 100;

/**
 * Circuit version. The response carries it as the string "v1"
 * (policyProof.circuitVersion); the circuit itself takes it as the
 * field element 1 (see CIRCUIT_VERSION_NUM).
 */
export const CIRCUIT_VERSION = "v1";
export const CIRCUIT_VERSION_NUM = 1;

export interface GameState {
  matchId: string | number;
  turn: number;
  selfBalance: number;
  opponentBalance: number;
}

export interface Move {
  action: ActionName;
  /** Only present for EXTRACT. MUST be omitted for HOLD/FORTIFY —
   * the platform schema rejects the field even when it is 0. */
  amount?: number;
}

/** The committed strategy: id, circuit version, params, salt. */
export interface Strategy {
  id: string;
  circuitVersion: string;
  params: number[];
  salt: string;
}

// ---------------------------------------------------------------------------
// TODO (OWNER): YOUR STRATEGY GOES HERE — AND NOWHERE ELSE.
// ---------------------------------------------------------------------------
// Fill in STRATEGY_ID (a public label) and STRATEGY_PARAMS (your 8
// committed parameters, in the order documented in the header above).
// The harness proves whatever you put here; it does not choose for you.
// After filling these in, run `npm run commitment` to get the Poseidon
// commitment to register on the dashboard (Dashboard → My Agents →
// Edit agent, Steal the VFY section) BEFORE Swiss Round 1 opens. Do NOT
// change the params or the salt after registering — every proof would
// fail the platform's commitment check.
// ---------------------------------------------------------------------------

export const STRATEGY_ID = "TODO: name your strategy";

/** TODO (OWNER): your 8 strategy params. Placeholder — NOT a strategy. */
export const STRATEGY_PARAMS: number[] = [0, 0, 0, 0, 0, 0, 0, 0];

/** True while STRATEGY_PARAMS is still the shipped TODO placeholder. */
export function isPlaceholderStrategy(params: number[] = STRATEGY_PARAMS): boolean {
  return params.length === 8 && params.every((p) => p === 0);
}

/**
 * Validate committed params against what the circuit accepts.
 * Throws on anything the circuit would reject outright, so a bad
 * strategy fails loudly at load time instead of costing -2 per turn.
 */
export function validateParams(params: number[]): void {
  if (params.length !== 8) throw new Error("strategyParams must have exactly 8 elements");
  for (const p of params) {
    if (!Number.isInteger(p) || p < 0) {
      throw new Error(`strategyParams must be non-negative integers, got ${p}`);
    }
  }
  if (params[3] > 1) throw new Error("strategyParams[3] (passiveMode) must be 0 or 1");
  if (params.slice(4).some((p) => p !== 0)) {
    throw new Error("strategyParams[4..7] must be 0 (circuit rejects anything else)");
  }
}

/** The BN128 field prime (same prime the circuit works over). */
export const BN128_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

/**
 * Validate a strategy salt: it must be a decimal field element
 * (a non-negative integer string, smaller than the BN128 prime).
 * A non-numeric salt would crash proof generation mid-turn, so a
 * bad salt fails loudly at load time instead.
 */
export function validateSalt(salt: string): void {
  let value: bigint;
  try {
    value = BigInt(salt);
  } catch {
    throw new Error(
      "STRATEGY_SALT must be a decimal field element (a non-negative integer string). " +
        "Generate one (e.g. a random 256-bit integer) and keep it secret.",
    );
  }
  if (value < 0n || value >= BN128_PRIME) {
    throw new Error("STRATEGY_SALT must be smaller than the BN128 field prime");
  }
}

/**
 * Load the committed strategy. The salt comes ONLY from the
 * STRATEGY_SALT environment variable — it is secret, it is never
 * derived from anything public, and it is never logged. Refuses to
 * load without it: a guessed or default salt would silently commit
 * to a different strategy than the one registered.
 */
export function loadStrategy(salt: string | undefined): Strategy {
  if (!salt) {
    throw new Error(
      "STRATEGY_SALT is not set. Set it in the environment (never in the repo) " +
        "BEFORE registering the commitment; the registered commitment is " +
        "Poseidon(strategyParams, salt).",
    );
  }
  validateSalt(salt);
  const strategy: Strategy = {
    id: STRATEGY_ID,
    circuitVersion: CIRCUIT_VERSION,
    params: [...STRATEGY_PARAMS],
    salt,
  };
  validateParams(strategy.params);
  return strategy;
}

/**
 * The generic policy: the circuit's threshold branches, as a pure,
 * deterministic function of (state, params). This is the ONLY policy
 * the harness ships — it encodes the circuit's rules, not a
 * competitive choice. Which thresholds to commit is the owner's call.
 *
 *   deficit = opponentBalance - selfBalance
 *   lead    = selfBalance - opponentBalance
 *   if deficit > 0 and deficit <= fortifyThreshold: FORTIFY
 *   elif lead > 0 and lead <= holdThreshold:        HOLD
 *   elif passiveMode == 1:                          HOLD
 *   else:                                            EXTRACT extractAmount
 *
 * Boundary caveat: the circuit may allow threshold + turnNumber — the
 * conservative form above is used until a practice turn pins the exact
 * boundary down. See the header and README.
 */
export function policy(state: GameState, params: number[]): Move {
  const [extractAmount, fortifyThreshold, holdThreshold, passiveMode] = params;
  const deficit = state.opponentBalance - state.selfBalance;
  const lead = state.selfBalance - state.opponentBalance;
  if (deficit > 0 && deficit <= fortifyThreshold) return { action: "FORTIFY" };
  if (lead > 0 && lead <= holdThreshold) return { action: "HOLD" };
  if (passiveMode === 1) return { action: "HOLD" };
  return { action: "EXTRACT", amount: extractAmount };
}

/** Named-threshold helper for building a params array. */
export interface ThresholdParams {
  extractAmount: number;
  fortifyThreshold: number;
  holdThreshold: number;
  passiveMode: 0 | 1;
}

export function paramsFromThreshold(p: ThresholdParams): number[] {
  return [p.extractAmount, p.fortifyThreshold, p.holdThreshold, p.passiveMode, 0, 0, 0, 0];
}
