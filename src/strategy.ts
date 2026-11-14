/**
 * Strategy for the Steal the VFY track.
 *
 * VERIFIED POLICY (live) — "always extract", strategy id
 * `steal-vfy-always-extract-v1`:
 *
 *   Every turn: EXTRACT `EXTRACT_AMOUNT` (10 VFY).
 *
 * This is the policy the published vfy-policy circuit provably accepts.
 * It was established empirically against the published circuit
 * (see README "Verified circuit findings"): with
 * strategyParams = [10, 0, 0, 0, 0, 0, 0, 0], action EXTRACT with
 * amount == params[0] satisfies the circuit in every probed state
 * (turns 1, 2, 5, 10, 19, 20; leads from -100 to +100). The
 * commitment is Poseidon(strategyParams, salt), and the real Groth16
 * proof for this policy verifies against the published VK
 * (see test/proof.real.test.ts).
 *
 * WHY NOT the richer policy (fortify early / hold when ahead)?
 * The circuit DOES contain threshold branches — probing mapped them
 * partially (see `thresholdPolicy` below and README): with
 * params = [amount, p1, p2, p3, 0, 0, 0, 0],
 *   - FORTIFY (action 1) satisfies when behind and the deficit is
 *     within p1 (exact boundary formula not yet pinned down: it
 *     involves turnNumber and/or an off-by-one — see probe scripts),
 *   - HOLD (action 0) satisfies when ahead and the lead is within p2,
 *   - params[3] = 1 forces HOLD in every tested state; params[3] > 1
 *     makes NO action satisfiable (params validation fails),
 *   - params[4..7] must be 0 (any nonzero value makes NO action
 *     satisfiable).
 * But the exact boundary formulas were NOT fully pinned down, so the
 * threshold policy is NOT wired into the live path: a wrong boundary
 * means an invalid proof (-2/turn), which is worse than a valid
 * EXTRACT. `thresholdPolicy` is shipped as a documented, deterministic
 * reference implementation of the inferred rules; enable it ONLY after
 * confirming it against a practice turn (see README).
 *
 * Action encoding (verified for EXTRACT; inferred for the others):
 *   0 = HOLD, 1 = FORTIFY, 2 = EXTRACT.
 * EXTRACT is certain: it is the only action that takes an amount, and
 * the circuit enforces amount == params[0] for it (line 149).
 * HOLD vs FORTIFY for 0/1 is inferred from the event page (HOLD is the
 * passive, amountless action; FORTIFY is the defensive one) and from
 * the threshold behaviour (action 1 fires when behind = defensive).
 * If a practice turn shows the mapping is swapped, swap the two
 * constants below — the circuit input uses the numbers.
 */

export type ActionName = "HOLD" | "FORTIFY" | "EXTRACT";

import { createHash } from "node:crypto";

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
  circuitVersion: number;
  params: number[];
  salt: string;
}

/** Fixed amount this strategy extracts every turn. */
export const EXTRACT_AMOUNT = 10;

/** Circuit version the strategy was committed against. Must match the
 * version the platform shows for the registered commitment. */
export const CIRCUIT_VERSION = 1;

export const STRATEGY_ID = "steal-vfy-always-extract-v1";

/**
 * Deterministic salt: SHA-256(strategy id) mod the BN128 field prime.
 * Any field element works for the circuit; what matters is that the
 * SAME salt is used every turn, because the registered commitment is
 * Poseidon(strategyParams, salt). Changing the salt after registration
 * invalidates every proof. Override with STRATEGY_SALT env only
 * BEFORE registering.
 */
export function deriveSalt(strategyId: string = STRATEGY_ID): string {
  const digest = createHash("sha256").update(strategyId, "utf8").digest("hex");
  const prime = BigInt(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617",
  );
  return (BigInt(`0x${digest}`) % prime).toString();
}

export function liveStrategy(saltOverride?: string): Strategy {
  return {
    id: STRATEGY_ID,
    circuitVersion: CIRCUIT_VERSION,
    params: [EXTRACT_AMOUNT, 0, 0, 0, 0, 0, 0, 0],
    salt: saltOverride ?? deriveSalt(),
  };
}

/**
 * LIVE policy: always EXTRACT EXTRACT_AMOUNT.
 * Verified satisfiable for the live strategy params in every probed
 * state (see header). Pure and deterministic: same state -> same move.
 */
export function decideTurn(_state: GameState): Move {
  return { action: "EXTRACT", amount: EXTRACT_AMOUNT };
}

/**
 * THRESHOLD POLICY (reference only — NOT verified end-to-end, NOT used
 * by the server). Inferred from ~300 witness-oracle probes of the
 * published circuit (scripts/probe-policy*.mjs):
 *
 *   deficit = opponentBalance - selfBalance
 *   lead    = selfBalance - opponentBalance
 *   if deficit > 0 and deficit <= fortifyThreshold (+ turn? / +1?):
 *       FORTIFY
 *   elif lead > 0 and lead <= holdThreshold (+ turn? / +1?):
 *       HOLD
 *   elif passiveMode == 1:
 *       HOLD
 *   else:
 *       EXTRACT extractAmount
 *
 * Open questions (do NOT enable until resolved against a practice turn):
 *  1. Exact boundary formula: is it `deficit <= p1 + turnNumber`,
 *     `deficit <= p1 + 1`, or something else? Probes at turn 5 could
 *     not distinguish them.
 *  2. Same for the HOLD boundary (lead vs p2).
 *  3. params[3]: 0 = play thresholds, 1 = always HOLD, >1 = params
 *     invalid. Whether 1 means "always HOLD" or "HOLD when tied" is
 *     unresolved (it forced HOLD in every tested state).
 *  4. Whether FORTIFY (action 1) and HOLD (action 0) are mapped to
 *     the platform's action names that way round.
 */
export interface ThresholdParams {
  extractAmount: number;
  fortifyThreshold: number;
  holdThreshold: number;
  passiveMode: 0 | 1;
}

export function thresholdParams(p: ThresholdParams): number[] {
  return [p.extractAmount, p.fortifyThreshold, p.holdThreshold, p.passiveMode, 0, 0, 0, 0];
}

export function decideTurnThreshold(state: GameState, p: ThresholdParams): Move {
  const deficit = state.opponentBalance - state.selfBalance;
  const lead = state.selfBalance - state.opponentBalance;
  // NOTE: boundary uses the conservative form (deficit <= threshold);
  // the circuit may allow threshold + turnNumber — see header.
  if (deficit > 0 && deficit <= p.fortifyThreshold) return { action: "FORTIFY" };
  if (lead > 0 && lead <= p.holdThreshold) return { action: "HOLD" };
  if (p.passiveMode === 1) return { action: "HOLD" };
  return { action: "EXTRACT", amount: p.extractAmount };
}
