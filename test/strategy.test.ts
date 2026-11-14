/**
 * Strategy tests.
 *
 * The live policy (always EXTRACT 10) is asserted for determinism and
 * shape. Its circuit-satisfiability is proven for real in
 * test/proof.real.test.ts (fullProve + groth16.verify) — unit tests
 * here do not re-prove it.
 */
import { describe, expect, it } from "vitest";
import {
  ACTION_CODE,
  CIRCUIT_VERSION,
  EXTRACT_AMOUNT,
  MATCH_TURNS,
  STRATEGY_ID,
  decideTurn,
  decideTurnThreshold,
  deriveSalt,
  liveStrategy,
  thresholdParams,
} from "../src/strategy.js";

const states = [
  { matchId: "m1", turn: 1, selfBalance: 100, opponentBalance: 100 },
  { matchId: "m1", turn: 20, selfBalance: 50, opponentBalance: 150 },
  { matchId: "m1", turn: 10, selfBalance: 150, opponentBalance: 50 },
  { matchId: 7, turn: 3, selfBalance: 0, opponentBalance: 200 },
];

describe("live strategy", () => {
  it("always EXTRACTs the fixed amount, in every state", () => {
    for (const state of states) {
      expect(decideTurn(state)).toEqual({ action: "EXTRACT", amount: EXTRACT_AMOUNT });
    }
  });

  it("is deterministic: same state -> same move", () => {
    const s = states[0];
    expect(decideTurn(s)).toEqual(decideTurn(s));
  });

  it("commits params [10, 0, 0, 0, 0, 0, 0, 0] (extract amount first, rest reserved-zero)", () => {
    const s = liveStrategy();
    expect(s.id).toBe(STRATEGY_ID);
    expect(s.circuitVersion).toBe(CIRCUIT_VERSION);
    expect(s.params).toEqual([EXTRACT_AMOUNT, 0, 0, 0, 0, 0, 0, 0]);
    expect(s.params).toHaveLength(8);
  });

  it("derives the same salt every time (commitment must be stable)", () => {
    expect(deriveSalt()).toBe(deriveSalt());
    expect(deriveSalt("other-id")).not.toBe(deriveSalt());
    expect(BigInt(deriveSalt())).toBeLessThan(
      BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617"),
    );
  });

  it("action codes match the circuit: HOLD 0, FORTIFY 1, EXTRACT 2", () => {
    expect(ACTION_CODE).toEqual({ HOLD: 0, FORTIFY: 1, EXTRACT: 2 });
  });

  it("match is 20 turns", () => {
    expect(MATCH_TURNS).toBe(20);
  });
});

describe("threshold policy (reference only — NOT the live policy)", () => {
  const p = { extractAmount: 10, fortifyThreshold: 20, holdThreshold: 10, passiveMode: 0 as const };
  it("fortifies when behind within the threshold", () => {
    expect(
      decideTurnThreshold({ matchId: "m", turn: 5, selfBalance: 90, opponentBalance: 100 }, p),
    ).toEqual({ action: "FORTIFY" });
  });
  it("holds when ahead within the threshold", () => {
    expect(
      decideTurnThreshold({ matchId: "m", turn: 5, selfBalance: 105, opponentBalance: 100 }, p),
    ).toEqual({ action: "HOLD" });
  });
  it("extracts otherwise", () => {
    expect(
      decideTurnThreshold({ matchId: "m", turn: 5, selfBalance: 50, opponentBalance: 150 }, p),
    ).toEqual({ action: "EXTRACT", amount: 10 });
    expect(
      decideTurnThreshold({ matchId: "m", turn: 5, selfBalance: 150, opponentBalance: 50 }, p),
    ).toEqual({ action: "EXTRACT", amount: 10 });
  });
  it("encodes params as [amount, fortify, hold, passive, 0, 0, 0, 0]", () => {
    expect(thresholdParams(p)).toEqual([10, 20, 10, 0, 0, 0, 0, 0]);
  });
});
