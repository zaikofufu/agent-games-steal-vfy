/**
 * Strategy tests.
 *
 * The generic policy is a pure function of (state, params) — it
 * encodes the circuit's threshold branches, not a competitive choice.
 * Tests pass their own params explicitly; the shipped
 * STRATEGY_PARAMS is a TODO placeholder and is never asserted as a
 * strategy here (its value is the owner's to fill in). Circuit
 * satisfiability of a given params+move combination is proven for
 * real in test/proof.real.test.ts.
 */
import { describe, expect, it } from "vitest";
import {
  ACTION_CODE,
  CIRCUIT_VERSION,
  MATCH_TURNS,
  STRATEGY_PARAMS,
  isPlaceholderStrategy,
  loadStrategy,
  paramsFromThreshold,
  policy,
  validateParams,
} from "../src/strategy.js";

const states = [
  { matchId: "m1", turn: 1, selfBalance: 100, opponentBalance: 100 },
  { matchId: "m1", turn: 20, selfBalance: 50, opponentBalance: 150 },
  { matchId: "m1", turn: 10, selfBalance: 150, opponentBalance: 50 },
  { matchId: 7, turn: 3, selfBalance: 0, opponentBalance: 200 },
];

describe("policy (generic threshold branches)", () => {
  const p = { extractAmount: 10, fortifyThreshold: 20, holdThreshold: 10, passiveMode: 0 as const };
  const params = paramsFromThreshold(p);

  it("fortifies when behind within the threshold", () => {
    expect(policy({ matchId: "m", turn: 5, selfBalance: 90, opponentBalance: 100 }, params)).toEqual({
      action: "FORTIFY",
    });
  });

  it("holds when ahead within the threshold", () => {
    expect(policy({ matchId: "m", turn: 5, selfBalance: 105, opponentBalance: 100 }, params)).toEqual({
      action: "HOLD",
    });
  });

  it("extracts otherwise (far behind and far ahead)", () => {
    expect(policy({ matchId: "m", turn: 5, selfBalance: 50, opponentBalance: 150 }, params)).toEqual({
      action: "EXTRACT",
      amount: 10,
    });
    expect(policy({ matchId: "m", turn: 5, selfBalance: 150, opponentBalance: 50 }, params)).toEqual({
      action: "EXTRACT",
      amount: 10,
    });
  });

  it("extracts on a tie (no deficit, no lead)", () => {
    expect(policy({ matchId: "m", turn: 1, selfBalance: 100, opponentBalance: 100 }, params)).toEqual({
      action: "EXTRACT",
      amount: 10,
    });
  });

  it("holds everywhere when passiveMode is 1", () => {
    const passive = paramsFromThreshold({ ...p, passiveMode: 1 });
    for (const state of states) {
      expect(policy(state, passive)).toEqual({ action: "HOLD" });
    }
  });

  it("is deterministic: same state + params -> same move", () => {
    const s = states[0];
    expect(policy(s, params)).toEqual(policy(s, params));
  });

  it("omits amount for HOLD/FORTIFY (schema rejects the field)", () => {
    expect(policy({ matchId: "m", turn: 5, selfBalance: 90, opponentBalance: 100 }, params)).not.toHaveProperty(
      "amount",
    );
  });

  it("encodes threshold params as [amount, fortify, hold, passive, 0, 0, 0, 0]", () => {
    expect(params).toEqual([10, 20, 10, 0, 0, 0, 0, 0]);
  });
});

describe("validateParams", () => {
  it("accepts a well-formed 8-element params array", () => {
    expect(() => validateParams([10, 20, 10, 0, 0, 0, 0, 0])).not.toThrow();
    expect(() => validateParams([0, 0, 0, 0, 0, 0, 0, 0])).not.toThrow();
  });

  it("rejects the wrong length", () => {
    expect(() => validateParams([10, 0, 0])).toThrow();
  });

  it("rejects passiveMode > 1 and nonzero reserved slots", () => {
    expect(() => validateParams([10, 0, 0, 2, 0, 0, 0, 0])).toThrow();
    expect(() => validateParams([10, 0, 0, 0, 1, 0, 0, 0])).toThrow();
  });

  it("rejects non-integers and negatives", () => {
    expect(() => validateParams([10.5, 0, 0, 0, 0, 0, 0, 0])).toThrow();
    expect(() => validateParams([-1, 0, 0, 0, 0, 0, 0, 0])).toThrow();
  });
});

describe("TODO placeholder + loading", () => {
  it("ships STRATEGY_PARAMS as the all-zero TODO placeholder", () => {
    expect(STRATEGY_PARAMS).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(isPlaceholderStrategy()).toBe(true);
    expect(isPlaceholderStrategy([10, 0, 0, 0, 0, 0, 0, 0])).toBe(false);
  });

  it("loadStrategy refuses to load without a salt", () => {
    expect(() => loadStrategy(undefined)).toThrow(/STRATEGY_SALT/);
    expect(() => loadStrategy("")).toThrow(/STRATEGY_SALT/);
  });

  it("loadStrategy refuses a non-numeric salt", () => {
    expect(() => loadStrategy("not-a-number")).toThrow(/STRATEGY_SALT/);
  });

  it("loadStrategy loads with a salt and keeps the params", () => {
    const s = loadStrategy("12345");
    expect(s.params).toEqual(STRATEGY_PARAMS);
    expect(s.salt).toBe("12345");
    expect(s.circuitVersion).toBe(CIRCUIT_VERSION);
  });

  it("action codes match the circuit: HOLD 0, FORTIFY 1, EXTRACT 2", () => {
    expect(ACTION_CODE).toEqual({ HOLD: 0, FORTIFY: 1, EXTRACT: 2 });
  });

  it("match is 20 turns", () => {
    expect(MATCH_TURNS).toBe(20);
  });
});
