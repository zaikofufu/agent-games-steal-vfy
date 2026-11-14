/**
 * Proof tests with a MOCKED prover (fast, labelled).
 *
 * The mock proves nothing — it only checks the wiring: circuit input
 * mapping, commitment computation, and the missing-artifacts error.
 * The REAL Groth16 proof is exercised in test/proof.real.test.ts.
 */
import { describe, expect, it } from "vitest";
import {
  CircuitArtifactsMissingError,
  VFY_POLICY_CIRCUIT,
  computeCommitment,
  generatePolicyProof,
  hashToField,
  toCircuitInput,
} from "../src/proof.js";
import { liveStrategy } from "../src/strategy.js";

describe("circuit constants", () => {
  it("matches /api/circuit-info (verified 14 Nov 2026)", () => {
    expect(VFY_POLICY_CIRCUIT.network).toBe("mainnet");
    expect(VFY_POLICY_CIRCUIT.vkHash).toBe(
      "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
    );
    expect(VFY_POLICY_CIRCUIT.wasmUrl).toBe("https://agentgames.zkverify.io/circuits/vfy-policy.wasm");
    expect(VFY_POLICY_CIRCUIT.zkeyUrl).toBe(
      "https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey",
    );
    expect(VFY_POLICY_CIRCUIT.nPublic).toBe(9);
  });
});

describe("computeCommitment", () => {
  it("is Poseidon(strategyParams, salt), salt last", async () => {
    // Reference value verified against the circuit: for params
    // [1,0,0,0,0,0,0,0] and salt 0, the circuit's line-72 assert
    // passes with this commitment (and it appears as publicSignals[1]
    // in the real proof — see proof.real.test.ts).
    expect(await computeCommitment([1, 0, 0, 0, 0, 0, 0, 0], "0")).toBe(
      "11299471465817035813941534680224295417418949445559228777402254279479107204147",
    );
  });

  it("is deterministic and salt-sensitive", async () => {
    const a = await computeCommitment([10, 0, 0, 0, 0, 0, 0, 0], "0");
    expect(a).toBe(await computeCommitment([10, 0, 0, 0, 0, 0, 0, 0], "0"));
    expect(a).not.toBe(await computeCommitment([10, 0, 0, 0, 0, 0, 0, 0], "1"));
    expect(a).not.toBe(await computeCommitment([9, 0, 0, 0, 0, 0, 0, 0], "0"));
  });

  it("rejects params that are not length 8", async () => {
    await expect(computeCommitment([1, 2, 3], "0")).rejects.toThrow();
  });
});

describe("toCircuitInput", () => {
  const strategy = { ...liveStrategy(), salt: "0" };

  it("maps a live-strategy EXTRACT to circuit inputs", async () => {
    const commitment = await computeCommitment(strategy.params, "0");
    const input = toCircuitInput(
      { matchId: 7, turn: 3, selfBalance: 90, opponentBalance: 110 },
      { action: "EXTRACT", amount: 10 },
      strategy,
      commitment,
    );
    expect(input).toMatchObject({
      action: "2",
      amount: "10",
      selfBalance: "90",
      opponentBalance: "110",
      turnNumber: "3",
      matchId: "7",
      commitment,
      salt: "0",
      circuitVersion: "1",
    });
    expect(input.strategyParams).toEqual(["10", "0", "0", "0", "0", "0", "0", "0"]);
  });

  it("hashes opaque string match ids to a field element", async () => {
    const commitment = await computeCommitment(strategy.params, "0");
    const input = toCircuitInput(
      { matchId: "st_abc_123", turn: 1, selfBalance: 100, opponentBalance: 100 },
      { action: "EXTRACT", amount: 10 },
      strategy,
      commitment,
    );
    expect(input.matchId).toBe(hashToField("st_abc_123"));
  });
});

describe("generatePolicyProof (mocked prover)", () => {
  it("uses an injected prover and returns its proof verbatim", async () => {
    const strategy = liveStrategy();
    const commitment = await computeCommitment(strategy.params, strategy.salt);
    const fake = { proof: { pi_a: ["1"] }, publicSignals: ["a", "b"] };
    const out = await generatePolicyProof(
      { matchId: 1, turn: 1, selfBalance: 100, opponentBalance: 100 },
      { action: "EXTRACT", amount: 10 },
      strategy,
      commitment,
      { prover: async () => fake },
    );
    expect(out).toBe(fake);
  });

  it("throws CircuitArtifactsMissingError without a prover or artifacts", async () => {
    const strategy = liveStrategy();
    await expect(
      generatePolicyProof(
        { matchId: 1, turn: 1, selfBalance: 100, opponentBalance: 100 },
        { action: "EXTRACT", amount: 10 },
        strategy,
        "0",
        {},
      ),
    ).rejects.toBeInstanceOf(CircuitArtifactsMissingError);
  });
});
