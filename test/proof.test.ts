/**
 * Proof tests with a MOCKED prover (fast, labelled).
 *
 * The mock proves nothing — it only checks the wiring: circuit input
 * mapping, commitment computation, the /build keccak256 audit hash,
 * and the missing-artifacts error. The REAL Groth16 proof is
 * exercised in test/proof.real.test.ts.
 *
 * The strategy used here is an explicit TEST FIXTURE (params
 * [10,0,0,0,0,0,0,0], salt "0") — it is not the agent's strategy
 * (STRATEGY_PARAMS in src/strategy.ts is a TODO for the owner).
 */
import { describe, expect, it } from "vitest";
import {
  CircuitArtifactsMissingError,
  VFY_POLICY_CIRCUIT,
  computeCommitment,
  computePublicInputsHash,
  generatePolicyProof,
  hashToField,
  toCircuitInput,
} from "../src/proof.js";
import type { Strategy } from "../src/strategy.js";

const testStrategy: Strategy = {
  id: "test-fixture",
  circuitVersion: "v1",
  params: [10, 0, 0, 0, 0, 0, 0, 0],
  salt: "0",
};

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

describe("computePublicInputsHash (/build keccak256 audit formula)", () => {
  // Test vector from scripts/probe-hash.mjs (real run, 15 Nov 2026):
  // commitment 16558...72347, UUID matchId, turn 3, 95/105, EXTRACT 10.
  const vectorCommitment =
    "16558278792999601739528827900028539763998923485550243417577873933892175672347";
  const vectorState = {
    matchId: "9f4e1b2a-1111-4000-8000-000000000001",
    turn: 3,
    selfBalance: 95,
    opponentBalance: 105,
  };

  it("matches the known keccak256 vector from the /build formula", () => {
    expect(
      computePublicInputsHash(vectorState, { action: "EXTRACT", amount: 10 }, vectorCommitment),
    ).toBe("0x3c38a8e2c7815cd57ff22531305df06cf7c287cb828ef9a01601861333269bdf");
  });

  it("is a 0x-prefixed 32-byte hash and deterministic", () => {
    const h = computePublicInputsHash(vectorState, { action: "EXTRACT", amount: 10 }, vectorCommitment);
    expect(h).toMatch(/^0x[0-9a-f]{64}$/);
    expect(computePublicInputsHash(vectorState, { action: "EXTRACT", amount: 10 }, vectorCommitment)).toBe(h);
  });

  it("changes when any field changes", () => {
    const base = computePublicInputsHash(vectorState, { action: "EXTRACT", amount: 10 }, vectorCommitment);
    expect(
      computePublicInputsHash({ ...vectorState, turn: 4 }, { action: "EXTRACT", amount: 10 }, vectorCommitment),
    ).not.toBe(base);
    expect(
      computePublicInputsHash(
        { ...vectorState, selfBalance: 96 },
        { action: "EXTRACT", amount: 10 },
        vectorCommitment,
      ),
    ).not.toBe(base);
    expect(
      computePublicInputsHash(vectorState, { action: "HOLD" }, vectorCommitment),
    ).not.toBe(base);
    expect(
      computePublicInputsHash(vectorState, { action: "EXTRACT", amount: 9 }, vectorCommitment),
    ).not.toBe(base);
    expect(
      computePublicInputsHash(vectorState, { action: "EXTRACT", amount: 10 }, "12345"),
    ).not.toBe(base);
  });

  it("uses amount 0 for HOLD/FORTIFY", () => {
    expect(computePublicInputsHash(vectorState, { action: "HOLD" }, vectorCommitment)).toBe(
      computePublicInputsHash(vectorState, { action: "HOLD", amount: 0 }, vectorCommitment),
    );
  });

  it("accepts a numeric matchId", () => {
    const h = computePublicInputsHash(
      { matchId: 7, turn: 1, selfBalance: 100, opponentBalance: 100 },
      { action: "EXTRACT", amount: 10 },
      vectorCommitment,
    );
    expect(h).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("returns null for an opaque non-UUID matchId (formula not applicable)", () => {
    expect(
      computePublicInputsHash(
        { matchId: "st_abc_123", turn: 1, selfBalance: 100, opponentBalance: 100 },
        { action: "EXTRACT", amount: 10 },
        vectorCommitment,
      ),
    ).toBeNull();
  });

  it("is NOT the circuit's publicSignals[0] (verified live — different hash)", async () => {
    // The real proof for the vector state has publicSignals[0] =
    // 18054142780609337750274101543188595559682643761682875673550740777443638678843
    // (scripts/probe-hash.mjs). The keccak audit value differs; the
    // two must never be confused (see src/proof.ts header).
    const h = computePublicInputsHash(vectorState, { action: "EXTRACT", amount: 10 }, vectorCommitment);
    expect(BigInt(h as string).toString()).not.toBe(
      "18054142780609337750274101543188595559682643761682875673550740777443638678843",
    );
  });
});

describe("toCircuitInput", () => {
  const strategy = { ...testStrategy, salt: "0" };

  it("maps an EXTRACT to circuit inputs", async () => {
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

  it("uses the UUID hex value as the circuit matchId (platform encoding)", async () => {
    const commitment = await computeCommitment(strategy.params, "0");
    const input = toCircuitInput(
      { matchId: "9f4e1b2a-1111-4000-8000-000000000001", turn: 1, selfBalance: 100, opponentBalance: 100 },
      { action: "EXTRACT", amount: 10 },
      strategy,
      commitment,
    );
    expect(input.matchId).toBe(BigInt("0x9f4e1b2a111140008000000000000001").toString());
  });

  it("hashes other opaque string match ids to a field element", async () => {
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
    const strategy = testStrategy;
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
    const strategy = testStrategy;
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
