/**
 * REAL Groth16 test: fullProve + groth16.verify against the published
 * vfy-policy circuit. Skipped if circuits/ is absent.
 *
 * This is the test that matters: it proves a move actually satisfies
 * the published circuit, and that the returned public signals have
 * the documented layout:
 *   [0] the circuit's own public-inputs hash, [1] commitment,
 *   [2] matchId, [3] turnNumber, [4] selfBalance,
 *   [5] opponentBalance, [6] action, [7] amount, [8] circuitVersion.
 *
 * The strategy used here is an explicit TEST FIXTURE (params
 * [10,0,0,0,0,0,0,0], fixed salt) chosen because it is the
 * combination already known to satisfy the circuit for EXTRACT 10.
 * It exists to prove the HARNESS end to end — it is not the agent's
 * strategy (STRATEGY_PARAMS in src/strategy.ts is a TODO).
 *
 * fullProve takes a few seconds; the test timeout is 120s.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { describe, expect, it } from "vitest";
import { computeCommitment, computePublicInputsHash, generatePolicyProof } from "../src/proof.js";
import type { Strategy } from "../src/strategy.js";

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = join(here, "..", "circuits", "vfy-policy.wasm");
const zkeyPath = join(here, "..", "circuits", "vfy-policy_final.zkey");
const vkPath = join(here, "..", "circuits", "vk.json");
const hasCircuits = existsSync(wasmPath) && existsSync(zkeyPath) && existsSync(vkPath);

/** Test fixture only — see the header. */
const fixtureStrategy: Strategy = {
  id: "test-fixture-always-extract-10",
  circuitVersion: "v1",
  params: [10, 0, 0, 0, 0, 0, 0, 0],
  salt: "12345",
};

describe.skipIf(!hasCircuits)("real policy proof (Groth16)", () => {
  it(
    "proves + verifies the fixture EXTRACT move (UUID matchId)",
    async () => {
      const strategy = fixtureStrategy;
      const commitment = await computeCommitment(strategy.params, strategy.salt);
      const state = {
        matchId: "9f4e1b2a-1111-4000-8000-000000000001",
        turn: 3,
        selfBalance: 95,
        opponentBalance: 105,
      };
      const move = { action: "EXTRACT" as const, amount: 10 };
      const out = await generatePolicyProof(state, move, strategy, commitment, {
        wasmPath,
        zkeyPath,
      });
      expect(out.publicSignals).toHaveLength(9);
      expect(out.publicSignals[1]).toBe(commitment);
      expect(out.publicSignals[2]).toBe(BigInt("0x9f4e1b2a111140008000000000000001").toString()); // matchId (UUID hex)
      expect(out.publicSignals[3]).toBe("3"); // turnNumber
      expect(out.publicSignals[4]).toBe("95"); // selfBalance
      expect(out.publicSignals[5]).toBe("105"); // opponentBalance
      expect(out.publicSignals[6]).toBe("2"); // action EXTRACT
      expect(out.publicSignals[7]).toBe("10"); // amount
      expect(out.publicSignals[8]).toBe("1"); // circuitVersion

      // The /build keccak audit hash is a DIFFERENT value from the
      // circuit's publicSignals[0] (verified live) — the two must
      // never be confused. The audit field carries the keccak value.
      const auditHash = computePublicInputsHash(state, move, commitment);
      expect(auditHash).toMatch(/^0x[0-9a-f]{64}$/);
      expect(BigInt(auditHash as string).toString()).not.toBe(out.publicSignals[0]);

      const vk = JSON.parse(readFileSync(vkPath, "utf8"));
      expect(await snarkjs.groth16.verify(vk, out.publicSignals, out.proof)).toBe(true);
    },
    120_000,
  );

  it(
    "proves + verifies a late-turn, behind move too (numeric matchId)",
    async () => {
      const strategy = fixtureStrategy;
      const commitment = await computeCommitment(strategy.params, strategy.salt);
      const state = { matchId: 42, turn: 19, selfBalance: 60, opponentBalance: 140 };
      const out = await generatePolicyProof(state, { action: "EXTRACT", amount: 10 }, strategy, commitment, {
        wasmPath,
        zkeyPath,
      });
      expect(out.publicSignals[2]).toBe("42");
      expect(out.publicSignals[3]).toBe("19");
      const vk = JSON.parse(readFileSync(vkPath, "utf8"));
      expect(await snarkjs.groth16.verify(vk, out.publicSignals, out.proof)).toBe(true);
    },
    120_000,
  );
});
