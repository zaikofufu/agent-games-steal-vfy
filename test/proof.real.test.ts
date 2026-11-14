/**
 * REAL Groth16 test: fullProve + groth16.verify against the published
 * vfy-policy circuit. Skipped if circuits/ is absent.
 *
 * This is the test that matters: it proves the live strategy's move
 * (always EXTRACT 10) actually satisfies the published circuit, and
 * that the returned public signals have the documented layout:
 *   [0] public-inputs hash, [1] commitment, [2] matchId,
 *   [3] turnNumber, [4] selfBalance, [5] opponentBalance,
 *   [6] action, [7] amount, [8] circuitVersion.
 *
 * fullProve takes a few seconds; the test timeout is 120s.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { describe, expect, it } from "vitest";
import { computeCommitment, generatePolicyProof } from "../src/proof.js";
import { liveStrategy } from "../src/strategy.js";

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = join(here, "..", "circuits", "vfy-policy.wasm");
const zkeyPath = join(here, "..", "circuits", "vfy-policy_final.zkey");
const vkPath = join(here, "..", "circuits", "vk.json");
const hasCircuits = existsSync(wasmPath) && existsSync(zkeyPath) && existsSync(vkPath);

describe.skipIf(!hasCircuits)("real policy proof (Groth16)", () => {
  it(
    "proves + verifies the live strategy's EXTRACT move",
    async () => {
      const strategy = liveStrategy();
      const commitment = await computeCommitment(strategy.params, strategy.salt);
      const state = { matchId: 1, turn: 1, selfBalance: 100, opponentBalance: 100 };
      const out = await generatePolicyProof(state, { action: "EXTRACT", amount: 10 }, strategy, commitment, {
        wasmPath,
        zkeyPath,
      });
      expect(out.publicSignals).toHaveLength(9);
      expect(out.publicSignals[1]).toBe(commitment);
      expect(out.publicSignals[2]).toBe("1"); // matchId
      expect(out.publicSignals[3]).toBe("1"); // turnNumber
      expect(out.publicSignals[4]).toBe("100"); // selfBalance
      expect(out.publicSignals[5]).toBe("100"); // opponentBalance
      expect(out.publicSignals[6]).toBe("2"); // action EXTRACT
      expect(out.publicSignals[7]).toBe("10"); // amount
      expect(out.publicSignals[8]).toBe("1"); // circuitVersion

      const vk = JSON.parse(readFileSync(vkPath, "utf8"));
      expect(await snarkjs.groth16.verify(vk, out.publicSignals, out.proof)).toBe(true);
    },
    120_000,
  );

  it(
    "proves + verifies a late-turn, behind move too",
    async () => {
      const strategy = liveStrategy();
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
