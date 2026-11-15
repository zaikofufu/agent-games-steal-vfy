/**
 * One-off probe (NOT part of the shipped agent): does the /build
 * keccak256 publicInputsHash formula equal the circuit's
 * publicSignals[0] for a real proof?
 *
 * Uses the previously verified strategy params [10,0,0,0,0,0,0,0]
 * (always EXTRACT 10) ONLY as a known-good probe input — the shipped
 * agent no longer hardcodes any strategy.
 *
 * Run: node scripts/probe-hash.mjs
 */
import { createHash } from "node:crypto";
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import { keccak256, concat, numberToHex } from "viem";

const PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

const params = [10, 0, 0, 0, 0, 0, 0, 0];
const salt = (
  BigInt(`0x${createHash("sha256").update("steal-vfy-always-extract-v1", "utf8").digest("hex")}`) % PRIME
).toString();

const poseidon = await buildPoseidon();
const commitment = poseidon.F.toString(poseidon([...params.map((p) => BigInt(p)), BigInt(salt)]));
console.log("commitment:", commitment);
console.log("salt:      (probe-only, not printed by shipped code)");

const matchIdUuid = "9f4e1b2a-1111-4000-8000-000000000001";
const turn = 3;
const selfBalance = 95;
const opponentBalance = 105;
const action = "EXTRACT";
const amount = 10;

// Circuit input: matchId as UUID-hex field element (the encoding the
// /build keccak formula uses).
const matchIdField = BigInt("0x" + matchIdUuid.replace(/-/g, "")).toString();
const input = {
  action: "2",
  amount: String(amount),
  selfBalance: String(selfBalance),
  opponentBalance: String(opponentBalance),
  turnNumber: String(turn),
  matchId: matchIdField,
  commitment,
  salt,
  circuitVersion: "1",
  strategyParams: params.map(String),
};

const { proof, publicSignals } = await snarkjs.groth16.fullProve(
  input,
  "circuits/vfy-policy.wasm",
  "circuits/vfy-policy_final.zkey",
);
console.log("publicSignals[0] (circuit):", publicSignals[0]);

// /build formula: keccak256 of ABI-packed fields, 32 bytes BE each.
const hash = keccak256(
  concat([
    numberToHex(BigInt(commitment), { size: 32 }),
    numberToHex(BigInt("0x" + matchIdUuid.replace(/-/g, "")), { size: 32 }),
    numberToHex(BigInt(turn), { size: 32 }),
    numberToHex(BigInt(selfBalance), { size: 32 }),
    numberToHex(BigInt(opponentBalance), { size: 32 }),
    numberToHex({ HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n }[action], { size: 32 }),
    numberToHex(BigInt(amount), { size: 32 }),
    numberToHex(1n, { size: 32 }),
  ]),
);
console.log("keccak256 (/build formula):", hash);
console.log("keccak as field element:  ", (BigInt(hash) % PRIME).toString());
console.log("MATCH (raw decimal):      ", BigInt(hash).toString() === publicSignals[0]);
console.log("MATCH (mod prime):        ", (BigInt(hash) % PRIME).toString() === publicSignals[0]);
