// Pin down public-signal indices 4/5 (balances) and 7/8 (amount/circuitVersion).
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const zkey = new URL("../circuits/vfy-policy_final.zkey", import.meta.url).pathname;
const poseidon = await buildPoseidon();
const F = poseidon.F;
const P = (arr) => F.toString(poseidon(arr.map((x) => BigInt(x))));
const params = [1,0,0,0,0,0,0,0];
const commitment = P([...params, 0]);
const base = { action: 2, amount: 1, selfBalance: 100, opponentBalance: 100,
  turnNumber: 1, matchId: 1, commitment, salt: 0, circuitVersion: 1, strategyParams: params };
const { publicSignals } = await snarkjs.groth16.fullProve(base, wasm, zkey);
console.log("base:", JSON.stringify(publicSignals));
for (const [label, patch] of [
  ["selfBalance 100->90", { selfBalance: 90 }],
  ["opponentBalance 100->80", { opponentBalance: 80 }],
  ["amount 1->10 (params[0]=10)", { amount: 10, strategyParams: [10,0,0,0,0,0,0,0], commitment: P([10,0,0,0,0,0,0,0,0]) }],
]) {
  const r = await snarkjs.groth16.fullProve({ ...base, ...patch }, wasm, zkey);
  const diff = r.publicSignals.map((x, i) => (x !== publicSignals[i] ? `${i}:${publicSignals[i]}->${x}` : null)).filter(Boolean);
  console.log(label, "=>", JSON.stringify(diff));
}
