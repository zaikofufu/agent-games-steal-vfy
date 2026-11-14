// 1) Real fullProve + verify with a satisfying assignment.
// 2) Map public-signal order via the witness vector (w[1..9]).
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import { readFileSync } from "node:fs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const zkey = new URL("../circuits/vfy-policy_final.zkey", import.meta.url).pathname;
const vk = JSON.parse(readFileSync(new URL("../circuits/vk.json", import.meta.url), "utf8"));
const poseidon = await buildPoseidon();
const F = poseidon.F;
const params = [1,0,0,0,0,0,0,0];
const input = { action: 2, amount: 1, selfBalance: 100, opponentBalance: 100,
  turnNumber: 1, matchId: 1, commitment: F.toString(poseidon([...params, 0])),
  salt: 0, circuitVersion: 1, strategyParams: params };
console.log("fullProve...");
const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
console.log("publicSignals:", JSON.stringify(publicSignals));
console.log("verify:", await snarkjs.groth16.verify(vk, publicSignals, proof));
// Map order: change one scalar at a time (witness calc is fast), diff w[1..9].
async function witnessSignals(inp) {
  const w = await snarkjs.wtns.calculate(inp, wasm, "/tmp/probe.wtns");
  return w.slice(1, 10).map((x) => x.toString());
}
const base = await witnessSignals(input);
console.log("witness public (base):", JSON.stringify(base));
for (const [k, v] of [["selfBalance", 90], ["opponentBalance", 80], ["turnNumber", 2], ["matchId", 7], ["salt", 5], ["circuitVersion", 2], ["action", 2]]) {
  const alt = await witnessSignals({ ...input, [k]: v, commitment: input.commitment });
  const diff = alt.map((x, i) => (x !== base[i] ? i : -1)).filter((i) => i >= 0);
  console.log(`vary ${k} -> changed public-signal indices:`, JSON.stringify(diff), alt);
}
