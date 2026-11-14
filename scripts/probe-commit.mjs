// Test whether `commitment` is a Poseidon hash of strategyParams (etc.).
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const poseidon = await buildPoseidon();
const F = poseidon.F;
async function ok(input) {
  try { await snarkjs.wtns.calculate(input, wasm, "/tmp/probe.wtns"); return "SATISFIES"; }
  catch (e) { return String(e?.message || e).split("\n")[0].slice(0, 80); }
}
const params = Array(8).fill(0);
const variants = {
  "poseidon(params)": F.toString(poseidon(params)),
  "poseidon(params+salt0)": F.toString(poseidon([...params, 0])),
  "poseidon(salt0+params)": F.toString(poseidon([0, ...params])),
  "poseidon(params) with salt=1": F.toString(poseidon(params)),
};
for (const [label, commitment] of Object.entries(variants)) {
  for (const action of [0, 1, 2]) {
    const r = await ok({ action, amount: 0, selfBalance: 100, opponentBalance: 100,
      turnNumber: 1, matchId: 1, commitment, salt: label.includes("salt=1") ? 1 : 0,
      circuitVersion: 1, strategyParams: params });
    console.log(`${label} action=${action} =>`, r);
  }
}
