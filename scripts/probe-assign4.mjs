// Bisect line 75: single-nonzero params; and disambiguate Poseidon order.
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const poseidon = await buildPoseidon();
const F = poseidon.F;
async function line(input) {
  try { await snarkjs.wtns.calculate(input, wasm, "/tmp/probe.wtns"); return "SATISFIES"; }
  catch (e) { const m = String(e?.message || e).match(/line: (\d+)/); return m ? "line " + m[1] : String(e).slice(0, 60); }
}
const base = { action: 0, amount: 0, selfBalance: 100, opponentBalance: 100,
  turnNumber: 1, matchId: 1, circuitVersion: 1 };
// 1) which single position breaks line 75?
for (let i = 0; i < 8; i++) {
  const params = Array(8).fill(0); params[i] = 1;
  const commitment = F.toString(poseidon([...params, 0]));
  console.log(`params[${i}]=1 =>`, await line({ ...base, commitment, salt: 0, strategyParams: params }));
}
// 2) Poseidon order: params with a 1 at pos 0, salt=7
const params = [1,0,0,0,0,0,0,0];
const cSaltLast = F.toString(poseidon([...params, 7]));
const cSaltFirst = F.toString(poseidon([7, ...params]));
console.log("salt-last commitment =>", await line({ ...base, commitment: cSaltLast, salt: 7, strategyParams: params }));
console.log("salt-first commitment =>", await line({ ...base, commitment: cSaltFirst, salt: 7, strategyParams: params }));
