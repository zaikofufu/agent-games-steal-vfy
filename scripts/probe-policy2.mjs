// Are params[1..7] turn-bounded? Test single-nonzero params at later turns.
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const poseidon = await buildPoseidon();
const F = poseidon.F;
async function line(input) {
  try { await snarkjs.wtns.calculate(input, wasm, "/tmp/probe.wtns"); return "OK"; }
  catch (e) { const m = String(e?.message || e).match(/line: (\d+)/); return m ? "L" + m[1] : "ERR"; }
}
async function testParams(params, turn) {
  const commitment = F.toString(poseidon([...params, 0]));
  const out = [];
  for (const [action, amount] of [[0,0],[1,0],[2,params[0]],[3,0]]) {
    const r = await line({ action, amount, selfBalance: 100, opponentBalance: 100,
      turnNumber: turn, matchId: 1, commitment, salt: 0, circuitVersion: 1, strategyParams: params });
    if (r === "OK") out.push(`a${action}`);
  }
  return out.length ? out.join(",") : "(none)";
}
for (const idx of [1, 2, 3, 4, 5, 6, 7]) {
  for (const turn of [1, 2, 3, 5, 10]) {
    const params = Array(8).fill(0); params[0] = 1; params[idx] = 1;
    console.log(`params[${idx}]=1 turn=${turn} => satisfying:`, await testParams(params, turn));
  }
}
