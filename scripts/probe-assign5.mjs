// params[0]=1 reaches line 140. Sweep action/amount/cv there; also vary params[0].
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const poseidon = await buildPoseidon();
const F = poseidon.F;
async function line(input) {
  try { await snarkjs.wtns.calculate(input, wasm, "/tmp/probe.wtns"); return "SATISFIES"; }
  catch (e) { const m = String(e?.message || e).match(/line: (\d+)/); return m ? "line " + m[1] : String(e).slice(0, 60); }
}
const base = { selfBalance: 100, opponentBalance: 100, turnNumber: 1, matchId: 1, salt: 0 };
for (const p0 of [1, 2, 3, 5, 10]) {
  const params = [p0,0,0,0,0,0,0,0];
  const commitment = F.toString(poseidon([...params, 0]));
  for (const action of [0, 1, 2, 3]) {
    for (const amount of [0, 1, 10]) {
      const r = await line({ ...base, action, amount, commitment, strategyParams: params, circuitVersion: 1 });
      if (r !== "line 140") console.log(`p0=${p0} action=${action} amt=${amount} =>`, r);
    }
  }
}
console.log("done (only non-140 results shown)");
