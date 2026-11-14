// Hunt a satisfying assignment: vary strategyParams, salt, action, amount.
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const poseidon = await buildPoseidon();
const F = poseidon.F;
async function ok(input) {
  try { await snarkjs.wtns.calculate(input, wasm, "/tmp/probe.wtns"); return "SATISFIES"; }
  catch (e) { return String(e?.message || e).split("\n")[0].replace("Error: Assert Failed. Error in template VfyPolicyProof_154 line: ", "line "); }
}
const paramSets = {
  zeros: [0,0,0,0,0,0,0,0],
  ones: [1,1,1,1,1,1,1,1,1].slice(0,8),
  seq: [1,2,3,4,5,6,7,8],
  myStrategy: [3,15,10,10,19,0,0,0],
  tens: [10,10,10,10,10,10,10,10],
  mixed: [3,10,5,10,20,1,2,3],
};
for (const [pname, params] of Object.entries(paramSets)) {
  for (const salt of [0, 1, 12345]) {
    const commitment = F.toString(poseidon([...params, salt]));
    for (const action of [0, 1, 2, 3]) {
      const r = await ok({ action, amount: 0, selfBalance: 100, opponentBalance: 100,
        turnNumber: 1, matchId: 1, commitment, salt, circuitVersion: 1, strategyParams: params });
      if (r !== "line 90" && r !== "line 72") console.log(`${pname} salt=${salt} action=${action} =>`, r);
    }
  }
}
console.log("done (only non-72/90 results shown)");
