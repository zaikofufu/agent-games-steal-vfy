// commitment = Poseidon(strategyParams[8], salt) passes line 72. Now grid line 90.
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const poseidon = await buildPoseidon();
const F = poseidon.F;
async function ok(input) {
  try { await snarkjs.wtns.calculate(input, wasm, "/tmp/probe.wtns"); return "SATISFIES"; }
  catch (e) { return String(e?.message || e).split("\n")[0].replace("Error: Assert Failed. Error in template VfyPolicyProof_154 line: ", "line "); }
}
const params = Array(8).fill(0);
const commitment = F.toString(poseidon([...params, 0]));
const base = { selfBalance: 100, opponentBalance: 100, turnNumber: 1, matchId: 1,
  commitment, salt: 0, strategyParams: params };
for (const action of [0, 1, 2, 3]) {
  for (const circuitVersion of [0, 1, 2, 3]) {
    for (const amount of [0, 10]) {
      const r = await ok({ ...base, action, circuitVersion, amount });
      if (r === "SATISFIES" || !String(r).includes("line 90")) console.log(`action=${action} cv=${circuitVersion} amt=${amount} =>`, r);
    }
  }
}
console.log("--- (only non-line-90 results shown above; all others failed at line 90) ---");
// vary turn/match with the most plausible action
for (const turnNumber of [0, 2, 20]) {
  for (const matchId of [0, 2]) {
    console.log(`turn=${turnNumber} match=${matchId} =>`, await ok({ ...base, action: 1, circuitVersion: 1, amount: 0, turnNumber, matchId }));
  }
}
