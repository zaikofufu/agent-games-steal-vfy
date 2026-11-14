// Grid-search a satisfying assignment for VfyPolicyProof (witness calc = fast oracle).
import * as snarkjs from "snarkjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
async function ok(input) {
  try { await snarkjs.wtns.calculate(input, wasm, "/tmp/probe.wtns"); return true; }
  catch (e) { return String(e?.message || e).split("\n")[0].slice(0, 90); }
}
const base = { amount: 0, selfBalance: 100, opponentBalance: 100, turnNumber: 1,
  matchId: 1, commitment: 0, salt: 0, strategyParams: Array(8).fill(0) };
for (const action of [0, 1, 2, 3]) {
  for (const circuitVersion of [0, 1, 2]) {
    const r = await ok({ ...base, action, circuitVersion });
    console.log(`action=${action} circuitVersion=${circuitVersion} =>`, r === true ? "SATISFIES" : r);
  }
}
