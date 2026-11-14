// Map the policy: params=[1,0,0,0,0,0,0,0], which action satisfies per state?
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const poseidon = await buildPoseidon();
const F = poseidon.F;
async function line(input) {
  try { await snarkjs.wtns.calculate(input, wasm, "/tmp/probe.wtns"); return "OK"; }
  catch (e) { const m = String(e?.message || e).match(/line: (\d+)/); return m ? "L" + m[1] : "ERR"; }
}
const params = [1,0,0,0,0,0,0,0];
const commitment = F.toString(poseidon([...params, 0]));
for (const turn of [1, 2, 5, 10, 19, 20]) {
  for (const [s, o] of [[100,100],[120,80],[80,120],[150,50],[50,150]]) {
    const good = [];
    for (const [action, amount] of [[0,0],[1,0],[2,1],[3,0]]) {
      const r = await line({ action, amount, selfBalance: s, opponentBalance: o,
        turnNumber: turn, matchId: 1, commitment, salt: 0, circuitVersion: 1, strategyParams: params });
      if (r === "OK") good.push(`a${action}/amt${amount}`);
    }
    console.log(`turn=${turn} self=${s} opp=${o} => satisfying: ${good.join(", ") || "(none)"}`);
  }
}
