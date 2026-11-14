// Does params[3] act as a lead threshold for HOLD? Do params[1]/[2] ever yield FORTIFY (a1)?
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const poseidon = await buildPoseidon();
const F = poseidon.F;
async function satisfying(params, turn, s, o) {
  const commitment = F.toString(poseidon([...params, 0]));
  const good = [];
  for (const [action, amount] of [[0,0],[1,0],[2,params[0]],[3,0]]) {
    try {
      await snarkjs.wtns.calculate({ action, amount, selfBalance: s, opponentBalance: o,
        turnNumber: turn, matchId: 1, commitment, salt: 0, circuitVersion: 1, strategyParams: params }, wasm, "/tmp/probe.wtns");
      good.push(`a${action}`);
    } catch { /* no */ }
  }
  return good.join(",") || "(none)";
}
// params[3]=5 at various leads
for (const [s, o] of [[100,100],[120,80],[80,120],[105,95],[95,105],[150,50],[50,150]]) {
  console.log(`p3=5 self=${s} opp=${o} lead=${s-o} turn=5 =>`, await satisfying([1,0,0,5,0,0,0,0], 5, s, o));
}
// params[1]=5 / params[2]=5 across turns (lead 0) — any FORTIFY?
for (const idx of [1, 2]) {
  for (const turn of [1, 2, 3, 4, 5, 6, 10]) {
    const params = [1,0,0,0,0,0,0,0]; params[idx] = 5;
    console.log(`params[${idx}]=5 turn=${turn} =>`, await satisfying(params, turn, 100, 100));
  }
}
