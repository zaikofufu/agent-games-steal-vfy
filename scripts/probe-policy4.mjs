// Final policy sweep: extreme leads + large p1/p2 — is FORTIFY (a1) ever satisfiable?
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
for (const p1 of [20, 50, 100]) {
  for (const [s, o] of [[60,140],[140,60],[100,100]]) {
    console.log(`p1=${p1} self=${s} opp=${o} =>`, await satisfying([1,p1,0,0,0,0,0,0], 5, s, o));
  }
}
for (const p2 of [20, 50, 100]) {
  for (const [s, o] of [[60,140],[140,60]]) {
    console.log(`p2=${p2} self=${s} opp=${o} =>`, await satisfying([1,0,p2,0,0,0,0,0], 5, s, o));
  }
}
for (const [s, o] of [[60,140],[140,60]]) {
  console.log(`p3=1 self=${s} opp=${o} =>`, await satisfying([1,0,0,1,0,0,0,0], 5, s, o));
}
