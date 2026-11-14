// Boundary + priority checks for the inferred policy function.
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
console.log("deficit==p1 (80==80):", await satisfying([1,80,0,0,0,0,0,0], 5, 20, 100));
console.log("deficit>p1 (80>79):", await satisfying([1,79,0,0,0,0,0,0], 5, 20, 100));
console.log("lead==p2 (80==80):", await satisfying([1,0,80,0,0,0,0,0], 5, 100, 20));
console.log("lead>p2 (80>79):", await satisfying([1,0,79,0,0,0,0,0], 5, 100, 20));
console.log("p3=1 + fortify-condition (deficit 80<=100):", await satisfying([1,100,0,1,0,0,0,0], 5, 60, 140));
console.log("p3=1 + hold-condition (lead 80<=100):", await satisfying([1,0,100,1,0,0,0,0], 5, 140, 60));
console.log("p3=0 tied, p1=100, p2=100:", await satisfying([1,100,100,0,0,0,0,0], 5, 100, 100));
console.log("p1=0 deficit 80:", await satisfying([1,0,0,0,0,0,0,0], 5, 60, 140));
