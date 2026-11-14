// Identify publicSignals[0] + map public-signal order via fullProve variations.
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import { readFileSync } from "node:fs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const zkey = new URL("../circuits/vfy-policy_final.zkey", import.meta.url).pathname;
const poseidon = await buildPoseidon();
const F = poseidon.F;
const P = (arr) => F.toString(poseidon(arr.map((x) => BigInt(x))));
const params = [1,0,0,0,0,0,0,0];
const commitment = P([...params, 0]);
const base = { action: 2, amount: 1, selfBalance: 100, opponentBalance: 100,
  turnNumber: 1, matchId: 1, commitment, salt: 0, circuitVersion: 1, strategyParams: params };
const pub0 = "1243904711429961858774220647610724273798918457991486031567244100767259239747";
const C = BigInt(commitment);
const tuples = {
  "all9scalars": [2,1,100,100,1,1,C,0,1],
  "scalarsNoSalt": [2,1,100,100,1,1,C,1],
  "commitment+salt": [C,0],
  "salt+commitment": [0,C],
  "commitment+action+amount": [C,2,1],
  "match+turn+self+opp+action+amount+commitment": [1,1,100,100,2,1,C],
  "match+turn+self+opp+action+amount+cv": [1,1,100,100,2,1,1],
  "self+opp+turn+match": [100,100,1,1],
  "match+turn+self+opp": [1,1,100,100],
  "action+amount+self+opp": [2,1,100,100],
  "commitment+match+turn+self+opp": [C,1,1,100,100],
  "paramsPoseidon=commitment": [...params, 0],
};
for (const [k, v] of Object.entries(tuples)) {
  const h = P(v);
  if (h === pub0) console.log("MATCH pub0:", k);
}
console.log("pub0 brute-force done (no MATCH line = unidentified)");
const { publicSignals } = await snarkjs.groth16.fullProve(base, wasm, zkey);
console.log("base pub:", JSON.stringify(publicSignals));
for (const [k, v] of [["matchId", 7], ["turnNumber", 2]]) {
  const r = await snarkjs.groth16.fullProve({ ...base, [k]: v }, wasm, zkey);
  const diff = r.publicSignals.map((x, i) => (x !== publicSignals[i] ? `${i}:${publicSignals[i]}->${x}` : null)).filter(Boolean);
  console.log(`vary ${k} =>`, JSON.stringify(diff));
}
