// Map the 9 public signals of VfyPolicyProof.
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const poseidon = await buildPoseidon();
const F = poseidon.F;
const P = (arr) => F.toString(poseidon(arr));
const params = [1,0,0,0,0,0,0,0];
const commitment = P([...params, 0]);
const input = { action: 2, amount: 1, selfBalance: 100, opponentBalance: 100,
  turnNumber: 1, matchId: 1, commitment, salt: 0, circuitVersion: 1, strategyParams: params };
const pub = ["1243904711429961858774220647610724273798918457991486031567244100767259239747",
  "11299471465817035813941534680224295417418949445559228777402254279479107204147",
  "1","1","100","100","2","1","1"];
console.log("commitment =", commitment, "-> public index", pub.indexOf(commitment));
const cands = {
  "poseidon(action,amount,self,opp,turn,match)": P([2,1,100,100,1,1]),
  "poseidon(match,turn,self,opp,action,amount)": P([1,1,100,100,2,1]),
  "poseidon(self,opp,turn,match,action,amount)": P([100,100,1,1,2,1]),
  "poseidon(action,amount,self,opp,turn,match,cv)": P([2,1,100,100,1,1,1]),
  "poseidon(match,turn,self,opp,action,amount,cv)": P([1,1,100,100,2,1,1]),
  "poseidon(commitment,match,turn)": P([BigInt(commitment),1,1]),
  "poseidon(params+salt,match,turn)": P([BigInt(commitment),1,1]),
};
for (const [k, v] of Object.entries(cands)) console.log(k, "-> public index", pub.indexOf(v));
async function wit(inp) {
  try { const w = await snarkjs.wtns.calculate(inp, wasm, "/tmp/probe.wtns"); return w.slice(1, 10).map((x) => x.toString()); }
  catch (e) { return "FAIL:" + (String(e?.message || e).match(/line: (\d+)/)?.[1] || "?"); }
}
const base = await wit(input);
console.log("base witness public:", JSON.stringify(base));
for (const [k, v, extra] of [["matchId", 7, {}], ["turnNumber", 2, {}], ["circuitVersion", 2, {}],
  ["selfBalance", 90, {}], ["opponentBalance", 80, {}],
  ["amount", 10, { strategyParams: [10,0,0,0,0,0,0,0], commitment: P([10,0,0,0,0,0,0,0,0]) }]]) {
  const alt = await wit({ ...input, [k]: v, ...extra });
  if (typeof alt === "string") { console.log(`vary ${k} =>`, alt); continue; }
  const diff = alt.map((x, i) => (x !== base[i] ? `${i}:${base[i]}->${x}` : null)).filter(Boolean);
  console.log(`vary ${k} => changed:`, JSON.stringify(diff));
}
