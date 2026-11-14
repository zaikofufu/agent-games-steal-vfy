// Round 3: hunt the remaining 8 input signals (17 total, 9 found).
// Oracle semantics (calibrated): a real scalar signal ACCEPTS one value;
// any unknown name behaves as size-0 ("Too many values").
import * as snarkjs from "snarkjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
async function probe(key, value = 0) {
  try {
    await snarkjs.wtns.calculate({ [key]: value }, wasm, "/tmp/probe.wtns");
    return "WITNESS_OK";
  } catch (e) {
    const msg = String(e?.message || e);
    if (/Only (\d+) out of (\d+)/.test(msg)) return "ACCEPTED";
    if (/Not enough values/.test(msg)) return "ARRAY_SIZE>1";
    if (/Too many values/.test(msg)) return "unknown";
    if (/not found/.test(msg)) return "NOT_FOUND";
    return "OTHER:" + msg.slice(0, 80);
  }
}
const candidates = [
  "strategy[0]","params[0]","policy[0]","inputs[0]","state[0]","balances[0]",
  "commitment[0]","rules[0]","weights[0]","thresholds[0]","features[0]","data[0]",
  "values[0]","actions[0]","turns[0]","salt[0]","hash[0]","publicInputs[0]",
  "a","b","c","d","e","f","g","h","i","j","k",
  "in0","in1","in2","in3","in4","in5","in6","in7","input0","input1",
  "fortifyUntil","extractWhenAhead","extractWhenBehind","holdWhenAhead",
  "minExtract","minLead","aggression","defense","risk","expiry","validAfter",
  "minBalance","maxAmount","cost","shield","turnsRemaining","remainingTurns",
  "score","myPoints","winThreshold","gameState","matchState",
  "opponentLastAction","lastOpponentAction","prevOpponentAction",
  "strategyId","policyId","strategyParams","fortifyTurn","extractTurn",
  "leadThreshold","behindThreshold","earlyFortify","lateExtract",
  "extractCapAmount","fortifyAmount","defenseAmount","protectedAmount",
  "exposedAmount","opponentProtected","myProtectedAmount","opponentExposedAmount",
  "turnLimit","maxTurns","roundNumber","matchNumber","swissRound","opponentId",
  "agentName","player","side","isFirst","firstMove","lastTurn","finalTurn",
  "zzzzqqqq999",
];
const found = [];
for (const k of candidates) {
  const r = await probe(k);
  if (r !== "unknown" && r !== "NOT_FOUND") { console.log(k, "=>", r); found.push(k); }
}
console.log("FOUND_EXTRA:", JSON.stringify(found));
