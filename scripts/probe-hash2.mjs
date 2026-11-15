/**
 * One-off probe (NOT shipped): try to identify the circuit's
 * publicSignals[0] hash function by testing candidate formulas against
 * the known value from scripts/probe-hash.mjs.
 *
 * Known inputs (probe-hash run):
 *   commitment = 16558278792999601739528827900028539763998923485550243417577873933892175672347
 *   matchId UUID = 9f4e1b2a-1111-4000-8000-000000000001
 *   turn = 3, selfBalance = 95, opponentBalance = 105
 *   action = EXTRACT (2), amount = 10, circuitVersion = 1
 *   publicSignals[0] = 18054142780609337750274101543188595559682643761682875673550740777443638678843
 *
 * Run: node scripts/probe-hash2.mjs
 */
import { buildPoseidon } from "circomlibjs";
import { keccak256, concat, numberToHex } from "viem";

const TARGET = "18054142780609337750274101543188595559682643761682875673550740777443638678843";
const commitment = BigInt("16558278792999601739528827900028539763998923485550243417577873933892175672347");
const matchId = BigInt("0x9f4e1b2a111140008000000000000001");
const turn = 3n;
const selfBalance = 95n;
const opponentBalance = 105n;
const action = 2n;
const amount = 10n;
const circuitVersion = 1n;

const fields = { commitment, matchId, turn, selfBalance, opponentBalance, action, amount, circuitVersion };

function keccakOf(order) {
  return keccak256(concat(order.map((k) => numberToHex(fields[k], { size: 32 }))));
}

const keccakOrders = [
  ["commitment", "matchId", "turn", "selfBalance", "opponentBalance", "action", "amount", "circuitVersion"],
  ["matchId", "turn", "selfBalance", "opponentBalance", "action", "amount", "circuitVersion", "commitment"],
  ["commitment", "matchId", "turn", "selfBalance", "opponentBalance", "action", "amount"],
  ["matchId", "turn", "selfBalance", "opponentBalance", "commitment", "action", "amount", "circuitVersion"],
  ["turn", "matchId", "selfBalance", "opponentBalance", "action", "amount", "commitment", "circuitVersion"],
  ["commitment", "matchId", "turn", "selfBalance", "opponentBalance", "action", "amount", "circuitVersion", "matchId"],
];
for (const order of keccakOrders) {
  const h = keccakOf(order);
  const dec = BigInt(h).toString();
  console.log(`keccak [${order.join(",")}]: ${dec === TARGET ? "MATCH!!!" : "no"}`);
}

const poseidon = await buildPoseidon();
const poseidonOrders = [
  ["commitment", "matchId", "turn", "selfBalance", "opponentBalance", "action", "amount", "circuitVersion"],
  ["matchId", "turn", "selfBalance", "opponentBalance", "action", "amount", "circuitVersion", "commitment"],
  ["commitment", "matchId", "turn", "selfBalance", "opponentBalance", "action", "amount"],
  ["matchId", "turn", "selfBalance", "opponentBalance", "action", "amount"],
  ["commitment", "matchId", "turn", "selfBalance", "opponentBalance", "action", "amount", "circuitVersion", "matchId"],
];
for (const order of poseidonOrders) {
  const out = poseidon.F.toString(poseidon(order.map((k) => fields[k])));
  console.log(`poseidon [${order.join(",")}]: ${out === TARGET ? "MATCH!!!" : "no"}`);
}
console.log("target:", TARGET);
