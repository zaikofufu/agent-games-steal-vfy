// Confirm strategyParams length and try to build a witness with all inputs.
import * as snarkjs from "snarkjs";
const wasm = new URL("../circuits/vfy-policy.wasm", import.meta.url).pathname;
const scalars = { action: 0, amount: 0, selfBalance: 100, opponentBalance: 100,
  turnNumber: 1, matchId: 1, commitment: 0, salt: 0, circuitVersion: 1 };
for (const n of [2, 4, 6, 8, 10, 12, 16]) {
  try {
    await snarkjs.wtns.calculate({ ...scalars, strategyParams: Array(n).fill(0) }, wasm, "/tmp/probe.wtns");
    console.log("strategyParams length", n, "=> WITNESS BUILT (all 17 inputs set)");
  } catch (e) {
    const msg = String(e?.message || e);
    const m = msg.match(/Only (\d+) out of (\d+)/);
    console.log("strategyParams length", n, "=>", m ? `count ${m[1]}/17` : msg.slice(0, 100));
  }
}
