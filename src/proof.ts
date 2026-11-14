/**
 * Policy-proof generation for the Steal the VFY track.
 *
 * VERIFIED facts (probed live from the published circuit, 14 Nov 2026):
 *  - Circuit info: https://agentgames.zkverify.io/api/circuit-info
 *    network mainnet, vfyPolicy vkHash
 *    0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047,
 *    wasm https://agentgames.zkverify.io/circuits/vfy-policy.wasm,
 *    zkey https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey
 *  - Exported VK: Groth16/BN128, nPublic = 9.
 *  - Circuit inputs (17 total), recovered by oracle-probing the wasm
 *    (scripts/probe-circuit.mjs, probe-size.mjs):
 *      9 scalars: action, amount, selfBalance, opponentBalance,
 *        turnNumber, matchId, commitment, salt, circuitVersion
 *      1 array:   strategyParams[8]
 *  - commitment == Poseidon(strategyParams[0..7], salt) — verified:
 *    salt-first order FAILS the circuit assert (line 72); salt-last
 *    passes. `salt` is a private input.
 *  - The circuit enforces the policy (template VfyPolicyProof):
 *    with strategyParams = [amount, 0, 0, 0, 0, 0, 0, 0], action
 *    EXTRACT (2) with amount == params[0] satisfies in every probed
 *    state; params[4..7] must be 0; params[3] > 1 makes no action
 *    satisfiable. See src/strategy.ts and README for the full map.
 *  - Public signals (9), order verified live by fullProve + vary-one-
 *    input-at-a-time (scripts/probe-pub0.mjs, probe-pub1.mjs):
 *      [0] public-inputs hash (changes with matchId/turnNumber; the
 *          hash function itself is NOT identified — see README. The
 *          value is forwarded verbatim from fullProve, never computed
 *          locally.)
 *      [1] commitment
 *      [2] matchId
 *      [3] turnNumber
 *      [4] selfBalance
 *      [5] opponentBalance
 *      [6] action
 *      [7] amount
 *      [8] circuitVersion
 *  - Real fullProve + groth16.verify against the published VK returns
 *    true (see test/proof.real.test.ts).
 */
import { createHash } from "node:crypto";
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import type { GameState, Move, Strategy } from "./strategy.js";
import { ACTION_CODE } from "./strategy.js";

export const VFY_POLICY_CIRCUIT = {
  network: "mainnet",
  vkHash: "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
  wasmUrl: "https://agentgames.zkverify.io/circuits/vfy-policy.wasm",
  zkeyUrl: "https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey",
  /** Public signals in the policy proof (from the exported VK). */
  nPublic: 9,
  /** Index of the commitment inside publicSignals. */
  commitmentIndex: 1,
  /** Index of the public-inputs hash inside publicSignals. */
  publicInputsHashIndex: 0,
} as const;

/** Action codes the circuit accepts (see src/strategy.ts). */
export const CIRCUIT_ACTION = ACTION_CODE;

const BN128_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

export function fieldElement(value: string): string {
  return (BigInt(value) % BN128_PRIME).toString();
}

export function hashToField(value: string): string {
  const digest = createHash("sha256").update(value, "utf8").digest("hex");
  return (BigInt(`0x${digest}`) % BN128_PRIME).toString();
}

/**
 * Parse a field element that may be a decimal string, a 0x-hex string,
 * or a JS number. Throws on anything else.
 */
export function parseFieldElement(value: unknown): string {
  if (typeof value === "number") return BigInt(value).toString();
  if (typeof value === "string") {
    const s = value.trim().toLowerCase();
    if (/^0x[0-9a-f]+$/.test(s)) return BigInt(s).toString();
    if (/^-?\d+$/.test(s)) return BigInt(s).toString();
  }
  throw new Error(`not a field element: ${String(value)}`);
}

/** The circuit's input signals. */
export interface PolicyCircuitInput {
  action: string;
  amount: string;
  selfBalance: string;
  opponentBalance: string;
  turnNumber: string;
  matchId: string;
  commitment: string;
  salt: string;
  circuitVersion: string;
  strategyParams: string[];
}

let poseidonPromise: ReturnType<typeof buildPoseidon> | null = null;

async function getPoseidon() {
  poseidonPromise ??= buildPoseidon();
  return poseidonPromise;
}

/**
 * commitment = Poseidon(strategyParams[0..7], salt).
 * Verified against the circuit: salt-last order passes the line-72
 * assert; salt-first fails it. Returns a decimal string.
 */
export async function computeCommitment(params: number[], salt: string): Promise<string> {
  if (params.length !== 8) throw new Error("strategyParams must have exactly 8 elements");
  const poseidon = await getPoseidon();
  const input = [...params.map((p) => BigInt(p)), BigInt(salt)];
  return poseidon.F.toString(poseidon(input));
}

/**
 * Map a game state + move + strategy to the circuit's input signals.
 * matchId may be a number, a decimal string, or an opaque string id
 * (e.g. "st_...") — opaque ids are hashed to a field element, which
 * the platform must do identically for its own publicInputsHash; if
 * the platform sends numeric match ids, use them as-is. The
 * commitment MUST be the Poseidon value for these params+salt, or
 * fullProve fails the line-72 assert.
 */
export function toCircuitInput(
  state: GameState,
  move: Move,
  strategy: Strategy,
  commitment: string,
): PolicyCircuitInput {
  let matchId: string;
  if (typeof state.matchId === "number") matchId = String(state.matchId);
  else if (/^-?\d+$/.test(state.matchId.trim())) matchId = BigInt(state.matchId.trim()).toString();
  else matchId = hashToField(state.matchId);
  return {
    action: String(ACTION_CODE[move.action]),
    amount: String(move.amount ?? 0),
    selfBalance: String(state.selfBalance),
    opponentBalance: String(state.opponentBalance),
    turnNumber: String(state.turn),
    matchId,
    commitment,
    salt: strategy.salt,
    circuitVersion: String(strategy.circuitVersion),
    strategyParams: strategy.params.map((p) => String(p)),
  };
}

export interface PolicyProof {
  proof: unknown;
  publicSignals: string[];
}

export type Prover = (input: PolicyCircuitInput) => Promise<PolicyProof>;

export class CircuitArtifactsMissingError extends Error {
  constructor() {
    super(
      "vfy-policy circuit artifacts not configured: set VFY_POLICY_WASM and " +
        "VFY_POLICY_ZKEY (or inject a prover). Policy proof cannot be generated.",
    );
    this.name = "CircuitArtifactsMissingError";
  }
}

/** Build a real snarkjs prover from local wasm/zkey files. */
export function createSnarkjsProver(wasmPath: string, zkeyPath: string): Prover {
  return async (input: PolicyCircuitInput): Promise<PolicyProof> => {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input as unknown as Record<string, unknown>,
      wasmPath,
      zkeyPath,
    );
    return { proof, publicSignals: publicSignals.map(String) };
  };
}

/**
 * Generate the policy proof for a move.
 *  - If a `prover` is injected (tests), use it.
 *  - Else if wasm/zkey paths are configured, build a snarkjs prover.
 *  - Else throw CircuitArtifactsMissingError — the caller (server)
 *    then answers HOLD with proof: null instead of inventing a proof.
 *
 * NOTE: a move the circuit does not accept (wrong action for the
 * committed params, amount != params[0], commitment mismatch) makes
 * fullProve throw a circuit assert. The caller must treat that as
 * "cannot prove this move" and fall back to HOLD-no-proof — never
 * return a bogus proof.
 */
export async function generatePolicyProof(
  state: GameState,
  move: Move,
  strategy: Strategy,
  commitment: string,
  opts: { prover?: Prover; wasmPath?: string; zkeyPath?: string } = {},
): Promise<PolicyProof> {
  const input = toCircuitInput(state, move, strategy, commitment);
  if (opts.prover) return opts.prover(input);
  if (opts.wasmPath && opts.zkeyPath) {
    return createSnarkjsProver(opts.wasmPath, opts.zkeyPath)(input);
  }
  throw new CircuitArtifactsMissingError();
}
