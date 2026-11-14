/**
 * HTTP server for the Steal the VFY agent.
 *
 * Contract (verified against https://agentgames.zkverify.io/build,
 * /guide, /events/steal-the-vfy and /api/circuit-info, 14 Nov 2026):
 *  - POST /agent — JSON turn envelope. Header
 *    x-agent-games-signature: <hmac-sha256-hex> over the RAW request
 *    body, using the per-agent secret issued at registration.
 *    Verify the signature BEFORE parsing the body. Missing header
 *    -> 401; failed verification -> 403. The body is never logged.
 *  - GET /agent — health check: {"status":"ok","agent":...,"version":"1.0.0"}
 *  - Every response is signed with x-agent-games-signature over the
 *    raw response body (same secret).
 *  - Turn deadline is 5 minutes; the platform waits ~30s per push.
 *    Internal budget is 20s; the server answers 503 if it cannot
 *    respond in time (a missed turn is substituted with HOLD -1, so a
 *    late 200 is worse than a fast 503/HOLD).
 *  - Response: echo matchId + turn, declare the action, attach the
 *    policy proof (circuitVersion + Groth16 proof + public_signals).
 *    `amount` is present ONLY for EXTRACT — the schema rejects the
 *    field for HOLD/FORTIFY even when it is 0. publicInputsHash is set
 *    to public_signals[0], the circuit's own public-inputs hash.
 *  - FAIL CLOSED: if no policy proof can be produced (no circuit
 *    artifacts, fullProve assert failure, commitment mismatch with the
 *    envelope), answer HOLD with proof: null and no public_signals.
 *    Per /build, a missing/mismatched required field is treated as
 *    HOLD with no proof — that costs a turn, not -2 for an invalid
 *    proof. Never invent a proof, and never return a bogus one.
 *  - Idempotency: the platform accepts only the first submission per
 *    idempotencyKey. Replays of the same matchId+turn return the
 *    cached response instead of generating a second proof.
 *
 * No framework is used (Node's built-in http only). The HMAC secret
 * comes from env (AGENT_SECRET) and is never logged, returned, or
 * written to disk.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  CircuitArtifactsMissingError,
  VFY_POLICY_CIRCUIT,
  computeCommitment,
  generatePolicyProof,
  parseFieldElement,
  type Prover,
} from "./proof.js";
import { decideTurn, liveStrategy, type GameState, type Move, type Strategy } from "./strategy.js";

export const AGENT_VERSION = "1.0.0";
export const MAX_BODY_BYTES = 1_000_000;
/** Internal budget, inside the platform's ~30s per-push wait. */
export const RESPONSE_BUDGET_MS = 20_000;

export interface AgentOptions {
  secret: string;
  agentName?: string;
  /** Defaults to the live always-extract strategy. */
  strategy?: Strategy;
  /** Defaults to a snarkjs prover when wasm/zkey paths are set. */
  prover?: Prover;
  wasmPath?: string;
  zkeyPath?: string;
  responseBudgetMs?: number;
}

export interface TurnEnvelope {
  matchId: string | number;
  turn: number;
  selfBalance: number;
  opponentBalance: number;
  commitmentHash?: string;
  deadline?: number | string;
  nonce?: string | number;
  idempotencyKey?: string;
}

function hmacHex(secret: string, body: Buffer): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

function signaturesMatch(secret: string, body: Buffer, header: string | undefined): boolean {
  if (!header) return false;
  const expected = hmacHex(secret, body);
  const given = header.trim().toLowerCase().replace(/^0x/, "");
  if (given.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(given, "utf8"), Buffer.from(expected, "utf8"));
  } catch {
    return false;
  }
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY_BYTES) throw new Error("body too large");
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("response budget exceeded")), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && /^-?\d+(\.\d+)?$/.test(value.trim())) return Number(value);
  return undefined;
}

function pick<T>(...values: (T | undefined)[]): T | undefined {
  return values.find((v) => v !== undefined);
}

/**
 * Normalise a turn envelope. The platform's exact field names are not
 * fully published (the /build page renders them in interactive
 * sections the text crawl collapses), so both the flat shape and a
 * nested `state`/`gameState` shape are accepted. Unknown extra fields
 * are ignored. Throws on a missing matchId/turn/balances.
 */
export function normaliseTurn(raw: Record<string, unknown>): TurnEnvelope {
  const state = (raw.state ?? raw.gameState ?? raw.game_state ?? {}) as Record<string, unknown>;
  const matchId = pick(raw.matchId, raw.match_id, raw.id, state.matchId, state.match_id);
  const turn = asNumber(pick(raw.turn, raw.turnNumber, raw.turn_number, state.turn, state.turnNumber));
  const selfBalance = asNumber(
    pick(raw.myBalance, raw.selfBalance, raw.my_balance, state.myBalance, state.selfBalance, state.my_balance),
  );
  const opponentBalance = asNumber(
    pick(
      raw.opponentBalance,
      raw.opponent_balance,
      state.opponentBalance,
      state.opponent_balance,
    ),
  );
  if (matchId === undefined || (typeof matchId !== "string" && typeof matchId !== "number")) {
    throw new Error("missing matchId");
  }
  if (turn === undefined || selfBalance === undefined || opponentBalance === undefined) {
    throw new Error("missing turn or balances");
  }
  const commitmentHash = pick(raw.commitmentHash, raw.commitment_hash, raw.commitment, state.commitmentHash);
  const idempotencyKey = pick(raw.idempotencyKey, raw.idempotency_key, state.idempotencyKey);
  return {
    matchId,
    turn,
    selfBalance,
    opponentBalance,
    commitmentHash: typeof commitmentHash === "string" ? commitmentHash : undefined,
    deadline: raw.deadline as number | string | undefined,
    nonce: raw.nonce as string | number | undefined,
    idempotencyKey: typeof idempotencyKey === "string" ? idempotencyKey : undefined,
  };
}

export function createApp(opts: AgentOptions): Server {
  const secret = opts.secret;
  if (!secret) throw new Error("AGENT_SECRET is required");
  const agentName = opts.agentName ?? "steal-vfy";
  const strategy: Strategy = opts.strategy ?? liveStrategy(process.env.STRATEGY_SALT || undefined);
  const budget = opts.responseBudgetMs ?? RESPONSE_BUDGET_MS;
  // matchId:turn -> response payload (idempotency: first submission wins).
  const seen = new Map<string, Record<string, unknown>>();
  // Commitment is computed lazily once (Poseidon is async to build).
  let commitmentPromise: Promise<string> | null = null;
  const getCommitment = (): Promise<string> => {
    commitmentPromise ??= computeCommitment(strategy.params, strategy.salt);
    return commitmentPromise;
  };

  function send(res: ServerResponse, status: number, payload: unknown): void {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    res.writeHead(status, {
      "content-type": "application/json",
      "x-agent-games-signature": hmacHex(secret, body),
    });
    res.end(body);
  }

  /** HOLD with no proof — the documented fail-closed answer. */
  function holdFallback(matchId: string | number, turn: number, idempotencyKey?: string) {
    return {
      matchId,
      turn,
      action: "HOLD",
      circuitVersion: strategy.circuitVersion,
      proof: null,
      ...(idempotencyKey ? { idempotencyKey } : {}),
    };
  }

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (url.pathname === "/agent" && req.method === "GET") {
        send(res, 200, { status: "ok", agent: agentName, version: AGENT_VERSION });
        return;
      }
      if (url.pathname !== "/agent" || req.method !== "POST") {
        send(res, 404, { error: "not_found" });
        return;
      }

      // Read the raw body first — the HMAC is over the raw bytes, and
      // it must be verified BEFORE the body is parsed or logged.
      const rawBody = await readBody(req);
      const sigHeader = req.headers["x-agent-games-signature"];
      const signature = Array.isArray(sigHeader) ? sigHeader[0] : sigHeader;
      if (!signature) {
        send(res, 401, { error: "missing_signature" });
        return;
      }
      if (!signaturesMatch(secret, rawBody, signature)) {
        send(res, 403, { error: "invalid_signature" });
        return;
      }

      let raw: Record<string, unknown>;
      try {
        raw = JSON.parse(rawBody.toString("utf8")) as Record<string, unknown>;
      } catch {
        send(res, 400, { error: "invalid_json" });
        return;
      }
      // Type is advisory: accept the steal envelope, or no type at all.
      // Reject only an envelope that is clearly for another track.
      if (typeof raw.type === "string" && !/steal/i.test(raw.type)) {
        send(res, 400, { error: "unsupported_type" });
        return;
      }

      let envelope: TurnEnvelope;
      try {
        envelope = normaliseTurn(raw);
      } catch {
        send(res, 400, { error: "invalid_turn" });
        return;
      }

      const cacheKey = `${String(envelope.matchId)}:${envelope.turn}`;
      const cached = seen.get(cacheKey);
      if (cached) {
        send(res, 200, cached);
        return;
      }

      const state: GameState = {
        matchId: envelope.matchId,
        turn: envelope.turn,
        selfBalance: envelope.selfBalance,
        opponentBalance: envelope.opponentBalance,
      };
      const move: Move = decideTurn(state);

      const result = await withTimeout(
        (async () => {
          const commitment = await getCommitment();
          // If the envelope carries the frozen commitment hash, it must
          // match ours — otherwise our proof's publicSignals[1] would
          // not equal the registered commitment and the platform would
          // reject it. Fail closed to HOLD-no-proof, never prove
          // against a commitment we do not own.
          if (envelope.commitmentHash) {
            try {
              const theirs = parseFieldElement(envelope.commitmentHash);
              if (theirs !== commitment) {
                console.error(
                  `commitment mismatch for ${cacheKey}: envelope commitment != computed commitment; answering HOLD`,
                );
                return holdFallback(envelope.matchId, envelope.turn, envelope.idempotencyKey);
              }
            } catch {
              // Unparseable commitment hash: ignore it (the proof
              // carries our own commitment) rather than failing the turn.
            }
          }
          try {
            const generated = await generatePolicyProof(state, move, strategy, commitment, {
              prover: opts.prover,
              wasmPath: opts.wasmPath,
              zkeyPath: opts.zkeyPath,
            });
            const publicSignals = generated.publicSignals;
            const response: Record<string, unknown> = {
              matchId: envelope.matchId,
              turn: envelope.turn,
              action: move.action,
              ...(move.action === "EXTRACT" ? { amount: move.amount } : {}),
              circuitVersion: strategy.circuitVersion,
              proof: generated.proof,
              public_signals: publicSignals,
              // publicSignals[0] is the circuit's own public-inputs
              // hash (verified: it changes with matchId/turnNumber).
              publicInputsHash: publicSignals[VFY_POLICY_CIRCUIT.publicInputsHashIndex],
              ...(envelope.idempotencyKey ? { idempotencyKey: envelope.idempotencyKey } : {}),
            };
            seen.set(cacheKey, response);
            return response;
          } catch (err) {
            if (err instanceof CircuitArtifactsMissingError) {
              // No circuit artifacts: HOLD with no proof (documented).
              const fallback = holdFallback(envelope.matchId, envelope.turn, envelope.idempotencyKey);
              seen.set(cacheKey, fallback);
              return fallback;
            }
            // fullProve assert failure (move not provable for the
            // committed params, or any other proving error): HOLD with
            // no proof. An invalid proof costs -2; a HOLD costs a turn.
            console.error(`proof generation failed for ${cacheKey}:`, err instanceof Error ? err.message : err);
            const fallback = holdFallback(envelope.matchId, envelope.turn, envelope.idempotencyKey);
            seen.set(cacheKey, fallback);
            return fallback;
          }
        })(),
        budget,
      );
      send(res, 200, result);
    } catch (err) {
      if (err instanceof Error && err.message === "response budget exceeded") {
        try {
          send(res, 503, { error: "response_timeout" });
        } catch {
          /* socket already gone */
        }
        return;
      }
      // Never leak internal details (or the body) in an error response.
      try {
        send(res, 500, { error: "internal_error" });
      } catch {
        /* socket already gone */
      }
    }
  });
}
