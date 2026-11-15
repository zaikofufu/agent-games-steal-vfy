/**
 * Live HTTP tests for the Steal the VFY server.
 *
 * A MOCKED prover is injected (labelled) so these tests run fast and
 * do not need the circuit artifacts; the real prover is exercised in
 * test/proof.real.test.ts. HMAC behaviour, envelope normalisation,
 * the /build response shape (proof + public_signals nested INSIDE
 * policyProof, action as an object), idempotency replay,
 * commitment-mismatch fallback and the no-artifacts HOLD fallback
 * are all covered here.
 *
 * The strategy used here is an explicit TEST FIXTURE (params
 * [10,20,10,0,0,0,0,0], salt "12345") — it is not the agent's
 * strategy (STRATEGY_PARAMS in src/strategy.ts is a TODO).
 */
import { createHmac } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { computeCommitment, computePublicInputsHash } from "../src/proof.js";
import { AGENT_VERSION, createApp } from "../src/server.js";
import type { Strategy } from "../src/strategy.js";

const SECRET = "test-secret-for-steal-vfy";
const strategy: Strategy = {
  id: "test-strategy",
  circuitVersion: "v1",
  params: [10, 20, 10, 0, 0, 0, 0, 0],
  salt: "12345",
};
let commitment = "";
let baseUrl = "";
let server: ReturnType<typeof createApp>;

function sign(body: string, secret = SECRET): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

async function postTurn(body: string, secret = SECRET, headers: Record<string, string> = {}) {
  const res = await fetch(`${baseUrl}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sign(body, secret), ...headers },
    body,
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown>, sig: res.headers.get("x-agent-games-signature") };
}

/** Exact /build turn envelope shape (UUID matchId, nested state, strategyCommitment.hash). */
const turnBody = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify({
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    mode: "competition",
    matchId: "9f4e1b2a-1111-4000-8000-000000000001",
    turn: 1,
    issuedAt: "2026-11-15T10:00:00.000Z",
    deadlineAt: "2026-11-15T10:05:00.000Z",
    state: { selfBalance: "100", opponentBalance: "100", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: `0x${BigInt(commitment).toString(16)}` },
    resolverVersion: "v1",
    nonce: "3c2f1a0000000000000000000000000000000000000000000000000000000000",
    ...overrides,
  });

beforeAll(async () => {
  commitment = await computeCommitment(strategy.params, strategy.salt);
  server = createApp({
    secret: SECRET,
    agentName: "steal-vfy",
    strategy,
    prover: async () => ({
      proof: { pi_a: ["1", "2"], pi_b: [["3"]], pi_c: ["4"], protocol: "groth16", curve: "bn128" },
      publicSignals: ["hash", commitment, "1", "1", "100", "100", "2", "10", "1"],
    }),
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("health + HMAC", () => {
  it("GET /agent returns ok + version", async () => {
    const res = await fetch(`${baseUrl}/agent`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok", agent: "steal-vfy", version: AGENT_VERSION });
  });

  it("missing signature -> 401", async () => {
    const res = await fetch(`${baseUrl}/agent`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: turnBody(),
    });
    expect(res.status).toBe(401);
  });

  it("invalid signature -> 403", async () => {
    const { status } = await postTurn(turnBody(), "wrong-secret");
    expect(status).toBe(403);
  });

  it("valid signature -> response is signed", async () => {
    const { status, sig } = await postTurn(turnBody({ turn: 2 }));
    expect(status).toBe(200);
    expect(sig).toBeTruthy();
  });
});

describe("turn handling (/build response shape)", () => {
  it("valid turn -> 200, action object + proof nested INSIDE policyProof", async () => {
    const { status, json } = await postTurn(turnBody({ turn: 3 }));
    expect(status).toBe(200);
    expect(json.matchId).toBe("9f4e1b2a-1111-4000-8000-000000000001");
    expect(json.turn).toBe(3);
    // Action is an OBJECT with amount only for EXTRACT.
    expect(json.action).toEqual({ type: "EXTRACT", amount: 10 });
    // Proof + public_signals live INSIDE policyProof — never top-level.
    expect(json.proof).toBeUndefined();
    expect(json.public_signals).toBeUndefined();
    expect(json.circuitVersion).toBeUndefined();
    expect(json.amount).toBeUndefined();
    const policyProof = json.policyProof as Record<string, unknown>;
    expect(policyProof.circuitVersion).toBe("v1");
    expect(policyProof.proof).toBeTruthy();
    expect(policyProof.public_signals).toEqual(["hash", commitment, "1", "1", "100", "100", "2", "10", "1"]);
    // Audit hash is the /build keccak256 value for this turn.
    const expectedHash = computePublicInputsHash(
      { matchId: "9f4e1b2a-1111-4000-8000-000000000001", turn: 3, selfBalance: 100, opponentBalance: 100 },
      { action: "EXTRACT", amount: 10 },
      commitment,
    );
    expect(policyProof.publicInputsHash).toBe(expectedHash);
    expect(json.agentTimestamp).toEqual(expect.any(String));
    expect(json.idempotencyKey).toEqual(expect.any(String));
  });

  it("FORTIFY turn -> action object without amount", async () => {
    const body = turnBody({
      turn: 4,
      state: { selfBalance: "90", opponentBalance: "100", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    });
    const { status, json } = await postTurn(body);
    expect(status).toBe(200);
    expect(json.action).toEqual({ type: "FORTIFY" });
    expect((json.action as Record<string, unknown>).amount).toBeUndefined();
  });

  it("accepts a legacy flat envelope too", async () => {
    const body = JSON.stringify({
      matchId: 9,
      turn: 1,
      myBalance: 100,
      opponentBalance: 100,
    });
    const { status, json } = await postTurn(body);
    expect(status).toBe(200);
    expect(json.matchId).toBe(9);
  });

  it("rejects an envelope for another event", async () => {
    const { status } = await postTurn(turnBody({ eventId: "proof-gatekeeper" }));
    expect(status).toBe(400);
  });

  it("rejects a turn missing balances", async () => {
    const { status } = await postTurn(JSON.stringify({ matchId: 1, turn: 1 }));
    expect(status).toBe(400);
  });

  it("echoes a supplied idempotencyKey, and mints a stable one when absent", async () => {
    const keyed = await postTurn(turnBody({ turn: 5, idempotencyKey: "key-5" }));
    expect(keyed.json.idempotencyKey).toBe("key-5");
    const minted = await postTurn(turnBody({ turn: 6 }));
    expect(minted.json.idempotencyKey).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it("replays the same match+turn from cache (idempotency)", async () => {
    const body = turnBody({ turn: 7 });
    const first = await postTurn(body);
    const second = await postTurn(body);
    expect(second.status).toBe(200);
    expect(second.json).toEqual(first.json);
  });

  it("commitment mismatch in the envelope -> HOLD with proof null inside policyProof", async () => {
    const { status, json } = await postTurn(
      turnBody({
        turn: 8,
        strategyCommitment: { hash: "0x0000000000000000000000000000000000000000000000000000000000000001" },
      }),
    );
    expect(status).toBe(200);
    expect(json.action).toEqual({ type: "HOLD" });
    expect((json.action as Record<string, unknown>).amount).toBeUndefined();
    expect(json.proof).toBeUndefined();
    expect(json.public_signals).toBeUndefined();
    const policyProof = json.policyProof as Record<string, unknown>;
    expect(policyProof.proof).toBeNull();
    expect(policyProof.public_signals).toBeUndefined();
  });

  it("matching commitment in the envelope is accepted", async () => {
    const { status, json } = await postTurn(turnBody({ turn: 9 }));
    expect(status).toBe(200);
    expect(json.action).toEqual({ type: "EXTRACT", amount: 10 });
  });
});

describe("no-artifacts fallback", () => {
  it("answers HOLD with proof null instead of inventing a proof", async () => {
    const fallbackServer = createApp({ secret: SECRET, strategy });
    await new Promise<void>((resolve) => fallbackServer.listen(0, resolve));
    const addr = fallbackServer.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    try {
      const body = turnBody({ turn: 1, matchId: 99 });
      const res = await fetch(`http://127.0.0.1:${port}/agent`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-agent-games-signature": sign(body) },
        body,
      });
      expect(res.status).toBe(200);
      const json = (await res.json()) as Record<string, unknown>;
      expect(json.action).toEqual({ type: "HOLD" });
      const policyProof = json.policyProof as Record<string, unknown>;
      expect(policyProof.proof).toBeNull();
      expect(json.proof).toBeUndefined();
      expect(json.public_signals).toBeUndefined();
    } finally {
      await new Promise<void>((resolve) => fallbackServer.close(() => resolve()));
    }
  });
});
