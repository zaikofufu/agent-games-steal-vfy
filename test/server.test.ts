/**
 * Live HTTP tests for the Steal the VFY server.
 *
 * A MOCKED prover is injected (labelled) so these tests run fast and
 * do not need the circuit artifacts; the real prover is exercised in
 * test/proof.real.test.ts. HMAC behaviour, envelope normalisation,
 * response shape, idempotency replay, commitment-mismatch fallback
 * and the no-artifacts HOLD fallback are all covered here.
 */
import { createHmac } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { computeCommitment } from "../src/proof.js";
import { AGENT_VERSION, createApp } from "../src/server.js";
import { liveStrategy } from "../src/strategy.js";

const SECRET = "test-secret-for-steal-vfy";
const strategy = liveStrategy();
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

const turnBody = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify({
    type: "agent-games.steal-the-vfy.v1",
    matchId: 1,
    turn: 1,
    myBalance: 100,
    opponentBalance: 100,
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

describe("turn handling", () => {
  it("valid turn -> 200 EXTRACT with amount, proof and public_signals", async () => {
    const { status, json } = await postTurn(turnBody({ turn: 3 }));
    expect(status).toBe(200);
    expect(json.matchId).toBe(1);
    expect(json.turn).toBe(3);
    expect(json.action).toBe("EXTRACT");
    expect(json.amount).toBe(10);
    expect(json.circuitVersion).toBe(1);
    expect(json.proof).toBeTruthy();
    expect(json.public_signals).toEqual(["hash", commitment, "1", "1", "100", "100", "2", "10", "1"]);
    expect(json.publicInputsHash).toBe("hash");
  });

  it("accepts a nested state envelope too", async () => {
    const body = JSON.stringify({
      matchId: 9,
      turn: 1,
      state: { myBalance: 100, opponentBalance: 100 },
    });
    const { status, json } = await postTurn(body);
    expect(status).toBe(200);
    expect(json.matchId).toBe(9);
  });

  it("rejects an envelope for another track", async () => {
    const { status } = await postTurn(
      JSON.stringify({ type: "agent-games.proof-gatekeeper.v1", matchId: 1, turn: 1, myBalance: 100, opponentBalance: 100 }),
    );
    expect(status).toBe(400);
  });

  it("rejects a turn missing balances", async () => {
    const { status } = await postTurn(JSON.stringify({ matchId: 1, turn: 1 }));
    expect(status).toBe(400);
  });

  it("replays the same match+turn from cache (idempotency)", async () => {
    const body = turnBody({ turn: 4 });
    const first = await postTurn(body);
    const second = await postTurn(body);
    expect(second.status).toBe(200);
    expect(second.json).toEqual(first.json);
  });

  it("commitment mismatch in the envelope -> HOLD with proof null", async () => {
    const { status, json } = await postTurn(
      turnBody({ turn: 5, commitmentHash: "0x0000000000000000000000000000000000000000000000000000000000000001" }),
    );
    expect(status).toBe(200);
    expect(json.action).toBe("HOLD");
    expect(json.proof).toBeNull();
    expect(json.amount).toBeUndefined();
  });

  it("matching commitment in the envelope is accepted", async () => {
    const { status, json } = await postTurn(turnBody({ turn: 6, commitmentHash: commitment }));
    expect(status).toBe(200);
    expect(json.action).toBe("EXTRACT");
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
      expect(json.action).toBe("HOLD");
      expect(json.proof).toBeNull();
      expect(json.amount).toBeUndefined();
    } finally {
      await new Promise<void>((resolve) => fallbackServer.close(() => resolve()));
    }
  });
});
