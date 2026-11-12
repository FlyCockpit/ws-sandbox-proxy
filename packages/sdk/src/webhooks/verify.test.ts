import { createHmac } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import vectors from "../../../sandbox-contracts/src/webhook-signing-vectors.json";

const crypto = vi.hoisted(() => ({ compares: 0 }));
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return {
    ...actual,
    timingSafeEqual: (a: NodeJS.ArrayBufferView, b: NodeJS.ArrayBufferView) => {
      crypto.compares++;
      return actual.timingSafeEqual(a, b);
    },
  };
});
const { verifyWebhook, WebhookVerificationError } = await import("./verify");

const secret = `whsec_${Buffer.alloc(32, 4).toString("base64")}`;
const NOW = 1_800_000_000_000;
const body = JSON.stringify({
  id: `evt_${"a".repeat(32)}`,
  type: "webhook.test",
  schemaVersion: 1,
  occurredAt: "2026-11-02T00:00:00.000Z",
  data: { endpointId: "whe_1" },
});
function sign(payload: string, at = NOW / 1000, key = secret, id = `evt_${"a".repeat(32)}`) {
  const mac = createHmac("sha256", Buffer.from(key.slice(6), "base64"))
    .update(`${id}.${at}.${payload}`)
    .digest("base64");
  return { "webhook-id": id, "webhook-timestamp": String(at), "webhook-signature": `v1,${mac}` };
}
const code = (fn: () => unknown) => {
  try {
    fn();
  } catch (error) {
    if (error instanceof WebhookVerificationError) return error.code;
    throw error;
  }
  return "ok";
};

describe("verifyWebhook", () => {
  it.each(vectors.vectors)("accepts the shared vector: $name", (vector) => {
    const event = () =>
      verifyWebhook({
        body: vector.body,
        headers: {
          "webhook-id": vector.id,
          "webhook-timestamp": String(vector.timestamp),
          "webhook-signature": vector.signature,
        },
        secret: vector.secrets,
        now: () => vector.timestamp * 1000,
      });
    // Bodies that are not a wssp envelope pass the signature and fail only the shape.
    expect(code(event)).toBe(vector.body.includes('"schemaVersion"') ? "ok" : "malformed_payload");
  });

  it("returns the typed event for a valid string or byte body, any header casing", () => {
    const headers = sign(body);
    const event = verifyWebhook({ body, headers, secret, now: () => NOW });
    expect(event).toMatchObject({ type: "webhook.test", data: { endpointId: "whe_1" } });
    const upper = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toUpperCase(), v]));
    expect(
      verifyWebhook({
        body: new TextEncoder().encode(body),
        headers: upper,
        secret,
        now: () => NOW,
      }).id,
    ).toBe(`evt_${"a".repeat(32)}`);
    expect(
      verifyWebhook({ body, headers: new Headers(headers), secret, now: () => NOW }).type,
    ).toBe("webhook.test");
  });

  it("reports each failure code", () => {
    const headers = sign(body);
    expect(code(() => verifyWebhook({ body, headers: {}, secret, now: () => NOW }))).toBe(
      "missing_header",
    );
    expect(code(() => verifyWebhook({ body: `${body} `, headers, secret, now: () => NOW }))).toBe(
      "invalid_signature",
    );
    expect(
      code(() =>
        verifyWebhook({
          body,
          headers,
          secret: `whsec_${Buffer.alloc(32, 9).toString("base64")}`,
          now: () => NOW,
        }),
      ),
    ).toBe("invalid_signature");
    const junk = "not json";
    expect(
      code(() => verifyWebhook({ body: junk, headers: sign(junk), secret, now: () => NOW })),
    ).toBe("malformed_payload");
  });

  it("enforces the ±300 s tolerance boundary", () => {
    for (const [skew, expected] of [
      [300, "ok"],
      [-300, "ok"],
      [301, "timestamp_out_of_tolerance"],
      [-301, "timestamp_out_of_tolerance"],
    ] as const) {
      const at = NOW / 1000 + skew;
      expect(
        code(() => verifyWebhook({ body, headers: sign(body, at), secret, now: () => NOW })),
        String(skew),
      ).toBe(expected);
    }
  });

  it("accepts either secret during rotation and compares every candidate in constant time", () => {
    const old = `whsec_${Buffer.alloc(32, 1).toString("base64")}`;
    const headers = sign(body, NOW / 1000, old);
    crypto.compares = 0;
    expect(
      code(() => verifyWebhook({ body, headers, secret: [secret, old], now: () => NOW })),
    ).toBe("ok");
    expect(crypto.compares).toBeGreaterThanOrEqual(2);
  });

  it("returns a typed sandbox.offloaded event (STOPPED → OFFLOADED, no host)", () => {
    const id = `evt_${"c".repeat(32)}`;
    const offloaded = JSON.stringify({
      id,
      type: "sandbox.offloaded",
      schemaVersion: 1,
      occurredAt: "2026-11-02T00:00:00.000Z",
      data: {
        sandbox: {
          id: "sbx_1",
          name: "nightly",
          state: "OFFLOADED",
          previousState: "STOPPED",
          generation: 3,
          hostId: null,
          templateId: "tpl_1",
          templateRevisionId: "rev_1",
          originPoolId: null,
          metadata: {},
        },
      },
    });
    const event = verifyWebhook({
      body: offloaded,
      headers: sign(offloaded, NOW / 1000, secret, id),
      secret,
      now: () => NOW,
    });
    expect(event).toMatchObject({
      type: "sandbox.offloaded",
      data: { sandbox: { state: "OFFLOADED", previousState: "STOPPED", hostId: null } },
    });
  });

  it("does not throw on an unknown future event type", () => {
    const future = JSON.stringify({
      id: `evt_${"b".repeat(32)}`,
      type: "sandbox.paused",
      schemaVersion: 2,
      occurredAt: "2027-01-01T00:00:00.000Z",
      data: { anything: true },
    });
    const event = verifyWebhook({
      body: future,
      headers: sign(future, NOW / 1000, secret, `evt_${"b".repeat(32)}`),
      secret,
      now: () => NOW,
    });
    expect(event).toMatchObject({ type: "sandbox.paused", schemaVersion: 2 });
  });
});
