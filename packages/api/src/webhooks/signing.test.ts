import { describe, expect, it } from "vitest";
import vectors from "../../../sandbox-contracts/src/webhook-signing-vectors.json";
import { signatureHeader, webhookSignedHeaders } from "./signing";

const key = (secret: string) => Buffer.from(secret.slice("whsec_".length), "base64");

describe("Standard Webhooks signing", () => {
  it.each(vectors.vectors)("matches the shared vector: $name", (vector) => {
    expect(signatureHeader(vector.secrets.map(key), vector.id, vector.timestamp, vector.body)).toBe(
      vector.signature,
    );
  });

  it("signs new then old during a rotation overlap, binding id and timestamp", () => {
    const [a, b] = [Buffer.alloc(32, 1), Buffer.alloc(32, 2)];
    const both = signatureHeader([a, b], "evt_1", 100, "{}").split(" ");
    expect(both).toHaveLength(2);
    expect(both[0]).toBe(signatureHeader([a], "evt_1", 100, "{}"));
    expect(signatureHeader([a], "evt_2", 100, "{}")).not.toBe(both[0]);
    expect(signatureHeader([a], "evt_1", 101, "{}")).not.toBe(both[0]);
  });

  it("sends the wssp headers and never a credential", () => {
    const headers = webhookSignedHeaders({
      keys: [Buffer.alloc(32, 3)],
      eventId: "evt_1",
      eventType: "sandbox.ready",
      deliveryId: "d1",
      attempt: 2,
      timestamp: 1_800_000_000,
      body: "{}",
    });
    expect(Object.keys(headers).sort()).toEqual(
      [
        "content-type",
        "user-agent",
        "webhook-id",
        "webhook-signature",
        "webhook-timestamp",
        "wssp-delivery-attempt",
        "wssp-delivery-id",
        "wssp-event-type",
      ].sort(),
    );
    expect(JSON.stringify(headers)).not.toMatch(/wssp_(sdk|host|device)_|cookie|authorization/i);
  });
});
