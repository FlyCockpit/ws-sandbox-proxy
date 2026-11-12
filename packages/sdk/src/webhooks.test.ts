import { expect, it } from "vitest";
import { createWsspClient } from "./client";

const now = "2026-11-02T00:00:00.000Z";
const endpoint = {
  id: "whe_1",
  url: "https://hooks.example.com/x",
  description: null,
  events: ["sandbox.ready"],
  operationKinds: "all",
  payloadVersion: 1,
  enabled: true,
  disabledAt: null,
  disabledReason: null,
  secretVersion: 1,
  previousSecretExpiresAt: null,
  health: {
    consecutiveFailures: 0,
    failingSince: null,
    lastSuccessAt: null,
    lastFailureAt: null,
    lastFailureClass: null,
  },
  createdAt: now,
  updatedAt: now,
};

it("drives the webhook routes without idempotency keys and with declared statuses", async () => {
  const calls: { method: string; path: string; headers: Headers; body: string | null }[] = [];
  const client = createWsspClient({
    baseUrl: "https://api.example.test",
    apiKey: "wssp_sdk_fixture",
    fetch: async (input, init) => {
      const url = new URL(String(input));
      calls.push({
        method: init?.method ?? "GET",
        path: url.pathname + url.search,
        headers: new Headers(init?.headers),
        body: typeof init?.body === "string" ? init.body : null,
      });
      if (url.pathname === "/v1/webhooks/endpoints" && init?.method === "POST")
        return Response.json(
          { endpoint, secret: `whsec_${Buffer.alloc(32, 1).toString("base64")}` },
          { status: 201 },
        );
      if (url.pathname.endsWith("/test"))
        return Response.json(
          { deliveryId: "whd_1", eventId: `evt_${"0".repeat(32)}` },
          { status: 202 },
        );
      if (init?.method === "DELETE") return Response.json({ id: "whe_1", deleted: true });
      if (url.pathname.endsWith("/deliveries"))
        return Response.json({ items: [], nextCursor: null });
      return Response.json(endpoint);
    },
  });
  const created = await client.webhooks.endpoints.create({
    url: endpoint.url,
    events: ["sandbox.ready"],
  });
  expect(created.secret).toMatch(/^whsec_/);
  expect(await client.webhooks.endpoints.test("whe_1")).toMatchObject({ deliveryId: "whd_1" });
  expect(await client.webhooks.deliveries.list("whe_1", { state: "FAILED", limit: 5 })).toEqual({
    items: [],
    nextCursor: null,
  });
  expect(await client.webhooks.endpoints.delete("whe_1")).toEqual({ id: "whe_1", deleted: true });
  expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
    "POST /v1/webhooks/endpoints",
    "POST /v1/webhooks/endpoints/whe_1/test",
    "GET /v1/webhooks/endpoints/whe_1/deliveries?limit=5&state=FAILED",
    "DELETE /v1/webhooks/endpoints/whe_1",
  ]);
  for (const call of calls) expect(call.headers.get("idempotency-key")).toBeNull();
});
