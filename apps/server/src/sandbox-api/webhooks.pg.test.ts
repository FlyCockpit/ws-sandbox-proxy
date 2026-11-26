const hoisted = vi.hoisted(() => {
  // A real 32-byte key, set before the webhook config is first read.
  const hex = Array.from({ length: 32 }, (_, i) =>
    ((i * 37 + 11) % 256).toString(16).padStart(2, "0"),
  ).join("");
  process.env.DATA_ENCRYPTION_KEY = hex;
  // An operator host allowlist for the create-time eligibility tests.
  process.env.WEBHOOK_ALLOWED_PRIVATE_HOSTS = "box.example.test";
  return { hex };
});
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "webhook-http-fixture",
    RATE_LIMIT_RPC_POINTS: 10000,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 30000,
    RATE_LIMIT_SDK_KEY_POINTS: 10000,
    RATE_LIMIT_SDK_OWNER_POINTS: 30000,
    SANDBOX_MAX_TIMEOUT_MS: 86400000,
    TRANSFER_MAX_BYTES: 1073741824,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.36" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import {
  webhookDeliveryDetailSchema,
  webhookDeliveryPageSchema,
  webhookEndpointPageSchema,
  webhookEndpointSchema,
  webhookEndpointWithSecretSchema,
} from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, describe, expect, it, vi } from "vitest";
import type { ServiceScope } from "../../../../packages/api/src/lib/service-scopes";
import { sessionPrincipal } from "../../../../packages/api/src/sandbox/contracts";
import { createSdkKey } from "../../../../packages/api/src/sandbox/services/sdk-keys";
import { setWebhookDestinationResolverForTests } from "../../../../packages/api/src/webhooks/service";
import { createSandboxApi } from "./middleware";

const db = await pgTestDatabase();
afterAll(() => db.close());
const app = new Hono().route("/v1", createSandboxApi());
// No real DNS in tests: a scripted resolver stands in for c-ares.
const resolved = new Map<string, string[]>([
  ["box.example.test", ["10.1.2.3"]],
  ["mixed.example.test", ["93.184.215.14", "169.254.169.254"]],
  ["nat64.example.test", ["64:ff9b::a9fe:a9fe"]],
]);
const unresolvable = new Set(["nowhere.example.test"]);
setWebhookDestinationResolverForTests(async (host) => {
  if (unresolvable.has(host)) throw new Error("ENOTFOUND");
  return resolved.get(host) ?? ["93.184.215.14"];
});

function call(secret: string, method: string, path: string, body?: unknown) {
  return app.request(path, {
    method,
    headers: {
      authorization: `Bearer ${secret}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

async function owner(role = "user") {
  const id = `user-${randomUUID()}`;
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
      role,
    },
  });
  return id;
}
async function key(ownerId: string, scopes: ServiceScope[] = ["webhooks:write"]) {
  return createSdkKey(sessionPrincipal(ownerId), {
    name: "webhooks",
    resourceMode: "ALL_OWNED",
    hostIds: [],
    templateRevisionIds: [],
    scopes,
  });
}
const createBody = { url: "https://hooks.example.com/wssp?team=a", events: ["sandbox.ready"] };

describe("/v1 webhooks (real PostgreSQL)", () => {
  it("advertises the feature when DATA_ENCRYPTION_KEY is configured", async () => {
    expect(hoisted.hex).toHaveLength(64);
    const k = await key(await owner());
    const caps = (await (await call(k.secret, "GET", "/v1/capabilities")).json()) as {
      features: string[];
    };
    expect(caps.features).toContain("webhooks.write");
  });

  it("creates with 201 + Location and shows the secret once; reads never return it", async () => {
    const k = await key(await owner());
    const created = await call(k.secret, "POST", "/v1/webhooks/endpoints", createBody);
    expect(created.status).toBe(201);
    const body = webhookEndpointWithSecretSchema.parse(await created.json());
    expect(created.headers.get("location")).toBe(`/v1/webhooks/endpoints/${body.endpoint.id}`);
    expect(body.endpoint).toMatchObject({
      url: "https://hooks.example.com/wssp?team=a",
      enabled: true,
      secretVersion: 1,
      operationKinds: [
        "CREATE_SANDBOX",
        "STOP_SANDBOX",
        "KILL_SANDBOX",
        "RECONNECT_SANDBOX",
        "RENEW_SANDBOX_LEASE",
        "RUN_COMMAND",
      ],
    });
    const get = await call(k.secret, "GET", `/v1/webhooks/endpoints/${body.endpoint.id}`);
    expect(get.status).toBe(200);
    const getText = await get.text();
    webhookEndpointSchema.parse(JSON.parse(getText));
    const list = await call(k.secret, "GET", "/v1/webhooks/endpoints?limit=5");
    const listText = await list.text();
    webhookEndpointPageSchema.parse(JSON.parse(listText));
    const secretPart = body.secret.slice("whsec_".length);
    for (const text of [getText, listText]) {
      expect(text).not.toContain(secretPart);
      expect(text).not.toMatch(/whsec_|ciphertext|nonce/i);
    }
    // The stored row is ciphertext only.
    const row = await db.inspect.webhookEndpoint.findUniqueOrThrow({
      where: { id: body.endpoint.id },
    });
    expect(Buffer.from(row.secretCiphertext).includes(Buffer.from(secretPart, "base64"))).toBe(
      false,
    );
  });

  it("rotates: a new secret once, version 2, the old secret overlapping", async () => {
    const k = await key(await owner());
    const created = webhookEndpointWithSecretSchema.parse(
      await (await call(k.secret, "POST", "/v1/webhooks/endpoints", createBody)).json(),
    );
    const rotated = await call(
      k.secret,
      "POST",
      `/v1/webhooks/endpoints/${created.endpoint.id}/rotate-secret`,
      { overlapSeconds: 60 },
    );
    expect(rotated.status).toBe(200);
    const body = webhookEndpointWithSecretSchema.parse(await rotated.json());
    expect(body.secret).not.toBe(created.secret);
    expect(body.endpoint.secretVersion).toBe(2);
    expect(body.endpoint.previousSecretExpiresAt).not.toBeNull();
    const row = await db.inspect.webhookEndpoint.findUniqueOrThrow({
      where: { id: created.endpoint.id },
    });
    expect(row.previousSecretVersion).toBe(1);
  });

  it("maps destination refusals to stable codes", async () => {
    const k = await key(await owner());
    for (const [url, code] of [
      ["http://hooks.example.com/", "webhook.destination_invalid"],
      ["https://user:pw@hooks.example.com/", "webhook.destination_invalid"],
      ["https://10.0.0.1/", "webhook.destination_blocked"],
      ["https://[::ffff:169.254.169.254]/", "webhook.destination_blocked"],
      ["https://localhost/", "webhook.destination_blocked"],
    ] as const) {
      const response = await call(k.secret, "POST", "/v1/webhooks/endpoints", {
        ...createBody,
        url,
      });
      expect(response.status, url).toBe(400);
      expect(await response.json()).toMatchObject({ error: { code } });
    }
  });

  it("resolves hostnames at create: private answers need an eligible owner (review finding 4)", async () => {
    const user = await key(await owner());
    const admin = await key(await owner("admin"));
    for (const [secret, url, status, code] of [
      // Allowlisted host resolving privately: refused for a non-admin at create...
      [user.secret, "https://box.example.test/hook", 400, "webhook.destination_blocked"],
      // ...accepted for an eligible administrator.
      [admin.secret, "https://box.example.test/hook", 201, null],
      // Any blocked answer refuses, even beside a public one, for everyone.
      [admin.secret, "https://mixed.example.test/hook", 400, "webhook.destination_blocked"],
      // Embedded metadata through NAT64 is hard-denied even for an admin.
      [admin.secret, "https://nat64.example.test/hook", 400, "webhook.destination_blocked"],
      // A name that does not resolve is refused.
      [user.secret, "https://nowhere.example.test/hook", 400, "webhook.destination_invalid"],
    ] as const) {
      const response = await call(secret, "POST", "/v1/webhooks/endpoints", { ...createBody, url });
      expect(response.status, url).toBe(status);
      if (code) expect(await response.json()).toMatchObject({ error: { code } });
    }
    // Update re-checks too: a non-admin cannot move an endpoint onto the private host.
    const created = webhookEndpointWithSecretSchema.parse(
      await (await call(user.secret, "POST", "/v1/webhooks/endpoints", createBody)).json(),
    );
    const moved = await call(user.secret, "PUT", `/v1/webhooks/endpoints/${created.endpoint.id}`, {
      url: "https://box.example.test/hook",
      description: null,
      events: ["sandbox.ready"],
      operationKinds: "all",
      enabled: true,
    });
    expect(moved.status).toBe(400);
    expect(await moved.json()).toMatchObject({ error: { code: "webhook.destination_blocked" } });
  });

  it("disables an endpoint whose name no longer resolves; enabling or moving it re-validates", async () => {
    const k = await key(await owner());
    const created = webhookEndpointWithSecretSchema.parse(
      await (
        await call(k.secret, "POST", "/v1/webhooks/endpoints", {
          ...createBody,
          url: "https://flaky.example.test/hook",
        })
      ).json(),
    );
    unresolvable.add("flaky.example.test");
    const update = (enabled: boolean, url = "https://flaky.example.test/hook") =>
      call(k.secret, "PUT", `/v1/webhooks/endpoints/${created.endpoint.id}`, {
        url,
        description: "off",
        events: ["sandbox.ready"],
        operationKinds: "all",
        enabled,
      });
    try {
      const disabled = await update(false);
      expect(disabled.status).toBe(200);
      expect(webhookEndpointSchema.parse(await disabled.json())).toMatchObject({
        enabled: false,
        description: "off",
      });
      // Still disabled, other fields changed: no DNS needed.
      expect((await update(false)).status).toBe(200);
      // Enabling, or moving the destination, needs a resolvable name.
      const enabling = await update(true);
      expect(enabling.status).toBe(400);
      expect(await enabling.json()).toMatchObject({
        error: { code: "webhook.destination_invalid" },
      });
      const moving = await update(false, "https://nowhere.example.test/hook");
      expect(moving.status).toBe(400);
    } finally {
      unresolvable.delete("flaky.example.test");
    }
    expect((await update(true)).status).toBe(200);
  });

  it("enforces the scope on every route before any read", async () => {
    const k = await key(await owner(), ["sandboxes:read"]);
    for (const [method, path, body] of [
      ["GET", "/v1/webhooks/endpoints", undefined],
      ["POST", "/v1/webhooks/endpoints", createBody],
      ["GET", "/v1/webhooks/endpoints/x", undefined],
      [
        "PUT",
        "/v1/webhooks/endpoints/x",
        { ...createBody, description: null, operationKinds: "all", enabled: true },
      ],
      ["DELETE", "/v1/webhooks/endpoints/x", undefined],
      ["POST", "/v1/webhooks/endpoints/x/rotate-secret", {}],
      ["POST", "/v1/webhooks/endpoints/x/test", {}],
      ["GET", "/v1/webhooks/endpoints/x/deliveries", undefined],
      ["GET", "/v1/webhook-deliveries/x", undefined],
      ["POST", "/v1/webhook-deliveries/x/redeliver", {}],
    ] as const) {
      const response = await call(k.secret, method, path, body);
      expect(response.status, `${method} ${path}`).toBe(403);
    }
  });

  it("refuses to mint webhooks:write on a restricted key", async () => {
    const id = await owner();
    for (const input of [
      { resourceMode: "ALLOWLIST" as const, hostIds: ["h"], templateRevisionIds: ["t"] },
      {
        resourceMode: "ALL_OWNED" as const,
        hostIds: [],
        templateRevisionIds: [],
        poolMode: "SELECTED" as const,
      },
    ])
      await expect(
        createSdkKey(sessionPrincipal(id), { name: "x", scopes: ["webhooks:write"], ...input }),
      ).rejects.toMatchObject({
        code: "BAD_REQUEST",
        data: { code: "sdk_key.webhooks_requires_all_owned" },
      });
  });

  it("is owner-scoped: another owner's ids are 404 with the route's code", async () => {
    const a = await key(await owner());
    const b = await key(await owner());
    const created = webhookEndpointWithSecretSchema.parse(
      await (await call(a.secret, "POST", "/v1/webhooks/endpoints", createBody)).json(),
    );
    const sent = (await (
      await call(a.secret, "POST", `/v1/webhooks/endpoints/${created.endpoint.id}/test`, {})
    ).json()) as { deliveryId: string };
    for (const [method, path, code] of [
      ["GET", `/v1/webhooks/endpoints/${created.endpoint.id}`, "webhook.endpoint_not_found"],
      ["DELETE", `/v1/webhooks/endpoints/${created.endpoint.id}`, "webhook.endpoint_not_found"],
      [
        "GET",
        `/v1/webhooks/endpoints/${created.endpoint.id}/deliveries`,
        "webhook.endpoint_not_found",
      ],
      ["GET", `/v1/webhook-deliveries/${sent.deliveryId}`, "webhook.delivery_not_found"],
    ] as const) {
      const response = await call(b.secret, method, path);
      expect(response.status, path).toBe(404);
      expect(await response.json()).toMatchObject({ error: { code } });
    }
    const redeliver = await call(
      b.secret,
      "POST",
      `/v1/webhook-deliveries/${sent.deliveryId}/redeliver`,
      {},
    );
    expect(redeliver.status).toBe(404);
    const list = webhookEndpointPageSchema.parse(
      await (await call(b.secret, "GET", "/v1/webhooks/endpoints")).json(),
    );
    expect(list.items).toEqual([]);
  });

  it("test-send, delivery log, redeliver, update/disable and delete", async () => {
    const k = await key(await owner());
    const created = webhookEndpointWithSecretSchema.parse(
      await (await call(k.secret, "POST", "/v1/webhooks/endpoints", createBody)).json(),
    );
    const id = created.endpoint.id;
    const test = await call(k.secret, "POST", `/v1/webhooks/endpoints/${id}/test`, {});
    expect(test.status).toBe(202);
    const accepted = (await test.json()) as { deliveryId: string; eventId: string };
    const page = webhookDeliveryPageSchema.parse(
      await (
        await call(k.secret, "GET", `/v1/webhooks/endpoints/${id}/deliveries?state=PENDING`)
      ).json(),
    );
    expect(page.items.map((item) => [item.id, item.kind, item.eventType])).toEqual([
      [accepted.deliveryId, "test", "webhook.test"],
    ]);
    const detail = webhookDeliveryDetailSchema.parse(
      await (await call(k.secret, "GET", `/v1/webhook-deliveries/${accepted.deliveryId}`)).json(),
    );
    expect(detail).toMatchObject({ eventId: accepted.eventId, attempts: [] });
    const again = await call(
      k.secret,
      "POST",
      `/v1/webhook-deliveries/${accepted.deliveryId}/redeliver`,
      {},
    );
    expect(again.status).toBe(202);
    expect(await again.json()).toMatchObject({ eventId: accepted.eventId });

    const disabled = await call(k.secret, "PUT", `/v1/webhooks/endpoints/${id}`, {
      url: "https://hooks.example.com/other",
      description: "ci",
      events: ["sandbox.ready", "operation.completed"],
      operationKinds: "all",
      enabled: false,
    });
    expect(disabled.status).toBe(200);
    expect(webhookEndpointSchema.parse(await disabled.json())).toMatchObject({
      enabled: false,
      disabledReason: "owner",
      operationKinds: "all",
      description: "ci",
    });
    // Disabling cancelled pending work; a disabled endpoint refuses test-send.
    expect(
      (await db.inspect.webhookDelivery.findMany({ where: { endpointId: id } })).every(
        (row) => row.state === "CANCELLED",
      ),
    ).toBe(true);
    const refused = await call(k.secret, "POST", `/v1/webhooks/endpoints/${id}/test`, {});
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ error: { code: "webhook.endpoint_disabled" } });

    const deleted = await call(k.secret, "DELETE", `/v1/webhooks/endpoints/${id}`);
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({ id, deleted: true });
    expect((await call(k.secret, "GET", `/v1/webhooks/endpoints/${id}`)).status).toBe(404);
  });

  it("budgets test-send per endpoint (429 after 2/min)", async () => {
    const k = await key(await owner());
    const created = webhookEndpointWithSecretSchema.parse(
      await (await call(k.secret, "POST", "/v1/webhooks/endpoints", createBody)).json(),
    );
    const path = `/v1/webhooks/endpoints/${created.endpoint.id}/test`;
    expect((await call(k.secret, "POST", path, {})).status).toBe(202);
    expect((await call(k.secret, "POST", path, {})).status).toBe(202);
    const third = await call(k.secret, "POST", path, {});
    expect(third.status).toBe(429);
  });
});
