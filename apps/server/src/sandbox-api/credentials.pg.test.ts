import { seedAcceptedOperation } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

const hoisted = vi.hoisted(() => {
  // A real 32-byte root, set before the vault first reads it.
  const hex = Array.from({ length: 32 }, (_, i) =>
    ((i * 53 + 7) % 256).toString(16).padStart(2, "0"),
  ).join("");
  process.env.DATA_ENCRYPTION_KEY = hex;
  process.env.CREDENTIALS_ENABLED = "true";
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
    BETTER_AUTH_SECRET: "credential-http-fixture",
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
  getConnInfo: () => ({ remote: { address: "198.51.100.37" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import {
  credentialAccountDtoSchema,
  credentialDtoSchema,
  credentialInstanceDtoSchema,
  credentialInstancePageSchema,
  credentialLeasePageSchema,
  credentialLeaseReleasedSchema,
  credentialPageSchema,
  credentialValueWriteResultSchema,
  sdkErrorEnvelopeSchema,
} from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, describe, expect, it, vi } from "vitest";
import type { ServiceScope } from "../../../../packages/api/src/lib/service-scopes";
import { sessionPrincipal } from "../../../../packages/api/src/sandbox/contracts";
import { createSdkKey } from "../../../../packages/api/src/sandbox/services/sdk-keys";
import { seedSandbox } from "../../../../packages/api/src/webhooks/testing/fixtures";
import { createSandboxApi } from "./middleware";

/**
 * C4b end to end: SDK key → real `/v1` adapters → real services → PostgreSQL.
 * Scopes, the per-login allowlist, write-only values and dashboard-only
 * settings are checked through HTTP.
 */
const db = await pgTestDatabase();
afterAll(() => db.close());
const app = new Hono().route("/v1", createSandboxApi());

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

async function owner() {
  const id = `user-${randomUUID()}`;
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  return id;
}
async function allOwnedKey(ownerId: string, scopes: ServiceScope[]) {
  return createSdkKey(sessionPrincipal(ownerId), {
    name: "logins",
    resourceMode: "ALL_OWNED",
    hostIds: [],
    templateRevisionIds: [],
    scopes,
  });
}

const document = {
  schemaVersion: 1,
  id: "tool",
  displayName: "Tool",
  login: { command: "tool login", method: "device-code" },
  credentials: { env: [{ name: "TOOL_TOKEN", required: true }] },
};

describe("/v1 CLI logins (real PostgreSQL)", () => {
  it("advertises credentials features when the vault key is configured", async () => {
    expect(hoisted.hex).toHaveLength(64);
    const k = await allOwnedKey(await owner(), ["credentials:read"]);
    const caps = (await (await call(k.secret, "GET", "/v1/capabilities")).json()) as {
      features: string[];
    };
    expect(caps.features).toEqual(
      expect.arrayContaining(["credentials.read", "credentials.write"]),
    );
  });

  it("create → account → instance → write-only value; reads never return it", async () => {
    const k = await allOwnedKey(await owner(), ["credentials:read", "credentials:write"]);
    const def = await call(k.secret, "POST", "/v1/credential-definitions", { document });
    expect(def.status).toBe(201);
    const definition = (await def.json()) as { id: string; version: number };
    expect(definition.version).toBe(1);
    const created = await call(k.secret, "POST", "/v1/credentials", {
      name: "tool",
      definitionId: definition.id,
    });
    expect(created.status).toBe(201);
    const login = credentialDtoSchema.parse(await created.json());
    expect(created.headers.get("location")).toBe(`/v1/credentials/${login.id}`);
    expect(login).toMatchObject({ delivery: "GUEST", mode: "EXCLUSIVE" });
    const account = credentialAccountDtoSchema.parse(
      await (
        await call(k.secret, "POST", `/v1/credentials/${login.id}/accounts`, { name: "work" })
      ).json(),
    );
    const instance = credentialInstanceDtoSchema.parse(
      await (
        await call(
          k.secret,
          "POST",
          `/v1/credentials/${login.id}/accounts/${account.id}/instances`,
          {},
        )
      ).json(),
    );
    const written = await call(
      k.secret,
      "PUT",
      `/v1/credentials/${login.id}/instances/${instance.id}/value`,
      { env: { TOOL_TOKEN: "very-secret-token" } },
    );
    expect(written.status).toBe(200);
    expect(credentialValueWriteResultSchema.parse(await written.json())).toMatchObject({
      state: "READY",
    });
    const listed = await call(
      k.secret,
      "GET",
      `/v1/credentials/${login.id}/accounts/${account.id}/instances`,
    );
    const text = await listed.text();
    expect(credentialInstancePageSchema.parse(JSON.parse(text)).items[0]?.state).toBe("READY");
    expect(text).not.toContain("very-secret-token");
    // Invalid value → typed error naming no value.
    const bad = await call(
      k.secret,
      "PUT",
      `/v1/credentials/${login.id}/instances/${instance.id}/value`,
      {
        env: { OTHER: "x" },
      },
    );
    expect(bad.status).toBe(400);
    const badBody = await bad.text();
    expect(badBody).toContain("credential.value_invalid");
    expect(badBody).not.toContain("very-secret-token");
    // E2-B-01/02: the envelope is the public contract's (what the SDK parses
    // strictly) and names the undeclared env var.
    expect(sdkErrorEnvelopeSchema.parse(JSON.parse(badBody)).error).toMatchObject({
      code: "credential.value_invalid",
      entry: "env.OTHER",
    });
  });

  it("E2-B-04 lists an instance's live leases (credentials:read) so force-release can name one", async () => {
    const ownerId = await owner();
    const k = await allOwnedKey(ownerId, ["credentials:read", "credentials:write"]);
    const def = (await (
      await call(k.secret, "POST", "/v1/credential-definitions", { document })
    ).json()) as { id: string };
    const login = credentialDtoSchema.parse(
      await (
        await call(k.secret, "POST", "/v1/credentials", { name: "held", definitionId: def.id })
      ).json(),
    );
    const account = credentialAccountDtoSchema.parse(
      await (await call(k.secret, "POST", `/v1/credentials/${login.id}/accounts`, {})).json(),
    );
    const instance = credentialInstanceDtoSchema.parse(
      await (
        await call(
          k.secret,
          "POST",
          `/v1/credentials/${login.id}/accounts/${account.id}/instances`,
          {},
        )
      ).json(),
    );
    const leasesPath = `/v1/credentials/${login.id}/instances/${instance.id}/leases`;
    expect(
      credentialLeasePageSchema.parse(await (await call(k.secret, "GET", leasesPath)).json()),
    ).toEqual({ items: [], nextCursor: null });
    const host = await db.inspect.sandboxHost.create({
      data: { userId: ownerId, slug: randomUUID(), label: "Own host", connectionEpoch: 1 },
      select: { id: true },
    });
    const sandbox = await seedSandbox(db.inspect, ownerId, "READY", {
      sandboxHostId: host.id,
      hostOwnerId: ownerId,
      originHostId: host.id,
    });
    const op = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: ownerId,
        sandboxId: sandbox.id,
        kind: "CREATE_SANDBOX",
        state: "RUNNING",
        generation: 1,
        idempotencyKey: `test-${randomUUID()}`,
        requestBodyHash: "a".repeat(64),
        dispatchedHostId: host.id,
      },
    });
    const lease = await db.inspect.credentialLease.create({
      data: {
        userId: ownerId,
        credentialId: login.id,
        accountId: account.id,
        instanceId: instance.id,
        sandboxId: sandbox.id,
        operationId: op.id,
        kind: "WORKLOAD",
        exclusive: true,
        state: "ACTIVE",
        hostId: host.id,
      },
      select: { id: true },
    });
    const listed = credentialLeasePageSchema.parse(
      await (await call(k.secret, "GET", `${leasesPath}?limit=1`)).json(),
    );
    expect(listed).toMatchObject({
      items: [
        {
          id: lease.id,
          kind: "WORKLOAD",
          state: "ACTIVE",
          sandboxId: sandbox.id,
          checkpoint: null,
        },
      ],
      nextCursor: null,
    });
    // The scope gate: a write-only key cannot list; another owner sees nothing.
    const writeOnly = await allOwnedKey(ownerId, ["credentials:write"]);
    expect((await call(writeOnly.secret, "GET", leasesPath)).status).toBe(403);
    const stranger = await allOwnedKey(await owner(), ["credentials:read"]);
    expect((await call(stranger.secret, "GET", leasesPath)).status).toBe(404);
    // The listed id is what force-release takes; afterwards it is gone.
    const released = await call(
      k.secret,
      "POST",
      `/v1/credentials/${login.id}/instances/${instance.id}/leases/${listed.items[0]?.id}/force-release`,
      { promoteCheckpoint: true },
    );
    expect(released.status).toBe(200);
    expect(credentialLeaseReleasedSchema.parse(await released.json())).toMatchObject({
      leaseId: lease.id,
      released: true,
    });
    expect(
      credentialLeasePageSchema.parse(await (await call(k.secret, "GET", leasesPath)).json()).items,
    ).toEqual([]);
  });

  it("scopes: read-only keys cannot write; SDK keys cannot choose PROXY or foreign hosts", async () => {
    const ownerId = await owner();
    const reader = await allOwnedKey(ownerId, ["credentials:read"]);
    expect(
      (await call(reader.secret, "POST", "/v1/credential-definitions", { document })).status,
    ).toBe(403);
    const writer = await allOwnedKey(ownerId, ["credentials:read", "credentials:write"]);
    const def = (await (
      await call(writer.secret, "POST", "/v1/credential-definitions", { document })
    ).json()) as {
      id: string;
    };
    const proxy = await call(writer.secret, "POST", "/v1/credentials", {
      name: "p",
      definitionId: def.id,
      delivery: "PROXY",
    });
    expect(proxy.status).toBe(403);
    const foreign = await call(writer.secret, "POST", "/v1/credentials", {
      name: "f",
      definitionId: def.id,
      foreignAllowed: true,
    });
    expect(foreign.status).toBe(403);
  });

  it("allowlist keys see and act on granted logins only", async () => {
    const ownerId = await owner();
    const writer = await allOwnedKey(ownerId, ["credentials:read", "credentials:write"]);
    const def = (await (
      await call(writer.secret, "POST", "/v1/credential-definitions", { document })
    ).json()) as {
      id: string;
    };
    const a = credentialDtoSchema.parse(
      await (
        await call(writer.secret, "POST", "/v1/credentials", { name: "a", definitionId: def.id })
      ).json(),
    );
    const b = credentialDtoSchema.parse(
      await (
        await call(writer.secret, "POST", "/v1/credentials", { name: "b", definitionId: def.id })
      ).json(),
    );
    // ALLOWLIST keys still need one owned revision (existing mint rule).
    const template = await db.inspect.sandboxTemplate.create({
      data: { userId: ownerId, slug: "base", label: "Base" },
    });
    const revision = await db.inspect.sandboxTemplateRevision.create({
      data: {
        userId: ownerId,
        templateId: template.id,
        revision: 1,
        incusFingerprint: `sha256:${"b".repeat(64)}`,
        architecture: "x86_64",
        manifestDigest: "b".repeat(64),
      },
    });
    const limited = await createSdkKey(sessionPrincipal(ownerId), {
      name: "limited",
      resourceMode: "ALLOWLIST",
      poolMode: "ALL_USABLE",
      hostIds: [],
      templateRevisionIds: [revision.id],
      credentialIds: [a.id],
      scopes: ["credentials:read", "credentials:write"],
    } as never);
    const page = credentialPageSchema.parse(
      await (await call(limited.secret, "GET", "/v1/credentials")).json(),
    );
    expect(page.items.map((item) => item.id)).toEqual([a.id]);
    expect((await call(limited.secret, "GET", `/v1/credentials/${b.id}`)).status).toBe(404);
    expect(
      (await call(limited.secret, "POST", `/v1/credentials/${b.id}/accounts`, {})).status,
    ).toBe(404);
    expect(
      (await call(limited.secret, "POST", `/v1/credentials/${a.id}/accounts`, {})).status,
    ).toBe(201);
  });

  it("credentials:use: attach/free need it (403 without), allowlist keys must name a login at mint, the feature is advertised", async () => {
    const ownerId = await owner();
    const user = await allOwnedKey(ownerId, ["sandboxes:write", "credentials:use"]);
    const caps = (await (await call(user.secret, "GET", "/v1/capabilities")).json()) as {
      features: string[];
    };
    expect(caps.features).toContain("credentials.use");
    const plain = await allOwnedKey(ownerId, ["sandboxes:write"]);
    const send = (secret: string, method: string, path: string, body: unknown) =>
      app.request(path, {
        method,
        headers: {
          authorization: `Bearer ${secret}`,
          "content-type": "application/json",
          "idempotency-key": `k-${randomUUID()}`,
        },
        body: JSON.stringify(body),
      });
    expect(
      (
        await send(plain.secret, "POST", "/v1/sandboxes/sbx-missing/credentials", {
          credentialId: "cred-1",
        })
      ).status,
    ).toBe(403);
    expect(
      (await send(plain.secret, "DELETE", "/v1/sandboxes/sbx-missing/credentials/cred-1", {}))
        .status,
    ).toBe(403);
    // With the scope, a missing sandbox is a plain 404 (no existence leak).
    expect(
      (
        await send(user.secret, "POST", "/v1/sandboxes/sbx-missing/credentials", {
          credentialId: "cred-1",
        })
      ).status,
    ).toBe(404);
    const template = await db.inspect.sandboxTemplate.create({
      data: { userId: ownerId, slug: "base-use", label: "Base" },
    });
    const revision = await db.inspect.sandboxTemplateRevision.create({
      data: {
        userId: ownerId,
        templateId: template.id,
        revision: 1,
        incusFingerprint: `sha256:${"d".repeat(64)}`,
        architecture: "x86_64",
        manifestDigest: "d".repeat(64),
      },
    });
    await expect(
      createSdkKey(sessionPrincipal(ownerId), {
        name: "use-without-logins",
        resourceMode: "ALLOWLIST",
        poolMode: "ALL_USABLE",
        hostIds: [],
        templateRevisionIds: [revision.id],
        credentialIds: [],
        scopes: ["sandboxes:write", "credentials:use"],
      } as never),
    ).rejects.toMatchObject({ data: { code: "sdk_key.credentials_use_needs_logins" } });
  });
});
