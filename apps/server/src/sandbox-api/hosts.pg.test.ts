import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import type { Context } from "@wssp/api/context";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { hostPageSchema } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, expect, it, vi } from "vitest";
import {
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "c24b-pg-fixture",
    RATE_LIMIT_EMAIL_POINTS: 10000,
    RATE_LIMIT_EMAIL_WINDOW_SECONDS: 60,
    RATE_LIMIT_AUTH_POINTS: 10000,
    RATE_LIMIT_AUTH_WINDOW_SECONDS: 60,
    RATE_LIMIT_RPC_POINTS: 10000,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 30_000,
    RATE_LIMIT_SDK_KEY_POINTS: 10_000,
    RATE_LIMIT_SDK_OWNER_POINTS: 30_000,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.25" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});
const db = await pgTestDatabase();
const { createHostControlApi } = await import("./hosts.js");
const { createSandboxApi } = await import("./middleware.js");
const { sandboxHostsRouter } = await import("../../../../packages/api/src/routers/sandbox-hosts");
const { createHostToken, setHostDraining } = await import(
  "../../../../packages/api/src/sandbox/services/hosts"
);
const { createSandbox, reconnectSandbox, runCommand } = await import(
  "@wssp/api/sandbox/services/sandboxes"
);
const { createTemplate } = await import("../../../../packages/api/src/sandbox/services/templates");
const { createTemplateInput, createSandboxInput, runCommandInput } = await import(
  "@wssp/api/sandbox/contracts"
);
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { bindHostImageVerifier } = await import(
  "../../../../packages/api/src/sandbox/host-image-verifier"
);
const { generateProductCredentialSecret, credentialLookupPrefix, hmacDigestForProductPurpose } =
  await import("@wssp/db/credential-security");
const FP = `sha256:${"d".repeat(64)}`;
bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
const app = new Hono()
  .route("/api/sandbox-host", createHostControlApi())
  .route("/v1", createSandboxApi());
afterAll(() => db.close());
const principal = (ownerId: string) => ({ kind: "session" as const, ownerId });
async function fixture() {
  const id = `drain-${randomUUID()}`;
  const user = await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: id,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,

      egressEnforcement: true,
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: FP,
    },
  });
  const stopped = await seedSandboxInstance(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      originHostId: host.id,
      templateId: template.id,
      originPoolId: null,
      state: "STOPPED",
    },
  });
  const token = await createHostToken(principal(id), { hostId: host.id, name: "daemon" });
  const key = await createSdkKey(principal(id), {
    name: "sdk",
    scopes: [
      "hosts:read",
      "sandboxes:read",
      "sandboxes:create",
      "sandboxes:manage",
      "sandboxes:destroy",
      "templates:write",
    ],
    resourceMode: "ALL_OWNED",
    hostIds: [],
    templateRevisionIds: [],
  });
  const device = generateProductCredentialSecret("deviceCredential");
  const deviceRow = await db.inspect.hostDeviceCredential.create({
    data: {
      userId: id,
      sandboxHostId: host.id,
      lookupPrefix: credentialLookupPrefix(device),
      secretDigest: hmacDigestForProductPurpose({ purpose: "deviceCredential", value: device.raw }),
    },
  });
  const context = {
    clientIp: undefined,
    session: {
      user,
      session: {
        id: `session-${id}`,
        userId: id,
        token: "fixture",
        expiresAt: new Date(Date.now() + 60000),
        createdAt: new Date(),
        updatedAt: new Date(),
        ipAddress: null,
        userAgent: null,
      },
    },
  } as Context;
  return {
    id,
    host,
    template,
    stopped,
    token,
    key,
    device,
    deviceRow,
    client: createRouterClient(sandboxHostsRouter, { context }),
  };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
const request = async (f: Fixture, secret = f.token.secret, id = f.host.id, draining = true) =>
  app.request("/api/sandbox-host/drain", {
    method: "POST",
    headers: { Authorization: `Bearer ${secret}`, "Content-Type": "application/json" },
    body: JSON.stringify({ id, draining }),
  });
const create = (f: Fixture, key = randomUUID()) =>
  createSandbox(
    principal(f.id),
    createSandboxInput.parse({
      template: "revision/" + f.template.id,
      sandboxHostId: f.host.id,
      idempotencyKey: key,
    }),
  );
const sites: { name: string; run: (f: Fixture) => Promise<unknown> }[] = [
  { name: "create", run: (f: Fixture) => create(f) },
  {
    name: "cold reconnect",
    run: (f: Fixture) =>
      reconnectSandbox(principal(f.id), {
        id: f.stopped.id,
        mode: "cold",
        idempotencyKey: randomUUID(),
      }),
  },
  {
    name: "template registration",
    run: (f: Fixture) =>
      createTemplate(
        principal(f.id),
        createTemplateInput.parse({
          hostId: f.host.id,
          slug: "extra",
          label: "Extra",
          imageRef: "images:ubuntu/24.04/cloud",
        }),
      ),
  },
];
const settle = (p: Promise<unknown>) =>
  p.then(
    (value) => ({ ok: true, value }),
    (error) => ({ ok: false, error }),
  );

it.each(sites)("$name commits before drain under the same host lock", async (site) => {
  const f = await fixture();
  const pause = db.pauseAt("work", { after: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/ });
  const work = settle(db.run("work", () => site.run(f)));
  await pause.waitReached();
  const drain = settle(
    db.run("drain", () => f.client.setHostDraining({ id: f.host.id, draining: true })),
  );
  try {
    await db.waitUntilBlocked("drain", { by: "work" });
  } finally {
    pause.release();
  }
  expect(await work).toMatchObject({ ok: true });
  expect(await drain).toMatchObject({ ok: true, value: { draining: true } });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).draining,
  ).toBe(true);
});

it.each(sites)(
  "$name waits for drain then refuses without effects; undrain restores admission",
  async (site) => {
    const f = await fixture();
    const pause = db.pauseAt("drain", { after: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/ });
    const drain = settle(
      db.run("drain", () => f.client.setHostDraining({ id: f.host.id, draining: true })),
    );
    await pause.waitReached();
    const work = settle(db.run("work", () => site.run(f)));
    try {
      await db.waitUntilBlocked("work", { by: "drain" });
    } finally {
      pause.release();
    }
    expect(await drain).toMatchObject({ ok: true });
    expect(await work).toMatchObject({
      ok: false,
      error: { code: "CONFLICT", data: { code: "sandbox.host_draining" } },
    });
    expect(
      await db.inspect.sandboxOperation.count({
        where: { NOT: { idempotencyKey: { startsWith: "fixture-boot:" } }, userId: f.id },
      }),
    ).toBe(0);
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(1);
    expect(await db.inspect.sandboxTemplate.count({ where: { userId: f.id } })).toBe(1);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    ).toMatchObject({ draining: true, liveCount: 0 });
    await f.client.setHostDraining({ id: f.host.id, draining: false });
    await expect(site.run(f)).resolves.toBeDefined();
  },
);

it("drain preserves running guests, command and warm access, receipt replay and truthful counts", async () => {
  const f = await fixture();
  expect(await f.client.setHostDraining({ id: f.host.id, draining: false })).toMatchObject({
    draining: false,
    drained: false,
    liveSandboxCount: 0,
  });
  const idle = await app.request("/v1/hosts", {
    headers: { Authorization: `Bearer ${f.key.secret}` },
  });
  expect(hostPageSchema.parse(await idle.json()).items[0]).toMatchObject({
    draining: false,
    drained: false,
    liveSandboxCount: 0,
  });
  expect(await (await request(f)).json()).toMatchObject({
    draining: true,
    drained: true,
    liveSandboxCount: 0,
  });
  expect(await (await request(f, f.token.secret, f.host.id, false)).json()).toMatchObject({
    draining: false,
    drained: false,
    liveSandboxCount: 0,
  });
  const key = randomUUID();
  const receipt = await create(f, key);
  const sandbox = await db.inspect.sandbox.findFirstOrThrow({
    where: { userId: f.id, liveResourcesHeld: true },
  });
  await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state: "READY" } });
  await db.inspect.sandboxOperation.updateMany({
    where: { userId: f.id, sandboxId: receipt.id },
    data: { state: "SUCCEEDED" },
  });
  const before = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
  expect(await request(f).then((r) => r.json())).toEqual({
    id: f.host.id,
    draining: true,
    liveSandboxCount: 1,
    drained: false,
    offload: false,
  });
  expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } })).toEqual(before);
  expect((await create(f, key)).id).toBe(receipt.id);
  await expect(
    runCommand(
      principal(f.id),
      runCommandInput.parse({ id: sandbox.id, script: "true", idempotencyKey: randomUUID() }),
    ),
  ).resolves.toBeDefined();
  await expect(
    reconnectSandbox(principal(f.id), {
      id: sandbox.id,
      mode: "warm",
      idempotencyKey: randomUUID(),
    }),
  ).resolves.toBeDefined();
  expect(
    await db.inspect.sandboxOperation.count({
      where: {
        NOT: { idempotencyKey: { startsWith: "fixture-boot:" } },
        userId: f.id,
        kind: { in: ["STOP_SANDBOX", "KILL_SANDBOX"] },
      },
    }),
  ).toBe(0);
  const hosts = await app.request("/v1/hosts", {
    headers: { Authorization: `Bearer ${f.key.secret}` },
  });
  expect(hosts.status).toBe(200);
  expect(hostPageSchema.parse(await hosts.json()).items[0]).toMatchObject({
    draining: true,
    drained: false,
    liveSandboxCount: 1,
  });
  // Enrollment stays available while draining (drain is not a tombstone).
  await expect(
    createHostToken(principal(f.id), { hostId: f.host.id, name: "replacement" }),
  ).resolves.toBeDefined();
});

it("owner control rejects anonymous, foreign owners and SDK principals", async () => {
  const f = await fixture(),
    other = await fixture();
  await expect(
    createRouterClient(sandboxHostsRouter, {
      context: { session: null, clientIp: undefined },
    }).setHostDraining({
      id: f.host.id,
      draining: true,
    }),
  ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  await expect(
    other.client.setHostDraining({ id: f.host.id, draining: true }),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
  const { authenticateSdkKeySecret } = await import("@wssp/api/lib/sdk-key-access");
  const sdk = await authenticateSdkKeySecret(f.key.secret);
  expect(sdk).not.toBeNull();
  await expect(setHostDraining(sdk!, { id: f.host.id, draining: true })).rejects.toMatchObject({
    code: "FORBIDDEN",
  });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).draining,
  ).toBe(false);
});

it("host and device credentials control only their bound host and cannot use SDK authority", async () => {
  const f = await fixture(),
    other = await fixture();
  const sibling = await seedLaunchHost(db.inspect, {
    data: { userId: f.id, slug: "sibling", label: "Sibling" },
  });
  for (const secret of [f.token.secret, f.device.raw]) {
    expect((await request(f, secret)).status).toBe(200);
    expect((await request(f, secret, f.host.id, false)).status).toBe(200);
    for (const id of [sibling.id, other.host.id, "missing"])
      expect((await request(f, secret, id)).status).toBe(404);
    expect(
      (await app.request("/v1/hosts", { headers: { Authorization: `Bearer ${secret}` } })).status,
    ).toBe(401);
  }
  expect((await request(f, f.key.secret)).status).toBe(401);
  expect(
    (
      await app.request("/api/sandbox-host/drain", {
        method: "POST",
        headers: { Cookie: "session=fixture", "Content-Type": "application/json" },
        body: JSON.stringify({ id: f.host.id, draining: true }),
      })
    ).status,
  ).toBe(401);
  await db.inspect.hostToken.update({
    where: { id: f.token.token.id },
    data: { revokedAt: new Date() },
  });
  await db.inspect.hostDeviceCredential.update({
    where: { id: f.deviceRow.id },
    data: { revokedAt: new Date() },
  });
  expect((await request(f)).status).toBe(401);
  expect((await request(f, f.device.raw)).status).toBe(401);
});

it("credential revocation while drain waits on H is rechecked before write", async () => {
  const f = await fixture();
  const pause = db.pauseAt("drain", { before: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/ });
  const drain = db.run("drain", () => request(f));
  await pause.waitReached();
  await db.inspect.hostToken.update({
    where: { id: f.token.token.id },
    data: { revokedAt: new Date() },
  });
  pause.release();
  expect((await drain).status).toBe(401);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).draining,
  ).toBe(false);
});

it.each([
  { plane: "host credential", drain: async (f: Fixture) => (await request(f)).status },
  {
    plane: "owner session",
    drain: (f: Fixture) =>
      f.client.setHostDraining({ id: f.host.id, draining: true }).then(
        () => 200,
        (error: { status?: number }) => error.status,
      ),
  },
])(
  "$plane drain answers 409 when a hello bumps the epoch before the host CAS",
  async ({ drain }) => {
    const f = await fixture();
    const pause = db.pauseAt("drain-epoch", {
      before: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/,
    });
    const work = db.run("drain-epoch", () => drain(f));
    await pause.waitReached();
    // The committed effect of a concurrent hello registration.
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { connectionEpoch: { increment: 1 } },
    });
    pause.release();
    expect(await work).toBe(409);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    ).toMatchObject({ draining: false, connectionEpoch: 2 });
  },
);

it("SDK mutations return the catalogued drain error and undrain restores HTTP create", async () => {
  const f = await fixture();
  await f.client.setHostDraining({ id: f.host.id, draining: true });
  const post = (path: string, body: unknown) =>
    app.request(path, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${f.key.secret}`,
        "Content-Type": "application/json",
        "Idempotency-Key": randomUUID(),
      },
      body: JSON.stringify(body),
    });
  for (const [path, body] of [
    ["/v1/sandboxes", { sandboxHostId: f.host.id, template: "revision/" + f.template.id }],
    [`/v1/sandboxes/${f.stopped.id}/reconnect`, { mode: "cold" }],
    [
      "/v1/templates",
      { hostId: f.host.id, slug: "sdk", label: "SDK", imageRef: "images:ubuntu/24.04/cloud" },
    ],
  ] as const) {
    const response = await post(path, body);
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: { code: "sandbox.host_draining" } });
  }
  await f.client.setHostDraining({ id: f.host.id, draining: false });
  expect(
    (
      await post("/v1/sandboxes", {
        sandboxHostId: f.host.id,
        template: "revision/" + f.template.id,
      })
    ).status,
  ).toBe(202);
});

it("failed template drain receipts preserve the stable refusal on replay after undrain", async () => {
  const f = await fixture();
  await f.client.setHostDraining({ id: f.host.id, draining: true });
  const key = randomUUID();
  const post = () =>
    app.request("/v1/templates", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${f.key.secret}`,
        "Content-Type": "application/json",
        "Idempotency-Key": key,
      },
      body: JSON.stringify({
        hostId: f.host.id,
        slug: "retry",
        label: "Retry",
        imageRef: "images:ubuntu/24.04/cloud",
      }),
    });
  expect((await post()).status).toBe(409);
  await f.client.setHostDraining({ id: f.host.id, draining: false });
  const replay = await post();
  expect(replay.status).toBe(409);
  expect(await replay.json()).toMatchObject({ error: { code: "sandbox.host_draining" } });
  expect(
    await db.inspect.sandboxActionReceipt.findUniqueOrThrow({
      where: { userId_idempotencyKey: { userId: f.id, idempotencyKey: key } },
    }),
  ).toMatchObject({ state: "FAILED", errorCode: "sandbox.host_draining" });
  expect(await db.inspect.sandboxTemplate.count({ where: { userId: f.id } })).toBe(1);
});

it("host control rejects expired, banned and policy-blocked credentials and malformed bodies", async () => {
  const f = await fixture();
  await db.inspect.hostToken.update({
    where: { id: f.token.token.id },
    data: { expiresAt: new Date(0) },
  });
  expect((await request(f)).status).toBe(401);
  await db.inspect.user.update({ where: { id: f.id }, data: { banned: true } });
  expect((await request(f, f.device.raw)).status).toBe(401);
  await db.inspect.user.update({
    where: { id: f.id },
    data: { banned: false, role: "admin", twoFactorEnabled: false, createdAt: new Date(0) },
  });
  expect((await request(f, f.device.raw)).status).toBe(401);
  for (const body of [
    { id: f.host.id, draining: "true" },
    { id: f.host.id, draining: true, userId: f.id },
    { id: "bad\0", draining: true },
  ]) {
    const response = await app.request("/api/sandbox-host/drain", {
      method: "POST",
      headers: { Authorization: `Bearer ${f.device.raw}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    expect(response.status).toBe(400);
  }
  expect(
    (
      await app.request("/api/sandbox-host/drain", {
        method: "POST",
        headers: { Authorization: `Bearer ${f.device.raw}`, "Content-Type": "application/json" },
        body: "x".repeat(1025),
      })
    ).status,
  ).toBe(413);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).draining,
  ).toBe(false);
});

it("a failed drain write rolls back and emits no committed audit", async () => {
  const f = await fixture();
  const audit = vi.spyOn(console, "info");
  const pause = db.pauseAt("drain-fail", { after: "sandboxHost.update" });
  const work = settle(
    db.run("drain-fail", () => f.client.setHostDraining({ id: f.host.id, draining: true })),
  );
  await pause.waitReached();
  pause.fail(new Error("injected transaction failure"));
  expect(await work).toMatchObject({ ok: false });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).draining,
  ).toBe(false);
  expect(audit).not.toHaveBeenCalled();
  audit.mockRestore();
});

it("owner ban between router authorization and transaction entry refuses drain", async () => {
  const f = await fixture();
  const pause = db.pauseAt("owner-ban", {
    before: /^sql:SELECT id FROM "user" WHERE id = \? FOR SHARE$/,
  });
  const work = settle(
    db.run("owner-ban", () => f.client.setHostDraining({ id: f.host.id, draining: true })),
  );
  await pause.waitReached();
  await db.inspect.user.update({ where: { id: f.id }, data: { banned: true } });
  pause.release();
  expect(await work).toMatchObject({ ok: false, error: { code: "FORBIDDEN" } });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).draining,
  ).toBe(false);
});
