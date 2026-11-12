import {
  seedAcceptedOperation,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", async (original) => ({
  ...(await original<typeof import("@wssp/api/sandbox/budgets")>()),
  consumeCreateConnectBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import {
  JSON_ROUTE_IDS as SDK_ROUTE_IDS,
  JSON_ROUTES as SDK_ROUTES,
  type JsonRouteId as SdkRouteId,
} from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, beforeEach, expect, it, vi } from "vitest";
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
    BETTER_AUTH_SECRET: "c24-pg-fixture",
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
  getConnInfo: () => ({ remote: { address: "198.51.100.24" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});
const db = await pgTestDatabase();
const { createSandboxApi } = await import("./middleware.js");
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { SERVICE_SCOPES } = await import("@wssp/api/lib/service-scopes");
const { unusableScopes } = await import("../../../../packages/api/src/lib/sdk-key-rules");
/** Every scope but `missing`, minus any scope it alone made usable (for
 * example credentials:use without sandboxes:write): mint refuses those. */
function withoutScope(missing: string) {
  const rest = SERVICE_SCOPES.filter((scope) => scope !== missing);
  const unusable = new Set(unusableScopes(rest));
  return rest.filter((scope) => !unusable.has(scope));
}
const { bindHostSandboxProbe, bindHostImageVerifier, HostImageMissing } = await import(
  "../../../../packages/api/src/sandbox/host-image-verifier"
);
const { bindSandboxDispatchWake } = await import("../../../../packages/api/src/sandbox/outbox");
const { hashRequestBody, requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
const { ACTION_DIGEST_DOMAIN, digestContextSnapshot } = await import(
  "../../../../packages/api/src/sandbox/digest-context"
);
const { createTemplateInput, runCommandInput } = await import("@wssp/api/sandbox/contracts");
const app = new Hono().route("/v1", createSandboxApi());
const FP = `sha256:${"c".repeat(64)}`;
afterAll(() => db.close());
beforeEach(() => {
  bindHostSandboxProbe(async () => "guest_ready");
  bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
  bindSandboxDispatchWake(null);
});
async function fixture(scopes: readonly (typeof SERVICE_SCOPES)[number][] = SERVICE_SCOPES) {
  const id = `c24-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id, name: "Owner", email: `${id}@example.test`, twoFactorEnabled: true },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: id,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,

      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 1,
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
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      originHostId: host.id,
      templateId: template.id,
      originPoolId: null,
      state: "READY",
      leaseExpiresAt: new Date(Date.now() + 3_600_000),
    },
  });
  const operation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: id,
      sandboxId: sandbox.id,
      kind: "RUN_COMMAND",
      generation: 1,
      idempotencyKey: "seed",
      requestBodyHash: "seed",
      state: "RUNNING",
      dispatchAttempt: 1,
      acceptedAttempt: 1,
      dispatchedHostId: host.id,
      dispatchedConnectionEpoch: 1,
      resultVersion: 1,
      processId: randomUUID(),
      processPid: 42,
      processBootId: randomUUID(),
      processStartTicks: "123",
      processStartedAt: new Date(),
    },
  });
  const key = await createSdkKey(
    { kind: "session", ownerId: id },
    {
      name: "sdk",
      scopes: [...scopes],
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
    },
  );
  return { id, host, template, sandbox, operation, key };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
// Receipt-bearing mutations only. Capture needs an image-capable host (its
// scope and refusal paths are covered by the dedicated test below); webhook
// resource routes answer with the resource itself (webhooks.pg.test.ts).
// Webhook, template-build and CLI-login routes answer with resources, not
// operation receipts; their own suites cover them.
const routeIds = SDK_ROUTE_IDS.filter(
  (id) =>
    SDK_ROUTES[id].method !== "get" &&
    id !== "captureSandbox" &&
    // Rename answers with the Sandbox itself, not a receipt (its own test below).
    id !== "updateSandbox" &&
    SDK_ROUTES[id].feature !== "webhooks.write" &&
    SDK_ROUTES[id].feature !== "templates.build" &&
    SDK_ROUTES[id].feature?.startsWith("credentials.") !== true,
);
function bodyFor(id: SdkRouteId, f: Fixture): Record<string, unknown> {
  switch (id) {
    case "createSandbox":
      return { sandboxHostId: f.host.id, template: "revision/" + f.template.id };
    case "reconnectSandbox":
      return { mode: "warm" };
    case "renewSandboxLease":
      return { timeoutMs: 60000 };
    case "startCommand":
      return { script: "printf 'hello'" };
    case "signalProcess":
      return { generation: 1, processId: f.operation.processId, attempt: 1, signal: "SIGKILL" };
    case "killProcess":
      return { generation: 1, processId: f.operation.processId, attempt: 1 };
    case "sendProcessStdin":
      return {
        generation: 1,
        processId: f.operation.processId,
        attempt: 1,
        contentBase64: Buffer.from("hi").toString("base64"),
      };
    case "writeStdin":
      return { contentBase64: "aGk=", eof: true };
    case "statPath":
    case "listDir":
    case "mkdir":
    case "removePath":
    case "requestDownload":
      return { path: "/tmp/test" };
    case "movePath":
      return { path: "/tmp/a", destPath: "/tmp/b" };
    case "associateTemplateAvailability":
      return { hostId: f.host.id, revisionId: f.template.id };
    case "appendTemplateRevision":
      return { hostId: f.host.id, imageRef: "images:ubuntu/24.04/cloud" };
    case "registerTemplate":
      return {
        hostId: f.host.id,
        slug: "new",
        label: "New",
        imageRef: "images:ubuntu/24.04/cloud",
      };
    default:
      return {};
  }
}
async function request(
  f: Fixture,
  id: SdkRouteId,
  body = bodyFor(id, f),
  key = randomUUID(),
  secret = f.key.secret,
) {
  const route = SDK_ROUTES[id];
  const path = route.path.replace(
    "{id}",
    route.path.includes("operations")
      ? f.operation.id
      : route.path.includes("/revisions/")
        ? f.template.id
        : route.path.includes("/templates/")
          ? f.template.templateId
          : f.sandbox.id,
  );
  return app.request(path.replace("{pid}", "42"), {
    method: route.method.toUpperCase(),
    headers: {
      authorization: `Bearer ${secret}`,
      "content-type": "application/json",
      "idempotency-key": key,
    },
    body: JSON.stringify(body),
  });
}
async function json(response: Response) {
  return (await response.json()) as {
    operationId: string;
    state: string;
    location: string;
    observation: string | null;
    error: { code: string };
  };
}
async function read(f: Fixture, location: string) {
  return app.request(location, { headers: { authorization: `Bearer ${f.key.secret}` } });
}

it("E-43 repeated DELETE redispatches an unknown kill from STOPPING", async () => {
  const f = await fixture();
  const retryKey = randomUUID();
  const first = await request(f, "destroySandbox", {}, randomUUID());
  expect(first.status).toBe(202);
  const receipt = await json(first);
  const stopping = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } });
  expect(stopping.state).toBe("STOPPING");
  expect((await request(f, "destroySandbox", {}, randomUUID())).status).toBe(409);
  await db.inspect.sandboxOperation.update({
    where: { id: receipt.operationId },
    data: { state: "UNKNOWN_OUTCOME", dispatchAttempt: 1 },
  });
  const response = await request(f, "destroySandbox", {}, retryKey);
  expect(response.status).toBe(202);
  const retried = await json(response);
  expect(retried.operationId).not.toBe(receipt.operationId);
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: retried.operationId } }),
  ).toMatchObject({ state: "QUEUED", generation: stopping.generation + 1 });
  expect(
    await db.inspect.outboxEvent.findFirst({
      where: {
        aggregateId: f.sandbox.id,
        eventType: "sandbox.kill_requested",
        payload: { path: ["operationId"], equals: retried.operationId },
      },
    }),
  ).not.toBeNull();
  // The same idempotency key still replays its original receipt.
  expect((await json(await request(f, "destroySandbox", {}, retryKey))).operationId).toBe(
    retried.operationId,
  );
});

it("E3B-02 DELETE of an already-DELETED sandbox succeeds idempotently; another owner still gets 404", async () => {
  const f = await fixture();
  // A create a node daemon restart interrupted ends DELETED, detached.
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: {
      state: "DELETED",
      sandboxHostId: null,
      storagePoolId: null,
      liveResourcesHeld: false,
      diskReservationHeld: false,
    },
  });
  const before = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } });
  const key = randomUUID();
  const response = await request(f, "destroySandbox", {}, key);
  const receipt = await json(response);
  expect(response.status, JSON.stringify(receipt)).toBe(202);
  expect(receipt.state).toBe("SUCCEEDED");
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: receipt.operationId } }),
  ).toMatchObject({ kind: "KILL_SANDBOX", state: "SUCCEEDED", generation: before.generation });
  // Nothing is sent to any host, and the sandbox is unchanged.
  expect(
    await db.inspect.outboxEvent.count({
      where: { aggregateId: f.sandbox.id, eventType: "sandbox.kill_requested" },
    }),
  ).toBe(0);
  expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } })).toEqual({
    ...before,
    updatedAt: expect.any(Date),
  });
  // The same key replays; a new key succeeds again.
  expect((await json(await request(f, "destroySandbox", {}, key))).operationId).toBe(
    receipt.operationId,
  );
  expect((await request(f, "destroySandbox", {}, randomUUID())).status).toBe(202);
  // Ownership is unchanged: another owner's key cannot see it.
  const other = await fixture();
  expect((await request(f, "destroySandbox", {}, randomUUID(), other.key.secret)).status).toBe(404);
});

it("mounts every mutation with its declared scope, durable receipt and operation location", async () => {
  expect(routeIds).toHaveLength(22);
  for (const id of routeIds) {
    const required = [...SDK_ROUTES[id].scopes];
    // The fixture cancellation target is RUN_COMMAND, so cancellation composes
    // its mutation grant with operations:cancel.
    if (id === "cancelOperation") required.push("commands:execute");
    const f = await fixture(required);
    const response = await request(f, id);
    const receipt = await json(response);
    expect(response.status, `${id}: ${JSON.stringify(receipt)}`).toBe(202);
    expect(SDK_ROUTES[id].response.schema.safeParse(receipt).success, id).toBe(true);
    if (id === "associateTemplateAvailability")
      expect(
        await db.inspect.sandboxActionReceipt.findUniqueOrThrow({
          where: { id: receipt.operationId },
        }),
      ).toMatchObject({
        templateRevisionId: f.template.id,
        verificationConnectionEpoch: f.host.connectionEpoch,
      });
    expect(response.headers.get("location"), id).toBe(receipt.location);
    const reader = await createSdkKey(
      { kind: "session", ownerId: f.id },
      {
        name: "reader",
        scopes: ["operations:read"],
        resourceMode: "ALL_OWNED",
        hostIds: [],
        templateRevisionIds: [],
      },
    );
    expect(
      (
        await app.request(receipt.location, {
          headers: { authorization: `Bearer ${reader.secret}` },
        })
      ).status,
      id,
    ).toBe(200);
    for (const missing of required) {
      const denied = await createSdkKey(
        { kind: "session", ownerId: f.id },
        {
          name: "denied",
          scopes: withoutScope(missing),
          resourceMode: "ALL_OWNED",
          hostIds: [],
          templateRevisionIds: [],
        },
      );
      const rejection = await request(f, id, bodyFor(id, f), randomUUID(), denied.secret);
      expect(rejection.status, `${id} without ${missing}`).toBe(403);
    }
  }
});

it.each(["createSandbox", "startCommand", "stopSandbox", "destroySandbox"] as const)(
  "concurrent different keys for identical %s bind one receipt and conflict",
  async (id) => {
    const f = await fixture();
    const body = bodyFor(id, f);
    const key = randomUUID();
    const otherKey = await createSdkKey(
      { kind: "session", ownerId: f.id },
      {
        name: "retry",
        scopes: [...SERVICE_SCOPES],
        resourceMode: "ALL_OWNED",
        hostIds: [],
        templateRevisionIds: [],
      },
    );
    const gate = db.pauseAt("first", { after: "sandboxOperation.create" });
    const first = db.run("first", () => request(f, id, body, key));
    await gate.waitReached();
    const second = db.run("second", () => request(f, id, body, key, otherKey.secret));
    await db.waitUntilBlocked("second", { by: "first" });
    gate.release();
    const [a, b] = await Promise.all([first, second]);
    expect(a.status).toBe(202);
    expect(b.status).toBe(409);
    expect((await json(b)).error.code).toBe("sandbox.idempotency_conflict");
    expect(
      await db.inspect.sandboxOperation.count({
        where: {
          NOT: { idempotencyKey: { startsWith: "fixture-boot:" } },
          userId: f.id,
          idempotencyKey: key,
        },
      }),
    ).toBe(1);
    expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(1);
    if (id === "createSandbox")
      expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(2);
  },
);

it("recovers a real P2002 winner after rollback without committing the losing outbox", async () => {
  const f = await fixture();
  const key = randomUUID();
  const body = bodyFor("startCommand", f);
  const gate = db.pauseAt("request", { before: "sandboxOperation.create" });
  const response = db.run("request", () => request(f, "startCommand", body, key));
  await gate.waitReached();
  const winner = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.id,
      sandboxId: f.sandbox.id,
      kind: "RUN_COMMAND",
      generation: 1,
      idempotencyKey: key,
      ...requestDigestMetadata(),
      authorizingKeyId: f.key.key.id,
      requestBodyHash: hashRequestBody(
        runCommandInput.parse({ ...body, id: f.sandbox.id, idempotencyKey: key }),
        { ownerId: f.id, hostOwnerId: f.id, hostId: f.host.id, authorizingKeyId: f.key.key.id },
      ),
    },
  });
  gate.release();
  const received = await response;
  expect(received.status).toBe(202);
  expect((await json(received)).operationId).toBe(winner.id);
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(0);
});

it("replays after a lost response and notifier failure while changed bodies and actions conflict", async () => {
  const f = await fixture();
  const key = randomUUID();
  bindSandboxDispatchWake(() => {
    throw new Error("shutdown");
  });
  const first = await request(f, "createSandbox", bodyFor("createSandbox", f), key);
  expect(first.status).toBe(202);
  // Deliberately discard the accepted body: a client timed out after commit.
  const retry = await request(f, "createSandbox", bodyFor("createSandbox", f), key);
  expect(retry.status).toBe(202);
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(1);
  for (const [id, body] of [
    ["createSandbox", { ...bodyFor("createSandbox", f), metadata: { changed: "true" } }],
    ["stopSandbox", {}],
    ["probeSandbox", {}],
  ] as const) {
    const changed = await request(f, id, body, key);
    expect(changed.status).toBe(409);
    expect((await json(changed)).error.code).toBe("sandbox.idempotency_conflict");
  }
});

it("replays before terminal state validation and adapts an omitted reconnect mode", async () => {
  const f = await fixture();
  const key = randomUUID();
  const body = bodyFor("startCommand", f);
  const first = await request(f, "startCommand", body, key);
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: { state: "DELETED", generation: 2 },
  });
  const retry = await request(f, "startCommand", body, key);
  expect(retry.status).toBe(202);
  expect(await retry.json()).toEqual(await first.json());
  expect((await request(f, "startCommand")).status).toBe(409);
  expect((await request(f, "reconnectSandbox", { mode: "cold" })).status).toBe(409);
  await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { state: "STOPPED" } });
  expect((await request(f, "reconnectSandbox", { mode: "warm" })).status).toBe(409);
  const cold = await request(f, "reconnectSandbox", {});
  expect(cold.status).toBe(202);
  expect(
    (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } })).generation,
  ).toBe(3);
});

it("C24 a reconnect idempotency key is bound to its mode in both directions", async () => {
  // warm first (sandbox READY): a cold retry with the same key conflicts.
  const warmFirst = await fixture();
  const key = randomUUID();
  const warm = await request(warmFirst, "reconnectSandbox", { mode: "warm" }, key);
  expect(warm.status, await warm.clone().text()).toBe(202);
  const coldRetry = await request(warmFirst, "reconnectSandbox", { mode: "cold" }, key);
  expect(coldRetry.status).toBe(409);
  expect((await json(coldRetry)).error.code).toBe("sandbox.idempotency_conflict");
  const warmReplay = await request(warmFirst, "reconnectSandbox", { mode: "warm" }, key);
  expect(warmReplay.status).toBe(202);
  expect(await warmReplay.json()).toEqual(await warm.json());

  // cold first (sandbox STOPPED): a warm retry with the same key conflicts.
  const coldFirst = await fixture();
  await db.inspect.sandbox.update({
    where: { id: coldFirst.sandbox.id },
    data: { state: "STOPPED" },
  });
  const other = randomUUID();
  const cold = await request(coldFirst, "reconnectSandbox", { mode: "cold" }, other);
  expect(cold.status, await cold.clone().text()).toBe(202);
  const warmRetry = await request(coldFirst, "reconnectSandbox", { mode: "warm" }, other);
  expect(warmRetry.status).toBe(409);
  expect((await json(warmRetry)).error.code).toBe("sandbox.idempotency_conflict");
  const coldReplay = await request(coldFirst, "reconnectSandbox", { mode: "cold" }, other);
  expect(coldReplay.status).toBe(202);
  expect(await coldReplay.json()).toEqual(await cold.json());
});

it("probe receipts require a host observation and preserve unknown transport outcomes on retry", async () => {
  const f = await fixture(["sandboxes:read", "operations:read"]);
  const key = randomUUID();
  let finish!: (state: "guest_ready") => void;
  let entered!: () => void;
  const reached = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const probe = vi.fn(() => {
    entered();
    return new Promise<"guest_ready">((resolve) => {
      finish = resolve;
    });
  });
  bindHostSandboxProbe(probe);
  const response = request(f, "probeSandbox", {}, key);
  await reached;
  const during = await request(f, "probeSandbox", {}, key);
  expect(during.status).toBe(202);
  const pending = await json(during);
  expect(pending.state).toBe("UNKNOWN_OUTCOME");
  finish("guest_ready");
  expect((await response).status).toBe(202);
  expect((await json(await read(f, pending.location))).observation).toBe("guest_ready");
  expect(probe).toHaveBeenCalledTimes(1);
  const statusOnly = await createSdkKey(
    { kind: "session", ownerId: f.id },
    {
      name: "status",
      scopes: ["operations:read"],
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
    },
  );
  const redacted = await app.request(pending.location, {
    headers: { authorization: `Bearer ${statusOnly.secret}` },
  });
  expect(redacted.status).toBe(200);
  expect((await json(redacted)).observation).toBeNull();
  const disconnected = vi.fn(async () => {
    throw new Error("transport closed");
  });
  bindHostSandboxProbe(disconnected);
  const unknownKey = randomUUID();
  const unknown = await json(await request(f, "probeSandbox", {}, unknownKey));
  expect(unknown.state).toBe("UNKNOWN_OUTCOME");
  expect(await json(await request(f, "probeSandbox", {}, unknownKey))).toEqual(unknown);
  expect(disconnected).toHaveBeenCalledTimes(1);
});

/**
 * A key the mint path refuses since C46 (a scope that grants nothing given the
 * others), inserted directly so the runtime authorization that must still deny
 * it stays covered.
 */
async function insertUnmintableSdkKey(ownerId: string, scopes: string[]): Promise<string> {
  const { credentialLookupPrefix, generateProductCredentialSecret, hmacDigestForProductPurpose } =
    await import("@wssp/db/credential-security");
  const credential = generateProductCredentialSecret("sdkKey");
  await db.inspect.sdkKey.create({
    data: {
      userId: ownerId,
      name: `unmintable-${randomUUID()}`,
      resourceMode: "ALL_OWNED",
      scopes,
      lookupPrefix: credentialLookupPrefix(credential),
      secretDigest: hmacDigestForProductPurpose({ purpose: "sdkKey", value: credential.raw }),
    },
  });
  return credential.raw;
}

it("cancellation composes the target mutation scope and stdin retries do not duplicate input", async () => {
  const f = await fixture();
  const key = randomUUID();
  const narrow = await insertUnmintableSdkKey(f.id, ["operations:cancel"]);
  expect((await request(f, "cancelOperation", {}, randomUUID(), narrow)).status).toBe(403);
  const first = await request(f, "writeStdin", { contentBase64: "aGk=" }, key);
  const retry = await request(f, "writeStdin", { contentBase64: "aGk=" }, key);
  expect(first.status).toBe(202);
  expect(await retry.json()).toEqual(await first.json());
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: f.id, eventType: "sandbox.stdin_requested" },
    }),
  ).toBe(1);
  expect((await request(f, "writeStdin", { contentBase64: "eA==" }, key)).status).toBe(409);
  const cancelled = await request(f, "cancelOperation");
  expect(cancelled.status).toBe(202);
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } })).state,
  ).toBe("CANCEL_REQUESTED");
});

it("bounds metadata and JSON before persistence and rejects malformed or absent request keys", async () => {
  const f = await fixture();
  const create = bodyFor("createSandbox", f);
  for (const metadata of [
    { nested: {} },
    { value: "\0" },
    { value: "\ud800" },
    { list: [] },
    Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, 1])),
    { ["x".repeat(65)]: true },
    { value: "x".repeat(1025) },
    Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`k${i}`, "😀".repeat(256)])),
  ]) {
    const response = await request(f, "createSandbox", { ...create, metadata });
    expect(response.status).toBe(400);
    expect((await json(response)).error.code).toBe("sandbox.metadata_invalid");
  }
  expect(
    (
      await request(f, "createSandbox", {
        ...create,
        metadata: { ok: "true", size: "0", nullable: "null", value: "😀" },
      })
    ).status,
  ).toBe(202);
  const path = `/v1/sandboxes/${f.sandbox.id}/stop`;
  for (const key of ["", "with spaces", "x".repeat(129), "lease-expire:forbidden"]) {
    const response = await app.request(path, {
      method: "POST",
      headers: { authorization: `Bearer ${f.key.secret}`, "Idempotency-Key": key },
    });
    expect(response.status).toBe(400);
  }
  for (const [body, status] of [
    ["{", 400],
    [JSON.stringify({ value: "x".repeat(1024 * 1024) }), 413],
  ] as const) {
    const response = await app.request(path, {
      method: "POST",
      headers: {
        authorization: `Bearer ${f.key.secret}`,
        "content-type": "application/json",
        "Idempotency-Key": randomUUID(),
      },
      body,
    });
    expect(response.status).toBe(status);
  }
});

it("C34 egress: normalizes policies only on capable hosts and rejects malformed ones with the typed error", async () => {
  const f = await fixture();
  const create = bodyFor("createSandbox", f);
  for (const egress of [
    { domains: ["*.example.com"] },
    { domains: ["https://example.com"] },
    { cidrs: ["0.0.0.0/0"] },
    { cidrs: ["::/0"] },
    { cidrs: ["10.0.0.0/8"] },
    { cidrs: ["168.63.129.16/32"] },
    { cidrs: ["2001:4860::/32"] },
  ]) {
    const response = await request(f, "createSandbox", { ...create, egress });
    expect(response.status, JSON.stringify(egress)).toBe(400);
    expect((await json(response)).error.code).toBe("sandbox.egress_policy_invalid");
  }
  // Unsupported fields, wrong types and oversized policies are egress policy
  // failures with the dedicated code, even though the request schema (not
  // resolveCreateEgressPolicy) rejects them.
  for (const egress of [
    { domains: ["ok.example.com"], wildcard: true },
    { domains: "example.com" },
    { cidrs: [42] },
    { domains: Array.from({ length: 129 }, (_, i) => `d${i}.example.com`) },
  ]) {
    const response = await request(f, "createSandbox", { ...create, egress });
    expect(response.status, JSON.stringify(egress)).toBe(400);
    expect((await json(response)).error.code, JSON.stringify(egress)).toBe(
      "sandbox.egress_policy_invalid",
    );
  }
  // A valid policy against a host without the egress capability: the host
  // advertised no enforcement, so the create cannot allocate.
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { egressEnforcement: false },
  });
  const incapable = await request(f, "createSandbox", {
    ...create,
    egress: { domains: ["example.com"] },
  });
  expect(incapable.status).toBe(400);
  expect((await json(incapable)).error.code).toBe("UNSUPPORTED_CAPABILITY");
  // The implicit deny-all policy is gated on the same capability.
  const deniedIncapable = await request(f, "createSandbox", create);
  expect(deniedIncapable.status).toBe(400);
  expect((await json(deniedIncapable)).error.code).toBe("UNSUPPORTED_CAPABILITY");
  const baseline = await db.inspect.sandbox.count({ where: { userId: f.id } });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { egressEnforcement: true },
  });
  const created = await request(f, "createSandbox", {
    ...create,
    egress: { domains: ["Example.COM.", "bücher.example"], cidrs: ["128.66.1.2/24"] },
  });
  expect(created.status).toBe(202);
  const row = await db.inspect.sandbox.findFirstOrThrow({
    where: { userId: f.id },
    orderBy: { createdAt: "desc" },
  });
  expect(row.egressPolicy).toEqual({
    domains: ["example.com", "xn--bcher-kva.example"],
    cidrs: ["128.66.1.0/24"],
  });
  expect(row.egressPolicyHash).toMatch(/^[0-9a-f]{64}$/);
  // The sandbox DTO discloses the normalized policy to the owner.
  const detail = await app.request(`/v1/sandboxes/${row.id}`, {
    headers: { authorization: `Bearer ${f.key.secret}` },
  });
  expect(detail.status).toBe(200);
  expect(((await detail.json()) as { egress: unknown }).egress).toEqual({
    mode: "allowlist",
    ...(row.egressPolicy as object),
  });
  // A create without a policy requests open; this host cannot serve open
  // mode, so the effective policy is deny-all (HOST_UNSUPPORTED).
  const denied = await request(f, "createSandbox", create);
  expect(denied.status).toBe(202);
  const denyAll = await db.inspect.sandbox.findFirstOrThrow({
    where: { userId: f.id },
    orderBy: { createdAt: "desc" },
  });
  expect(denyAll.egressPolicy).toEqual({ domains: [], cidrs: [] });
  expect(denyAll.egressModeReason).toBe("HOST_UNSUPPORTED");
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(baseline + 2);
});

it("rechecks owner, creating key and revocation while retained replay survives future grant loss", async () => {
  const f = await fixture();
  const other = await fixture();
  const key = randomUUID();
  const body = bodyFor("startCommand", f);
  expect((await request(f, "startCommand", body, key)).status).toBe(202);
  expect((await request(f, "startCommand", body, key, other.key.secret)).status).toBe(404);
  for (const allow of ["host", "template"] as const) {
    const restricted = await createSdkKey(
      { kind: "session", ownerId: f.id },
      {
        name: "restricted",
        scopes: SERVICE_SCOPES.filter(
          // An allowlist key can hold neither webhooks:write (all-owned only) nor
          // credentials:use without an allowlisted login.
          (scope) => scope !== "webhooks:write" && scope !== "credentials:use",
        ),
        resourceMode: "ALLOWLIST",
        hostIds: [f.host.id],
        templateRevisionIds: [f.template.id],
      },
    );
    await db.inspect.sandboxOperation.updateMany({
      where: { sandboxId: f.sandbox.id, kind: "CREATE_SANDBOX" },
      data: { authorizingKeyId: restricted.key.id },
    });
    const restrictedIntent = randomUUID();
    expect(
      (await request(f, "startCommand", body, restrictedIntent, restricted.secret)).status,
    ).toBe(202);
    if (allow === "host")
      await db.inspect.sdkKeyRevisionAllowlist.deleteMany({
        where: { sdkKeyId: restricted.key.id },
      });
    else
      await db.inspect.sdkKeyHostAllowlist.deleteMany({ where: { sdkKeyId: restricted.key.id } });
    expect((await request(f, "startCommand", body, key, restricted.secret)).status).toBe(409);
    expect(
      (await request(f, "startCommand", body, restrictedIntent, restricted.secret)).status,
    ).toBe(202);
  }
  await db.inspect.sdkKey.update({ where: { id: f.key.key.id }, data: { revokedAt: new Date() } });
  expect((await request(f, "startCommand", body, key)).status).toBe(401);
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(3);
});

it("retains template action status after host deletion without granting restricted keys history access", async () => {
  const f = await fixture();
  const row = await db.inspect.sandboxActionReceipt.create({
    data: {
      ...requestDigestMetadata(),
      digestContext: digestContextSnapshot({
        domain: ACTION_DIGEST_DOMAIN,
        hostId: "deleted-host",
        hostOwnerId: f.id,
      }),
      userId: f.id,
      idempotencyKey: "retained",
      requestBodyHash: "hash",
      action: "templates.create",
      hostId: "deleted-host",
      resourceId: f.template.templateId,
      templateRevisionId: f.template.id,
      state: "SUCCEEDED",
    },
  });
  expect((await read(f, `/v1/operations/${row.id}`)).status).toBe(200);
  const restricted = await createSdkKey(
    { kind: "session", ownerId: f.id },
    {
      name: "restricted",
      scopes: ["operations:read"],
      resourceMode: "ALLOWLIST",
      hostIds: [f.host.id],
      templateRevisionIds: [f.template.id],
    },
  );
  const response = await app.request(`/v1/operations/${row.id}`, {
    headers: { authorization: `Bearer ${restricted.secret}` },
  });
  expect(response.status).toBe(403);
});

it("a TCP client timeout after commit recovers the same operation on retry", async () => {
  const { createServer } = await import("node:http");
  const { getRequestListener } = await import("@hono/node-server");
  const f = await fixture();
  const key = randomUUID();
  const body = bodyFor("createSandbox", f);
  const controller = new AbortController();
  let handled!: () => void;
  const completed = new Promise<void>((resolve) => {
    handled = resolve;
  });
  const listener = getRequestListener(app.fetch);
  const server = createServer((request, response) => {
    void listener(request, response).finally(handled);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("TCP fixture failed to listen");
  try {
    bindSandboxDispatchWake(() => controller.abort());
    await expect(
      fetch(`http://127.0.0.1:${address.port}/v1/sandboxes`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${f.key.secret}`,
          "content-type": "application/json",
          "Idempotency-Key": key,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: "AbortError" });
    await completed;
    const retry = await request(f, "createSandbox", body, key);
    expect(retry.status).toBe(202);
    const operations = await db.inspect.sandboxOperation.findMany({
      where: { userId: f.id, idempotencyKey: key },
      take: 2,
    });
    expect(operations).toHaveLength(1);
    expect((await json(retry)).operationId).toBe(operations[0]!.id);
    expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(1);
  } finally {
    bindSandboxDispatchWake(null);
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

it("template registration retries retain success or failed verification without repeating host IO", async () => {
  const f = await fixture();
  const key = randomUUID();
  const body = bodyFor("registerTemplate", f);
  const verify = vi.fn(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
  bindHostImageVerifier(verify);
  const first = await request(f, "registerTemplate", body, key);
  const retry = await request(f, "registerTemplate", body, key);
  expect(first.status).toBe(202);
  expect(await retry.json()).toEqual(await first.json());
  expect(verify).toHaveBeenCalledTimes(1);
  expect(await db.inspect.sandboxTemplate.count({ where: { userId: f.id, slug: "new" } })).toBe(1);
  expect((await request(f, "registerTemplate", { ...body, label: "changed" }, key)).status).toBe(
    409,
  );
  const failedKey = randomUUID();
  verify.mockRejectedValue(new Error("unavailable"));
  const failed = await request(f, "registerTemplate", { ...body, slug: "failed" }, failedKey);
  expect((await json(failed)).state).toBe("FAILED");
  const failedRetry = await request(f, "registerTemplate", { ...body, slug: "failed" }, failedKey);
  expect((await json(failedRetry)).state).toBe("FAILED");
  expect(verify).toHaveBeenCalledTimes(2);
  expect(await db.inspect.sandboxTemplate.count({ where: { userId: f.id, slug: "failed" } })).toBe(
    0,
  );
});

it("2B request rotation refuses both same and changed input without allocation", async () => {
  const f = await fixture();
  const key = randomUUID();
  const body = bodyFor("startCommand", f);
  expect((await request(f, "startCommand", body, key)).status).toBe(202);
  const prior = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { userId_idempotencyKey: { userId: f.id, idempotencyKey: key } },
  });
  expect(prior).toMatchObject(requestDigestMetadata());
  const { env } = await import("@wssp/env/server");
  const original = env.SANDBOX_REQUEST_HMAC_SECRET;
  Object.assign(env, { SANDBOX_REQUEST_HMAC_SECRET: "fedcba9876543210".repeat(4) });
  try {
    for (const input of [body, { script: "different" }]) {
      const response = await request(f, "startCommand", input, key);
      expect(response.status).toBe(409);
      expect((await json(response)).error).toMatchObject({
        code: "digest_key_changed",
        message: "Digest key changed.",
      });
    }
    expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(1);
  } finally {
    Object.assign(env, { SANDBOX_REQUEST_HMAC_SECRET: original });
  }
});

it.each([
  ["startCommand", false],
  ["startCommand", true],
  ["registerTemplate", false],
  ["registerTemplate", true],
] as const)(
  "2B P2002 %s recovery checks the digest key before body equality (changed body: %s)",
  async (route, changed) => {
    const f = await fixture();
    const key = randomUUID();
    const body = bodyFor(route, f);
    const action = route === "registerTemplate";
    const verify = vi.fn(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
    bindHostImageVerifier(verify);
    const gate = db.pauseAt("rotating-request", {
      before: action ? "sandboxActionReceipt.create" : "sandboxOperation.create",
    });
    const incoming = changed
      ? action
        ? { ...body, label: "different" }
        : { script: "different" }
      : body;
    const pending = db.run("rotating-request", () => request(f, route, incoming, key));
    await gate.waitReached();
    // This writer bypasses the API advisory, forcing a real unique violation
    // and the fresh transaction lookup after the losing INSERT rolls back.
    const winner = action
      ? await db.inspect.sandboxActionReceipt.create({
          data: {
            digestContext: digestContextSnapshot({
              domain: ACTION_DIGEST_DOMAIN,
              hostId: f.host.id,
              hostOwnerId: f.id,
            }),
            userId: f.id,
            hostId: f.host.id,
            action: "templates.create",
            idempotencyKey: key,
            authorizingKeyId: f.key.key.id,
            ...requestDigestMetadata(),
            requestBodyHash: hashRequestBody(
              {
                action: "templates.create",
                input: { ...createTemplateInput.parse(body), idempotencyKey: key },
              },
              {
                domain: ACTION_DIGEST_DOMAIN,
                hostOwnerId: f.id,
                ownerId: f.id,
                hostId: f.host.id,
                authorizingKeyId: f.key.key.id,
              },
            ),
          },
        })
      : await seedAcceptedOperation(db.inspect, {
          data: {
            userId: f.id,
            sandboxId: f.sandbox.id,
            kind: "RUN_COMMAND",
            generation: 1,
            idempotencyKey: key,
            authorizingKeyId: f.key.key.id,
            ...requestDigestMetadata(),
            requestBodyHash: hashRequestBody(
              runCommandInput.parse({ ...body, id: f.sandbox.id, idempotencyKey: key }),
              {
                ownerId: f.id,
                hostOwnerId: f.id,
                hostId: f.host.id,
                authorizingKeyId: f.key.key.id,
              },
            ),
          },
        });
    const { env } = await import("@wssp/env/server");
    const original = env.SANDBOX_REQUEST_HMAC_SECRET;
    Object.assign(env, { SANDBOX_REQUEST_HMAC_SECRET: "fedcba9876543210".repeat(4) });
    try {
      gate.release();
      const response = await pending;
      expect(response.status).toBe(409);
      expect((await json(response)).error).toMatchObject({
        code: "digest_key_changed",
        message: "Digest key changed.",
      });
      expect(
        action
          ? await db.inspect.sandboxActionReceipt.findUniqueOrThrow({
              where: { userId_idempotencyKey: { userId: f.id, idempotencyKey: key } },
            })
          : await db.inspect.sandboxOperation.findUniqueOrThrow({
              where: { userId_idempotencyKey: { userId: f.id, idempotencyKey: key } },
            }),
      ).toMatchObject({ id: winner.id, requestDigestKeyId: winner.requestDigestKeyId });
      expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(0);
      expect(verify).not.toHaveBeenCalled();
    } finally {
      gate.release();
      Object.assign(env, { SANDBOX_REQUEST_HMAC_SECRET: original });
    }
  },
);

it("2B action receipt rotation refuses same and changed input without host IO", async () => {
  const f = await fixture();
  const key = randomUUID();
  const body = bodyFor("registerTemplate", f);
  const verify = vi.fn(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
  bindHostImageVerifier(verify);
  expect((await request(f, "registerTemplate", body, key)).status).toBe(202);
  const prior = await db.inspect.sandboxActionReceipt.findUniqueOrThrow({
    where: { userId_idempotencyKey: { userId: f.id, idempotencyKey: key } },
  });
  expect(prior).toMatchObject(requestDigestMetadata());
  const { env } = await import("@wssp/env/server");
  const original = env.SANDBOX_REQUEST_HMAC_SECRET;
  Object.assign(env, { SANDBOX_REQUEST_HMAC_SECRET: "fedcba9876543210".repeat(4) });
  try {
    for (const input of [body, { ...body, label: "different" }]) {
      const response = await request(f, "registerTemplate", input, key);
      expect(response.status).toBe(409);
      expect((await json(response)).error).toMatchObject({
        code: "digest_key_changed",
        message: "Digest key changed.",
      });
    }
    expect(verify).toHaveBeenCalledTimes(1);
    expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.id } })).toBe(1);
    expect(await db.inspect.sandboxTemplate.count({ where: { userId: f.id, slug: "new" } })).toBe(
      1,
    );
  } finally {
    Object.assign(env, { SANDBOX_REQUEST_HMAC_SECRET: original });
  }
});

it.each(["owner", "idempotency"] as const)(
  "3A P2002 recovery reacquires %s in a fresh transaction",
  async (rank) => {
    const f = await fixture();
    const key = randomUUID();
    const body = bodyFor("startCommand", f);
    const insertion = db.pauseAt("request", { before: "sandboxOperation.create" });
    const response = db.run("request", () => request(f, "startCommand", body, key));
    await insertion.waitReached();
    const winner = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: f.id,
        sandboxId: f.sandbox.id,
        kind: "RUN_COMMAND",
        generation: 1,
        idempotencyKey: key,
        authorizingKeyId: f.key.key.id,
        ...requestDigestMetadata(),
        requestBodyHash: hashRequestBody(
          runCommandInput.parse({ ...body, id: f.sandbox.id, idempotencyKey: key }),
          { ownerId: f.id, hostOwnerId: f.id, hostId: f.host.id, authorizingKeyId: f.key.key.id },
        ),
      },
    });
    const recovering = db.pauseAt("request", { before: /^sql:SELECT id FROM "user".*FOR SHARE$/ });
    insertion.release();
    await recovering.waitReached(); // P2002 rolled the first transaction back.
    const held = db.pauseAt("holder", { before: "$transaction.commit" });
    const holder = db.run("holder", () =>
      db.prisma.$transaction(async (tx) => {
        if (rank === "owner")
          await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${f.id} FOR UPDATE`;
        else
          await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${JSON.stringify([f.id, key])}, 0))`;
      }),
    );
    await held.waitReached();
    recovering.release();
    try {
      // pg_blocking_pids observes the current lock wait while pg_stat_activity
      // can still expose the preceding statement during its stats update.
      // Require the exact fresh-transaction lock query once both agree.
      await expect
        .poll(async () => (await db.waitUntilBlocked("request", { by: "holder" })).query, {
          timeout: 10000,
        })
        .toMatch(rank === "owner" ? /"user".*FOR SHARE/ : /pg_advisory_xact_lock/);
    } finally {
      held.release();
    }
    await holder;
    const result = await response;
    expect(result.status).toBe(202);
    expect((await json(result)).operationId).toBe(winner.id);
    expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(0);
  },
);

it("3A generic P2002 recovery admits the owner before invoking a lookup", async () => {
  const f = await fixture();
  const { ownerKeyTransaction } = await import("@wssp/api/sandbox/operation-transaction");
  const key = randomUUID();
  const gate = db.pauseAt("generic", { before: "sandboxOperation.create" });
  const pending = db.run("generic", () =>
    ownerKeyTransaction(
      { kind: "session", ownerId: f.id },
      key,
      async (tx) => {
        const prior = await tx.sandboxOperation.findUnique({
          where: { userId_idempotencyKey: { userId: f.id, idempotencyKey: key } },
          select: { id: true },
        });
        return prior ? { value: prior.id } : null;
      },
      async (tx) =>
        (
          await seedAcceptedOperation(tx, {
            data: {
              userId: f.id,
              sandboxId: f.sandbox.id,
              kind: "RUN_COMMAND",
              generation: 1,
              idempotencyKey: key,
              requestBodyHash: "test",
            },
          })
        ).id,
    ),
  );
  await gate.waitReached();
  const winner = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.id,
      sandboxId: f.sandbox.id,
      kind: "RUN_COMMAND",
      generation: 1,
      idempotencyKey: key,
      requestBodyHash: "test",
    },
  });
  const recovery = db.pauseAt("generic", { before: /^sql:SELECT id FROM "user".*FOR SHARE$/ });
  gate.release();
  await recovery.waitReached();
  const held = db.pauseAt("root", { before: "$transaction.commit" });
  const root = db.run("root", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${f.id} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  recovery.release();
  try {
    expect((await db.waitUntilBlocked("generic", { by: "root", timeoutMs: 2000 })).query).toMatch(
      /"user".*FOR SHARE/,
    );
  } finally {
    held.release();
  }
  await root;
  expect(await pending).toBe(winner.id);
});

it.each(["host", "revision"] as const)(
  "stored_creation_key_matrix HTTP retains history after future %s grant removal; use needs the current host",
  async (removed) => {
    const f = await fixture();
    const key = await createSdkKey(
      { kind: "session", ownerId: f.id },
      {
        name: "matrix",
        scopes: SERVICE_SCOPES.filter(
          // An allowlist key can hold neither webhooks:write (all-owned only) nor
          // credentials:use without an allowlisted login.
          (scope) => scope !== "webhooks:write" && scope !== "credentials:use",
        ),
        resourceMode: "ALLOWLIST",
        hostIds: [f.host.id],
        templateRevisionIds: [f.template.id],
      },
    );
    await db.inspect.sandboxOperation.updateMany({
      where: { sandboxId: f.sandbox.id, kind: "CREATE_SANDBOX" },
      data: { authorizingKeyId: key.key.id },
    });
    const probe = await json(await request(f, "probeSandbox", {}, randomUUID(), key.secret));
    if (removed === "host")
      await db.inspect.sdkKeyHostAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
    else await db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
    // Fresh placement/template work still requires current resource selection.
    for (const route of [
      "createSandbox",
      "appendTemplateRevision",
      "associateTemplateAvailability",
    ] as const)
      expect((await request(f, route, bodyFor(route, f), randomUUID(), key.secret)).status).toBe(
        removed === "revision" ? 404 : 403,
      );
    for (const path of [
      `/v1/sandboxes/${f.sandbox.id}`,
      `/v1/operations/${f.operation.id}`,
      probe.location,
    ])
      expect(
        (await app.request(path, { headers: { authorization: `Bearer ${key.secret}` } })).status,
        path,
      ).toBe(200);
    const list = await app.request("/v1/sandboxes", {
      headers: { authorization: `Bearer ${key.secret}` },
    });
    expect(list.status).toBe(200);
    expect(await list.json()).toMatchObject({ items: [{ id: f.sandbox.id }] });
    const intent = randomUUID(),
      body = bodyFor("startCommand", f);
    // History reads above are retained, but use needs
    // the sandbox's current host grant; the revision grant is not custody.
    const used = removed === "host" ? 403 : 202;
    const accepted = await request(f, "startCommand", body, intent, key.secret);
    expect(accepted.status).toBe(used);
    expect((await request(f, "startCommand", body, intent, key.secret)).status).toBe(used);
    if (removed === "host")
      await db.inspect.sdkKeyHostAllowlist.create({
        data: { sdkKeyId: key.key.id, sandboxHostId: f.host.id },
      });
    else
      await db.inspect.sdkKeyRevisionAllowlist.create({
        data: { userId: f.id, sdkKeyId: key.key.id, templateRevisionId: f.template.id },
      });
    expect(
      (
        await app.request(`/v1/sandboxes/${f.sandbox.id}`, {
          headers: { authorization: `Bearer ${key.secret}` },
        })
      ).status,
    ).toBe(200);
    expect(
      (await request(f, "startCommand", bodyFor("startCommand", f), randomUUID(), key.secret))
        .status,
    ).toBe(202);
  },
);

it("3B HTTP K2 correct and guessed envs return identical conflict without invoking a request digest", async () => {
  const f = await fixture();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: {
      journalKeyVersion: 1,
      journalKeyId: requestDigestMetadata().requestDigestKeyId,
      journalKeyAcknowledgedEpoch: 1,
    },
  });
  const key = randomUUID();
  const body = { script: "true", envs: { TOKEN: "synthetic-k1-secret" } };
  expect((await request(f, "startCommand", body, key)).status).toBe(202);
  const other = await createSdkKey(
    { kind: "session", ownerId: f.id },
    {
      name: "other",
      scopes: [...SERVICE_SCOPES],
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
    },
  );
  const digests = await import("@wssp/api/sandbox/idempotency");
  const digest = vi.spyOn(digests, "hashOperationRequestBody");
  try {
    for (const value of [body.envs.TOKEN, "guessed"]) {
      const response = await request(
        f,
        "startCommand",
        { ...body, envs: { TOKEN: value } },
        key,
        other.secret,
      );
      expect(response.status).toBe(409);
      expect((await json(response)).error).toMatchObject({
        code: "sandbox.idempotency_conflict",
        message: "Idempotency key was used for different input.",
      });
    }
    expect(digest).not.toHaveBeenCalled();
  } finally {
    digest.mockRestore();
  }
});

it("3B typed non-sandbox action receipt requires its exact revision grant", async () => {
  const f = await fixture();
  const key = await createSdkKey(
    { kind: "session", ownerId: f.id },
    {
      name: "typed-receipt",
      scopes: SERVICE_SCOPES.filter(
        // An allowlist key can hold neither webhooks:write (all-owned only) nor
        // credentials:use without an allowlisted login.
        (scope) => scope !== "webhooks:write" && scope !== "credentials:use",
      ),
      resourceMode: "ALLOWLIST",
      hostIds: [f.host.id],
      templateRevisionIds: [f.template.id],
    },
  );
  const receipt = await db.inspect.sandboxActionReceipt.create({
    data: {
      digestContext: digestContextSnapshot({
        domain: ACTION_DIGEST_DOMAIN,
        hostId: f.host.id,
        hostOwnerId: f.id,
      }),
      userId: f.id,
      authorizingKeyId: key.key.id,
      action: "templates.create",
      hostId: f.host.id,
      resourceId: f.template.templateId,
      templateRevisionId: f.template.id,
      idempotencyKey: randomUUID(),
      requestBodyHash: "opaque-receipt",
      state: "SUCCEEDED",
      ...requestDigestMetadata(),
    },
  });
  const readReceipt = () =>
    app.request(`/v1/operations/${receipt.id}`, {
      headers: { authorization: `Bearer ${key.secret}` },
    });
  expect((await readReceipt()).status).toBe(200);
  await db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
  expect((await readReceipt()).status).toBe(403);
  await db.inspect.sdkKeyRevisionAllowlist.create({
    data: { userId: f.id, sdkKeyId: key.key.id, templateRevisionId: f.template.id },
  });
  expect((await readReceipt()).status).toBe(200);
});

it("3E a logical ID or resourceId fallback never authorizes an exact revision receipt", async () => {
  const f = await fixture();
  const key = await createSdkKey(
    { kind: "session", ownerId: f.id },
    {
      name: "exact",
      scopes: SERVICE_SCOPES.filter(
        // An allowlist key can hold neither webhooks:write (all-owned only) nor
        // credentials:use without an allowlisted login.
        (scope) => scope !== "webhooks:write" && scope !== "credentials:use",
      ),
      resourceMode: "ALLOWLIST",
      hostIds: [f.host.id],
      templateRevisionIds: [f.template.id],
    },
  );
  for (const revisionId of [null, f.template.templateId]) {
    const row = await db.inspect.sandboxActionReceipt.create({
      data: {
        digestContext: digestContextSnapshot({
          domain: ACTION_DIGEST_DOMAIN,
          hostId: f.host.id,
          hostOwnerId: f.id,
        }),

        userId: f.id,
        hostId: f.host.id,
        action: "templates.create",
        authorizingKeyId: key.key.id,
        idempotencyKey: randomUUID(),
        requestBodyHash: "opaque",
        ...requestDigestMetadata(),
        state: "SUCCEEDED",
        resourceId: f.template.id,
        templateRevisionId: revisionId,
      },
    });
    const response = await app.request(`/v1/operations/${row.id}`, {
      headers: { authorization: `Bearer ${key.secret}` },
    });
    expect(response.status).toBe(revisionId === null ? 404 : 403);
  }
});
it("3E an interrupted append keeps a visible logical context and replays UNKNOWN without another verification", async () => {
  const f = await fixture();
  const key = await createSdkKey(
    { kind: "session", ownerId: f.id },
    {
      name: "append",
      scopes: SERVICE_SCOPES.filter(
        // An allowlist key can hold neither webhooks:write (all-owned only) nor
        // credentials:use without an allowlisted login.
        (scope) => scope !== "webhooks:write" && scope !== "credentials:use",
      ),
      resourceMode: "ALLOWLIST",
      hostIds: [f.host.id],
      templateRevisionIds: [f.template.id],
    },
  );
  const verify = vi.fn(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
  bindHostImageVerifier(verify);
  const idempotencyKey = randomUUID();
  const gate = db.pauseAt("append", { before: "sandboxTemplateRevision.create" });
  const pending = db.run("append", () =>
    request(
      f,
      "appendTemplateRevision",
      { hostId: f.host.id, imageRef: "local:base", envs: { APP: "synthetic-append-private" } },
      idempotencyKey,
      key.secret,
    ),
  );
  await gate.waitReached();
  gate.fail(new Error("interrupted append"));
  const response = await pending;
  expect(response.status).toBe(202);
  const accepted = await json(response);
  expect(accepted.state).toBe("UNKNOWN_OUTCOME");
  expect(
    await db.inspect.sandboxActionReceipt.findUniqueOrThrow({
      where: { id: accepted.operationId },
    }),
  ).toMatchObject({
    templateRevisionId: null,
    logicalTemplateId: f.template.templateId,
    resourceId: null,
  });
  const replay = await request(
    f,
    "appendTemplateRevision",
    { hostId: f.host.id, imageRef: "local:base", envs: { APP: "synthetic-append-private" } },
    idempotencyKey,
    key.secret,
  );
  expect(replay.status).toBe(202);
  expect(await json(replay)).toMatchObject({
    operationId: accepted.operationId,
    state: "UNKNOWN_OUTCOME",
  });
  expect(verify).toHaveBeenCalledOnce();
  const read = () =>
    app.request(accepted.location, { headers: { authorization: `Bearer ${key.secret}` } });
  expect((await read()).status).toBe(200);
  await db.inspect.sdkKeyRevisionAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
  expect((await read()).status).toBe(404);
  expect(
    await db.inspect.sandboxTemplateRevision.count({
      where: { templateId: f.template.templateId },
    }),
  ).toBe(1);
  expect(
    JSON.stringify(
      await db.inspect.sandboxActionReceipt.findUniqueOrThrow({
        where: { id: accepted.operationId },
      }),
    ),
  ).not.toContain("synthetic-append-private");
});

it.each(["registerTemplate", "appendTemplateRevision", "associateTemplateAvailability"] as const)(
  "%s stored outcome replays over budget without another charge or receipt",
  async (route) => {
    const f = await fixture();
    const key = randomUUID();
    const body = bodyFor(route, f);
    const accepted = await request(f, route, body, key);
    expect(accepted.status).toBe(202);
    const outcome = await json(accepted);
    expect(outcome).toMatchObject({ state: "SUCCEEDED" });
    const { consumeSandboxWriteBudget } = await import("@wssp/api/sandbox/budgets");
    for (let i = 1; i < 10_000; i++) await consumeSandboxWriteBudget(f.id, "template");
    // Both successful and failed durable outcomes replay, still reauthorizing
    // and checking the digest. Neither re-enters the effect or budget boundary.
    for (const state of ["SUCCEEDED", "FAILED"] as const) {
      await db.inspect.sandboxActionReceipt.updateMany({
        where: { userId: f.id, idempotencyKey: key },
        data: { state },
      });
      const replay = await request(f, route, body, key);
      expect(replay.status).toBe(202);
      expect(await replay.json()).toMatchObject({ ...outcome, state });
    }
    expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.id } })).toBe(1);
    const newWrite = await request(f, route, body, randomUUID());
    expect(newWrite.status).toBe(429);
    expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.id } })).toBe(1);
  },
);

// Real procedure budget, HTTP adapter and disposable PG: a throttle has no effect
// to reconcile. Expiry permits the original idempotency key to be accepted.
it.each(["registerTemplate", "appendTemplateRevision", "associateTemplateAvailability"] as const)(
  "%s budget refusal is 429 with no receipt and the same key succeeds after expiry",
  async (route) => {
    const f = await fixture();
    const { consumeSandboxWriteBudget } = await import("@wssp/api/sandbox/budgets");
    for (let i = 0; i < 10_000; i++) await consumeSandboxWriteBudget(f.id, "template");
    const key = randomUUID();
    const body = bodyFor(route, f);
    const refused = await request(f, route, body, key);
    expect(refused.status).toBe(429);
    expect(await refused.json()).toMatchObject({
      error: {
        code: "TOO_MANY_REQUESTS",
        message: "Request budget exceeded.",
        retryAfterSeconds: 60,
      },
    });
    expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.id } })).toBe(0);
    // Change only wall time; PG and HTTP IO continue on real timers.
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now + 61_000);
    try {
      const accepted = await request(f, route, body, key);
      expect(accepted.status).toBe(202);
      expect(await accepted.json()).toMatchObject({ state: "SUCCEEDED" });
      expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.id } })).toBe(1);
    } finally {
      clock.mockRestore();
    }
  },
);

it("ALL_OWNED template availability hides absent and foreign revisions with the declared 404", async () => {
  const f = await fixture();
  const foreign = await fixture();
  for (const method of ["GET", "POST"]) {
    const refusals = [];
    for (const revisionId of [randomUUID(), foreign.template.id]) {
      const response = await app.request(
        `/v1/templates/${f.template.templateId}/availability${method === "GET" ? `?revisionId=${revisionId}` : ""}`,
        {
          method,
          headers: {
            authorization: `Bearer ${f.key.secret}`,
            "content-type": "application/json",
            "idempotency-key": randomUUID(),
          },
          ...(method === "POST" ? { body: JSON.stringify({ revisionId, hostId: f.host.id }) } : {}),
        },
      );
      expect(response.status).toBe(404);
      const body = (await response.json()) as { error: { code: string; message: string } };
      expect(body.error.code).toBe("sandbox.template_not_found");
      refusals.push({ code: body.error.code, message: body.error.message });
    }
    expect(refusals[0]).toEqual(refusals[1]);
  }
  expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.id } })).toBe(0);
});

it("missing image association records the canonical failed receipt and later create returns the same 409 code", async () => {
  const f = await fixture();
  await db.inspect.sandboxTemplateAvailability.deleteMany({
    where: { revisionId: f.template.id, hostId: f.host.id },
  });
  const verify = vi.fn(async () => {
    throw new HostImageMissing("private-image-diagnostic");
  });
  bindHostImageVerifier(verify);
  const key = randomUUID();
  const association = await request(
    f,
    "associateTemplateAvailability",
    bodyFor("associateTemplateAvailability", f),
    key,
  );
  expect(association.status).toBe(202);
  const receipt = await json(association);
  expect(receipt.state).toBe("FAILED");
  expect(await (await read(f, receipt.location)).json()).toMatchObject({
    state: "FAILED",
    errorCode: "sandbox.template_image_missing",
    outcome: "failed",
  });
  expect(
    await db.inspect.sandboxTemplateAvailability.findUniqueOrThrow({
      where: { revisionId_hostId: { revisionId: f.template.id, hostId: f.host.id } },
    }),
  ).toMatchObject({ status: "MISSING", verifiedConnectionEpoch: f.host.connectionEpoch });
  const create = await request(f, "createSandbox");
  expect(create.status).toBe(409);
  expect(await create.json()).toMatchObject({ error: { code: "sandbox.template_image_missing" } });
  const replay = await request(
    f,
    "associateTemplateAvailability",
    bodyFor("associateTemplateAvailability", f),
    key,
  );
  expect((await json(replay)).operationId).toBe(receipt.operationId);
  expect(verify).toHaveBeenCalledTimes(1);
});

it("empty command name is BAD_REQUEST before receipt or outbox allocation", async () => {
  const f = await fixture();
  const operations = await db.inspect.sandboxOperation.count({ where: { userId: f.id } });
  const events = await db.inspect.outboxEvent.count({ where: { userId: f.id } });
  const response = await request(f, "startCommand", { argv: [""] }, randomUUID());
  expect(response.status).toBe(400);
  expect((await json(response)).error).toMatchObject({ code: "BAD_REQUEST" });
  expect(await db.inspect.sandboxOperation.count({ where: { userId: f.id } })).toBe(operations);
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(events);
});

it.each(["invalid", "unsupported", "full", "unavailable"] as const)(
  "B5 native fresh %s size refusal has no receipt, rows or Location",
  async (condition) => {
    const f = await fixture();
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: {
        daemonMemoryBudgetMiB: condition === "unavailable" ? null : 1536,
        daemonMaxCpuCount: condition === "unavailable" ? null : 1,
        ...(condition === "full" ? { liveCount: 1, memoryReservedMiB: 1024 } : {}),
      },
    });
    if (condition === "full")
      await db.inspect.sandbox.update({
        where: { id: f.sandbox.id },
        data: { liveResourcesHeld: true },
      });
    const where = { userId: f.id };
    const counts = () =>
      Promise.all([
        db.inspect.sandbox.count({ where }),
        db.inspect.sandboxOperation.count({ where }),
        db.inspect.sandboxPlacement.count({ where }),
        db.inspect.sandboxExecutionConfig.count({ where }),
        db.inspect.sandboxActionReceipt.count({ where }),
        db.inspect.outboxEvent.count({ where }),
      ]);
    const before = await counts();
    const response = await request(f, "createSandbox", {
      diskGiB: 32,
      ...bodyFor("createSandbox", f),
      cpuCount: condition === "unsupported" ? 2 : 1,
      memoryMiB: condition === "invalid" ? 513 : 1024,
      envs: { APP: "private-size-sentinel" },
    });
    expect(response.status).toBe(condition === "invalid" ? 400 : 409);
    expect(response.headers.has("Location")).toBe(false);
    const text = await response.text();
    expect(JSON.parse(text)).toMatchObject({
      error: {
        code:
          condition === "invalid"
            ? "sandbox.vm_size_invalid"
            : condition === "unsupported"
              ? "sandbox.vm_size_unsupported"
              : condition === "full"
                ? "sandbox.host_capacity"
                : "sandbox.host_unavailable",
      },
    });
    expect(text).not.toContain("private-size-sentinel");
    expect(await counts()).toEqual(before);
  },
);

it("P2-8: POST /v1/sandboxes/{id}/capture spends the shared image budget (429 once it is exhausted)", async () => {
  const f = await fixture([...SDK_ROUTES.captureSandbox.scopes]);
  const { consumeSandboxWriteBudget } = await import("@wssp/api/sandbox/budgets");
  for (let i = 0; i < 10_000; i++) {
    try {
      await consumeSandboxWriteBudget(f.id, "image");
    } catch {
      break;
    }
  }
  const refused = await request(f, "captureSandbox");
  expect(refused.status).toBe(429);
});

it("captureSandbox: each declared scope is required, and a host without the image cache refuses with capture_unsupported", async () => {
  const required = [...SDK_ROUTES.captureSandbox.scopes];
  expect(required.sort()).toEqual(["sandboxes:write", "templates:write"]);
  const f = await fixture(required);
  const refused = await request(f, "captureSandbox");
  expect(refused.status).toBe(409);
  expect(await json(refused)).toMatchObject({
    error: { code: "sandbox.capture_unsupported", reason: "runtime" },
  });
  for (const missing of required) {
    const denied = await createSdkKey(
      { kind: "session", ownerId: f.id },
      {
        name: "denied",
        scopes: withoutScope(missing),
        resourceMode: "ALL_OWNED",
        hostIds: [],
        templateRevisionIds: [],
      },
    );
    const rejection = await request(f, "captureSandbox", {}, randomUUID(), denied.secret);
    expect(rejection.status, `captureSandbox without ${missing}`).toBe(403);
  }
});

it("a well-formed lease above the 24-day ceiling is lease_exceeds_policy with the maximum, not a generic 400", async () => {
  const f = await fixture();
  const where = { userId: f.id };
  const counts = () =>
    Promise.all([
      db.inspect.sandbox.count({ where }),
      db.inspect.sandboxOperation.count({ where }),
      db.inspect.sandboxActionReceipt.count({ where }),
      db.inspect.outboxEvent.count({ where }),
    ]);
  const before = await counts();
  const over = 2_073_600_001;
  for (const id of ["createSandbox", "reconnectSandbox", "renewSandboxLease"] as const) {
    const response = await request(f, id, { ...bodyFor(id, f), timeoutMs: over });
    expect(response.status, id).toBe(400);
    // The fixture's deployment maximum is the 24 h default, smaller than the ceiling.
    expect((await json(response)).error, id).toMatchObject({
      code: "lease_exceeds_policy",
      maxTimeoutMs: 86_400_000,
    });
    for (const timeoutMs of [1.5, -1]) {
      const malformed = await request(f, id, { ...bodyFor(id, f), timeoutMs });
      expect(malformed.status, id).toBe(400);
      expect((await json(malformed)).error, id).toMatchObject({ code: "BAD_REQUEST" });
    }
  }
  expect(await counts()).toEqual(before);
});

it("PUT /v1/sandboxes/{id} renames with a 200 Sandbox, typed refusals and the write scope", async () => {
  const f = await fixture();
  const put = (body: unknown, secret = f.key.secret, id = f.sandbox.id) =>
    app.request(`/v1/sandboxes/${id}`, {
      method: "PUT",
      headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  const operations = () => db.inspect.sandboxOperation.count({ where: { userId: f.id } });
  const outbox = () => db.inspect.outboxEvent.count({ where: { userId: f.id } });
  const [opsBefore, outboxBefore] = [await operations(), await outbox()];
  const renamed = await put({ name: "nightly-build" });
  const dto = await json(renamed);
  expect(renamed.status, JSON.stringify(dto)).toBe(200);
  expect(SDK_ROUTES.updateSandbox.response.schema.safeParse(dto).success).toBe(true);
  expect(dto).toMatchObject({ id: f.sandbox.id, name: "nightly-build" });
  expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } })).name).toBe(
    "nightly-build",
  );
  // Not an operation: no receipt, operation or outbox row.
  expect([await operations(), await outbox()]).toEqual([opsBefore, outboxBefore]);

  const invalid = await put({ name: "Bad_Name" });
  expect(invalid.status).toBe(400);
  expect((await json(invalid)).error.code).toBe("sandbox.name_invalid");

  await seedSandboxInstance(db.inspect, {
    data: {
      userId: f.id,
      originHostId: f.host.id,
      templateId: f.template.id,
      state: "READY",
      name: "taken-name",
    },
  });
  const taken = await put({ name: "taken-name" });
  expect(taken.status).toBe(409);
  expect((await json(taken)).error.code).toBe("sandbox.name_taken");

  const reader = await createSdkKey(
    { kind: "session", ownerId: f.id },
    {
      name: "reader",
      scopes: withoutScope("sandboxes:write"),
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
    },
  );
  expect((await put({ name: "other-name" }, reader.secret)).status).toBe(403);
  const other = await fixture();
  expect((await put({ name: "other-name" }, other.key.secret)).status).toBe(404);
  expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } })).name).toBe(
    "nightly-build",
  );
});

it("POST /v1/sandboxes stores an explicit name and refuses invalid or taken names", async () => {
  const f = await fixture();
  const create = (name: string) =>
    request(f, "createSandbox", {
      sandboxHostId: f.host.id,
      template: `revision/${f.template.id}`,
      name,
    });
  const accepted = await create("ci-runner");
  expect(accepted.status, JSON.stringify(await json(accepted.clone()))).toBe(202);
  expect(await db.inspect.sandbox.count({ where: { userId: f.id, name: "ci-runner" } })).toBe(1);
  const invalid = await create("wssp-reserved");
  expect(invalid.status).toBe(400);
  expect((await json(invalid)).error.code).toBe("sandbox.name_invalid");
  const taken = await create("ci-runner");
  expect(taken.status).toBe(409);
  expect((await json(taken)).error.code).toBe("sandbox.name_taken");
});
