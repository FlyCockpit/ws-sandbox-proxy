import { vmLiveMemoryChargeMiB } from "@wssp/sandbox-contracts";
import {
  seedAcceptedOperation,
  seedLaunchHost,
  seedMintSession,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { inspect } from "node:util";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, beforeEach, expect, it, vi } from "vitest";
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
    CORS_ORIGIN: "http://localhost:3000",
    RATE_LIMIT_AUTH_POINTS: 10000,
    RATE_LIMIT_AUTH_WINDOW_SECONDS: 60,
    RATE_LIMIT_EMAIL_POINTS: 10000,
    RATE_LIMIT_EMAIL_WINDOW_SECONDS: 60,
    RATE_LIMIT_RPC_POINTS: 10000,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 30_000,
    RATE_LIMIT_SDK_KEY_POINTS: 10_000,
    RATE_LIMIT_SDK_OWNER_POINTS: 30_000,
  },
  ADMIN_EMAILS: new Set<string>(),
  SIGNUP_ENABLED: true,
  resolveAppName: () => "wssp",
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  QUEUE_NAMES: {},
  reapExpiredAuthTokensQueue: {},
  imageStoreMaintenanceQueue: {
    add: vi.fn(),
    upsertJobScheduler: vi.fn(),
    removeJobScheduler: vi.fn(),
  },
  checkBackupFreshnessQueue: {},
  notifyDataDeletionsQueue: {},
}));
vi.mock("@wssp/queue/consumer-health", () => ({ hasExternalConsumer: vi.fn() }));
vi.mock("@wssp/mailer", () => ({ isEmailConfigured: () => false }));
const sessionState = vi.hoisted(() => ({ ownerId: "", rawError: undefined as unknown }));
vi.mock("@wssp/auth", () => ({
  auth: {
    api: {
      getSession: async () => ({
        user: {
          id: sessionState.ownerId,
          role: "user",
          emailVerified: true,
          twoFactorEnabled: true,
        },
        session: { id: `session-${sessionState.ownerId}` },
      }),
    },
    handler: vi.fn(),
  },
}));
vi.mock("@wssp/api/routers/index", async () => ({
  appRouter: {
    sandboxTemplates: (await import("../../../../packages/api/src/routers/sandbox-templates"))
      .sandboxTemplatesRouter,
    sandboxes: (await import("../../../../packages/api/src/routers/sandboxes")).sandboxesRouter,
    rawFailure: (await import("@wssp/api")).protectedProcedure.handler(() => {
      throw sessionState.rawError;
    }),
  },
}));
vi.mock("../ssr-handler.js", () => ({
  loadSsrHandler: async () => ({ fetch: async () => new Response("test") }),
}));
vi.mock("../lifecycle.js", () => ({ withTimeout: (promise: Promise<unknown>) => promise }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.24" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});
const db = await pgTestDatabase();
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { SERVICE_SCOPES } = await import("@wssp/api/lib/service-scopes");
const { bindHostSandboxProbe, bindHostImageVerifier } = await import(
  "../../../../packages/api/src/sandbox/host-image-verifier"
);
const { bindSandboxDispatchWake } = await import("../../../../packages/api/src/sandbox/outbox");
const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
const { createApp } = await import("../app.js");
const { Prisma } = await import("../../../../packages/db/prisma/generated/client");
const FP = `sha256:${"c".repeat(64)}`;
afterAll(() => db.close());
beforeEach(() => {
  bindHostSandboxProbe(async () => "guest_ready");
  bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
  bindSandboxDispatchWake(null);
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});
async function fixture(scopes: readonly (typeof SERVICE_SCOPES)[number][] = SERVICE_SCOPES) {
  const id = `c24-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id, name: "Owner", email: `${id}@example.test`, twoFactorEnabled: true },
  });
  await db.inspect.session.create({
    data: {
      id: `session-${id}`,
      userId: id,
      token: randomUUID(),
      expiresAt: new Date(Date.now() + 3_600_000),
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
    },
  });
  const owner = await seedMintSession(db.inspect, { kind: "session" as const, ownerId: id });
  const key = await createSdkKey(owner, {
    name: "sdk",
    scopes: [...scopes],
    resourceMode: "ALL_OWNED",
    hostIds: [],
    templateRevisionIds: [],
  });
  return { id, host, template, sandbox, operation, key };
}

afterEach(() => vi.restoreAllMocks());
const SENTINEL = "synthetic-env-stdin-producer-3a";
const BASE64 = Buffer.from(SENTINEL).toString("base64");

/** Real PG failures from env/stdin-bearing outbox writes. PostgreSQL and its
 * server logs are inside the operator DB boundary; application sinks are not. */
async function rawDatabaseFailure(
  f: Awaited<ReturnType<typeof fixture>>,
  kind: "23502" | "22P02" | "22P05",
): Promise<Error> {
  const payload =
    kind === "22P02"
      ? `{ "env": ${SENTINEL}`
      : kind === "22P05"
        ? JSON.stringify({ env: SENTINEL, stdinBase64: BASE64, nul: "\u0000" })
        : JSON.stringify({ env: { TOKEN: SENTINEL }, stdinBase64: BASE64 });
  try {
    await db.inspect
      .$executeRaw`INSERT INTO sandbox_dispatch_outbox (id, "userId", "aggregateType", "aggregateId", "eventType", payload) VALUES (${randomUUID()}, ${f.id}, 'sandbox', ${f.sandbox.id}, ${kind === "23502" ? null : "test"}, ${payload}::jsonb)`;
  } catch (error) {
    expect(error).toBeInstanceOf(Error);
    expect(inspect(error, { depth: 20 })).toContain(kind);
    return error as Error;
  }
  throw new Error("Expected PostgreSQL failure");
}

for (const plane of ["v1", "orpc"] as const) {
  for (const fault of ["23502", "22P02", "22P05", "validation", "commit", "rollback"] as const) {
    it(`3A ${plane} ${fault} producer errors discard env/stdin and nested causes`, async () => {
      const f = await fixture();
      sessionState.ownerId = f.id;
      await db.inspect.sandboxHost.update({
        where: { id: f.host.id },
        data: {
          journalKeyVersion: 1,
          journalKeyId: requestDigestMetadata().requestDigestKeyId,
          journalKeyAcknowledgedEpoch: 1,
        },
      });
      const app = await createApp({ isShuttingDown: () => false, isWorkerReady: () => true });
      let raw: Error;
      if (fault === "23502" || fault === "22P02" || fault === "22P05")
        raw = await rawDatabaseFailure(f, fault);
      else if (fault === "validation")
        raw = new Prisma.PrismaClientValidationError(
          `Invalid invocation env=${SENTINEL} stdin=${BASE64}`,
          { clientVersion: "test" },
        );
      else raw = new Error(`${fault}: ${SENTINEL}`, { cause: new Error(BASE64) });
      const point =
        fault === "commit" || fault === "rollback" ? "$transaction.commit" : "outboxEvent.create";
      const gate = db.pauseAt("request", { before: point });
      const key = randomUUID();
      const input = {
        id: f.sandbox.id,
        idempotencyKey: key,
        script: "true",
        envs: { TOKEN: SENTINEL },
        stdinBase64: BASE64,
      };
      const response = db.run("request", async () =>
        plane === "v1"
          ? app.request(`/v1/sandboxes/${f.sandbox.id}/commands`, {
              method: "POST",
              headers: {
                authorization: `Bearer ${f.key.secret}`,
                "content-type": "application/json",
                "idempotency-key": key,
              },
              body: JSON.stringify({
                script: input.script,
                envs: input.envs,
              }),
            })
          : app.request("/rpc/sandboxes/runCommand", {
              method: "POST",
              headers: {
                cookie: "better-auth.session_token=fixture",
                "x-csrf-token": "orpc",
                "content-type": "application/json",
              },
              body: JSON.stringify({ json: input }),
            }),
      );
      await Promise.race([
        gate.waitReached(),
        response.then(async (result) => {
          throw new Error(
            `Request completed before producer: ${result.status} ${await result.clone().text()}`,
          );
        }),
      ]);
      gate.fail(raw);
      const result = await response;
      expect(result.status).toBe(500);
      const body = await result.text();
      expect(body).not.toContain(SENTINEL);
      expect(body).not.toContain(BASE64);
      // This is the real app.ts oRPC logger; it must see only a safe code.
      if (plane === "orpc")
        expect(console.error).toHaveBeenCalledWith("[orpc] Request failed", {
          code: "INTERNAL_SERVER_ERROR",
          errorClass: "ORPCError",
        });
      const logs = inspect(
        [vi.mocked(console.error).mock.calls, vi.mocked(console.warn).mock.calls],
        { depth: 30 },
      );
      expect(logs).not.toContain(SENTINEL);
      expect(logs).not.toContain(BASE64);
      expect(
        await db.inspect.sandboxOperation.count({
          where: {
            NOT: { idempotencyKey: { startsWith: "fixture-boot:" } },
            userId: f.id,
            idempotencyKey: key,
          },
        }),
      ).toBe(0);
      expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(0);
    });
  }
}

it("3A env/stdin outbox tables have no CHECK constraints", async () => {
  const rows = await db.inspect.$queryRaw<
    { name: string }[]
  >`SELECT conname AS name FROM pg_constraint WHERE contype = 'c' AND conrelid IN (SELECT oid FROM pg_class WHERE relname IN ('sandbox_dispatch_outbox', 'sandbox_dispatch_outbox'))`;
  expect(rows).toEqual([]);
});

it.each(["v1", "orpc"] as const)(
  "3A %s stdin producer wraps the entire outbox transaction",
  async (plane) => {
    const f = await fixture();
    sessionState.ownerId = f.id;
    const app = await createApp({ isShuttingDown: () => false, isWorkerReady: () => true });
    const raw = new Prisma.PrismaClientValidationError(`Invalid stdin invocation ${BASE64}`, {
      clientVersion: "test",
    });
    const gate = db.pauseAt("stdin", { before: "outboxEvent.create" });
    const input = { operationId: f.operation.id, contentBase64: BASE64, eof: true };
    const request = db.run("stdin", async () =>
      plane === "v1"
        ? app.request(`/v1/operations/${f.operation.id}/stdin`, {
            method: "POST",
            headers: {
              authorization: `Bearer ${f.key.secret}`,
              "content-type": "application/json",
              "idempotency-key": randomUUID(),
            },
            body: JSON.stringify({ contentBase64: BASE64, eof: true }),
          })
        : app.request("/rpc/sandboxes/writeStdin", {
            method: "POST",
            headers: {
              cookie: "better-auth.session_token=fixture",
              "x-csrf-token": "orpc",
              "content-type": "application/json",
            },
            body: JSON.stringify({ json: input }),
          }),
    );
    await Promise.race([
      gate.waitReached(),
      request.then(async (r) => {
        throw new Error(`Early stdin response: ${r.status} ${await r.clone().text()}`);
      }),
    ]);
    gate.fail(raw);
    const result = await request;
    expect(result.status).toBe(500);
    const body = await result.text();
    expect(body).not.toContain(BASE64);
    expect(inspect(vi.mocked(console.error).mock.calls, { depth: 30 })).not.toContain(BASE64);
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }))
        .nextStdinSequence,
    ).toBe(0);
    expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(0);
    expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.id } })).toBe(0);
  },
);

it("3A host receipt errors are constants in operation/sandbox rows and public errorMessage", async () => {
  const f = await fixture();
  const { applyOperationResult } = await import("../sandbox-relay/operation-handlers.js");
  const { getOperationView } = await import(
    "../../../../packages/api/src/sandbox/services/operation-views"
  );
  await db.inspect.sandboxOperation.update({
    where: { id: f.operation.id },
    data: { kind: "CREATE_SANDBOX", dispatchedConnectionEpoch: 1, state: "DISPATCHED" },
  });
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: { state: "PROVISIONING", liveResourcesHeld: true },
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { liveCount: 1, memoryReservedMiB: vmLiveMemoryChargeMiB(1024), vcpuReserved: 1 },
  });
  expect(
    await applyOperationResult({
      sender: { userId: f.id, hostId: f.host.id, connectionEpoch: 1 },
      operationId: f.operation.id,
      sandboxId: f.sandbox.id,
      generation: 1,
      attempt: 1,
      state: "failed",
      error: { code: "guest_operation_failed", message: `${SENTINEL} ${BASE64}` },
    }),
  ).toEqual({ written: true });
  const row = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: f.operation.id },
  });
  const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } });
  expect(row.errorDetail).toBe("Guest operation failed.");
  expect(sandbox.lastErrorDetail).toBe("Guest operation failed.");
  const view = await getOperationView(
    { kind: "session", ownerId: f.id },
    { operationId: f.operation.id },
  );
  expect(view.errorMessage).toBe("Guest operation failed.");
  expect(inspect([row, sandbox, view], { depth: 10 })).not.toContain(SENTINEL);
  expect(inspect([row, sandbox, view], { depth: 10 })).not.toContain(BASE64);
});

it("3A actual oRPC logger backstop strips a bypassed raw producer", async () => {
  const f = await fixture();
  sessionState.ownerId = f.id;
  sessionState.rawError = new Prisma.PrismaClientValidationError(`${SENTINEL} ${BASE64}`, {
    clientVersion: "test",
  });
  const app = await createApp({ isShuttingDown: () => false, isWorkerReady: () => true });
  const result = await app.request("/rpc/rawFailure", {
    method: "POST",
    headers: {
      cookie: "better-auth.session_token=fixture",
      "x-csrf-token": "orpc",
      "content-type": "application/json",
    },
    body: JSON.stringify({ json: null }),
  });
  expect(result.status).toBe(500);
  expect(await result.text()).not.toContain(SENTINEL);
  expect(console.error).toHaveBeenCalledWith("[orpc] Request failed", {
    code: "unhandled_error",
    errorClass: "PrismaClientValidationError",
  });
  const logs = inspect(vi.mocked(console.error).mock.calls, { depth: 30 });
  expect(logs).not.toContain(SENTINEL);
  expect(logs).not.toContain(BASE64);
});

it.each(["v1", "orpc"] as const)(
  "3A %s fresh P2002 recovery producer drops raw validation sources",
  async (plane) => {
    const f = await fixture();
    sessionState.ownerId = f.id;
    const { runCommandInput } = await import("@wssp/api/sandbox/contracts");
    const { hashRequestBody } = await import("@wssp/api/sandbox/idempotency");
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: {
        journalKeyVersion: 1,
        journalKeyId: requestDigestMetadata().requestDigestKeyId,
        journalKeyAcknowledgedEpoch: 1,
      },
    });
    const app = await createApp({ isShuttingDown: () => false, isWorkerReady: () => true });
    const key = randomUUID();
    const body = { script: "true", envs: { TOKEN: SENTINEL } };
    const input = runCommandInput.parse({ ...body, id: f.sandbox.id, idempotencyKey: key });
    const insert = db.pauseAt("recovery", { before: "sandboxOperation.create" });
    const response = db.run("recovery", async () =>
      plane === "v1"
        ? app.request(`/v1/sandboxes/${f.sandbox.id}/commands`, {
            method: "POST",
            headers: {
              authorization: `Bearer ${f.key.secret}`,
              "content-type": "application/json",
              "idempotency-key": key,
            },
            body: JSON.stringify(body),
          })
        : app.request("/rpc/sandboxes/runCommand", {
            method: "POST",
            headers: {
              cookie: "better-auth.session_token=fixture",
              "x-csrf-token": "orpc",
              "content-type": "application/json",
            },
            body: JSON.stringify({ json: input }),
          }),
    );
    await insert.waitReached();
    await seedAcceptedOperation(db.inspect, {
      data: {
        userId: f.id,
        sandboxId: f.sandbox.id,
        generation: 1,
        kind: "RUN_COMMAND",
        idempotencyKey: key,
        requestBodyHash: hashRequestBody(input),
        ...requestDigestMetadata(),
      },
    });
    const recovery = db.pauseAt("recovery", { before: /^sql:SELECT id FROM "user".*FOR SHARE$/ });
    insert.release();
    await recovery.waitReached();
    const lookup = db.pauseAt("recovery", { before: "sandboxOperation.findFirst" });
    recovery.release();
    await lookup.waitReached();
    lookup.fail(
      new Prisma.PrismaClientValidationError(`recovery ${SENTINEL} ${BASE64}`, {
        clientVersion: "test",
      }),
    );
    const result = await response;
    expect(result.status).toBe(500);
    const captured = inspect(
      [
        await result.text(),
        vi.mocked(console.error).mock.calls,
        vi.mocked(console.warn).mock.calls,
      ],
      { depth: 30 },
    );
    expect(captured).not.toContain(SENTINEL);
    expect(captured).not.toContain(BASE64);
    expect(await db.inspect.outboxEvent.count({ where: { userId: f.id } })).toBe(0);
  },
);

it("3A direct command producer discards raw errors before caller/logger boundaries", async () => {
  const f = await fixture();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: {
      journalKeyVersion: 1,
      journalKeyId: requestDigestMetadata().requestDigestKeyId,
      journalKeyAcknowledgedEpoch: 1,
    },
  });
  const { runCommand } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
  const { ORPCError } = await import("@orpc/server");
  const gate = db.pauseAt("producer", { before: "outboxEvent.create" });
  const failure = db
    .run("producer", () =>
      runCommand(
        { kind: "session", ownerId: f.id },
        {
          id: f.sandbox.id,
          idempotencyKey: randomUUID(),
          script: "true",
          timeoutMs: 5000,
          envs: { TOKEN: SENTINEL },
          stdinBase64: BASE64,
        },
      ),
    )
    .catch((error: unknown) => error);
  await gate.waitReached();
  gate.fail(
    new Prisma.PrismaClientValidationError(`${SENTINEL} ${BASE64}`, { clientVersion: "test" }),
  );
  const error = await failure;
  expect(error).toBeInstanceOf(ORPCError);
  expect(inspect(error, { depth: 30 })).not.toContain(SENTINEL);
  expect(inspect(error, { depth: 30 })).not.toContain(BASE64);
});

for (const plane of ["v1", "orpc"] as const) {
  for (const fault of [
    "23514",
    "23502",
    "22P02",
    "22P05",
    "validation",
    "commit",
    "rollback",
  ] as const) {
    it(`3D ${plane} private config ${fault} producer strips values and rollback details`, async () => {
      const f = await fixture();
      sessionState.ownerId = f.id;
      await db.inspect.sandboxHost.update({
        where: { id: f.host.id },
        data: {
          journalKeyVersion: 1,
          journalKeyId: requestDigestMetadata().requestDigestKeyId,
          journalKeyAcknowledgedEpoch: 1,
        },
      });
      let raw: Error = new Prisma.PrismaClientValidationError(`config ${SENTINEL} ${BASE64}`, {
        clientVersion: "test",
      });
      if (fault === "23514" || fault === "23502" || fault === "22P02" || fault === "22P05") {
        const payload =
          fault === "22P02"
            ? `{"APP":${SENTINEL}`
            : JSON.stringify({ APP: SENTINEL, ...(fault === "22P05" ? { nul: "\u0000" } : {}) });
        try {
          if (fault === "23514") {
            await db.inspect
              .$executeRaw`UPDATE sandbox_template_revision SET revision = 0, "guestHome" = ${SENTINEL} WHERE id = ${f.template.id}`;
          } else
            await db.inspect
              .$executeRaw`INSERT INTO sandbox_execution_config (id, "userId", "sandboxId", generation, "hostId", "templateDefaults", "sandboxOverrides", "mergedDefaults", "bindingScheme", "bindingKeyId", "bindingMac", "createdAt") VALUES (${randomUUID()}, ${f.id}, ${f.sandbox.id}, 1, ${f.host.id}, '{}'::jsonb, ${payload}::jsonb, ${payload}::jsonb, ${fault === "23502" ? null : "hmac-sha256-v1"}, 'key', 'mac', CURRENT_TIMESTAMP)`;
          throw new Error("expected database refusal");
        } catch (error) {
          expect(inspect(error, { depth: 20 })).toContain(fault);
          expect(error).toBeInstanceOf(Error);
          raw = error as Error;
        }
      } else if (fault === "commit" || fault === "rollback")
        raw = new Error(`${fault} ${SENTINEL}`, { cause: new Error(BASE64) });
      const app = await createApp({ isShuttingDown: () => false, isWorkerReady: () => true });
      const gate = db.pauseAt("config-create", {
        before:
          fault === "commit" || fault === "rollback"
            ? "$transaction.commit"
            : "sandboxExecutionConfig.create",
      });
      const key = randomUUID();
      const input = {
        template: "revision/" + f.template.id,
        sandboxHostId: f.host.id,
        envs: { APP: SENTINEL },
        idempotencyKey: key,
      };
      const response = db.run("config-create", async () =>
        plane === "v1"
          ? app.request("/v1/sandboxes", {
              method: "POST",
              headers: {
                authorization: `Bearer ${f.key.secret}`,
                "content-type": "application/json",
                "idempotency-key": key,
              },
              body: JSON.stringify({
                template: "revision/" + input.template.slice("revision/".length),
                sandboxHostId: input.sandboxHostId,
                envs: input.envs,
              }),
            })
          : app.request("/rpc/sandboxes/createSandbox", {
              method: "POST",
              headers: {
                cookie: "better-auth.session_token=fixture",
                "x-csrf-token": "orpc",
                "content-type": "application/json",
              },
              body: JSON.stringify({ json: input }),
            }),
      );
      await Promise.race([
        gate.waitReached(),
        response.then(async (r) => {
          throw new Error(`completed before config producer: ${r.status}`);
        }),
      ]);
      gate.fail(raw);
      const result = await response;
      expect(result.status).toBe(500);
      for (const value of [
        await result.text(),
        inspect([vi.mocked(console.error).mock.calls, vi.mocked(console.warn).mock.calls], {
          depth: 30,
        }),
      ]) {
        expect(value).not.toContain(SENTINEL);
        expect(value).not.toContain(BASE64);
      }
      expect(await db.inspect.sandboxExecutionConfig.count({ where: { userId: f.id } })).toBe(1);
      expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(1);
      expect(
        (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
      ).toBe(0);
    });
  }
}

for (const plane of ["v1", "orpc"] as const) {
  for (const fault of ["23502", "22P02", "22P05", "validation", "commit", "rollback"] as const) {
    it(`3E ${plane} revision defaults ${fault} producer strips values and rolls back registration`, async () => {
      const f = await fixture();
      sessionState.ownerId = f.id;
      const verifier = vi.fn(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
      bindHostImageVerifier(verifier);
      let raw: Error = new Prisma.PrismaClientValidationError(
        `revision config ${SENTINEL} ${BASE64}`,
        { clientVersion: "test" },
      );
      if (fault === "23502" || fault === "22P02" || fault === "22P05") {
        const payload =
          fault === "22P02"
            ? `{"APP":${SENTINEL}`
            : JSON.stringify({ APP: SENTINEL, ...(fault === "22P05" ? { nul: "\u0000" } : {}) });
        try {
          await db.inspect
            .$executeRaw`INSERT INTO sandbox_revision_config (id, "userId", "revisionId", "defaultEnvs", checksum, "digestScheme", "digestKeyId") VALUES (${randomUUID()}, ${f.id}, ${f.template.id}, ${payload}::jsonb, ${fault === "23502" ? null : "checksum"}, 'hmac-sha256-v1', 'key')`;
          throw new Error("expected database refusal");
        } catch (error) {
          expect(inspect(error, { depth: 20 })).toContain(fault);
          expect(error).toBeInstanceOf(Error);
          raw = error as Error;
        }
      } else if (fault === "commit" || fault === "rollback")
        raw = new Error(`${fault} ${SENTINEL}`, { cause: new Error(BASE64) });
      const app = await createApp({ isShuttingDown: () => false, isWorkerReady: () => true });
      const afterInsert = fault === "commit" || fault === "rollback";
      const gate = db.pauseAt(
        "revision-create",
        afterInsert
          ? { after: "sandboxRevisionConfig.create" }
          : { before: "sandboxRevisionConfig.create" },
      );
      const key = randomUUID();
      const input = {
        hostId: f.host.id,
        slug: "new-private",
        label: "Private",
        imageRef: "local:base",
        envs: { APP: SENTINEL },
      };
      const invoke = async () =>
        plane === "v1"
          ? app.request("/v1/templates", {
              method: "POST",
              headers: {
                authorization: `Bearer ${f.key.secret}`,
                "content-type": "application/json",
                "idempotency-key": key,
              },
              body: JSON.stringify(input),
            })
          : app.request("/rpc/sandboxTemplates/createTemplate", {
              method: "POST",
              headers: {
                cookie: "better-auth.session_token=fixture",
                "x-csrf-token": "orpc",
                "content-type": "application/json",
              },
              body: JSON.stringify({ json: input }),
            });
      const response = db.run("revision-create", invoke);
      await Promise.race([
        gate.waitReached(),
        response.then((r) => {
          throw new Error(`completed before revision producer: ${r.status}`);
        }),
      ]);
      if (afterInsert) {
        const commit = db.pauseAt("revision-create", { before: "$transaction.commit" });
        gate.release();
        await commit.waitReached();
        commit.fail(raw);
      } else gate.fail(raw);
      const result = await response;
      expect(result.status).toBe(plane === "v1" ? 202 : 500);
      const text = await result.text();
      for (const value of [
        text,
        inspect([vi.mocked(console.error).mock.calls, vi.mocked(console.warn).mock.calls], {
          depth: 30,
        }),
      ]) {
        expect(value).not.toContain(SENTINEL);
        expect(value).not.toContain(BASE64);
      }
      if (plane === "v1") {
        expect(JSON.parse(text)).toMatchObject({ state: "UNKNOWN_OUTCOME" });
        const replay = await invoke();
        expect(replay.status).toBe(202);
        expect(await replay.json()).toMatchObject({ state: "UNKNOWN_OUTCOME" });
        expect(verifier).toHaveBeenCalledOnce();
      }
      for (const count of [
        db.inspect.sandboxTemplate.count({ where: { userId: f.id } }),
        db.inspect.sandboxTemplateRevision.count({ where: { userId: f.id } }),
        db.inspect.sandboxRevisionConfig.count({ where: { userId: f.id } }),
        db.inspect.sandboxTemplateTag.count({ where: { userId: f.id } }),
        db.inspect.sandboxTemplateAvailability.count({ where: { userId: f.id } }),
      ])
        expect(await count).toBe(1);
    });
  }
}

it("B5 a single HTTP RPC batch charges each stdin procedure; same-key batch replay is free", async () => {
  const f = await fixture();
  sessionState.ownerId = f.id;
  const app = await createApp({ isShuttingDown: () => false, isWorkerReady: () => true });
  const budgets = await import("@wssp/api/sandbox/budgets");
  const charged = vi.spyOn(budgets, "consumeSandboxWriteBudget");
  const batch = Array.from({ length: 3 }, () => ({
    method: "POST",
    url: "http://localhost/rpc/sandboxes/writeStdin",
    body: {
      json: {
        operationId: f.operation.id,
        idempotencyKey: randomUUID(),
        contentBase64: Buffer.from("line").toString("base64"),
      },
    },
  }));
  const send = () =>
    app.request("/rpc/sandboxes/__batch__", {
      method: "POST",
      headers: {
        cookie: "better-auth.session_token=fixture",
        "x-csrf-token": "orpc",
        "content-type": "application/json",
        "x-orpc-batch": "buffered",
      },
      body: JSON.stringify(batch),
    });
  for (let replay = 0; replay < 2; replay++) {
    const response = await send();
    expect(response.status).toBe(207);
    expect(await response.json()).toMatchObject([
      { status: 200 },
      { status: 200 },
      { status: 200 },
    ]);
    expect(charged.mock.calls).toEqual(Array.from({ length: 3 }, () => [f.id, "stdin"]));
    expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.id } })).toBe(3);
    expect(
      await db.inspect.outboxEvent.count({
        where: { userId: f.id, eventType: "sandbox.stdin_requested" },
      }),
    ).toBe(3);
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }))
        .nextStdinSequence,
    ).toBe(3);
  }
});
