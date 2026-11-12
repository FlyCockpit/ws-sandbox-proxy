import { randomUUID } from "node:crypto";
import { withAuthorityChange } from "@wssp/db/authority";
import { credentialLookupPrefix } from "@wssp/db/credential-security";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import {
  capabilitiesSchema,
  mutationReceiptSchema,
  operationResultSchema,
  operationSchema,
  processConnectionSchema,
  sandboxCapabilitiesSchema,
  sdkErrorEnvelopeSchema,
} from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import {
  seedAcceptedOperation,
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "ab".repeat(32),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "b6-test",
    RATE_LIMIT_RPC_POINTS: 100,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 300,
    RATE_LIMIT_SDK_KEY_POINTS: 100,
    RATE_LIMIT_SDK_OWNER_POINTS: 300,
    SANDBOX_MAX_TIMEOUT_MS: 86400000,
    TRANSFER_MAX_BYTES: 1_073_741_824,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.17" } }),
}));
const charged = vi.hoisted(() => vi.fn(async () => {}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: vi.fn(),
  consumeSandboxWriteBudget: charged,
}));
const zeroPolicy = vi.hoisted(() => ({ enabled: false }));
vi.mock("../../../../packages/sandbox-contracts/src/command-timeout-policy", () => ({
  get commandTimeoutZeroEnabled() {
    return zeroPolicy.enabled;
  },
}));
const db = await pgTestDatabase();
const access = await import("@wssp/api/lib/sdk-key-access");
const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
const { createSandboxApi } = await import("./middleware");
const { connectProcess } = await import("@wssp/api/sandbox/process-connect");
afterAll(() => db.close());
afterEach(() => {
  zeroPolicy.enabled = false;
  charged.mockClear();
  vi.restoreAllMocks();
});

async function seed() {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: {
      id: userId,
      email: `${userId}@example.test`,
      name: "Owner",
      twoFactorEnabled: true,
      createdAt: new Date("2020-01-01"),
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId, slug: "lab", label: "Lab", status: "CONNECTED", connectionEpoch: 1 },
  });
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: {
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 1,
      admissionEpoch: 1,
      admissionRuntime: "FAKE",
      journalKeyVersion: 1,
      journalKeyId: requestDigestMetadata().requestDigestKeyId,
      journalKeyAcknowledgedEpoch: 1,
    },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId,
      templateId: revision.id,
      sandboxHostId: host.id,
      originHostId: host.id,
      state: "READY",
    },
  });
  const startedAt = new Date();
  const command = await seedAcceptedOperation(db.inspect, {
    data: {
      userId,
      sandboxId: sandbox.id,
      generation: 1,
      kind: "RUN_COMMAND",
      state: "RUNNING",
      dispatchAttempt: 1,
      dispatchedHostId: host.id,
      dispatchedConnectionEpoch: 1,
      resultVersion: 1,
      processId: randomUUID(),
      processPid: 42,
      processBootId: randomUUID(),
      processStartTicks: "123",
      processStartedAt: startedAt,
      processDescription: { cmd: "sh", args: [], argsTruncated: false, cwd: "/" },
      resultObservedAt: startedAt,
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      ...requestDigestMetadata(),
    },
  });
  const process = {
    sandboxId: sandbox.id,
    generation: 1,
    processId: command.processId!,
    attempt: 1,
    pid: 42,
  };
  const key = access.generateSdkKeySecret();
  const sdkKey = await db.inspect.sdkKey.create({
    data: {
      userId,
      name: "B6",
      resourceMode: "ALL_OWNED",
      scopes: [
        "sandboxes:read",
        "commands:read",
        "commands:execute",
        "operations:read",
        "operations:cancel",
        "files:read",
        "files:write",
      ],
      lookupPrefix: credentialLookupPrefix(key),
      secretDigest: access.digestSdkKeySecret(key.raw),
    },
  });
  const app = new Hono().route("/v1", createSandboxApi());
  const request = (path: string, body?: unknown, idempotencyKey = randomUUID()) =>
    app.request(`/v1${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        authorization: `Bearer ${key.raw}`,
        ...(body === undefined
          ? {}
          : { "content-type": "application/json", "idempotency-key": idempotencyKey }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  const base = `/sandboxes/${sandbox.id}/processes/42`;
  const qualifiers = { generation: 1, processId: process.processId, attempt: 1 };
  return {
    userId,
    host,
    revision,
    sandbox,
    command,
    process,
    sdkKey,
    request,
    base,
    qualifiers,
    owner: { kind: "session" as const, ownerId: userId },
  };
}
async function error(response: Response, status: number, code: string) {
  expect(response.status, await response.clone().text()).toBe(status);
  expect(sdkErrorEnvelopeSchema.parse(await response.json()).error.code).toBe(code);
}

it("SIGKILL through the signal route aliases the canonical kill receipt", async () => {
  const f = await seed();
  // Both aliases share the original canonical cancel receipt and send only once.
  const key = randomUUID();
  const killed = await f.request(`${f.base}/signal`, { ...f.qualifiers, signal: "SIGKILL" }, key);
  expect(killed.status).toBe(202);
  const receipt = mutationReceiptSchema.parse(await killed.json());
  expect(await (await f.request(`${f.base}/kill`, f.qualifiers, key)).json()).toEqual(receipt);
  expect(
    await db.inspect.sandboxActionReceipt.findUnique({ where: { id: receipt.operationId } }),
  ).toMatchObject({
    action: "operations.cancel",
    targetOperationId: f.command.id,
    authorizingKeyId: f.sdkKey.id,
  });
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: f.userId, eventType: "sandbox.operation_cancel_requested" },
    }),
  ).toBe(1);
});

it("advertises non-kill signals and binds a signal to the exact owned command", async () => {
  const f = await seed();
  const capabilities = sandboxCapabilitiesSchema.parse(
    await (await f.request(`/sandboxes/${f.sandbox.id}/capabilities`)).json(),
  );
  expect(capabilities.guestApi.supportedSignals).toEqual([
    "SIGTERM",
    "SIGINT",
    "SIGHUP",
    "SIGKILL",
  ]);
  expect(capabilities.features).toContain("processes.signal");
  // A guest the host observed without group signals (kernel < 6.9) lists only
  // SIGKILL; a positive observation lists all four. Calls still check.
  const signalsWith = async (guestGroupSignals: boolean | null) => {
    await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { guestGroupSignals } });
    return sandboxCapabilitiesSchema.parse(
      await (await f.request(`/sandboxes/${f.sandbox.id}/capabilities`)).json(),
    ).guestApi.supportedSignals;
  };
  expect(await signalsWith(false)).toEqual(["SIGKILL"]);
  expect(await signalsWith(true)).toEqual(["SIGTERM", "SIGINT", "SIGHUP", "SIGKILL"]);
  await signalsWith(null);
  const accepted = await f.request(`${f.base}/signal`, { ...f.qualifiers, signal: "SIGTERM" });
  expect(accepted.status).toBe(202);
  const receipt = mutationReceiptSchema.parse(await accepted.json());
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { userId: f.userId, eventType: "sandbox.process_signal_requested" },
  });
  expect(event.payload).toMatchObject({
    operationId: receipt.operationId,
    targetOperationId: f.command.id,
    process: f.process,
  });
  // A supported interface does not promise the guest primitive. Its precise refusal survives status/result.
  await db.inspect.sandboxOperation.update({
    where: { id: receipt.operationId },
    data: {
      state: "FAILED",
      errorCode: "signal_unsupported_on_guest",
      failure: { resource: "process", effect: "none" },
    },
  });
  const status = await (await f.request(`/operations/${receipt.operationId}`)).json();
  expect(status).toMatchObject({
    errorCode: "signal_unsupported_on_guest",
    failure: { resource: "process", effect: "none" },
  });
  expect(
    operationResultSchema.parse(
      await (await f.request(`/operations/${receipt.operationId}/result`)).json(),
    ),
  ).toMatchObject({ result: null, outcome: "failed" });
});

it("connect is one authorized identity/attempt/output snapshot, preserves terminal history offline, and creates no work", async () => {
  const f = await seed();
  await db.inspect.sandboxCommandOutput.create({
    data: { id: f.command.id, attempt: 1, receivedEnd: 17n },
  });
  const path = `${f.base}?generation=1&processId=${f.process.processId}&attempt=1`;
  const result = await f.request(path);
  expect(result.status).toBe(200);
  const body = processConnectionSchema.parse(await result.json());
  expect(body).toMatchObject({
    info: { process: f.process, cmd: "sh", args: [] },
    attachmentCursor: "1_17",
    attempt: 1,
    outputOperationId: f.command.id,
  });
  expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.userId } })).toBe(0);
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: f.userId, eventType: { startsWith: "sandbox.process_" } },
    }),
  ).toBe(0);
  await db.inspect.sandboxOperation.update({
    where: { id: f.command.id },
    data: { resultObservedAt: null },
  });
  expect(processConnectionSchema.parse(await (await f.request(path)).json()).info.observedAt).toBe(
    f.command.processStartedAt!.toISOString(),
  );
  await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { state: "UNREACHABLE" } });
  await error(await f.request(path), 409, "sandbox.process_unavailable");
  await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { state: "READY" } });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { status: "DISCONNECTED", connectionEpoch: 2 },
  });
  await error(await f.request(path), 409, "sandbox.process_unknown_outcome");
  await db.inspect.sandboxOperation.update({
    where: { id: f.command.id },
    data: {
      state: "SUCCEEDED",
      completedAt: new Date(),
      scalarResult: {
        type: "command",
        process: f.process,
        startedAt: f.command.processStartedAt!.toISOString(),
        exitCode: 7,
      },
    },
  });
  expect(await (await f.request(path)).json()).toMatchObject({
    state: "SUCCEEDED",
    exitCode: 7,
    attachmentCursor: "1_17",
  });
  await db.inspect.sandboxOperation.update({
    where: { id: f.command.id },
    data: { completedAt: new Date(Date.now() - 86400001) },
  });
  await error(await f.request(path), 410, "OUTPUT_EXPIRED");
});

it("connect serializes with output writers: no mixed attempt/watermark", async () => {
  const f = await seed();
  const pause = db.pauseAt("connect", {
    after: /sql:SELECT id FROM sandbox_mutation_operation .*FOR UPDATE/,
  });
  const read = db.run("connect", () => connectProcess(f.owner, { process: f.process }));
  await pause.waitReached();
  const write = db.run("output", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id=${f.command.id} FOR UPDATE`;
      await tx.sandboxCommandOutput.create({
        data: { id: f.command.id, attempt: 1, receivedEnd: 29n },
      });
    }),
  );
  await db.waitUntilBlocked("output");
  pause.release();
  expect(await read).toMatchObject({ attachmentCursor: "1_0", attempt: 1 });
  await write;
  expect(await connectProcess(f.owner, { process: f.process })).toMatchObject({
    attachmentCursor: "1_29",
  });
});

it("kind scope precedes content and expiry; legacy unsupported differs from versioned expiry; generic status is private-field free", async () => {
  const f = await seed();
  const op = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.userId,
      sandboxId: f.sandbox.id,
      generation: 1,
      kind: "STAT_PATH",
      state: "FAILED",
      errorCode: "fs_not_found",
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
    },
  });
  await error(await f.request(`/operations/${op.id}/result`), 400, "OPERATION_RESULT_UNSUPPORTED");
  await db.inspect.sandboxOperation.update({
    where: { id: op.id },
    data: { resultVersion: 1, resultExpiresAt: new Date(0) },
  });
  await error(await f.request(`/operations/${op.id}/result`), 410, "OPERATION_RESULT_EXPIRED");
  await db.inspect.sdkKey.update({
    where: { id: f.sdkKey.id },
    data: { scopes: ["operations:read"] },
  });
  await error(await f.request(`/operations/${op.id}/result`), 403, "FORBIDDEN");
  const status = operationSchema.parse(
    await (await f.request(`/operations/${f.command.id}`)).json(),
  );
  expect(Object.keys(status).sort()).toEqual(
    [
      "id",
      "sandboxId",
      "kind",
      "state",
      "outcome",
      "generation",
      "leaseIntent",
      "failure",
      "errorCode",
      "createdAt",
      "updatedAt",
      "dispatchedAt",
      "completedAt",
    ].sort(),
  );
  expect(JSON.stringify(status)).not.toContain(f.process.processId);
  await error(
    await f.request(`${f.base}?generation=1&processId=${f.process.processId}&attempt=1`),
    403,
    "FORBIDDEN",
  );
});

it("new controls and reads authorize the caller before disclosing qualifier/target state", async () => {
  const f = await seed();
  await db.inspect.sdkKey.update({
    where: { id: f.sdkKey.id },
    data: { scopes: ["sandboxes:read"] },
  });
  const wrong = { ...f.qualifiers, attempt: 2 };
  await error(
    await f.request(`${f.base}/signal`, { ...wrong, signal: "SIGTERM" }),
    403,
    "FORBIDDEN",
  );
  await error(await f.request(`${f.base}/kill`, wrong), 403, "FORBIDDEN");
  await error(
    await f.request(`${f.base}/stdin`, {
      ...wrong,
      contentBase64: Buffer.from("x").toString("base64"),
    }),
    403,
    "FORBIDDEN",
  );
  await error(
    await f.request(`${f.base}?generation=1&processId=${f.process.processId}&attempt=2`),
    403,
    "FORBIDDEN",
  );
  await db.inspect.sdkKey.update({
    where: { id: f.sdkKey.id },
    data: { scopes: ["commands:read"] },
  });
  await error(
    await f.request(`${f.base}?generation=1&processId=${f.process.processId}&attempt=2`),
    404,
    "sandbox.process_not_found",
  );
  expect(
    (await f.request(`${f.base}?generation=1&processId=${f.process.processId}&attempt=1`)).status,
  ).toBe(200);
  const foreign = await seed();
  await error(
    await f.request(
      `${foreign.base}?generation=1&processId=${foreign.process.processId}&attempt=1`,
    ),
    404,
    "sandbox.process_not_found",
  );
});

it("native required-start and rich files refuse every older negotiated host before durable admission", async () => {
  const f = await seed();
  const count = await db.inspect.sandboxOperation.count({ where: { userId: f.userId } });
  const outbox = await db.inspect.outboxEvent.count({ where: { userId: f.userId } });
  for (const version of ["10.0", "10.4", "10.5", "10.6", "10.7"]) {
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { relayProtocolVersion: version },
    });
    await error(
      await f.request(`/sandboxes/${f.sandbox.id}/commands`, {
        argv: ["true"],
        startEvidence: "required",
      }),
      400,
      "UNSUPPORTED_CAPABILITY",
    );
    await error(
      await f.request(`/sandboxes/${f.sandbox.id}/files/stat`, { path: "/" }),
      400,
      "UNSUPPORTED_CAPABILITY",
    );
  }
  expect(await db.inspect.sandboxOperation.count({ where: { userId: f.userId } })).toBe(count);
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.userId } })).toBe(outbox);
  expect(await db.inspect.sandboxOperationResult.count({ where: { userId: f.userId } })).toBe(0);
  await error(
    await f.request(`/sandboxes/${f.sandbox.id}/commands`, { argv: ["true"] }),
    400,
    "UNSUPPORTED_CAPABILITY",
  );
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { relayProtocolVersion: "1.0" },
  });
  const modern = await f.request(`/sandboxes/${f.sandbox.id}/commands`, {
    argv: ["true"],
    startEvidence: "required",
  });
  expect(modern.status).toBe(202);
  const modernReceipt = mutationReceiptSchema.parse(await modern.json());
  expect(
    await db.inspect.sandboxOperation.findUnique({ where: { id: modernReceipt.operationId } }),
  ).toMatchObject({ resultVersion: 1, processId: expect.any(String) });
});

it("effective capabilities serialize with host downgrade and reject mismatched persisted epoch facts", async () => {
  const f = await seed();
  const { getSandboxCapabilities } = await import("@wssp/api/sandbox/services/capabilities");
  // A downgrade committed before H must be visible, even with the same epoch.
  const beforeLock = db.pauseAt("prelock-capabilities", {
    before: /sql:SELECT id FROM sandbox_host .*FOR UPDATE/,
  });
  const prelockRead = db.run("prelock-capabilities", () =>
    getSandboxCapabilities(f.owner, { id: f.sandbox.id }),
  );
  await beforeLock.waitReached();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { relayProtocolVersion: "10.7" },
  });
  beforeLock.release();
  const downgraded = await prelockRead;
  expect(downgraded.unavailableReason).toBe("unsupported_runtime");
  for (const feature of ["commands.background", "files.list", "files.metadata", "processes.list"])
    expect(downgraded.features).not.toContain(feature);
  expect(downgraded.features).toContain("operations.result");
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { relayProtocolVersion: "1.0" },
  });
  const gate = db.pauseAt("capabilities", {
    after: /sql:SELECT id FROM sandbox_host .*FOR UPDATE/,
  });
  const reading = db.run("capabilities", () =>
    getSandboxCapabilities(f.owner, { id: f.sandbox.id }),
  );
  await gate.waitReached();
  const downgrade = db.run("downgrade", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.sandboxHost.update({
        where: { id: f.host.id },
        data: { relayProtocolVersion: "10.7" },
      });
    }),
  );
  await db.waitUntilBlocked("downgrade");
  gate.release();
  expect((await reading).features).toContain("commands.background");
  await downgrade;
  const afterDowngrade = await getSandboxCapabilities(f.owner, { id: f.sandbox.id });
  const newFeatures = [
    "files.metadata",
    "files.list",
    "commands.background",
    "processes.list",
    "processes.signal",
  ];
  for (const feature of newFeatures) expect(afterDowngrade.features).not.toContain(feature);
  expect(afterDowngrade.unavailableReason).toBe("unsupported_runtime");
  for (const feature of ["processes.connect", "processes.kill", "operations.result"])
    expect(afterDowngrade.features).toContain(feature);
  // Retained server connect and canonical kill remain operational on 10.4.
  expect(
    (await f.request(`${f.base}?generation=1&processId=${f.process.processId}&attempt=1`)).status,
  ).toBe(200);
  expect((await f.request(`${f.base}/kill`, f.qualifiers)).status).toBe(202);
  // The version cutover leaves all older command/output/cancel families intact.
  for (const feature of [
    "commands.execute",
    "commands.read",
    "operations.read",
    "operations.cancel",
  ])
    expect(afterDowngrade.features).toContain(feature);
  for (const mismatch of [{ relayProtocolEpoch: 2 }, { admissionEpoch: 2 }]) {
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { relayProtocolVersion: "1.0", relayProtocolEpoch: 1, admissionEpoch: 1, ...mismatch },
    });
    const capabilities = await getSandboxCapabilities(f.owner, { id: f.sandbox.id });
    for (const feature of newFeatures) expect(capabilities.features).not.toContain(feature);
    // Stale facts are transitional (not yet reported), never proof of no support.
    expect(capabilities.unavailableReason).toBe("host_unavailable");
    expect(capabilities.features).toContain("operations.result");
  }
});

it("relay reconnect window admits fs/process work and reports host_unavailable, not unsupported", async () => {
  const f = await seed();
  // The state a hello leaves until the daemon's admission report arrives.
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: {
      connectionEpoch: 2,
      relayProtocolEpoch: 2,
      admissionEpoch: null,
      admissionRuntime: null,
      journalKeyAcknowledgedEpoch: null,
    },
  });
  const capabilities = sandboxCapabilitiesSchema.parse(
    await (await f.request(`/sandboxes/${f.sandbox.id}/capabilities`)).json(),
  );
  expect(capabilities.unavailableReason).toBe("host_unavailable");
  expect(capabilities.features).not.toContain("files.metadata");
  const stat = await f.request(`/sandboxes/${f.sandbox.id}/files/stat`, { path: "/" });
  expect(stat.status).toBe(202);
  const receipt = mutationReceiptSchema.parse(await stat.json());
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: receipt.operationId } }),
  ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
  // A current-epoch admission without fs/process support is positive proof.
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { admissionEpoch: 2, admissionRuntime: "UNSUPPORTED" },
  });
  const refused = sandboxCapabilitiesSchema.parse(
    await (await f.request(`/sandboxes/${f.sandbox.id}/capabilities`)).json(),
  );
  expect(refused.unavailableReason).toBe("unsupported_runtime");
  await error(
    await f.request(`/sandboxes/${f.sandbox.id}/files/stat`, { path: "/" }),
    400,
    "UNSUPPORTED_CAPABILITY",
  );
});

it("connect and capabilities deny disclosure when key revocation waits at read commit", async () => {
  for (const path of ["connect", "capabilities"]) {
    const f = await seed();
    const gate = db.pauseAt("read", { before: "$transaction.commit" });
    const reading = db.run("read", async () =>
      f.request(
        path === "connect"
          ? `${f.base}?generation=1&processId=${f.process.processId}&attempt=1`
          : `/sandboxes/${f.sandbox.id}/capabilities`,
      ),
    );
    await gate.waitReached();
    const revoking = db.run("revoke", () =>
      withAuthorityChange({ ownerId: f.userId, credentialId: f.sdkKey.id }, () =>
        db.prisma.$transaction(async (tx) => {
          await tx.sdkKey.update({ where: { id: f.sdkKey.id }, data: { revokedAt: new Date() } });
        }),
      ),
    );
    await db.waitUntilBlocked("revoke", { by: "read" });
    gate.release();
    await error(await reading, 403, "FORBIDDEN");
    await revoking;
  }
});

it("continuation admission reads cursor content and expiry on the acceptance connection", async () => {
  const f = await seed();
  const expiresAt = new Date(Date.now() + 3600000);
  const page = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.userId,
      sandboxId: f.sandbox.id,
      generation: 1,
      kind: "LIST_DIR",
      state: "SUCCEEDED",
      dispatchAttempt: 1,
      resultVersion: 1,
      resultExpiresAt: expiresAt,
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
    },
  });
  const continuation = {
    lastKey: "a",
    root: "/",
    depth: 1,
    limit: 100,
    generation: 1,
    kind: "LIST_DIR",
  };
  await db.inspect.sandboxOperationResult.create({
    data: {
      operationId: page.id,
      sandboxId: f.sandbox.id,
      userId: f.userId,
      generation: 1,
      attempt: 1,
      version: 1,
      reservationBytes: 200,
      reservationState: "PUBLISHED",
      expiresAt,
      continuation,
    },
  });
  const prefix = db.pauseAt("page-two", {
    after: /sql:SELECT id FROM sandbox_instance .*FOR NO KEY UPDATE/,
  });
  const content = db.pauseAt("page-two", { before: "sandboxOperationResult.findFirst" });
  const read = db.run("page-two", async () =>
    f.request(`/sandboxes/${f.sandbox.id}/files/list`, {
      path: "/",
      depth: 1,
      limit: 100,
      cursor: page.id,
    }),
  );
  await prefix.waitReached();
  const acceptancePid = db.backendPid("page-two");
  prefix.release();
  await content.waitReached();
  expect(acceptancePid).toBeTypeOf("number");
  expect(db.backendPid("page-two")).toBe(acceptancePid);
  // The expiry clock is sampled on the same backend after the prefix locks.
  const [activity] = await db.inspect.$queryRaw<
    { query: string }[]
  >`SELECT query FROM pg_stat_activity WHERE pid=${acceptancePid}`;
  expect(activity?.query).toContain("clock_timestamp()");
  content.release();
  const response = await read;
  expect(response.status).toBe(202);
  const accepted = mutationReceiptSchema.parse(await response.json());
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }),
  ).toMatchObject({ resultExpiresAt: expiresAt });
});

it.each([false, true])(
  "D-20 native command admission and capabilities share landing switch=%s",
  async (enabled) => {
    zeroPolicy.enabled = enabled;
    const f = await seed();
    const effective = sandboxCapabilitiesSchema.parse(
      await (await f.request(`/sandboxes/${f.sandbox.id}/capabilities`)).json(),
    );
    expect(effective.limits.commandTimeoutZero).toBe(enabled);
    const global = capabilitiesSchema.parse(await (await f.request("/capabilities")).json());
    expect(global.limits.commandTimeoutZero).toBe(enabled);
    const before = await db.inspect.sandboxOperation.count({ where: { userId: f.userId } });
    const response = await f.request(`/sandboxes/${f.sandbox.id}/commands`, {
      argv: ["true"],
      timeoutMs: 0,
    });
    if (enabled) {
      expect(response.status).toBe(202);
      expect(
        (
          await db.inspect.outboxEvent.findFirstOrThrow({
            where: { userId: f.userId, eventType: "sandbox.command_requested" },
          })
        ).payload,
      ).toMatchObject({ timeoutMs: 0 });
    } else {
      expect(response.status).toBe(400);
      expect(await db.inspect.sandboxOperation.count({ where: { userId: f.userId } })).toBe(before);
      expect(await db.inspect.outboxEvent.count({ where: { userId: f.userId } })).toBe(0);
      expect(charged).not.toHaveBeenCalled();
    }
    for (const mode of ["old", "unknown", "unsupported"] as const) {
      await db.inspect.sandboxHost.update({
        where: { id: f.host.id },
        data: {
          relayProtocolVersion: mode === "old" ? "10.7" : "1.0",
          relayProtocolEpoch: mode === "unknown" ? null : 1,
          admissionRuntime: mode === "unsupported" ? "UNSUPPORTED" : "FAKE",
        },
      });
      const unsupported = sandboxCapabilitiesSchema.parse(
        await (await f.request(`/sandboxes/${f.sandbox.id}/capabilities`)).json(),
      );
      expect(unsupported.limits.commandTimeoutZero).toBe(false);
    }
  },
);

it("result reads are server capabilities even after a 10.4 downgrade", async () => {
  const f = await seed();
  await db.inspect.sandboxOperation.update({
    where: { id: f.command.id },
    data: {
      scalarResult: {
        type: "command",
        process: f.process,
        startedAt: f.command.processStartedAt!.toISOString(),
        exitCode: null,
      },
    },
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { relayProtocolVersion: "10.7" },
  });
  const capabilities = sandboxCapabilitiesSchema.parse(
    await (await f.request(`/sandboxes/${f.sandbox.id}/capabilities`)).json(),
  );
  expect(capabilities.features).toContain("operations.result");
  expect(capabilities.features).not.toContain("processes.list");
  const response = await f.request(`/operations/${f.command.id}/result`);
  expect(response.status).toBe(200);
  expect(operationResultSchema.parse(await response.json()).result?.type).toBe("command");
});
