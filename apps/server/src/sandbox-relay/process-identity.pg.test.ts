import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { vmLiveMemoryChargeMiB } from "@wssp/sandbox-contracts";
import { afterAll, expect, it, vi } from "vitest";
import {
  seedAcceptedOperation,
  seedDispatchEvent,
  seedLaunchHost,
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
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeSandboxWriteBudget: async () => {},
  consumeCreateConnectBudget: async () => {},
}));
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockResolvedValue("sent"),
    captureHostDispatchCredential: vi.fn(),
    installExecutionConfig: vi.fn().mockResolvedValue(true),
  },
}));
const db = await pgTestDatabase();
const {
  acceptFencedBinaryChunk,
  applyProcessStarted,
  applyOperationResult,
  confirmOperationReceipt,
  finishHostReconciliation,
} = await import("./operation-handlers");
const { reserveOperationResult, getOperationResult } = await import(
  "@wssp/api/sandbox/operation-results"
);
const { sessionPrincipal } = await import("@wssp/api/sandbox/contracts");
const { lockOwnerForAdmission } = await import("@wssp/db/account-deletion");
const { lockHostByEpoch, cancelQueuedOperation, relayTransaction } = await import(
  "@wssp/api/sandbox/relay-fence"
);
afterAll(() => db.close());
async function seed(
  kind: "RUN_COMMAND" | "STAT_PATH" | "LIST_PROCESSES" | "STOP_SANDBOX" = "RUN_COMMAND",
) {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: { id: userId, name: "Owner", email: `${userId}@example.test` },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId,
      slug: "host",
      label: "Host",
      status: "CONNECTED",
      connectionEpoch: 1,
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 1,
    },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      slug: "image",
      label: "Image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      originHostId: host.id,
      templateId: revision.id,
      state: "READY",
    },
  });
  const op = await seedAcceptedOperation(db.inspect, {
    data: {
      userId,
      sandboxId: sandbox.id,
      kind,
      generation: 1,
      idempotencyKey: "command",
      requestBodyHash: "a".repeat(64),
      state: kind === "RUN_COMMAND" ? "RUNNING" : "QUEUED",
      dispatchAttempt: kind === "RUN_COMMAND" ? 1 : 0,
      dispatchedHostId: kind === "RUN_COMMAND" ? host.id : null,
      dispatchedConnectionEpoch: kind === "RUN_COMMAND" ? 1 : null,
      ...(kind === "RUN_COMMAND" ? { resultVersion: 1, processId: randomUUID() } : {}),
    },
  });
  const sender = { userId, hostId: host.id, connectionEpoch: 1 };
  const birth = {
    type: "process.started" as const,
    operationId: op.id,
    sandboxId: sandbox.id,
    generation: 1,
    attempt: 1,
    processId: op.processId!,
    pid: 42,
    bootId: "12345678-1234-4234-8234-123456789abc",
    startTicks: "123",
    startedAt: "2026-10-27T00:00:00.000Z",
    observedAt: "2026-10-27T00:00:00.001Z",
  };
  const input = { sender, operationId: op.id, sandboxId: sandbox.id, generation: 1, attempt: 1 };
  return { userId, host, sandbox, op, sender, birth, input, revision };
}
type Fixture = Awaited<ReturnType<typeof seed>>;
const operation = (f: Fixture) =>
  db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } });
function command(f: Fixture, exitCode: number | null = 7) {
  const { sandboxId, generation, attempt, processId, pid } = f.birth;
  return {
    version: 1,
    observedAt: f.birth.observedAt,
    payload: {
      type: "command",
      process: { sandboxId, generation, attempt, processId, pid },
      startedAt: f.birth.startedAt,
      exitCode,
    },
    continuation: null,
    birth: f.birth,
    failure: null,
    outputBytes: 0,
  };
}
it("birth is immutable, duplicate-safe and never promotes interim UNKNOWN or CANCEL_REQUESTED", async () => {
  for (const state of ["RUNNING", "UNKNOWN_OUTCOME", "CANCEL_REQUESTED"] as const) {
    const f = await seed();
    await db.inspect.sandboxOperation.update({ where: { id: f.op.id }, data: { state } });
    expect(await applyProcessStarted({ sender: f.sender, birth: f.birth })).toEqual({
      written: true,
    });
    expect(await applyProcessStarted({ sender: f.sender, birth: f.birth })).toEqual({
      written: true,
    });
    for (const change of [
      { pid: 43 },
      { startTicks: "124" },
      { bootId: "00000000-1234-4234-8234-123456789abc" },
      { processId: "other" },
      { attempt: 2 },
      { generation: 2 },
      { nonce: "sentinel" },
    ])
      expect(
        await applyProcessStarted({ sender: f.sender, birth: { ...f.birth, ...change } }),
      ).toEqual({ written: false });
    expect(await operation(f)).toMatchObject({ state, processPid: 42, processStartTicks: "123" });
  }
});
it("fast final receipt supplies lost birth, commits scalar evidence and replays without extending retention", async () => {
  const f = await seed();
  const receipt = {
    bodyHash: f.op.requestBodyHash,
    idempotencyKey: f.op.idempotencyKey,
    kind: "command.run",
  };
  const input = { ...f.input, state: "succeeded", result: command(f), receipt };
  expect(await applyOperationResult(input)).toEqual({ written: true });
  const first = await operation(f);
  expect(first).toMatchObject({
    state: "SUCCEEDED",
    processPid: 42,
    scalarResult: { type: "command", exitCode: 7 },
    result: { exitCode: 7, pid: 42, outputBytes: 0 },
  });
  expect(JSON.stringify(first.result)).not.toContain("bootId");
  expect(await applyProcessStarted({ sender: f.sender, birth: f.birth })).toEqual({
    written: true,
  });
  expect(await applyOperationResult(input)).toEqual({ written: false });
  expect(await confirmOperationReceipt({ ...input, written: false })).toMatchObject({
    type: "receipt.confirmed",
  });
  expect((await operation(f)).completedAt).toEqual(first.completedAt);
  expect((await operation(f)).processDescriptionExpiresAt).toEqual(
    first.processDescriptionExpiresAt,
  );
});
it("a versioned success without permanent evidence is refused; missing scalar is internal, never expired", async () => {
  const f = await seed();
  expect(
    await applyOperationResult({
      ...f.input,
      state: "succeeded",
      result: {
        version: 1,
        observedAt: f.birth.observedAt,
        payload: null,
        continuation: null,
        birth: null,
        failure: null,
      },
    }),
  ).toEqual({ written: false });
  expect((await operation(f)).state).toBe("RUNNING");
  await db.inspect.sandboxOperation.update({
    where: { id: f.op.id },
    data: { state: "SUCCEEDED" },
  });
  await expect(
    getOperationResult(sessionPrincipal(f.userId), { operationId: f.op.id }),
  ).rejects.toMatchObject({ status: 500, data: { code: "INTERNAL_SERVER_ERROR" } });
});
it("all identity and result writers refuse epoch E after E+1 commits under H", async () => {
  const f = await seed();
  const gate = db.pauseAt("epoch", { before: "$transaction.commit" });
  const changed = db.run("epoch", () =>
    db.prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, f.userId);
      await lockHostByEpoch(tx, f.host.id, 1, f.userId);
      await tx.sandboxHost.update({ where: { id: f.host.id }, data: { connectionEpoch: 2 } });
    }),
  );
  await gate.waitReached();
  const start = db.run("start", () => applyProcessStarted({ sender: f.sender, birth: f.birth }));
  await db.waitUntilBlocked("start", { by: "epoch" });
  gate.release();
  await changed;
  expect(await start).toEqual({ written: false });
  expect(
    await applyOperationResult({ ...f.input, state: "succeeded", result: command(f) }),
  ).toEqual({ written: false });
  expect(await operation(f)).toMatchObject({
    processPid: null,
    scalarResult: null,
    state: "RUNNING",
  });
});
it("birth versus replacement dispatch serializes at S/O and never permits a second incarnation", async () => {
  const f = await seed();
  const gate = db.pauseAt("birth", { before: "$transaction.commit" });
  const born = db.run("birth", () => applyProcessStarted({ sender: f.sender, birth: f.birth }));
  await gate.waitReached();
  const claim = db.run("claim", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${f.sandbox.id} FOR UPDATE`;
      return tx.sandboxOperation.updateMany({
        where: { id: f.op.id, processPid: null },
        data: { dispatchAttempt: 2 },
      });
    }),
  );
  await db.waitUntilBlocked("claim", { by: "birth" });
  gate.release();
  expect(await born).toEqual({ written: true });
  expect((await claim).count).toBe(0);
  expect((await operation(f)).dispatchAttempt).toBe(1);
});
it("result is unacknowledgeable before DB commit and a failed commit leaves no identity", async () => {
  const f = await seed();
  const gate = db.pauseAt("result", { before: "$transaction.commit" });
  let ack = false;
  const writing = db
    .run("result", () =>
      applyOperationResult({ ...f.input, state: "succeeded", result: command(f) }),
    )
    .then((v) => {
      ack = v.written;
      return v;
    });
  await gate.waitReached();
  expect(ack).toBe(false);
  expect((await operation(f)).processPid).toBeNull();
  gate.fail(new Error("injected commit failure"));
  await expect(writing).rejects.toThrow();
  expect(ack).toBe(false);
  expect(await operation(f)).toMatchObject({
    state: "RUNNING",
    processPid: null,
    scalarResult: null,
  });
});
const entry = {
  name: "x",
  path: "/x",
  type: "file",
  size: 1,
  mode: 420,
  permissions: "rw-r--r--",
  uid: 1000,
  gid: 1000,
  owner: null,
  group: null,
  modifiedTime: null,
  symlinkTarget: null,
};
async function content(kind: "STAT_PATH" | "LIST_PROCESSES" = "STAT_PATH") {
  const f = await seed(kind);
  await db.inspect.outboxEvent.create({
    data: {
      userId: f.userId,
      aggregateType: "sandbox",
      aggregateId: f.sandbox.id,
      eventType:
        kind === "STAT_PATH" ? "sandbox.file_stat_requested" : "sandbox.process_list_requested",
      operationId: f.op.id,
      payload: { operationId: f.op.id, ...(kind === "STAT_PATH" ? { path: "/x" } : {}) },
    },
  });
  await relayTransaction(async (tx) => {
    await lockOwnerForAdmission(tx, f.userId);
    await lockHostByEpoch(tx, f.host.id, 1, f.userId);
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${f.sandbox.id} FOR UPDATE`;
    await reserveOperationResult(tx, { ownerId: f.userId, operationId: f.op.id });
  }, undefined);
  await db.inspect.sandboxOperation.update({
    where: { id: f.op.id },
    data: {
      state: "RUNNING",
      dispatchAttempt: 1,
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: 1,
    },
  });
  return f;
}
const statResult = {
  version: 1,
  observedAt: "2026-10-27T00:00:00.001Z",
  payload: { type: "file.stat", entry },
  continuation: null,
  birth: null,
  failure: null,
};
const malformedStatResults = [
  { ...statResult, secret: "sentinel" },
  { ...statResult, payload: { type: "file.stat", entry: { ...entry, path: "/other" } } },
  // Self-consistent, so it decodes; only the request binding (/x) refuses it.
  {
    ...statResult,
    payload: { type: "file.stat", entry: { ...entry, name: "other", path: "/other" } },
  },
  { ...statResult, payload: { type: "file.mkdir", created: true } },
  {
    ...statResult,
    payload: {
      type: "file.list",
      items: [],
      path: "/",
      depth: 1,
      nextCursor: null,
      consistency: "live",
    },
    padding: "x".repeat(24576),
  },
];
it("live and receipt use the same codec before writes, including paths, extras and byte limits", async () => {
  const f = await content();
  for (const result of malformedStatResults)
    expect(await applyOperationResult({ ...f.input, state: "succeeded", result })).toEqual({
      written: false,
    });
  expect((await operation(f)).state).toBe("RUNNING");
  expect(
    await applyOperationResult({ ...f.input, state: "succeeded", result: statResult }),
  ).toEqual({ written: true });
  expect(
    await db.inspect.sandboxOperationResult.findUnique({ where: { operationId: f.op.id } }),
  ).toMatchObject({ reservationState: "PUBLISHED", payload: { type: "file.stat" } });
});
// WP0: a refused exact receipt would stay unconfirmed and replay into every
// later session. It gets the server's terminal verdict instead, and none of
// its content is stored.
it.each(malformedStatResults.map((result, index) => [index, result] as const))(
  "an exact receipt the codec refuses (case %i) settles FAILED protocol_error without its content",
  async (_index, result) => {
    const f = await content();
    const receipt = {
      bodyHash: f.op.requestBodyHash,
      idempotencyKey: f.op.idempotencyKey,
      kind: "file.stat",
    };
    expect(await applyOperationResult({ ...f.input, state: "succeeded", receipt, result })).toEqual(
      { written: true },
    );
    const row = await operation(f);
    expect(row).toMatchObject({ state: "FAILED", errorCode: "protocol_error" });
    expect(JSON.stringify(row)).not.toContain("sentinel");
    expect(
      await db.inspect.sandboxOperationResult.findUnique({ where: { operationId: f.op.id } }),
    ).toMatchObject({ reservationState: "RELEASED", payload: null });
    expect(
      await confirmOperationReceipt({
        ...f.input,
        receipt,
        state: "succeeded",
        written: true,
      }),
    ).toMatchObject({ type: "receipt.confirmed", operationId: f.op.id });
  },
);
it.each([
  ["another process identity", { processId: randomUUID() }],
  ["another incarnation of the bound birth", { pid: 43 }],
] as const)(
  "an exact command receipt carrying %s settles FAILED protocol_error and is confirmed",
  async (label, change) => {
    const f = await seed();
    if (label === "another incarnation of the bound birth")
      expect(await applyProcessStarted({ sender: f.sender, birth: f.birth })).toEqual({
        written: true,
      });
    const receipt = {
      bodyHash: f.op.requestBodyHash,
      idempotencyKey: f.op.idempotencyKey,
      kind: "command.run",
    };
    // Self-consistent evidence (payload process = birth) for the wrong process.
    const result = command({ ...f, birth: { ...f.birth, ...change } });
    expect(await applyOperationResult({ ...f.input, state: "succeeded", result })).toEqual({
      written: false,
    });
    expect((await operation(f)).state).toBe("RUNNING");
    expect(await applyOperationResult({ ...f.input, state: "succeeded", receipt, result })).toEqual(
      { written: true },
    );
    expect(await operation(f)).toMatchObject({
      state: "FAILED",
      errorCode: "protocol_error",
      processId: f.op.processId,
    });
    expect(
      await confirmOperationReceipt({ ...f.input, receipt, state: "succeeded", written: true }),
    ).toMatchObject({ type: "receipt.confirmed", operationId: f.op.id });
  },
);
// WP0: the exact-receipt classifier. Every refusal outside the
// retryable allowlist settles; authority changes, database errors and pending
// observations stay refused.
const exact = (f: Fixture, kind: string) => ({
  bodyHash: f.op.requestBodyHash,
  idempotencyKey: f.op.idempotencyKey,
  kind,
});
async function listed(birthBound: boolean) {
  const f = await content("LIST_PROCESSES");
  const processId = randomUUID();
  const command = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.userId,
      sandboxId: f.sandbox.id,
      kind: "RUN_COMMAND",
      generation: 1,
      idempotencyKey: "listed",
      requestBodyHash: "b".repeat(64),
      state: "RUNNING",
      dispatchAttempt: 1,
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: 1,
      resultVersion: 1,
      processId,
      ...(birthBound
        ? {
            processPid: 42,
            processBootId: f.birth.bootId,
            processStartTicks: "123",
            processStartedAt: new Date(f.birth.startedAt),
          }
        : {}),
    },
  });
  const item = (id: string) => ({
    process: { sandboxId: f.sandbox.id, generation: 1, attempt: 1, processId: id, pid: 42 },
    operationId: command.id,
    kind: "command",
    cmd: "sleep",
    args: ["9"],
    argsTruncated: false,
    cwd: "/",
    startedAt: f.birth.startedAt,
    observedAt: f.birth.observedAt,
  });
  const page = (id: string) => ({
    ...statResult,
    payload: { type: "process.list", items: [item(id)], nextCursor: null, consistency: "live" },
  });
  return { f, processId, page };
}
it("a process-list receipt naming another immutable process identity settles", async () => {
  const { f, page } = await listed(true);
  const receipt = exact(f, "process.list");
  const result = page(randomUUID());
  expect(await applyOperationResult({ ...f.input, state: "succeeded", result })).toEqual({
    written: false,
  });
  expect(await applyOperationResult({ ...f.input, state: "succeeded", receipt, result })).toEqual({
    written: true,
  });
  expect(await operation(f)).toMatchObject({ state: "FAILED", errorCode: "protocol_error" });
  expect(
    await confirmOperationReceipt({ ...f.input, receipt, state: "succeeded", written: true }),
  ).toMatchObject({ type: "receipt.confirmed" });
});
it("a process-list receipt whose listed birth the server has not recorded stays pending", async () => {
  const { f, processId, page } = await listed(false);
  const receipt = exact(f, "process.list");
  expect(
    await applyOperationResult({
      ...f.input,
      state: "succeeded",
      receipt,
      result: page(processId),
    }),
  ).toEqual({ written: false });
  expect((await operation(f)).state).toBe("RUNNING");
  expect(
    await confirmOperationReceipt({ ...f.input, receipt, state: "succeeded", written: false }),
  ).toBeNull();
});
it("a command receipt declaring fewer output bytes than were stored settles", async () => {
  const f = await seed();
  expect(
    await acceptFencedBinaryChunk({
      sender: f.sender,
      operationId: f.op.id,
      generation: 1,
      attempt: 1,
      sequence: 0,
      ended: false,
      body: new Uint8Array([65]),
      output: {
        type: "stream.chunk",
        streamId: f.op.id,
        operationId: f.op.id,
        generation: 1,
        attempt: 1,
        sequence: 0,
        offset: 0,
        flags: { stdout: true },
      },
    }),
  ).toBe(true);
  const receipt = exact(f, "command.run");
  const result = { ...command(f, 0), outputBytes: 0 };
  expect(await applyOperationResult({ ...f.input, state: "succeeded", receipt, result })).toEqual({
    written: true,
  });
  expect(await operation(f)).toMatchObject({ state: "FAILED", errorCode: "protocol_error" });
  expect(
    await confirmOperationReceipt({ ...f.input, receipt, state: "succeeded", written: true }),
  ).toMatchObject({ type: "receipt.confirmed" });
});
it("a stop receipt claiming success with a running VM settles FAILED, never stopped", async () => {
  const f = await seed("STOP_SANDBOX");
  await db.inspect.sandboxOperation.update({
    where: { id: f.op.id },
    data: {
      state: "RUNNING",
      dispatchAttempt: 1,
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: 1,
    },
  });
  await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { state: "STOPPING" } });
  const receipt = exact(f, "sandbox.stop");
  const ready = { state: "ready" };
  expect(
    await applyOperationResult({ ...f.input, state: "succeeded", receipt, result: ready }),
  ).toEqual({ written: true });
  expect(await operation(f)).toMatchObject({ state: "FAILED", errorCode: "protocol_error" });
  expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandbox.id } })).toMatchObject(
    { state: "ERROR", lastErrorCode: "protocol_error" },
  );
  expect(
    await confirmOperationReceipt({ ...f.input, receipt, state: "succeeded", written: true }),
  ).toMatchObject({ type: "receipt.confirmed" });
});
it("an exact receipt refused for authority (host replaced) stays refused", async () => {
  const f = await seed();
  const receipt = exact(f, "command.run");
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { connectionEpoch: 2 },
  });
  // The old epoch's session can no longer act for the host at all.
  const result = { ...command(f), birth: { ...f.birth, processId: randomUUID() } };
  expect(await applyOperationResult({ ...f.input, state: "succeeded", receipt, result })).toEqual({
    written: false,
  });
  expect((await operation(f)).state).toBe("RUNNING");
});
it("a capture receipt after its live result recorded the capture is confirmed, never failed", async () => {
  const f = await seed();
  const op = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.userId,
      sandboxId: f.sandbox.id,
      kind: "CAPTURE_TEMPLATE",
      state: "RUNNING",
      generation: 1,
      idempotencyKey: "capture",
      requestBodyHash: "c".repeat(64),
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: 1,
      dispatchAttempt: 1,
    },
  });
  await db.inspect.sandboxTemplateCapture.create({
    data: {
      operationId: op.id,
      userId: f.userId,
      sandboxId: f.sandbox.id,
      templateId: f.revision.templateId,
      tag: "latest",
      hostId: f.host.id,
      hostOwnerId: f.userId,
      state: "PENDING",
      architecture: "x86_64",
    },
  });
  const input = { ...f.input, operationId: op.id };
  const result = {
    fingerprint: `sha256:${"d".repeat(64)}`,
    sizeBytes: 4096,
    architecture: "x86_64",
  };
  expect(await applyOperationResult({ ...input, state: "succeeded", result })).toEqual({
    written: true,
  });
  expect(
    await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({ where: { operationId: op.id } }),
  ).toMatchObject({ state: "CAPTURED" });
  // The usual following receipt misses the PENDING-only capture CAS; the
  // recorded capture is a settlement, so it is confirmed, not given a verdict.
  const receipt = {
    bodyHash: op.requestBodyHash,
    idempotencyKey: op.idempotencyKey,
    kind: "sandbox.capture",
  };
  expect(
    await applyOperationResult({ ...input, state: "succeeded", receipt, result }),
  ).toMatchObject({ written: false });
  const after = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } });
  expect(after).toMatchObject({ state: "RUNNING", errorCode: null });
  expect(
    await confirmOperationReceipt({ ...input, receipt, state: "succeeded", written: false }),
  ).toMatchObject({ type: "receipt.confirmed", operationId: op.id });
  expect(
    await db.inspect.webhookEvent.count({
      where: { operationId: op.id, type: "operation.completed" },
    }),
  ).toBe(0);
});
it("a reconnect during capture finalization leaves the recorded capture to its finalizer", async () => {
  const f = await seed();
  const op = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.userId,
      sandboxId: f.sandbox.id,
      kind: "CAPTURE_TEMPLATE",
      state: "RUNNING",
      generation: 1,
      idempotencyKey: "capture",
      requestBodyHash: "c".repeat(64),
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: 1,
      dispatchAttempt: 1,
    },
  });
  await db.inspect.sandboxTemplateCapture.create({
    data: {
      operationId: op.id,
      userId: f.userId,
      sandboxId: f.sandbox.id,
      templateId: f.revision.templateId,
      tag: "latest",
      hostId: f.host.id,
      hostOwnerId: f.userId,
      state: "PENDING",
      architecture: "x86_64",
    },
  });
  const result = {
    fingerprint: `sha256:${"d".repeat(64)}`,
    sizeBytes: 4096,
    architecture: "x86_64",
  };
  expect(
    await applyOperationResult({ ...f.input, operationId: op.id, state: "succeeded", result }),
  ).toEqual({ written: true });
  // The host reconnects while the server is still finalizing the revision.
  await db.inspect.sandboxHost.update({ where: { id: f.host.id }, data: { connectionEpoch: 2 } });
  expect(await finishHostReconciliation({ ...f.sender, connectionEpoch: 2 })).toBe(true);
  // An ordinary old-epoch command has no outcome and becomes UNKNOWN; the
  // recorded capture has one, so it stays with its finalizer (whose
  // SUCCEEDED is then its only completion).
  expect((await operation(f)).state).toBe("UNKNOWN_OUTCOME");
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } }),
  ).toMatchObject({ state: "RUNNING", errorCode: null });
  expect(
    await db.inspect.webhookEvent.count({
      where: { operationId: op.id, type: "operation.completed" },
    }),
  ).toBe(0);
});
it("a process-list receipt whose later item has a wrong identity settles despite an earlier pending item", async () => {
  const { f, processId, page } = await listed(false);
  const result = page(processId);
  const pending = result.payload.items[0]!;
  // A second, later-started item naming the same command at another attempt.
  result.payload.items.push({
    ...pending,
    process: { ...pending.process, attempt: 2, processId: "zz" + processId.slice(2) },
    startedAt: new Date(Date.parse(pending.startedAt) + 1000).toISOString(),
  });
  const receipt = exact(f, "process.list");
  expect(await applyOperationResult({ ...f.input, state: "succeeded", receipt, result })).toEqual({
    written: true,
  });
  expect(await operation(f)).toMatchObject({ state: "FAILED", errorCode: "protocol_error" });
});
it.each(["generation", "attempt", "processId"] as const)(
  "a process-list receipt naming a birthless command with the wrong %s settles",
  async (field) => {
    const { f, processId, page } = await listed(false);
    const result = page(processId);
    const item = result.payload.items[0]!;
    if (field === "generation") item.process.generation = 2;
    if (field === "attempt") item.process.attempt = 2;
    if (field === "processId") item.process.processId = randomUUID();
    const receipt = exact(f, "process.list");
    expect(await applyOperationResult({ ...f.input, state: "succeeded", receipt, result })).toEqual(
      { written: true },
    );
    expect(await operation(f)).toMatchObject({ state: "FAILED", errorCode: "protocol_error" });
  },
);
it.each(["FAILED", "CANCELLED"] as const)(
  "a process-list receipt naming a %s command that never got a birth settles",
  async (state) => {
    const { f, processId, page } = await listed(false);
    await db.inspect.sandboxOperation.updateMany({
      where: { sandboxId: f.sandbox.id, kind: "RUN_COMMAND", idempotencyKey: "listed" },
      data: { state, completedAt: new Date() },
    });
    const receipt = exact(f, "process.list");
    expect(
      await applyOperationResult({
        ...f.input,
        state: "succeeded",
        receipt,
        result: page(processId),
      }),
    ).toEqual({ written: true });
    expect(await operation(f)).toMatchObject({ state: "FAILED", errorCode: "protocol_error" });
    expect(
      await confirmOperationReceipt({ ...f.input, receipt, state: "succeeded", written: true }),
    ).toMatchObject({ type: "receipt.confirmed" });
  },
);
it("failure releases once, retains only catalog error and failure facts, and late content never resurrects", async () => {
  const f = await content();
  const sentinel = "PRIVATE_PATH_ENV_STDERR";
  expect(
    await applyOperationResult({
      ...f.input,
      state: "failed",
      error: { code: "fs_not_found", message: sentinel },
      result: { ...statResult, payload: null, failure: { resource: "filesystem", effect: "none" } },
    }),
  ).toEqual({ written: true });
  const row = await operation(f);
  expect(row.errorDetail).toBe("Guest path not found.");
  expect(JSON.stringify(row)).not.toContain(sentinel);
  expect(
    await db.inspect.sandboxOperationResult.findUnique({ where: { operationId: f.op.id } }),
  ).toMatchObject({ reservationState: "RELEASED", reservationBytes: 0, payload: null });
  expect(
    await applyOperationResult({
      ...f.input,
      state: "succeeded",
      result: statResult,
      receipt: {
        bodyHash: f.op.requestBodyHash,
        idempotencyKey: f.op.idempotencyKey,
        kind: "file.stat",
      },
    }),
  ).toEqual({ written: false });
  expect(
    await getOperationResult(sessionPrincipal(f.userId), { operationId: f.op.id }),
  ).toMatchObject({ outcome: "failed", result: null });
});

it("a real replacement dispatch cannot reclaim a command whose birth won the H/S/O race", async () => {
  const { processSandboxOutboxBatch } = await import("./outbox-processor");
  const { sandboxRelaySessionManager: manager } = await import("./session-manager");
  const f = await seed();
  await db.inspect.sandboxOperation.update({
    where: { id: f.op.id },
    data: { state: "DISPATCHED", acceptedAttempt: null },
  });
  await seedDispatchEvent(db.inspect, {
    data: {
      userId: f.userId,
      aggregateType: "sandbox",
      aggregateId: f.sandbox.id,
      eventType: "sandbox.command_requested",
      payload: {
        operationId: f.op.id,
        sandboxId: f.sandbox.id,
        sandboxHostId: f.host.id,
        generation: 1,
        dispatchAttempt: 1,
        kind: "command.run",
        argv: ["true"],
        idempotencyKey: "command",
        authorizingPrincipal: { kind: "session" },
      },
    },
  });
  const gate = db.pauseAt("born", { before: "$transaction.commit" });
  const born = db.run("born", () => applyProcessStarted({ sender: f.sender, birth: f.birth }));
  await gate.waitReached();
  const epoch = db.run("epoch", () =>
    db.prisma.$transaction(async (tx) => {
      await lockHostByEpoch(tx, f.host.id, 1, f.userId);
      await tx.sandboxHost.update({
        where: { id: f.host.id },
        data: {
          connectionEpoch: 2,
          relayProtocolEpoch: 2,
          admissionEpoch: 2,
          journalKeyAcknowledgedEpoch: 2,
          inventoryAcknowledgedEpoch: 2,
        },
      });
      await tx.sandboxExecutionConfig.updateMany({
        where: { sandboxId: f.sandbox.id },
        data: { acknowledgedEpoch: 2 },
      });
    }),
  );
  await db.waitUntilBlocked("epoch", { by: "born" });
  gate.release();
  await born;
  await epoch;
  vi.mocked(manager.dispatchOperation).mockClear();
  await processSandboxOutboxBatch();
  expect((await operation(f)).dispatchAttempt).toBe(1);
  expect((await operation(f)).processPid).toBe(42);
  expect(manager.dispatchOperation).not.toHaveBeenCalled();
});

it("queued observation cancellation releases its hold once and refuses late content", async () => {
  const f = await content();
  await db.inspect.sandboxOperation.update({
    where: { id: f.op.id },
    data: {
      state: "QUEUED",
      dispatchAttempt: 0,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
    },
  });
  await relayTransaction(async (tx) => {
    await lockOwnerForAdmission(tx, f.userId);
    await lockHostByEpoch(tx, f.host.id, 1, f.userId);
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${f.sandbox.id} FOR UPDATE`;
    await cancelQueuedOperation(
      tx,
      {
        operationId: f.op.id,
        sandboxId: f.sandbox.id,
        userId: f.userId,
        generation: 1,
        attempt: 0,
        hostId: null,
        kind: "STAT_PATH",
      },
      new Date(),
    );
    return true;
  }, false);
  expect(
    await db.inspect.sandboxOperationResult.findUnique({ where: { operationId: f.op.id } }),
  ).toMatchObject({ reservationState: "RELEASED", reservationBytes: 0 });
  expect(
    await applyOperationResult({ ...f.input, state: "succeeded", result: statResult }),
  ).toEqual({ written: false });
  expect(
    await getOperationResult(sessionPrincipal(f.userId), { operationId: f.op.id }),
  ).toMatchObject({ outcome: "cancelled", result: null });
});
it("a late exact receipt settles status after fixed expiry without recreating content", async () => {
  const f = await content();
  const expiry = new Date(Date.now() - 1000);
  await db.inspect.sandboxOperation.update({
    where: { id: f.op.id },
    data: { resultExpiresAt: expiry, state: "UNKNOWN_OUTCOME" },
  });
  await db.inspect.sandboxOperationResult.update({
    where: { operationId: f.op.id },
    data: { expiresAt: expiry },
  });
  const receipt = {
    bodyHash: f.op.requestBodyHash,
    idempotencyKey: f.op.idempotencyKey,
    kind: "file.stat",
  };
  expect(
    await applyOperationResult({ ...f.input, state: "succeeded", receipt, result: statResult }),
  ).toEqual({ written: true });
  expect(
    await db.inspect.sandboxOperationResult.findUnique({ where: { operationId: f.op.id } }),
  ).toMatchObject({ reservationBytes: 0, payload: null });
  await expect(
    getOperationResult(sessionPrincipal(f.userId), { operationId: f.op.id }),
  ).rejects.toMatchObject({ status: 410 });
});
it.each(["stop", "kill"] as const)(
  "lingering UNKNOWN command recovers through sandbox %s with one proven slot release",
  async (action) => {
    const { stopSandbox, killSandbox, cancelOperation } = await import(
      "@wssp/api/sandbox/services/sandboxes"
    );
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    const { sandboxRelaySessionManager: manager } = await import("./session-manager");
    const f = await seed();
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { state: "UNKNOWN_OUTCOME", completedAt: new Date() },
    });
    await db.inspect.sandbox.update({
      where: { id: f.sandbox.id },
      data: { liveResourcesHeld: true },
    });
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { liveCount: 1, memoryReservedMiB: vmLiveMemoryChargeMiB(1024), vcpuReserved: 1 },
    });
    const owner = sessionPrincipal(f.userId);
    const args = { id: f.sandbox.id, idempotencyKey: randomUUID() };
    await (action === "stop" ? stopSandbox(owner, args) : killSandbox(owner, args));
    await processSandboxOutboxBatch();
    const lifecycle = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { userId_idempotencyKey: { userId: f.userId, idempotencyKey: args.idempotencyKey } },
    });
    expect(lifecycle.dispatchAttempt).toBe(1);
    const input = {
      sender: f.sender,
      operationId: lifecycle.id,
      sandboxId: f.sandbox.id,
      generation: lifecycle.generation,
      attempt: 1,
      state: "succeeded",
      result: { state: action === "stop" ? "stopped" : "deleted" },
    };
    expect(await applyOperationResult(input)).toEqual({ written: true });
    expect(await applyOperationResult(input)).toEqual({ written: false });
    expect(await db.inspect.sandbox.findUnique({ where: { id: f.sandbox.id } })).toMatchObject({
      state: action === "stop" ? "STOPPED" : "DELETED",
      liveResourcesHeld: false,
    });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
    expect((await operation(f)).state).toBe("CANCELLED");
    vi.mocked(manager.dispatchOperation).mockClear();
    await expect(cancelOperation(owner, { operationId: f.op.id })).rejects.toMatchObject({
      status: 409,
    });
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  },
);

it("matching live result fills birth on interim UNKNOWN without promoting state or releasing slots", async () => {
  const f = await seed();
  await db.inspect.sandboxOperation.update({
    where: { id: f.op.id },
    data: { state: "UNKNOWN_OUTCOME" },
  });
  expect(
    await applyOperationResult({ ...f.input, state: "succeeded", result: command(f) }),
  ).toEqual({ written: true });
  expect(await operation(f)).toMatchObject({
    state: "UNKNOWN_OUTCOME",
    processPid: 42,
    scalarResult: { type: "command", exitCode: 7 },
  });
  expect(
    await applyOperationResult({
      ...f.input,
      state: "succeeded",
      result: command(f),
      receipt: {
        bodyHash: f.op.requestBodyHash,
        idempotencyKey: f.op.idempotencyKey,
        kind: "command.run",
      },
    }),
  ).toEqual({ written: true });
  expect((await operation(f)).state).toBe("SUCCEEDED");
});

it("interim UNKNOWN carries birth without sealing output and anchors description expiry once", async () => {
  const f = await seed();
  const result: Record<string, unknown> = command(f, null);
  delete result.outputBytes;
  expect(await applyOperationResult({ ...f.input, state: "unknown_outcome", result })).toEqual({
    written: true,
  });
  const first = await operation(f);
  expect(first).toMatchObject({ state: "UNKNOWN_OUTCOME", processPid: 42 });
  expect(first.processDescriptionExpiresAt?.getTime()).toBe(
    first.completedAt!.getTime() + 86_400_000,
  );
  expect(await db.inspect.sandboxCommandOutput.findUnique({ where: { id: f.op.id } })).toBeNull();
  expect(
    await applyOperationResult({
      ...f.input,
      state: "succeeded",
      result: command(f),
      receipt: {
        bodyHash: f.op.requestBodyHash,
        idempotencyKey: f.op.idempotencyKey,
        kind: "command.run",
      },
    }),
  ).toEqual({ written: true });
  expect((await operation(f)).processDescriptionExpiresAt).toEqual(
    first.processDescriptionExpiresAt,
  );
});

it.each(["FAILED", "CANCELLED", "SUCCEEDED"] as const)(
  "late birth on terminal %s without prior identity performs no write",
  async (state) => {
    const f = await seed();
    await db.inspect.sandboxOperation.update({ where: { id: f.op.id }, data: { state } });
    const before = await operation(f);
    expect(await applyProcessStarted({ sender: f.sender, birth: f.birth })).toEqual({
      written: false,
    });
    expect(await operation(f)).toEqual(before);
    // Receipt ingress uses the same birth-binding predicate, even on an
    // interim UNKNOWN receipt that could otherwise carry scalar evidence.
    expect(
      await applyOperationResult({
        ...f.input,
        state: "unknown_outcome",
        result: command(f),
        receipt: {
          bodyHash: f.op.requestBodyHash,
          idempotencyKey: f.op.idempotencyKey,
          kind: "command.run",
        },
      }),
    ).toEqual({ written: false });
    expect(await operation(f)).toEqual(before);
  },
);
