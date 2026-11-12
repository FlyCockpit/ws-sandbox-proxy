import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { vmLiveMemoryChargeMiB } from "@wssp/sandbox-contracts";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { capacityFixture, helloFixture } from "./capacity-fixtures";

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
vi.mock("@wssp/api/lib/host-token-access", () => ({
  revalidateSandboxHostIdentity: vi
    .fn()
    .mockResolvedValue({ status: "active", hostDeletionRequested: false }),
}));
const zeroPolicy = vi.hoisted(() => ({ enabled: false }));
vi.mock("../../../../packages/sandbox-contracts/src/command-timeout-policy", () => ({
  get commandTimeoutZeroEnabled() {
    return zeroPolicy.enabled;
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeSandboxWriteBudget: async () => {},
  consumeCreateConnectBudget: async () => {},
}));
vi.mock("../../../../packages/api/src/sandbox/sharing-budgets", () => ({
  consumeSharingWrite: async () => {},
  consumeInviteAccept: async () => {},
  consumeInviteIssue: async () => {},
}));
const db = await pgTestDatabase();
const { SandboxRelaySessionManager } = await import("./session-manager");
const { commitHostHello } = await import("./host-hello");
const managers: InstanceType<typeof SandboxRelaySessionManager>[] = [];
afterEach(async () => {
  zeroPolicy.enabled = false;
  for (const manager of managers.splice(0)) await manager.dispose();
  vi.restoreAllMocks();
});
afterAll(() => db.close());
function hello(hostId: string, version: string) {
  const message = helloFixture(hostId, false);
  // Replacement peers use only 1.0. An unavailable runtime revokes capability.
  if (version !== "1.0") {
    message.daemon.capabilities.runtimeKind = "unsupported";
    message.inventory.schedulable = false;
  }
  return message;
}
async function registered(
  version = "1.0",
  reconcile = true,
  manager = new SandboxRelaySessionManager(),
) {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: {
      id: userId,
      name: "Owner",
      email: `${userId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId, slug: "host", label: "Host", connectionEpoch: 0, status: "DISCONNECTED" },
  });
  managers.push(manager);
  const frames: Record<string, unknown>[] = [];
  const socket = {
    readyState: 1,
    send(data: string | ArrayBuffer | Uint8Array) {
      if (typeof data === "string") frames.push(JSON.parse(data));
    },
    close() {},
  };
  const identity = {
    hostId: host.id,
    userId,
    tokenId: randomUUID(),
    credentialKind: "hostToken" as const,
    expiresAt: null,
  };
  manager.acceptAuthenticatedSocket({ socket, identity });
  manager.handleTextFrame(socket, JSON.stringify(helloFixture(host.id, false)));
  await manager.drain(socket);
  manager.handleTextFrame(
    socket,
    JSON.stringify({
      vmCapacity: { memoryBudgetMiB: 65536, maxCpuCount: 32, vcpuBudget: 64 },
      storagePools: capacityFixture(host.id).storagePools,
      journalId: "1234567890abcdef1234567890abcdef",
      type: "host.admission",
      connectionEpoch: 1,
      runtimeKind: "fake",
      schedulable: true,
      egressPolicy: true,
      terminal: false,
      ...(version === "1.0"
        ? { vmCapacity: { vcpuBudget: 64, memoryBudgetMiB: 65536, maxCpuCount: 32 } }
        : {}),
    }),
  );
  await manager.drain(socket);
  // Explicit legacy fixture evidence supports unrelated non-sizing tests.
  if (version !== "1.0")
    await db.inspect.sandboxHost.update({
      where: { id: host.id },
      data: { daemonMemoryBudgetMiB: 65536, daemonMaxCpuCount: 32 },
    });
  if (reconcile) {
    manager.handleTextFrame(
      socket,
      JSON.stringify({ type: "sandbox.inventory", page: 0, complete: true, entries: [] }),
    );
    manager.handleTextFrame(socket, JSON.stringify({ type: "reconcile.complete" }));
    await manager.drain(socket);
  }
  expect(manager.isHostConnected(host.id, 1)).toBe(reconcile);
  if (version !== "1.0")
    await db.inspect.sandboxHost.update({
      where: { id: host.id },
      data: { relayProtocolVersion: version },
    });
  // Direct carrier tests still require a durable creator/transport placement.
  const { seedTemplateRevision, seedSandboxInstance, seedAcceptedOperation } = await import(
    "../../../../packages/api/src/sandbox/testing/resource-fixtures"
  );
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      slug: "carrier",
      label: "Carrier",
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
      liveResourcesHeld: false,
      diskReservationHeld: false,
    },
  });
  const operation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId,
      sandboxId: sandbox.id,
      kind: "RUN_COMMAND",
      generation: 1,
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      state: "DISPATCHED",
      dispatchAttempt: 1,
      dispatchedHostId: host.id,
      dispatchedConnectionEpoch: 1,
    },
  });
  frames.length = 0;
  return {
    userId,
    host,
    manager,
    socket,
    frames,
    identity,
    dispatchInput: { operationId: operation.id, sandboxId: sandbox.id },
  };
}
const input = {
  connectionEpoch: 1,
  operationId: "command",
  sandboxId: "sandbox",
  idempotencyKey: "key",
  kind: "command.run",
  generation: 1,
  attempt: 1,
  argv: ["true"],
  bodyHash: "a".repeat(64),
};

it("old-epoch process.started before reconciliation is refused without a write", async () => {
  const f = await registered("1.0", false);
  const { seedTemplateRevision, seedSandboxInstance, seedAcceptedOperation } = await import(
    "../../../../packages/api/src/sandbox/testing/resource-fixtures"
  );
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.userId,
      sandboxHostId: f.host.id,
      slug: "image",
      label: "Image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: f.userId,
      templateId: revision.id,
      sandboxHostId: f.host.id,
      originHostId: f.host.id,
      state: "READY",
    },
  });
  const op = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.userId,
      sandboxId: sandbox.id,
      kind: "RUN_COMMAND",
      generation: 1,
      idempotencyKey: "old",
      requestBodyHash: "a".repeat(64),
      resultVersion: 1,
      processId: randomUUID(),
      state: "RUNNING",
      dispatchAttempt: 1,
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: 0,
    },
  });
  const before = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } });
  f.manager.handleTextFrame(
    f.socket,
    JSON.stringify({
      type: "process.started",
      operationId: op.id,
      sandboxId: sandbox.id,
      generation: 1,
      attempt: 1,
      processId: op.processId,
      pid: 42,
      bootId: "12345678-1234-4234-8234-123456789abc",
      startTicks: "123",
      startedAt: "2026-10-27T00:00:00.000Z",
      observedAt: "2026-10-27T00:00:00.001Z",
    }),
  );
  await f.manager.drain(f.socket);
  expect(await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } })).toEqual(
    before,
  );
  expect(f.frames).toEqual([]);
});
it("epoch downgrade between prepare and send refuses despite an unchanged cached 10.5 session", async () => {
  const f = await registered();
  const first = db.pauseAt("send", { after: "sandboxHost.findFirst" });
  const possible = vi.fn();
  const sending = db.run("send", () =>
    f.manager.dispatchOperation(f.host.id, {
      authorizingPrincipal: { kind: "session" },
      ...input,
      ...f.dispatchInput,
      requiresFsProcess: true,
      resultVersion: 1,
      processId: "process",
      onPossibleDispatchFrame: possible,
    }),
  );
  await first.waitReached();
  const gate = db.pauseAt("send", { before: /sql:SELECT id FROM sandbox_host/ });
  first.release();
  await gate.waitReached();
  await commitHostHello({
    identity: f.identity,
    now: new Date(),
    message: hello(f.host.id, "10.4"),
  });
  gate.release();
  expect(await sending).toBe("refused_before_frame");
  expect(possible).not.toHaveBeenCalled();
  expect(f.frames).toEqual([]);
});
it.each(
  [
    {
      shape: "required-start",
      fields: { requiresFsProcess: true, resultVersion: 1 as const, processId: "process" },
    },
    { shape: "limit alone", fields: { kind: "file.list", limit: 1 } },
    {
      shape: "continuation alone",
      fields: {
        kind: "file.list",
        continuation: {
          lastKey: "x",
          root: "/",
          depth: 1,
          limit: 1,
          generation: 1,
          kind: "LIST_DIR" as const,
        },
      },
    },
    {
      shape: "targetOperationId alone",
      fields: { kind: "file.list", targetOperationId: "target" },
    },
  ].flatMap((shape) => (["runtime", "protocol"] as const).map((change) => ({ ...shape, change }))),
)(
  "same-epoch $change downgrade between prepare and send refuses before any frame ($shape)",
  async ({ change, fields }) => {
    const f = await registered();
    const first = db.pauseAt("send", { after: "sandboxHost.findFirst" });
    const possible = vi.fn();
    const sending = db.run("send", () =>
      f.manager.dispatchOperation(f.host.id, {
        authorizingPrincipal: { kind: "session" },
        ...input,
        ...f.dispatchInput,
        ...fields,
        onPossibleDispatchFrame: possible,
      }),
    );
    await first.waitReached();
    const final = db.pauseAt("send", { before: /sql:SELECT id FROM sandbox_host/ });
    first.release();
    await final.waitReached();
    if (change === "runtime") {
      const { recordHostAdmission } = await import("./inventory-reconcile");
      expect(
        await recordHostAdmission(
          { hostId: f.host.id, userId: f.userId, connectionEpoch: 1 },
          {
            vmCapacity: { memoryBudgetMiB: 65536, maxCpuCount: 32, vcpuBudget: 64 },
            storagePools: capacityFixture(f.host.id).storagePools,
            journalId: "1234567890abcdef1234567890abcdef",
            type: "host.admission",
            connectionEpoch: 1,
            runtimeKind: "unsupported",
            schedulable: false,
            egressPolicy: false,
            terminal: false,
          },
          new Date(),
          {},
        ),
      ).toBe(true);
    } else {
      await db.inspect.sandboxHost.update({
        where: { id: f.host.id },
        data: { relayProtocolVersion: "10.7" },
      });
    }
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }))
        .connectionEpoch,
    ).toBe(1);
    final.release();
    expect(await sending).toBe("refused_before_frame");
    expect(possible).not.toHaveBeenCalled();
    expect(f.frames).toEqual([]);
  },
);
it("H stays locked from the final capability read through synchronous frame enqueue", async () => {
  const f = await registered();
  // authorizeSession reads host deletion from the credential row (no host
  // read of its own), so the first host read is the preliminary capability
  // check. Pass it; park the final H-held capability read.
  const preliminary = db.pauseAt("send", { after: "sandboxHost.findFirst" });
  const sending = db.run("send", () =>
    f.manager.dispatchOperation(f.host.id, {
      authorizingPrincipal: { kind: "session" },
      ...input,
      ...f.dispatchInput,
      requiresFsProcess: true,
      resultVersion: 1,
      processId: "process",
    }),
  );
  await preliminary.waitReached();
  const final = db.pauseAt("send", { after: "sandboxHost.findFirst" });
  preliminary.release();
  await final.waitReached();
  const downgrade = db.run("downgrade", () =>
    commitHostHello({ identity: f.identity, now: new Date(), message: hello(f.host.id, "10.4") }),
  );
  await db.waitUntilBlocked("downgrade", { by: "send" });
  expect(f.frames).toEqual([]);
  final.release();
  expect(await sending).toBe("sent");
  expect(f.frames).toHaveLength(1);
  expect(f.frames[0]).toMatchObject({
    type: "operation.dispatch",
    resultVersion: 1,
    processId: "process",
  });
  await downgrade;
});

// Internal codec conformance only: public non-kill admission stays disabled
// until the separately gated 6C cutover.
it.each(
  (["1.0"] as const).flatMap((version) =>
    (["SIGTERM", "SIGINT", "SIGHUP"] as const).map((signal) => ({ version, signal })),
  ),
)(
  "qualified $signal keeps its full identity on negotiated $version",
  async ({ signal, version }) => {
    const f = await registered(version);
    const process = {
      sandboxId: f.dispatchInput.sandboxId,
      generation: 1,
      processId: "process",
      attempt: 1,
      pid: 42,
    };
    expect(
      await f.manager.dispatchOperation(f.host.id, {
        authorizingPrincipal: { kind: "session" },
        ...input,
        ...f.dispatchInput,
        kind: "process.signal",
        requiresFsProcess: true,
        resultVersion: 1,
        process,
        targetOperationId: "target",
        signal,
      }),
    ).toBe("sent");
    expect(f.frames).toHaveLength(1);
    expect(f.frames[0]).toMatchObject({
      type: "operation.dispatch",
      kind: "process.signal",
      process,
      targetOperationId: "target",
      // E4-01: the wire pid is derived from the qualified target only.
      pid: 42,
      signal,
    });
  },
);

// Real sockets and reconciliation: refusal must not depend on a reconciled
// successor. Only the dispatch boundary is paused to install the replacement.
async function queuedStat(prior = false) {
  const { sandboxRelaySessionManager } = await import("./session-manager");
  const f = await registered("1.0", true, sandboxRelaySessionManager);
  const fixtures = await import("../../../../packages/api/src/sandbox/testing/resource-fixtures");
  const revision = await fixtures.seedTemplateRevision(db.inspect, {
    data: {
      userId: f.userId,
      sandboxHostId: f.host.id,
      slug: "image",
      label: "Image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await fixtures.seedSandboxInstance(db.inspect, {
    data: {
      userId: f.userId,
      templateId: revision.id,
      originHostId: f.host.id,
      sandboxHostId: f.host.id,
      state: "READY",
    },
  });
  const op = await fixtures.seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.userId,
      sandboxId: sandbox.id,
      generation: 1,
      kind: "STAT_PATH",
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      resultVersion: null,
    },
  });
  const { reserveOperationResult } = await import("@wssp/api/sandbox/operation-results");
  const { lockOwnerForAdmission } = await import("@wssp/db/account-deletion");
  const { lockHostByEpoch } = await import("@wssp/api/sandbox/relay-fence");
  await db.prisma.$transaction(async (tx) => {
    await lockOwnerForAdmission(tx, f.userId);
    await lockHostByEpoch(tx, f.host.id, 1, f.userId);
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandbox.id} FOR UPDATE`;
    await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${op.id} FOR UPDATE`;
    expect(await reserveOperationResult(tx, { ownerId: f.userId, operationId: op.id })).toBe(true);
  });
  if (prior)
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: {
        state: "DISPATCHED",
        dispatchAttempt: 1,
        dispatchedHostId: f.host.id,
        dispatchedConnectionEpoch: 0,
      },
    });
  await fixtures.seedDispatchEvent(db.inspect, {
    data: {
      userId: f.userId,
      aggregateType: "sandbox",
      aggregateId: sandbox.id,
      eventType: "sandbox.file_stat_requested",
      payload: {
        operationId: op.id,
        sandboxId: sandbox.id,
        sandboxHostId: f.host.id,
        generation: 1,
        dispatchAttempt: prior ? 1 : 0,
        idempotencyKey: op.idempotencyKey,
        kind: "file.stat",
        path: "/x",
        authorizingPrincipal: { kind: "session" },
      },
    },
  });
  const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
  f.manager.handleTextFrame(
    f.socket,
    JSON.stringify({
      type: "journal.key.ack",
      connectionEpoch: 1,
      keyVersion: 1,
      keyId: host.journalKeyId,
    }),
  );
  await f.manager.drain(f.socket);
  return { ...f, op, sandbox };
}
function reconcileSocket(f: Awaited<ReturnType<typeof queuedStat>>, socket: typeof f.socket) {
  f.manager.handleTextFrame(
    socket,
    JSON.stringify({
      type: "sandbox.inventory",
      page: 0,
      complete: true,
      entries: [{ sandboxOwnerId: f.userId, root: null, sandboxId: f.sandbox.id, state: "ready" }],
    }),
  );
  f.manager.handleTextFrame(socket, JSON.stringify({ type: "reconcile.complete" }));
  return f.manager.drain(socket);
}
it.each(
  [false, true].flatMap((reconcileFirst) =>
    (["first-unsent", "prior-possible", "frame-possible"] as const).map((proof) => ({
      reconcileFirst,
      proof,
    })),
  ),
)(
  "real 10.4 hello settles $proof with reconciliation first=$reconcileFirst",
  async ({ reconcileFirst, proof }) => {
    const f = await queuedStat(proof === "prior-possible");
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    const successor = { ...f.socket };
    const dispatch = f.manager.dispatchOperation.bind(f.manager);
    vi.spyOn(f.manager, "dispatchOperation").mockImplementationOnce(async (hostId, input) => {
      if (proof === "frame-possible") input.onPossibleDispatchFrame?.();
      f.manager.acceptAuthenticatedSocket({ socket: successor, identity: f.identity });
      await replaceHello(f, successor, "10.4");
      expect(f.manager.isHostConnected(f.host.id, 2)).toBe(false);
      if (reconcileFirst) await reconcileSocket(f, successor);
      // The actual old-epoch dispatch refuses before a frame on this replacement.
      return dispatch(hostId, input);
    });
    await processSandboxOutboxBatch();
    if (!reconcileFirst) await reconcileSocket(f, successor);
    expect(f.manager.isHostConnected(f.host.id, 2)).toBe(true);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } }),
    ).toMatchObject({
      state: proof === "first-unsent" ? "FAILED" : "UNKNOWN_OUTCOME",
      dispatchAttempt: proof === "prior-possible" ? 2 : 1,
    });
    expect(
      await db.inspect.sandboxOperationResult.findUniqueOrThrow({
        where: { operationId: f.op.id },
      }),
    ).toMatchObject({
      reservationState: proof === "first-unsent" ? "RELEASED" : "RESERVED",
      reservationBytes: proof === "first-unsent" ? 0 : 24576,
    });
    expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
  },
);
it.each(["protocol", "runtime"] as const)(
  "stale-epoch %s refusal proof leaves real queued work pending",
  async (change) => {
    const f = await queuedStat();
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    // Keep the real epoch-1 socket registered, while an old server's non-carry
    // increment leaves only stale refusal evidence in the database at epoch 2.
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: {
        connectionEpoch: 2,
        ...(change === "protocol"
          ? { relayProtocolVersion: "1.0" }
          : { admissionRuntime: "UNSUPPORTED" }),
      },
    });
    expect(f.manager.isHostConnected(f.host.id, 1)).toBe(true);
    expect(f.manager.isHostConnected(f.host.id, 2)).toBe(false);
    await processSandboxOutboxBatch();
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } }),
    ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
    expect(
      await db.inspect.sandboxOperationResult.findUniqueOrThrow({
        where: { operationId: f.op.id },
      }),
    ).toMatchObject({ reservationState: "RESERVED", reservationBytes: 24576 });
    expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
    // Retire the fixture through real current-epoch proof before the next batch.
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { relayProtocolVersion: "1.0", relayProtocolEpoch: 2 },
    });
    await processSandboxOutboxBatch();
  },
);

it("carried 10.4 proof while disconnected keeps queued work and its hold until reconnect", async () => {
  const f = await queuedStat();
  const { processSandboxOutboxBatch } = await import("./outbox-processor");
  const successor = { ...f.socket };
  f.manager.acceptAuthenticatedSocket({ socket: successor, identity: f.identity });
  await replaceHello(f, successor, "10.4");
  await f.manager.removeSession(successor);
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({
    connectionEpoch: 3,
    status: "DISCONNECTED",
    relayProtocolVersion: "10.4",
    relayProtocolEpoch: 3,
  });
  await processSandboxOutboxBatch();
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } }),
  ).toMatchObject({
    state: "QUEUED",
    dispatchAttempt: 0,
  });
  expect(
    await db.inspect.sandboxOperationResult.findUniqueOrThrow({ where: { operationId: f.op.id } }),
  ).toMatchObject({
    reservationState: "RESERVED",
    reservationBytes: 24576,
  });
  const reconnected = { ...f.socket };
  f.manager.acceptAuthenticatedSocket({ socket: reconnected, identity: f.identity });
  await replaceHello(f, reconnected, "10.4");
  await processSandboxOutboxBatch();
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } }),
  ).toMatchObject({
    state: "FAILED",
    errorCode: "unsupported_capability",
    dispatchAttempt: 0,
  });
  expect(
    await db.inspect.sandboxOperationResult.findUniqueOrThrow({ where: { operationId: f.op.id } }),
  ).toMatchObject({
    reservationState: "RELEASED",
    reservationBytes: 0,
  });
  expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
});

it("another scanner retiring the old claim as unsupported still permits first-unsent settlement", async () => {
  const f = await queuedStat();
  const { processSandboxOutboxBatch } = await import("./outbox-processor");
  const dispatch = f.manager.dispatchOperation.bind(f.manager);
  const successor = { ...f.socket };
  vi.spyOn(f.manager, "dispatchOperation").mockImplementationOnce(async (hostId, input) => {
    f.manager.acceptAuthenticatedSocket({ socket: successor, identity: f.identity });
    await replaceHello(f, successor, "10.4");
    // A nested independent scan stands in for a different server process.
    await processSandboxOutboxBatch();
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } }),
    ).toMatchObject({
      state: "UNKNOWN_OUTCOME",
      errorCode: "unsupported_capability",
      dispatchAttempt: 1,
    });
    return dispatch(hostId, input);
  });
  await processSandboxOutboxBatch();
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } }),
  ).toMatchObject({
    state: "FAILED",
    errorCode: "unsupported_capability",
    dispatchAttempt: 1,
  });
  expect(
    await db.inspect.sandboxOperationResult.findUniqueOrThrow({ where: { operationId: f.op.id } }),
  ).toMatchObject({
    reservationState: "RELEASED",
    reservationBytes: 0,
  });
  expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
});

it.each(["pid", "acceptance", "dispatch-epoch", "error-code", "same-epoch"] as const)(
  "refinement refuses defensive state with %s",
  async (predicate) => {
    const f = await queuedStat();
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    const dispatch = f.manager.dispatchOperation.bind(f.manager);
    const successor = { ...f.socket };
    let before: Awaited<ReturnType<typeof db.inspect.sandboxOperation.findUniqueOrThrow>>;
    vi.spyOn(f.manager, "dispatchOperation").mockImplementationOnce(async (hostId, input) => {
      const event = await db.inspect.outboxEvent.findFirstOrThrow({
        where: { aggregateId: f.sandbox.id },
      });
      f.manager.acceptAuthenticatedSocket({ socket: successor, identity: f.identity });
      await replaceHello(f, successor, "10.4");
      await reconcileSocket(f, successor);
      // These synthetic inconsistent states cannot arise from this no-frame
      // first claim. O serializes real receipt/acceptance writers with settle;
      // repeat CAS predicates cannot independently race after its guarded read.
      before = await db.inspect.sandboxOperation.update({
        where: { id: f.op.id },
        data: {
          ...(predicate === "pid" ? { processPid: 42 } : {}),
          ...(predicate === "acceptance" ? { acceptedAttempt: 1 } : {}),
          ...(predicate === "dispatch-epoch" ? { dispatchedConnectionEpoch: 2 } : {}),
          ...(predicate === "error-code" ? { errorCode: "superseded" } : {}),
        },
      });
      if (predicate === "same-epoch") {
        await db.inspect.sandboxHost.update({
          where: { id: f.host.id },
          data: { connectionEpoch: 1, relayProtocolEpoch: 1, admissionEpoch: 1 },
        });
        // Preserve the old claim so the event fence alone cannot mask the
        // newer-epoch requirement when its fault is injected.
        await db.inspect.outboxEvent.update({
          where: { id: event.id },
          data: { claimToken: event.claimToken },
        });
      }
      return dispatch(hostId, input);
    });
    await processSandboxOutboxBatch();
    expect(await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } })).toEqual(
      before!,
    );
    expect(before!.state).toBe("UNKNOWN_OUTCOME");
    expect(
      await db.inspect.sandboxOperationResult.findUniqueOrThrow({
        where: { operationId: f.op.id },
      }),
    ).toMatchObject({
      reservationState: "RESERVED",
      reservationBytes: 24576,
    });
    expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
  },
);

async function timerCommand(version = "1.0") {
  const { sandboxRelaySessionManager } = await import("./session-manager");
  const f = await registered(version, true, sandboxRelaySessionManager);
  const fixtures = await import("../../../../packages/api/src/sandbox/testing/resource-fixtures");
  const revision = await fixtures.seedTemplateRevision(db.inspect, {
    data: {
      userId: f.userId,
      sandboxHostId: f.host.id,
      slug: "timer",
      label: "Timer",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await fixtures.seedSandboxInstance(db.inspect, {
    data: {
      userId: f.userId,
      templateId: revision.id,
      originHostId: f.host.id,
      sandboxHostId: f.host.id,
      state: "READY",
    },
  });
  const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
  f.manager.handleTextFrame(
    f.socket,
    JSON.stringify({
      type: "journal.key.ack",
      connectionEpoch: 1,
      keyVersion: 1,
      keyId: host.journalKeyId,
    }),
  );
  await f.manager.drain(f.socket);
  const { runCommand } = await import("@wssp/api/sandbox/services/sandboxes");
  const accept = (timeoutMs?: number, key = randomUUID()) =>
    runCommand({ kind: "session", ownerId: f.userId }, {
      id: sandbox.id,
      idempotencyKey: key,
      argv: ["true"],
      timeoutMs,
    } as Parameters<typeof runCommand>[1]);
  const events = () =>
    db.inspect.outboxEvent.findMany({
      where: { userId: f.userId },
      orderBy: { createdAt: "asc" },
      take: 100,
    });
  return { ...f, sandbox, accept, events };
}

it.each([undefined, 0, 1, 120000, 300000, 1800000])(
  "D-20 production persist through live dispatched frame retains %s",
  async (timeoutMs) => {
    zeroPolicy.enabled = true;
    const f = await timerCommand();
    const accepted = await f.accept(timeoutMs);
    const events = await f.events();
    expect(events).toHaveLength(1);
    expect(events[0]?.payload).toMatchObject({
      timeoutMs: timeoutMs ?? 120000,
      privateConfig: { configId: expect.any(String) },
    });
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    await processSandboxOutboxBatch();
    const frame = f.frames.find((frame) => frame.type === "operation.dispatch");
    const operation = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: accepted.operationId },
    });
    expect(frame).toMatchObject({
      kind: "command.run",
      operationId: accepted.operationId,
      timeoutMs: timeoutMs ?? 120000,
      bodyHash: operation.requestBodyHash,
    });
  },
);

it.each([false, true])(
  "a typed unknown command result preserves the relay and other terminal bindings (started: %s)",
  async (started) => {
    zeroPolicy.enabled = true;
    const f = await timerCommand();
    const accepted = await f.accept(300_000);
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    await processSandboxOutboxBatch();
    const op = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: accepted.operationId },
    });
    const observedAt = new Date().toISOString();
    const birth = started
      ? {
          type: "process.started",
          operationId: op.id,
          sandboxId: f.sandbox.id,
          generation: 1,
          attempt: 1,
          processId: op.processId,
          pid: 42,
          bootId: "12345678-1234-4234-8234-123456789abc",
          startTicks: "123",
          startedAt: observedAt,
          observedAt,
        }
      : null;
    if (birth) {
      f.manager.handleTextFrame(f.socket, JSON.stringify(birth));
      await f.manager.drain(f.socket);
      expect(
        await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } }),
      ).toMatchObject({ processPid: 42 });
    }
    const close = vi.spyOn(f.socket, "close");
    const terminals = Reflect.get(
      f.manager,
      "terminals",
    ) as import("./terminal-manager").SandboxTerminalManager;
    const removeTerminals = vi.spyOn(terminals, "removeHostSocket");
    f.manager.handleTextFrame(
      f.socket,
      JSON.stringify({
        type: "operation.result",
        id: "unknown-command",
        operationId: accepted.operationId,
        sandboxId: f.sandbox.id,
        generation: 1,
        attempt: 1,
        state: "unknown_outcome",
        error: { code: "unknown_outcome", message: "unknown_outcome" },
        result: {
          version: 1,
          observedAt,
          payload: birth
            ? {
                type: "command",
                process: {
                  sandboxId: birth.sandboxId,
                  generation: 1,
                  attempt: 1,
                  processId: birth.processId,
                  pid: birth.pid,
                },
                startedAt: birth.startedAt,
                exitCode: null,
              }
            : null,
          birth,
          continuation: null,
          failure: { resource: "command", effect: "unknown" },
        },
      }),
    );
    f.manager.handleTextFrame(f.socket, JSON.stringify({ type: "heartbeat", id: "after-unknown" }));
    await f.manager.drain(f.socket);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }),
    ).toMatchObject({ state: "UNKNOWN_OUTCOME" });
    expect(f.frames).toContainEqual(
      expect.objectContaining({ type: "heartbeat.pong", id: "after-unknown" }),
    );
    expect(f.manager.isHostConnected(f.host.id, 1)).toBe(true);
    expect(close).not.toHaveBeenCalled();
    expect(removeTerminals).not.toHaveBeenCalled();
  },
);

it("D-20 canonical replay preserves zero and unifies omission with the explicit default", async () => {
  zeroPolicy.enabled = true;
  const f = await timerCommand();
  const key = randomUUID();
  const zero = await f.accept(0, key);
  expect(await f.accept(0, key)).toEqual(zero);
  await expect(f.accept(120000, key)).rejects.toMatchObject({ code: "CONFLICT" });
  await expect(f.accept(undefined, key)).rejects.toMatchObject({ code: "CONFLICT" });
  const timedKey = randomUUID();
  expect(await f.accept(undefined, timedKey)).toEqual(await f.accept(120000, timedKey));
  const events = await f.events();
  expect(events).toHaveLength(2);
  const rows = await db.inspect.sandboxOperation.findMany({
    where: { userId: f.userId, sandboxId: f.sandbox.id, kind: "RUN_COMMAND" },
    take: 10,
  });
  expect(new Set(rows.map((row) => row.requestBodyHash)).size).toBe(2);
});

it.each(["off", "old", "unknown", "runtime"])(
  "D-20 %s refuses zero before receipt or outbox",
  async (mode) => {
    zeroPolicy.enabled = mode !== "off";
    const f = await timerCommand(mode === "old" ? "10.7" : "1.0");
    if (mode === "unknown" || mode === "runtime")
      await db.inspect.sandboxHost.update({
        where: { id: f.host.id },
        data:
          mode === "unknown" ? { relayProtocolEpoch: null } : { admissionRuntime: "UNSUPPORTED" },
      });
    if (mode === "unknown") {
      // Missing protocol facts prove no downgrade: zero is admitted and queued;
      // the send itself still requires current-epoch support.
      await expect(f.accept(0)).resolves.toMatchObject({ state: "QUEUED" });
      expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
      return;
    }
    await expect(f.accept(0)).rejects.toMatchObject(
      mode === "off" ? { code: "BAD_REQUEST" } : { data: { code: "UNSUPPORTED_CAPABILITY" } },
    );
    expect(await f.events()).toEqual([]);
    expect(
      await db.inspect.sandboxOperation.count({
        where: { userId: f.userId, sandboxId: f.sandbox.id, kind: "RUN_COMMAND" },
      }),
    ).toBe(0);
    expect(await db.inspect.sandboxOperationResult.count({ where: { userId: f.userId } })).toBe(0);
  },
);

it.each(["first-unsent", "prior-possible", "frame-possible"] as const)(
  "D-20 downgrade at live send preserves C-26 for %s",
  async (proof) => {
    zeroPolicy.enabled = true;
    const f = await timerCommand();
    const accepted = await f.accept(0);
    if (proof === "prior-possible")
      await db.inspect.sandboxOperation.update({
        where: { id: accepted.operationId },
        data: {
          state: "DISPATCHED",
          dispatchAttempt: 1,
          dispatchedHostId: f.host.id,
          dispatchedConnectionEpoch: 0,
        },
      });
    const dispatch = f.manager.dispatchOperation.bind(f.manager);
    const successor = { ...f.socket };
    vi.spyOn(f.manager, "dispatchOperation").mockImplementationOnce(async (hostId, input) => {
      if (proof === "frame-possible") input.onPossibleDispatchFrame?.();
      f.manager.acceptAuthenticatedSocket({ socket: successor, identity: f.identity });
      await replaceHello(f, successor, "10.4");
      return dispatch(hostId, input);
    });
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    await processSandboxOutboxBatch();
    f.manager.handleTextFrame(
      successor,
      JSON.stringify({
        type: "sandbox.inventory",
        page: 0,
        complete: true,
        entries: [
          { sandboxOwnerId: f.userId, root: null, sandboxId: f.sandbox.id, state: "ready" },
        ],
      }),
    );
    f.manager.handleTextFrame(successor, JSON.stringify({ type: "reconcile.complete" }));
    await f.manager.drain(successor);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }),
    ).toMatchObject({
      state: proof === "first-unsent" ? "FAILED" : "UNKNOWN_OUTCOME",
      errorCode: proof === "frame-possible" ? "unknown_outcome" : "unsupported_capability",
    });
    expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
  },
);

it.each([false, true])(
  "D-20 immediate send refuses unnegotiated zero (switch=%s)",
  async (enabled) => {
    zeroPolicy.enabled = enabled;
    const f = await registered("10.4");
    expect(
      await f.manager.dispatchOperation(f.host.id, {
        authorizingPrincipal: { kind: "session" },
        ...input,
        ...f.dispatchInput,
        timeoutMs: 0,
      }),
    ).toBe("refused_before_frame");
    expect(f.frames).toEqual([]);
  },
);

it("D-20 zero survives nonempty private defaults through the live frame", async () => {
  zeroPolicy.enabled = true;
  const f = await timerCommand();
  const config = await db.inspect.sandboxExecutionConfig.findUniqueOrThrow({
    where: { sandboxId: f.sandbox.id },
  });
  const { privateConfigBinding } = await import("@wssp/api/sandbox/idempotency");
  const binding = privateConfigBinding(
    { configId: config.id, sandboxId: f.sandbox.id, generation: 1, env: [["DEFAULT", "present"]] },
    { ownerId: f.userId, hostOwnerId: f.userId, hostId: f.host.id, authorizingKeyId: null },
  );
  await db.inspect.sandboxExecutionConfig.update({
    where: { id: config.id },
    data: {
      templateDefaults: { DEFAULT: "present" },
      mergedDefaults: { DEFAULT: "present" },
      bindingScheme: binding.bindingScheme,
      bindingKeyId: binding.bindingKeyId,
      bindingMac: binding.bindingMac,
    },
  });
  const accepted = await f.accept(0);
  const { processSandboxOutboxBatch } = await import("./outbox-processor");
  await processSandboxOutboxBatch();
  expect(f.frames.find((frame) => frame.type === "operation.dispatch")).toMatchObject({
    operationId: accepted.operationId,
    timeoutMs: 0,
    privateConfig: { configId: config.id },
  });
});

it("D-20 zero and default race on one key accepts exactly one intent", async () => {
  zeroPolicy.enabled = true;
  const f = await timerCommand();
  const key = randomUUID();
  const results = await Promise.allSettled([f.accept(0, key), f.accept(120000, key)]);
  expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
  expect(results.filter((result) => result.status === "rejected")).toMatchObject([
    { reason: { code: "CONFLICT" } },
  ]);
  expect(await f.events()).toHaveLength(1);
  expect(
    await db.inspect.sandboxOperation.count({
      where: { userId: f.userId, sandboxId: f.sandbox.id, kind: "RUN_COMMAND" },
    }),
  ).toBe(1);
});

it("D-20 admission waits for H before reading a competing downgrade", async () => {
  zeroPolicy.enabled = true;
  const f = await timerCommand();
  const gate = db.pauseAt("downgrade", { before: "$transaction.commit" });
  const downgrade = db.run("downgrade", () =>
    commitHostHello({ identity: f.identity, now: new Date(), message: hello(f.host.id, "10.4") }),
  );
  await gate.waitReached();
  const accepting = db.run("accept-zero", () => f.accept(0));
  const denied = expect(accepting).rejects.toMatchObject({ code: "CONFLICT" });
  await db.waitUntilBlocked("accept-zero", { by: "downgrade" });
  gate.release();
  const epoch = await downgrade;
  await denied;
  // Post-hello, pre-admission: the runtime is not yet reported, so admission
  // is not refused as unsupported; the in-flight key ACK holds zero with the
  // transient reconnect refusal.
  await expect(f.accept(0)).rejects.toMatchObject({ data: { code: "sandbox.host_reconnecting" } });
  // The replacement's admission report of an unsupported runtime is proof.
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { admissionEpoch: epoch, admissionRuntime: "UNSUPPORTED" },
  });
  await expect(f.accept(0)).rejects.toMatchObject({ data: { code: "UNSUPPORTED_CAPABILITY" } });
  expect(await f.events()).toEqual([]);
});

it.each([null, "0", -1, 0.5, 1800001])(
  "D-20 malformed persisted timeout %s refuses instead of defaulting",
  async (timeoutMs) => {
    zeroPolicy.enabled = true;
    const f = await timerCommand();
    const accepted = await f.accept(1000);
    const event = (await f.events())[0]!;
    await db.inspect.outboxEvent.update({
      where: { id: event.id },
      data: { payload: { ...(event.payload as Record<string, unknown>), timeoutMs } },
    });
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    await processSandboxOutboxBatch();
    expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }),
    ).toMatchObject({ state: "FAILED", errorCode: "protocol_error" });
  },
);

it("D-20 disabling the landing switch refuses an already queued zero without remapping", async () => {
  zeroPolicy.enabled = true;
  const f = await timerCommand();
  const accepted = await f.accept(0);
  zeroPolicy.enabled = false;
  const { processSandboxOutboxBatch } = await import("./outbox-processor");
  await processSandboxOutboxBatch();
  expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }),
  ).toMatchObject({ state: "FAILED", errorCode: "unsupported_capability", dispatchAttempt: 0 });
});

it("D-20 carried offline support reaches key-ACK refusal while original zero replay stays exact", async () => {
  zeroPolicy.enabled = true;
  const f = await timerCommand();
  const key = randomUUID();
  const accepted = await f.accept(0, key);
  const { disconnectJournalKey } = await import("./journal-key-ack");
  expect(await disconnectJournalKey({ ...f.identity, connectionEpoch: 1 }, new Date(), true)).toBe(
    true,
  );
  expect(await f.accept(0, key)).toEqual(accepted);
  await expect(f.accept(0)).rejects.toMatchObject({ data: { code: "sandbox.host_unavailable" } });
  const { getSandboxCapabilities } = await import("@wssp/api/sandbox/services/capabilities");
  expect(
    await getSandboxCapabilities({ kind: "session", ownerId: f.userId }, { id: f.sandbox.id }),
  ).toMatchObject({ unavailableReason: "host_unavailable", limits: { commandTimeoutZero: true } });
  expect(await f.events()).toHaveLength(1);
  expect((await f.events())[0]?.payload).toMatchObject({ timeoutMs: 0 });
  expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
});

async function queuedSignal() {
  const { sandboxRelaySessionManager } = await import("./session-manager");
  const f = await registered("1.0", true, sandboxRelaySessionManager);
  const fixtures = await import("../../../../packages/api/src/sandbox/testing/resource-fixtures");
  const revision = await fixtures.seedTemplateRevision(db.inspect, {
    data: {
      userId: f.userId,
      sandboxHostId: f.host.id,
      slug: "image",
      label: "Image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await fixtures.seedSandboxInstance(db.inspect, {
    data: {
      userId: f.userId,
      templateId: revision.id,
      originHostId: f.host.id,
      sandboxHostId: f.host.id,
      state: "READY",
    },
  });
  const target = await fixtures.seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.userId,
      sandboxId: sandbox.id,
      generation: 1,
      kind: "RUN_COMMAND",
      state: "RUNNING",
      resultVersion: 1,
      dispatchAttempt: 1,
      acceptedAttempt: 1,
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: 1,
      processId: randomUUID(),
      processPid: 42,
      processBootId: randomUUID(),
      processStartTicks: "123",
      processStartedAt: new Date(),
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
    },
  });
  const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
  f.manager.handleTextFrame(
    f.socket,
    JSON.stringify({
      type: "journal.key.ack",
      connectionEpoch: 1,
      keyVersion: 1,
      keyId: host.journalKeyId,
    }),
  );
  await f.manager.drain(f.socket);
  f.frames.length = 0;
  const process = {
    sandboxId: sandbox.id,
    generation: 1,
    attempt: 1,
    processId: target.processId!,
    pid: 42,
  };
  const { signalProcessAction } = await import("@wssp/api/sandbox/process-signals");
  const { getSandboxCapabilities } = await import("@wssp/api/sandbox/services/capabilities");
  const owner = { kind: "session" as const, ownerId: f.userId };
  const capabilities = await getSandboxCapabilities(owner, { id: sandbox.id });
  expect(capabilities.guestApi.supportedSignals.includes("SIGTERM")).toBe(true);
  const receipt = await signalProcessAction(owner, {
    process,
    signal: "SIGTERM",
    idempotencyKey: randomUUID(),
  });
  expect(receipt.state).toBe("QUEUED");
  expect(
    await db.inspect.outboxEvent.count({
      where: {
        userId: f.userId,
        eventType: "sandbox.process_signal_requested",
        processedAt: null,
      },
    }),
  ).toBe(1);
  return { f, sandbox, target, process, receipt };
}

it("signal admission through outbox sends a qualified frame", async () => {
  const { f, sandbox, target, process, receipt } = await queuedSignal();
  const { processSandboxOutboxBatch } = await import("./outbox-processor");
  await processSandboxOutboxBatch();
  const frames = f.frames.filter((frame) => frame.type === "operation.dispatch");
  expect(
    frames,
    JSON.stringify({
      operation: await db.inspect.sandboxOperation.findUnique({
        where: { id: receipt.operationId },
        select: { state: true, errorCode: true, dispatchAttempt: true },
      }),
      events: await db.inspect.outboxEvent.findMany({
        where: { userId: f.userId },
        select: { processedAt: true, claimToken: true, sentAt: true },
      }),
      frameTypes: f.frames.map((frame) => frame.type),
    }),
  ).toHaveLength(1);
  expect(frames[0]).toMatchObject({
    type: "operation.dispatch",
    operationId: receipt.operationId,
    kind: "process.signal",
    signal: "SIGTERM",
    process,
    // E4-01: the queued payload carries only `process`; the daemon requires
    // the wire pid to repeat process.pid or it refuses the dispatch.
    pid: process.pid,
    targetOperationId: target.id,
    sandboxId: sandbox.id,
    generation: 1,
    attempt: 1,
    resultVersion: 1,
  });
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: receipt.operationId } }),
  ).toMatchObject({ state: "DISPATCHED", dispatchAttempt: 1 });
});

// E4-01: the daemon refuses an invalid signal dispatch as one operation
// (`refuse_invalid_dispatch`, the exact frame below). The server must settle
// it, keep the session, and leave nothing for a reconnect audit to redeliver.
it("a daemon's per-operation signal refusal settles it without redispatch", async () => {
  const { f, sandbox, receipt } = await queuedSignal();
  const { processSandboxOutboxBatch } = await import("./outbox-processor");
  await processSandboxOutboxBatch();
  expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toHaveLength(1);
  const close = vi.spyOn(f.socket, "close");
  f.manager.handleTextFrame(
    f.socket,
    JSON.stringify({
      type: "operation.result",
      id: `result-${receipt.operationId}`,
      operationId: receipt.operationId,
      sandboxId: sandbox.id,
      generation: 1,
      attempt: 1,
      state: "failed",
      error: {
        code: "protocol_error",
        message: "invalid process identity field",
        operationId: receipt.operationId,
        sandboxId: sandbox.id,
      },
    }),
  );
  f.manager.handleTextFrame(f.socket, JSON.stringify({ type: "heartbeat", id: "after-refusal" }));
  await f.manager.drain(f.socket);
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: receipt.operationId } }),
  ).toMatchObject({ state: "FAILED", errorCode: "protocol_error", dispatchAttempt: 1 });
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: f.userId, aggregateId: sandbox.id, processedAt: null },
    }),
  ).toBe(0);
  expect(f.frames).toContainEqual(
    expect.objectContaining({ type: "heartbeat.pong", id: "after-refusal" }),
  );
  expect(f.manager.isHostConnected(f.host.id, 1)).toBe(true);
  expect(close).not.toHaveBeenCalled();
  f.frames.length = 0;
  await processSandboxOutboxBatch();
  expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toHaveLength(0);
});

it.each([
  "match",
  "payload",
  "placement",
  "missing",
  "epoch",
  "absent-sandbox",
  "advanced-generation",
] as const)(
  "B5 launch %s is checked against S and its pinned placement under H before send",
  async (condition) => {
    const f = await registered("1.0");
    const { seedTemplateRevision, seedSandboxInstance, seedAcceptedOperation } = await import(
      "../../../../packages/api/src/sandbox/testing/resource-fixtures"
    );
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.userId,
        sandboxHostId: f.host.id,
        slug: "sized",
        label: "Sized",
        incusFingerprint: `sha256:${"a".repeat(64)}`,
      },
    });
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        diskGiB: 32,
        userId: f.userId,
        templateId: revision.id,
        sandboxHostId: f.host.id,
        originHostId: f.host.id,
        state: "PROVISIONING",
        cpuCount: 2,
        memoryMiB: 2048,
      },
    });
    const operation = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: f.userId,
        sandboxId: sandbox.id,
        kind: "CREATE_SANDBOX",
        state: "DISPATCHED",
        generation: 1,
        dispatchAttempt: 1,
        dispatchedHostId: f.host.id,
        dispatchedConnectionEpoch: 1,
        idempotencyKey: randomUUID(),
        requestBodyHash: "a".repeat(64),
      },
    });
    const allocation = {
      cpuCount: 2,
      memoryMiB: 2048,
      diskGiB: 32,
      storagePoolName: sandbox.storagePoolName!,
      storageMarker: sandbox.storageMarker!,
      chargedMemoryMiB: vmLiveMemoryChargeMiB(2048),
      chargedVcpu: 2,
      rootChargeGiB: 33,
    };
    await db.inspect.outboxEvent.create({
      data: {
        userId: f.userId,
        aggregateType: "sandbox",
        aggregateId: sandbox.id,
        eventType: "sandbox.create_requested",
        operationId: operation.id,
        payload: {
          operationId: operation.id,
          allocationJournalEpoch: 1,
          allocationJournalAttempt: 1,
        },
      },
    });
    if (condition === "placement")
      await db.inspect.sandboxPlacement.update({
        where: { id: sandbox.currentPlacementId! },
        data: { memoryMiB: 3072, chargedMemoryMiB: vmLiveMemoryChargeMiB(3072) },
      });
    if (condition === "advanced-generation")
      await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { generation: 2 } });
    const possible = vi.fn();
    const gate =
      condition === "epoch"
        ? db.pauseAt("sized-send", { before: /sql:SELECT id FROM sandbox_host/ })
        : undefined;
    const send = db.run("sized-send", () =>
      f.manager.dispatchOperation(f.host.id, {
        authorizingPrincipal: { kind: "session" },
        allocation,
        connectionEpoch: 1,
        operationId: operation.id,
        sandboxId: condition === "absent-sandbox" ? randomUUID() : sandbox.id,
        idempotencyKey: operation.idempotencyKey,
        kind: "sandbox.create",
        generation: 1,
        attempt: 1,
        bodyHash: "a".repeat(64),
        cpuCount: 2,
        ...(condition === "missing"
          ? {}
          : { memoryMiB: condition === "payload" || condition === "placement" ? 3072 : 2048 }),
        incusFingerprint: revision.incusFingerprint,
        architecture: revision.architecture,
        egressPolicy: { domains: [], cidrs: [] },
        egressPolicyHash: "b".repeat(64),
        lease: {
          revision: 1,
          deadlineUnixMs: Date.now() + 300000,
          action: "stop",
          expiryPolicy: "retry-force-60s",
        },
        onPossibleDispatchFrame: possible,
      }),
    );
    if (gate) {
      await gate.waitReached();
      await commitHostHello({
        identity: f.identity,
        now: new Date(),
        message: hello(f.host.id, "1.0"),
      });
      gate.release();
    }
    if (condition === "match") {
      expect(await send).toBe("sent");
      expect(possible).toHaveBeenCalledOnce();
      expect(f.frames.find((frame) => frame.type === "operation.dispatch")).toMatchObject({
        allocation: { diskGiB: 32 },
        cpuCount: 2,
        memoryMiB: 2048,
      });
    } else if (["epoch", "absent-sandbox", "advanced-generation"].includes(condition)) {
      await expect(send).resolves.toBe("refused_before_frame");
      expect(possible).not.toHaveBeenCalled();
      expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
    } else {
      await expect(send).rejects.toThrow("VM allocation mismatch.");
      expect(possible).not.toHaveBeenCalled();
      expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
    }
  },
);

it.each(["1.0"])(
  "B5 sandbox capability on %s exposes allocation support without host budgets",
  async (version) => {
    const f = await registered(version);
    const { seedTemplateRevision, seedSandboxInstance } = await import(
      "../../../../packages/api/src/sandbox/testing/resource-fixtures"
    );
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.userId,
        sandboxHostId: f.host.id,
        slug: "cap-size",
        label: "Capacity",
        incusFingerprint: `sha256:${"a".repeat(64)}`,
      },
    });
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: f.userId,
        templateId: revision.id,
        sandboxHostId: f.host.id,
        originHostId: f.host.id,
        state: "READY",
      },
    });
    const { getSandboxCapabilities } = await import("@wssp/api/sandbox/services/capabilities");
    const read = () =>
      getSandboxCapabilities({ kind: "session", ownerId: f.userId }, { id: sandbox.id });
    const capable = await read();
    expect(capable.features.includes("sandboxes.vmSize")).toBe(version === "1.0");
    expect(capable.features).toContain("files.metadata");
    expect(JSON.stringify(capable)).not.toMatch(
      /memoryBudgetMiB|memoryReservedMiB|maxCpuCount|maxMemoryMiB/,
    );
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { status: "DISCONNECTED" },
    });
    const offline = await read();
    expect(offline.features).not.toContain("sandboxes.vmSize");
    expect(offline.unavailableReason).toBe("host_unavailable");
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { status: "CONNECTED", daemonMemoryBudgetMiB: null },
    });
    expect((await read()).features).not.toContain("sandboxes.vmSize");
  },
);

it("B5 outbox size mismatch fails the first unsent launch while retaining its live slot and RAM", async () => {
  const { sandboxRelaySessionManager } = await import("./session-manager");
  const f = await registered("1.0", true, sandboxRelaySessionManager);
  const { seedTemplateRevision, acknowledgeFixtureExecutionConfigs } = await import(
    "../../../../packages/api/src/sandbox/testing/resource-fixtures"
  );
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.userId,
      sandboxHostId: f.host.id,
      slug: "outbox-size",
      label: "Outbox size",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
  f.manager.handleTextFrame(
    f.socket,
    JSON.stringify({
      type: "journal.key.ack",
      connectionEpoch: 1,
      keyVersion: 1,
      keyId: host.journalKeyId,
    }),
  );
  await f.manager.drain(f.socket);
  // Stage current capacity and egress-guard evidence (default-open egress
  // M11: a create needs an active guard lease at the current epoch)
  // independently of this legacy wire fixture.
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: {
      daemonVcpuBudget: 64,
      daemonEgressGuardOk: true,
      daemonEgressGuardEpoch: 1,
      daemonEgressGuardLeaseUntil: new Date("2999-01-01T00:00:00.000Z"),
    },
  });
  await db.inspect.sandboxHostStoragePool.updateMany({
    where: { sandboxHostId: f.host.id },
    data: { connectionEpoch: 1, reportedAt: new Date() },
  });
  const { createSandbox } = await import("@wssp/api/sandbox/services/sandboxes");
  const sandbox = await createSandbox(
    { kind: "session", ownerId: f.userId },
    {
      diskGiB: 32,
      template: `revision/${revision.id}`,
      sandboxHostId: f.host.id,
      cpuCount: 2,
      memoryMiB: 2048,
      idempotencyKey: randomUUID(),
    },
  );
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
  });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: sandbox.id },
  });
  await db.inspect.outboxEvent.update({
    where: { id: event.id },
    data: {
      payload: { ...(event.payload as Record<string, string>), memoryMiB: 3072 },
    },
  });
  f.frames.length = 0;
  const { processSandboxOutboxBatch } = await import("./outbox-processor");
  expect(await processSandboxOutboxBatch()).toBe(0);
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operation.id } }),
  ).toMatchObject({
    state: "FAILED",
    errorCode: "vm_size_mismatch",
    dispatchAttempt: 1,
    acceptedAttempt: null,
  });
  expect(await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: event.id } })).toMatchObject(
    {
      processedAt: expect.any(Date),
      sentAt: null,
      claimToken: null,
    },
  );
  expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } })).toMatchObject({
    diskGiB: 32,
    liveResourcesHeld: true,
    cpuCount: 2,
    memoryMiB: 2048,
  });
  expect(
    await db.inspect.sandboxPlacement.findFirstOrThrow({
      where: { sandboxId: sandbox.id, generation: 1 },
    }),
  ).toMatchObject({ diskGiB: 32, cpuCount: 2, memoryMiB: 2048 });
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({
    liveCount: 1,
    memoryReservedMiB: vmLiveMemoryChargeMiB(2048),
    vcpuReserved: 2,
  });
  expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
});

it.each(["10.0", "10.4", "10.5", "10.6", "10.7", "11.1"])(
  "stored version %s cannot gain 1.0 authority",
  async (version) => {
    const f = await registered();
    const { requireFsProcessHost } = await import("@wssp/api/sandbox/host-protocol");
    await expect(
      db.prisma.$transaction((tx) => requireFsProcessHost(tx, f.userId, f.host.id)),
    ).resolves.toMatchObject({ relayProtocolVersion: "1.0" });
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { relayProtocolVersion: version },
    });
    await expect(
      db.prisma.$transaction((tx) => requireFsProcessHost(tx, f.userId, f.host.id)),
    ).rejects.toMatchObject({ data: { code: "UNSUPPORTED_CAPABILITY" } });
  },
);

async function replaceHello(
  f: Awaited<ReturnType<typeof registered>>,
  socket: Parameters<InstanceType<typeof SandboxRelaySessionManager>["handleTextFrame"]>[0],
  storedVersion: string,
) {
  f.manager.handleTextFrame(socket, JSON.stringify(helloFixture(f.host.id, false)));
  await f.manager.drain(socket);
  // Simulate a historical stored snapshot without accepting an old wire peer.
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { relayProtocolVersion: storedVersion },
  });
}

// Three distinct parties ensure the graph owner's ticket, rather than a
// coincidentally shared creator/transport-owner ticket, fences the send.
it.each(["delete", "remove", "ownHostsOnly", "withdraw", "leave", "revoke"] as const)(
  "r1 %s commits after path authorization and before final send: zero guest-effect frames (real PG barriers)",
  async (withdrawal) => {
    const f = await registered();
    const { seedTemplateRevision, seedSandboxInstance, seedAcceptedOperation } = await import(
      "../../../../packages/api/src/sandbox/testing/resource-fixtures"
    );
    const { deletePool, removePoolMember, updatePool } = await import(
      "../../../../packages/api/src/sandbox/services/pools"
    );
    const { withdrawPoolHost, leavePool, revokePoolShare } = await import(
      "../../../../packages/api/src/sandbox/services/sharing"
    );
    const parties = await Promise.all(
      ["pool", "creator"].map((name) => {
        const id = randomUUID();
        return db.inspect.user.create({
          data: {
            id,
            name,
            email: `${id}@example.test`,
            emailVerified: true,
            twoFactorEnabled: true,
          },
        });
      }),
    );
    const [poolOwner, creator] = parties;
    if (!poolOwner || !creator) throw new Error("Missing parties");
    const pool = await db.inspect.sandboxPool.create({
      data: {
        userId: poolOwner.id,
        slug: randomUUID(),
        label: "Shared",
      },
    });
    const contribution = await db.inspect.share.create({
      data: {
        poolId: pool.id,
        ownerUserId: poolOwner.id,
        granteeUserId: f.userId,
        canUse: false,
        canContribute: true,
      },
    });
    await db.inspect.share.create({
      data: {
        poolId: pool.id,
        ownerUserId: poolOwner.id,
        granteeUserId: creator.id,
        canUse: true,
        canContribute: false,
      },
    });
    const member = await db.inspect.sandboxPoolMember.create({
      data: {
        poolId: pool.id,
        sandboxHostId: f.host.id,
        userId: poolOwner.id,
        hostOwnerId: f.userId,
        shareId: contribution.id,
        contributeWitness: true,
        ownHostsOnlyWitness: false,
      },
    });
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: creator.id,
        slug: randomUUID(),
        label: "Private",
        incusFingerprint: `sha256:${"b".repeat(64)}`,
      },
    });
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: creator.id,
        hostOwnerId: f.userId,
        templateId: revision.id,
        sandboxHostId: f.host.id,
        originHostId: f.host.id,
        state: "READY",
        usagePoolId: pool.id,
        usageMemberId: member.id,
        liveResourcesHeld: false,
        diskReservationHeld: false,
      },
    });
    const operation = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: creator.id,
        sandboxId: sandbox.id,
        kind: "RUN_COMMAND",
        generation: 1,
        idempotencyKey: randomUUID(),
        requestBodyHash: "a".repeat(64),
        state: "DISPATCHED",
        dispatchAttempt: 1,
        dispatchedHostId: f.host.id,
        dispatchedConnectionEpoch: 1,
      },
    });
    const path = db.pauseAt("sharing-send", { after: "sandboxPoolMember.findFirst" });
    const possible = vi.fn();
    const sending = db.run("sharing-send", () =>
      f.manager.dispatchOperation(f.host.id, {
        authorizingPrincipal: { kind: "session" },
        ...input,
        operationId: operation.id,
        sandboxId: sandbox.id,
        requiresFsProcess: true,
        resultVersion: 1,
        processId: randomUUID(),
        onPossibleDispatchFrame: possible,
      }),
    );
    let final: ReturnType<typeof db.pauseAt> | undefined;
    try {
      await path.waitReached();
      // The authorizer releases H before this next transaction takes H for
      // protocol support. Withdrawal must COMMIT while the send is parked here.
      final = db.pauseAt("sharing-send", { before: /sql:SELECT id FROM sandbox_host/ });
      path.release();
      await final.waitReached();
      const owner = { kind: "session" as const, ownerId: poolOwner.id };
      const hostOwner = { kind: "session" as const, ownerId: f.userId };
      const target = { poolId: pool.id, sandboxHostId: f.host.id };
      if (withdrawal === "delete") await deletePool(owner, { id: pool.id });
      if (withdrawal === "remove") await removePoolMember(owner, target);
      if (withdrawal === "ownHostsOnly")
        await updatePool(owner, {
          id: pool.id,
          slug: pool.slug,
          label: pool.label,
          ownHostsOnly: true,
          disconnectGraceSeconds: pool.disconnectGraceSeconds,
        });
      if (withdrawal === "withdraw") await withdrawPoolHost(hostOwner, target);
      if (withdrawal === "leave") await leavePool(hostOwner, { poolId: pool.id });
      if (withdrawal === "revoke")
        await revokePoolShare(owner, {
          poolId: pool.id,
          granteeUserId: creator.id,
        });
    } finally {
      path.release();
      final?.release();
    }
    expect(await sending).toBe("refused_before_frame");
    expect(possible).not.toHaveBeenCalled();
    expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
  },
);

it.each(["supported", "unsupported"] as const)(
  "relay reconnect window admits rich work, holds it until admission, then %s settles it",
  async (runtime) => {
    const f = await queuedStat();
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    const { statPath } = await import("@wssp/api/sandbox/services/sandboxes");
    const { sessionPrincipal } = await import("@wssp/api/sandbox/contracts");
    // Settle the fixture's own queued stat on the epoch-1 session first.
    await processSandboxOutboxBatch();
    f.frames.length = 0;
    const successor = { ...f.socket };
    f.manager.acceptAuthenticatedSocket({ socket: successor, identity: f.identity });
    f.manager.handleTextFrame(successor, JSON.stringify(helloFixture(f.host.id, false)));
    await f.manager.drain(successor);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    ).toMatchObject({
      status: "CONNECTED",
      connectionEpoch: 2,
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 2,
      admissionEpoch: null,
      admissionRuntime: null,
    });
    // Before the fix this refused with a final 400 UNSUPPORTED_CAPABILITY.
    const owner = sessionPrincipal(f.userId);
    const receipt = await statPath(owner, {
      id: f.sandbox.id,
      path: "/x",
      idempotencyKey: randomUUID(),
    });
    await processSandboxOutboxBatch();
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: receipt.operationId } }),
    ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
    expect(f.frames.filter((frame) => frame.type === "operation.dispatch")).toEqual([]);
    f.manager.handleTextFrame(
      successor,
      JSON.stringify({
        vmCapacity: { memoryBudgetMiB: 65536, maxCpuCount: 32, vcpuBudget: 64 },
        storagePools: capacityFixture(f.host.id).storagePools,
        journalId: "1234567890abcdef1234567890abcdef",
        type: "host.admission",
        connectionEpoch: 2,
        runtimeKind: runtime === "supported" ? "fake" : "unsupported",
        schedulable: runtime === "supported",
        egressPolicy: true,
        terminal: false,
      }),
    );
    await f.manager.drain(successor);
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
    f.manager.handleTextFrame(
      successor,
      JSON.stringify({
        type: "journal.key.ack",
        connectionEpoch: 2,
        keyVersion: 1,
        keyId: host.journalKeyId,
      }),
    );
    await reconcileSocket(f, successor);
    if (runtime === "unsupported")
      // Current-epoch refusal evidence now refuses new work at admission.
      await expect(
        statPath(owner, { id: f.sandbox.id, path: "/x", idempotencyKey: randomUUID() }),
      ).rejects.toMatchObject({ data: { code: "UNSUPPORTED_CAPABILITY" } });
    await processSandboxOutboxBatch();
    const dispatched = f.frames.filter(
      (frame) => frame.type === "operation.dispatch" && frame.operationId === receipt.operationId,
    );
    if (runtime === "supported") {
      expect(dispatched).toHaveLength(1);
      expect(
        await db.inspect.sandboxOperation.findUniqueOrThrow({
          where: { id: receipt.operationId },
        }),
      ).toMatchObject({ state: "DISPATCHED", dispatchAttempt: 1, dispatchedConnectionEpoch: 2 });
    } else {
      expect(dispatched).toEqual([]);
      expect(
        await db.inspect.sandboxOperation.findUniqueOrThrow({
          where: { id: receipt.operationId },
        }),
      ).toMatchObject({ state: "FAILED", errorCode: "unsupported_capability", dispatchAttempt: 0 });
    }
  },
);
