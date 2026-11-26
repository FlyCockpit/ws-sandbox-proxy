import { capacityFixture, helloFixture } from "./capacity-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import {
  seedAcceptedOperation,
  seedLaunchHost,
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
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockResolvedValue("sent"),
    captureHostDispatchCredential: vi.fn(),
    installExecutionConfig: vi.fn().mockResolvedValue(true),
  },
}));
const db = await pgTestDatabase();
const { commitHostHello } = await import("./host-hello");
const { disconnectJournalKey } = await import("./journal-key-ack");
const { requireFsProcessHost } = await import("../../../../packages/api/src/sandbox/host-protocol");
const { lockOwnerForAdmission } = await import("@wssp/db/account-deletion");
afterAll(() => db.close());
afterEach(() => vi.restoreAllMocks());
async function seed() {
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
      connectionEpoch: 8,
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 8,
    },
  });
  return { hostId: host.id, userId, connectionEpoch: 8 };
}
const row = (f: { hostId: string }) =>
  db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } });
async function hello(f: { hostId: string; userId: string }, versions: string[]) {
  const epoch = await commitHostHello({
    identity: f,
    now: new Date(),
    message: helloFixture(f.hostId, false),
  });
  // Seed historical stored evidence; no old peer is negotiated by the server.
  if (!versions.includes("1.0"))
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: { relayProtocolVersion: versions[0] },
    });
  return epoch;
}

const admit = (f: { hostId: string; userId: string }) =>
  db.prisma.$transaction(async (tx) => {
    await lockOwnerForAdmission(tx, f.userId);
    return requireFsProcessHost(tx, f.userId, f.hostId);
  });
describe("durable negotiated host admission", () => {
  it("binds every negotiated minor to the returned incremented epoch, including downgrade", async () => {
    const f = await seed();
    for (const version of ["1.0"]) {
      const epoch = await hello(f, [version, "99.0"]);
      expect(await row(f)).toMatchObject({
        connectionEpoch: epoch,
        relayProtocolEpoch: epoch,
        relayProtocolVersion: version,
      });
      // Post-hello, pre-admission (every relay reconnect): the current
      // protocol is supported and the runtime is not yet reported, so the
      // host is transitional, not unsupported — admit and queue.
      await expect(admit(f)).resolves.toMatchObject({
        connectionEpoch: epoch,
        admissionEpoch: null,
        status: "CONNECTED",
      });
    }
    // A current-epoch older protocol is positive refusal evidence.
    await hello(f, ["0.7"]);
    await expect(admit(f)).rejects.toMatchObject({ data: { code: "UNSUPPORTED_CAPABILITY" } });
    const epoch = await hello(f, ["1.0", "0.4"]);
    await (await import("./inventory-reconcile")).recordHostAdmission(
      { ...f, connectionEpoch: epoch },
      {
        vmCapacity: { memoryBudgetMiB: 65536, maxCpuCount: 32, vcpuBudget: 64 },
        storagePools: capacityFixture(f.hostId).storagePools,
        journalId: "1234567890abcdef1234567890abcdef",
        type: "host.admission",
        connectionEpoch: epoch,
        runtimeKind: "fake",
        schedulable: true,
        egressPolicy: true,
        terminal: false,
      },
      new Date(),
      {},
    );
    expect(await admit(f)).toMatchObject({
      connectionEpoch: epoch,
      relayProtocolEpoch: epoch,
      admissionEpoch: epoch,
    });
  });
  it("rolls back the epoch increment if the unconditional protocol binding fails", async () => {
    const f = await seed();
    const original = await row(f);
    const gate = db.pauseAt("hello", { before: "sandboxHost.updateMany" });
    const work = db.run("hello", () => hello(f, ["0.0"]));
    await gate.waitReached();
    gate.fail(new Error("injected between hello writes"));
    await expect(work).rejects.toThrow();
    expect(await row(f)).toEqual(original);
  });
  it("actual revoke carries protocol and runtime epochs but revokes the key ACK; non-revoke preserves epochs", async () => {
    const f = await seed();
    expect(await disconnectJournalKey(f, new Date(), false)).toBe(true);
    expect(await row(f)).toMatchObject({
      connectionEpoch: 8,
      relayProtocolEpoch: 8,
      admissionEpoch: 8,
      journalKeyAcknowledgedEpoch: null,
    });
    expect(await disconnectJournalKey(f, new Date(), true)).toBe(true);
    expect(await admit(f)).toMatchObject({
      connectionEpoch: 9,
      relayProtocolEpoch: 9,
      relayProtocolVersion: "1.0",
      admissionEpoch: 9,
      admissionRuntime: "FAKE",
      status: "DISCONNECTED",
    });
    expect((await row(f)).journalKeyAcknowledgedEpoch).toBeNull();
    expect(await disconnectJournalKey(f, new Date(), true)).toBe(false);
    expect((await row(f)).connectionEpoch).toBe(9);
  });
  it.each([null, 7, 9])("never promotes invalid protocol epoch %s on disconnect", async (epoch) => {
    const f = await seed();
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: { relayProtocolEpoch: epoch },
    });
    await disconnectJournalKey(f, new Date(), true);
    expect(await row(f)).toMatchObject({
      relayProtocolVersion: null,
      relayProtocolEpoch: null,
      admissionRuntime: null,
      admissionEpoch: null,
    });
    // Nothing current is proven offline: admit and queue until reconnect.
    await expect(admit(f)).resolves.toMatchObject({ connectionEpoch: 9, status: "DISCONNECTED" });
  });
  it.each([null, 7, 9])("never promotes invalid runtime epoch %s on disconnect", async (epoch) => {
    const f = await seed();
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: { admissionEpoch: epoch },
    });
    await disconnectJournalKey(f, new Date(), true);
    expect(await row(f)).toMatchObject({
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 9,
      admissionRuntime: null,
      admissionEpoch: null,
    });
    await expect(admit(f)).resolves.toMatchObject({ connectionEpoch: 9, admissionEpoch: null });
  });
  it("a disconnected host's carried current-epoch downgrade refuses before any row", async () => {
    const { f, accept, counts } = await stagedAcceptance();
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: { relayProtocolVersion: "0.7" },
    });
    expect(await disconnectJournalKey(f, new Date(), true)).toBe(true);
    expect(await row(f)).toMatchObject({
      status: "DISCONNECTED",
      connectionEpoch: 9,
      relayProtocolVersion: "0.7",
      relayProtocolEpoch: 9,
    });
    await expect(admit(f)).rejects.toMatchObject({ data: { code: "UNSUPPORTED_CAPABILITY" } });
    for (const kind of ["STAT_PATH", "RUN_COMMAND"] as const)
      await expect(accept(kind, `disconnected-${kind}`)).rejects.toMatchObject({
        data: { code: "UNSUPPORTED_CAPABILITY" },
      });
    expect(await counts()).toEqual([0, 0, 0]);
  });
  it("admission reads after H, never before the competing downgrade commits", async () => {
    const f = await seed();
    const gate = db.pauseAt("downgrade", { before: "$transaction.commit" });
    const downgrade = db.run("downgrade", () => hello(f, ["0.4"]));
    await gate.waitReached();
    const acceptance = db.run("accept", () => admit(f));
    const denied = expect(acceptance).rejects.toThrow();
    await db.waitUntilBlocked("accept", { by: "downgrade" });
    gate.release();
    await downgrade;
    await denied;
  });
  it("reads negotiated facts only after H even when the epoch is unchanged", async () => {
    const f = await seed();
    const gate = db.pauseAt("runtime-change", { before: "$transaction.commit" });
    const changed = db.run("runtime-change", () =>
      db.prisma.$transaction(async (tx) => {
        await lockOwnerForAdmission(tx, f.userId);
        await tx.sandboxHost.update({
          where: { id: f.hostId },
          data: { admissionRuntime: "UNSUPPORTED" },
        });
      }),
    );
    await gate.waitReached();
    const accepting = db.run("accept", () => admit(f));
    const denied = expect(accepting).rejects.toMatchObject({
      data: { code: "UNSUPPORTED_CAPABILITY" },
    });
    await db.waitUntilBlocked("accept", { by: "runtime-change" });
    gate.release();
    await changed;
    await denied;
  });
  it("disconnect and hello serialize; a stale disconnect cannot overwrite the successor", async () => {
    const f = await seed();
    const gate = db.pauseAt("hello", { before: "$transaction.commit" });
    const successor = db.run("hello", () => hello(f, ["1.0"]));
    await gate.waitReached();
    const disconnect = db.run("disconnect", () => disconnectJournalKey(f, new Date(), true));
    await db.waitUntilBlocked("disconnect", { by: "hello" });
    gate.release();
    const epoch = await successor;
    expect(await disconnect).toBe(false);
    expect(await row(f)).toMatchObject({
      status: "CONNECTED",
      connectionEpoch: epoch,
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: epoch,
    });
  });
});

async function stagedAcceptance() {
  const { seedSandboxInstance, seedTemplateRevision } = await import(
    "../../../../packages/api/src/sandbox/testing/resource-fixtures"
  );
  const { sessionPrincipal } = await import("../../../../packages/api/src/sandbox/contracts");
  const { operationTransaction } = await import(
    "../../../../packages/api/src/sandbox/operation-transaction"
  );
  const { reserveOperationResult } = await import(
    "../../../../packages/api/src/sandbox/operation-results"
  );
  const f = await seed();
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.userId,
      sandboxHostId: f.hostId,
      slug: "template",
      label: "Template",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: f.userId,
      templateId: revision.id,
      originHostId: f.hostId,
      sandboxHostId: f.hostId,
      state: "READY",
    },
  });
  const owner = sessionPrincipal(f.userId);
  const counts = async () => [
    await db.inspect.sandboxOperation.count({
      where: { userId: f.userId, kind: { in: ["RUN_COMMAND", "STAT_PATH"] } },
    }),
    await db.inspect.sandboxOperationResult.count({ where: { userId: f.userId } }),
    await db.inspect.outboxEvent.count({ where: { userId: f.userId } }),
  ];
  const accept = (kind: "RUN_COMMAND" | "STAT_PATH", key: string) =>
    operationTransaction(
      owner,
      {
        key,
        kind,
        action: kind === "RUN_COMMAND" ? "commands.run" : "files.stat",
        target: { sandboxId: sandbox.id },
        intent:
          kind === "RUN_COMMAND" ? { argv: ["true"], startEvidence: "required" } : { path: "/x" },
        fsProcess: {},
      },
      async (tx, digest) => {
        await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandbox.id} AND "userId" = ${f.userId} FOR UPDATE`;
        const op = await seedAcceptedOperation(tx, {
          data: {
            userId: f.userId,
            sandboxId: sandbox.id,
            generation: sandbox.generation,
            kind,
            idempotencyKey: key,
            requestBodyHash: digest(),
            ...(
              await import("../../../../packages/api/src/sandbox/idempotency")
            ).requestDigestMetadata(kind),
          },
        });
        // Prefix FK/outbox insertion precedes the quota suffix.
        await tx.outboxEvent.create({
          data: {
            userId: f.userId,
            aggregateType: "sandbox",
            aggregateId: sandbox.id,
            eventType: "staged.fs-process",
            operationId: op.id,
            payload: {
              operationId: op.id,
              sandboxId: sandbox.id,
              sandboxHostId: f.hostId,
              generation: sandbox.generation,
              dispatchAttempt: 0,
              idempotencyKey: key,
              authorizingPrincipal: { kind: "session" },
              kind: kind === "STAT_PATH" ? "file.stat" : "command.run",
              path: "/x",
              incusName: `wssp-sbx-${sandbox.id}`,
              ...(kind === "RUN_COMMAND"
                ? {
                    argv: ["true"],
                    timeoutMs: 120000,
                    startEvidence: "required",
                    privateConfig: (await (
                      await import("@wssp/api/sandbox/execution-config")
                    ).loadExecutionConfig(tx, sandbox.id, f.userId))!.reference,
                  }
                : {}),
            },
          },
        });
        if (kind === "STAT_PATH")
          await reserveOperationResult(tx, { ownerId: f.userId, operationId: op.id });
        return op.id;
      },
      async (_tx, prior) => prior.id,
    );
  return { f, sandbox, accept, counts };
}

it.each(["carried", "old-server", "invalid-snapshot"] as const)(
  "offline %s keeps accepted rich/required-start pending until a registered downgrade",
  async (disconnect) => {
    const { f, accept, counts } = await stagedAcceptance();
    // Connected/config+ACK acceptance is possible, before the first send.
    const connected = await accept("RUN_COMMAND", "connected-required");
    expect(connected).toBeTruthy();
    await disconnectJournalKey(f, new Date(), true);
    const before = await counts();
    await expect(accept("RUN_COMMAND", "offline-required")).rejects.toMatchObject({
      data: { code: "sandbox.host_unavailable" },
    });
    expect(await counts()).toEqual(before);
    const rich = await accept("STAT_PATH", "offline-rich");
    expect(await accept("STAT_PATH", "offline-rich")).toBe(rich);
    expect(await counts()).toEqual([before[0]! + 1, before[1]! + 1, before[2]! + 1]);
    const uncertain = await accept("STAT_PATH", "offline-possible");
    await db.inspect.sandboxOperation.update({
      where: { id: uncertain },
      data: {
        state: "DISPATCHED",
        dispatchAttempt: 1,
        acceptedAttempt: 1,
        dispatchedHostId: f.hostId,
        dispatchedConnectionEpoch: f.connectionEpoch + 1,
      },
    });
    const { sandboxRelaySessionManager: offlineManager } = await import("./session-manager.js");
    const { processSandboxOutboxBatch: offlineBatch } = await import("./outbox-processor.js");
    if (disconnect === "old-server") {
      await db.inspect.sandboxHost.update({
        where: { id: f.hostId },
        data: { connectionEpoch: { increment: 1 }, status: "DISCONNECTED" },
      });
    } else if (disconnect === "invalid-snapshot") {
      await db.inspect.sandboxHost.update({
        where: { id: f.hostId },
        data: { relayProtocolEpoch: null },
      });
      expect(await disconnectJournalKey({ ...f, connectionEpoch: 9 }, new Date(), true)).toBe(true);
    }
    vi.mocked(offlineManager.isHostConnected).mockReturnValue(false);
    vi.mocked(offlineManager.dispatchOperation).mockClear();
    await offlineBatch();
    expect(offlineManager.dispatchOperation).not.toHaveBeenCalled();
    for (const id of [connected, rich]) {
      expect(await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id } })).toMatchObject({
        state: "QUEUED",
        dispatchAttempt: 0,
        dispatchedHostId: null,
      });
    }
    expect(
      await db.inspect.sandboxOperationResult.findUniqueOrThrow({ where: { operationId: rich } }),
    ).toMatchObject({ reservationState: "RESERVED", reservationBytes: 24576 });
    // Stale or missing facts while offline prove no downgrade: rich work is
    // admitted and queued exactly like carried support. Required start still
    // needs the connected key ACK.
    const queued = [connected, rich];
    if (disconnect !== "carried") {
      const disconnectedCounts = await counts();
      const staleRich = await accept("STAT_PATH", "old-disconnected-rich");
      queued.push(staleRich);
      await expect(accept("RUN_COMMAND", "old-disconnected-required")).rejects.toMatchObject({
        data: { code: "sandbox.host_unavailable" },
      });
      expect(await counts()).toEqual([
        disconnectedCounts[0]! + 1,
        disconnectedCounts[1]! + 1,
        disconnectedCounts[2]! + 1,
      ]);
      expect(
        await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: staleRich } }),
      ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
    }
    vi.mocked(offlineManager.isHostConnected).mockReturnValue(true);
    await hello(f, ["0.4"]);
    const downgraded = await counts();
    await expect(accept("STAT_PATH", "old-rich")).rejects.toMatchObject({
      data: { code: "UNSUPPORTED_CAPABILITY" },
    });
    await expect(accept("RUN_COMMAND", "old-required")).rejects.toMatchObject({
      data: { code: "UNSUPPORTED_CAPABILITY" },
    });
    expect(await counts()).toEqual(downgraded);
    const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");
    const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
    vi.mocked(manager.dispatchOperation).mockClear();
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    for (const id of queued)
      expect(await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id } })).toMatchObject({
        state: "FAILED",
        errorCode: "unsupported_capability",
        dispatchAttempt: 0,
      });
    expect(
      await db.inspect.sandboxOperationResult.findUniqueOrThrow({ where: { operationId: rich } }),
    ).toMatchObject({ reservationState: "RELEASED", reservationBytes: 0 });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: uncertain } }),
    ).toMatchObject({ state: "UNKNOWN_OUTCOME", dispatchAttempt: 1 });
    expect(
      await db.inspect.sandboxOperationResult.findUniqueOrThrow({
        where: { operationId: uncertain },
      }),
    ).toMatchObject({ reservationState: "RESERVED", reservationBytes: 24576 });
  },
);

it.each(["refusal", "publish"] as const)(
  "actual downgrade refusal races publication, %s first",
  async (first) => {
    const { seedSandboxInstance, seedTemplateRevision } = await import(
      "../../../../packages/api/src/sandbox/testing/resource-fixtures"
    );
    const { sessionPrincipal } = await import("@wssp/api/sandbox/contracts");
    const { statPath } = await import("@wssp/api/sandbox/services/sandboxes");
    const { sandboxOutboxTransaction } = await import("@wssp/api/sandbox/outbox");
    const { lockHostByEpoch, casActiveOperation } = await import("@wssp/api/sandbox/relay-fence");
    const { reserveOperationResult, publishOperationResult } = await import(
      "@wssp/api/sandbox/operation-results"
    );
    const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
    const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");
    const f = await seed();
    const owner = sessionPrincipal(f.userId);
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.userId,
        sandboxHostId: f.hostId,
        slug: "template",
        label: "Template",
        incusFingerprint: `sha256:${"a".repeat(64)}`,
      },
    });
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: f.userId,
        templateId: revision.id,
        originHostId: f.hostId,
        sandboxHostId: f.hostId,
        state: "READY",
      },
    });
    const op = await statPath(owner, { id: sandbox.id, path: "/x", idempotencyKey: randomUUID() });
    const prefix = <T>(work: (tx: import("@wssp/db").Prisma.TransactionClient) => Promise<T>) =>
      sandboxOutboxTransaction(async (tx) => {
        await lockOwnerForAdmission(tx, f.userId);
        const host = await tx.sandboxHost.findUniqueOrThrow({
          where: { id: f.hostId },
          select: { connectionEpoch: true },
        });
        await lockHostByEpoch(tx, f.hostId, host.connectionEpoch, f.userId);
        await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandbox.id} FOR UPDATE`;
        await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${op.operationId} FOR UPDATE`;
        return work(tx);
      });
    await prefix((tx) =>
      reserveOperationResult(tx, { ownerId: f.userId, operationId: op.operationId }),
    );
    await hello(f, ["0.4"]);
    const publish = () =>
      prefix(async (tx) => {
        const { connectionEpoch } = await tx.sandboxHost.findUniqueOrThrow({
          where: { id: f.hostId },
          select: { connectionEpoch: true },
        });
        await casActiveOperation(
          tx,
          {
            operationId: op.operationId,
            sandboxId: sandbox.id,
            userId: f.userId,
            generation: sandbox.generation,
            attempt: 0,
            hostId: null,
          },
          {
            state: "SUCCEEDED",
            dispatchAttempt: 1,
            dispatchedHostId: f.hostId,
            dispatchedConnectionEpoch: connectionEpoch,
          },
        );
        return publishOperationResult(tx, {
          ownerId: f.userId,
          operationId: op.operationId,
          sender: { hostId: f.hostId, connectionEpoch },
          attempt: 1,
          observedAt: new Date(),
          payload: {
            type: "file.stat",
            entry: {
              name: "x",
              path: "/x",
              type: "file",
              size: 0,
              mode: 0o644,
              permissions: "rw-r--r--",
              uid: 1000,
              gid: 1000,
              owner: null,
              group: null,
              modifiedTime: null,
              symlinkTarget: null,
            },
          },
        });
      });
    vi.mocked(manager.dispatchOperation).mockClear();
    const gate = db.pauseAt("winner", { before: "$transaction.commit" });
    const winner = db.run("winner", async () =>
      first === "refusal" ? processSandboxOutboxBatch() : publish(),
    );
    await gate.waitReached();
    const loser = db
      .run("loser", async () => (first === "refusal" ? publish() : processSandboxOutboxBatch()))
      .then(
        () => "settled",
        () => "fenced",
      );
    await db.waitUntilBlocked("loser", { by: "winner" });
    gate.release();
    await winner;
    await loser;
    const child = await db.inspect.sandboxOperationResult.findUniqueOrThrow({
      where: { operationId: op.operationId },
    });
    expect(child.reservationState).toBe(first === "refusal" ? "RELEASED" : "PUBLISHED");
    expect(child.reservationBytes === 0).toBe(first === "refusal");
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  },
);

const b4Shapes = [
  { kind: "STAT_PATH", wire: "file.stat", payload: { path: "/x" } },
  { kind: "LIST_DIR", wire: "file.list", payload: { path: "/d", maxDepth: 1, limit: 1 } },
  {
    kind: "LIST_DIR",
    wire: "file.list",
    payload: {
      path: "/d",
      maxDepth: 1,
      limit: 1,
      continuation: {
        lastKey: "a",
        root: "/d",
        depth: 1,
        limit: 1,
        generation: 1,
        kind: "LIST_DIR",
      },
    },
  },
  {
    kind: "LIST_PROCESSES",
    wire: "process.list",
    payload: {
      limit: 1,
      continuation: {
        lastKey: '["2026-10-27T00:00:00.000Z","process"]',
        root: "/",
        depth: 1,
        limit: 1,
        generation: 1,
        kind: "LIST_PROCESSES",
      },
    },
  },
  {
    kind: "SIGNAL_PROCESS",
    wire: "process.signal",
    legacyNaked: true,
    payload: { pid: 42, signal: "SIGTERM" },
  },
  { kind: "MKDIR", wire: "file.mkdir", payload: { path: "/d" } },
  { kind: "REMOVE_PATH", wire: "file.remove", payload: { path: "/d", recursive: true } },
  { kind: "MOVE_PATH", wire: "file.move", payload: { path: "/d", destPath: "/e" } },
  { kind: "LIST_PROCESSES", wire: "process.list", payload: { limit: 1 } },
  { kind: "SIGNAL_PROCESS", wire: "process.signal", payload: { pid: 42, signal: "SIGTERM" } },
  {
    kind: "RUN_COMMAND",
    wire: "command.run",
    payload: { argv: ["true"], startEvidence: "required" },
  },
] as const;
it.each(b4Shapes)(
  "C-26 $wire downgrade keeps prior possible effects UNKNOWN and releases only first-unsent holds",
  async (shape) => {
    const { seedTemplateRevision, seedSandboxInstance, seedAcceptedOperation, seedDispatchEvent } =
      await import("../../../../packages/api/src/sandbox/testing/resource-fixtures");
    const { reserveOperationResult, isContentResultKind } = await import(
      "@wssp/api/sandbox/operation-results"
    );
    const { lockHostByEpoch } = await import("@wssp/api/sandbox/relay-fence");
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    const { sandboxRelaySessionManager: manager } = await import("./session-manager");
    const f = await seed();
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.userId,
        sandboxHostId: f.hostId,
        slug: "template",
        label: "Template",
        incusFingerprint: `sha256:${"a".repeat(64)}`,
      },
    });
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: f.userId,
        templateId: revision.id,
        originHostId: f.hostId,
        sandboxHostId: f.hostId,
        state: "READY",
        liveResourcesHeld: true,
      },
    });
    await db.inspect.sandboxHost.update({ where: { id: f.hostId }, data: { liveCount: 1 } });
    const target =
      shape.kind === "SIGNAL_PROCESS"
        ? await seedAcceptedOperation(db.inspect, {
            data: {
              userId: f.userId,
              sandboxId: sandbox.id,
              generation: 1,
              kind: "RUN_COMMAND",
              idempotencyKey: randomUUID(),
              requestBodyHash: "a".repeat(64),
              state: "RUNNING",
              dispatchAttempt: 1,
              dispatchedHostId: f.hostId,
              dispatchedConnectionEpoch: 8,
              processId: randomUUID(),
              processPid: 42,
            },
          })
        : null;
    const ids: string[] = [];
    for (const prior of [false, true]) {
      const op = await seedAcceptedOperation(db.inspect, {
        data: {
          userId: f.userId,
          sandboxId: sandbox.id,
          generation: 1,
          kind: shape.kind,
          idempotencyKey: randomUUID(),
          requestBodyHash: "a".repeat(64),
          state: prior ? "DISPATCHED" : "QUEUED",
          dispatchAttempt: prior ? 1 : 0,
          dispatchedHostId: prior ? f.hostId : null,
          dispatchedConnectionEpoch: prior ? 8 : null,
          ...(!isContentResultKind(shape.kind)
            ? { resultVersion: "legacyNaked" in shape ? null : 1 }
            : {}),
          ...(shape.kind === "RUN_COMMAND" ? { processId: randomUUID() } : {}),
        },
      });
      await seedDispatchEvent(db.inspect, {
        data: {
          userId: f.userId,
          aggregateType: "sandbox",
          aggregateId: sandbox.id,
          eventType: "staged.fs-process",
          payload: {
            operationId: op.id,
            sandboxId: sandbox.id,
            sandboxHostId: f.hostId,
            generation: 1,
            dispatchAttempt: prior ? 1 : 0,
            idempotencyKey: op.idempotencyKey,
            kind: shape.wire,
            authorizingPrincipal: { kind: "session" },
            ...shape.payload,
            ...(target && !("legacyNaked" in shape)
              ? {
                  process: {
                    sandboxId: sandbox.id,
                    generation: 1,
                    attempt: 1,
                    processId: target.processId,
                    pid: 42,
                  },
                  targetOperationId: target.id,
                }
              : {}),
          },
        },
      });
      if (isContentResultKind(shape.kind)) {
        // Reserve while genuinely queued, then model the prior possible send.
        if (prior)
          await db.inspect.sandboxOperation.update({
            where: { id: op.id },
            data: { state: "QUEUED", dispatchAttempt: 0 },
          });
        await db.prisma.$transaction(async (tx) => {
          await lockOwnerForAdmission(tx, f.userId);
          await lockHostByEpoch(tx, f.hostId, 8, f.userId);
          await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandbox.id} FOR UPDATE`;
          await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${op.id} FOR UPDATE`;
          await reserveOperationResult(tx, { ownerId: f.userId, operationId: op.id });
        });
        if (prior)
          await db.inspect.sandboxOperation.update({
            where: { id: op.id },
            data: { state: "DISPATCHED", dispatchAttempt: 1 },
          });
      }
      ids.push(op.id);
    }
    await hello(f, ["0.4"]);
    vi.mocked(manager.dispatchOperation).mockClear();
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    for (const [i, id] of ids.entries()) {
      expect(await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id } })).toMatchObject({
        state: i === 0 ? "FAILED" : "UNKNOWN_OUTCOME",
        errorCode: "unsupported_capability",
      });
      if (isContentResultKind(shape.kind))
        expect(
          await db.inspect.sandboxOperationResult.findUniqueOrThrow({ where: { operationId: id } }),
        ).toMatchObject({
          reservationState: i === 0 ? "RELEASED" : "RESERVED",
          reservationBytes: i === 0 ? 0 : 24576,
        });
    }
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } })).toMatchObject(
      { liveResourcesHeld: true },
    );
    expect((await row(f)).liveCount).toBe(1);
    if (target)
      expect(
        await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: target.id } }),
      ).toMatchObject({ state: "RUNNING", processPid: 42, dispatchAttempt: 1 });
  },
);
it.each(
  [
    { kind: "MKDIR", wire: "file.mkdir", payload: { path: "/x" } },
    { kind: "STAT_PATH", wire: "file.stat", payload: { path: "/x" } },
    {
      kind: "RUN_COMMAND",
      wire: "command.run",
      payload: { argv: ["true"], startEvidence: "required" },
    },
  ].flatMap((shape) => [false, true].map((prior) => ({ ...shape, prior }))),
)(
  "downgrade after the actual prepare claim uses C-26 for $wire (earlier possible send=$prior)",
  async ({ prior, kind, wire, payload }) => {
    const { seedTemplateRevision, seedSandboxInstance, seedAcceptedOperation, seedDispatchEvent } =
      await import("../../../../packages/api/src/sandbox/testing/resource-fixtures");
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    const { sandboxRelaySessionManager: manager } = await import("./session-manager");
    const f = await seed();
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.userId,
        sandboxHostId: f.hostId,
        slug: "image",
        label: "Image",
        incusFingerprint: `sha256:${"a".repeat(64)}`,
      },
    });
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: f.userId,
        templateId: revision.id,
        originHostId: f.hostId,
        sandboxHostId: f.hostId,
        state: "READY",
      },
    });
    const { reserveOperationResult, isContentResultKind } = await import(
      "@wssp/api/sandbox/operation-results"
    );
    const { lockHostByEpoch } = await import("@wssp/api/sandbox/relay-fence");
    const op = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: f.userId,
        sandboxId: sandbox.id,
        generation: 1,
        kind: kind as "MKDIR" | "STAT_PATH" | "RUN_COMMAND",
        idempotencyKey: randomUUID(),
        requestBodyHash: "a".repeat(64),
        resultVersion: kind === "STAT_PATH" ? null : 1,
        ...(kind === "RUN_COMMAND" ? { processId: randomUUID() } : {}),
        state: prior ? "DISPATCHED" : "QUEUED",
        dispatchAttempt: prior ? 1 : 0,
        dispatchedHostId: prior ? f.hostId : null,
        dispatchedConnectionEpoch: prior ? 7 : null,
      },
    });
    if (isContentResultKind(op.kind)) {
      if (prior)
        await db.inspect.sandboxOperation.update({
          where: { id: op.id },
          data: { state: "QUEUED", dispatchAttempt: 0 },
        });
      await db.prisma.$transaction(async (tx) => {
        await lockOwnerForAdmission(tx, f.userId);
        await lockHostByEpoch(tx, f.hostId, 8, f.userId);
        await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandbox.id} FOR UPDATE`;
        await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${op.id} FOR UPDATE`;
        await reserveOperationResult(tx, { ownerId: f.userId, operationId: op.id });
      });
      if (prior)
        await db.inspect.sandboxOperation.update({
          where: { id: op.id },
          data: { state: "DISPATCHED", dispatchAttempt: 1 },
        });
    }
    await seedDispatchEvent(db.inspect, {
      data: {
        userId: f.userId,
        aggregateType: "sandbox",
        aggregateId: sandbox.id,
        eventType: "sandbox.file_mkdir_requested",
        payload: {
          operationId: op.id,
          sandboxId: sandbox.id,
          sandboxHostId: f.hostId,
          generation: 1,
          dispatchAttempt: prior ? 1 : 0,
          idempotencyKey: op.idempotencyKey,
          kind: wire,
          ...payload,
          authorizingPrincipal: { kind: "session" },
        },
      },
    });
    vi.mocked(manager.dispatchOperation).mockImplementationOnce(async () => {
      await hello(f, ["0.4"]);
      // A registered successor cannot be connected for dispatch until its real
      // reconciliation finishes. Never fabricate the old always-true state.
      vi.mocked(manager.isHostConnected).mockReturnValue(false);
      return "refused_before_frame";
    });
    await processSandboxOutboxBatch();
    const { finishHostReconciliation } = await import("./operation-handlers");
    expect(
      await finishHostReconciliation({
        userId: f.userId,
        hostId: f.hostId,
        connectionEpoch: (await row(f)).connectionEpoch,
      }),
    ).toBe(true);
    vi.mocked(manager.isHostConnected).mockReturnValue(true);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } }),
    ).toMatchObject({
      state: prior ? "UNKNOWN_OUTCOME" : "FAILED",
      errorCode: "unsupported_capability",
      dispatchAttempt: prior ? 2 : 1,
    });
    if (isContentResultKind(op.kind)) {
      const held = await db.inspect.sandboxOperationResult.findUniqueOrThrow({
        where: { operationId: op.id },
      });
      expect(held).toMatchObject({
        reservationState: prior ? "RESERVED" : "RELEASED",
        reservationBytes: prior ? 24576 : 0,
      });
      await processSandboxOutboxBatch();
      expect(
        await db.inspect.sandboxOperationResult.findUniqueOrThrow({
          where: { operationId: op.id },
        }),
      ).toEqual(held);
    }
  },
);

it.each(
  (["STAT_PATH", "RUN_COMMAND"] as const).flatMap((kind) =>
    (["old-server", "invalid-snapshot"] as const).map((disconnect) => ({ kind, disconnect })),
  ),
)(
  "offline $disconnect after claim requeues first-unsent $kind without releasing its content",
  async ({ kind, disconnect }) => {
    const { f, accept } = await stagedAcceptance();
    const id = await accept(kind, "offline-after-claim");
    const { sandboxRelaySessionManager: manager } = await import("./session-manager");
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    vi.mocked(manager.dispatchOperation).mockClear();
    vi.mocked(manager.dispatchOperation).mockImplementationOnce(async () => {
      if (disconnect === "old-server") {
        await db.inspect.sandboxHost.update({
          where: { id: f.hostId },
          data: {
            connectionEpoch: { increment: 1 },
            status: "DISCONNECTED",
          },
        });
      } else {
        await db.inspect.sandboxHost.update({
          where: { id: f.hostId },
          data: { relayProtocolEpoch: null },
        });
        expect(await disconnectJournalKey(f, new Date(), true)).toBe(true);
      }
      vi.mocked(manager.isHostConnected).mockReturnValue(false);
      return "refused_before_frame";
    });
    try {
      await processSandboxOutboxBatch();
      expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
      expect(await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id } })).toMatchObject({
        state: "QUEUED",
        dispatchAttempt: 0,
        dispatchedHostId: null,
        dispatchedConnectionEpoch: null,
        errorCode: null,
      });
      if (kind === "STAT_PATH")
        expect(
          await db.inspect.sandboxOperationResult.findUniqueOrThrow({ where: { operationId: id } }),
        ).toMatchObject({ reservationState: "RESERVED", reservationBytes: 24576 });
      expect(
        await db.inspect.outboxEvent.findFirstOrThrow({
          where: {
            userId: f.userId,
            payload: { path: ["operationId"], equals: id },
          },
        }),
      ).toMatchObject({ processedAt: null, claimToken: null });
      // A further offline scan produces no guest effect or additional claim.
      await processSandboxOutboxBatch();
      expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    } finally {
      vi.mocked(manager.isHostConnected).mockReturnValue(true);
    }
    // Finish this fixture through the real downgrade path so its intentionally
    // queued event cannot intercept the next test's batch/clock barrier.
    await hello(f, ["0.4"]);
    await processSandboxOutboxBatch();
    expect(await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id } })).toMatchObject({
      state: "FAILED",
      errorCode: "unsupported_capability",
      dispatchAttempt: 0,
    });
    if (kind === "STAT_PATH")
      expect(
        await db.inspect.sandboxOperationResult.findUniqueOrThrow({ where: { operationId: id } }),
      ).toMatchObject({ reservationState: "RELEASED", reservationBytes: 0 });
  },
);

it("dispatch reads the database clock only after its operation lock", async () => {
  const { seedTemplateRevision, seedSandboxInstance, seedAcceptedOperation, seedDispatchEvent } =
    await import("../../../../packages/api/src/sandbox/testing/resource-fixtures");
  const { processSandboxOutboxBatch } = await import("./outbox-processor");
  const f = await seed();
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: f.userId,
      sandboxHostId: f.hostId,
      slug: "image",
      label: "Image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: f.userId,
      templateId: revision.id,
      originHostId: f.hostId,
      sandboxHostId: f.hostId,
      state: "READY",
    },
  });
  const op = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.userId,
      sandboxId: sandbox.id,
      generation: 1,
      kind: "MKDIR",
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      resultVersion: 1,
    },
  });
  await seedDispatchEvent(db.inspect, {
    data: {
      userId: f.userId,
      aggregateType: "sandbox",
      aggregateId: sandbox.id,
      eventType: "sandbox.file_mkdir_requested",
      payload: {
        operationId: op.id,
        sandboxId: sandbox.id,
        sandboxHostId: f.hostId,
        generation: 1,
        dispatchAttempt: 0,
        idempotencyKey: op.idempotencyKey,
        kind: "file.mkdir",
        path: "/x",
        authorizingPrincipal: { kind: "session" },
      },
    },
  });
  const held = db.pauseAt("held-operation", { before: "$transaction.commit" });
  const holder = db.run("held-operation", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${op.id} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const clock = db.pauseAt("dispatch-clock", { before: /sql:SELECT clock_timestamp/ });
  let sampled = false;
  void clock.reached.then(() => {
    sampled = true;
  });
  const dispatching = db.run("dispatch-clock", () => processSandboxOutboxBatch());
  const blocked = await db.waitUntilBlocked("dispatch-clock", { by: "held-operation" });
  expect(blocked.query).toContain("sandbox_mutation_operation");
  expect(sampled).toBe(false);
  held.release();
  await holder;
  await clock.waitReached();
  clock.release();
  await dispatching;
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } })).dispatchAttempt,
  ).toBe(1);
});

it.each([false, true])(
  "ordinary run accepted on the current protocol keeps its version and uses C-26 after downgrade (prior=$prior)",
  async (prior) => {
    const { seedTemplateRevision, seedSandboxInstance } = await import(
      "../../../../packages/api/src/sandbox/testing/resource-fixtures"
    );
    const { runCommand } = await import("@wssp/api/sandbox/services/sandboxes");
    const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
    const { processSandboxOutboxBatch } = await import("./outbox-processor");
    const { sandboxRelaySessionManager: manager } = await import("./session-manager");
    const f = await seed();
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: {
        admissionEpoch: 8,
        admissionRuntime: "FAKE",
        journalKeyId: requestDigestMetadata().requestDigestKeyId,
        journalKeyVersion: 1,
        journalKeyAcknowledgedEpoch: 8,
      },
    });
    const revision = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.userId,
        sandboxHostId: f.hostId,
        slug: "base",
        label: "Base",
        incusFingerprint: `sha256:${"a".repeat(64)}`,
      },
    });
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: f.userId,
        templateId: revision.id,
        originHostId: f.hostId,
        sandboxHostId: f.hostId,
        state: "READY",
      },
    });
    const accepted = await runCommand(
      { kind: "session", ownerId: f.userId },
      { id: sandbox.id, argv: ["true"], timeoutMs: 120000, idempotencyKey: randomUUID() },
    );
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }),
    ).toMatchObject({ resultVersion: 1, processId: expect.any(String) });
    expect(
      await db.inspect.outboxEvent.findFirst({
        where: {
          aggregateId: sandbox.id,
          payload: { path: ["operationId"], equals: accepted.operationId },
        },
        select: { payload: true },
      }),
    ).toMatchObject({ payload: { resultVersion: 1 } });
    if (prior)
      await db.inspect.sandboxOperation.update({
        where: { id: accepted.operationId },
        data: {
          state: "DISPATCHED",
          dispatchAttempt: 1,
          dispatchedHostId: f.hostId,
          dispatchedConnectionEpoch: 8,
        },
      });
    await hello(f, ["0.4"]);
    vi.mocked(manager.dispatchOperation).mockClear();
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: accepted.operationId } }),
    ).toMatchObject({
      state: prior ? "UNKNOWN_OUTCOME" : "FAILED",
      resultVersion: 1,
      errorCode: "unsupported_capability",
    });
  },
);

it.each(["1.0"])("accepts current-epoch fs/process admission on %s", async (version) => {
  const f = await seed();
  await db.inspect.sandboxHost.update({
    where: { id: f.hostId },
    data: { relayProtocolVersion: version },
  });
  await expect(admit(f)).resolves.toBeDefined();
  // A stale protocol epoch proves nothing about this epoch's peer: admit and
  // queue (send still requires current support). A non-current version at the current epoch refuses.
  await db.inspect.sandboxHost.update({ where: { id: f.hostId }, data: { relayProtocolEpoch: 7 } });
  await expect(admit(f)).resolves.toBeDefined();
  await db.inspect.sandboxHost.update({
    where: { id: f.hostId },
    data: { relayProtocolEpoch: 8, relayProtocolVersion: "0.7" },
  });
  await expect(admit(f)).rejects.toMatchObject({ data: { code: "UNSUPPORTED_CAPABILITY" } });
});
