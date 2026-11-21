import { seedAcceptedOperation } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { capacityFixture, helloFixture } from "./capacity-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { requestDigestMetadata } from "@wssp/api/sandbox/idempotency";

vi.mock("@wssp/api/lib/host-token-access", () => ({
  revalidateSandboxHostIdentity: vi
    .fn()
    .mockResolvedValue({ status: "active", hostDeletionRequested: false }),
}));

// The server lifecycle registers a migration-runner instance heartbeat; it is a no-op
// without WSSP_INSTANCE_ID, but importing it would validate the shared env here.
vi.mock("@wssp/db/instance-heartbeat", () => ({
  startInstanceHeartbeat: () => ({ markReady() {}, async stop() {} }),
}));

import { readFileSync } from "node:fs";
import {
  commandRunDispatchBuildInputForEnqueueGuard,
  commandRunDispatchFitsControlLimit,
  encodedCommandRunDispatchControlBytes,
} from "@wssp/api/sandbox/dispatch-control-envelope";
import {
  bindSandboxDispatchWake,
  createSandboxOutboxEvent,
  sandboxOutboxTransaction,
} from "@wssp/api/sandbox/outbox";
import { relayTransaction } from "@wssp/api/sandbox/relay-fence";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createServerLifecycle } from "../lifecycle.js";
import {
  commandResultFixture,
  gate,
  installFenceTransaction,
  matches,
  prismaPromise,
  relayStore,
  runningCensusFrames,
} from "./fenced-prisma-harness.js";
import { processSandboxOutboxBatch, startSandboxOutboxProcessor } from "./outbox-processor.js";
import { sandboxRelaySessionManager as manager } from "./session-manager.js";

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return {
    default: mockDeep<typeof import("@wssp/db").default>(),
    disconnectConnectAuditPrisma: async () => {},
  };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    WORKER_MODE: "external",
  },
}));
// Startup ordering/aggregation is proven by lifecycle.test.ts and real PG;
// these unit drain barriers begin after bootstrap has completed.
vi.mock("@wssp/api/sandbox/host-admission", async (original) => ({
  ...(await original<typeof import("@wssp/api/sandbox/host-admission")>()),
  initializeHostMemoryReservations: async () => {},
}));
// The boot host sweep (WP4) is proven by host-liveness.pg.test.ts.
vi.mock("./host-liveness.js", () => ({
  sweepConnectedHosts: async () => ({ disconnected: 0 }),
}));
vi.mock("@wssp/queue", () => ({
  redisConnection: { ping: vi.fn().mockResolvedValue("PONG"), disconnect: vi.fn() },
}));
// These probes own outbox shutdown; real spool IO/drain is exercised by store.pg.test.ts.
const fakeUploadSources = vi.hoisted(() => ({
  sources: new Map<
    string,
    { size: number; sha256: string; read(offset: number, length: number): Promise<Uint8Array> }
  >(),
}));
vi.mock("../sandbox-image-relay/index.js", () => ({
  resetImageRelay: vi.fn(async () => {}),
  imageRelaySpool: vi.fn(),
}));
vi.mock("../sandbox-image-relay/scheduler.js", () => ({
  startImageScheduler: vi.fn(() => () => {}),
}));
vi.mock("../sandbox-transfers/runtime.js", () => ({
  startTransferStore: async () => ({ close: async () => {} }),
  transferStore: () => ({
    uploadSource: async (transferId: string) => {
      const source = fakeUploadSources.sources.get(transferId);
      if (!source) throw new Error(`no such transfer ${transferId}`);
      return source;
    },
  }),
}));
// Build-context staging is a separate store; its recovery is not under test
// here (a real start would walk the spool and hold the lifecycle open).
vi.mock("../template-builds/runtime.js", () => ({
  startBuildContextStore: async () => ({ close: async () => {} }),
  bindBuildContextStores: () => {},
  buildContextStore: () => {
    throw new Error("build contexts are not used in this test");
  },
}));
vi.mock("worker/runtime", () => ({
  startWorkerRuntime: vi.fn(),
  WorkerDrainError: class extends Error {},
}));
const { default: prisma } = await import("@wssp/db");
const { redisConnection } = await import("@wssp/queue");
const db = vi.mocked(prisma, true);
let store = relayStore("RUN_COMMAND", "QUEUED");
let stop: (() => Promise<void>) | undefined;

class FakeSocket {
  readyState = 1;
  bufferedAmount = 0;
  messages: Record<string, unknown>[] = [];
  binary: ArrayBuffer[] = [];
  onDispatch?: (message: Record<string, unknown>) => void;
  send(data: string | ArrayBuffer | Uint8Array) {
    if (typeof data !== "string") {
      this.binary.push(data instanceof ArrayBuffer ? data : data.slice().buffer);
      return;
    }
    const message = JSON.parse(data) as Record<string, unknown>;
    this.messages.push(message);
    if (message.type === "operation.dispatch") {
      const operation = store.operations.get(String(message.operationId))!;
      const event = [...store.outbox.values()].find(
        (row) => row.payload.operationId === message.operationId,
      )!;
      // Every real send observes committed authority, not a staged transaction.
      expect(operation.dispatchAttempt).toBe(message.attempt);
      expect(operation.state).toBe("DISPATCHED");
      expect(event.claimToken).toEqual(expect.any(String));
      expect(event.sentConnectionEpoch).toBe(store.hosts.get("host-1")!.connectionEpoch);
      this.onDispatch?.(message);
    }
  }
  close() {
    this.readyState = 3;
  }
  get dispatches() {
    return this.messages.filter((message) => message.type === "operation.dispatch");
  }
}

async function frame(socket: FakeSocket, message: Record<string, unknown>) {
  manager.handleTextFrame(socket, JSON.stringify(message));
  await manager.drain(socket);
}
async function connect(reconcile = true, egressPolicy = true, keyed = false, sized = false) {
  const socket = new FakeSocket();
  manager.acceptAuthenticatedSocket({
    socket,
    identity: {
      hostId: "host-1",
      userId: "user-1",
      tokenId: "token-1",
      credentialKind: "hostToken" as const,
      expiresAt: null,
    },
  });
  const hello = helloFixture("host-1", false);
  hello.daemon.capabilities.egressPolicy = egressPolicy;
  await frame(socket, hello);
  if (keyed) {
    const install = socket.messages.find((message) => message.type === "journal.key.install")!;
    await frame(socket, {
      type: "journal.key.ack",
      connectionEpoch: install.connectionEpoch,
      keyVersion: install.keyVersion,
      keyId: install.keyId,
    });
  }
  if (keyed)
    await frame(socket, {
      vmCapacity: { memoryBudgetMiB: 65536, maxCpuCount: 32, vcpuBudget: 64 },
      storagePools: capacityFixture("host-1").storagePools,
      journalId: "1234567890abcdef1234567890abcdef",
      type: "host.admission",
      connectionEpoch: 1,
      runtimeKind: "fake",
      schedulable: true,
      egressPolicy,
      terminal: false,
    });
  // A current daemon renews its egress guard lease on the new connection.
  const ok = socket.messages.find((message) => message.type === "hello.ok");
  if (ok)
    await frame(socket, {
      type: "host.egress-state",
      connectionEpoch: ok.connectionEpoch,
      sequence: 1,
      allowOpenForOthers: false,
      allowGuestSudoForOthers: false,
      guardOk: true,
      guardInstanceId: "fake-guard",
      guardGeneration: 1,
    });
  if (reconcile) await reconcileHost(socket);
  if (sized) {
    const sessions = Reflect.get(manager, "sessionsBySocket") as Map<
      FakeSocket,
      { protocolVersion: string }
    >;
    sessions.get(socket)!.protocolVersion = "1.0";
  }
  return socket;
}
async function reconcileHost(socket: FakeSocket) {
  for (const page of runningCensusFrames(store)) await frame(socket, JSON.parse(page));
  await frame(socket, { type: "reconcile.complete" });
}
function start() {
  stop = startSandboxOutboxProcessor(new AbortController().signal);
}
async function tick() {
  for (const event of store.outbox.values()) {
    if (event.payload.kind === "sandbox.create") event.eventType = "sandbox.create_requested";
    if (event.payload.kind === "sandbox.reconnect") event.eventType = "sandbox.reconnect_requested";
    if (
      ["sandbox.create", "sandbox.reconnect", "sandbox.stop", "sandbox.kill"].includes(
        String(event.payload.kind),
      ) &&
      !event.payload.allocation
    ) {
      const p = store.placements.get(`placement:${event.aggregateId}`)!;
      event.payload.allocation = {
        cpuCount: p.cpuCount,
        memoryMiB: p.memoryMiB,
        diskGiB: p.diskGiB,
        storagePoolName: p.storagePoolName,
        storageMarker: p.storageMarker,
        chargedMemoryMiB: p.chargedMemoryMiB,
        chargedVcpu: p.chargedVcpu,
        rootChargeGiB: p.rootChargeGiB,
      };
    }
  }
  await vi.advanceTimersByTimeAsync(0);
}
async function enqueue(id = "new", sandboxId = "sbx-1", script?: string) {
  return sandboxOutboxTransaction(async (tx) => {
    const operation = await seedAcceptedOperation(tx, {
      data: {
        id,
        userId: "user-1",
        sandboxId,
        generation: 1,
        kind: "RUN_COMMAND",
        resultVersion: 1,
        processId: `proc-${id}`,
        state: "QUEUED",
        idempotencyKey: id,
        requestBodyHash: "a".repeat(64),
      },
    });
    await createSandboxOutboxEvent(tx, {
      authorizingPrincipal: { kind: "session" },
      userId: "user-1",
      aggregateId: sandboxId,
      eventType: "sandbox.command_requested",
      payload: {
        operationId: operation.id,
        sandboxId,
        sandboxHostId: "host-1",
        generation: 1,
        dispatchAttempt: 0,
        kind: "command.run",
        ...(script === undefined ? { argv: ["echo", "fake-tool"] } : { script }),
      },
    });
  });
}
function expiredCreate() {
  Object.assign(store.operations.get("op-1")!, {
    kind: "CREATE_SANDBOX",
    idempotencyKey: "op-1",
    state: "DISPATCHED",
    dispatchAttempt: 1,
    dispatchedHostId: "host-1",
    dispatchedConnectionEpoch: 1,
  });
  Object.assign(store.sandboxes.get("sbx-1")!, {
    state: "PROVISIONING",
    leaseExpiresAt: new Date(Date.now() - 1),
  });
  Object.assign(store.outbox.get("evt-1")!.payload, {
    kind: "sandbox.create",
    dispatchAttempt: 1,
  });
}
const result = {
  id: "result-1",
  type: "operation.result",
  operationId: "op-1",
  sandboxId: "sbx-1",
  generation: 1,
  attempt: 1,
  state: "succeeded",
  result: { state: "ready" },
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.clearAllMocks();
  fakeUploadSources.sources.clear();
  store = relayStore("RUN_COMMAND", "QUEUED");
  store.hosts.get("host-1")!.connectionEpoch = 0;
  store.sandboxes.get("sbx-1")!.templateId = "tpl-1";
  store.templates.set("tpl-1", {
    retiredAt: null,
    id: "tpl-1",
    userId: "user-1",
    sandboxHostId: "host-1",
    incusFingerprint: "sha256:" + "a".repeat(64),
    architecture: "x86_64",
    guestUid: 1000,
    guestGid: 1000,
    guestHome: "/home/user",
    guestShell: "/bin/bash",
  });
  Object.assign(store.operations.get("op-1")!, {
    dispatchAttempt: 0,
    acceptedAttempt: null,
    dispatchedHostId: null,
    dispatchedConnectionEpoch: null,
  });
  store.outbox.get("evt-1")!.payload.dispatchAttempt = 0;
  installFenceTransaction(db, store);
  db.outboxEvent.findMany.mockImplementation((args) =>
    prismaPromise(
      Promise.resolve(
        [...store.outbox.values()]
          .filter((row) => matches(row, args?.where as Record<string, unknown>))
          .sort((a, b) => a.id.localeCompare(b.id))
          .slice(0, args?.take ?? 32) as never,
      ),
    ),
  );
  db.sandboxTemplateAvailability.findMany.mockImplementation((args) =>
    prismaPromise(prisma.$transaction((tx) => tx.sandboxTemplateAvailability.findMany(args))),
  );
  db.sandbox.findMany.mockImplementation((args) =>
    prismaPromise(
      Promise.resolve(
        [...store.sandboxes.values()]
          .filter((row) => matches(row, args?.where as Record<string, unknown>))
          .sort((a, b) => a.id.localeCompare(b.id))
          .slice(0, args?.take ?? 32) as never,
      ),
    ),
  );
  db.outboxEvent.updateMany.mockImplementation((args) =>
    prismaPromise(db.$transaction((tx) => tx.outboxEvent.updateMany(args))),
  );
  db.sandboxHost.updateMany.mockImplementation((args) =>
    prismaPromise(db.$transaction((tx) => tx.sandboxHost.updateMany(args))),
  );
  db.$queryRaw.mockImplementation((_query, ...values) =>
    db.sandbox.findMany({
      where: {
        leaseExpiresAt: { lte: values[0] as Date },
        state: { in: ["READY", "REQUESTED", "SCHEDULED", "PROVISIONING", "STOPPED"] },
        ...(typeof values[1] === "string" ? { id: { gt: values[1] } } : {}),
      },
      orderBy: { id: "asc" },
      take: Number(values[4]),
    }),
  );
});
afterEach(async () => {
  await stop?.();
  stop = undefined;
  bindSandboxDispatchWake(null);
  await manager.dispose();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("production dispatcher wake boundaries", () => {
  it("rolls back the operation when its encoded command envelope is oversized", async () => {
    store.outbox.clear();
    const socket = await connect();
    start();
    await tick();
    Object.assign(store.placements.get("placement:sbx-1")!, { guestHome: "/" + "x".repeat(65536) });
    await expect(enqueue("oversized", "sbx-1", "true")).rejects.toThrow(
      "Encoded command dispatch exceeds 64 KiB",
    );
    await tick();
    expect(store.operations.has("oversized")).toBe(false);
    expect(store.outbox.size).toBe(0);
    expect(socket.dispatches).toHaveLength(0);
  });

  it.each([
    { attempt: 2147483647, sequence: 10000000, env: undefined },
    { attempt: 2147483647, sequence: 2147483647, env: undefined },
    { attempt: 1, sequence: 0, env: [["K", "V".repeat(20), "extra"]] },
  ])(
    "C15-S1 c3 guard bounds production dispatch $attempt/$sequence/$env",
    async ({ attempt, sequence, env }) => {
      const socket = await connect(true, true, env != null);
      if (env)
        expect(store.hosts.get("host-1")).toMatchObject({
          journalKeyVersion: 1,
          journalKeyAcknowledgedEpoch: store.hosts.get("host-1")!.connectionEpoch,
          journalKeyId: requestDigestMetadata().requestDigestKeyId,
        });
      const sandboxId = "s".repeat(24);
      const operationId = "o".repeat(24);
      store.sandboxes.set(sandboxId, {
        ...store.sandboxes.get("sbx-1")!,
        id: sandboxId,
        currentPlacementId: `placement:${sandboxId}`,
      });
      store.placements.set(`placement:${sandboxId}`, {
        ...store.placements.get("placement:sbx-1")!,
        id: `placement:${sandboxId}`,
        sandboxId,
      });
      const operation = {
        ...store.operations.get("op-1")!,
        id: operationId,
        sandboxId,
        ...(env ? requestDigestMetadata() : {}),
        requestBodyHash: "a".repeat(64),
        dispatchAttempt: attempt - 1,
        nextStdinSequence: sequence,
      };
      const payload = {
        operationId,
        sandboxId,
        sandboxHostId: "host-1",
        generation: 1,
        dispatchAttempt: attempt - 1,
        kind: "command.run",
        script: "true",
        idempotencyKey: "k".repeat(128),
        incusName: `wssp-sbx-${sandboxId}`,
        templateDigest: `sha256:${"a".repeat(64)}`,
        incusFingerprint: `sha256:${"a".repeat(64)}`,
        architecture: "x".repeat(500),
        guestUid: 1000,
        guestGid: 1000,
        guestShell: "/bin/bash",
        timeoutMs: 120000,
        env,
      };
      // First reproduce the exact former accepted boundary, then exercise a
      // guard-admitted payload through the real processor/session/encoder too.
      for (const homeLength of [64244, 63800]) {
        socket.messages.length = 0;
        store.operations.clear();
        store.operations.set(operationId, { ...operation });
        store.outbox.clear();
        const stored = { ...payload, guestHome: `/${"x".repeat(homeLength)}` };
        store.outbox.set("evt-1", {
          id: "evt-1",
          userId: "user-1",
          aggregateId: sandboxId,
          aggregateType: "sandbox",
          processedAt: null,
          sentAt: null,
          claimToken: null,
          payload: stored,
        });
        const fits = commandRunDispatchFitsControlLimit(stored, sandboxId);
        expect(fits).toBe(homeLength === 63800);
        await processSandboxOutboxBatch();
        if (fits) {
          expect(socket.dispatches).toHaveLength(1);
          const wire = socket.dispatches[0]!;
          expect(wire).toMatchObject({ attempt, stdinSequence: sequence });
          expect(wire.env).toEqual(env ? [["K", "V".repeat(20)]] : undefined);
          expect(new TextEncoder().encode(JSON.stringify(wire)).byteLength).toBeLessThanOrEqual(
            encodedCommandRunDispatchControlBytes(
              commandRunDispatchBuildInputForEnqueueGuard(stored, sandboxId),
            ),
          );
          expect(store.outbox.get("evt-1")!.sentAt).not.toBeNull();
        } else {
          expect(socket.dispatches).toHaveLength(0);
          expect(store.operations.get(operationId)).toMatchObject({
            state: attempt === 1 ? "FAILED" : "UNKNOWN_OUTCOME",
            errorCode: "request_too_large",
          });
        }
      }
    },
  );

  it("C15-S4 revocation after encode failure leaves exactly ordinary revoke state", async () => {
    const socket = await connect();
    Object.assign(store.outbox.get("evt-1")!.payload, { script: "x".repeat(65536) });
    const dispatch = manager.dispatchOperation.bind(manager);
    let revokedState: unknown;
    const state = () =>
      structuredClone({
        hosts: store.hosts,
        sandboxes: store.sandboxes,
        operations: store.operations,
        outbox: store.outbox,
      });
    vi.spyOn(manager, "dispatchOperation").mockImplementationOnce(async (...args) => {
      try {
        return await dispatch(...args);
      } catch (error) {
        expect(store.hosts.get("host-1")!.connectionEpoch).toBe(1);
        expect(store.operations.get("op-1")).toMatchObject({
          state: "DISPATCHED",
          dispatchedConnectionEpoch: 1,
        });
        expect(store.outbox.get("evt-1")).toMatchObject({
          sentConnectionEpoch: 1,
          claimToken: expect.any(String),
        });
        // removeSession runs the actual revokeEpoch implementation. Wait for
        // its commit before the terminalizer even starts its transaction/read.
        const revocation = manager.removeSession(socket);
        const transaction = db.$transaction.getMockImplementation()!;
        db.$transaction.mockImplementationOnce(async (...txArgs) => {
          await revocation;
          expect(store.hosts.get("host-1")!.connectionEpoch).toBe(2);
          revokedState = state();
          return transaction(...txArgs);
        });
        throw error;
      }
    });
    expect(await processSandboxOutboxBatch()).toBe(0);
    expect(revokedState).toBeDefined();
    expect(state()).toEqual(revokedState);
    expect(socket.dispatches).toHaveLength(0);
    expect(store.operations.get("op-1")!.state).toBe("DISPATCHED");
    expect(store.outbox.get("evt-1")!.processedAt).toBeNull();
  });

  it.each(["operation epoch", "event epoch", "claim"])(
    "C15-S4 rolls back all failure writes when %s no longer matches",
    async (changed) => {
      const socket = await connect();
      Object.assign(store.outbox.get("evt-1")!.payload, { script: "x".repeat(65536) });
      const dispatch = manager.dispatchOperation.bind(manager);
      let expected: unknown;
      const state = () =>
        structuredClone({
          hosts: store.hosts,
          sandboxes: store.sandboxes,
          operations: store.operations,
          outbox: store.outbox,
        });
      vi.spyOn(manager, "dispatchOperation").mockImplementationOnce(async (...args) => {
        try {
          return await dispatch(...args);
        } catch (error) {
          if (changed === "operation epoch")
            store.operations.get("op-1")!.dispatchedConnectionEpoch = 2;
          else if (changed === "event epoch") store.outbox.get("evt-1")!.sentConnectionEpoch = 2;
          else store.outbox.get("evt-1")!.claimToken = "replacement";
          expected = state();
          throw error;
        }
      });
      expect(await processSandboxOutboxBatch()).toBe(0);
      expect(expected).toBeDefined();
      expect(state()).toEqual(expected);
      expect(socket.dispatches).toHaveLength(0);
    },
  );

  it("C15-S4 empty non-EOF stdin terminalizes before send and allows later events", async () => {
    const socket = await connect();
    Object.assign(store.operations.get("op-1")!, {
      state: "RUNNING",
      dispatchAttempt: 1,
      acceptedAttempt: 1,
      dispatchedHostId: "host-1",
      dispatchedConnectionEpoch: 1,
      nextStdinSequence: 1,
    });
    Object.assign(store.outbox.get("evt-1")!.payload, {
      kind: "process.stdin",
      dispatchAttempt: 1,
      stdinSequence: 0,
      stdinBase64: "",
      eof: false,
    });
    await enqueue("later");
    expect(await processSandboxOutboxBatch()).toBe(1);
    expect(store.operations.get("op-1")).toMatchObject({
      state: "RUNNING",
      dispatchAttempt: 1,
    });
    expect(store.outbox.get("evt-1")).toMatchObject({
      processedAt: expect.any(Date),
      claimToken: null,
    });
    expect(socket.binary).toHaveLength(0);
    expect(socket.dispatches.map((message) => message.operationId)).toEqual(["later"]);
    expect(await processSandboxOutboxBatch()).toBe(0);
  });

  it("preserves the long script from committed outbox through the wire", async () => {
    const fixture = JSON.parse(
      readFileSync(
        new URL(
          "../../../../crates/sandbox-protocol/fixtures/control_operation_dispatch_script.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    const socket = await connect();
    start();
    await enqueue("script", "sbx-1", fixture.script);
    await tick();
    const sent = socket.dispatches.find((message) => message.operationId === "script");
    expect(sent?.script).toBe(fixture.script);
    expect(sent?.argv).toBeUndefined();
    expect(sent?.timeoutMs).toBe(120_000);
  });

  it("C34: a create dispatch carries the recorded egress policy; a malformed one fails closed", async () => {
    const socket = await connect(true, true, false, true);
    Object.assign(store.operations.get("op-1")!, { kind: "CREATE_SANDBOX" });
    Object.assign(store.sandboxes.get("sbx-1")!, {
      state: "PROVISIONING",
      liveResourcesHeld: true,
    });
    Object.assign(store.outbox.get("evt-1")!.payload, {
      diskGiB: 32,
      kind: "sandbox.create",
      cpuCount: 1,
      memoryMiB: 1024,
      dispatchAttempt: 0,
      egressPolicy: { domains: ["example.com"], cidrs: [] },
      egressPolicyHash: "b".repeat(64),
    });
    start();
    await tick();
    expect(socket.dispatches).toHaveLength(1);
    expect(socket.dispatches[0]).toMatchObject({
      allocation: { diskGiB: 32 },
      kind: "sandbox.create",
      cpuCount: 1,
      memoryMiB: 1024,
      egressPolicy: { domains: ["example.com"], cidrs: [] },
      egressPolicyHash: "b".repeat(64),
    });
  });

  it("C34: a non-canonical durable egress policy fails closed before any send", async () => {
    const socket = await connect(true, true, false, true);
    Object.assign(store.operations.get("op-1")!, { kind: "CREATE_SANDBOX" });
    Object.assign(store.sandboxes.get("sbx-1")!, {
      state: "PROVISIONING",
      liveResourcesHeld: true,
    });
    store.hosts.get("host-1")!.liveCount = 1;
    store.hosts.get("host-1")!.memoryReservedMiB = 1344;
    store.hosts.get("host-1")!.vcpuReserved = 1;
    Object.assign(store.outbox.get("evt-1")!.payload, {
      diskGiB: 32,
      kind: "sandbox.create",
      cpuCount: 1,
      memoryMiB: 1024,
      dispatchAttempt: 0,
      incusName: "wssp-sbx-sbx-1",
      templateDigest: `sha256:${"a".repeat(64)}`,
      incusFingerprint: `sha256:${"a".repeat(64)}`,
      architecture: "x86_64",
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
      guestShell: "/bin/bash",
      egressPolicy: { domains: ["UPPER.example.com"], cidrs: [] },
      egressPolicyHash: "b".repeat(64),
    });
    start();
    await tick();
    expect(socket.dispatches).toHaveLength(0);
    expect(store.operations.get("op-1")!.state).toBe("FAILED");
    expect(store.operations.get("op-1")!.errorCode).toBe("protocol_error");
  });

  const downgradeFixture = (kind: "sandbox.create" | "sandbox.reconnect", attempt: number) => {
    Object.assign(store.operations.get("op-1")!, {
      kind: kind === "sandbox.create" ? "CREATE_SANDBOX" : "RECONNECT_SANDBOX",
      state: attempt === 0 ? "QUEUED" : "DISPATCHED",
      dispatchAttempt: attempt,
      dispatchedHostId: attempt === 0 ? null : "host-1",
      dispatchedConnectionEpoch: attempt === 0 ? null : 1,
    });
    Object.assign(store.sandboxes.get("sbx-1")!, {
      state: kind === "sandbox.create" ? "PROVISIONING" : "STOPPED",
      liveResourcesHeld: true,
    });
    store.hosts.get("host-1")!.liveCount = 1;
    store.hosts.get("host-1")!.memoryReservedMiB = 1344;
    store.hosts.get("host-1")!.vcpuReserved = 1;
    Object.assign(store.outbox.get("evt-1")!.payload, {
      diskGiB: 32,
      kind,
      cpuCount: 1,
      memoryMiB: 1024,
      dispatchAttempt: attempt,
      incusName: "wssp-sbx-sbx-1",
      templateDigest: `sha256:${"a".repeat(64)}`,
      incusFingerprint: `sha256:${"a".repeat(64)}`,
      architecture: "x86_64",
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
      guestShell: "/bin/bash",
      egressPolicy: { domains: ["example.com"], cidrs: [] },
      egressPolicyHash: "b".repeat(64),
    });
  };

  it("C34: a replacement hello dropping egress enforcement sends zero queued creates", async () => {
    await connect();
    downgradeFixture("sandbox.create", 0);
    // A replacement daemon without the capability takes over the epoch.
    const replacement = await connect(true, false);
    expect(store.hosts.get("host-1")!.egressEnforcement).toBe(false);
    start();
    await tick();
    expect(replacement.dispatches).toHaveLength(0);
    expect(store.operations.get("op-1")).toMatchObject({
      state: "FAILED",
      errorCode: "unsupported_capability",
    });
    // A never-dispatched create is a knowable failure: the sandbox leaves the
    // transitional states and the reserved capacity is released.
    expect(store.sandboxes.get("sbx-1")).toMatchObject({
      state: "ERROR",
      lastErrorCode: "unsupported_capability",
      liveResourcesHeld: false,
    });
    expect(store.hosts.get("host-1")!.liveCount).toBe(0);
    expect(store.outbox.get("evt-1")!.processedAt).toEqual(expect.any(Date));
    expect(await processSandboxOutboxBatch()).toBe(0);
  });

  it("C34: a create dispatched before a downgrading hello keeps its uncertainty and is never resent (census reconciliation)", async () => {
    const socket = await connect(true, true, false, true);
    downgradeFixture("sandbox.create", 0);
    start();
    await tick();
    // The first dispatch went through the production claim path: the
    // operation attempt advanced while the durable payload kept
    // dispatchAttempt 0.
    expect(socket.dispatches).toHaveLength(1);
    expect(socket.dispatches[0]).toMatchObject({ kind: "sandbox.create", attempt: 1 });
    expect(store.operations.get("op-1")).toMatchObject({
      state: "DISPATCHED",
      dispatchAttempt: 1,
      dispatchedConnectionEpoch: 1,
    });
    expect(store.outbox.get("evt-1")!.payload.dispatchAttempt).toBe(0);

    // A capability-downgrading replacement hello reopens the sent intent and
    // its census reconciles the interrupted launch.
    const replacement = await connect(true, false);
    expect(store.hosts.get("host-1")).toMatchObject({
      connectionEpoch: 2,
      egressEnforcement: false,
    });
    expect(store.outbox.get("evt-1")).toMatchObject({ sentAt: null, claimToken: null });
    expect(replacement.dispatches).toHaveLength(0);
    expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");

    // The reopened event is retired without any send; uncertainty is retained
    // and the sandbox state is NOT authored — the epoch-1 dispatch may have
    // launched the VM.
    await processSandboxOutboxBatch();
    expect(replacement.dispatches).toHaveLength(0);
    expect(socket.dispatches).toHaveLength(1);
    expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
    expect(store.sandboxes.get("sbx-1")!.state).toBe("PROVISIONING");
    expect(store.outbox.get("evt-1")!.processedAt).toEqual(expect.any(Date));
    expect(await processSandboxOutboxBatch()).toBe(0);
  });

  it("C34: a dispatched warm reconnect whose replacement hello drops the capability is never resent", async () => {
    const socket = await connect(true, true, false, true);
    // A warm reconnect targets a READY sandbox, so the replacement census
    // converges nothing and the dispatch gate is the backstop that retires
    // the reopened intent.
    downgradeFixture("sandbox.reconnect", 0);
    Object.assign(store.sandboxes.get("sbx-1")!, { state: "READY" });
    start();
    await tick();
    // The first dispatch went through the production claim path: the
    // operation attempt advanced while the durable payload kept
    // dispatchAttempt 0.
    expect(socket.dispatches).toHaveLength(1);
    expect(socket.dispatches[0]).toMatchObject({ kind: "sandbox.reconnect", attempt: 1 });
    expect(store.operations.get("op-1")).toMatchObject({
      state: "DISPATCHED",
      dispatchAttempt: 1,
      dispatchedConnectionEpoch: 1,
    });
    expect(store.outbox.get("evt-1")!.payload.dispatchAttempt).toBe(0);

    const replacement = await connect(true, false);
    expect(store.hosts.get("host-1")).toMatchObject({
      connectionEpoch: 2,
      egressEnforcement: false,
    });
    expect(store.outbox.get("evt-1")).toMatchObject({ sentAt: null, claimToken: null });
    expect(replacement.dispatches).toHaveLength(0);
    // Reconciliation classifies the interrupted warm reconnect; the reopened
    // intent is then retired without any send and the uncertainty retained.
    expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");

    await processSandboxOutboxBatch();
    expect(replacement.dispatches).toHaveLength(0);
    expect(socket.dispatches).toHaveLength(1);
    expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
    expect(store.sandboxes.get("sbx-1")!.state).toBe("READY");
    expect(store.outbox.get("evt-1")!.processedAt).toEqual(expect.any(Date));
    expect(await processSandboxOutboxBatch()).toBe(0);
  });

  it("C34: a capability downgrade sends zero cold-reconnect launches", async () => {
    await connect();
    downgradeFixture("sandbox.reconnect", 0);
    const replacement = await connect(true, false);
    start();
    await tick();
    expect(replacement.dispatches).toHaveLength(0);
    expect(store.operations.get("op-1")).toMatchObject({
      state: "FAILED",
      errorCode: "unsupported_capability",
    });
  });

  it("scans empty startup, dispatches only after commit, and recovers a lost wake", async () => {
    store.outbox.clear();
    const socket = await connect();
    start();
    await tick();
    expect(socket.dispatches).toHaveLength(0);
    const entered = gate(),
      resume = gate();
    store.barriers.beforeCommit = async () => {
      store.barriers.beforeCommit = undefined;
      entered.resolve();
      await resume.promise;
    };
    const work = enqueue();
    await entered.promise;
    await tick();
    expect(socket.dispatches).toHaveLength(0);
    resume.resolve();
    await work;
    await tick();
    expect(socket.dispatches).toHaveLength(1);
    bindSandboxDispatchWake(null);
    await enqueue("lost-wake");
    await vi.advanceTimersByTimeAsync(1999);
    expect(socket.dispatches).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(socket.dispatches).toHaveLength(2);
  });

  it.each(["service", "relay"])(
    "%s rollback after staged insertion never dispatches",
    async (source) => {
      store.outbox.clear();
      const socket = await connect();
      start();
      await tick();
      const entered = gate(),
        resume = gate();
      store.barriers.beforeCommit = async () => {
        store.barriers.beforeCommit = undefined;
        entered.resolve();
        await resume.promise;
        throw new Error("commit rejected");
      };
      const work =
        source === "service"
          ? enqueue()
          : relayTransaction(async (tx) => {
              await tx.outboxEvent.create({
                data: {
                  userId: "user-1",
                  aggregateType: "sandbox",
                  aggregateId: "sbx-1",
                  eventType: "sandbox.command_requested",
                  operationId: "op-1",
                  payload: {
                    operationId: "op-1",
                    sandboxId: "sbx-1",
                    sandboxHostId: "host-1",
                    generation: 1,
                    dispatchAttempt: 0,
                    kind: "command.run",
                  },
                },
              });
              return true;
            }, false);
      const rejected = expect(work).rejects.toThrow(
        source === "service" ? "commit rejected" : "An internal error occurred.",
      );
      await entered.promise;
      const scans = db.outboxEvent.findMany.mock.calls.length;
      await tick();
      resume.resolve();
      await rejected;
      await tick();
      expect(db.outboxEvent.findMany).toHaveBeenCalledTimes(scans);
      await vi.advanceTimersByTimeAsync(2000);
      expect(store.outbox.size).toBe(0);
      expect(socket.dispatches).toHaveLength(0);
    },
  );

  it.each(["result", "receipt", "scan", "reconcile"])(
    "expired create via %s dispatches cleanup without recovery time",
    async (path) => {
      const socket = await connect();
      expiredCreate();
      if (path !== "scan") store.outbox.get("evt-1")!.sentAt = new Date();
      start();
      await tick();
      const now = Date.now();
      if (path === "result") await frame(socket, result);
      if (path === "receipt")
        await frame(socket, {
          sandboxOwnerId: "user-1",
          ...result,
          id: undefined,
          error: null,
          type: "operation.receipt",
          kind: "sandbox.create",
          bodyHash: "a".repeat(64),
          idempotencyKey: "op-1",
        });
      const current = path === "reconcile" ? await connect() : socket;
      await tick();
      expect(Date.now()).toBe(now);
      expect(current.dispatches.map((message) => message.kind)).toEqual(["sandbox.stop"]);
    },
  );

  it("hello drain waits, then delayed reconcile.complete dispatches immediately", async () => {
    const socket = await connect(false);
    start();
    await tick();
    expect(socket.dispatches).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(500);
    await reconcileHost(socket);
    await tick();
    expect(socket.dispatches).toHaveLength(1);
  });

  it.each(["accepted", "running"])(
    "%s unlocks cancel and stdin with no recovery tick",
    async (state) => {
      const socket = await connect();
      start();
      await tick();
      const { cancelOperation, writeStdin } = await import(
        "../../../../packages/api/src/sandbox/services/sandboxes"
      );
      db.sandboxOperation.findFirst.mockImplementation(() =>
        Object.assign(prismaPromise(Promise.resolve(store.operations.get("op-1")! as never)), {
          User: vi.fn(),
          Sandbox: vi.fn(),
          TypedResult: vi.fn(),
          CommandOutput: vi.fn(),
          Placement: vi.fn(),
          Capture: vi.fn(),
          CapacityWait: vi.fn(),
          CredentialSpec: vi.fn(),
          RestoreWait: vi.fn(),
        }),
      );
      // Stdin requires the attested process identity before acceptance.
      await frame(socket, commandResultFixture(store).birth);
      // Stdin and cancel have different state gates; exercise them independently.
      await writeStdin(
        { kind: "session" as const, ownerId: "user-1" },
        { operationId: "op-1", contentBase64: "eA==", eof: true },
      );
      await tick();
      expect(socket.binary).toHaveLength(0);
      await frame(socket, { ...result, result: undefined, type: "operation.progress", state });
      await tick();
      expect(socket.binary).toHaveLength(1);
      // Simulate a second unaccepted dispatch for cancellation's acceptance gate.
      Object.assign(store.operations.get("op-1")!, { state: "DISPATCHED", acceptedAttempt: null });
      await cancelOperation(
        { kind: "session" as const, ownerId: "user-1" },
        { operationId: "op-1" },
      );
      await tick();
      expect(socket.messages.filter((message) => message.type === "operation.cancel")).toHaveLength(
        0,
      );
      await frame(socket, { ...result, result: undefined, type: "operation.progress", state });
      await tick();
      expect(socket.messages.filter((message) => message.type === "operation.cancel")).toHaveLength(
        1,
      );
    },
  );

  it("enqueue during held claim drains both batches without overlapping owners", async () => {
    const socket = await connect();
    const entered = gate(),
      resume = gate();
    store.barriers.afterCommit = async () => {
      store.barriers.afterCommit = undefined;
      entered.resolve();
      await resume.promise;
    };
    start();
    await tick();
    await entered.promise;
    await enqueue("during-claim");
    expect(socket.dispatches).toHaveLength(0);
    resume.resolve();
    await tick();
    expect(socket.dispatches).toHaveLength(2);
    expect(new Set(socket.dispatches.map((message) => message.operationId)).size).toBe(2);
  });

  it("stops between items after a held claim and resumes a 34-row backlog on restart", async () => {
    const socket = await connect();
    for (let i = 0; i < 33; i++) await enqueue(`backlog-${i}`);
    const entered = gate(),
      resume = gate();
    store.barriers.afterCommit = async () => {
      store.barriers.afterCommit = undefined;
      entered.resolve();
      await resume.promise;
    };
    start();
    await tick();
    await entered.promise;
    const stopping = stop!();
    expect(stop!()).toBe(stopping);
    let done = false;
    void stopping.then(() => {
      done = true;
    });
    await tick();
    expect(done).toBe(false);
    resume.resolve();
    await stopping;
    expect(socket.dispatches).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(2000);
    expect(socket.dispatches).toHaveLength(1);
    start();
    await tick();
    expect(socket.dispatches).toHaveLength(34);
  });

  it("passes 32 waiting control rows to dispatch the next page", async () => {
    const socket = await connect();
    store.outbox.clear();
    Object.assign(store.operations.get("op-1")!, {
      state: "DISPATCHED",
      dispatchAttempt: 1,
      dispatchedHostId: "host-1",
      dispatchedConnectionEpoch: 1,
    });
    for (let i = 0; i < 32; i++)
      store.outbox.set(`a-${i.toString().padStart(2, "0")}`, {
        id: `a-${i.toString().padStart(2, "0")}`,
        userId: "user-1",
        aggregateId: "sbx-1",
        aggregateType: "sandbox",
        processedAt: null,
        sentAt: null,
        claimToken: null,
        payload: {
          operationId: "op-1",
          sandboxId: "sbx-1",
          sandboxHostId: "host-1",
          generation: 1,
          dispatchAttempt: 1,
          kind: "process.stdin",
          stdinSequence: i,
        },
      });
    await enqueue("page-two");
    start();
    await tick();
    expect(socket.dispatches.map((message) => message.operationId)).toEqual(["page-two"]);
    expect(socket.binary).toHaveLength(0);
  });

  it("shutdown stops READY lease reclaim between sandboxes", async () => {
    store.outbox.clear();
    const socket = await connect();
    const base = store.sandboxes.get("sbx-1")!;
    base.leaseExpiresAt = new Date(Date.now() - 1);
    for (let i = 0; i < 33; i++)
      store.sandboxes.set(`expired-${i}`, { ...base, id: `expired-${i}` });
    const entered = gate(),
      resume = gate();
    store.barriers.afterCommit = async () => {
      store.barriers.afterCommit = undefined;
      entered.resolve();
      await resume.promise;
    };
    start();
    await tick();
    await entered.promise;
    const stopping = stop!();
    resume.resolve();
    await stopping;
    expect([...store.sandboxes.values()].filter((row) => row.state === "STOPPING")).toHaveLength(1);
    expect(store.outbox.size).toBe(1);
    expect(socket.dispatches).toHaveLength(0);
  });

  it.each(["claim", "send"])(
    "restart after interruption at %s preserves unknown outcome without rerun",
    async (phase) => {
      const socket = await connect();
      vi.spyOn(console, "error").mockImplementation(() => {});
      if (phase === "claim")
        store.barriers.afterCommit = async () => {
          store.barriers.afterCommit = undefined;
          throw new Error("crash after durable claim");
        };
      else
        socket.onDispatch = () => {
          db.outboxEvent.updateMany.mockRejectedValueOnce(
            new Error("crash before send confirmation"),
          );
        };
      start();
      await tick();
      expect(store.operations.get("op-1")!.state).toBe("DISPATCHED");
      expect(socket.dispatches).toHaveLength(phase === "send" ? 1 : 0);
      await stop!();
      const replacement = await connect();
      start();
      await tick();
      expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
      expect(replacement.dispatches).toHaveLength(0);
    },
  );

  it.each(["claim", "send", "scan", "finalization"])(
    "SIGTERM with held %s waits before sessions/Prisma/Redis teardown; repeated signals are safe",
    async (phase) => {
      const socket = await connect();
      if (phase === "finalization") expiredCreate();
      const listeners = new Map<string, (...args: unknown[]) => void>();
      const order: string[] = [];
      vi.spyOn(process, "on").mockImplementation((event, listener) => {
        listeners.set(String(event), listener);
        return process;
      });
      vi.spyOn(process, "exit").mockImplementation(() => {
        order.push("exit");
        return undefined as never;
      });
      db.$disconnect.mockImplementation(async () => {
        order.push("db");
      });
      vi.mocked(redisConnection.disconnect).mockImplementation(() => {
        order.push("redis");
      });
      const dispose = vi.spyOn(manager, "dispose");
      const entered = gate(),
        resume = gate();
      const hold = async () => {
        entered.resolve();
        await resume.promise;
        order.push("drained");
      };
      if (phase === "scan")
        db.outboxEvent.findMany.mockImplementationOnce(() => prismaPromise(hold().then(() => [])));
      else if (phase === "send")
        socket.onDispatch = () => {
          // socket.send is synchronous. Hold the post-send durable confirmation.
          store.barriers.beforeCommit = async () => {
            store.barriers.beforeCommit = undefined;
            await hold();
          };
        };
      else
        store.barriers.afterCommit = async () => {
          store.barriers.afterCommit = undefined;
          await hold();
        };
      const lifecycle = createServerLifecycle();
      const close = vi.fn((done: () => void) => done());
      await lifecycle.start(() => ({ close }));
      await tick();
      await entered.promise;
      listeners.get("SIGTERM")!();
      listeners.get("SIGTERM")!();
      listeners.get("SIGINT")!();
      await vi.advanceTimersByTimeAsync(5000);
      expect(dispose).not.toHaveBeenCalled();
      expect(db.$disconnect).not.toHaveBeenCalled();
      expect(redisConnection.disconnect).not.toHaveBeenCalled();
      resume.resolve();
      await tick();
      expect(order).toEqual(["drained", "db", "redis", "exit"]);
      expect(dispose).toHaveBeenCalledOnce();
      expect(close).toHaveBeenCalledOnce();
      expect(process.exit).toHaveBeenCalledWith(0);
    },
  );

  it("measures six concurrent fake clients through enqueue, dispatch and host result", {
    timeout: 15_000,
  }, async () => {
    vi.useRealTimers();
    store.outbox.clear();
    const socket = await connect();
    const sent = new Map<string, number>();
    const completed = new Map<string, ReturnType<typeof gate>>();
    // Fake runtime reports command completion through the real
    // ordered host receive queue. No production session/dispatch method is mocked.
    socket.onDispatch = (message) => {
      const id = String(message.operationId);
      sent.set(id, performance.now());
      const commandResult = commandResultFixture(store, id);
      setTimeout(() => {
        void frame(socket, {
          id: `result-${id}`,
          operationId: id,
          sandboxId: message.sandboxId,
          generation: message.generation,
          attempt: message.attempt,
          type: "operation.result",
          state: "succeeded",
          result: commandResult,
        }).then(() => completed.get(id)!.resolve());
      }, 1);
    };
    start();
    const dispatchMs: number[] = [],
      cycleMs: number[] = [];
    const clientCount = 6,
      cyclesPerClient = 20;
    await Promise.all(
      Array.from({ length: clientCount }, async (_, client) => {
        for (let cycle = 0; cycle < cyclesPerClient; cycle++) {
          const id = `client-${client}-cycle-${cycle}`;
          const done = gate();
          completed.set(id, done);
          const began = performance.now();
          await enqueue(id);
          await done.promise;
          dispatchMs.push(sent.get(id)! - began);
          cycleMs.push(performance.now() - began);
          expect(store.operations.get(id)!.state).toBe("SUCCEEDED");
        }
      }),
    );
    const stats = (values: number[]) => {
      const sorted = values.toSorted((a, b) => a - b);
      return Object.fromEntries(
        [
          ["p50", 0.5],
          ["p95", 0.95],
          ["max", 1],
        ].map(([key, p]) => [
          key,
          Number(sorted[Math.ceil(sorted.length * Number(p)) - 1]!.toFixed(3)),
        ]),
      );
    };
    console.log(
      `DISPATCH_LATENCY ${JSON.stringify({
        clients: clientCount,
        cyclesPerClient,
        samples: cycleMs.length,
        enqueueToSendMs: stats(dispatchMs),
        cycleMs: stats(cycleMs),
      })}`,
    );
    expect(cycleMs).toHaveLength(120);
    expect(socket.dispatches).toHaveLength(120);
  });
});

it("C29 a saturated upload pool strands no committed dispatch: the extra event stays retryable and recovers", async () => {
  store.outbox.clear();
  const hang = () => new Promise<Uint8Array>(() => {});
  let releaseFirst!: (bytes: Uint8Array) => void;
  // Sixteen uploads whose streams park on their first ACK, plus a seventeenth.
  for (let i = 0; i < 17; i++) {
    const id = `put-${String(i).padStart(2, "0")}`;
    store.operations.set(id, {
      id,
      userId: "user-1",
      sandboxId: "sbx-1",
      kind: "PUT_FILE",
      state: "QUEUED",
      idempotencyKey: id,
      requestBodyHash: "a".repeat(64),
      generation: 1,
      dispatchAttempt: 0,
      acceptedAttempt: null,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
      nextStdinSequence: 0,
      completedAt: null,
    });
    store.outbox.set(`evt-${id}`, {
      id: `evt-${id}`,
      userId: "user-1",
      aggregateType: "sandbox",
      aggregateId: "sbx-1",
      processedAt: null,
      sentAt: null,
      claimToken: null,
      claimedAt: null,
      sentConnectionEpoch: null,
      payload: {
        operationId: id,
        sandboxId: "sbx-1",
        sandboxHostId: "host-1",
        generation: 1,
        dispatchAttempt: 0,
        kind: "file.put",
        transferId: `tr-${String(i).padStart(2, "0")}`,
        destPath: "/tmp/f",
      },
    });
    fakeUploadSources.sources.set(`tr-${String(i).padStart(2, "0")}`, {
      size: 1,
      sha256: "b".repeat(64),
      read:
        i === 0
          ? () =>
              new Promise<Uint8Array>((resolve) => {
                releaseFirst = resolve;
              })
          : hang,
    });
  }
  const socket = await connect();
  expect(await processSandboxOutboxBatch()).toBe(16);
  expect(socket.dispatches).toHaveLength(16);
  // The seventeenth upload was never claimed: it stays pending and retryable
  // instead of stranding as DISPATCHED on an epoch no scan will retry.
  expect(store.operations.get("put-16")).toMatchObject({
    state: "QUEUED",
    dispatchAttempt: 0,
    dispatchedConnectionEpoch: null,
  });
  expect(store.outbox.get("evt-put-16")).toMatchObject({ processedAt: null, claimToken: null });
  // Capacity frees: the first stream's only chunk is ACKed and its task ends.
  releaseFirst(new Uint8Array([7]));
  await vi.advanceTimersByTimeAsync(0);
  await frame(socket, {
    type: "file.chunk.ack",
    operationId: "put-00",
    generation: 1,
    attempt: 1,
    sequence: 0,
    offset: 1,
  });
  await vi.advanceTimersByTimeAsync(0);
  // The next scan dispatches the waiting upload on the same epoch.
  expect(await processSandboxOutboxBatch()).toBe(1);
  expect(store.operations.get("put-16")).toMatchObject({
    state: "DISPATCHED",
    dispatchAttempt: 1,
  });
  expect(socket.dispatches).toHaveLength(17);
});
