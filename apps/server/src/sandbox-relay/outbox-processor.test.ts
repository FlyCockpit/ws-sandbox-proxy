import { seedAcceptedOperation } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { OPERATION_DISPATCH_KIND } from "@wssp/api/sandbox/contracts";
import {
  buildCommandRunOperationDispatchMessage,
  commandRunDispatchBuildInputFromOutboxPayload,
} from "@wssp/api/sandbox/dispatch-control-envelope";
import {
  initialProcessFields,
  initialResultFields,
  reserveOperationResult,
} from "@wssp/api/sandbox/operation-results";
import { bindSandboxDispatchWake } from "@wssp/api/sandbox/outbox";
import {
  cancelQueuedOperation,
  RelayFenceRejected,
  retireSupersededOperations,
} from "@wssp/api/sandbox/relay-fence";
import { CANCELLABLE_OPERATION_KINDS } from "@wssp/api/sandbox/state-transitions";
import { RESULT_TYPE_BY_KIND } from "@wssp/sandbox-contracts";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  commandResultFixture,
  gate,
  installFenceTransaction,
  matches,
  prismaPromise,
  relayStore,
} from "./fenced-prisma-harness.js";
import { encodeServerControlMessage, SandboxRelayDispatchValidationError } from "./protocol.js";

const upload = vi.hoisted(() => ({ source: vi.fn() }));
vi.mock("../sandbox-transfers/runtime.js", () => ({
  transferStore: () => ({ uploadSource: upload.source }),
}));

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "service-principal-test",
  },
}));

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    isHostQuiescing: vi.fn().mockReturnValue(false),
    dispatchOperation: vi.fn().mockReturnValue("sent"),
    cancelOperation: vi.fn().mockReturnValue(true),
    sendStdin: vi.fn().mockReturnValue(true),
    reserveFileStreamSlot: vi.fn(() => ({ release: vi.fn() })),
  },
}));
// Only the outbox processor's SDK-key revalidation is substituted; service
// authorization keeps its own (session) implementation.
vi.mock("@wssp/api/lib/sdk-key-access", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@wssp/api/lib/sdk-key-access")>()),
  checkAcceptedDispatchAuthority: vi.fn().mockResolvedValue("active"),
}));
const { default: prisma } = await import("@wssp/db");
const db = vi.mocked(prisma, true);
const { checkAcceptedDispatchAuthority } = await import("@wssp/api/lib/sdk-key-access");
const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");
const { processSandboxOutboxBatch, createSandboxOutboxDrain, SANDBOX_OUTBOX_FULL_PASS_MS } =
  await import("./outbox-processor.js");
const { applyOperationResult, applyOperationProgress, finishHostReconciliation } = await import(
  "./operation-handlers.js"
);
const sender = { hostId: "host-1", userId: "user-1", connectionEpoch: 1 };
const result = () =>
  applyOperationResult({
    sender,
    operationId: "op-1",
    sandboxId: "sbx-1",
    generation: 1,
    attempt: 1,
    state: "succeeded",
    result:
      store.operations.get("op-1")?.kind === "RUN_COMMAND"
        ? commandResultFixture(store)
        : {
            state:
              store.operations.get("op-1")?.kind === "KILL_SANDBOX"
                ? "deleted"
                : store.operations.get("op-1")?.kind === "STOP_SANDBOX"
                  ? "stopped"
                  : "ready",
            lease: store.outbox.get("evt-1")!.payload.lease,
          },
  });
let store = relayStore();
beforeEach(() => {
  vi.clearAllMocks();
  store = relayStore("RUN_COMMAND", "QUEUED");
  Object.assign(store.operations.get("op-1")!, {
    dispatchAttempt: 0,
    acceptedAttempt: null,
    dispatchedHostId: null,
    dispatchedConnectionEpoch: null,
  });
  store.outbox.get("evt-1")!.payload.dispatchAttempt = 0;
  installFenceTransaction(db, store);
  // Only the scans are outside transactions; every predicate/write runs the stateful double.
  db.outboxEvent.findMany.mockImplementation((args) =>
    prismaPromise(
      Promise.resolve(
        [...store.outbox.values()]
          .filter((event) => matches(event, args?.where as Record<string, unknown>))
          .sort((a, b) => a.id.localeCompare(b.id))
          .slice(0, args?.take ?? 32) as never,
      ),
    ),
  );
  db.outboxEvent.updateMany.mockImplementation((args) =>
    prismaPromise(db.$transaction((tx) => tx.outboxEvent.updateMany(args))),
  );
  db.$queryRaw.mockResolvedValue([]);
  db.sandboxOperation.findUnique.mockResolvedValue(null);
  vi.mocked(manager.isHostConnected).mockReturnValue(true);
  vi.mocked(manager.isHostQuiescing).mockReturnValue(false);
  vi.mocked(manager.dispatchOperation).mockResolvedValue("sent");
});
function running(kind = "operation.cancel") {
  Object.assign(store.operations.get("op-1")!, {
    state: kind === "operation.cancel" ? "CANCEL_REQUESTED" : "RUNNING",
    acceptedAttempt: 1,
    processPid: 123,
    processBootId: "12345678-1234-4234-8234-123456789abc",
    processStartTicks: "123456",
    processStartedAt: new Date("2026-10-27T00:00:00.000Z"),
    dispatchAttempt: 1,
    dispatchedHostId: "host-1",
    dispatchedConnectionEpoch: 1,
  });
  Object.assign(store.outbox.get("evt-1")!.payload, { kind, dispatchAttempt: 1, stdinSequence: 0 });
  store.operations.get("op-1")!.nextStdinSequence = 1;
}
const lifecycleCases = [
  ["CREATE_SANDBOX", "REQUESTED", "READY"],
  ["STOP_SANDBOX", "STOPPING", "STOPPED"],
  ["KILL_SANDBOX", "STOPPING", "DELETED"],
  ["RECONNECT_SANDBOX", "STOPPED", "READY"],
  ["RECONNECT_SANDBOX", "READY", "READY"],
] as const;

function mockOwnedOperation() {
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
}

describe("durable outbound fences", () => {
  it.each(["accepted", "running"])(
    "C10 host serialization: %s after committed cancel preserves intent and sends once",
    async (state) => {
      const { cancelOperation } = await import(
        "../../../../packages/api/src/sandbox/services/sandboxes"
      );
      running("command.run");
      Object.assign(store.operations.get("op-1")!, { state: "DISPATCHED", acceptedAttempt: null });
      store.outbox.clear();
      mockOwnedOperation();
      const beforeHost = gate();
      const resumeProgress = gate();
      store.barriers.beforeHostLock = async () => {
        store.barriers.beforeHostLock = undefined;
        beforeHost.resolve();
        await resumeProgress.promise;
      };
      const progress = applyOperationProgress({
        sender,
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        state,
      });
      // Progress pauses before H. Cancel acceptance takes H → S → O first.
      await beforeHost.promise;
      let receipt: Awaited<ReturnType<typeof cancelOperation>> | undefined;
      try {
        // Commit cancel before progress acquires H; progress then rereads the intent.
        receipt = await cancelOperation(
          { kind: "session" as const, ownerId: "user-1" },
          { operationId: "op-1" },
        );
        expect(receipt.state).toBe("CANCEL_REQUESTED");
        expect(store.operations.get("op-1")!.acceptedAttempt).toBeNull();
      } finally {
        resumeProgress.resolve();
      }
      expect(await progress).toEqual({ written: true });
      expect(store.operations.get("op-1")!).toMatchObject({
        state: "CANCEL_REQUESTED",
        acceptedAttempt: 1,
      });
      expect(
        await cancelOperation(
          { kind: "session" as const, ownerId: "user-1" },
          { operationId: "op-1" },
        ),
      ).toEqual(receipt);
      expect([...store.outbox.values()]).toHaveLength(1);
      await processSandboxOutboxBatch();
      await processSandboxOutboxBatch();
      expect(manager.cancelOperation).toHaveBeenCalledTimes(1);
      expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
      expect([...store.outbox.values()][0]!.processedAt).toBeNull();
    },
  );
  it.each(lifecycleCases)(
    "Fix5: %s in %s rejects cancel without writes and still completes as %s",
    async (kind, state, completedState) => {
      const { cancelOperation } = await import(
        "../../../../packages/api/src/sandbox/services/sandboxes"
      );
      store.operations.get("op-1")!.kind = kind;
      store.sandboxes.get("sbx-1")!.state = state;
      Object.assign(store.outbox.get("evt-1")!.payload, {
        kind: OPERATION_DISPATCH_KIND[kind],
        egressPolicy: { domains: [], cidrs: [] },
        egressPolicyHash: "a".repeat(64),
      });
      mockOwnedOperation();
      for (const operationState of ["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING"]) {
        store.operations.get("op-1")!.state = operationState;
        await expect(
          cancelOperation({ kind: "session" as const, ownerId: "user-1" }, { operationId: "op-1" }),
        ).rejects.toMatchObject({
          code: "CONFLICT",
          data: { code: "sandbox.state_conflict" },
          message: "lifecycle operations cannot be cancelled; use kill",
        });
        expect(store.writes).toEqual([]);
        expect(db.$transaction).not.toHaveBeenCalled();
        expect(store.sandboxes.get("sbx-1")!.state).toBe(state);
        expect(store.operations.get("op-1")!.state).toBe(operationState);
        expect(store.outbox.get("evt-1")!.processedAt).toBeNull();
      }
      store.operations.get("op-1")!.state = "QUEUED";
      expect(await processSandboxOutboxBatch()).toBe(1);
      expect(manager.dispatchOperation).toHaveBeenCalledWith(
        "host-1",
        expect.objectContaining({ kind: OPERATION_DISPATCH_KIND[kind] }),
      );
      expect(await result()).toEqual({ written: true });
      expect(store.sandboxes.get("sbx-1")!.state).toBe(completedState);
    },
  );

  it("C34: a downgraded host never receives a retried launch; the durable payload keeps dispatchAttempt 0", async () => {
    // Production representation after the first send: the operation advanced
    // to attempt 1 at epoch 1, while the durable event payload still carries
    // dispatchAttempt 0 (the claim rewrite preserves the payload's attempt).
    Object.assign(store.operations.get("op-1")!, {
      kind: "RECONNECT_SANDBOX",
      state: "DISPATCHED",
      dispatchAttempt: 1,
      dispatchedHostId: "host-1",
      dispatchedConnectionEpoch: 1,
    });
    store.sandboxes.get("sbx-1")!.liveResourcesHeld = true;
    store.hosts.get("host-1")!.liveCount = 1;
    store.hosts.get("host-1")!.memoryReservedMiB = 1344;
    store.hosts.get("host-1")!.vcpuReserved = 1;
    // The replacement hello bumped the epoch and dropped the capability.
    Object.assign(store.hosts.get("host-1")!, {
      connectionEpoch: 2,
      journalKeyAcknowledgedEpoch: 2,
      egressEnforcement: false,
    });
    Object.assign(store.outbox.get("evt-1")!.payload, {
      kind: "sandbox.reconnect",
      dispatchAttempt: 0,
      egressPolicy: { domains: ["example.com"], cidrs: [] },
      egressPolicyHash: "b".repeat(64),
    });
    expect(await processSandboxOutboxBatch()).toBe(0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(store.operations.get("op-1")).toMatchObject({
      state: "UNKNOWN_OUTCOME",
      errorCode: "unsupported_capability",
    });
    // Uncertainty is retained: the epoch-1 dispatch may have launched, so the
    // gate must NOT author the sandbox state.
    expect(store.sandboxes.get("sbx-1")!.state).toBe("READY");
    expect(store.sandboxes.get("sbx-1")!.lastErrorCode ?? null).toBeNull();
    expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
  });
  it("C34: a never-dispatched create on a downgraded host fails atomically and leaves no transitional sandbox", async () => {
    Object.assign(store.operations.get("op-1")!, {
      kind: "CREATE_SANDBOX",
      state: "QUEUED",
      dispatchAttempt: 0,
    });
    Object.assign(store.sandboxes.get("sbx-1")!, {
      state: "PROVISIONING",
      liveResourcesHeld: true,
    });
    store.hosts.get("host-1")!.liveCount = 1;
    store.hosts.get("host-1")!.memoryReservedMiB = 1344;
    store.hosts.get("host-1")!.vcpuReserved = 1;
    store.hosts.get("host-1")!.egressEnforcement = false;
    Object.assign(store.outbox.get("evt-1")!.payload, {
      kind: "sandbox.create",
      dispatchAttempt: 0,
      egressPolicy: { domains: ["example.com"], cidrs: [] },
      egressPolicyHash: "b".repeat(64),
    });
    expect(await processSandboxOutboxBatch()).toBe(0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(store.operations.get("op-1")).toMatchObject({
      state: "FAILED",
      errorCode: "unsupported_capability",
    });
    expect(store.sandboxes.get("sbx-1")).toMatchObject({
      state: "ERROR",
      lastErrorCode: "unsupported_capability",
      liveResourcesHeld: false,
    });
    expect(store.hosts.get("host-1")!.liveCount).toBe(0);
    expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
  });
  it.each(lifecycleCases)("Fix5: queued helper refuses %s before writes", async (kind) => {
    await expect(
      db.$transaction((tx) =>
        cancelQueuedOperation(
          tx,
          {
            operationId: "op-1",
            sandboxId: "sbx-1",
            userId: "user-1",
            generation: 1,
            attempt: 0,
            hostId: null,
            kind,
          },
          new Date(),
        ),
      ),
    ).rejects.toBeInstanceOf(RelayFenceRejected);
    expect(store.writes).toEqual([]);
  });
  it("Fix5: a caller cannot cancel a lifecycle row by supplying an ordinary kind", async () => {
    store.operations.get("op-1")!.kind = "STOP_SANDBOX";
    await expect(
      db.$transaction((tx) =>
        cancelQueuedOperation(
          tx,
          {
            operationId: "op-1",
            sandboxId: "sbx-1",
            userId: "user-1",
            generation: 1,
            attempt: 0,
            hostId: null,
            kind: "RUN_COMMAND",
          },
          new Date(),
        ),
      ),
    ).rejects.toBeInstanceOf(RelayFenceRejected);
    expect(store.operations.get("op-1")!.state).toBe("QUEUED");
    expect(store.outbox.get("evt-1")!.processedAt).toBeNull();
  });
  it.each(lifecycleCases)(
    "Fix5: scanner discards only legacy cancel of %s in %s",
    async (kind, state) => {
      for (const operationState of ["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING"]) {
        store.operations.get("op-1")!.kind = kind;
        store.operations.get("op-1")!.state = operationState;
        store.sandboxes.get("sbx-1")!.state = state;
        const dispatch = store.outbox.get("evt-1")!;
        Object.assign(dispatch.payload, {
          kind: OPERATION_DISPATCH_KIND[kind],
          egressPolicy: { domains: [], cidrs: [] },
          egressPolicyHash: "a".repeat(64),
        });
        // Keep the original dispatch outside this scan; only the cancel is eligible.
        dispatch.sentAt = new Date();
        store.outbox.set("a-cancel", {
          ...dispatch,
          id: "a-cancel",
          sentAt: null,
          payload: { ...dispatch.payload, kind: "operation.cancel" },
        });
        const original = structuredClone(store.operations.get("op-1"));
        expect(await processSandboxOutboxBatch()).toBe(0);
        expect(store.operations.get("op-1")).toEqual(original);
        expect(store.sandboxes.get("sbx-1")!.state).toBe(state);
        expect(store.outbox.get("evt-1")!.processedAt).toBeNull();
        expect(store.outbox.get("a-cancel")!.processedAt).not.toBeNull();
        expect(manager.cancelOperation).not.toHaveBeenCalled();
      }
      // Cancellation did not retire the continuation: it can still dispatch.
      store.operations.get("op-1")!.state = "QUEUED";
      store.outbox.get("evt-1")!.sentAt = null;
      expect(await processSandboxOutboxBatch()).toBe(1);
    },
  );
  it.each([...CANCELLABLE_OPERATION_KINDS])(
    "Fix5: ordinary queued %s cancellation still retires its dispatch",
    async (kind) => {
      const { cancelOperation } = await import(
        "../../../../packages/api/src/sandbox/services/sandboxes"
      );
      store.operations.get("op-1")!.kind = kind;
      mockOwnedOperation();
      expect(
        await cancelOperation(
          { kind: "session" as const, ownerId: "user-1" },
          { operationId: "op-1" },
        ),
      ).toEqual({
        operationId: "op-1",
        state: "CANCELLED",
      });
      expect(store.sandboxes.get("sbx-1")!.state).toBe("READY");
      expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
      expect(await processSandboxOutboxBatch()).toBe(0);
      expect(manager.dispatchOperation).not.toHaveBeenCalled();
    },
  );

  it.each([
    [{ depth: 2 }, 2],
    [{}, undefined],
    [{ maxDepth: 2 }, undefined],
  ] as const)(
    "dispatches stored listing depth %j using the maxDepth wire field",
    async (shape, maxDepth) => {
      store.operations.get("op-1")!.kind = "LIST_DIR";
      Object.assign(store.outbox.get("evt-1")!, { eventType: "sandbox.file_list_requested" });
      Object.assign(store.outbox.get("evt-1")!.payload, { kind: "file.list", path: "/", ...shape });
      expect(await processSandboxOutboxBatch()).toBe(1);
      expect(manager.dispatchOperation).toHaveBeenCalledWith(
        "host-1",
        expect.objectContaining({ kind: "file.list", maxDepth }),
      );
    },
  );

  it("empty/default batch has no effects", async () => {
    store.outbox.clear();
    expect(await processSandboxOutboxBatch()).toBe(0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  });
  it("claims before sending, carries timeout and leaves unacknowledged intent pending", async () => {
    vi.mocked(manager.dispatchOperation).mockImplementation(async (_host, input) => {
      expect(store.operations.get("op-1")!.dispatchAttempt).toBe(input.attempt);
      expect(store.operations.get("op-1")!.state).toBe("DISPATCHED");
      return "sent";
    });
    expect(await processSandboxOutboxBatch()).toBe(1);
    expect(manager.dispatchOperation).toHaveBeenCalledWith(
      "host-1",
      expect.objectContaining({ attempt: 1, connectionEpoch: 1 }),
    );
    // Timeout normalization now belongs to the shared command wire path. Keep
    // checking the default against the exact input delivered by the processor.
    const input = vi.mocked(manager.dispatchOperation).mock.calls[0]![1];
    expect(
      buildCommandRunOperationDispatchMessage(
        commandRunDispatchBuildInputFromOutboxPayload(input, input.sandboxId, {
          sandboxOwnerId: "user-1",
          attempt: input.attempt,
          bodyHash: input.bodyHash!,
          stdinSequence: input.stdinSequence!,
        }),
      ),
    ).toMatchObject({ timeoutMs: 120_000 });
    expect(store.writes.indexOf("hosts")).toBeLessThan(store.writes.indexOf("sandboxes"));
    expect(store.writes.indexOf("sandboxes")).toBeLessThan(store.writes.indexOf("operations"));
    expect(store.writes.indexOf("operations")).toBeLessThan(store.writes.indexOf("outbox"));
    expect(store.outbox.get("evt-1")!.processedAt).toBeNull();
  });
  // WP0 precondition for retiring the daemon's pre-10.5 result paths: a
  // daemon refuses an unversioned result kind per operation, so every row
  // current acceptance writes must dispatch versioned. The encoder still
  // only forwards what the row carries.
  it.each(Object.keys(RESULT_TYPE_BY_KIND))(
    "a %s row written by acceptance dispatches versioned, a command with its process identity",
    async (kind) => {
      const dispatchKind = OPERATION_DISPATCH_KIND[kind as keyof typeof OPERATION_DISPATCH_KIND];
      Object.assign(store.operations.get("op-1")!, {
        kind,
        // The created row: nullable columns read NULL until a writer sets them.
        resultVersion: null,
        processId: null,
        ...initialResultFields(kind, true),
        ...initialProcessFields(kind),
      });
      Object.assign(store.outbox.get("evt-1")!.payload, {
        kind: dispatchKind,
        resultVersion: 1,
        ...(kind === "SIGNAL_PROCESS"
          ? {
              targetOperationId: "op-target",
              signal: "SIGTERM",
              process: {
                sandboxId: "sbx-1",
                generation: 1,
                attempt: 1,
                processId: "00000000-0000-4000-8000-000000000000",
                pid: 42,
              },
            }
          : {}),
      });
      // A content kind is versioned by the result hold acceptance reserves.
      if (store.operations.get("op-1")!.resultVersion === null)
        await db.$transaction((tx) =>
          reserveOperationResult(tx, { ownerId: "user-1", operationId: "op-1" }),
        );
      expect(await processSandboxOutboxBatch()).toBe(1);
      const input = vi.mocked(manager.dispatchOperation).mock.calls[0]![1];
      expect(input).toMatchObject({ kind: dispatchKind, resultVersion: 1 });
      if (kind === "RUN_COMMAND")
        expect(input.processId).toBe(store.operations.get("op-1")!.processId);
      else expect(input.processId).toBeUndefined();
    },
  );
  it("waits for socket publication after hello commit before claiming the new epoch", async () => {
    store.hosts.get("host-1")!.connectionEpoch = 2;
    store.hosts.get("host-1")!.journalKeyAcknowledgedEpoch = 2;
    let socketEpoch = 1;
    vi.mocked(manager.isHostConnected).mockImplementation(
      (_host, expectedEpoch) => expectedEpoch == null || expectedEpoch === socketEpoch,
    );
    await processSandboxOutboxBatch();
    expect(store.operations.get("op-1")!.dispatchAttempt).toBe(0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    socketEpoch = 2;
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).toHaveBeenCalledWith(
      "host-1",
      expect.objectContaining({ connectionEpoch: 2, attempt: 1 }),
    );
  });

  it("N4: reconnect retries only unacknowledged DISPATCHED with a new attempt", async () => {
    vi.mocked(manager.dispatchOperation).mockResolvedValue("sent_then_lost_authority");
    await processSandboxOutboxBatch();
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    store.hosts.get("host-1")!.connectionEpoch = 2;
    store.hosts.get("host-1")!.journalKeyAcknowledgedEpoch = 2;
    vi.mocked(manager.dispatchOperation).mockResolvedValue("sent");
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).toHaveBeenLastCalledWith(
      "host-1",
      expect.objectContaining({ attempt: 2, connectionEpoch: 2 }),
    );
    expect(await result()).toEqual({ written: false });
    expect(store.operations.get("op-1")!.state).toBe("DISPATCHED");
  });
  it.each(["ACCEPTED", "RUNNING"])("never redispatches %s on reconnect", async (state) => {
    running("command.run");
    store.operations.get("op-1")!.state = state;
    store.hosts.get("host-1")!.connectionEpoch = 2;
    store.hosts.get("host-1")!.journalKeyAcknowledgedEpoch = 2;
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  });
  it("overlapping scans produce one attempt and one send", async () => {
    const entered = gate(),
      resume = gate();
    store.barriers.beforeOperationWrite = async () => {
      store.barriers.beforeOperationWrite = undefined;
      entered.resolve();
      await resume.promise;
    };
    const first = processSandboxOutboxBatch();
    await entered.promise;
    const second = processSandboxOutboxBatch();
    resume.resolve();
    await Promise.all([first, second]);
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    expect(store.operations.get("op-1")!.dispatchAttempt).toBe(1);
  });
  it.each(["process.stdin", "operation.cancel"])(
    "Q1: overlapping %s scanners own exactly one send",
    async (kind) => {
      running(kind);
      const entered = gate(),
        resume = gate();
      store.barriers.beforeOperationWrite = async () => {
        store.barriers.beforeOperationWrite = undefined;
        entered.resolve();
        await resume.promise;
      };
      const first = processSandboxOutboxBatch();
      await entered.promise;
      const waiting = gate();
      store.barriers.beforeHostLock = async () => {
        store.barriers.beforeHostLock = undefined;
        waiting.resolve();
      };
      const second = processSandboxOutboxBatch();
      await waiting.promise;
      resume.resolve();
      await Promise.all([first, second]);
      expect(
        kind === "process.stdin" ? manager.sendStdin : manager.cancelOperation,
      ).toHaveBeenCalledTimes(1);
      if (kind === "operation.cancel") expect(store.outbox.get("evt-1")!.processedAt).toBeNull();
      else expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
    },
  );
  it.each(["process.stdin", "operation.cancel"])(
    "Q1-expiry: live expired %s claimant sends at least once but loses bookkeeping",
    async (kind) => {
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        running(kind);
        const entered = gate(),
          resume = gate();
        store.barriers.afterCommit = async () => {
          store.barriers.afterCommit = undefined;
          entered.resolve();
          await resume.promise;
        };
        const first = processSandboxOutboxBatch();
        await entered.promise;
        expect(store.outbox.get("evt-1")!.sentConnectionEpoch).toBe(1);
        vi.setSystemTime(Date.now() + 31_001);
        await processSandboxOutboxBatch();
        const writesAfterNewOwner = store.writes.length;
        resume.resolve();
        await first;
        // Both controls reclaim the same identity after claim expiry.
        expect(store.writes.slice(writesAfterNewOwner)).toEqual(["outbox"]);
        if (kind === "process.stdin") expect(manager.sendStdin).toHaveBeenCalledTimes(2);
        else expect(manager.cancelOperation).toHaveBeenCalledTimes(2);
        if (kind === "process.stdin")
          expect(vi.mocked(manager.sendStdin).mock.calls.map((call) => call[7])).toEqual([0, 0]);
        expect(store.operations.get("op-1")!.nextStdinSequence).toBe(1);
      } finally {
        vi.useRealTimers();
      }
    },
  );
  it("queued cancel retires unsent dispatch in the same fenced transaction before a competing scan", async () => {
    const { cancelOperation } = await import(
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
    const entered = gate(),
      resume = gate(),
      waiting = gate();
    store.barriers.beforeOperationWrite = async () => {
      store.barriers.beforeOperationWrite = undefined;
      entered.resolve();
      await resume.promise;
    };
    const cancellation = cancelOperation(
      { kind: "session" as const, ownerId: "user-1" },
      { operationId: "op-1" },
    );
    await entered.promise;
    expect(store.operations.get("op-1")!.state).toBe("QUEUED");
    expect(store.outbox.get("evt-1")!.processedAt).toBeNull();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      waiting.resolve();
    };
    const scan = processSandboxOutboxBatch();
    await waiting.promise;
    resume.resolve();
    expect(await cancellation).toEqual({ operationId: "op-1", state: "CANCELLED" });
    await scan;
    expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(manager.cancelOperation).not.toHaveBeenCalled();
    // Acceptance now takes H before S, shared with the scanner.
    expect(store.writes[0]).toBe("hosts");
    expect(store.writes.indexOf("operations")).toBeLessThan(store.writes.indexOf("outbox"));
  });
  it("a full page of waiting controls remains pending and does not starve a later dispatch", async () => {
    running("process.stdin");
    store.operations.get("op-1")!.state = "DISPATCHED";
    const template = store.outbox.get("evt-1")!;
    store.outbox.clear();
    for (let i = 0; i < 32; i++) {
      const id = `a-${String(i).padStart(2, "0")}`;
      store.outbox.set(id, { ...template, id, payload: { ...template.payload, stdinSequence: i } });
    }
    store.operations.set("later", {
      ...store.operations.get("op-1")!,
      id: "later",
      state: "QUEUED",
      acceptedAttempt: null,
      processId: "proc-later",
      processPid: null,
      processBootId: null,
      processStartTicks: null,
      processStartedAt: null,
      dispatchAttempt: 0,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
    });
    store.outbox.set("z-later", {
      ...template,
      id: "z-later",
      operationId: "later",
      payload: {
        ...template.payload,
        operationId: "later",
        kind: "command.run",
        dispatchAttempt: 0,
      },
    });
    expect(await processSandboxOutboxBatch()).toBe(1);
    expect(manager.sendStdin).not.toHaveBeenCalled();
    expect(manager.dispatchOperation).toHaveBeenCalledWith(
      "host-1",
      expect.objectContaining({ operationId: "later" }),
    );
    for (const event of [...store.outbox.values()].slice(0, 32)) {
      expect(event.processedAt).toBeNull();
      expect(event.claimToken).toBeNull();
    }
  });
  it.each([undefined, false])(
    "empty stdin without EOF (%s) cannot reserve a sequence even through direct service entry",
    async (eof) => {
      const { writeStdin } = await import(
        "../../../../packages/api/src/sandbox/services/sandboxes"
      );
      await expect(
        writeStdin(
          { kind: "session" as const, ownerId: "user-1" },
          { operationId: "op-1", contentBase64: "", eof },
        ),
      ).rejects.toMatchObject({ code: "BAD_REQUEST" });
      expect(store.operations.get("op-1")!.nextStdinSequence).toBe(0);
      expect(store.writes).toEqual([]);
    },
  );
  it("Q11: acceptance allocates ordered sequences even when IDs reverse dispatch including EOF", async () => {
    const { writeStdin } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
    running("process.stdin");
    store.outbox.clear();
    store.operations.get("op-1")!.nextStdinSequence = 0;
    db.sandboxOperation.findFirst.mockImplementation((args) =>
      Object.assign(
        prismaPromise(
          Promise.resolve(
            [...store.operations.values()].find((row) =>
              matches(
                { ...row, Sandbox: store.sandboxes.get(row.sandboxId) },
                args?.where as Record<string, unknown>,
              ),
            ) as never,
          ),
        ),
        {
          User: vi.fn(),
          Sandbox: vi.fn(),
          TypedResult: vi.fn(),
          CommandOutput: vi.fn(),
          Placement: vi.fn(),
          Capture: vi.fn(),
          CapacityWait: vi.fn(),
          CredentialSpec: vi.fn(),
          RestoreWait: vi.fn(),
        },
      ),
    );
    const owner = { kind: "session" as const, ownerId: "user-1" };
    const entered = gate(),
      resume = gate();
    store.barriers.beforeOperationWrite = async () => {
      store.barriers.beforeOperationWrite = undefined;
      entered.resolve();
      await resume.promise;
    };
    const first = writeStdin(owner, { operationId: "op-1", contentBase64: "QQ==", eof: false });
    await entered.promise;
    const waiting = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      waiting.resolve();
    };
    const second = writeStdin(owner, { operationId: "op-1", contentBase64: "Qg==", eof: true });
    await waiting.promise;
    resume.resolve();
    await Promise.all([first, second]);
    const [a, b] = [...store.outbox.values()];
    expect([a!.payload.stdinSequence, b!.payload.stdinSequence]).toEqual([0, 1]);
    store.outbox.clear();
    store.outbox.set("z-earlier", { ...a!, id: "z-earlier" });
    store.outbox.set("a-later", { ...b!, id: "a-later" });
    await processSandboxOutboxBatch();
    expect(
      vi.mocked(manager.sendStdin).mock.calls.map((call) => [call[4][0], call[5], call[7]]),
    ).toEqual([
      [66, true, 1],
      [65, false, 0],
    ]);
    expect(store.operations.get("op-1")!.nextStdinSequence).toBe(2);
    // Host production-function regression consumes exactly this reverse wire order.
  });
  it("stdin acceptance reserves one sequence per bounded write, including empty EOF, and rolls back terminal races", async () => {
    const { writeStdin } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
    running("process.stdin");
    store.outbox.clear();
    store.operations.get("op-1")!.nextStdinSequence = 0;
    db.sandboxOperation.findFirst.mockImplementation((args) =>
      Object.assign(
        prismaPromise(
          Promise.resolve(
            [...store.operations.values()].find((row) =>
              matches(
                { ...row, Sandbox: store.sandboxes.get(row.sandboxId) },
                args?.where as Record<string, unknown>,
              ),
            ) as never,
          ),
        ),
        {
          User: vi.fn(),
          Sandbox: vi.fn(),
          TypedResult: vi.fn(),
          CommandOutput: vi.fn(),
          Placement: vi.fn(),
          Capture: vi.fn(),
          CapacityWait: vi.fn(),
          CredentialSpec: vi.fn(),
          RestoreWait: vi.fn(),
        },
      ),
    );
    const owner = { kind: "session" as const, ownerId: "user-1" };
    await expect(
      writeStdin(owner, {
        operationId: "op-1",
        contentBase64: Buffer.alloc(32 * 1024 + 1).toString("base64"),
      }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await writeStdin(owner, {
      operationId: "op-1",
      contentBase64: Buffer.alloc(32 * 1024).toString("base64"),
    });
    await writeStdin(owner, { operationId: "op-1", contentBase64: "", eof: true });
    expect([...store.outbox.values()].map((row) => row.payload.stdinSequence)).toEqual([0, 1]);
    expect(store.operations.get("op-1")!.nextStdinSequence).toBe(2);
    const entered = gate(),
      resume = gate();
    store.barriers.beforeHostLock = async () => {
      store.barriers.beforeHostLock = undefined;
      entered.resolve();
      await resume.promise;
    };
    const pending = writeStdin(owner, { operationId: "op-1", contentBase64: "QQ==" });
    await entered.promise;
    await result();
    resume.resolve();
    await expect(pending).rejects.toMatchObject({ code: "CONFLICT" });
    expect(store.operations.get("op-1")!.nextStdinSequence).toBe(2);
    expect(store.outbox.size).toBe(2);
  });
  it("retries start the new attempt at the persisted counter without allocating in dispatch", async () => {
    Object.assign(store.operations.get("op-1")!, {
      state: "DISPATCHED",
      dispatchedHostId: "host-1",
      dispatchAttempt: 1,
      dispatchedConnectionEpoch: 1,
      nextStdinSequence: 7,
    });
    store.hosts.get("host-1")!.connectionEpoch = 2;
    store.hosts.get("host-1")!.journalKeyAcknowledgedEpoch = 2;
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).toHaveBeenCalledWith(
      "host-1",
      expect.objectContaining({ attempt: 2, stdinSequence: 7 }),
    );
    expect(store.operations.get("op-1")!.nextStdinSequence).toBe(7);
  });
  it("Q2: retires a full stale page and sends the later valid row in one scan", async () => {
    const operation = structuredClone(store.operations.get("op-1")!);
    const event = structuredClone(store.outbox.get("evt-1")!);
    store.operations.clear();
    store.outbox.clear();
    store.sandboxes.get("sbx-1")!.generation = 2;
    for (let i = 0; i < 33; i++) {
      const id = `op-${String(i).padStart(3, "0")}`;
      const eventId = `evt-${String(i).padStart(3, "0")}`;
      const generation = i === 32 ? 2 : 1;
      store.operations.set(id, { ...operation, id, generation });
      store.outbox.set(eventId, {
        ...event,
        id: eventId,
        payload: { ...event.payload, operationId: id, generation },
      });
    }
    expect(await processSandboxOutboxBatch()).toBe(1);
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    expect([...store.outbox.values()].filter((e) => e.processedAt !== null)).toHaveLength(32);
    expect([...store.operations.values()].filter((o) => o.errorCode === "superseded")).toHaveLength(
      32,
    );
  });
  it("sent work leaves the send scan; a held or expired claim is evaluated by predicates", async () => {
    await processSandboxOutboxBatch();
    expect(store.outbox.get("evt-1")!.sentAt).not.toBeNull();
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    running("process.stdin");
    Object.assign(store.outbox.get("evt-1")!, {
      sentAt: null,
      claimToken: "crashed",
      claimedAt: new Date(0),
    });
    await processSandboxOutboxBatch();
    expect(manager.sendStdin).toHaveBeenCalledTimes(1);
  });
  it("failed stdin send releases its claim and retries the same persisted sequence", async () => {
    running("process.stdin");
    vi.mocked(manager.sendStdin).mockResolvedValueOnce(false);
    await processSandboxOutboxBatch();
    expect(store.outbox.get("evt-1")!.claimToken).toBeNull();
    expect(store.outbox.get("evt-1")!.payload.stdinSequence).toBe(0);
    await processSandboxOutboxBatch();
    expect(vi.mocked(manager.sendStdin).mock.calls.map((call) => call[7])).toEqual([0, 0]);
    expect(store.operations.get("op-1")!.nextStdinSequence).toBe(1);
  });
  it("terminal, deleted and offline superseded intents retire without sending", async () => {
    running("process.stdin");
    vi.mocked(manager.isHostConnected).mockReturnValue(false);
    store.sandboxes.get("sbx-1")!.state = "DELETED";
    await processSandboxOutboxBatch();
    expect(store.operations.get("op-1")!.errorCode).toBe("superseded");
    expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
    expect(manager.sendStdin).not.toHaveBeenCalled();
  });
  it("JS-5: the fast pass skips an offline host's event before any transaction; the full pass settles it", async () => {
    running("process.stdin");
    vi.mocked(manager.isHostConnected).mockReturnValue(false);
    store.sandboxes.get("sbx-1")!.state = "DELETED";
    db.$transaction.mockClear();
    await processSandboxOutboxBatch(undefined, undefined, { skipOfflineHosts: true });
    expect(db.$transaction).not.toHaveBeenCalled();
    expect(store.outbox.get("evt-1")!.processedAt).toBeNull();
    // The periodic full pass: drain #1 is full, #2 two seconds later is fast,
    // #3 thirty seconds after #1 is full again.
    let at = 1_000_000;
    const drain = createSandboxOutboxDrain(() => at);
    store.sandboxes.get("sbx-1")!.state = "READY";
    await drain(() => false);
    store.sandboxes.get("sbx-1")!.state = "DELETED";
    at += 2_000;
    await drain(() => false);
    expect(store.outbox.get("evt-1")!.processedAt).toBeNull();
    at += SANDBOX_OUTBOX_FULL_PASS_MS - 2_000;
    await drain(() => false);
    expect(store.operations.get("op-1")!.errorCode).toBe("superseded");
    expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
    expect(manager.sendStdin).not.toHaveBeenCalled();
  });
  it("JS-5: a connected host's event dispatches in the fast pass unchanged", async () => {
    vi.mocked(manager.isHostConnected).mockReturnValue(true);
    expect(await processSandboxOutboxBatch(undefined, undefined, { skipOfflineHosts: true })).toBe(
      1,
    );
    expect(manager.dispatchOperation).toHaveBeenCalledWith(
      "host-1",
      expect.objectContaining({ attempt: 1, connectionEpoch: 1 }),
    );
  });
  describe("WP7 quiesce: command.run is held before the claim (D9)", () => {
    const unclaimedQueued = () => {
      expect(store.outbox.get("evt-1")!).toMatchObject({
        claimToken: null,
        sentAt: null,
        processedAt: null,
      });
      expect(store.operations.get("op-1")!).toMatchObject({
        state: "QUEUED",
        dispatchAttempt: 0,
        dispatchedHostId: null,
        dispatchedConnectionEpoch: null,
      });
      expect(manager.dispatchOperation).not.toHaveBeenCalled();
    };
    it("the fast pass skips it before any transaction", async () => {
      expect(store.outbox.get("evt-1")!.payload.kind).toBe("command.run");
      vi.mocked(manager.isHostQuiescing).mockReturnValue(true);
      db.$transaction.mockClear();
      expect(
        await processSandboxOutboxBatch(undefined, undefined, { skipOfflineHosts: true }),
      ).toBe(0);
      expect(db.$transaction).not.toHaveBeenCalled();
      expect(manager.isHostQuiescing).toHaveBeenCalledWith("host-1");
      unclaimedQueued();
    });
    it("the full pass's in-transaction fence holds it without spending an attempt; it dispatches after a hello without quiescing", async () => {
      vi.mocked(manager.isHostQuiescing).mockReturnValue(true);
      for (let pass = 0; pass < 3; pass++) expect(await processSandboxOutboxBatch()).toBe(0);
      unclaimedQueued();
      // The next connection's hello clears it; reconcile.complete wakes the scan.
      vi.mocked(manager.isHostQuiescing).mockReturnValue(false);
      expect(
        await processSandboxOutboxBatch(undefined, undefined, { skipOfflineHosts: true }),
      ).toBe(1);
      expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
      expect(manager.dispatchOperation).toHaveBeenCalledWith(
        "host-1",
        expect.objectContaining({ kind: "command.run", attempt: 1, connectionEpoch: 1 }),
      );
      expect(store.operations.get("op-1")!).toMatchObject({
        state: "DISPATCHED",
        dispatchAttempt: 1,
      });
    });
    it.each(["process.stdin", "operation.cancel"])(
      "controls for running work (%s) still flow to a quiescing host",
      async (kind) => {
        running(kind);
        vi.mocked(manager.isHostQuiescing).mockReturnValue(true);
        await processSandboxOutboxBatch(undefined, undefined, { skipOfflineHosts: true });
        if (kind === "process.stdin") expect(manager.sendStdin).toHaveBeenCalledTimes(1);
        else expect(manager.cancelOperation).toHaveBeenCalledTimes(1);
      },
    );
    it("other kinds still dispatch to a quiescing host", async () => {
      store.operations.get("op-1")!.kind = "STAT_PATH";
      store.outbox.get("evt-1")!.payload.kind = "file.stat";
      vi.mocked(manager.isHostQuiescing).mockReturnValue(true);
      await processSandboxOutboxBatch();
      expect(manager.dispatchOperation).toHaveBeenCalledWith(
        "host-1",
        expect.objectContaining({ kind: "file.stat" }),
      );
    });
  });
  it("deleted operation and sandbox retire the orphaned event", async () => {
    store.operations.clear();
    store.sandboxes.clear();
    await processSandboxOutboxBatch();
    expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  });
  for (const kind of [
    "command.run",
    "operation.cancel",
    "process.stdin",
    "sandbox.explode",
    "snapshot.create",
  ]) {
    it(`${kind}: stale generation, terminal, mismatched owner/host/sandbox leave every row intact`, async () => {
      for (const mismatch of ["owner", "host", "sandbox", "aggregate"]) {
        running(kind);
        const event = store.outbox.get("evt-1")!;
        // Reset each independent mismatch case.
        event.userId = "user-1";
        event.aggregateId = "sbx-1";
        event.payload.sandboxId = "sbx-1";
        event.payload.sandboxHostId = "host-1";
        store.sandboxes.get("sbx-1")!.generation = 1;
        if (mismatch === "owner") event.userId = "foreign";
        if (mismatch === "host") event.payload.sandboxHostId = "foreign";
        if (mismatch === "sandbox") event.payload.sandboxId = "foreign";
        if (mismatch === "aggregate") event.aggregateId = "foreign";
        const before = structuredClone([
          store.operations,
          store.sandboxes,
          store.outbox,
          store.hosts,
        ]);
        await processSandboxOutboxBatch();
        expect([store.operations, store.sandboxes, store.outbox, store.hosts]).toEqual(before);
      }
      expect(manager.dispatchOperation).not.toHaveBeenCalled();
      expect(manager.cancelOperation).not.toHaveBeenCalled();
      expect(manager.sendStdin).not.toHaveBeenCalled();
    });
  }
  it.each(["process.stdin", "sandbox.explode"])(
    "%s never substitutes the current attempt for an event's recorded attempt",
    async (kind) => {
      running(kind);
      store.operations.get("op-1")!.dispatchAttempt = 2;
      await processSandboxOutboxBatch();
      expect(store.operations.get("op-1")!.state).toBe("RUNNING");
      expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
      expect(manager.cancelOperation).not.toHaveBeenCalled();
      expect(manager.sendStdin).not.toHaveBeenCalled();
      store.outbox.get("evt-1")!.payload.dispatchAttempt = 0;
      await processSandboxOutboxBatch();
      expect(store.operations.get("op-1")!.state).toBe("RUNNING");
    },
  );
  it("cancel never rebinds to a newer dispatch attempt", async () => {
    running("operation.cancel");
    store.operations.get("op-1")!.dispatchAttempt = 2;
    await processSandboxOutboxBatch();
    expect(manager.cancelOperation).not.toHaveBeenCalled();
    expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
    expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
  });
  it("queued cancel wins transactionally without sending", async () => {
    store.outbox.get("evt-1")!.payload.kind = "operation.cancel";
    await processSandboxOutboxBatch();
    expect(store.operations.get("op-1")!.state).toBe("CANCELLED");
    expect(manager.cancelOperation).not.toHaveBeenCalled();
  });
  it.each(["operation.cancel", "process.stdin", "sandbox.explode"])(
    "completion wins before %s admission",
    async (kind) => {
      running(kind);
      const entered = gate(),
        resume = gate();
      store.barriers.beforeHostLock = async () => {
        store.barriers.beforeHostLock = undefined;
        entered.resolve();
        await resume.promise;
      };
      const pending = processSandboxOutboxBatch();
      await entered.promise;
      expect(await result()).toEqual({ written: true });
      resume.resolve();
      await pending;
      expect(store.operations.get("op-1")!.state).toBe("SUCCEEDED");
      expect(manager.cancelOperation).not.toHaveBeenCalled();
      expect(manager.sendStdin).not.toHaveBeenCalled();
    },
  );
  it.each(["snapshot.create", "sandbox.explode"])(
    "fails closed on %s with a valid bound event",
    async (kind) => {
      store.outbox.get("evt-1")!.payload.kind = kind;
      await processSandboxOutboxBatch();
      expect(store.operations.get("op-1")!.state).toBe("FAILED");
      expect(store.operations.get("op-1")!.dispatchedHostId).toBeNull();
      expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
    },
  );
  it("C15-S4: deterministic encode failure terminalizes poison and delivers later events", async () => {
    Object.assign(store.operations.get("op-1")!, {
      state: "QUEUED",
      dispatchAttempt: 0,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
      requestBodyHash: "a".repeat(64),
    });
    store.operations.set("op-2", {
      id: "op-2",
      userId: "user-1",
      sandboxId: "sbx-1",
      kind: "RUN_COMMAND",
      state: "QUEUED",
      requestBodyHash: "b".repeat(64),
      generation: 1,
      dispatchAttempt: 0,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
      nextStdinSequence: 0,
      acceptedAttempt: null,
    });
    Object.assign(store.outbox.get("evt-1")!.payload, {
      kind: "command.run",
      dispatchAttempt: 0,
      script: "true",
      operationId: "op-1",
      idempotencyKey: "poison",
    });
    store.outbox.set("evt-2", {
      id: "evt-2",
      userId: "user-1",
      aggregateType: "sandbox",
      aggregateId: "sbx-1",
      processedAt: null,
      sentAt: null,
      claimToken: null,
      claimedAt: null,
      payload: {
        sandboxOwnerId: "user-1",
        operationId: "op-2",
        sandboxId: "sbx-1",
        sandboxHostId: "host-1",
        generation: 1,
        dispatchAttempt: 0,
        kind: "command.run",
        script: "echo ok",
        idempotencyKey: "valid",
      },
    });
    vi.mocked(manager.dispatchOperation)
      .mockImplementationOnce(async () => {
        encodeServerControlMessage(
          {
            type: "protocol.error",
            failure: "protocol_error",
            message: "x".repeat(70_000),
          },
          "1.0",
        );
        return "refused_before_frame";
      })
      .mockResolvedValue("sent");
    await processSandboxOutboxBatch();
    expect(store.operations.get("op-1")!.state).toBe("FAILED");
    expect(store.operations.get("op-1")!.errorCode).toBe("request_too_large");
    expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
    expect(store.outbox.get("evt-2")!.sentAt).not.toBeNull();
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(2);
    vi.mocked(manager.dispatchOperation).mockClear();
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  });
  it("C7: corrupt poison backs off without starving later events or reclaim", async () => {
    Object.assign(store.operations.get("op-1")!, { kind: "CREATE_SANDBOX" });
    Object.assign(store.sandboxes.get("sbx-1")!, {
      state: "PROVISIONING",
      liveResourcesHeld: true,
    });
    Object.assign(store.hosts.get("host-1")!, {
      liveCount: 1,
      memoryReservedMiB: 512,
      vcpuReserved: 0,
      rootCount: 0,
      daemonVcpuBudget: 64,
      StoragePools: [],
      egressEnforcement: false,
    });
    Object.assign(store.outbox.get("evt-1")!.payload, {
      kind: "sandbox.create",
      egressPolicy: { domains: ["example.com"], cidrs: [] },
      egressPolicyHash: "b".repeat(64),
    });
    // Fill a whole page with the same poison intent to exercise cursor progress.
    const poison = structuredClone(store.outbox.get("evt-1")!);
    store.outbox.clear();
    for (let i = 0; i < 32; i++) {
      const id = `evt-${String(i).padStart(3, "0")}`;
      store.outbox.set(id, { ...structuredClone(poison), id });
    }
    store.hosts.set("host-2", {
      ...structuredClone(store.hosts.get("host-1")!),
      id: "host-2",
      userId: "user-2",
      egressEnforcement: true,
    });
    store.sandboxes.set("sbx-2", {
      ...structuredClone(store.sandboxes.get("sbx-1")!),
      id: "sbx-2",
      userId: "user-2",
      sandboxHostId: "host-2",
      state: "READY",
      liveResourcesHeld: false,
    });
    store.operations.set("op-2", {
      ...structuredClone(store.operations.get("op-1")!),
      id: "op-2",
      userId: "user-2",
      sandboxId: "sbx-2",
      kind: "RUN_COMMAND",
    });
    Object.assign(store.sandboxes.get("sbx-2")!, {
      hostOwnerId: "user-2",
      currentPlacementId: "placement:sbx-2",
    });
    store.placements.set("placement:sbx-2", {
      ...store.placements.get("placement:sbx-1")!,
      id: "placement:sbx-2",
      sandboxId: "sbx-2",
      userId: "user-2",
      hostOwnerId: "user-2",
      originHostId: "host-2",
    });
    store.outbox.set("evt-999", {
      ...structuredClone(poison),
      id: "evt-999",
      userId: "user-2",
      aggregateId: "sbx-2",
      payload: {
        ...poison.payload,
        operationId: "op-2",
        sandboxId: "sbx-2",
        sandboxHostId: "host-2",
        kind: "command.run",
        script: "true",
      },
    });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const wake = vi.fn();
    bindSandboxDispatchWake(wake);
    try {
      for (let scan = 0; scan < 3; scan++) {
        expect(await processSandboxOutboxBatch()).toBe(scan === 0 ? 1 : 0);
        expect(log).toHaveBeenCalledTimes(32);
        expect(db.$queryRaw).toHaveBeenCalledTimes(scan + 1);
      }
      expect(store.outbox.get("evt-000")).toMatchObject({
        processedAt: null,
        sentAt: null,
        claimToken: "integrity-backoff:sandbox_reservation_underflow",
        claimedAt: expect.any(Date),
      });
      expect(store.outbox.get("evt-999")!.sentAt).not.toBeNull();
      expect(store.operations.get("op-1")).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
      expect(store.sandboxes.get("sbx-1")).toMatchObject({
        liveResourcesHeld: true,
        state: "PROVISIONING",
      });
      expect(store.hosts.get("host-1")).toMatchObject({ liveCount: 1, memoryReservedMiB: 512 });
      expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
      expect(wake).not.toHaveBeenCalled();
      expect(log).toHaveBeenCalledWith("[sandbox] integrity failure:", {
        code: "sandbox_reservation_underflow",
        errorClass: "Error",
      });
    } finally {
      log.mockRestore();
      bindSandboxDispatchWake(null);
    }
  });
  it("current stdin is sent and finalization is fenced", async () => {
    running("process.stdin");
    Object.assign(store.outbox.get("evt-1")!.payload, { stdinBase64: "QQ==", eof: true });
    await processSandboxOutboxBatch();
    expect(manager.sendStdin).toHaveBeenCalledWith(
      "host-1",
      "op-1",
      1,
      1,
      new Uint8Array([65]),
      true,
      1,
      0,
      { kind: "session" },
    );
    expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
  });
  it.each([false, true])(
    "expiry retires old sent/acknowledged=%s work outside the send scan",
    async (acknowledged) => {
      running("command.run");
      const now = new Date();
      Object.assign(store.outbox.get("evt-1")!, {
        sentAt: now,
        sentConnectionEpoch: 1,
        processedAt: acknowledged ? now : null,
      });
      store.sandboxes.get("sbx-1")!.leaseExpiresAt = new Date(now.getTime() - 1);
      db.$queryRaw.mockResolvedValue([...store.sandboxes.values()] as never);
      await processSandboxOutboxBatch(() => now);
      expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
      expect(store.operations.get("op-1")!.errorCode).toBe("superseded");
      expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
      expect(
        [...store.operations.values()].some(
          (op) => op.kind === "STOP_SANDBOX" && op.generation === 2,
        ),
      ).toBe(true);
      expect(manager.dispatchOperation).not.toHaveBeenCalled();
    },
  );
  it("expiry owns host then sandbox before inserting operation and outbox", async () => {
    store.outbox.clear();
    store.operations.clear();
    const now = new Date();
    store.sandboxes.get("sbx-1")!.leaseExpiresAt = new Date(now.getTime() - 1);
    db.$queryRaw.mockResolvedValue([...store.sandboxes.values()] as never);
    expect(await processSandboxOutboxBatch(() => now)).toBe(1);
    expect(store.writes).toEqual([
      "hosts",
      "sandboxes",
      "sandboxes",
      "operations",
      "operations",
      "outbox",
      "outbox",
    ]);
    expect(store.sandboxes.get("sbx-1")!.generation).toBe(2);
    expect([...store.operations.values()][0]!.generation).toBe(2);
    const { cancelOperation } = await import(
      "../../../../packages/api/src/sandbox/services/sandboxes"
    );
    const stop = [...store.operations.values()][0]!;
    db.sandboxOperation.findFirst.mockResolvedValue(stop as never);
    const before = structuredClone([store.operations, store.sandboxes, store.outbox]);
    store.writes.length = 0;
    await expect(
      cancelOperation({ kind: "session" as const, ownerId: "user-1" }, { operationId: stop.id }),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    expect(store.writes).toEqual([]);
    expect([store.operations, store.sandboxes, store.outbox]).toEqual(before);
  });
  it("C10: cancel send leaves CANCEL_REQUESTED until host acknowledgement", async () => {
    running("operation.cancel");
    await processSandboxOutboxBatch();
    expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
    expect(manager.cancelOperation).toHaveBeenCalled();
  });
  it("C10: natural completion wins over a pending cancel request", async () => {
    running("operation.cancel");
    store.operations.get("op-1")!.state = "CANCEL_REQUESTED";
    expect(await result()).toEqual({ written: true });
    expect(store.operations.get("op-1")!.state).toBe("SUCCEEDED");
  });
  it("C10: cancel-before-start retires queued work without host dispatch", async () => {
    store.operations.get("op-1")!.state = "QUEUED";
    const { cancelOperation } = await import(
      "../../../../packages/api/src/sandbox/services/sandboxes"
    );
    mockOwnedOperation();
    expect(
      await cancelOperation(
        { kind: "session" as const, ownerId: "user-1" },
        { operationId: "op-1" },
      ),
    ).toEqual({
      operationId: "op-1",
      state: "CANCELLED",
    });
    expect(manager.cancelOperation).not.toHaveBeenCalled();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  });
  it("C10: stop expiry supersedes in-flight cancel request", async () => {
    running("command.run");
    store.operations.get("op-1")!.state = "CANCEL_REQUESTED";
    const now = new Date();
    store.sandboxes.get("sbx-1")!.leaseExpiresAt = new Date(now.getTime() - 1);
    db.$queryRaw.mockResolvedValue([...store.sandboxes.values()] as never);
    await processSandboxOutboxBatch(() => now);
    expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
    expect(store.operations.get("op-1")!.errorCode).toBe("superseded");
  });
  it("C10: duplicate cancel is idempotent at CANCEL_REQUESTED", async () => {
    const { cancelOperation } = await import(
      "../../../../packages/api/src/sandbox/services/sandboxes"
    );
    running("command.run");
    store.operations.get("op-1")!.state = "CANCEL_REQUESTED";
    mockOwnedOperation();
    expect(
      await cancelOperation(
        { kind: "session" as const, ownerId: "user-1" },
        { operationId: "op-1" },
      ),
    ).toEqual({
      operationId: "op-1",
      state: "CANCEL_REQUESTED",
    });
    expect(store.outbox.size).toBe(1);
  });
  it.each(["ACCEPTED", "RUNNING", "DISPATCHED"])(
    "C10-1 API %s cancel delivers once accepted and retries until result",
    async (state) => {
      const { cancelOperation } = await import(
        "../../../../packages/api/src/sandbox/services/sandboxes"
      );
      running("command.run");
      store.operations.get("op-1")!.state = state;
      store.operations.get("op-1")!.acceptedAttempt = state === "DISPATCHED" ? null : 1;
      store.outbox.clear();
      mockOwnedOperation();
      const receipt = await cancelOperation(
        { kind: "session" as const, ownerId: "user-1" },
        { operationId: "op-1" },
      );
      expect(
        await cancelOperation(
          { kind: "session" as const, ownerId: "user-1" },
          { operationId: "op-1" },
        ),
      ).toEqual(receipt);
      expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
      expect(store.outbox.size).toBe(1);
      if (state === "DISPATCHED") {
        await processSandboxOutboxBatch();
        expect(manager.cancelOperation).not.toHaveBeenCalled();
        expect(
          await applyOperationProgress({
            sender,
            operationId: "op-1",
            sandboxId: "sbx-1",
            generation: 1,
            attempt: 1,
            state: "accepted",
          }),
        ).toEqual({ written: true });
        expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
      }
      vi.mocked(manager.cancelOperation).mockResolvedValueOnce(false).mockResolvedValue(true);
      await processSandboxOutboxBatch();
      await processSandboxOutboxBatch();
      expect(manager.cancelOperation).toHaveBeenCalledTimes(2);
      expect([...store.outbox.values()][0]!.processedAt).toBeNull();
      await processSandboxOutboxBatch(() => new Date(Date.now() + 31_001));
      expect(manager.cancelOperation).toHaveBeenCalledTimes(3);
      expect(vi.mocked(manager.cancelOperation).mock.calls.every((call) => call[3] === 1)).toBe(
        true,
      );
      await result();
      expect([...store.outbox.values()][0]!.processedAt).not.toBeNull();
      await processSandboxOutboxBatch(() => new Date(Date.now() + 62_002));
      expect(manager.cancelOperation).toHaveBeenCalledTimes(3);
    },
  );

  it.each(["succeeded", "failed", "unknown_outcome"])(
    "C10-1 supersession waits for stop evidence: %s",
    async (state) => {
      running("command.run");
      store.outbox.get("evt-1")!.processedAt = new Date();
      store.sandboxes.get("sbx-1")!.leaseExpiresAt = new Date(Date.now() - 1);
      db.$queryRaw.mockResolvedValue([...store.sandboxes.values()] as never);
      await processSandboxOutboxBatch();
      expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
      expect(manager.dispatchOperation).not.toHaveBeenCalled();
      db.$queryRaw.mockResolvedValue([]);
      await processSandboxOutboxBatch();
      const stop = [...store.operations.values()].find((o) => o.kind === "STOP_SANDBOX")!;
      expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
      expect(
        await applyOperationResult({
          sender,
          operationId: stop.id,
          result: { state: "stopped" },
          sandboxId: "sbx-1",
          generation: 2,
          attempt: 1,
          state,
        }),
      ).toEqual({ written: true });
      expect(store.operations.get("op-1")!.state).toBe(
        state === "succeeded" ? "CANCELLED" : "UNKNOWN_OUTCOME",
      );
    },
  );

  async function expireQueuedWork() {
    const now = new Date();
    vi.mocked(manager.isHostConnected).mockReturnValue(false);
    store.sandboxes.get("sbx-1")!.leaseExpiresAt = new Date(now.getTime() - 1);
    db.$queryRaw.mockResolvedValue([...store.sandboxes.values()] as never);
    expect(await processSandboxOutboxBatch(() => now)).toBe(1);
    const stop = [...store.operations.values()].find((op) => op.kind === "STOP_SANDBOX")!;
    expect(stop.state).toBe("QUEUED");
    expect(store.operations.get("op-1")!).toMatchObject({
      state: "CANCEL_REQUESTED",
      errorCode: "superseded",
      dispatchAttempt: 0,
      dispatchedHostId: null,
      dispatchedConnectionEpoch: null,
    });
    expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
    db.$queryRaw.mockResolvedValue([]);
    vi.mocked(manager.isHostConnected).mockReturnValue(true);
    return stop;
  }

  it.each(["missing", "succeeded", "failed", "unknown_outcome"])(
    "C10-CX6: expiry, failed stop send and replacement receipt=%s settle undispatched work",
    async (state) => {
      const stop = await expireQueuedWork();
      vi.mocked(manager.dispatchOperation).mockResolvedValue("sent_then_lost_authority");
      await processSandboxOutboxBatch();
      expect(store.operations.get(stop.id)!.state).toBe("DISPATCHED");
      store.hosts.get("host-1")!.connectionEpoch = 2;
      store.hosts.get("host-1")!.journalKeyAcknowledgedEpoch = 2;
      const replacement = { ...sender, connectionEpoch: 2 };
      store.writes.length = 0;
      if (state !== "missing") {
        expect(
          await applyOperationResult({
            sender: replacement,
            operationId: stop.id,
            result: { state: "stopped" },
            sandboxId: "sbx-1",
            generation: 2,
            attempt: 1,
            state,
            receipt: {
              bodyHash: String(stop.requestBodyHash),
              idempotencyKey: String(stop.idempotencyKey),
              kind: "sandbox.stop",
            },
          }),
        ).toEqual({ written: true });
      }
      expect(await finishHostReconciliation(replacement)).toBe(true);
      const expected = state === "succeeded" ? "CANCELLED" : "UNKNOWN_OUTCOME";
      expect(store.operations.get("op-1")!.state).toBe(expected);
      expect(store.operations.get("op-1")!.completedAt).toEqual(
        store.operations.get(stop.id)!.completedAt,
      );
      expect(store.writes.indexOf("hosts")).toBeLessThan(store.writes.indexOf("sandboxes"));
      expect(store.writes.indexOf("sandboxes")).toBeLessThan(store.writes.indexOf("operations"));
      expect(store.writes.lastIndexOf("operations")).toBeLessThan(store.writes.indexOf("outbox"));
      expect([...store.outbox.values()].every((event) => event.processedAt != null)).toBe(true);
      await processSandboxOutboxBatch();
      expect(await finishHostReconciliation(replacement)).toBe(true);
      expect(store.operations.get("op-1")!.state).toBe(expected);

      if (state === "missing") {
        // A later exact receipt upgrades uncertainty for the lifecycle and its
        // undispatched predecessors together, after another reconnect.
        store.hosts.get("host-1")!.connectionEpoch = 3;
        expect(
          await applyOperationResult({
            sender: { ...sender, connectionEpoch: 3 },
            operationId: stop.id,
            result: { state: "stopped" },
            sandboxId: "sbx-1",
            generation: 2,
            attempt: 1,
            state: "succeeded",
            receipt: {
              bodyHash: String(stop.requestBodyHash),
              idempotencyKey: String(stop.idempotencyKey),
              kind: "sandbox.stop",
            },
          }),
        ).toEqual({ written: true });
        expect(store.operations.get("op-1")!.state).toBe("CANCELLED");
      }
    },
  );

  it("C10-CX6: lost reconciliation authority rolls back lifecycle and predecessor settlement", async () => {
    const stop = await expireQueuedWork();
    vi.mocked(manager.dispatchOperation).mockResolvedValue("sent_then_lost_authority");
    await processSandboxOutboxBatch();
    store.hosts.get("host-1")!.connectionEpoch = 2;
    store.hosts.get("host-1")!.journalKeyAcknowledgedEpoch = 2;
    const before = structuredClone([store.operations, store.outbox]);
    expect(
      await finishHostReconciliation({
        ...sender,
        connectionEpoch: 2,
        // Inventory is current; authority is lost after the O/outbox writes.
        isCurrent: vi.fn().mockReturnValueOnce(true).mockReturnValue(false),
      }),
    ).toBe(false);
    expect([store.operations, store.outbox]).toEqual(before);
    expect(store.operations.get(stop.id)!.state).toBe("DISPATCHED");
    expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
  });

  it.each([
    "DELETED",
    "ERROR",
    "HOST_LOST",
    "host-removed",
    "sandbox.explode",
    "snapshot.create",
    "command.run",
  ])("C10-CX6: outbox lifecycle retirement/failure %s settles predecessors", async (reason) => {
    const stop = await expireQueuedWork();
    if (["DELETED", "ERROR", "HOST_LOST"].includes(reason)) {
      store.sandboxes.get("sbx-1")!.state = reason;
    } else if (reason === "host-removed") {
      store.hosts.clear();
    } else {
      const event = [...store.outbox.values()].find((e) => e.payload.operationId === stop.id)!;
      event.payload.kind = reason;
    }
    await processSandboxOutboxBatch();
    expect(["UNKNOWN_OUTCOME", "FAILED"]).toContain(store.operations.get(stop.id)!.state);
    expect(store.operations.get("op-1")!.state).toBe("UNKNOWN_OUTCOME");
    expect(store.operations.get("op-1")!.completedAt).toEqual(
      store.operations.get(stop.id)!.completedAt,
    );
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect([...store.outbox.values()].every((event) => event.processedAt != null)).toBe(true);
  });

  it.each(["succeeded", "unknown_outcome"])(
    "C10-CX6: retiring a superseding lifecycle retains its predecessors until newest result %s",
    async (state) => {
      const stop = await expireQueuedWork();
      // Same generation-advance transaction used by lifecycle enqueue/kill/expiry.
      await db.$transaction(async (tx) => {
        await tx.sandboxHost.updateMany({ where: { id: "host-1" }, data: { connectionEpoch: 1 } });
        await tx.sandbox.updateMany({ where: { id: "sbx-1" }, data: { generation: 3 } });
        await seedAcceptedOperation(tx, {
          data: {
            id: "kill",
            userId: "user-1",
            sandboxId: "sbx-1",
            generation: 3,
            kind: "KILL_SANDBOX",
            state: "DISPATCHED",
            dispatchAttempt: 1,
            dispatchedHostId: "host-1",
            dispatchedConnectionEpoch: 1,
            requestBodyHash: "b".repeat(64),
            idempotencyKey: "kill",
          },
        });
        await retireSupersededOperations(tx, "user-1", "sbx-1", 3);
      });
      expect(store.operations.get(stop.id)!.state).toBe("CANCEL_REQUESTED");
      expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
      expect(
        await applyOperationResult({
          sender,
          operationId: "kill",
          result: { state: "deleted" },
          sandboxId: "sbx-1",
          generation: 3,
          attempt: 1,
          state,
        }),
      ).toEqual({ written: true });
      const expected = state === "succeeded" ? "CANCELLED" : "UNKNOWN_OUTCOME";
      expect(store.operations.get(stop.id)!.state).toBe(expected);
      expect(store.operations.get("op-1")!.state).toBe(expected);
    },
  );
});

describe("C21 revoked authorizing key (credential_inactive)", () => {
  function authorizedBy(keyId = "key-1") {
    store.operations.get("op-1")!.authorizingKeyId = keyId;
    store.outbox.get("evt-1")!.payload.authorizingPrincipal = { kind: "sdkKey", keyId };
  }

  it("C21-9: a key revoked before claim terminalizes FAILED credential_inactive and processes the event", async () => {
    authorizedBy();
    vi.mocked(checkAcceptedDispatchAuthority).mockResolvedValue("inactive");
    await processSandboxOutboxBatch();
    expect(store.operations.get("op-1")).toMatchObject({
      state: "FAILED",
      errorCode: "credential_inactive",
      dispatchAttempt: 1,
    });
    expect(store.outbox.get("evt-1")!.processedAt).toEqual(expect.any(Date));
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    // C21-16a: the key is re-read through the claiming transaction, never pooled prisma.
    const client = vi.mocked(checkAcceptedDispatchAuthority).mock.calls[0]![1];
    expect(client).toBeDefined();
    expect(client).not.toBe(prisma);
    // Not retried: a second scan finds nothing claimable.
    vi.mocked(checkAcceptedDispatchAuthority).mockClear();
    await processSandboxOutboxBatch();
    expect(checkAcceptedDispatchAuthority).not.toHaveBeenCalled();
  });

  it("C21-9: a revoked key terminalizes even while the host is offline", async () => {
    authorizedBy();
    vi.mocked(checkAcceptedDispatchAuthority).mockResolvedValue("inactive");
    vi.mocked(manager.isHostConnected).mockReturnValue(false);
    await processSandboxOutboxBatch();
    expect(store.operations.get("op-1")).toMatchObject({
      state: "FAILED",
      errorCode: "credential_inactive",
    });
    expect(store.outbox.get("evt-1")!.processedAt).toEqual(expect.any(Date));
  });

  it("C21-16b: a send refused after claim for an inactive key is FAILED credential_inactive, not stranded DISPATCHED", async () => {
    authorizedBy();
    // Active under the claim, revoked before the socket send.
    vi.mocked(checkAcceptedDispatchAuthority)
      .mockResolvedValueOnce("active")
      .mockResolvedValue("inactive");
    vi.mocked(manager.dispatchOperation).mockResolvedValue("refused_before_frame");
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    expect(store.operations.get("op-1")).toMatchObject({
      state: "FAILED",
      errorCode: "credential_inactive",
      dispatchAttempt: 1,
    });
    expect(store.outbox.get("evt-1")).toMatchObject({
      processedAt: expect.any(Date),
      sentAt: null,
    });
  });

  it("C21-16b: a send refused for another reason with a still-valid key stays pending", async () => {
    authorizedBy();
    vi.mocked(checkAcceptedDispatchAuthority).mockResolvedValue("active");
    vi.mocked(manager.dispatchOperation).mockResolvedValue("refused_before_frame");
    await processSandboxOutboxBatch();
    expect(store.operations.get("op-1")!.state).toBe("QUEUED");
    expect(store.operations.get("op-1")!.errorCode ?? null).toBeNull();
    expect(store.outbox.get("evt-1")!.processedAt).toBeNull();
  });

  it("C21-16c: a cancel control for a revoked key is not sent and does not terminalize dispatched work", async () => {
    running("operation.cancel");
    authorizedBy();
    vi.mocked(checkAcceptedDispatchAuthority).mockResolvedValue("inactive");
    await processSandboxOutboxBatch();
    expect(manager.cancelOperation).not.toHaveBeenCalled();
    expect(store.operations.get("op-1")!.state).toBe("CANCEL_REQUESTED");
    expect(store.outbox.get("evt-1")!.processedAt).toEqual(expect.any(Date));
  });

  it("C21-16c: a cancel control for a valid key carries authorizingKeyId to the session fence", async () => {
    running("operation.cancel");
    authorizedBy();
    vi.mocked(checkAcceptedDispatchAuthority).mockResolvedValue("active");
    await processSandboxOutboxBatch();
    expect(manager.cancelOperation).toHaveBeenCalledWith(
      "host-1",
      "op-1",
      1,
      1,
      expect.any(Number),
      { kind: "sdkKey", keyId: "key-1" },
    );
  });
});

it("dispatches committed uploads from the bound spool instead of inline payload bytes", async () => {
  store.operations.get("op-1")!.kind = "PUT_FILE";
  Object.assign(store.outbox.get("evt-1")!.payload, {
    kind: "file.put",
    transferId: "transfer-1",
    path: "/tmp/data",
  });
  const source = { size: 33 * 1024 * 1024, sha256: "a".repeat(64), read: vi.fn() };
  upload.source.mockResolvedValue(source);
  expect(await processSandboxOutboxBatch()).toBe(1);
  expect(upload.source).toHaveBeenCalledWith("transfer-1", "op-1");
  expect(manager.dispatchOperation).toHaveBeenCalledWith(
    "host-1",
    expect.objectContaining({ kind: "file.put", fileUpload: source }),
  );
});

it("fails a file.put without a committed transfer instead of reading any SQL payload", async () => {
  store.operations.get("op-1")!.kind = "PUT_FILE";
  Object.assign(store.outbox.get("evt-1")!.payload, { kind: "file.put", path: "/tmp/data" });
  await processSandboxOutboxBatch();
  expect(upload.source).not.toHaveBeenCalled();
  expect(manager.dispatchOperation).not.toHaveBeenCalled();
  expect(store.operations.get("op-1")!.state).toBe("FAILED");
  expect(store.outbox.get("evt-1")!.processedAt).not.toBeNull();
});

it("dispatches initial command stdin from the durable outbox payload", async () => {
  Object.assign(store.outbox.get("evt-1")!.payload, {
    kind: "command.run",
    script: "cat",
    hasStdin: true,
    stdinBase64: Buffer.from([0, 255, 10]).toString("base64"),
  });
  expect(await processSandboxOutboxBatch()).toBe(1);
  expect(manager.dispatchOperation).toHaveBeenCalledWith(
    "host-1",
    expect.objectContaining({
      kind: "command.run",
      stdinBytes: Uint8Array.from([0, 255, 10]),
      stdinEof: true,
      stdinSequence: 0,
    }),
  );
});

it("shares accepted command description fixtures with the Rust host", async () => {
  const { acceptedCommandDescription } = await import("./outbox-processor");
  const cases = (
    await import("../../../../crates/sandbox-protocol/fixtures/command_descriptions.json")
  ).default;
  for (const c of cases)
    expect(acceptedCommandDescription(c.input) ?? null, c.name).toEqual(c.expected);
});

it("allocation journal lineage survives same-journal retries and is permanently invalidated by a different journal", async () => {
  store.operations.get("op-1")!.kind = "RECONNECT_SANDBOX";
  Object.assign(store.outbox.get("evt-1")!.payload, {
    kind: "sandbox.reconnect",
    egressPolicy: { domains: [], cidrs: [] },
    egressPolicyHash: "a".repeat(64),
  });
  vi.mocked(manager.dispatchOperation).mockResolvedValue("sent_then_lost_authority");
  for (const [index, id] of ["a", "a", "b", "a"].entries()) {
    const epoch = index + 1;
    Object.assign(store.hosts.get("host-1")!, {
      connectionEpoch: epoch,
      admissionEpoch: epoch,
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: epoch,
      inventoryAcknowledgedEpoch: epoch,
      journalKeyAcknowledgedEpoch: epoch,
      daemonFeatures: { egressPolicy: true, terminal: false, journalId: id.repeat(32) },
    });
    for (const row of store.availability.values()) row.verifiedConnectionEpoch = epoch;
    Object.assign(store.outbox.get("evt-1")!, {
      claimedAt: null,
      claimToken: null,
      sentAt: null,
      processedAt: null,
    });
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(epoch);
    expect(store.operations.get("op-1")!.dispatchAttempt).toBe(epoch);
    expect(store.outbox.get("evt-1")!.payload).toMatchObject({
      allocationJournalId: epoch < 3 ? "a".repeat(32) : null,
      allocationJournalAttempt: epoch,
      allocationJournalEpoch: epoch,
    });
    // Journal lineage is server-only metadata, never guest/dispatch content.
    expect(manager.dispatchOperation).toHaveBeenLastCalledWith(
      "host-1",
      expect.not.objectContaining({ allocationJournalId: expect.anything() }),
    );
  }
});

it.each([false, true])(
  "an unbound 10.7 allocation cannot retry-loop and releases only a proven first claim (retry: %s)",
  async (retry) => {
    Object.assign(store.operations.get("op-1")!, {
      kind: "CREATE_SANDBOX",
      ...(retry
        ? {
            state: "DISPATCHED",
            dispatchAttempt: 1,
            dispatchedHostId: "host-1",
            dispatchedConnectionEpoch: 1,
          }
        : {}),
    });
    Object.assign(store.sandboxes.get("sbx-1")!, {
      state: "PROVISIONING",
      liveResourcesHeld: true,
    });
    Object.assign(store.hosts.get("host-1")!, {
      liveCount: 1,
      memoryReservedMiB: 1344,
      vcpuReserved: 1,
      rootCount: 1,
      daemonVcpuBudget: 64,
      StoragePools: [],
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: retry ? 2 : 1,
      connectionEpoch: retry ? 2 : 1,
      admissionEpoch: retry ? 2 : 1,
      inventoryAcknowledgedEpoch: retry ? 2 : 1,
      journalKeyAcknowledgedEpoch: retry ? 2 : 1,
      daemonEgressGuardEpoch: retry ? 2 : 1,
      // No admitted journal identity: prepare cannot establish a binding.
      daemonFeatures: { egressPolicy: true },
    });
    const rootPool = store.storagePools.get("storage:host-1")!;
    rootPool.connectionEpoch = retry ? 2 : 1;
    rootPool.reportedAt = new Date();
    Object.assign(store.outbox.get("evt-1")!, { eventType: "sandbox.create_requested" });
    Object.assign(store.outbox.get("evt-1")!.payload, {
      kind: "sandbox.create",
      egressPolicy: { domains: [], cidrs: [] },
      egressPolicyHash: "a".repeat(64),
    });
    vi.mocked(manager.dispatchOperation).mockImplementation(async () => {
      expect(store.outbox.get("evt-1")!.payload.allocationJournalEpoch).toBeUndefined();
      throw new SandboxRelayDispatchValidationError("Missing allocation journal binding.");
    });
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    expect(store.operations.get("op-1")).toMatchObject({
      state: retry ? "UNKNOWN_OUTCOME" : "FAILED",
      errorCode: "protocol_error",
    });
    expect(store.sandboxes.get("sbx-1")).toMatchObject({
      state: retry ? "PROVISIONING" : "ERROR",
      liveResourcesHeld: retry,
      ...(retry ? {} : { lastErrorCode: "protocol_error" }),
    });
    expect(store.hosts.get("host-1")).toMatchObject({
      liveCount: retry ? 1 : 0,
      memoryReservedMiB: retry ? 1344 : 0,
    });
    expect(store.outbox.get("evt-1")).toMatchObject({
      processedAt: expect.any(Date),
      sentAt: null,
    });
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    expect(store.hosts.get("host-1")!.liveCount).toBe(retry ? 1 : 0);
  },
);

describe("launch credential spec reference (CLI logins §6.1)", () => {
  const ref = { digest: "a".repeat(64), bytes: 512 };

  it("rides create, reconnect and template capture dispatches verbatim", async () => {
    const { launchCredentialSpec } = await import("./outbox-processor.js");
    for (const kind of ["sandbox.create", "sandbox.reconnect", "sandbox.capture"])
      expect(launchCredentialSpec(kind, { credentialSpec: ref })).toEqual({
        credentialSpec: ref,
      });
    expect(launchCredentialSpec("sandbox.create", {})).toEqual({});
  });

  it("fails closed on a malformed or misplaced reference", async () => {
    const { launchCredentialSpec } = await import("./outbox-processor.js");
    for (const bad of [
      { digest: "A".repeat(64), bytes: 512 },
      { digest: "a".repeat(64), bytes: 0 },
      { digest: "a".repeat(64), bytes: 512, extra: 1 },
      "inline-spec",
    ])
      expect(() => launchCredentialSpec("sandbox.create", { credentialSpec: bad })).toThrow(
        SandboxRelayDispatchValidationError,
      );
    expect(() => launchCredentialSpec("command.run", { credentialSpec: ref })).toThrow(
      SandboxRelayDispatchValidationError,
    );
  });
});
