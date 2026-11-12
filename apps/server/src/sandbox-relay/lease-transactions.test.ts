vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { readFileSync } from "node:fs";
import {
  createSandboxInput,
  reconnectSandboxInput,
  relayDispatchKind,
  setSandboxTimeoutInput,
} from "@wssp/api/sandbox/contracts";
import { requestDigestMetadata } from "@wssp/api/sandbox/idempotency";
import {
  initialLeaseFields,
  leaseExpiryIdempotencyKey,
  leaseExpiryRequestHash,
  reclaimExpiredSandboxLeases,
} from "@wssp/api/sandbox/lease";
import { isLifecycleOperationKind } from "@wssp/api/sandbox/state-transitions";
import prisma from "@wssp/db";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createSandbox,
  killSandbox,
  reconnectSandbox,
  setSandboxTimeout,
  stopSandbox,
} from "../../../../packages/api/src/sandbox/services/sandboxes";
import {
  createFenceStore,
  gate,
  installFenceTransaction,
  matches,
  type OperationRow,
  prismaPromise,
  type Row,
} from "./fenced-prisma-harness.js";
import {
  applyOperationResult,
  confirmOperationReceipt,
  finishHostReconciliation,
} from "./operation-handlers.js";
import { processSandboxOutboxBatch } from "./outbox-processor.js";
import { parseDaemonControlFrame } from "./protocol.js";
import { sandboxRelaySessionManager as manager } from "./session-manager.js";

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
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
    dispatchOperation: vi.fn().mockReturnValue("sent"),
  },
}));
const db = vi.mocked(prisma, true);
const owner = { kind: "session" as const, ownerId: "user-1" };
const clock = () => new Date();
const tick = (ms: number) => vi.setSystemTime(Date.now() + ms);
const deadline = (ms = 1000) => new Date(Date.now() + ms);
let store: ReturnType<typeof createFenceStore>;
function setup(init: Parameters<typeof createFenceStore>[0] = {}) {
  store = createFenceStore({
    hosts: [{ id: "host-1", userId: "user-1", connectionEpoch: 1 }],
    templates: [
      {
        id: "tpl-1",
        userId: "user-1",
        sandboxHostId: "host-1",
        imageRef: "images:ubuntu/24.04/cloud",
        architecture: "x86_64",
        incusFingerprint: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        guestUid: 1000,
        guestGid: 1000,
        guestHome: "/home/user",
        guestShell: "/bin/bash",
      },
    ],
    ...init,
  });
  installFenceTransaction(db, store);
  function find(rows: Map<string, Row>, where: unknown) {
    return structuredClone(
      [...rows.values()].find((r) => matches(r, where as Record<string, unknown>)) ?? null,
    );
  }
  db.sandbox.findFirst.mockImplementation((args) =>
    Object.assign(prismaPromise(Promise.resolve(find(store.sandboxes, args?.where) as never)), {
      User: vi.fn(),
      SandboxHost: vi.fn(),
      SandboxTemplateRevision: vi.fn(),
      StoragePool: vi.fn(),
      Placements: vi.fn(),
      CurrentPlacement: vi.fn(),
      CapacityWait: vi.fn(),
      Operations: vi.fn(),
      Transfers: vi.fn(),
      TerminalTickets: vi.fn(),
      TerminalSessions: vi.fn(),
      ExecutionConfig: vi.fn(),
      DispatchOutbox: vi.fn(),
      CredentialLeases: vi.fn(),
      CredentialResidue: vi.fn(),
      Credentials: vi.fn(),
      DiskOffloads: vi.fn(),
      CurrentDiskOffload: vi.fn(),
      DiskCopies: vi.fn(),
    }),
  );
  db.sandboxHost.findFirst.mockImplementation((args) =>
    Object.assign(prismaPromise(Promise.resolve(find(store.hosts, args?.where) as never)), {
      User: vi.fn(),
      HostTerminalTickets: vi.fn(),
      HostTokens: vi.fn(),
      HostDeviceCredentials: vi.fn(),
      SdkKeyHostAllowlist: vi.fn(),
      Sandboxes: vi.fn(),
      TemplateAvailability: vi.fn(),
      PoolMemberships: vi.fn(),
      StoragePools: vi.fn(),
      ImageCache: vi.fn(),
      CredentialPendingCaptures: vi.fn(),
      CredentialCensus: vi.fn(),
      CredentialTombstones: vi.fn(),
      CredentialReturnKeys: vi.fn(),
      DiskCopies: vi.fn(),
    }),
  );
  db.sandboxTemplateRevision.findFirst.mockImplementation((args) =>
    Object.assign(prismaPromise(Promise.resolve(find(store.templates, args?.where) as never)), {
      User: vi.fn(),
      Sandboxes: vi.fn(),
      SandboxHost: vi.fn(),
      SdkKeyRevisionAllowlist: vi.fn(),
      Revisions: vi.fn(),
      Tags: vi.fn(),
      Template: vi.fn(),
      Availability: vi.fn(),
      Config: vi.fn(),
      Grants: vi.fn(),
      Placements: vi.fn(),
      UpstreamImage: vi.fn(),
    }),
  );
  db.sandboxOperation.findFirst.mockImplementation((args) => {
    const rows = new Map(
      [...store.operations].map(([id, row]) => [
        id,
        { ...row, Sandbox: store.sandboxes.get(row.sandboxId) },
      ]),
    );
    return Object.assign(prismaPromise(Promise.resolve(find(rows, args?.where) as never)), {
      User: vi.fn(),
      Sandbox: vi.fn(),
      TypedResult: vi.fn(),
      CommandOutput: vi.fn(),
      Placement: vi.fn(),
      Capture: vi.fn(),
      CapacityWait: vi.fn(),
      CredentialSpec: vi.fn(),
      RestoreWait: vi.fn(),
    });
  });
  db.sandboxOperation.findUnique.mockImplementation((args) =>
    Object.assign(prismaPromise(Promise.resolve(find(store.operations, args?.where) as never)), {
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
  for (const [delegate, rows] of [
    [db.sandbox, store.sandboxes],
    [db.outboxEvent, store.outbox],
  ] as const) {
    delegate.findMany.mockImplementation((args) =>
      prismaPromise(
        Promise.resolve(
          [...rows.values()]
            .filter((r) => matches(r, args?.where as Record<string, unknown>))
            .sort((a, b) => a.id.localeCompare(b.id))
            .slice(0, args?.take ?? 32) as never,
        ),
      ),
    );
  }
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
  db.outboxEvent.updateMany.mockImplementation((args) =>
    prismaPromise(db.$transaction((tx) => tx.outboxEvent.updateMany(args))),
  );
}
function operation(id: string) {
  return store.operations.get(id)!;
}
function operations(kind: string) {
  return [...store.operations.values()].filter((op) => op.kind === kind);
}
function expiryOperations(id: string) {
  return [...store.operations.values()].filter(
    (op) => op.sandboxId === id && String(op.idempotencyKey).startsWith("lease-expire:"),
  );
}
// Model only hello's durable epoch advance; lifecycle transitions still use
// production services/handlers. No sockets or runtime effects are simulated.
async function replaceHostEpoch() {
  await db.$transaction((tx) =>
    tx.sandboxHost.updateMany({
      where: { id: "host-1", connectionEpoch: 1 },
      data: { connectionEpoch: 2 },
    }),
  );
}
async function result(
  op: OperationRow,
  state = "succeeded",
  receipt = false,
  connectionEpoch = 1,
  payload?: Record<string, unknown>,
) {
  if (!isLifecycleOperationKind(op.kind)) throw new Error("expected lifecycle operation");
  return applyOperationResult(
    {
      sender: { userId: op.userId, hostId: op.dispatchedHostId!, connectionEpoch },
      operationId: op.id,
      sandboxId: op.sandboxId,
      generation: op.generation,
      attempt: op.dispatchAttempt,
      state,
      result: payload ?? {
        lease: [...store.outbox.values()].find((event) => event.payload.operationId === op.id)
          ?.payload.lease,
        state:
          op.kind === "STOP_SANDBOX" ? "stopped" : op.kind === "KILL_SANDBOX" ? "deleted" : "ready",
      },
      ...(receipt
        ? {
            receipt: {
              bodyHash: String(op.requestBodyHash),
              idempotencyKey: String(op.idempotencyKey),
              kind: relayDispatchKind(op.kind)!,
            },
          }
        : {}),
    },
    clock,
  );
}
async function create(key = "create", onExpire: "stop" | "destroy" = "stop", ms = 1000) {
  const sandbox = await createSandbox(owner, {
    template: "revision/" + "tpl-1",
    sandboxHostId: "host-1",
    idempotencyKey: key,
    timeoutMs: ms,
    lifecycle: { onTimeout: onExpire === "stop" ? "stop" : "kill" },
  });
  return {
    id: sandbox.id,
    op: operations("CREATE_SANDBOX").find((op) => op.sandboxId === sandbox.id)!,
  };
}
async function ready(key = "create", ms = 1000, onExpire: "stop" | "destroy" = "stop") {
  const created = await create(key, onExpire, ms);
  await processSandboxOutboxBatch(clock);
  expect(await result(operation(created.op.id))).toEqual({ written: true });
  return created.id;
}
async function stopped(onExpire: "stop" | "destroy" = "stop") {
  const id = await ready("create", 1000, onExpire);
  const stopped = await stopSandbox(owner, { id, idempotencyKey: "manual-stop" });
  const opId = stopped.operationId;
  await processSandboxOutboxBatch(clock);
  expect(await result(operation(opId))).toEqual({ written: true });
  return id;
}
async function reconnect(id: string, key = "reconnect", _onExpire: "stop" | "destroy" = "stop") {
  const queued = await reconnectSandbox(owner, { id, idempotencyKey: key, timeoutMs: 1000 }, clock);
  return operation(queued.operationId);
}
function pause(
  point: "beforeHostLock" | "beforeSandboxLock" | "beforeOperationWrite" | "beforeCommit",
) {
  const entered = gate();
  const resume = gate();
  store.barriers[point] = async () => {
    store.barriers[point] = undefined;
    entered.resolve();
    await resume.promise;
  };
  return { entered: entered.promise, resume: resume.resolve };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
  vi.setSystemTime("2026-01-01T00:00:00Z");
  setup();
});
afterEach(() => vi.useRealTimers());

describe("C11 service / outbox / handler lease transactions", () => {
  it("empty scan and omitted lease defaults", async () => {
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    const row = await createSandbox(
      owner,
      createSandboxInput.parse({
        template: "revision/" + "tpl-1",
        sandboxHostId: "host-1",
        idempotencyKey: "default",
      }),
    );
    expect(store.sandboxes.get(row.id)).toMatchObject({
      leaseRevision: 1,
      leaseExpiresAt: deadline(300_000),
      leaseExpireAction: "DESTROY",
      leaseExpiresAtEffective: null,
      leaseExpireActionEffective: null,
    });
    expect(reconnectSandboxInput.parse({ id: row.id, idempotencyKey: "reconnect" })).toMatchObject({
      id: row.id,
      idempotencyKey: "reconnect",
    });
  });

  it("two complete stop-expire → cold reconnect → renew → expire cycles use distinct operations", async () => {
    const id = await ready();
    const expiryIds: string[] = [];
    async function expireAndStop() {
      tick(1000);
      expect(await reclaimExpiredSandboxLeases(clock)).toBe(1);
      const expiry = operations("STOP_SANDBOX").at(-1)!;
      expiryIds.push(expiry.id);
      await processSandboxOutboxBatch(clock);
      expect(await result(operation(expiry.id))).toEqual({ written: true });
      expect(store.sandboxes.get(id)?.state).toBe("STOPPED");
    }
    await expireAndStop();
    for (let cycle = 0; cycle < 2; cycle++) {
      const priorRevision = store.sandboxes.get(id)!.leaseRevision!;
      const op = await reconnect(id, `reconnect-${cycle}`);
      expect(store.sandboxes.get(id)).toMatchObject({
        leaseRevision: priorRevision + 1,
        leaseExpiresAt: deadline(),
      });
      await processSandboxOutboxBatch(clock);
      expect(await result(operation(op.id))).toEqual({ written: true });
      const renewal = {
        id,
        idempotencyKey: `renew-${cycle}`,
        timeoutMs: 1000,
      };
      const renewed = await setSandboxTimeout(owner, renewal, clock);
      expect(renewed.leaseRevision).toBe(priorRevision + 2);
      expect((await setSandboxTimeout(owner, renewal, clock)).leaseRevision).toBe(
        renewed.leaseRevision,
      );
      await expireAndStop();
    }
    expect(new Set(expiryIds).size).toBe(3);
    expect(new Set(operations("STOP_SANDBOX").map((op) => op.idempotencyKey)).size).toBe(3);
    expect(new Set(operations("STOP_SANDBOX").map((op) => op.requestBodyHash)).size).toBe(3);
  });

  it("simultaneous reclaim workers commit only one expiry", async () => {
    await ready();
    tick(1000);
    const barrier = pause("beforeSandboxLock");
    const first = reclaimExpiredSandboxLeases(clock);
    await barrier.entered;
    const second = reclaimExpiredSandboxLeases(clock);
    barrier.resume();
    expect((await Promise.all([first, second])).sort()).toEqual([0, 1]);
    expect(operations("STOP_SANDBOX")).toHaveLength(1);
  });

  it("a committed renewal invalidates a stale scanner candidate", async () => {
    const id = await ready();
    // Only an unacknowledged lease is renewable past the server deadline; an
    // effective host deadline that already passed is enforced without us.
    Object.assign(store.sandboxes.get(id) ?? {}, {
      leaseRevisionEffective: null,
      leaseExpiresAtEffective: null,
      leaseExpireActionEffective: null,
    });
    tick(1000);
    const barrier = pause("beforeHostLock");
    const expiry = reclaimExpiredSandboxLeases(clock);
    await barrier.entered;
    await setSandboxTimeout(owner, { id, timeoutMs: 1000, idempotencyKey: "renew" }, clock);
    barrier.resume();
    expect(await expiry).toBe(0);
    expect(store.sandboxes.get(id)?.leaseRevision).toBe(2);
  });

  it("an effective host lease past its deadline defeats a stale renewal", async () => {
    const id = await ready();
    expect(store.sandboxes.get(id)?.leaseExpiresAtEffective).toBeInstanceOf(Date);
    tick(1000);
    await expect(
      setSandboxTimeout(owner, { id, timeoutMs: 1000, idempotencyKey: "late" }, clock),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    expect(store.sandboxes.get(id)?.leaseRevision).toBe(1);
  });
  it("expiry wins before renewal acquires H: renewal conflicts", async () => {
    const id = await ready();
    tick(1000);
    const barrier = pause("beforeHostLock");
    const renewal = setSandboxTimeout(
      owner,
      { id, timeoutMs: 1000, idempotencyKey: "renew" },
      clock,
    );
    const rejection = expect(renewal).rejects.toMatchObject({ code: "CONFLICT" });
    await barrier.entered;
    expect(await reclaimExpiredSandboxLeases(clock)).toBe(1);
    barrier.resume();
    await rejection;
  });

  it.each(["stop", "destroy"] as const)(
    "late create and cold reconnect apply %s cleanup and settle predecessors",
    async (onExpire) => {
      const created = await create("late-create", onExpire);
      await processSandboxOutboxBatch(clock);
      tick(1000);
      expect(await result(operation(created.op.id), "succeeded", true)).toEqual({ written: true });
      expect(operation(created.op.id)).toMatchObject({
        state: "FAILED",
        errorCode: "lease_expired",
      });
      expect(store.sandboxes.get(created.id)).toMatchObject({
        state: "STOPPING",
        incusName: `wssp-sbx-${created.id}`,
      });
      const kind = onExpire === "stop" ? "STOP_SANDBOX" : "KILL_SANDBOX";
      expect(operations(kind)).toHaveLength(1);
      expect(await result(operation(created.op.id))).toEqual({ written: false });
      await processSandboxOutboxBatch(clock);
      await result(operations(kind)[0]!);
      expect(store.sandboxes.get(created.id)?.state).toBe(
        onExpire === "stop" ? "STOPPED" : "DELETED",
      );

      const id = await stopped(onExpire);
      const older = await reconnect(id, "older", onExpire);
      await processSandboxOutboxBatch(clock);
      const newer = await reconnect(id, "newer", onExpire);
      await processSandboxOutboxBatch(clock);
      expect(operation(older.id).state).toBe("CANCEL_REQUESTED");
      tick(1000);
      expect(await result(operation(newer.id))).toEqual({ written: true });
      expect(operation(older.id)).toMatchObject({
        state: "UNKNOWN_OUTCOME",
        errorCode: "superseded",
      });
      expect(operation(newer.id)).toMatchObject({ state: "FAILED", errorCode: "lease_expired" });
      expect(store.sandboxes.get(id)?.state).toBe("STOPPING");
      const expiry = operations(kind)
        .filter((op) => String(op.idempotencyKey).startsWith("lease-expire:"))
        .at(-1)!;
      await processSandboxOutboxBatch(clock);
      await result(operation(expiry.id));
      expect(operation(older.id).state).toBe("CANCELLED");
      expect(store.sandboxes.get(id)?.state).toBe(onExpire === "stop" ? "STOPPED" : "DELETED");
      if (onExpire === "destroy") {
        await expect(reconnect(id, "cannot-revive")).rejects.toMatchObject({ code: "CONFLICT" });
        await expect(
          setSandboxTimeout(owner, { id, timeoutMs: 1000, idempotencyKey: "cannot-renew" }, clock),
        ).rejects.toMatchObject({ code: "CONFLICT" });
        expect(await result(operation(newer.id))).toEqual({ written: false });
      }
    },
  );

  it.each(["stop", "destroy"] as const)(
    "never-launched create with %s expiry retires without host intent",
    async (onExpire) => {
      const { id, op } = await create("never-launched", onExpire);
      tick(1000);
      await processSandboxOutboxBatch(clock);
      await processSandboxOutboxBatch(clock);
      expect(operation(op.id)).toMatchObject({
        state: "FAILED",
        errorCode: "lease_expired",
        dispatchAttempt: 0,
      });
      expect(store.sandboxes.get(id)?.state).toBe("ERROR");
      expect(expiryOperations(id)).toHaveLength(0);
      expect([...store.outbox.values()].every((event) => event.processedAt != null)).toBe(true);
      expect(manager.dispatchOperation).not.toHaveBeenCalled();
    },
  );

  it.each(["stop", "destroy"] as const)(
    "queued replacement uses current %s action after predecessor reconciles unknown",
    async (onExpire) => {
      const id = await stopped(onExpire);
      const older = await reconnect(id, "older", onExpire === "stop" ? "destroy" : "stop");
      await processSandboxOutboxBatch(clock);
      const newer = await reconnect(id, "newer", onExpire);
      await replaceHostEpoch();
      const sender = { userId: "user-1", hostId: "host-1", connectionEpoch: 2 };
      expect(await finishHostReconciliation(sender, clock)).toBe(true);
      expect(operation(older.id)).toMatchObject({
        state: "UNKNOWN_OUTCOME",
        errorCode: "superseded",
      });
      tick(1000);
      await processSandboxOutboxBatch(clock);
      expect(operation(newer.id)).toMatchObject({ state: "FAILED", errorCode: "lease_expired" });
      expect(expiryOperations(id)).toHaveLength(1);
      expect(expiryOperations(id)[0]).toMatchObject({
        kind: onExpire === "stop" ? "STOP_SANDBOX" : "KILL_SANDBOX",
        idempotencyKey: leaseExpiryIdempotencyKey(
          id,
          newer.generation + 1,
          3,
          onExpire === "stop" ? "STOP" : "DESTROY",
        ),
      });
      expect(await result(operation(older.id), "succeeded", true, 2)).toEqual({ written: false });
      expect(await finishHostReconciliation(sender, clock)).toBe(true);
      expect(expiryOperations(id)).toHaveLength(1);
    },
  );

  const expiryExits = (["create", "reconnect"] as const).flatMap((kind) =>
    (["stop", "destroy"] as const).flatMap((onExpire) =>
      (["retry", "reconciliation", "failed", "unknown_outcome", "cancelled"] as const).map(
        (exit) => ({ kind, onExpire, exit }),
      ),
    ),
  );
  it.each(expiryExits)(
    "$kind $exit at deadline commits one $onExpire intent",
    async ({ kind, onExpire, exit }) => {
      const id =
        kind === "create" ? (await create("create", onExpire)).id : await stopped(onExpire);
      const op =
        kind === "create"
          ? operations("CREATE_SANDBOX")[0]!
          : await reconnect(id, "reconnect", onExpire);
      if (exit === "retry")
        vi.mocked(manager.dispatchOperation).mockResolvedValueOnce("sent_then_lost_authority");
      await processSandboxOutboxBatch(clock);
      expect(operation(op.id).state).toBe("DISPATCHED");
      vi.mocked(manager.dispatchOperation).mockClear();
      const sender = { userId: "user-1", hostId: "host-1", connectionEpoch: 2 };
      if (exit === "retry" || exit === "reconciliation") await replaceHostEpoch();
      if (exit === "reconciliation") {
        // Cross the deadline while waiting for S, not before inventory sampling.
        const barrier = pause("beforeSandboxLock");
        const pending = finishHostReconciliation(sender, clock);
        await barrier.entered;
        tick(1000);
        barrier.resume();
        expect(await pending).toBe(true);
      } else {
        tick(1000);
        if (exit === "retry") await processSandboxOutboxBatch(clock);
        else expect(await result(operation(op.id), exit)).toEqual({ written: true });
      }
      expect(manager.dispatchOperation).not.toHaveBeenCalled();
      // Uncertain fresh creates now transfer all holds to teardown, including
      // a stop lease that expired before the uncertainty result arrived.
      const uncertainCreate = kind === "create" && exit === "unknown_outcome";
      expect(operation(op.id)).toMatchObject({
        state: "FAILED",
        errorCode: uncertainCreate ? "unknown_outcome" : "lease_expired",
      });
      expect(store.sandboxes.get(id)?.state).toBe("STOPPING");
      const cleanupOperations = () =>
        uncertainCreate
          ? operations("KILL_SANDBOX").filter((row) => row.sandboxId === id)
          : expiryOperations(id);
      expect(cleanupOperations()).toHaveLength(1);
      const expiry = cleanupOperations()[0]!;
      expect(expiry.kind).toBe(
        uncertainCreate || onExpire === "destroy" ? "KILL_SANDBOX" : "STOP_SANDBOX",
      );
      expect([...store.outbox.values()].filter((event) => event.processedAt == null)).toHaveLength(
        1,
      );
      expect(await reclaimExpiredSandboxLeases(clock)).toBe(0);
      expect(await result(operation(op.id), "succeeded", true)).toEqual({ written: false });
      await processSandboxOutboxBatch(clock);
      await result(
        operation(expiry.id),
        "succeeded",
        false,
        exit === "retry" || exit === "reconciliation" ? 2 : 1,
      );
      expect(store.sandboxes.get(id)?.state).toBe(
        uncertainCreate || onExpire === "destroy" ? "DELETED" : "STOPPED",
      );
      expect(cleanupOperations()).toHaveLength(1);
    },
  );

  it("expired exact receipt on a replacement epoch uses the adopted operation fence", async () => {
    const { id, op } = await create();
    await processSandboxOutboxBatch(clock);
    await replaceHostEpoch();
    tick(1000);
    expect(await result(operation(op.id), "succeeded", true, 2)).toEqual({ written: true });
    expect(operation(op.id)).toMatchObject({ state: "FAILED", dispatchedConnectionEpoch: 2 });
    expect(expiryOperations(id)).toHaveLength(1);
    expect(store.sandboxes.get(id)?.incusName).toBe(`wssp-sbx-${id}`);
  });

  it.each([
    { onExpire: "stop", receipt: false },
    { onExpire: "stop", receipt: true },
    { onExpire: "destroy", receipt: false },
    { onExpire: "destroy", receipt: true },
  ] as const)(
    "C3: dispatched create with no VM expires; $onExpire cleanup (receipt=$receipt) confirms no startable disk",
    async ({ onExpire, receipt }) => {
      // These exact wire outcomes are checked against Incus's executable shim,
      // FakeRuntime's live supervisor, and the Rust protocol (no invented success).
      const fixtures = JSON.parse(
        readFileSync(
          new URL(
            "../../../../crates/sandbox-protocol/fixtures/control_absent_cleanup_results.json",
            import.meta.url,
          ),
          "utf8",
        ),
      );
      const frame = parseDaemonControlFrame(
        JSON.stringify(fixtures[onExpire === "stop" ? 0 : 1].frame),
      );
      if (frame.type !== "operation.result") throw new Error("expected result");
      const { id, op } = await create("create-no-vm", onExpire);
      await processSandboxOutboxBatch(clock);
      expect(operation(op.id).state).toBe("DISPATCHED");
      // Dispatch reserves the name; only the host's query establishes absence.
      expect(store.sandboxes.get(id)?.incusName).toBe(`wssp-sbx-${id}`);
      tick(1000);
      expect(await result(operation(op.id), "failed")).toEqual({ written: true });
      expect(operation(op.id)).toMatchObject({ state: "FAILED", errorCode: "lease_expired" });
      expect(store.sandboxes.get(id)?.state).toBe("STOPPING");
      expect(expiryOperations(id)).toHaveLength(1);
      const cleanup = expiryOperations(id)[0]!;
      expect(cleanup.kind).toBe(onExpire === "stop" ? "STOP_SANDBOX" : "KILL_SANDBOX");
      await processSandboxOutboxBatch(clock);
      if (receipt) await replaceHostEpoch();
      const epoch = receipt ? 2 : 1;
      expect(
        await result(operation(cleanup.id), frame.state, receipt, epoch, frame.result),
      ).toEqual({ written: true });
      expect(operation(cleanup.id)).toMatchObject({ state: "SUCCEEDED", result: frame.result });
      // Proven absence ends DELETED for both Stop and Destroy, including
      // lease expiry before init. Replaying the receipt cannot release twice.
      expect(store.sandboxes.get(id)?.state).toBe(onExpire === "stop" ? "STOPPED" : "DELETED");
      expect(await reclaimExpiredSandboxLeases(clock)).toBe(0);
      expect(await processSandboxOutboxBatch(clock)).toBe(0);
      expect(
        await result(operation(cleanup.id), frame.state, receipt, epoch, frame.result),
      ).toEqual({ written: false });
      expect(expiryOperations(id)).toHaveLength(1);
      expect([...store.outbox.values()].every((event) => event.processedAt != null)).toBe(true);
    },
  );

  it("lost reconciliation authority rolls back expiry and settlement before retry", async () => {
    const id = await stopped();
    const older = await reconnect(id, "older");
    await processSandboxOutboxBatch(clock);
    const newer = await reconnect(id, "newer");
    await processSandboxOutboxBatch(clock);
    await replaceHostEpoch();
    tick(1000);
    const before = structuredClone([store.sandboxes, store.operations, store.outbox]);
    const sender = { userId: "user-1", hostId: "host-1", connectionEpoch: 2 };
    expect(
      await finishHostReconciliation(
        {
          ...sender,
          // Reject both per-operation transactions after their writes.
          isCurrent: vi.fn().mockReturnValueOnce(true).mockReturnValue(false),
        },
        clock,
      ),
    ).toBe(false);
    expect([store.sandboxes, store.operations, store.outbox]).toEqual(before);
    expect(expiryOperations(id)).toHaveLength(0);
    expect(await finishHostReconciliation(sender, clock)).toBe(true);
    expect(operation(newer.id)).toMatchObject({ state: "FAILED", errorCode: "lease_expired" });
    expect(operation(older.id).state).toBe("UNKNOWN_OUTCOME");
    expect(expiryOperations(id)).toHaveLength(1);
  });

  it.each(["create", "reconnect"] as const)(
    "%s expires before dispatch without orphan state; retry can re-arm cold reconnect",
    async (kind) => {
      const id = kind === "create" ? (await create()).id : await stopped();
      const op = kind === "create" ? operations("CREATE_SANDBOX")[0]! : await reconnect(id);
      vi.mocked(manager.dispatchOperation).mockClear();
      tick(1000);
      await processSandboxOutboxBatch(clock);
      expect(manager.dispatchOperation).not.toHaveBeenCalled();
      expect(operation(op.id)).toMatchObject({ state: "FAILED", errorCode: "lease_expired" });
      expect(store.sandboxes.get(id)?.state).toBe(kind === "create" ? "ERROR" : "STOPPED");
      if (kind === "reconnect") {
        expect(expiryOperations(id)).toHaveLength(0);
        expect(store.sandboxes.get(id)?.liveResourcesHeld).toBe(false);
        expect(store.hosts.get("host-1")?.liveCount).toBe(0);
        const retry = await reconnect(id, "retry");
        await processSandboxOutboxBatch(clock);
        expect(await result(operation(retry.id))).toEqual({ written: true });
      }
    },
  );

  it.each(["stop", "destroy"] as const)(
    "C2: queued replacement expiry retains %s intent for its dispatched predecessor",
    async (onExpire) => {
      const id = await stopped(onExpire);
      const older = await reconnect(id, "older-active", onExpire);
      await processSandboxOutboxBatch(clock);
      const newer = await reconnect(id, "newer-queued", onExpire);
      const lease = structuredClone(store.sandboxes.get(id)!);
      tick(1000);
      await processSandboxOutboxBatch(clock);
      expect(await result(operation(older.id), "succeeded", true)).toEqual({ written: false });
      expect(await reclaimExpiredSandboxLeases(clock)).toBe(0);
      const expiry = [...store.operations.values()].filter(
        (op) => op.sandboxId === id && String(op.idempotencyKey).startsWith("lease-expire:"),
      );
      expect(expiry).toHaveLength(1);
      expect(expiry[0]).toMatchObject({
        kind: onExpire === "stop" ? "STOP_SANDBOX" : "KILL_SANDBOX",
        generation: lease.generation + 1,
        idempotencyKey: leaseExpiryIdempotencyKey(
          id,
          lease.generation + 1,
          lease.leaseRevision!,
          onExpire === "stop" ? "STOP" : "DESTROY",
        ),
      });
      expect(operation(older.id)).toMatchObject({
        state: "UNKNOWN_OUTCOME",
        errorCode: "superseded",
      });
      expect(operation(newer.id)).toMatchObject({ state: "FAILED", errorCode: "lease_expired" });
      expect(store.sandboxes.get(id)?.state).toBe("STOPPING");
      await processSandboxOutboxBatch(clock);
      await result(operation(expiry[0]!.id));
      expect(operation(older.id).state).toBe("CANCELLED");
      expect(store.sandboxes.get(id)?.state).toBe(onExpire === "stop" ? "STOPPED" : "DELETED");
      await processSandboxOutboxBatch(clock);
      expect(
        [...store.operations.values()].filter(
          (op) => op.sandboxId === id && String(op.idempotencyKey).startsWith("lease-expire:"),
        ),
      ).toHaveLength(1);
    },
  );

  it.each(["create", "reconnect"] as const)(
    "%s dispatch samples time after H/S wait",
    async (kind) => {
      const id = kind === "create" ? (await create()).id : await stopped();
      const op = kind === "create" ? operations("CREATE_SANDBOX")[0]! : await reconnect(id);
      vi.mocked(manager.dispatchOperation).mockClear();
      const barrier = pause("beforeSandboxLock");
      const dispatch = processSandboxOutboxBatch(clock);
      await barrier.entered;
      tick(1000);
      barrier.resume();
      await dispatch;
      expect(manager.dispatchOperation).not.toHaveBeenCalled();
      expect(operation(op.id).state).toBe("FAILED");
    },
  );

  it.each(["create", "reconnect"] as const)("%s result samples time after H wait", async (kind) => {
    const id = kind === "create" ? (await create()).id : await stopped();
    const op = kind === "create" ? operations("CREATE_SANDBOX")[0]! : await reconnect(id);
    await processSandboxOutboxBatch(clock);
    const barrier = pause("beforeHostLock");
    const completion = result(operation(op.id));
    await barrier.entered;
    tick(1000);
    barrier.resume();
    await completion;
    expect(operation(op.id).state).toBe("FAILED");
    expect(store.sandboxes.get(id)?.state).toBe("STOPPING");
  });

  it("cold re-arm defaults start after the sandbox lock wait", async () => {
    const id = await stopped();
    const barrier = pause("beforeSandboxLock");
    const pending = reconnectSandbox(owner, { id, idempotencyKey: "default-rearm" }, clock);
    await barrier.entered;
    tick(2000);
    barrier.resume();
    await pending;
    expect(store.sandboxes.get(id)).toMatchObject({
      leaseRevision: 2,
      leaseExpiresAt: deadline(300_000),
      leaseExpireAction: "STOP",
      leaseExpiresAtEffective: null,
    });
  });

  it("later batch entries use fresh time after an earlier dispatch wait", async () => {
    const first = await create("first");
    const second = await create("second");
    vi.mocked(manager.dispatchOperation).mockImplementationOnce(async () => {
      tick(1000);
      return "sent";
    });
    await processSandboxOutboxBatch(clock);
    expect(operation(first.op.id).state).toBe("DISPATCHED");
    expect(operation(second.op.id)).toMatchObject({ state: "FAILED", errorCode: "lease_expired" });
    expect(store.sandboxes.get(second.id)?.state).toBe("ERROR");
  });

  it("renewal refuses an effective lease that expires while awaiting serialization", async () => {
    const id = await ready();
    const barrier = pause("beforeHostLock");
    const renewal = setSandboxTimeout(
      owner,
      { id, timeoutMs: 1000, idempotencyKey: "renew" },
      clock,
    );
    const rejected = expect(renewal).rejects.toMatchObject({ code: "CONFLICT" });
    await barrier.entered;
    tick(1000);
    barrier.resume();
    await rejected;
    expect(store.sandboxes.get(id)?.leaseRevision).toBe(1);
  });

  it("concurrent identical renewals both replay, changed body conflicts", async () => {
    const id = await ready();
    const input = {
      id,
      timeoutMs: 2000,
      idempotencyKey: "renew",
    };
    const barrier = pause("beforeHostLock");
    const first = setSandboxTimeout(owner, input, clock);
    await barrier.entered;
    const second = await setSandboxTimeout(owner, input, clock);
    barrier.resume();
    expect((await first).leaseRevision).toBe(second.leaseRevision);
    expect(second.leaseRevision).toBe(2);
    expect(operations("RENEW_SANDBOX_LEASE")).toHaveLength(1);
    await expect(
      setSandboxTimeout(owner, { ...input, timeoutMs: 3000 }, clock),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    tick(2000);
    await reclaimExpiredSandboxLeases(clock);
    expect((await setSandboxTimeout(owner, input, clock)).leaseRevision).toBe(2);
  });

  it("owner-wide cross-sandbox reuse returns typed CONFLICT", async () => {
    const first = await ready("first");
    const second = await ready("second");
    await setSandboxTimeout(owner, { id: first, timeoutMs: 2000, idempotencyKey: "shared" }, clock);
    await expect(
      setSandboxTimeout(owner, { id: second, timeoutMs: 2000, idempotencyKey: "shared" }, clock),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    expect(store.sandboxes.get(second)?.leaseRevision).toBe(1);
  });

  it("cross-host duplicate insertion rolls back and translates P2002 to CONFLICT", async () => {
    // Initial independent hosts are fixture topology, not a simulated transition.
    setup({
      hosts: [
        { id: "host-1", userId: "user-1", connectionEpoch: 1 },
        { id: "host-2", userId: "user-1", connectionEpoch: 1 },
      ],
      templates: [
        {
          id: "tpl-1",
          userId: "user-1",
          sandboxHostId: "host-1",
          imageRef: "images:ubuntu/24.04/cloud",
          architecture: "x86_64",
          incusFingerprint:
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
          guestUid: 1000,
          guestGid: 1000,
          guestHome: "/home/user",
          guestShell: "/bin/bash",
        },
        {
          id: "tpl-2",
          userId: "user-1",
          sandboxHostId: "host-2",
          imageRef: "images:ubuntu/24.04/cloud",
          architecture: "x86_64",
          incusFingerprint:
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
          guestUid: 1000,
          guestGid: 1000,
          guestHome: "/home/user",
          guestShell: "/bin/bash",
        },
      ],
    });
    const first = await ready("first");
    const second = await createSandbox(owner, {
      template: "revision/" + "tpl-2",
      sandboxHostId: "host-2",
      idempotencyKey: "second",
      timeoutMs: 1000,
    });
    await processSandboxOutboxBatch(clock);
    await result(operations("CREATE_SANDBOX").at(-1)!);
    const barrier = pause("beforeOperationWrite");
    const loser = setSandboxTimeout(
      owner,
      { id: first, timeoutMs: 2000, idempotencyKey: "race" },
      clock,
    );
    const rejected = expect(loser).rejects.toMatchObject({ code: "CONFLICT" });
    await barrier.entered;
    await setSandboxTimeout(
      owner,
      { id: second.id, timeoutMs: 2000, idempotencyKey: "race" },
      clock,
    );
    barrier.resume();
    await rejected;
    expect(store.sandboxes.get(first)?.leaseRevision).toBe(1);
    expect(operations("RENEW_SANDBOX_LEASE")).toHaveLength(1);
  });

  it("caller contract rejects reserved namespace and non-ASCII/invalid keys", () => {
    for (const idempotencyKey of [
      "lease-expire:sbx-1:2",
      "lease-expire:sbx-1:3:2:STOP",
      "has space",
      "😎",
    ]) {
      expect(
        setSandboxTimeoutInput.safeParse({
          id: "sbx-1",
          leaseExpiresAt: deadline(),
          idempotencyKey,
        }).success,
      ).toBe(false);
      expect(reconnectSandboxInput.safeParse({ id: "sbx-1", idempotencyKey }).success).toBe(false);
      expect(createSandboxInput.safeParse({ templateId: "tpl-1", idempotencyKey }).success).toBe(
        false,
      );
    }
  });

  it("32 semantically skipped expiry rows cannot starve another owner", async () => {
    // Adversarial initial receipts test semantic deduplication and keyset progress.
    const sandboxes = Array.from({ length: 33 }, (_, i) => ({
      id: `sbx-${String(i).padStart(2, "0")}`,
      userId: i < 32 ? "user-1" : "user-2",
      sandboxHostId: i < 32 ? "host-1" : "host-2",
      generation: 1,
      state: "READY",
      ...initialLeaseFields({
        now: Date.now() - 2000,
        onExpire: "stop",
        timeoutMs: 1000,
      }),
    }));
    const receipts = sandboxes.slice(0, 32).map((sandbox, i) => ({
      id: `expiry-${i}`,
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      kind: "STOP_SANDBOX",
      state: "SUCCEEDED",
      generation: 2,
      dispatchAttempt: 1,
      dispatchedHostId: "host-1",
      idempotencyKey: leaseExpiryIdempotencyKey(sandbox.id, 2, 1, "STOP"),
      ...requestDigestMetadata("STOP_SANDBOX"),
      requestBodyHash: leaseExpiryRequestHash({
        sandboxId: sandbox.id,
        generation: 2,
        leaseRevision: 1,
        action: "expire-stop",
      }),
    }));
    setup({
      sandboxes,
      operations: receipts,
      hosts: [
        { id: "host-1", userId: "user-1", connectionEpoch: 1 },
        { id: "host-2", userId: "user-2", connectionEpoch: 1 },
      ],
    });
    expect(await reclaimExpiredSandboxLeases(clock)).toBe(1);
    expect(store.sandboxes.get("sbx-32")?.state).toBe("STOPPING");
    expect([...store.outbox.values()]).toHaveLength(1);
    expect(await reclaimExpiredSandboxLeases(clock)).toBe(0);
  });

  it("repeated shortenings and extensions keep the persistent lifecycle policy", async () => {
    const id = await ready();
    for (const [index, timeoutMs] of ([500, 2000, 1000] as const).entries()) {
      await setSandboxTimeout(owner, { id, timeoutMs, idempotencyKey: `renew-${index}` }, clock);
    }
    tick(1000);
    await reclaimExpiredSandboxLeases(clock);
    expect(operations("STOP_SANDBOX")).toHaveLength(1);
    expect(operations("KILL_SANDBOX")).toHaveLength(0);
    expect(operations("STOP_SANDBOX")[0]!.idempotencyKey).toBe(
      leaseExpiryIdempotencyKey(id, 2, 4, "STOP"),
    );
  });
});

function pinnedReadyFixture() {
  setup({
    hosts: [{ id: "host-1", userId: "user-1", connectionEpoch: 1, liveCount: 1 }],
    sandboxes: [
      {
        id: "sbx-1",
        userId: "user-1",
        sandboxHostId: "host-1",
        templateId: "tpl-1",
        templateRevisionId: "tpl-1",
        originPoolId: null,
        generation: 1,
        state: "READY",
        liveResourcesHeld: true,
        ...initialLeaseFields({ timeoutMs: 10_000 }),
      },
    ],
  });
}
function nextHostWait() {
  const waiting = gate();
  store.onLockWait = (key) => {
    if (key === "hosts:host-1") waiting.resolve();
  };
  return waiting.promise;
}
it("C12 regression restored barrier proves pinned dispatch owns H and renewal waits without inversion", async () => {
  pinnedReadyFixture();
  const op = await reconnect("sbx-1");
  const barrier = pause("beforeSandboxLock");
  const dispatch = processSandboxOutboxBatch(clock);
  await barrier.entered;
  const hostWait = nextHostWait();
  const renew = setSandboxTimeout(
    owner,
    { id: "sbx-1", timeoutMs: 1000, idempotencyKey: "renew" },
    clock,
  );
  await hostWait;
  expect(store.sandboxes.get("sbx-1")?.leaseRevision).toBe(2);
  barrier.resume();
  await Promise.all([dispatch, renew]);
  expect(operation(op.id).state).toBe("DISPATCHED");
  expect(store.sandboxes.get("sbx-1")?.leaseRevision).toBe(3);
  expect(await result(operation(op.id))).toEqual({ written: true });
});

it("C12 regression concurrent production creates cannot exceed cap", async () => {
  setup({
    hosts: [{ id: "host-1", userId: "user-1", connectionEpoch: 1, daemonMemoryBudgetMiB: 1536 }],
  });
  const barrier = pause("beforeSandboxLock");
  const first = create("first");
  await barrier.entered;
  const hostWait = nextHostWait();
  const second = create("second");
  const outcomes = Promise.allSettled([first, second]);
  await hostWait;
  barrier.resume();
  const settled = await outcomes;
  expect(settled.map((x) => x.status)).toEqual(["fulfilled", "rejected"]);
  expect(store.hosts.get("host-1")?.liveCount).toBe(1);
  expect(store.sandboxes.size).toBe(1);
  expect(store.operations.size).toBe(1);
  expect(store.outbox.size).toBe(1);
});

it("C12 regression concurrent production cold reconnects cannot exceed cap", async () => {
  setup({
    hosts: [{ id: "host-1", userId: "user-1", connectionEpoch: 1, daemonMemoryBudgetMiB: 1536 }],
    sandboxes: ["a", "b"].map((id) => ({
      id,
      userId: "user-1",
      sandboxHostId: "host-1",
      templateId: "tpl-1",
      templateRevisionId: "tpl-1",
      originPoolId: null,
      generation: 2,
      state: "STOPPED",
      liveResourcesHeld: false,
      ...initialLeaseFields({ timeoutMs: 1000 }),
    })),
  });
  const barrier = pause("beforeSandboxLock");
  const first = reconnect("a", "cold-a");
  await barrier.entered;
  const hostWait = nextHostWait();
  const second = reconnect("b", "cold-b");
  const outcomes = Promise.allSettled([first, second]);
  await hostWait;
  barrier.resume();
  expect((await outcomes).map((x) => x.status)).toEqual(["fulfilled", "rejected"]);
  expect(store.hosts.get("host-1")?.liveCount).toBe(1);
  expect(store.sandboxes.get("a")?.liveResourcesHeld).toBe(true);
  expect(store.sandboxes.get("b")?.liveResourcesHeld).toBe(false);
  expect(store.sandboxes.get("b")?.generation).toBe(2);
});

it("C12 regression offline pinned create stays queued and reserved", async () => {
  vi.mocked(manager.isHostConnected).mockReturnValue(false);
  try {
    const created = await create();
    await processSandboxOutboxBatch(clock);
    expect(operation(created.op.id).state).toBe("QUEUED");
    expect(store.sandboxes.get(created.id)?.sandboxHostId).toBe("host-1");
    expect(store.hosts.get("host-1")?.liveCount).toBe(1);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  } finally {
    vi.mocked(manager.isHostConnected).mockReturnValue(true);
  }
});

it("C12 regression never dispatched expiry must release proven unallocated reservation", async () => {
  const created = await create("expires", "stop", 1);
  tick(1);
  await processSandboxOutboxBatch(clock);
  expect(operation(created.op.id).state).toBe("FAILED");
  expect(expiryOperations(created.id)).toHaveLength(0);
  expect(store.sandboxes.get(created.id)?.liveResourcesHeld).toBe(false);
  expect(store.hosts.get("host-1")?.liveCount).toBe(0);
});

it("C12 regression replacement cold reconnect refusal must retain possible predecessor VM", async () => {
  setup({
    hosts: [{ id: "host-1", userId: "user-1", connectionEpoch: 1, liveCount: 1 }],
    sandboxes: [
      {
        id: "sbx-1",
        userId: "user-1",
        sandboxHostId: "host-1",
        templateId: "tpl-1",
        templateRevisionId: "tpl-1",
        originPoolId: null,
        generation: 3,
        state: "STOPPED",
        liveResourcesHeld: true,
        ...initialLeaseFields({ timeoutMs: 1000 }),
      },
    ],
    operations: [
      {
        id: "cold-a",
        userId: "user-1",
        sandboxId: "sbx-1",
        generation: 3,
        kind: "RECONNECT_SANDBOX",
        state: "RUNNING",
        dispatchAttempt: 1,
        dispatchedHostId: "host-1",
        idempotencyKey: "cold-a",
      },
    ],
  });
  const b = await reconnect("sbx-1", "cold-b");
  await processSandboxOutboxBatch(clock);
  expect(operation(b.id).state).toBe("DISPATCHED");
  expect(
    await applyOperationResult(
      {
        sender: { userId: "user-1", hostId: "host-1", connectionEpoch: 1 },
        operationId: b.id,
        sandboxId: "sbx-1",
        generation: b.generation,
        attempt: operation(b.id).dispatchAttempt,
        state: "failed",
        error: { code: "host_capacity", message: "host live sandbox capacity reached" },
      },
      clock,
    ),
  ).toEqual({ written: true });
  expect(operation("cold-a").state).toBe("UNKNOWN_OUTCOME");
  expect(store.sandboxes.get("sbx-1")?.liveResourcesHeld).toBe(true);
});

it("C12 regression absent STOP settles predecessors and releases sandbox flag", async () => {
  const id = await ready();
  const receipt = await stopSandbox(owner, { id, idempotencyKey: "stop-absent" });
  const opId = receipt.operationId;
  await processSandboxOutboxBatch(clock);
  expect(await result(operation(opId), "succeeded", false, 1, { state: "absent" })).toEqual({
    written: true,
  });
  expect(store.sandboxes.get(id)?.state).toBe("STOPPED");
  expect(store.sandboxes.get(id)?.liveResourcesHeld).toBe(false);
});

it("C12 regression harness must model reservation decrement numerically", async () => {
  await stopped();
  expect(store.hosts.get("host-1")?.liveCount).toBe(0);
});

it("C12 regression confirmed kill settles unknown predecessor and frees reusable slot", async () => {
  const { killSandbox } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
  pinnedReadyFixture();
  store.operations.set("old-unknown", {
    id: "old-unknown",
    userId: "user-1",
    sandboxId: "sbx-1",
    kind: "RUN_COMMAND",
    state: "UNKNOWN_OUTCOME",
    generation: 1,
    dispatchAttempt: 1,
    dispatchedHostId: "host-1",
    dispatchedConnectionEpoch: 1,
    idempotencyKey: "old-unknown",
  });
  await killSandbox(owner, { id: "sbx-1", idempotencyKey: "kill" });
  const killing = operations("KILL_SANDBOX")[0]!;
  await processSandboxOutboxBatch(clock);
  expect(await result(operation(killing.id), "succeeded", false, 1, { state: "deleted" })).toEqual({
    written: true,
  });
  expect(operation("old-unknown").state).toBe("CANCELLED");
  expect(store.sandboxes.get("sbx-1")?.liveResourcesHeld).toBe(false);
  expect(store.hosts.get("host-1")?.liveCount).toBe(0);
  await create("next-create");
  expect(store.hosts.get("host-1")?.liveCount).toBe(1);
});

it("C12 regression cold reconnect reserves again after confirmed stop", async () => {
  const id = await stopped();
  expect(store.hosts.get("host-1")?.liveCount).toBe(0);
  await reconnect(id);
  expect(store.sandboxes.get(id)?.liveResourcesHeld).toBe(true);
  expect(store.hosts.get("host-1")?.liveCount).toBe(1);
});

it.each(["snapshot.create", "invalid.dispatch", "sandbox.kill"])(
  "C12 undispatched create rejected as %s releases its reservation",
  async (kind) => {
    const created = await create();
    const event = [...store.outbox.values()][0]!;
    event.payload.kind = kind;
    await processSandboxOutboxBatch(clock);
    expect(operation(created.op.id)).toMatchObject({
      state: "FAILED",
      errorCode: kind === "snapshot.create" ? "unsupported_capability" : "protocol_error",
    });
    expect(store.sandboxes.get(created.id)?.liveResourcesHeld).toBe(false);
    expect(store.hosts.get("host-1")?.liveCount).toBe(0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  },
);

it("C12 dispatched invalid work retains uncertainty and its reservation", async () => {
  const created = await create();
  await processSandboxOutboxBatch(clock);
  const event = [...store.outbox.values()][0]!;
  event.sentAt = null;
  event.claimToken = null;
  event.payload.kind = "invalid.dispatch";
  event.payload.dispatchAttempt = operation(created.op.id).dispatchAttempt;
  await processSandboxOutboxBatch(clock);
  expect(operation(created.op.id).state).toBe("UNKNOWN_OUTCOME");
  expect(store.sandboxes.get(created.id)?.liveResourcesHeld).toBe(true);
});

it.each(["delete-first", "create-first"])(
  "C12 host delete vs create serializes: %s",
  async (order) => {
    const { deleteHost } = await import("../../../../packages/api/src/sandbox/services/hosts");
    const barrier = pause("beforeCommit");
    const first = order === "delete-first" ? deleteHost(owner, { id: "host-1" }) : create("racing");
    await barrier.entered;
    const waiting = nextHostWait();
    const second =
      order === "delete-first" ? create("racing") : deleteHost(owner, { id: "host-1" });
    const outcomes = Promise.allSettled([first, second]);
    await waiting;
    expect(store.hosts.has("host-1")).toBe(true);
    expect(store.sandboxes.size).toBe(0);
    barrier.resume();
    expect((await outcomes).map((value) => value.status)).toEqual(
      order === "delete-first" ? ["fulfilled", "rejected"] : ["fulfilled", "fulfilled"],
    );
    expect(store.hosts.has("host-1")).toBe(order === "create-first");
    expect(store.sandboxes.size).toBe(order === "create-first" ? 1 : 0);
    for (const row of store.sandboxes.values()) expect(row.sandboxHostId).toBe("host-1");
  },
);

it.each(["STOPPED", "ERROR"])(
  "C12 host delete preserves %s placement with Restrict",
  async (state) => {
    const { deleteHost } = await import("../../../../packages/api/src/sandbox/services/hosts");
    setup({
      sandboxes: [{ id: "sbx", userId: "user-1", sandboxHostId: "host-1", generation: 1, state }],
    });
    await expect(deleteHost(owner, { id: "host-1" })).resolves.toEqual({ ok: true, pending: true });
    expect(store.hosts.has("host-1")).toBe(true);
    expect(store.hosts.get("host-1")?.deletionRequestedAt).toEqual(expect.any(Date));
    // Even a bypass of the service guard is prohibited by the declared FK.
    const schema = readFileSync(
      new URL("../../../../packages/db/prisma/schema/sandbox.prisma", import.meta.url),
      "utf8",
    );
    expect(schema).toMatch(
      /SandboxHost\s+SandboxHost\?\s+@relation\(fields: \[sandboxHostId, hostOwnerId\], references: \[id, userId\], onDelete: Restrict/,
    );
    await expect(
      db.$transaction((tx) => tx.sandboxHost.deleteMany({ where: { id: "host-1" } })),
    ).rejects.toMatchObject({ code: "P2003" });
  },
);

it("local budget shrink blocks new admission while retained live holds drain", async () => {
  const id = await ready();
  store.hosts.get("host-1")!.daemonMemoryBudgetMiB = 1536;
  await expect(create("after-shrink")).rejects.toMatchObject({
    data: { code: "sandbox.host_capacity", reason: "ram" },
  });
  expect(store.sandboxes.get(id)?.liveResourcesHeld).toBe(true);
});

it("C12 confirmed cleanup proves earlier expired effects dead on subsequent cold failure", async () => {
  // A confirmed stop may retain an existing disk after an uncertain resume;
  // uncertain fresh creates are destroyed and cannot be resumed cold.
  const id = await stopped();
  const op = await reconnect(id);
  await processSandboxOutboxBatch(clock);
  tick(1000);
  await result(operation(op.id), "unknown_outcome");
  await processSandboxOutboxBatch(clock);
  await result(operation(expiryOperations(id)[0]!.id));
  expect(store.hosts.get("host-1")?.liveCount).toBe(0);
  const cold = await reconnect(id);
  await processSandboxOutboxBatch(clock);
  await result(operation(cold.id), "failed");
  expect(store.hosts.get("host-1")?.liveCount).toBe(0);
});

it("C12 warm dispatch waits for renewal H and reads the committed deadline", async () => {
  pinnedReadyFixture();
  const op = await reconnect("sbx-1");
  const barrier = pause("beforeOperationWrite");
  const renewal = setSandboxTimeout(
    owner,
    {
      id: "sbx-1",
      timeoutMs: 30_000,
      idempotencyKey: "renew-first",
    },
    clock,
  );
  await barrier.entered;
  const waiting = nextHostWait();
  const dispatch = processSandboxOutboxBatch(clock);
  await waiting;
  tick(11_000);
  barrier.resume();
  await Promise.all([renewal, dispatch]);
  expect(operation(op.id).state).toBe("DISPATCHED");
  expect(store.sandboxes.get("sbx-1")?.leaseRevision).toBe(3);
  expect(await result(operation(op.id))).toEqual({ written: true });
});

it("C12 stop needs stopped/absent evidence before settlement or release", async () => {
  const id = await ready();
  await stopSandbox(owner, { id, idempotencyKey: "stop-proof" });
  await processSandboxOutboxBatch(clock);
  const stopping = operations("STOP_SANDBOX")[0]!;
  for (const payload of [{}, { state: "ready" }]) {
    expect(await result(operation(stopping.id), "succeeded", false, 1, payload)).toEqual({
      written: false,
    });
    expect(store.hosts.get("host-1")?.liveCount).toBe(1);
  }
  expect(await result(operation(stopping.id))).toEqual({ written: true });
  expect(await result(operation(stopping.id))).toEqual({ written: false });
  expect(store.hosts.get("host-1")?.liveCount).toBe(0);
});

it("C12 failed replacement retains the slot when queued supersession settles unknown", async () => {
  const id = await stopped();
  const older = await reconnect(id, "older-queued");
  const newer = await reconnect(id, "newer");
  await processSandboxOutboxBatch(clock);
  expect(operation(older.id).dispatchAttempt).toBe(0);
  await result(operation(newer.id), "failed");
  expect(operation(older.id).state).toBe("UNKNOWN_OUTCOME");
  expect(store.sandboxes.get(id)?.liveResourcesHeld).toBe(true);
  expect(store.hosts.get("host-1")?.liveCount).toBe(1);
});

it.each(["kill", "absent stop"])(
  "C12 Fix2 create → %s → deleteHost releases placement and retains history",
  async (cleanup) => {
    const { deleteHost } = await import("../../../../packages/api/src/sandbox/services/hosts");
    const id = await ready();
    const receipt = await (cleanup === "kill" ? killSandbox : stopSandbox)(owner, {
      id,
      idempotencyKey: "delete-cleanup",
    });
    const opId =
      cleanup === "kill"
        ? operations("KILL_SANDBOX")[0]!.id
        : "operationId" in receipt
          ? receipt.operationId
          : receipt.id;
    await processSandboxOutboxBatch(clock);
    expect(
      await result(operation(opId), "succeeded", false, 1, {
        state: cleanup === "kill" ? "deleted" : "absent",
      }),
    ).toEqual({ written: true });
    if (cleanup !== "kill") {
      expect(store.sandboxes.get(id)).toMatchObject({
        state: "STOPPED",
        diskReservationHeld: true,
      });
      await killSandbox(owner, { id, idempotencyKey: "kill-retained-root" });
      await processSandboxOutboxBatch(clock);
      expect(await result(operations("KILL_SANDBOX")[0]!)).toEqual({ written: true });
    }
    expect(store.sandboxes.get(id)).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      liveResourcesHeld: false,
    });
    expect(store.hosts.get("host-1")?.liveCount).toBe(0);
    await expect(deleteHost(owner, { id: "host-1" })).resolves.toEqual({
      ok: true,
      pending: false,
    });
    expect(store.hosts.has("host-1")).toBe(false);
    expect(store.sandboxes.get(id)?.originHostId).toBe("host-1");
    db.sdkKey.findUnique.mockResolvedValue({
      id: "history-key",
      userId: "user-1",
      resourceMode: "ALL_OWNED",
      scopes: ["sandboxes:read"],
      revokedAt: null,
      expiresAt: null,
      HostAllowlist: [],
      RevisionAllowlist: [],
      User: {
        banned: false,
        banExpires: null,
        twoFactorEnabled: true,
        role: "user",
        createdAt: new Date("2020-01-01"),
      },
    } as never);
    db.appSetting.findMany.mockResolvedValue([]);
    db.sandboxTemplate.findFirst.mockResolvedValue({ id: "tpl-1" } as never);
    const { getSandbox } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
    await expect(
      getSandbox(
        {
          kind: "sdkKey",
          expiresAt: null,
          keyId: "history-key",
          ownerId: "user-1",
          resourceMode: "ALL_OWNED",
          scopes: new Set(["sandboxes:read"]),
          allowedHostIds: "allOwned",
          allowedRevisionIds: "allOwned",
          allowedPoolIds: "allUsable",
        },
        { id },
      ),
    ).resolves.toMatchObject({ state: "DELETED", sandboxHostId: null });
    expect(operation(opId)).toMatchObject({
      sandboxId: id,
      state: "SUCCEEDED",
      dispatchedHostId: "host-1",
    });
    expect(store.sandboxes.has(id)).toBe(true);
  },
);

it("C12 Fix2 actual stopped disk still conflicts with host deletion", async () => {
  const { deleteHost } = await import("../../../../packages/api/src/sandbox/services/hosts");
  const id = await stopped();
  expect(store.sandboxes.get(id)).toMatchObject({
    state: "STOPPED",
    sandboxHostId: "host-1",
    liveResourcesHeld: false,
  });
  expect(store.hosts.get("host-1")?.liveCount).toBe(0);
  await expect(deleteHost(owner, { id: "host-1" })).resolves.toEqual({ ok: true, pending: true });
});

const retainedCleanupCases = JSON.parse(
  readFileSync(
    new URL("../../../../crates/sandbox-protocol/fixtures/cleanup_retention.json", import.meta.url),
    "utf8",
  ),
) as { kind: string; retained: Record<string, unknown> }[];
it.each(retainedCleanupCases)(
  "C12 Fix2 accepts journal-pruned $kind evidence and releases on exact receipt",
  async ({ kind, retained }) => {
    const id = await ready();
    const receipt = await (kind === "sandbox.kill" ? killSandbox : stopSandbox)(owner, {
      id,
      idempotencyKey: "pruned-cleanup",
    });
    const opId =
      kind === "sandbox.kill"
        ? operations("KILL_SANDBOX")[0]!.id
        : "operationId" in receipt
          ? receipt.operationId
          : receipt.id;
    await processSandboxOutboxBatch(clock);
    await replaceHostEpoch();
    expect(await result(operation(opId), "succeeded", true, 2, retained)).toEqual({
      written: true,
    });
    expect(operation(opId).result).toEqual(retained);
    expect(store.sandboxes.get(id)).toMatchObject({
      state: kind === "sandbox.stop" ? "STOPPED" : "DELETED",
      liveResourcesHeld: false,
      sandboxHostId: kind === "sandbox.stop" ? "host-1" : null,
    });
    expect(store.hosts.get("host-1")?.liveCount).toBe(0);
    expect(await result(operation(opId), "succeeded", true, 2, retained)).toEqual({
      written: false,
    });
    expect(store.hosts.get("host-1")?.liveCount).toBe(0);
  },
);

it.each(["kill", "stop"])(
  "C12 Fix2 confirmed %s permits cleanup-bound retirement of old UNKNOWN allocation",
  async (cleanup) => {
    const id = await ready();
    const op = await reconnect(id);
    await processSandboxOutboxBatch(clock);
    expect(await result(operation(op.id), "unknown_outcome")).toEqual({
      written: true,
      allocationUnknown: true,
    });
    const input = {
      sender: { userId: owner.ownerId, hostId: "host-1", connectionEpoch: 1 },
      operationId: op.id,
      sandboxId: id,
      generation: op.generation,
      attempt: operation(op.id).dispatchAttempt,
      state: "unknown_outcome",
      written: false,
      receipt: {
        bodyHash: String(op.requestBodyHash),
        idempotencyKey: String(op.idempotencyKey),
        kind: "sandbox.reconnect",
      },
    };
    expect(await confirmOperationReceipt(input)).toBeNull();
    await (cleanup === "kill" ? killSandbox : stopSandbox)(owner, { id, idempotencyKey: "settle" });
    const later = operations(cleanup === "kill" ? "KILL_SANDBOX" : "STOP_SANDBOX")[0]!;
    await processSandboxOutboxBatch(clock);
    expect(await result(operation(later.id))).toEqual({ written: true });
    expect(operation(op.id).state).toBe("CANCELLED");
    const confirmed = await confirmOperationReceipt(input);
    expect(confirmed).toMatchObject({
      type: "receipt.confirmed",
      operationId: op.id,
      cleanupGeneration: later.generation,
    });
    for (const field of ["bodyHash", "idempotencyKey", "kind"] as const) {
      expect(
        await confirmOperationReceipt({
          ...input,
          receipt: { ...input.receipt, [field]: "foreign" },
        }),
      ).toBeNull();
    }
    for (const change of [
      { dispatchedHostId: "other-host" },
      { dispatchedConnectionEpoch: 2 },
      { sandboxId: "other-sandbox" },
      { state: "FAILED" },
      { result: { outputExpired: true } },
      { generation: op.generation },
    ]) {
      const original = structuredClone(operation(later.id));
      Object.assign(operation(later.id), change);
      expect(await confirmOperationReceipt(input)).not.toHaveProperty("cleanupGeneration");
      store.operations.set(later.id, original);
    }
  },
);

it("C12 Fix2 deleted placement, capacity and result roll back together before re-entry", async () => {
  const id = await ready();
  await killSandbox(owner, { id, idempotencyKey: "atomic-delete" });
  await processSandboxOutboxBatch(clock);
  const killing = operations("KILL_SANDBOX")[0]!;
  store.barriers.beforeCommit = async () => {
    throw new Error("injected commit failure");
  };
  await expect(result(operation(killing.id))).rejects.toThrow("An internal error occurred.");
  expect(store.sandboxes.get(id)).toMatchObject({
    state: "STOPPING",
    sandboxHostId: "host-1",
    liveResourcesHeld: true,
  });
  expect(store.hosts.get("host-1")?.liveCount).toBe(1);
  expect(operation(killing.id).state).toBe("DISPATCHED");
  store.barriers.beforeCommit = undefined;
  expect(await result(operation(killing.id))).toEqual({ written: true });
  expect(store.sandboxes.get(id)).toMatchObject({
    state: "DELETED",
    sandboxHostId: null,
    liveResourcesHeld: false,
  });
});

it("C12 Fix2 cleanup also retires host UNKNOWN when the server predecessor is lease-expired FAILED", async () => {
  const id = await stopped();
  const op = await reconnect(id);
  await processSandboxOutboxBatch(clock);
  tick(1000);
  await result(operation(op.id), "unknown_outcome");
  expect(operation(op.id)).toMatchObject({ state: "FAILED", errorCode: "lease_expired" });
  const input = {
    sender: { userId: owner.ownerId, hostId: "host-1", connectionEpoch: 1 },
    operationId: op.id,
    sandboxId: id,
    generation: op.generation,
    attempt: operation(op.id).dispatchAttempt,
    state: "unknown_outcome",
    written: false,
    receipt: {
      bodyHash: String(op.requestBodyHash),
      idempotencyKey: String(op.idempotencyKey),
      kind: "sandbox.reconnect",
    },
  };
  expect(await confirmOperationReceipt(input)).not.toHaveProperty("cleanupGeneration");
  await processSandboxOutboxBatch(clock);
  const cleanup = operation(expiryOperations(id)[0]!.id);
  expect(await result(cleanup)).toEqual({ written: true });
  expect(await confirmOperationReceipt(input)).toMatchObject({
    type: "receipt.confirmed",
    cleanupGeneration: cleanup.generation,
  });
});

it.each(["CREATE_SANDBOX", "RECONNECT_SANDBOX"])(
  "C14 readiness failure durably queues cleanup for %s before any READY",
  async (kind) => {
    setup();
    const op =
      kind === "CREATE_SANDBOX"
        ? (await create("readiness", "stop", 60_000)).op
        : await reconnect(await stopped());
    await processSandboxOutboxBatch();
    const current = operation(op.id);
    const applied = await applyOperationResult(
      {
        sender: { userId: "user-1", hostId: "host-1", connectionEpoch: 1 },
        operationId: current.id,
        sandboxId: current.sandboxId,
        generation: current.generation,
        attempt: current.dispatchAttempt,
        state: "unknown_outcome",
        error: { code: "guest_unavailable", message: "missing guest user", reason: "guest_home" },
      },
      clock,
    );
    expect(applied.written).toBe(true);
    const sbx = store.sandboxes.get(current.sandboxId)!;
    expect(sbx.lastErrorDetail).toBe(
      "Sandbox guest readiness failed (guest_home: the guest user's HOME is missing, not writable or wrongly owned); cleanup queued.",
    );
    expect(operation(current.id).errorDetail).toBe(sbx.lastErrorDetail);
    // The `/v1` operation's readinessReason comes from this label-only record.
    expect(operation(current.id).failure).toEqual({ readinessReason: "guest_home" });
    expect(sbx.state).toBe("STOPPING");
    expect(sbx.liveResourcesHeld).toBe(true);
    expect(sbx.generation).toBe(current.generation + 1);
    expect(operation(current.id)).toMatchObject({
      state: "FAILED",
      errorCode: "guest_unavailable",
    });
    const cleanup = operations("KILL_SANDBOX")[0]!;
    expect(cleanup).toMatchObject({ state: "QUEUED", generation: sbx.generation });
    expect(cleanup.idempotencyKey).toBe(`readiness-failed:${sbx.id}:${sbx.generation}`);
    expect(
      [...store.outbox.values()].some((event) => event.payload.operationId === cleanup.id),
    ).toBe(true);
    expect(await result(current)).toEqual({ written: false });
    await processSandboxOutboxBatch();
    await result(operation(cleanup.id));
    expect(store.sandboxes.get(sbx.id)!.state).toBe("DELETED");
    expect(store.sandboxes.get(sbx.id)!.liveResourcesHeld).toBe(false);
  },
);

it("E1-A-01 a create whose guest got no network fails typed and is destroyed, never READY", async () => {
  setup();
  const { op } = await create("no-network", "stop", 60_000);
  await processSandboxOutboxBatch();
  const current = operation(op.id);
  const applied = await applyOperationResult(
    {
      sender: { userId: "user-1", hostId: "host-1", connectionEpoch: 1 },
      operationId: current.id,
      sandboxId: current.sandboxId,
      generation: current.generation,
      attempt: current.dispatchAttempt,
      state: "failed",
      error: { code: "guest_network_unavailable", message: "no IPv4 default route" },
    },
    clock,
  );
  expect(applied.written).toBe(true);
  expect(operation(current.id)).toMatchObject({
    state: "FAILED",
    errorCode: "guest_network_unavailable",
  });
  const sbx = store.sandboxes.get(current.sandboxId)!;
  expect(sbx.state).not.toBe("READY");
  const cleanup = operations("KILL_SANDBOX")[0]!;
  expect(cleanup).toMatchObject({ state: "QUEUED", generation: sbx.generation });
  await processSandboxOutboxBatch();
  await result(operation(cleanup.id));
  expect(store.sandboxes.get(sbx.id)!.state).toBe("DELETED");
});

it.each(["CREATE_SANDBOX", "RECONNECT_SANDBOX"])(
  "conflicting binding (%s) retains holds; only uncertain creates queue fenced teardown",
  async (kind) => {
    setup();
    const op =
      kind === "CREATE_SANDBOX"
        ? (await create("conflict", "stop", 60_000)).op
        : await reconnect(await stopped());
    await processSandboxOutboxBatch();
    const current = operation(op.id);
    const applied = await applyOperationResult(
      {
        sender: { userId: "user-1", hostId: "host-1", connectionEpoch: 1 },
        operationId: current.id,
        sandboxId: current.sandboxId,
        generation: current.generation,
        attempt: current.dispatchAttempt,
        state: "unknown_outcome",
        error: {
          code: "idempotency_conflict",
          message: "instance belongs to another sandbox",
        },
      },
      clock,
    );
    expect(applied.written).toBe(true);
    // A create always converges through the host's full binding-fenced kill;
    // this queues no execution authority over a foreign VM. A reconnect has
    // a retained guest and keeps its existing inconclusive behavior.
    const createCleanup = kind === "CREATE_SANDBOX";
    expect(operations("KILL_SANDBOX")).toHaveLength(createCleanup ? 1 : 0);
    const sbx = store.sandboxes.get(current.sandboxId)!;
    expect(sbx.liveResourcesHeld).toBe(true);
    expect(sbx.state === "STOPPING").toBe(createCleanup);
    expect(sbx.generation).toBe(current.generation + (createCleanup ? 1 : 0));
    expect(operation(current.id)).toMatchObject({
      state: createCleanup ? "FAILED" : "UNKNOWN_OUTCOME",
      errorCode: "idempotency_conflict",
    });
  },
);

it.each([false, true])(
  "C-26 create refusal releases only FAILED; UNKNOWN keeps all capacity (imageMissing=%s)",
  async (imageMissing) => {
    for (const state of ["failed", "unknown_outcome"] as const) {
      setup();
      const { op } = await create("create-refusal", "stop", 60_000);
      await processSandboxOutboxBatch();
      const current = operation(op.id);
      const sandbox = store.sandboxes.get(current.sandboxId)!;
      const host = store.hosts.get("host-1")!;
      const { liveCount, memoryReservedMiB } = host;
      const memoryMiB = store.placements.get(String(sandbox.currentPlacementId))!.chargedMemoryMiB;
      if (
        typeof liveCount !== "number" ||
        typeof memoryReservedMiB !== "number" ||
        typeof memoryMiB !== "number"
      ) {
        throw new Error("expected numeric reservation counters and sandbox memory");
      }
      const reserved = { liveCount, memoryReservedMiB };
      expect(sandbox.liveResourcesHeld).toBe(true);
      expect(reserved.liveCount).toBeGreaterThan(0);
      expect(reserved.memoryReservedMiB).toBeGreaterThanOrEqual(memoryMiB);
      const code = imageMissing ? "not_found" : "state_conflict";
      expect(
        await applyOperationResult(
          {
            sender: { userId: "user-1", hostId: "host-1", connectionEpoch: 1 },
            operationId: current.id,
            sandboxId: current.sandboxId,
            generation: current.generation,
            attempt: current.dispatchAttempt,
            state,
            error: { code, message: code },
            ...(imageMissing
              ? {
                  result: {
                    imageMissing: {
                      templateRevisionId: "tpl-1",
                      artifact: store.templates.get("tpl-1")!.incusFingerprint,
                      architecture: "x86_64",
                      connectionEpoch: 1,
                    },
                  },
                }
              : {}),
          },
          clock,
        ),
      ).toEqual({ written: true });
      expect(operation(current.id).state).toBe("FAILED");
      expect(store.sandboxes.get(current.sandboxId)!.liveResourcesHeld).toBe(
        state === "unknown_outcome",
      );
      expect(store.hosts.get("host-1")).toMatchObject(
        state === "unknown_outcome"
          ? reserved
          : {
              liveCount: reserved.liveCount - 1,
              memoryReservedMiB: reserved.memoryReservedMiB - memoryMiB,
            },
      );
      expect(operations("KILL_SANDBOX")).toHaveLength(state === "unknown_outcome" ? 1 : 0);
    }
  },
);

it.each([false, true])(
  "C-26 reconnect refusal retains UNKNOWN capacity (warm=%s)",
  async (warm) => {
    for (const state of ["failed", "unknown_outcome"] as const) {
      setup();
      const id = warm ? await ready() : await stopped();
      const queued = await reconnect(id);
      await processSandboxOutboxBatch();
      const current = operation(queued.id);
      const sandbox = store.sandboxes.get(id)!;
      const memoryMiB = store.placements.get(String(sandbox.currentPlacementId))!.chargedMemoryMiB;
      const host = store.hosts.get("host-1")!;
      const reserved = {
        liveCount: host.liveCount,
        memoryReservedMiB: host.memoryReservedMiB,
      };
      expect(reserved.liveCount).toBe(1);
      expect(reserved.memoryReservedMiB).toBe(memoryMiB);
      expect(
        await applyOperationResult(
          {
            sender: { userId: "user-1", hostId: "host-1", connectionEpoch: 1 },
            operationId: current.id,
            sandboxId: id,
            generation: current.generation,
            attempt: current.dispatchAttempt,
            state,
            error: { code: "state_conflict", message: "lease refused" },
          },
          clock,
        ),
      ).toEqual({
        written: true,
        ...(state === "unknown_outcome" ? { allocationUnknown: true } : {}),
      });
      const retained = warm || state === "unknown_outcome";
      expect(store.sandboxes.get(id)!.liveResourcesHeld).toBe(retained);
      expect(store.hosts.get("host-1")).toMatchObject(
        retained
          ? reserved
          : {
              liveCount: 0,
              memoryReservedMiB: 0,
              vcpuReserved: 0,
              rootCount: 1,
              daemonVcpuBudget: 64,
            },
      );
    }
  },
);

it("logical archive prevents subsequent admission and retains the immutable revision (real race: direct-placement.pg.test.ts)", async () => {
  const { retireTemplate } = await import(
    "../../../../packages/api/src/sandbox/services/templates"
  );
  await retireTemplate(owner, { id: "tpl-1" });
  // The double stores the logical projection together; PostgreSQL proves the join.
  store.templates.get("tpl-1")!.Template = { archivedAt: new Date() };
  await expect(create("retired")).rejects.toMatchObject({ code: "NOT_FOUND" });
  expect(store.sandboxes.size).toBe(0);
});

it.each([false, true])(
  "C14 empty host with unused/retired template is deletable (retired=%s)",
  async (retired) => {
    const { deleteHost } = await import("../../../../packages/api/src/sandbox/services/hosts");
    const { retireTemplate } = await import(
      "../../../../packages/api/src/sandbox/services/templates"
    );
    if (retired) await retireTemplate(owner, { id: "tpl-1" });
    await expect(deleteHost(owner, { id: "host-1" })).resolves.toEqual({
      ok: true,
      pending: false,
    });
    expect(store.hosts.has("host-1")).toBe(false);
    expect(store.templates.get("tpl-1")).toMatchObject({
      retiredAt: null,
    });
  },
);

describe("unit (fenced harness; real-DB: host-tombstone.pg.test.ts) — C21-HOSTTOMB / C21-HOSTFINALIZE tombstoned host cleanup", () => {
  async function tombstone() {
    const { deleteHost } = await import("../../../../packages/api/src/sandbox/services/hosts");
    await expect(deleteHost(owner, { id: "host-1" })).resolves.toEqual({ ok: true, pending: true });
    expect(store.hosts.get("host-1")?.deletionRequestedAt).toEqual(expect.any(Date));
  }

  it("C21-HOSTTOMB owner stop/kill enqueue succeeds on a tombstoned host; create is CONFLICT", async () => {
    const a = await ready("create-a");
    const b = await ready("create-b");
    await tombstone();
    const stop = await stopSandbox(owner, { id: a, idempotencyKey: "tomb-stop" });
    expect(operation(stop.operationId)).toMatchObject({ kind: "STOP_SANDBOX", state: "QUEUED" });
    const kill = await killSandbox(owner, { id: b, idempotencyKey: "tomb-kill" });
    expect(kill.state).toBe("STOPPING");
    const renewed = await setSandboxTimeout(
      owner,
      { id: a, idempotencyKey: "tomb-renew", timeoutMs: 60_000 },
      clock,
    ).catch((error: unknown) => error);
    // Renewal is lease work, never tombstone-rejected (STOPPING is simply not renewable).
    expect(renewed).not.toMatchObject({ message: "Sandbox host is pending deletion." });
    await expect(create("after-tombstone")).rejects.toMatchObject({
      code: "CONFLICT",
      message: "Host cannot be deleted in its current state.",
    });
  });

  it("C21-HOSTFINALIZE KILL from STOPPED (no live slot) finalizes the host in the same transaction", async () => {
    const id = await stopped();
    expect(store.sandboxes.get(id)).toMatchObject({ liveResourcesHeld: false, state: "STOPPED" });
    await tombstone();
    await killSandbox(owner, { id, idempotencyKey: "kill-stopped" });
    await processSandboxOutboxBatch(clock);
    const kill = operations("KILL_SANDBOX")[0]!;
    // Same transaction: a failed commit leaves both the placement and the host.
    store.barriers.beforeCommit = async () => {
      throw new Error("injected commit failure");
    };
    await expect(result(operation(kill.id))).rejects.toThrow("An internal error occurred.");
    expect(store.hosts.has("host-1")).toBe(true);
    expect(store.sandboxes.get(id)).toMatchObject({ sandboxHostId: "host-1" });
    store.barriers.beforeCommit = undefined;
    expect(await result(operation(kill.id))).toEqual({ written: true });
    expect(store.sandboxes.get(id)).toMatchObject({ state: "DELETED", sandboxHostId: null });
    expect(store.hosts.has("host-1")).toBe(false);
    expect(store.templates.get("tpl-1")).toBeDefined();
  });

  it("C21-HOSTFINALIZE KILL from a held slot finalizes after the detach", async () => {
    const id = await ready();
    expect(store.sandboxes.get(id)?.liveResourcesHeld).toBe(true);
    await tombstone();
    await killSandbox(owner, { id, idempotencyKey: "kill-held" });
    await processSandboxOutboxBatch(clock);
    const kill = operations("KILL_SANDBOX")[0]!;
    expect(await result(operation(kill.id))).toEqual({ written: true });
    expect(store.sandboxes.get(id)).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      liveResourcesHeld: false,
    });
    expect(store.hosts.has("host-1")).toBe(false);
  });

  it("C21-HOSTFINALIZE a non-last release leaves the tombstoned host in place", async () => {
    const a = await ready("create-a");
    await ready("create-b");
    await tombstone();
    await killSandbox(owner, { id: a, idempotencyKey: "kill-a" });
    await processSandboxOutboxBatch(clock);
    expect(await result(operation(operations("KILL_SANDBOX")[0]!.id))).toEqual({ written: true });
    expect(store.hosts.has("host-1")).toBe(true);
    expect(store.hosts.get("host-1")?.liveCount).toBe(1);
  });

  it("3E logical retirement is independent of host finalization", async () => {
    const { retireTemplate } = await import(
      "../../../../packages/api/src/sandbox/services/templates"
    );
    setup({
      hosts: [
        {
          id: "host-1",
          userId: "user-1",
          connectionEpoch: 1,
          deletionRequestedAt: new Date("2026-01-01T00:00:00Z"),
        },
      ],
    });
    await expect(retireTemplate(owner, { id: "tpl-1" })).resolves.toEqual({ ok: true });
    expect(store.templates.get("tpl-1")).toBeDefined();
    expect(store.hosts.has("host-1")).toBe(true);
  });
});

describe("unit (fenced harness; real-DB coverage named per test) — C21-ACCTDEL-RACE owner lock precedes every owner-row insert", () => {
  const OWNER_LOCK = 'sql:SELECT id FROM "user" WHERE id = ? FOR SHARE';
  function lockedBefore(insert: string) {
    const lock = store.trace.indexOf(OWNER_LOCK);
    const created = store.trace.indexOf(insert);
    expect(lock).toBeGreaterThanOrEqual(0);
    expect(created).toBeGreaterThan(lock);
  }

  it("sandbox create takes the owner lock before the sandbox, operation and outbox inserts (real-DB: admission-lock.pg.test.ts)", async () => {
    await create("lock-order");
    lockedBefore("create:sandboxes");
    lockedBefore("create:operations");
    lockedBefore("create:outbox");
  });

  it("lifecycle enqueue (stop) takes the owner lock before its operation/outbox inserts (real-DB: admission-lock.pg.test.ts)", async () => {
    const id = await ready();
    store.trace.length = 0;
    await stopSandbox(owner, { id, idempotencyKey: "lock-stop" });
    lockedBefore("create:operations");
    lockedBefore("create:outbox");
  });

  it("kill takes the owner lock before its operation/outbox inserts (real-DB: admission-lock.pg.test.ts)", async () => {
    const id = await ready();
    store.trace.length = 0;
    await killSandbox(owner, { id, idempotencyKey: "lock-kill" });
    lockedBefore("create:operations");
    lockedBefore("create:outbox");
  });
});

it("C31 offline renewal dispatches its immutable lease and only ACK changes effective lifetime", async () => {
  const id = await ready();
  const effective = store.sandboxes.get(id)?.leaseExpiresAtEffective;
  vi.mocked(manager.isHostConnected).mockReturnValue(false);
  await setSandboxTimeout(owner, { id, idempotencyKey: "renew-wire", timeoutMs: 5000 }, clock);
  const op = operations("RENEW_SANDBOX_LEASE")[0]!;
  expect(op.state).toBe("QUEUED");
  expect(await processSandboxOutboxBatch(clock)).toBe(0);
  expect(store.sandboxes.get(id)?.leaseExpiresAtEffective).toEqual(effective);
  vi.mocked(manager.isHostConnected).mockReturnValue(true);
  await processSandboxOutboxBatch(clock);
  const lease = {
    revision: 2,
    deadlineUnixMs: deadline(5000).getTime(),
    action: "stop",
    expiryPolicy: "retry-force-60s",
  };
  expect(manager.dispatchOperation).toHaveBeenLastCalledWith(
    "host-1",
    expect.objectContaining({ kind: "sandbox.lease.renew", lease }),
  );
  expect(operation(op.id).state).toBe("DISPATCHED");
  expect(
    await applyOperationResult(
      {
        sender: { userId: owner.ownerId, hostId: "host-1", connectionEpoch: 1 },
        operationId: op.id,
        sandboxId: id,
        generation: op.generation,
        attempt: operation(op.id).dispatchAttempt,
        state: "succeeded",
        result: { lease },
      },
      clock,
    ),
  ).toEqual({ written: true });
  expect(store.sandboxes.get(id)).toMatchObject({
    leaseRevisionEffective: 2,
    leaseExpireActionEffective: "STOP",
    leaseExpiresAtEffective: deadline(5000),
  });
});
