// Real-PostgreSQL proofs for reconnect adoption (`adoptOperation`): the
// dispatch-equivalent gates, exactly-one-winner races against kill, sharing
// stop, lease expiry and the inactive-key attempt+1 claim, control and stdin
// re-arming, allocation lineage, and the session-level frame rules.
import {
  seedAcceptedOperation,
  seedDispatchEvent,
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { commandResultFixture } from "./command-result-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("../../../../packages/api/src/lib/procedure-budget", () => ({
  createProcedureBudget: () => async () => {},
}));

import { randomBytes, randomUUID } from "node:crypto";
import type { OperationState, SandboxOperationKind, SandboxState } from "@wssp/db";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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

const db = await pgTestDatabase();
const handlers = await import("./operation-handlers.js");
const {
  adoptOperation,
  listUnacknowledgedDispatches,
  settleUndeliveredDispatch,
  applyOperationResult,
  acceptFencedBinaryChunk,
  applyProcessStarted,
  confirmOperationReceipt,
  finishHostReconciliation,
  FILE_PUT_REQUEUE_MAX_ATTEMPT,
} = handlers;
const { convergeInventoryEntry } = await import("./inventory-reconcile.js");
const { leasePolicyIdempotencyKey } = await import(
  "../../../../packages/api/src/sandbox/idempotency-key-reserved"
);
const waiters = await import("@wssp/api/sandbox/operation-waiters");
afterAll(() => db.close());
afterEach(() => waiters.bindOperationChangeFanout(null));

const JOURNAL = "1234567890abcdef1234567890abcdef";
const HASH = "a".repeat(64);
const OLD = 1;
const NOW = 3;

type SeedOptions = {
  kind?: SandboxOperationKind;
  state?: OperationState;
  errorCode?: string | null;
  sandboxState?: SandboxState;
  banned?: boolean;
  egress?: boolean;
  nextStdinSequence?: number;
  leaseExpiresAt?: Date | null;
  lineageJournal?: string | null;
  resultVersion?: number;
  /** RENEW_SANDBOX_LEASE only: the shorten-only flag on the stored lease. */
  shortenOnly?: boolean;
  /** The host negotiated lease policy (hello reported maxLeaseMs). */
};

const WIRE: Partial<Record<SandboxOperationKind, string>> = {
  RUN_COMMAND: "command.run",
  CREATE_SANDBOX: "sandbox.create",
  STOP_SANDBOX: "sandbox.stop",
  RENEW_SANDBOX_LEASE: "sandbox.lease.renew",
  PUT_FILE: "file.put",
};
const DEFAULT_STATE: Partial<Record<SandboxOperationKind, SandboxState>> = {
  RUN_COMMAND: "READY",
  CREATE_SANDBOX: "PROVISIONING",
  STOP_SANDBOX: "STOPPING",
  RENEW_SANDBOX_LEASE: "READY",
  PUT_FILE: "READY",
};

/** A host that dropped at epoch OLD and is now registered at epoch NOW (not
 * yet reconciled), with one operation dispatched on OLD. */
async function seed(options: SeedOptions = {}) {
  const kind = options.kind ?? "RUN_COMMAND";
  const wire = WIRE[kind]!;
  const userId = randomUUID();
  await db.inspect.user.create({
    data: {
      id: userId,
      name: "Owner",
      email: `${userId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
      ...(options.banned ? { banned: true } : {}),
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId,
      slug: "host",
      label: "Host",
      status: "CONNECTED",
      connectionEpoch: NOW,
      // The seeded sandbox holds one live reservation.
      liveCount: 1,
      egressEnforcement: options.egress ?? true,
      daemonLeasePolicy: true,
    },
  });
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: { daemonFeatures: { egressPolicy: true, terminal: true, journalId: JOURNAL } },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      slug: "image",
      label: "image",
      imageRef: "image",
      incusFingerprint: `sha256:${"b".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId,
      templateId: revision.id,
      sandboxHostId: host.id,
      originHostId: host.id,
      originPoolId: null,
      state: options.sandboxState ?? DEFAULT_STATE[kind]!,
      liveResourcesHeld: true,
      leaseExpiresAt: options.leaseExpiresAt ?? null,
    },
  });
  // The lease-policy pull-in: a system renewal under its reserved key.
  const leasePolicy = kind === "RENEW_SANDBOX_LEASE";
  const idempotencyKey = leasePolicy
    ? leasePolicyIdempotencyKey(sandbox.id, 1, 1)
    : `key-${randomUUID()}`;
  const operation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId,
      sandboxId: sandbox.id,
      kind,
      generation: 1,
      idempotencyKey,
      requestBodyHash: HASH,
      state: options.state ?? "DISPATCHED",
      errorCode: options.errorCode ?? null,
      dispatchAttempt: 1,
      acceptedAttempt: options.state === "DISPATCHED" || !options.state ? null : 1,
      dispatchedHostId: host.id,
      dispatchedConnectionEpoch: OLD,
      nextStdinSequence: options.nextStdinSequence ?? 0,
      ...(kind === "RUN_COMMAND"
        ? { resultVersion: options.resultVersion ?? 1, processId: `proc-${randomUUID()}` }
        : {}),
    },
  });
  const launch = kind === "CREATE_SANDBOX";
  const dispatch = await seedDispatchEvent(db.inspect, {
    data: {
      userId,
      aggregateType: "sandbox",
      aggregateId: sandbox.id,
      eventType: launch ? "sandbox.create_requested" : `sandbox.${wire}_requested`,
      claimedAt: null,
      claimToken: null,
      sentAt: null,
      sentConnectionEpoch: OLD,
      payload: {
        operationId: operation.id,
        sandboxId: sandbox.id,
        sandboxHostId: host.id,
        generation: 1,
        dispatchAttempt: 0,
        idempotencyKey,
        kind: wire,
        authorizingPrincipal: { kind: leasePolicy ? "system" : "session" },
        ...(kind === "RUN_COMMAND" ? { argv: ["true"] } : {}),
        ...(kind === "PUT_FILE" ? { path: "/tmp/upload", transferId: `tr-${operation.id}` } : {}),
        ...(leasePolicy
          ? {
              lease: {
                revision: 2,
                deadlineUnixMs: Date.now() + 3_600_000,
                action: "stop",
                expiryPolicy: "retry-force-60s",
                ...(options.shortenOnly === false ? {} : { shortenOnly: true }),
              },
            }
          : {}),
        ...(launch
          ? {
              allocationJournalId:
                options.lineageJournal === undefined ? JOURNAL : options.lineageJournal,
              allocationJournalAttempt: 1,
              allocationJournalEpoch: OLD,
              allocationDispatchSequence: 7,
            }
          : {}),
      },
    },
  });
  const sender = { userId, hostId: host.id, connectionEpoch: NOW };
  const adopt = (patch: Partial<Parameters<typeof adoptOperation>[0]> = {}) =>
    adoptOperation({
      sender,
      sandboxOwnerId: userId,
      operationId: operation.id,
      sandboxId: sandbox.id,
      generation: 1,
      attempt: 1,
      bodyHash: HASH,
      idempotencyKey,
      kind: wire,
      phase: "effect",
      stdinNextSequence: null,
      ...(launch ? { allocationSequence: 1 } : {}),
      ...patch,
    });
  const row = () => db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operation.id } });
  const event = (id: string) => db.inspect.outboxEvent.findUniqueOrThrow({ where: { id } });
  const control = (kindName: "operation.cancel" | "process.stdin", extra = {}) =>
    db.inspect.outboxEvent.create({
      data: {
        userId,
        aggregateType: "sandbox",
        aggregateId: sandbox.id,
        eventType:
          kindName === "operation.cancel"
            ? "sandbox.operation_cancel_requested"
            : "sandbox.stdin_requested",
        operationId: operation.id,
        payload: {
          sandboxId: sandbox.id,
          sandboxHostId: host.id,
          operationId: operation.id,
          kind: kindName,
          generation: 1,
          dispatchAttempt: 1,
          connectionEpoch: OLD,
          authorizingPrincipal: { kind: "session" },
          ...extra,
        },
      },
    });
  return {
    userId,
    host,
    sandbox,
    operation,
    idempotencyKey,
    dispatch,
    sender,
    adopt,
    row,
    event,
    control,
    wire,
  };
}

/** The processor scans every claimable event in this file's database; retire
 * other tests' leftovers so a scan sees only the sandboxes under test. */
async function isolateOutbox(...sandboxIds: string[]) {
  await db.inspect.outboxEvent.updateMany({
    where: { aggregateId: { notIn: sandboxIds }, processedAt: null },
    data: { processedAt: new Date() },
  });
}

describe("successful adoption", () => {
  it("re-binds the epoch, accepts DISPATCHED work and retires its dispatch event", async () => {
    const s = await seed();
    expect(await s.adopt()).toBe(true);
    expect(await s.row()).toMatchObject({
      state: "ACCEPTED",
      dispatchedConnectionEpoch: NOW,
      acceptedAttempt: 1,
      dispatchAttempt: 1,
    });
    expect((await s.event(s.dispatch.id)).processedAt).not.toBeNull();
    // Reconciliation leaves adopted work alone.
    expect(await finishHostReconciliation(s.sender)).toBe(true);
    expect((await s.row()).state).toBe("ACCEPTED");
    // Output and the final result are accepted on the new epoch.
    expect(
      await acceptFencedBinaryChunk({
        sender: s.sender,
        operationId: s.operation.id,
        generation: 1,
        attempt: 1,
        sequence: 0,
        ended: false,
        body: new Uint8Array([104, 105]),
        output: {
          type: "stream.chunk",
          streamId: s.operation.id,
          operationId: s.operation.id,
          generation: 1,
          attempt: 1,
          sequence: 0,
          offset: 0,
          flags: { stdout: true },
        },
      }),
    ).toBe(true);
    expect(
      await applyOperationResult({
        sender: s.sender,
        operationId: s.operation.id,
        sandboxId: s.sandbox.id,
        generation: 1,
        attempt: 1,
        state: "succeeded",
        result: commandResultFixture(s.operation, { exitCode: 0, outputBytes: 2 }),
      }),
    ).toEqual({ written: true });
    expect((await s.row()).state).toBe("SUCCEEDED");
  });

  it("an unadopted operation is still marked UNKNOWN by reconciliation", async () => {
    const s = await seed({ state: "RUNNING" });
    expect(await finishHostReconciliation(s.sender)).toBe(true);
    expect(await s.row()).toMatchObject({
      state: "UNKNOWN_OUTCOME",
      dispatchedConnectionEpoch: OLD,
    });
  });

  it("process.started binds a birth on the adopted epoch", async () => {
    const s = await seed({ state: "RUNNING", resultVersion: 1 });
    expect(await s.adopt()).toBe(true);
    const op = await s.row();
    const birth = {
      type: "process.started",
      operationId: op.id,
      sandboxId: s.sandbox.id,
      generation: 1,
      attempt: 1,
      processId: op.processId!,
      pid: 4242,
      bootId: "00000000-1234-4234-8234-123456789abc",
      startTicks: "12345",
      startedAt: new Date().toISOString(),
      observedAt: new Date().toISOString(),
    };
    expect(await applyProcessStarted({ sender: s.sender, birth })).toEqual({ written: true });
    expect((await s.row()).processPid).toBe(4242);
    // R2-1: the adopting daemon republishes the same evidence; the replay
    // binds nothing new, and a different incarnation never overwrites it.
    expect(await applyProcessStarted({ sender: s.sender, birth })).toEqual({ written: true });
    expect(await applyProcessStarted({ sender: s.sender, birth: { ...birth, pid: 4343 } })).toEqual(
      { written: false },
    );
    expect(await s.row()).toMatchObject({
      processPid: 4242,
      processBootId: birth.bootId,
      processStartTicks: "12345",
      dispatchedConnectionEpoch: s.sender.connectionEpoch,
    });
  });

  it("wakes a long-poll waiter on the adoption commit and on the final result", async () => {
    const s = await seed({ state: "RUNNING" });
    const seen: string[] = [];
    waiters.bindOperationChangeFanout((change) => {
      if (change === "all" || change.operationIds.has(s.operation.id)) seen.push("wake");
    });
    expect(await s.adopt()).toBe(true);
    expect(seen.length).toBeGreaterThanOrEqual(1);
    const afterAdopt = seen.length;
    expect(
      await applyOperationResult({
        sender: s.sender,
        operationId: s.operation.id,
        sandboxId: s.sandbox.id,
        generation: 1,
        attempt: 1,
        state: "succeeded",
        result: commandResultFixture(s.operation, { exitCode: 0, outputBytes: 0 }),
      }),
    ).toEqual({ written: true });
    expect(seen.length).toBeGreaterThan(afterAdopt);
  });

  it("double adoption across two reconnects is idempotent per epoch", async () => {
    const s = await seed({ state: "RUNNING" });
    expect(await s.adopt()).toBe(true);
    // The same epoch cannot adopt twice (the row is no longer older).
    expect(await s.adopt()).toBe(false);
    await db.inspect.sandboxHost.update({
      where: { id: s.host.id },
      data: { connectionEpoch: 5, admissionEpoch: 5, relayProtocolEpoch: 5 },
    });
    expect(await s.adopt({ sender: { ...s.sender, connectionEpoch: 5 } })).toBe(true);
    expect(await s.row()).toMatchObject({ state: "RUNNING", dispatchedConnectionEpoch: 5 });
  });
});

describe("refusals", () => {
  it("refuses identity mismatches, a current-epoch row and a stale sender", async () => {
    const s = await seed({ state: "RUNNING" });
    for (const patch of [
      { bodyHash: "c".repeat(64) },
      { idempotencyKey: "other" },
      { kind: "file.stat" },
      { attempt: 2 },
      { generation: 2 },
      { sandboxOwnerId: randomUUID() },
      { sender: { ...s.sender, connectionEpoch: 2 } },
      { sender: { ...s.sender, isCurrent: () => false } },
    ])
      expect(await s.adopt(patch), JSON.stringify(patch)).toBe(false);
    expect(await s.row()).toMatchObject({ state: "RUNNING", dispatchedConnectionEpoch: OLD });
  });

  it("never resurrects terminal or superseded rows", async () => {
    for (const state of ["SUCCEEDED", "FAILED", "CANCELLED"] as const) {
      const s = await seed({ state });
      expect(await s.adopt()).toBe(false);
      expect((await s.row()).state).toBe(state);
    }
    const superseded = await seed({ state: "CANCEL_REQUESTED", errorCode: "superseded" });
    expect(await superseded.adopt()).toBe(false);
    const reconciled = await seed({ state: "UNKNOWN_OUTCOME", errorCode: "superseded" });
    expect(await reconciled.adopt()).toBe(false);
  });

  it("refuses an Intent-phase command whose cancellation was requested meanwhile", async () => {
    const s = await seed({ state: "CANCEL_REQUESTED" });
    expect(await s.adopt({ phase: "intent" })).toBe(false);
    expect(await s.row()).toMatchObject({
      state: "CANCEL_REQUESTED",
      dispatchedConnectionEpoch: OLD,
    });
  });
});

describe("minor 5: interim UNKNOWN commands", () => {
  it("adopts an interim-UNKNOWN command with an epoch re-bind only; the receipt settles it", async () => {
    const s = await seed({ state: "UNKNOWN_OUTCOME", errorCode: "unknown_outcome" });
    expect(await s.adopt({ phase: "intent" })).toBe(false);
    expect(await s.adopt()).toBe(true);
    expect(await s.row()).toMatchObject({
      state: "UNKNOWN_OUTCOME",
      dispatchedConnectionEpoch: NOW,
    });
    expect(
      await applyOperationResult({
        sender: s.sender,
        operationId: s.operation.id,
        sandboxId: s.sandbox.id,
        generation: 1,
        attempt: 1,
        state: "succeeded",
        result: commandResultFixture(s.operation, { exitCode: 0, outputBytes: 0 }),
        receipt: { bodyHash: HASH, idempotencyKey: s.idempotencyKey, kind: "command.run" },
      }),
    ).toEqual({ written: true });
    expect((await s.row()).state).toBe("SUCCEEDED");
  });

  it("refuses a lifecycle UNKNOWN (server-owned teardown)", async () => {
    const s = await seed({
      kind: "CREATE_SANDBOX",
      state: "UNKNOWN_OUTCOME",
      errorCode: "unknown_outcome",
    });
    expect(await s.adopt()).toBe(false);
  });
});

describe("D11: pendingReceipts", () => {
  const dispatchedAt = (s: Awaited<ReturnType<typeof seed>>, at: Date) =>
    db.inspect.sandboxOperation.update({
      where: { id: s.operation.id },
      data: { dispatchedAt: at },
    });

  it("publishes no interim UNKNOWN for a deferred create and dispatches no replacement", async () => {
    const s = await seed({ kind: "CREATE_SANDBOX" });
    await dispatchedAt(s, new Date());
    expect(await finishHostReconciliation(s.sender, undefined, new Set([s.operation.id]))).toBe(
      true,
    );
    expect(await s.row()).toMatchObject({
      state: "DISPATCHED",
      errorCode: null,
      dispatchedConnectionEpoch: OLD,
    });
    // The dispatch intent is retired: no attempt 2 while the receipt is pending.
    expect((await s.event(s.dispatch.id)).processedAt).not.toBeNull();
    // The receipt never came this session: the next reconciliation without
    // it settles the operation as before.
    expect(await finishHostReconciliation(s.sender)).toBe(true);
    expect((await s.row()).state).toBe("UNKNOWN_OUTCOME");
  });

  it("keeps a cancel queued during the disconnect for delivery", async () => {
    const s = await seed({ state: "RUNNING" });
    await dispatchedAt(s, new Date());
    const cancel = await s.control("operation.cancel");
    const stdin = await s.control("process.stdin", {
      stdinSequence: 0,
      stdinBase64: "",
      eof: true,
    });
    expect(await finishHostReconciliation(s.sender, undefined, new Set([s.operation.id]))).toBe(
      true,
    );
    expect((await s.row()).state).toBe("RUNNING");
    expect((await s.event(s.dispatch.id)).processedAt).not.toBeNull();
    expect((await s.event(cancel.id)).processedAt, "cancel stays queued").toBeNull();
    expect((await s.event(stdin.id)).processedAt, "stdin stays queued").toBeNull();
  });

  it("holds an operation only for a bounded time from its dispatch", async () => {
    const { PENDING_RECEIPT_MAX_HOLD_MS } = await import("./operation-handlers.js");
    const s = await seed({ kind: "CREATE_SANDBOX" });
    await dispatchedAt(s, new Date(Date.now() - PENDING_RECEIPT_MAX_HOLD_MS - 1000));
    expect(await finishHostReconciliation(s.sender, undefined, new Set([s.operation.id]))).toBe(
      true,
    );
    expect((await s.row()).state).toBe("UNKNOWN_OUTCOME");
  });

  it("settles every operation it does not name", async () => {
    const s = await seed({ kind: "CREATE_SANDBOX" });
    await dispatchedAt(s, new Date());
    expect(await finishHostReconciliation(s.sender, undefined, new Set(["other-op"]))).toBe(true);
    expect((await s.row()).state).toBe("UNKNOWN_OUTCOME");
  });
});

describe("races with exactly one winner", () => {
  const SANDBOX_LOCK =
    /^sql:SELECT id FROM sandbox_instance WHERE id = \? AND "userId" = \? AND generation = \? FOR UPDATE$/;

  async function supersede(s: Awaited<ReturnType<typeof seed>>, state: SandboxState) {
    // The kill/stop writer's S critical section: lock S, then advance it.
    // The instrumented client, so the race can observe its lock wait.
    await db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${s.sandbox.id} FOR UPDATE`;
      await tx.sandbox.update({ where: { id: s.sandbox.id }, data: { state, generation: 2 } });
    });
  }

  it("a kill committed first wins: adoption is refused", async () => {
    const s = await seed({ state: "RUNNING" });
    await supersede(s, "STOPPING");
    expect(await s.adopt()).toBe(false);
    expect((await s.row()).dispatchedConnectionEpoch).toBe(OLD);
  });

  it("an adoption holding S makes the kill wait; the kill then sees the adopted row", async () => {
    const s = await seed({ state: "RUNNING" });
    const gate = db.pauseAt("adopt", { after: SANDBOX_LOCK });
    const adoption = db.run("adopt", () => s.adopt());
    await gate.waitReached();
    const kill = db.run("kill", () => supersede(s, "STOPPING"));
    await db.waitUntilBlocked("kill", { by: "adopt" });
    gate.release();
    expect(await adoption).toBe(true);
    await kill;
    expect(await s.row()).toMatchObject({ dispatchedConnectionEpoch: NOW });
    expect(
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.sandbox.id } })).generation,
    ).toBe(2);
  });

  it("a sharing-loss stop (sandbox no longer READY) refuses adoption", async () => {
    const s = await seed({ state: "RUNNING" });
    await db.inspect.sandbox.update({ where: { id: s.sandbox.id }, data: { state: "STOPPING" } });
    expect(await s.adopt()).toBe(false);
  });

  it("a passed lease deadline refuses a create; a live lease admits it", async () => {
    const expired = await seed({
      kind: "CREATE_SANDBOX",
      state: "ACCEPTED",
      leaseExpiresAt: new Date(Date.now() - 60_000),
    });
    expect(await expired.adopt()).toBe(false);
    const live = await seed({
      kind: "CREATE_SANDBOX",
      state: "ACCEPTED",
      leaseExpiresAt: new Date(Date.now() + 3_600_000),
    });
    expect(await live.adopt()).toBe(true);
  });

  it("the inactive-key attempt+1 claim and adoption: exactly one wins, in either order", async () => {
    vi.resetModules();
    const sessionManager = {
      isHostConnected: vi.fn().mockReturnValue(false),
      dispatchOperation: vi.fn().mockReturnValue("sent"),
      captureHostDispatchCredential: undefined,
    };
    vi.doMock("./session-manager.js", () => ({ sandboxRelaySessionManager: sessionManager }));
    const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
    const fresh = await import("./operation-handlers.js");
    vi.doUnmock("./session-manager.js");

    // Claim first: the banned owner's undispatched-epoch row takes attempt+1
    // offline and settles; the late adoption is refused.
    const claimed = await seed({ banned: true });
    await isolateOutbox(claimed.sandbox.id);
    await processSandboxOutboxBatch(() => new Date());
    const afterClaim = await claimed.row();
    expect(afterClaim.dispatchAttempt).toBe(2);
    expect(
      await fresh.adoptOperation({
        sender: claimed.sender,
        sandboxOwnerId: claimed.userId,
        operationId: claimed.operation.id,
        sandboxId: claimed.sandbox.id,
        generation: 1,
        attempt: 1,
        bodyHash: HASH,
        idempotencyKey: claimed.idempotencyKey,
        kind: "command.run",
        phase: "effect",
        stdinNextSequence: null,
      }),
    ).toBe(false);

    // Adoption first (Effect phase skips the key gate): the claim finds the
    // dispatch event retired and the row accepted on the current epoch.
    const adopted = await seed({ banned: true });
    expect(await adopted.adopt()).toBe(true);
    await isolateOutbox(adopted.sandbox.id);
    await processSandboxOutboxBatch(() => new Date());
    expect(await adopted.row()).toMatchObject({
      state: "ACCEPTED",
      dispatchAttempt: 1,
      dispatchedConnectionEpoch: NOW,
    });
  });
});

describe("controls and stdin", () => {
  it("re-binds a cancel requested during the disconnect so it is delivered afterwards (M1)", async () => {
    const s = await seed({ state: "CANCEL_REQUESTED" });
    const cancel = await s.control("operation.cancel");
    expect(await s.adopt()).toBe(true);
    expect(await s.row()).toMatchObject({
      state: "CANCEL_REQUESTED",
      acceptedAttempt: 1,
      dispatchedConnectionEpoch: NOW,
    });
    expect((await s.event(cancel.id)).payload).toMatchObject({ connectionEpoch: NOW });
  });

  it("the processor then delivers the re-bound cancel and stdin on the new epoch", async () => {
    vi.resetModules();
    const sessionManager = {
      // Not reconciled yet: the processor claims nothing for this host.
      isHostConnected: vi.fn().mockReturnValue(false),
      cancelOperation: vi.fn().mockResolvedValue(true),
      sendStdin: vi.fn().mockResolvedValue(true),
      captureHostDispatchCredential: undefined,
    };
    vi.doMock("./session-manager.js", () => ({ sandboxRelaySessionManager: sessionManager }));
    const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
    const cancelled = await seed({ state: "CANCEL_REQUESTED" });
    await cancelled.control("operation.cancel");
    const writing = await seed({ state: "RUNNING", nextStdinSequence: 1 });
    await writing.control("process.stdin", { stdinSequence: 0, stdinBase64: "YQ==" });
    await isolateOutbox(cancelled.sandbox.id, writing.sandbox.id);
    try {
      // Before reconciliation the old-epoch controls are never sent.
      await processSandboxOutboxBatch(() => new Date());
      expect(sessionManager.cancelOperation).not.toHaveBeenCalled();
      expect(sessionManager.sendStdin).not.toHaveBeenCalled();
      expect(await cancelled.adopt()).toBe(true);
      expect(await writing.adopt({ stdinNextSequence: 0 })).toBe(true);
      // reconcile.complete: the session is now connected and reconciled.
      sessionManager.isHostConnected.mockReturnValue(true);
      await processSandboxOutboxBatch(() => new Date());
    } finally {
      vi.doUnmock("./session-manager.js");
    }
    expect(sessionManager.cancelOperation).toHaveBeenCalledWith(
      cancelled.host.id,
      cancelled.operation.id,
      1,
      1,
      NOW,
      expect.anything(),
    );
    expect(sessionManager.sendStdin).toHaveBeenCalledWith(
      writing.host.id,
      writing.operation.id,
      1,
      1,
      expect.any(Uint8Array),
      false,
      NOW,
      0,
      expect.anything(),
    );
  });

  it.each(["process.stdin", "operation.cancel"] as const)(
    "an old-epoch %s sender finishing after adoption cannot retire the re-bound event",
    async (kind) => {
      vi.resetModules();
      let release!: () => void;
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      let entered = false;
      const blocked = async () => {
        entered = true;
        await held;
        return true;
      };
      const sessionManager = {
        isHostConnected: vi.fn().mockReturnValue(true),
        // The old session's send blocks until adoption has committed.
        sendStdin: vi.fn(blocked),
        cancelOperation: vi.fn(blocked),
        captureHostDispatchCredential: undefined,
      };
      vi.doMock("./session-manager.js", () => ({ sandboxRelaySessionManager: sessionManager }));
      const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
      vi.doUnmock("./session-manager.js");
      const stdin = kind === "process.stdin";
      const s = await seed(
        stdin ? { state: "RUNNING", nextStdinSequence: 1 } : { state: "CANCEL_REQUESTED" },
      );
      const control = await s.control(kind, stdin ? { stdinSequence: 0, stdinBase64: "YQ==" } : {});
      // The old session is still current: its processor claims the control.
      await db.inspect.sandboxHost.update({
        where: { id: s.host.id },
        data: { connectionEpoch: OLD },
      });
      await isolateOutbox(s.sandbox.id);
      const oldSender = processSandboxOutboxBatch(() => new Date());
      for (let i = 0; i < 400 && !entered; i++)
        await new Promise((resolve) => setTimeout(resolve, 10));
      expect(entered, "old sender claimed and is mid-send").toBe(true);
      // The transport drops; the reconnect adopts before the old send returns.
      await db.inspect.sandboxHost.update({
        where: { id: s.host.id },
        data: { connectionEpoch: NOW },
      });
      expect(await s.adopt(stdin ? { stdinNextSequence: 0 } : {})).toBe(true);
      release();
      await oldSender;
      const event = await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: control.id } });
      expect(event.processedAt, "still owed to the new epoch").toBeNull();
      expect(event.sentAt).toBeNull();
      expect(event.payload).toMatchObject({ connectionEpoch: NOW });
      // The new epoch's processor delivers it.
      sessionManager.sendStdin.mockClear().mockImplementation(async () => true);
      sessionManager.cancelOperation.mockClear().mockImplementation(async () => true);
      await processSandboxOutboxBatch(() => new Date());
      if (stdin)
        expect(sessionManager.sendStdin).toHaveBeenCalledWith(
          s.host.id,
          s.operation.id,
          1,
          1,
          expect.any(Uint8Array),
          false,
          NOW,
          0,
          expect.anything(),
        );
      else
        expect(sessionManager.cancelOperation).toHaveBeenCalledWith(
          s.host.id,
          s.operation.id,
          1,
          1,
          NOW,
          expect.anything(),
        );
    },
  );

  it("re-arms every stdin chunk the host has not received (B1)", async () => {
    const s = await seed({ state: "RUNNING", nextStdinSequence: 4 });
    const now = new Date();
    const lost = await s.control("process.stdin", { stdinSequence: 1, stdinBase64: "YQ==" });
    const lost2 = await s.control("process.stdin", { stdinSequence: 2, stdinBase64: "Yg==" });
    const pending = await s.control("process.stdin", { stdinSequence: 3, stdinBase64: "Yw==" });
    const received = await s.control("process.stdin", { stdinSequence: 0, stdinBase64: "eg==" });
    for (const id of [lost.id, lost2.id, received.id])
      await db.inspect.outboxEvent.update({
        where: { id },
        data: { processedAt: now, sentAt: now, sentConnectionEpoch: OLD },
      });
    expect(await s.adopt({ stdinNextSequence: 1 })).toBe(true);
    for (const id of [lost.id, lost2.id, pending.id]) {
      const event = await s.event(id);
      expect(event).toMatchObject({ processedAt: null, sentAt: null, claimToken: null });
      expect(event.payload).toMatchObject({ connectionEpoch: NOW });
    }
    // The chunk the host already has is never re-armed.
    expect((await s.event(received.id)).processedAt).not.toBeNull();
  });

  it("locks only the reopenable stdin range, never the stdin history", async () => {
    const s = await seed({ state: "RUNNING", nextStdinSequence: 300 });
    const now = new Date();
    // 298 delivered chunks of this attempt and 50 of an older attempt.
    const history = await db.inspect.outboxEvent.createManyAndReturn({
      data: [
        ...Array.from({ length: 298 }, (_, i) => ({ sequence: i, attempt: 1 })),
        ...Array.from({ length: 50 }, (_, i) => ({ sequence: i, attempt: 0 })),
      ].map(({ sequence, attempt }) => ({
        userId: s.userId,
        aggregateType: "sandbox",
        aggregateId: s.sandbox.id,
        eventType: "sandbox.stdin_requested",
        operationId: s.operation.id,
        processedAt: now,
        sentAt: now,
        payload: {
          operationId: s.operation.id,
          kind: "process.stdin",
          generation: 1,
          dispatchAttempt: attempt,
          connectionEpoch: OLD,
          stdinSequence: sequence,
          stdinBase64: "YQ==",
        },
      })),
      select: { id: true },
    });
    const lost = await s.control("process.stdin", { stdinSequence: 298, stdinBase64: "YQ==" });
    const pending = await s.control("process.stdin", { stdinSequence: 299, stdinBase64: "Yg==" });
    await db.inspect.outboxEvent.update({ where: { id: lost.id }, data: { processedAt: now } });
    const gate = db.pauseAt("adopt", { after: /^sql:SELECT id FROM sandbox_dispatch_outbox/ });
    const adoption = db.run("adopt", () => s.adopt({ stdinNextSequence: 298 }));
    await gate.waitReached();
    const lockedBy = async (id: string) =>
      db.inspect
        .$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM sandbox_dispatch_outbox WHERE id = ${id} FOR UPDATE NOWAIT`;
          return false;
        })
        .catch(() => true);
    expect(await lockedBy(lost.id), "reopenable chunk").toBe(true);
    expect(await lockedBy(pending.id), "pending control").toBe(true);
    for (const row of [history[0]!, history[297]!, history[300]!])
      expect(await lockedBy(row.id), "history stays unlocked").toBe(false);
    gate.release();
    expect(await adoption).toBe(true);
    expect((await s.event(lost.id)).processedAt).toBeNull();
  });

  it("refuses when the pending backlog exceeds the lock bound", async () => {
    const s = await seed({ state: "RUNNING" });
    await db.inspect.outboxEvent.createMany({
      data: Array.from({ length: 600 }, () => ({
        userId: s.userId,
        aggregateType: "sandbox",
        aggregateId: s.sandbox.id,
        eventType: "sandbox.operation_cancel_requested",
        operationId: s.operation.id,
        payload: {
          operationId: s.operation.id,
          kind: "operation.cancel",
          generation: 1,
          dispatchAttempt: 1,
          connectionEpoch: OLD,
        },
      })),
    });
    expect(await s.adopt()).toBe(false);
    expect((await s.row()).dispatchedConnectionEpoch).toBe(OLD);
  });

  it("refuses refused, missing, future and over-bound stdin", async () => {
    const refused = await seed({ state: "RUNNING", nextStdinSequence: 2 });
    const event = await refused.control("process.stdin", {
      stdinSequence: 1,
      stdinBase64: "YQ==",
      dispatchRefusal: "unknown_outcome",
    });
    await db.inspect.outboxEvent.update({
      where: { id: event.id },
      data: { processedAt: new Date() },
    });
    expect(await refused.adopt({ stdinNextSequence: 1 })).toBe(false);

    // Inline sequence 0 rides the dispatch, never an event: lost means refused.
    const inline = await seed({ state: "RUNNING", nextStdinSequence: 1 });
    expect(await inline.adopt({ stdinNextSequence: 0 })).toBe(false);

    const future = await seed({ state: "RUNNING", nextStdinSequence: 1 });
    expect(await future.adopt({ stdinNextSequence: 2 })).toBe(false);

    const wide = await seed({ state: "RUNNING", nextStdinSequence: 70 });
    expect(await wide.adopt({ stdinNextSequence: 1 })).toBe(false);

    const closed = await seed({ state: "RUNNING", nextStdinSequence: 3 });
    expect(await closed.adopt({ stdinNextSequence: null })).toBe(true);
  });
});

describe("Intent-phase gates", () => {
  /** One `host.egress-state` frame on this epoch, through the production
   * wire decoder and then the recorder (as the session manager does). */
  async function renewGuard(s: Awaited<ReturnType<typeof seed>>, report: Record<string, unknown>) {
    const { recordHostEgressState } = await import("./host-egress-state.js");
    const { parseDaemonControlFrame } = await import("./protocol.js");
    const message = parseDaemonControlFrame(
      JSON.stringify({
        type: "host.egress-state",
        connectionEpoch: NOW,
        sequence: 1,
        allowOpenForOthers: false,
        allowGuestSudoForOthers: false,
        ...report,
      }),
      "1.0",
    );
    if (message.type !== "host.egress-state") throw new Error(`decoded ${message.type}`);
    return recordHostEgressState(
      {
        identity: { hostId: s.host.id, userId: s.sender.userId },
        connectionEpoch: NOW,
        egressSequence: 0,
      },
      message,
      () => true,
    );
  }

  it("an inactive key refuses Intent work but adopts Effect work", async () => {
    const intent = await seed({ banned: true });
    expect(await intent.adopt({ phase: "intent" })).toBe(false);
    const effect = await seed({ banned: true });
    expect(await effect.adopt({ phase: "effect" })).toBe(true);
  });

  it("egress no longer advertised refuses an Intent create", async () => {
    const s = await seed({ kind: "CREATE_SANDBOX", egress: false });
    expect(await s.adopt({ phase: "intent" })).toBe(false);
    const effect = await seed({ kind: "CREATE_SANDBOX", egress: false });
    expect(await effect.adopt({ phase: "effect" })).toBe(true);
  });

  it("draining storage refuses an Intent create", async () => {
    const s = await seed({ kind: "CREATE_SANDBOX" });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: s.host.id },
      data: { draining: true },
    });
    expect(await s.adopt({ phase: "intent" })).toBe(false);
    const ok = await seed({ kind: "CREATE_SANDBOX" });
    expect(await ok.adopt({ phase: "intent" })).toBe(true);
  });

  // A create still fetching its template image (Intent) across a server
  // redeploy must be adopted, not settled UNKNOWN. A hello clears the guard
  // lease (it belongs to the connection), so the Intent create's guard gate
  // needs this epoch's first healthy `host.egress-state`, which the daemon
  // sends before the adoption frame.
  it("an Intent create needs this epoch's guard lease renewal, an Effect create does not", async () => {
    const s = await seed({ kind: "CREATE_SANDBOX" });
    // Exactly what host-hello writes for a new connection.
    await db.inspect.sandboxHost.update({
      where: { id: s.host.id },
      data: { daemonEgressGuardLeaseUntil: null, daemonEgressStateSequence: null },
    });
    expect(await s.adopt({ phase: "intent" })).toBe(false);
    // A healthy verdict is valid on the wire only with the guard's identity.
    await expect(renewGuard(s, { guardOk: true })).rejects.toThrow();
    expect(
      await renewGuard(s, {
        guardOk: true,
        guardInstanceId: "0123456789abcdef0123456789abcdef",
        guardGeneration: 1,
      }),
    ).toBe(true);
    expect(await s.adopt({ phase: "intent" })).toBe(true);

    const effect = await seed({ kind: "CREATE_SANDBOX" });
    await db.inspect.sandboxHost.update({
      where: { id: effect.host.id },
      data: { daemonEgressGuardLeaseUntil: null },
    });
    expect(await effect.adopt({ phase: "effect" })).toBe(true);
  });

  it("an Intent create refuses an unhealthy guard renewal", async () => {
    const s = await seed({ kind: "CREATE_SANDBOX" });
    expect(await renewGuard(s, { guardOk: false, guardReason: "guard_unreachable" })).toBe(true);
    expect(await s.adopt({ phase: "intent" })).toBe(false);
  });

  // The same class: storage health is fresh for 15 s (STORAGE_HEALTH_STALE_MS)
  // and an Intent create's retained-storage gate re-checks it at adoption.
  it("an Intent create needs a fresh, healthy storage observation of this epoch", async () => {
    const { recordHostInventory } = await import("./inventory-reconcile.js");
    const observation = (
      s: Awaited<ReturnType<typeof seed>>,
      sequence: number,
      health: "healthy" | "unavailable",
    ) => ({
      type: "inventory.update" as const,
      id: randomUUID(),
      connectionEpoch: NOW,
      observationSequence: sequence,
      inventory: { hostId: s.host.id, schedulable: true, sandboxCount: 1 },
      storagePools: capacityFixture(s.host.id).storagePools.map(({ name, marker }) => ({
        name,
        marker,
        health,
        reason: health === "healthy" ? null : ("io" as const),
        totalBytes: null,
        usedBytes: null,
        freeBytes: null,
      })),
    });
    const stale = async () => {
      const s = await seed({ kind: "CREATE_SANDBOX" });
      await db.inspect.sandboxHost.update({
        where: { id: s.host.id },
        data: { capacityReport: JSON.stringify(capacityFixture(s.host.id)) },
      });
      // The hello's observation, outlived by a long reconciliation.
      await db.inspect.sandboxHostStoragePool.updateMany({
        where: { sandboxHostId: s.host.id },
        data: { reportedAt: new Date(Date.now() - 20_000) },
      });
      return s;
    };
    const s = await stale();
    expect(await s.adopt({ phase: "intent" })).toBe(false);
    expect(await recordHostInventory(s.sender, true, observation(s, 1, "healthy"))).toBe(true);
    expect(await s.adopt({ phase: "intent" })).toBe(true);

    const unhealthy = await stale();
    expect(
      await recordHostInventory(unhealthy.sender, true, observation(unhealthy, 1, "unavailable")),
    ).toBe(true);
    expect(await unhealthy.adopt({ phase: "intent" })).toBe(false);
  });
});

describe("lease-policy pull-ins across adoption and the dispatch audit", () => {
  it("an Intent-phase system renewal passes the gates only with its shorten-only lease", async () => {
    const shortenOnly = await seed({ kind: "RENEW_SANDBOX_LEASE" });
    expect(await shortenOnly.adopt({ phase: "intent" })).toBe(true);
    // A keyless system renewal that could extend is never admitted.
    const extending = await seed({ kind: "RENEW_SANDBOX_LEASE", shortenOnly: false });
    expect(await extending.adopt({ phase: "intent" })).toBe(false);
  });

  it("a never-received pull-in is requeued with its shorten-only lease", async () => {
    vi.resetModules();
    const sessionManager = {
      isHostConnected: vi.fn().mockReturnValue(true),
      dispatchOperation: vi.fn().mockResolvedValue("sent"),
      captureHostDispatchCredential: undefined,
    };
    vi.doMock("./session-manager.js", () => ({ sandboxRelaySessionManager: sessionManager }));
    const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
    vi.doUnmock("./session-manager.js");
    const entry = (s: Awaited<ReturnType<typeof seed>>) => ({
      sender: s.sender,
      sandboxOwnerId: s.userId,
      operationId: s.operation.id,
      sandboxId: s.sandbox.id,
      generation: 1,
      attempt: 1,
      idempotencyKey: s.idempotencyKey,
      kind: s.wire,
    });
    const s = await seed({ kind: "RENEW_SANDBOX_LEASE" });
    expect(await settleUndeliveredDispatch(entry(s))).toBe("requeued");
    await isolateOutbox(s.sandbox.id);
    await processSandboxOutboxBatch(() => new Date());
    expect(sessionManager.dispatchOperation).toHaveBeenCalledWith(
      s.host.id,
      expect.objectContaining({
        operationId: s.operation.id,
        attempt: 2,
        authorizingPrincipal: { kind: "system" },
        lease: expect.objectContaining({ shortenOnly: true }),
      }),
    );
  });
});

describe("allocation lineage (M3)", () => {
  it("refuses a journal-id mismatch and a missing lineage", async () => {
    const other = await seed({ kind: "CREATE_SANDBOX", lineageJournal: "f".repeat(32) });
    expect(await other.adopt()).toBe(false);
    const broken = await seed({ kind: "CREATE_SANDBOX", lineageJournal: null });
    expect(await broken.adopt()).toBe(false);
    const unsequenced = await seed({ kind: "CREATE_SANDBOX" });
    expect(await unsequenced.adopt({ allocationSequence: undefined })).toBe(false);
  });

  it("re-binds the lineage so allocation attestation still settles after adoption", async () => {
    const s = await seed({ kind: "CREATE_SANDBOX" });
    expect(await s.adopt({ allocationSequence: 1 })).toBe(true);
    expect((await s.event(s.dispatch.id)).payload).toMatchObject({
      allocationJournalId: JOURNAL,
      allocationJournalAttempt: 1,
      allocationJournalEpoch: NOW,
      allocationDispatchSequence: 1,
    });
    // The adopted create later ends uncertain; a barrier above its sequence
    // proves it never issued.
    await db.inspect.sandboxOperation.update({
      where: { id: s.operation.id },
      data: { state: "UNKNOWN_OUTCOME", errorCode: "unknown_outcome", completedAt: new Date() },
    });
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.sandbox.id } });
    const outcome = await convergeInventoryEntry(
      s.sender,
      { sandboxId: s.sandbox.id, state: "absent" },
      undefined,
      {
        connectionEpoch: NOW,
        barrier: 2,
        journalId: JOURNAL,
        root: {
          storageMarker: sandbox.storageMarker!,
          storagePoolName: sandbox.storagePoolName!,
          diskGiB: sandbox.diskGiB,
        },
      },
    );
    expect(outcome).toMatchObject({ converged: true });
    expect((await s.row()).state).toBe("FAILED");
  });
});

describe("stop during initial provisioning", () => {
  it("settles the absent STOP's credential receipt before queuing its cleanup KILL", async () => {
    const savedKey = process.env.DATA_ENCRYPTION_KEY;
    const savedEnabled = process.env.CREDENTIALS_ENABLED;
    process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("hex");
    process.env.CREDENTIALS_ENABLED = "true";
    try {
      const s = await seed({ kind: "STOP_SANDBOX", state: "ACCEPTED" });
      expect(s.sandbox).toMatchObject({ readyAt: null, generation: 1 });
      const service = await import("@wssp/api/credentials/service");
      const { settleCredentialTeardown } = await import(
        "../../../../packages/api/src/credentials/teardown"
      );
      const actor = { kind: "session" as const, ownerId: s.userId };
      const slug = `tool-${randomUUID().slice(0, 8)}`;
      const definition = await service.createDefinition(actor, {
        document: {
          schemaVersion: 1,
          id: slug,
          displayName: "Tool",
          login: { command: "tool login", method: "device-code" },
          credentials: {
            files: { required: [".config/tool"], optional: [], exclude: [] },
            sharing: "exclusive",
          },
        },
      });
      const login = await service.createLogin(actor, { name: slug, definitionId: definition.id });
      const account = await service.createAccount(actor, { credentialId: login.id });
      const instance = await service.createInstance(actor, {
        credentialId: login.id,
        accountId: account.id,
      });
      const lease = await db.inspect.credentialLease.create({
        data: {
          userId: s.userId,
          credentialId: login.id,
          accountId: account.id,
          instanceId: instance.id,
          sandboxId: s.sandbox.id,
          operationId: `create-${randomUUID()}`,
          kind: "WORKLOAD",
          exclusive: true,
          state: "ACTIVE",
          hostId: s.host.id,
          baseSeq: 1,
        },
      });
      await db.inspect.credentialInstance.update({
        where: { id: instance.id },
        data: { activeLeases: 1, state: "READY", currentSeq: 1, nextStorageSeq: 2 },
      });
      const binding = await db.inspect.credentialBinding.create({
        data: {
          leaseId: lease.id,
          instanceId: instance.id,
          sandboxId: s.sandbox.id,
          hostId: s.host.id,
          grantGeneration: 1,
          baseSeq: 1,
          purpose: "INSTALL",
        },
      });
      await db.inspect.credentialLease.update({
        where: { id: lease.id },
        data: { currentBindingId: binding.id },
      });
      await db.inspect.credentialResidue.create({
        data: {
          sandboxId: s.sandbox.id,
          userId: s.userId,
          credentialId: login.id,
          instanceId: instance.id,
          leaseId: lease.id,
          bindingId: binding.id,
          grantGeneration: 1,
          paths: [".config/tool"],
          recoverable: true,
        },
      });
      // Use the same teardown writer as stop acceptance, under the sandbox lock.
      await db.inspect.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${s.sandbox.id} FOR UPDATE`;
        await settleCredentialTeardown(tx, {
          sandboxId: s.sandbox.id,
          priorState: "PROVISIONING",
          generation: 1,
          teardownOperationId: s.operation.id,
        });
      });
      const leaseRow = () =>
        db.inspect.credentialLease.findUniqueOrThrow({ where: { id: lease.id } });
      expect(await leaseRow()).toMatchObject({
        state: "RELEASING",
        teardownOperationId: s.operation.id,
        releasedAt: null,
      });
      expect(await s.adopt()).toBe(true);
      // Seed the committed capture ledger: settlement trusts this row, not the receipt's ack.
      const captureId = `cap-${randomUUID()}`;
      await db.inspect.credentialCapture.create({
        data: {
          captureId,
          leaseId: lease.id,
          bindingId: binding.id,
          captureSeq: 1,
          kind: "stop",
          kidR: "test-return-key",
          envelopeDigest: Buffer.alloc(32),
          outcome: "COMMITTED",
          storageSeq: 2,
        },
      });
      await db.inspect.credentialInstance.update({
        where: { id: instance.id },
        data: { currentSeq: 2, nextStorageSeq: 3 },
      });
      expect(
        await applyOperationResult({
          sender: s.sender,
          operationId: s.operation.id,
          sandboxId: s.sandbox.id,
          generation: 1,
          attempt: 1,
          state: "succeeded",
          result: {
            state: "absent",
            credentialOutcomes: [
              {
                leaseId: lease.id,
                bindingId: binding.id,
                capture: { status: "acked", captureId, outcome: "committed" },
                scrub: "verified",
              },
            ],
          },
        }),
      ).toEqual({ written: true });
      expect(await s.row()).toMatchObject({ state: "SUCCEEDED", result: { state: "absent" } });
      expect(JSON.stringify((await s.row()).result)).not.toContain("credentialOutcomes");
      const sandboxRow = () =>
        db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.sandbox.id } });
      expect(await sandboxRow()).toMatchObject({ state: "STOPPING", generation: 2, readyAt: null });
      const kills = await db.inspect.sandboxOperation.findMany({
        where: { sandboxId: s.sandbox.id, kind: "KILL_SANDBOX" },
        take: 2,
      });
      expect(kills).toHaveLength(1);
      const kill = kills[0]!;
      expect(kill).toMatchObject({ state: "QUEUED", generation: 2 });
      // Match the ordinary successful STOP: captured lease released, binding closed, scrub applied.
      const settledLease = await leaseRow();
      expect(settledLease).toMatchObject({
        state: "RELEASED",
        endReason: "captured",
        releasedAt: expect.any(Date),
        teardownOperationId: null,
      });
      expect(settledLease.teardownOperationId).not.toBe(kill.id);
      const instanceRow = () =>
        db.inspect.credentialInstance.findUniqueOrThrow({ where: { id: instance.id } });
      expect(await instanceRow()).toMatchObject({ activeLeases: 0, currentSeq: 2, state: "READY" });
      expect(
        await db.inspect.credentialBinding.findUniqueOrThrow({ where: { id: binding.id } }),
      ).toMatchObject({ closedAt: expect.any(Date), closeReason: "captured" });
      const residueRow = () =>
        db.inspect.credentialResidue.findUniqueOrThrow({ where: { bindingId: binding.id } });
      const scrubbedResidue = await residueRow();
      expect(scrubbedResidue).toMatchObject({
        clearedAt: expect.any(Date),
        clearReason: "scrubbed",
      });

      await db.inspect.sandboxOperation.update({
        where: { id: kill.id },
        data: {
          state: "ACCEPTED",
          dispatchAttempt: 1,
          acceptedAttempt: 1,
          dispatchedHostId: s.host.id,
          dispatchedConnectionEpoch: NOW,
        },
      });
      expect(
        await applyOperationResult({
          sender: s.sender,
          operationId: kill.id,
          sandboxId: s.sandbox.id,
          generation: kill.generation,
          attempt: 1,
          state: "succeeded",
          result: { state: "deleted" },
        }),
      ).toEqual({ written: true });
      expect(await sandboxRow()).toMatchObject({
        state: "DELETED",
        generation: 2,
        liveResourcesHeld: false,
        diskReservationHeld: false,
        sandboxHostId: null,
      });
      // DELETED settlement preserves terminal leases and already-cleared scrub evidence.
      expect(await leaseRow()).toEqual(settledLease);
      expect(await instanceRow()).toMatchObject({ activeLeases: 0, currentSeq: 2, state: "READY" });
      expect(await residueRow()).toEqual(scrubbedResidue);
    } finally {
      if (savedKey === undefined) delete process.env.DATA_ENCRYPTION_KEY;
      else process.env.DATA_ENCRYPTION_KEY = savedKey;
      if (savedEnabled === undefined) delete process.env.CREDENTIALS_ENABLED;
      else process.env.CREDENTIALS_ENABLED = savedEnabled;
    }
  });

  it.each([false, true])(
    "keeps absent never-ready roots STOPPING until system kill proves deletion (retry=%s)",
    async (retry) => {
      const s = await seed({ kind: "STOP_SANDBOX", state: "ACCEPTED" });
      await db.inspect.sandboxHost.update({
        where: { id: s.host.id },
        data: { daemonDiskOffload: true },
      });
      expect(s.sandbox).toMatchObject({ readyAt: null, diskReservationHeld: true });
      expect(await s.adopt()).toBe(true);
      const stopResult = {
        sender: s.sender,
        operationId: s.operation.id,
        sandboxId: s.sandbox.id,
        generation: 1,
        attempt: 1,
        state: "succeeded",
        result: { state: "absent" },
      };
      expect(await applyOperationResult(stopResult)).toEqual({ written: true });
      expect(await s.row()).toMatchObject({ state: "SUCCEEDED", result: { state: "absent" } });
      const sandbox = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.sandbox.id } });
      expect(await sandbox()).toMatchObject({
        state: "STOPPING",
        generation: 2,
        readyAt: null,
        lastStoppedAt: null,
        liveResourcesHeld: false,
        diskReservationHeld: true,
        sandboxHostId: s.host.id,
      });
      expect(
        await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: s.host.id } }),
      ).toMatchObject({
        liveCount: 0,
        rootCount: 1,
      });
      const kills = () =>
        db.inspect.sandboxOperation.findMany({
          where: { sandboxId: s.sandbox.id, kind: "KILL_SANDBOX" },
          take: 2,
        });
      let [kill] = await kills();
      expect(await kills()).toHaveLength(1);
      expect(kill).toMatchObject({ state: "QUEUED", generation: 2, teardownIntent: null });
      const events = await db.inspect.outboxEvent.findMany({
        where: { aggregateId: s.sandbox.id, eventType: "sandbox.kill_requested" },
        take: 2,
      });
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        operationId: kill!.id,
        processedAt: null,
        payload: {
          operationId: kill!.id,
          generation: 2,
          kind: "sandbox.kill",
          credentialTeardown: "system",
          authorizingPrincipal: { kind: "system" },
        },
      });
      expect(await applyOperationResult(stopResult)).toEqual({ written: false });
      expect(await kills()).toHaveLength(1);

      // Exercise both real offload gates with deployment availability enabled:
      // neither the candidate scan nor a direct enqueue may export this root.
      const availability = await import("@wssp/api/sandbox/disk-offload/availability");
      const available = vi.spyOn(availability, "canOffload").mockReturnValue(true);
      try {
        const { enqueueOffload, offloadCandidates } = await import(
          "@wssp/api/sandbox/disk-offload/enqueue"
        );
        expect((await offloadCandidates()).some((c) => c.sandboxId === s.sandbox.id)).toBe(false);
        expect(
          await enqueueOffload({
            sandboxId: s.sandbox.id,
            userId: s.userId,
            generation: 2,
            hostId: s.host.id,
            hostOwnerId: s.userId,
            epoch: NOW,
          }),
        ).toBeNull();
      } finally {
        available.mockRestore();
      }
      expect(
        await db.inspect.sandboxDiskOffload.count({ where: { sandboxId: s.sandbox.id } }),
      ).toBe(0);

      await db.inspect.sandboxOperation.update({
        where: { id: kill!.id },
        data: {
          state: "ACCEPTED",
          dispatchAttempt: 1,
          acceptedAttempt: 1,
          dispatchedHostId: s.host.id,
          dispatchedConnectionEpoch: NOW,
        },
      });
      if (retry) {
        const failedKill = {
          sender: s.sender,
          operationId: kill!.id,
          sandboxId: s.sandbox.id,
          generation: kill!.generation,
          attempt: 1,
          state: "failed",
          error: { code: "host_capacity" as const, message: "host refused cleanup admission" },
        };
        expect(await applyOperationResult(failedKill)).toEqual({ written: true });
        expect(
          await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: kill!.id } }),
        ).toMatchObject({ state: "FAILED", errorCode: "host_capacity" });
        expect(await sandbox()).toMatchObject({
          state: "STOPPING",
          generation: 3,
          liveResourcesHeld: false,
          diskReservationHeld: true,
        });
        expect(await applyOperationResult(failedKill)).toEqual({ written: false });
        expect(await kills()).toHaveLength(2);
        kill = await db.inspect.sandboxOperation.findFirstOrThrow({
          where: { sandboxId: s.sandbox.id, kind: "KILL_SANDBOX", generation: 3 },
        });
        expect(kill).toMatchObject({ state: "QUEUED" });
        await db.inspect.sandboxOperation.update({
          where: { id: kill.id },
          data: {
            state: "ACCEPTED",
            dispatchAttempt: 1,
            acceptedAttempt: 1,
            dispatchedHostId: s.host.id,
            dispatchedConnectionEpoch: NOW,
          },
        });
      }
      const killResult = {
        sender: s.sender,
        operationId: kill!.id,
        sandboxId: s.sandbox.id,
        generation: kill!.generation,
        attempt: 1,
        state: "succeeded",
        result: { state: "deleted" },
      };
      expect(await applyOperationResult(killResult)).toEqual({ written: true });
      expect(await sandbox()).toMatchObject({
        state: "DELETED",
        generation: kill!.generation,
        liveResourcesHeld: false,
        diskReservationHeld: false,
        sandboxHostId: null,
        storagePoolId: null,
      });
      expect(
        await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: s.host.id } }),
      ).toMatchObject({
        liveCount: 0,
        rootCount: 0,
      });
      expect(
        await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({
          where: { id: s.sandbox.storagePoolId! },
        }),
      ).toMatchObject({ diskReservedGiB: 0 });
      expect(await applyOperationResult(killResult)).toEqual({ written: false });
    },
  );

  it("preserves STOPPED and its root when the sandbox previously reached READY", async () => {
    const s = await seed({ kind: "STOP_SANDBOX", state: "ACCEPTED" });
    await db.inspect.sandbox.update({
      where: { id: s.sandbox.id },
      data: { readyAt: new Date(0) },
    });
    expect(await s.adopt()).toBe(true);
    expect(
      await applyOperationResult({
        sender: s.sender,
        operationId: s.operation.id,
        sandboxId: s.sandbox.id,
        generation: 1,
        attempt: 1,
        state: "succeeded",
        result: { state: "absent" },
      }),
    ).toEqual({ written: true });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.sandbox.id } }),
    ).toMatchObject({
      state: "STOPPED",
      generation: 1,
      liveResourcesHeld: false,
      diskReservationHeld: true,
      sandboxHostId: s.host.id,
    });
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: s.sandbox.id, kind: "KILL_SANDBOX" },
      }),
    ).toBe(0);
  });
});

describe("minor 6: census settles an adopted stop", () => {
  it("the later live result is a no-op and the exact receipt confirms", async () => {
    const s = await seed({ kind: "STOP_SANDBOX", state: "ACCEPTED" });
    expect(await s.adopt()).toBe(true);
    const outcome = await convergeInventoryEntry(s.sender, {
      sandboxId: s.sandbox.id,
      state: "stopped",
    });
    expect(outcome).toMatchObject({ converged: true });
    expect((await s.row()).state).toBe("SUCCEEDED");
    const result = {
      sender: s.sender,
      operationId: s.operation.id,
      sandboxId: s.sandbox.id,
      generation: 1,
      attempt: 1,
      state: "succeeded",
      result: { state: "stopped" },
    };
    expect(await applyOperationResult(result)).toEqual({ written: false });
    const confirmed = await confirmOperationReceipt({
      ...result,
      written: false,
      receipt: { bodyHash: HASH, idempotencyKey: s.idempotencyKey, kind: "sandbox.stop" },
    });
    expect(confirmed).toMatchObject({ type: "receipt.confirmed", operationId: s.operation.id });
  });
});

describe("plan §10: an UNKNOWN command receipt retires without a sandbox stop", () => {
  const unknownReceipt = (s: Awaited<ReturnType<typeof seed>>, kind = "command.run") => ({
    sender: s.sender,
    operationId: s.operation.id,
    sandboxId: s.sandbox.id,
    generation: 1,
    attempt: 1,
    state: "unknown_outcome",
    error: { code: "unknown_outcome" as const, message: "unknown_outcome" },
    receipt: { bodyHash: HASH, idempotencyKey: s.idempotencyKey, kind },
  });
  const teardowns = (s: Awaited<ReturnType<typeof seed>>) =>
    db.inspect.sandboxOperation.count({
      where: { sandboxId: s.sandbox.id, kind: { in: ["STOP_SANDBOX", "KILL_SANDBOX"] } },
    });

  it("answers retireCommand on an unlimited lease; the row stays UNKNOWN and nothing stops", async () => {
    // A running command whose host lost it: the replayed receipt is UNKNOWN.
    const s = await seed({ state: "RUNNING", leaseExpiresAt: null });
    const input = unknownReceipt(s);
    const outbox = await db.inspect.outboxEvent.count({ where: { aggregateId: s.sandbox.id } });
    for (let reconnect = 0; reconnect < 2; reconnect += 1) {
      const outcome = await applyOperationResult(input);
      const confirmed = await confirmOperationReceipt({
        ...input,
        ...outcome,
      });
      expect(confirmed).toEqual({
        type: "receipt.confirmed",
        sandboxOwnerId: s.userId,
        operationId: s.operation.id,
        sandboxId: s.sandbox.id,
        generation: 1,
        attempt: 1,
        bodyHash: HASH,
        idempotencyKey: s.idempotencyKey,
        kind: "command.run",
        retireCommand: true,
      });
    }
    expect(await s.row()).toMatchObject({ state: "UNKNOWN_OUTCOME", errorCode: "unknown_outcome" });
    expect(await teardowns(s)).toBe(0);
    expect(await db.inspect.outboxEvent.count({ where: { aggregateId: s.sandbox.id } })).toBe(
      outbox,
    );
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.sandbox.id } }),
    ).toMatchObject({ state: "READY", leaseExpiresAt: null });
  });

  it("retires only the exact unknown command receipt", async () => {
    const s = await seed({ state: "UNKNOWN_OUTCOME", errorCode: "unknown_outcome" });
    const input = unknownReceipt(s);
    const outcome = await applyOperationResult(input);
    expect(
      await confirmOperationReceipt({
        ...input,
        ...outcome,
        receipt: { ...input.receipt, bodyHash: "c".repeat(64) },
      }),
    ).toBeNull();
    expect(
      await confirmOperationReceipt({
        ...input,
        ...outcome,
        sender: { ...s.sender, connectionEpoch: OLD - 1 },
      }),
    ).toBeNull();
    expect(await teardowns(s)).toBe(0);
    expect((await s.row()).state).toBe("UNKNOWN_OUTCOME");
  });

  it("never asks to retire another kind, nor a settled command", async () => {
    const put = await seed({
      kind: "PUT_FILE",
      state: "UNKNOWN_OUTCOME",
      errorCode: "unknown_outcome",
    });
    const input = unknownReceipt(put, "file.put");
    expect(await confirmOperationReceipt({ ...input, written: false })).toBeNull();
    const settled = await seed({ state: "FAILED", errorCode: "internal" });
    const confirmed = await confirmOperationReceipt({
      ...unknownReceipt(settled),
      written: false,
    });
    expect(confirmed).toMatchObject({ type: "receipt.confirmed" });
    expect(confirmed).not.toHaveProperty("retireCommand");
  });
});

describe("session frame rules", () => {
  let manager: InstanceType<
    typeof import("./session-manager.js").SandboxRelaySessionManager
  > | null = null;
  beforeEach(() => {
    manager = null;
  });
  afterEach(async () => {
    await manager?.dispose();
  });

  async function registered(reconcile: boolean) {
    const { SandboxRelaySessionManager } = await import("./session-manager.js");
    const s = await seed({ state: "RUNNING" });
    // The reconnecting hello bumps the host from NOW to NOW + 1.
    await db.inspect.sandboxHost.update({
      where: { id: s.host.id },
      data: { status: "DISCONNECTED" },
    });
    manager = new SandboxRelaySessionManager();
    const frames: Record<string, unknown>[] = [];
    let closed = false;
    const socket = {
      readyState: 1,
      send(data: string | ArrayBuffer | Uint8Array) {
        if (typeof data === "string") frames.push(JSON.parse(data));
      },
      close() {
        closed = true;
      },
    };
    manager.acceptAuthenticatedSocket({
      socket,
      identity: {
        hostId: s.host.id,
        userId: s.userId,
        tokenId: randomUUID(),
        credentialKind: "hostToken" as const,
        expiresAt: null,
      },
    });
    manager.handleTextFrame(socket, JSON.stringify(helloFixture(s.host.id, false)));
    await manager.drain(socket);
    manager.handleTextFrame(
      socket,
      JSON.stringify({
        type: "host.admission",
        vmCapacity: { memoryBudgetMiB: 65536, maxCpuCount: 32, vcpuBudget: 64 },
        storagePools: capacityFixture(s.host.id).storagePools,
        journalId: JOURNAL,
        connectionEpoch: NOW + 1,
        runtimeKind: "fake",
        schedulable: true,
        egressPolicy: true,
        terminal: false,
      }),
    );
    await manager.drain(socket);
    if (reconcile) {
      manager.handleTextFrame(
        socket,
        JSON.stringify({ type: "sandbox.inventory", page: 0, complete: true, entries: [] }),
      );
      manager.handleTextFrame(socket, JSON.stringify({ type: "reconcile.complete" }));
      await manager.drain(socket);
    }
    frames.length = 0;
    const frame = (patch: Record<string, unknown> = {}) =>
      JSON.stringify({
        type: "operation.adopt",
        sandboxOwnerId: s.userId,
        operationId: s.operation.id,
        sandboxId: s.sandbox.id,
        generation: 1,
        attempt: 1,
        bodyHash: HASH,
        idempotencyKey: s.idempotencyKey,
        kind: "command.run",
        phase: "effect",
        stdinNextSequence: null,
        ...patch,
      });
    return { s, socket, frames, frame, closed: () => closed };
  }

  it("answers operation.adopt.result before reconciliation", async () => {
    const r = await registered(false);
    manager!.handleTextFrame(r.socket, r.frame());
    await manager!.drain(r.socket);
    expect(r.frames).toContainEqual({
      type: "operation.adopt.result",
      operationId: r.s.operation.id,
      generation: 1,
      attempt: 1,
      adopted: true,
    });
    expect(r.closed()).toBe(false);
    expect(await r.s.row()).toMatchObject({ dispatchedConnectionEpoch: NOW + 1 });
  });

  it("pages the dispatch audit and requeues a never-received attempt", async () => {
    const r = await registered(false);
    await db.inspect.sandboxOperation.update({
      where: { id: r.s.operation.id },
      data: { state: "DISPATCHED", acceptedAttempt: null },
    });
    manager!.handleTextFrame(r.socket, JSON.stringify({ type: "dispatch.audit.request", page: 0 }));
    await manager!.drain(r.socket);
    const page = r.frames.find((f) => f.type === "dispatch.audit.page");
    expect(page).toMatchObject({
      page: 0,
      complete: true,
      entries: [expect.objectContaining({ operationId: r.s.operation.id, connectionEpoch: OLD })],
    });
    manager!.handleTextFrame(
      r.socket,
      JSON.stringify({
        type: "dispatch.audit.result",
        page: 0,
        entries: [{ operationId: r.s.operation.id, generation: 1, attempt: 1, received: false }],
      }),
    );
    await manager!.drain(r.socket);
    expect(r.closed()).toBe(false);
    expect((await r.s.row()).state).toBe("QUEUED");
  });

  it("a verdict for an attempt the server never offered is a protocol error", async () => {
    const r = await registered(false);
    manager!.handleTextFrame(r.socket, JSON.stringify({ type: "dispatch.audit.request", page: 0 }));
    await manager!.drain(r.socket);
    manager!.handleTextFrame(
      r.socket,
      JSON.stringify({
        type: "dispatch.audit.result",
        page: 0,
        entries: [{ operationId: r.s.operation.id, generation: 1, attempt: 1, received: false }],
      }),
    );
    await manager!.drain(r.socket);
    expect(r.frames.some((f) => f.type === "protocol.error")).toBe(true);
    expect((await r.s.row()).state).toBe("RUNNING");
  });

  it("an adoption after reconcile.complete is a protocol error", async () => {
    const r = await registered(true);
    manager!.handleTextFrame(r.socket, r.frame());
    await manager!.drain(r.socket);
    expect(r.frames.some((f) => f.type === "operation.adopt.result")).toBe(false);
    expect(r.frames.some((f) => f.type === "protocol.error")).toBe(true);
  });

  it("caps a session at 512 adoption frames", async () => {
    const r = await registered(false);
    // Batches stay under the receive-queue bound; the session counter does not.
    for (let i = 0; i < 513; i++) {
      manager!.handleTextFrame(r.socket, r.frame({ attempt: 100 + i }));
      if (i % 128 === 127) await manager!.drain(r.socket);
    }
    await manager!.drain(r.socket);
    expect(r.frames.filter((f) => f.type === "operation.adopt.result")).toHaveLength(512);
    expect(r.frames.some((f) => f.type === "protocol.error")).toBe(true);
  });
});

describe("reconnect dispatch audit (live finding B-1)", () => {
  const entryOf = (s: Awaited<ReturnType<typeof seed>>) => ({
    sender: s.sender,
    sandboxOwnerId: s.userId,
    operationId: s.operation.id,
    sandboxId: s.sandbox.id,
    generation: 1,
    attempt: 1,
    idempotencyKey: s.idempotencyKey,
    kind: s.wire,
  });

  it("lists only unacknowledged older-epoch attempts", async () => {
    const lost = await seed({ state: "DISPATCHED" });
    const page = await listUnacknowledgedDispatches(lost.sender, undefined, 64);
    expect(page.entries).toEqual([
      expect.objectContaining({ operationId: lost.operation.id, attempt: 1, connectionEpoch: OLD }),
    ]);
    for (const state of ["ACCEPTED", "RUNNING", "SUCCEEDED"] as const) {
      const other = await seed({ state });
      expect((await listUnacknowledgedDispatches(other.sender, undefined, 64)).entries).toEqual([]);
    }
    const adopted = await seed({ state: "DISPATCHED" });
    expect(await adopted.adopt()).toBe(true);
    expect((await listUnacknowledgedDispatches(adopted.sender, undefined, 64)).entries).toEqual([]);
  });

  it("a never-received command is dispatched again, never UNKNOWN", async () => {
    const s = await seed({ state: "DISPATCHED" });
    expect(await settleUndeliveredDispatch(entryOf(s))).toBe("requeued");
    expect(await s.row()).toMatchObject({ state: "QUEUED", dispatchAttempt: 1 });
    expect(await s.event(s.dispatch.id)).toMatchObject({
      processedAt: null,
      sentAt: null,
      claimToken: null,
    });
    // Reconciliation leaves it alone; idempotent: a replayed verdict is refused.
    expect(await finishHostReconciliation(s.sender)).toBe(true);
    expect((await s.row()).state).toBe("QUEUED");
    expect(await settleUndeliveredDispatch(entryOf(s))).toBe(false);
  });

  it("the processor then claims it as attempt + 1 on the new epoch", async () => {
    vi.resetModules();
    const sessionManager = {
      isHostConnected: vi.fn().mockReturnValue(true),
      dispatchOperation: vi.fn().mockResolvedValue("sent"),
      captureHostDispatchCredential: undefined,
    };
    vi.doMock("./session-manager.js", () => ({ sandboxRelaySessionManager: sessionManager }));
    const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
    vi.doUnmock("./session-manager.js");
    const s = await seed({ state: "DISPATCHED" });
    expect(await settleUndeliveredDispatch(entryOf(s))).toBe("requeued");
    await isolateOutbox(s.sandbox.id);
    await processSandboxOutboxBatch(() => new Date());
    expect(sessionManager.dispatchOperation).toHaveBeenCalledWith(
      s.host.id,
      expect.objectContaining({ operationId: s.operation.id, attempt: 2, connectionEpoch: NOW }),
    );
    expect(await s.row()).toMatchObject({
      state: "DISPATCHED",
      dispatchAttempt: 2,
      dispatchedConnectionEpoch: NOW,
    });
  });

  it("a cancel requested before receipt settles CANCELLED", async () => {
    const s = await seed({ state: "CANCEL_REQUESTED" });
    // Requested while still DISPATCHED: the host never acknowledged it.
    await db.inspect.sandboxOperation.update({
      where: { id: s.operation.id },
      data: { acceptedAttempt: null },
    });
    expect(await settleUndeliveredDispatch(entryOf(s))).toBe("cancelled");
    expect(await s.row()).toMatchObject({ state: "CANCELLED", errorCode: "cancelled" });
  });

  it("work a fresh dispatch would refuse settles FAILED host_effect_not_issued", async () => {
    const s = await seed({ state: "DISPATCHED", banned: true });
    expect(await settleUndeliveredDispatch(entryOf(s))).toBe("failed");
    expect(await s.row()).toMatchObject({ state: "FAILED", errorCode: "host_effect_not_issued" });
  });

  // E4-01: a frame an older daemon drops with its session is reported never
  // received on every reconnect; redelivery is bounded, then settled.
  it("bounds redelivery of a repeatedly undelivered attempt", async () => {
    const { UNDELIVERED_REDISPATCH_MAX_ATTEMPT } = await import("./operation-handlers");
    for (const [attempt, verdict] of [
      [UNDELIVERED_REDISPATCH_MAX_ATTEMPT - 1, "requeued"],
      [UNDELIVERED_REDISPATCH_MAX_ATTEMPT, "failed"],
    ] as const) {
      const s = await seed({ state: "DISPATCHED" });
      await db.inspect.sandboxOperation.update({
        where: { id: s.operation.id },
        data: { dispatchAttempt: attempt },
      });
      expect(await settleUndeliveredDispatch({ ...entryOf(s), attempt })).toBe(verdict);
      expect(await s.row()).toMatchObject(
        verdict === "failed"
          ? { state: "FAILED", errorCode: "host_effect_not_issued" }
          : { state: "QUEUED", dispatchAttempt: attempt },
      );
      if (verdict === "failed")
        expect(await s.event(s.dispatch.id)).toMatchObject({ processedAt: expect.any(Date) });
    }
  });

  it("WP5 groundwork: each strike is logged with the send-to-epoch-end age", async () => {
    const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
    try {
      const sentAt = new Date("2026-11-05T10:00:00.000Z");
      const s = await seed({ state: "DISPATCHED" });
      await db.inspect.sandboxOperation.update({
        where: { id: s.operation.id },
        data: { dispatchedAt: sentAt },
      });
      await db.inspect.sandboxHost.update({
        where: { id: s.host.id },
        data: { lastDisconnectedAt: new Date(sentAt.getTime() + 1_200) },
      });
      expect(await settleUndeliveredDispatch(entryOf(s))).toBe("requeued");
      expect(info).toHaveBeenLastCalledWith("[sandbox-relay] undelivered dispatch strike:", {
        code: "undelivered_dispatch_strike",
        kind: "command.run",
        attempt: 1,
        verdict: "requeued",
        sendToEpochEndMs: 1_200,
      });
      // More than one epoch ended since the send: the end time is unknown.
      const gap = await seed({ state: "DISPATCHED" });
      await db.inspect.sandboxHost.update({
        where: { id: gap.host.id },
        data: { connectionEpoch: NOW + 2, lastDisconnectedAt: new Date() },
      });
      expect(
        await settleUndeliveredDispatch({
          ...entryOf(gap),
          sender: { ...gap.sender, connectionEpoch: NOW + 2 },
        }),
      ).toBe("requeued");
      expect(info).toHaveBeenLastCalledWith(
        "[sandbox-relay] undelivered dispatch strike:",
        expect.objectContaining({ sendToEpochEndMs: null }),
      );
      // A refused verdict logs nothing.
      const calls = info.mock.calls.length;
      expect(await settleUndeliveredDispatch(entryOf(s))).toBe(false);
      expect(info.mock.calls.length).toBe(calls);
    } finally {
      info.mockRestore();
    }
  });

  it("a create is dispatched again with its journal lineage intact", async () => {
    const s = await seed({ kind: "CREATE_SANDBOX", state: "DISPATCHED" });
    expect(await settleUndeliveredDispatch(entryOf(s))).toBe("requeued");
    expect((await s.row()).state).toBe("QUEUED");
  });

  // Follow-up 11: a lifecycle op the host dropped with its session on every
  // attempt cycled the node for 37 minutes. Allocation redelivery is bounded:
  // it stays DISPATCHED for reconciliation (UNKNOWN, then attestation).
  // Teardown keeps requeueing until cleanup completes.
  it("bounds redelivery of a repeatedly undelivered lifecycle attempt", async () => {
    const { UNDELIVERED_REDISPATCH_MAX_ATTEMPT } = await import("./operation-handlers");
    for (const kind of ["CREATE_SANDBOX", "STOP_SANDBOX"] as const) {
      for (const attempt of [
        UNDELIVERED_REDISPATCH_MAX_ATTEMPT - 1,
        UNDELIVERED_REDISPATCH_MAX_ATTEMPT,
        UNDELIVERED_REDISPATCH_MAX_ATTEMPT + 3,
      ] as const) {
        const verdict =
          kind === "CREATE_SANDBOX" && attempt >= UNDELIVERED_REDISPATCH_MAX_ATTEMPT
            ? false
            : "requeued";
        const s = await seed({ kind, state: "DISPATCHED" });
        await db.inspect.sandboxOperation.update({
          where: { id: s.operation.id },
          data: { dispatchAttempt: attempt },
        });
        expect(await settleUndeliveredDispatch({ ...entryOf(s), attempt }), kind).toBe(verdict);
        expect(await s.row()).toMatchObject(
          verdict === false
            ? { state: "DISPATCHED", dispatchAttempt: attempt, errorCode: null }
            : { state: "QUEUED", dispatchAttempt: attempt },
        );
      }
    }
  });

  it("refuses acknowledged, superseded, mismatched and current-epoch attempts", async () => {
    for (const state of ["ACCEPTED", "RUNNING"] as const) {
      const s = await seed({ state });
      expect(await settleUndeliveredDispatch(entryOf(s))).toBe(false);
    }
    const superseded = await seed({ state: "CANCEL_REQUESTED", errorCode: "superseded" });
    expect(await settleUndeliveredDispatch(entryOf(superseded))).toBe(false);
    const s = await seed({ state: "DISPATCHED" });
    for (const patch of [
      { attempt: 2 },
      { generation: 2 },
      { idempotencyKey: "other" },
      { sender: { ...s.sender, connectionEpoch: OLD } },
      { sender: { ...s.sender, isCurrent: () => false } },
    ])
      expect(
        await settleUndeliveredDispatch({ ...entryOf(s), ...patch }),
        JSON.stringify(patch),
      ).toBe(false);
    expect((await s.row()).state).toBe("DISPATCHED");
    // A kill committed first wins: the generation CAS refuses.
    await db.inspect.sandbox.update({
      where: { id: s.sandbox.id },
      data: { generation: 2, state: "STOPPING" },
    });
    expect(await settleUndeliveredDispatch(entryOf(s))).toBe(false);
  });
});

describe("dead uncertain receipts (live finding B-5)", () => {
  it("an UNKNOWN receipt replay never re-binds an UNKNOWN row to the new epoch", async () => {
    const s = await seed({ state: "UNKNOWN_OUTCOME", errorCode: "unknown_outcome" });
    expect(
      await applyOperationResult({
        sender: s.sender,
        operationId: s.operation.id,
        sandboxId: s.sandbox.id,
        generation: 1,
        attempt: 1,
        state: "unknown_outcome",
        error: { code: "unknown_outcome", message: "x" },
        receipt: { bodyHash: HASH, idempotencyKey: s.idempotencyKey, kind: "command.run" },
      }),
    ).toEqual({ written: false });
    expect(await s.row()).toMatchObject({
      state: "UNKNOWN_OUTCOME",
      dispatchedConnectionEpoch: OLD,
    });
  });
});

describe("WP6: file.put proven not issued is requeued while its source is retained", () => {
  const SHA = "c".repeat(64);
  /** The committed upload's durable source, bound to the PUT_FILE operation. */
  async function upload(
    patch: { attempt?: number; transfer?: Record<string, unknown>; epoch?: number } = {},
  ) {
    const s = await seed({ kind: "PUT_FILE", state: "DISPATCHED" });
    await db.inspect.sandboxOperation.update({
      where: { id: s.operation.id },
      data: {
        dispatchAttempt: patch.attempt ?? 1,
        dispatchedConnectionEpoch: patch.epoch ?? OLD,
        dispatchedAt: new Date(),
      },
    });
    await db.inspect.sandboxTransfer.create({
      data: {
        id: `tr-${s.operation.id}`,
        userId: s.userId,
        sandboxId: s.sandbox.id,
        acceptedHostId: s.sandbox.sandboxHostId!,
        generation: 1,
        direction: "UPLOAD",
        guestPath: "/tmp/upload",
        idempotencyKey: `upload-${s.operation.id}`,
        requestBodyHash: HASH,
        totalBytes: 1n,
        receivedBytes: 1n,
        state: "SEALED",
        sha256: SHA,
        operationId: s.operation.id,
        idleExpiresAt: new Date(Date.now() + 600_000),
        expiresAt: new Date(Date.now() + 3_600_000),
        ...patch.transfer,
      },
    });
    const notIssued = (attempt = patch.attempt ?? 1, receipt = true) => ({
      sender: s.sender,
      operationId: s.operation.id,
      sandboxId: s.sandbox.id,
      generation: 1,
      attempt,
      state: "failed",
      error: { code: "host_effect_not_issued" as const, message: "upload interrupted" },
      ...(receipt
        ? { receipt: { bodyHash: HASH, idempotencyKey: s.idempotencyKey, kind: "file.put" } }
        : {}),
    });
    return { ...s, notIssued };
  }

  it("requeues the receipt's attempt, confirms it in the same transaction and reopens the intent", async () => {
    const s = await upload();
    const input = s.notIssued();
    const outcome = await applyOperationResult(input);
    expect(outcome).toEqual({
      written: true,
      requeued: {
        type: "receipt.confirmed",
        sandboxOwnerId: s.userId,
        operationId: s.operation.id,
        sandboxId: s.sandbox.id,
        generation: 1,
        attempt: 1,
        bodyHash: HASH,
        idempotencyKey: s.idempotencyKey,
        kind: "file.put",
      },
    });
    expect(await s.row()).toMatchObject({
      state: "QUEUED",
      dispatchAttempt: 1,
      dispatchedConnectionEpoch: NOW,
      errorCode: null,
      completedAt: null,
    });
    expect(await s.event(s.dispatch.id)).toMatchObject({
      processedAt: null,
      sentAt: null,
      claimToken: null,
      sentConnectionEpoch: null,
    });
    // The confirmation the host needs to drop its receipt before attempt 2.
    expect(await confirmOperationReceipt({ ...input, ...outcome })).toEqual(outcome.requeued);
    // The source stays retained and the slot stays held (not a settlement).
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: `tr-${s.operation.id}` } }),
    ).toMatchObject({ state: "SEALED", reservationHeld: true });
    // Reconciliation leaves the queued put alone; a replayed receipt is refused.
    expect(await finishHostReconciliation(s.sender)).toBe(true);
    expect((await s.row()).state).toBe("QUEUED");
    expect(await applyOperationResult(s.notIssued())).toEqual({ written: false });
  });

  it("the processor then claims it as attempt + 1 on the new epoch", async () => {
    vi.resetModules();
    const sessionManager = {
      isHostConnected: vi.fn().mockReturnValue(true),
      dispatchOperation: vi.fn().mockResolvedValue("sent"),
      reserveFileStreamSlot: vi.fn(() => ({ release: () => {} })),
      captureHostDispatchCredential: undefined,
    };
    const uploadSource = vi.fn(async () => ({ size: 1, sha256: SHA, read: async () => [] }));
    vi.doMock("./session-manager.js", () => ({ sandboxRelaySessionManager: sessionManager }));
    vi.doMock("../sandbox-transfers/runtime.js", () => ({
      transferStore: () => ({ uploadSource }),
    }));
    const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
    vi.doUnmock("./session-manager.js");
    vi.doUnmock("../sandbox-transfers/runtime.js");
    const s = await upload();
    expect((await applyOperationResult(s.notIssued())).requeued).toBeDefined();
    await isolateOutbox(s.sandbox.id);
    await processSandboxOutboxBatch(() => new Date());
    expect(uploadSource).toHaveBeenCalledWith(`tr-${s.operation.id}`, s.operation.id);
    expect(sessionManager.dispatchOperation).toHaveBeenCalledWith(
      s.host.id,
      expect.objectContaining({
        operationId: s.operation.id,
        kind: "file.put",
        attempt: 2,
        connectionEpoch: NOW,
      }),
    );
    expect(await s.row()).toMatchObject({
      state: "DISPATCHED",
      dispatchAttempt: 2,
      dispatchedConnectionEpoch: NOW,
    });
  });

  it("a live result on the current epoch requeues too", async () => {
    const s = await upload({ epoch: NOW });
    const outcome = await applyOperationResult(s.notIssued(1, false));
    expect(outcome.requeued).toMatchObject({ attempt: 1, kind: "file.put" });
    expect(await s.row()).toMatchObject({ state: "QUEUED", dispatchAttempt: 1 });
  });

  it("caps requeues at 3 per operation: attempt 4 settles FAILED as before", async () => {
    for (const [attempt, requeued] of [
      [FILE_PUT_REQUEUE_MAX_ATTEMPT - 1, true],
      [FILE_PUT_REQUEUE_MAX_ATTEMPT, false],
    ] as const) {
      const s = await upload({ attempt });
      const outcome = await applyOperationResult(s.notIssued());
      expect(outcome.requeued !== undefined, `attempt ${attempt}`).toBe(requeued);
      expect(outcome.written).toBe(true);
      expect(await s.row()).toMatchObject(
        requeued
          ? { state: "QUEUED", dispatchAttempt: attempt }
          : { state: "FAILED", errorCode: "host_effect_not_issued", dispatchAttempt: attempt },
      );
      if (!requeued)
        expect(await s.event(s.dispatch.id)).toMatchObject({ processedAt: expect.any(Date) });
    }
  });

  it("settles FAILED when the source is no longer retained", async () => {
    const past = new Date(Date.now() - 1_000);
    for (const transfer of [
      { state: "EXPIRED", reservationHeld: false },
      { reservationHeld: false },
      { idleExpiresAt: past },
      { expiresAt: past, idleExpiresAt: past },
      { generation: 2 },
    ]) {
      const s = await upload({ transfer });
      const outcome = await applyOperationResult(s.notIssued());
      expect(outcome, JSON.stringify(transfer)).toEqual({ written: true });
      expect(await s.row()).toMatchObject({ state: "FAILED", errorCode: "host_effect_not_issued" });
    }
    // No transfer row at all.
    const bare = await seed({ kind: "PUT_FILE", state: "DISPATCHED" });
    expect(
      await applyOperationResult({
        sender: bare.sender,
        operationId: bare.operation.id,
        sandboxId: bare.sandbox.id,
        generation: 1,
        attempt: 1,
        state: "failed",
        error: { code: "host_effect_not_issued", message: "x" },
        receipt: { bodyHash: HASH, idempotencyKey: bare.idempotencyKey, kind: "file.put" },
      }),
    ).toEqual({ written: true });
    expect((await bare.row()).state).toBe("FAILED");
  });

  it("other failures, cancels and UNKNOWN rows settle exactly as before", async () => {
    const other = await upload();
    expect(
      await applyOperationResult({
        ...other.notIssued(),
        error: { code: "guest_unavailable", message: "x" },
      }),
    ).toEqual({ written: true });
    expect(await other.row()).toMatchObject({ state: "FAILED", errorCode: "guest_unavailable" });
    for (const state of ["CANCEL_REQUESTED", "UNKNOWN_OUTCOME"] as const) {
      const s = await upload();
      await db.inspect.sandboxOperation.update({ where: { id: s.operation.id }, data: { state } });
      const outcome = await applyOperationResult(s.notIssued());
      expect(outcome.requeued, state).toBeUndefined();
      expect((await s.row()).state, state).toBe("FAILED");
    }
  });
});
