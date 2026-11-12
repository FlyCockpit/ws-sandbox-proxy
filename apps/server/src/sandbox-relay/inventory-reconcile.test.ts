vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { relayDispatchKind } from "@wssp/api/sandbox/contracts";
import { lockWorkAdmissionHost } from "@wssp/api/sandbox/host-admission";
import {
  inventoryObservationIdempotencyKey,
  leaseExpiryIdempotencyKey,
} from "@wssp/api/sandbox/lease";
import prisma from "@wssp/db";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createFenceStore,
  type FenceStore,
  installFenceTransaction,
  type OperationRow,
  type OutboxRow,
  type SandboxRow,
} from "./fenced-prisma-harness.js";
import {
  convergeInventoryEntry,
  InventoryCensus,
  judgeExpiryStatus,
} from "./inventory-reconcile.js";
import { ObservationFence } from "./observation-fence.js";
import { applyOperationResult, finishHostReconciliation } from "./operation-handlers.js";
import type { InventoryEntry } from "./protocol.js";

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
const NOW = new Date("2030-01-01T00:00:00.000Z");
const clock = () => NOW;
const PAST = NOW.getTime() - 60_000;
const FUTURE = NOW.getTime() + 3_600_000;
const sender = (connectionEpoch = 2) => ({ userId: "user-1", hostId: "host-1", connectionEpoch });

let store: FenceStore;
function setup(init: {
  sandboxes?: Partial<SandboxRow>[];
  operations?: OperationRow[];
  outbox?: OutboxRow[];
  host?: Record<string, unknown>;
}) {
  store = createFenceStore({
    hosts: [
      {
        id: "host-1",
        userId: "user-1",
        connectionEpoch: 2,
        liveCount: init.sandboxes?.filter((row) => row.liveResourcesHeld !== false).length ?? 0,
        inventorySeq: 0,
        inventoryAcknowledgedAt: null,
        quarantinedAt: null,
        quarantineReason: null,
        draining: false,
        ...init.host,
      },
      { id: "host-2", userId: "user-1", connectionEpoch: 1 },
    ],
    sandboxes: (init.sandboxes ?? []).map((row) => ({
      id: "sbx-1",
      userId: "user-1",
      state: "READY",
      generation: 1,
      sandboxHostId: "host-1",
      originHostId: "host-1",
      liveResourcesHeld: true,
      diskReservationHeld: false,
      leaseRevision: 1,
      leaseRevisionEffective: null,
      leaseExpiresAtEffective: null,
      leaseExpireActionEffective: null,
      hostExpiryConfirmedAt: null,
      hostExpiryRevision: null,
      hostExpiryAction: null,
      ...row,
    })),
    operations: init.operations,
    outbox: init.outbox,
  });
  installFenceTransaction(db, store);
}

const hostLease = (
  input: Partial<{
    generation: number;
    revision: number;
    deadline: number;
    action: "stop" | "destroy";
    expired: boolean;
    complete: boolean;
    timer: boolean;
    failure: string;
  }> = {},
): NonNullable<InventoryEntry["lease"]> => ({
  generation: input.generation ?? 1,
  lease: {
    revision: input.revision ?? 1,
    deadlineUnixMs: input.deadline ?? FUTURE,
    action: input.action ?? "stop",
    expiryPolicy: "retry-force-60s",
  },
  expired: input.expired ?? false,
  expiryComplete: input.complete ?? input.expired ?? false,
  timerExpired: input.timer ?? input.expired ?? false,
  ...(input.failure
    ? { expiryFailure: { reason: input.failure, attempts: 2, sinceUnixMs: PAST } }
    : {}),
});
const effective = (deadline: number, action: "STOP" | "DESTROY" = "STOP", revision = 1) => ({
  leaseRevisionEffective: revision,
  leaseExpiresAtEffective: new Date(deadline),
  leaseExpireActionEffective: action,
});
const page = (n: number, entries: InventoryEntry[], complete = true) => ({
  type: "sandbox.inventory" as const,
  page: n,
  complete,
  entries,
});
const sandbox = (id = "sbx-1") => store.sandboxes.get(id)!;
const host = () => store.hosts.get("host-1")!;
const operationsFor = (id = "sbx-1") =>
  [...store.operations.values()].filter((row) => row.sandboxId === id);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("census pagination and completeness", () => {
  it("rejects out-of-order pages, non-ascending ids and pages after completion", async () => {
    setup({ sandboxes: [{ id: "sbx-a" }, { id: "sbx-b" }] });
    const census = new InventoryCensus(sender(), clock);
    await expect(census.acceptPage(page(1, [], false))).rejects.toThrow(/out of order/);
    await census.acceptPage(
      page(
        0,
        [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-b", state: "ready" }],
        false,
      ),
    );
    await expect(
      census.acceptPage(
        page(1, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-a", state: "ready" }]),
      ),
    ).rejects.toThrow(/ascending/);
    await census.acceptPage(page(1, []));
    expect(census.complete).toBe(true);
    await expect(census.acceptPage(page(2, []))).rejects.toThrow(/after completion/);
  });

  it("concludes nothing from silence until the final page, then reports the instance missing", async () => {
    setup({ sandboxes: [{ id: "sbx-a" }, { id: "sbx-b" }, { id: "sbx-c" }] });
    const census = new InventoryCensus(sender(), clock);
    await census.acceptPage(
      page(
        0,
        [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-b", state: "ready" }],
        false,
      ),
    );
    // sbx-a was skipped inside page 0 and sbx-c is beyond it: both still READY.
    expect([sandbox("sbx-a").state, sandbox("sbx-c").state]).toEqual(["READY", "READY"]);
    expect(host().inventorySeq).toBe(0);

    await census.acceptPage(page(1, []));
    for (const id of ["sbx-a", "sbx-c"]) {
      expect(sandbox(id)).toMatchObject({
        state: "ERROR",
        generation: 2,
        liveResourcesHeld: false,
        lastErrorCode: "instance_missing",
        sandboxHostId: "host-1",
      });
      // Absence alone never proves a destroy: no lifecycle operation is invented.
      expect(operationsFor(id)).toHaveLength(0);
    }
    expect(sandbox("sbx-b")).toMatchObject({
      state: "READY",
      generation: 1,
      liveResourcesHeld: true,
    });
    expect(host()).toMatchObject({
      liveCount: 1,
      inventorySeq: 1,
      inventoryAcknowledgedAt: expect.any(Date),
    });
  });

  it("an abandoned partial census (socket loss) concludes nothing", async () => {
    setup({ sandboxes: [{ id: "sbx-a" }, { id: "sbx-b" }] });
    const census = new InventoryCensus(sender(), clock);
    await census.acceptPage(
      page(
        0,
        [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-b", state: "ready" }],
        false,
      ),
    );
    expect(sandbox("sbx-a")).toMatchObject({ state: "READY", liveResourcesHeld: true });
    expect(host()).toMatchObject({ liveCount: 2, inventorySeq: 0 });
  });

  it("a census from a superseded connection epoch writes nothing", async () => {
    setup({ sandboxes: [{ id: "sbx-a", state: "READY" }] });
    const census = new InventoryCensus(sender(1), clock);
    expect(
      await census.acceptPage(
        page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-a", state: "stopped" }]),
      ),
    ).toEqual({
      stale: true,
    });
    expect(sandbox("sbx-a")).toMatchObject({ state: "READY", liveResourcesHeld: true });
    expect(host().inventorySeq).toBe(0);
  });
});

describe("lifecycle convergence on proof", () => {
  it("a stopped READY sandbox converges STOPPED, releases capacity once and stays listed", async () => {
    setup({ sandboxes: [{}] });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "stopped" }]),
    );
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      generation: 2,
      liveResourcesHeld: false,
      sandboxHostId: "host-1",
      hostExpiryConfirmedAt: null,
    });
    const [operation] = operationsFor();
    expect(operation).toMatchObject({
      kind: "STOP_SANDBOX",
      state: "SUCCEEDED",
      generation: 2,
      idempotencyKey: inventoryObservationIdempotencyKey("sbx-1", 2),
    });
    expect(host().liveCount).toBe(0);

    // Server restart / reconnect replays the census: nothing changes again.
    store.hosts.get("host-1")!.connectionEpoch = 3;
    await new InventoryCensus(sender(3), clock).acceptPage(
      page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "stopped" }]),
    );
    expect(sandbox()).toMatchObject({ state: "STOPPED", generation: 2 });
    expect(operationsFor()).toHaveLength(1);
    expect(host()).toMatchObject({ liveCount: 0, inventorySeq: 2 });
  });

  it("a host-verified destroy expiry converges DELETED with offline expiry truth", async () => {
    setup({ sandboxes: [{ ...effective(PAST, "DESTROY") }] });
    const entry = {
      sandboxOwnerId: "user-1",
      root: null,
      sandboxId: "sbx-1",
      state: "absent" as const,
      lease: hostLease({ deadline: PAST, action: "destroy", expired: true }),
    };
    await new InventoryCensus(sender(), clock).acceptPage(page(0, [entry]));
    expect(sandbox()).toMatchObject({
      state: "DELETED",
      generation: 2,
      liveResourcesHeld: false,
      sandboxHostId: null,
      hostExpiryConfirmedAt: NOW,
      hostExpiryRevision: 1,
    });
    expect(operationsFor()).toEqual([
      expect.objectContaining({
        kind: "KILL_SANDBOX",
        state: "SUCCEEDED",
        idempotencyKey: leaseExpiryIdempotencyKey("sbx-1", 2, 1, "DESTROY"),
      }),
    ]);
    expect(host().liveCount).toBe(0);

    // The detached tombstone is no longer the host's; a replayed absence is a no-op.
    expect(await convergeInventoryEntry(sender(), entry, clock)).toEqual({ converged: false });
    expect(
      await convergeInventoryEntry(
        sender(),
        { sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "stopped" },
        clock,
      ),
    ).toEqual({ conflict: "deleted_instance_present" });
  });

  it("absence under an unexpired or stop lease is never promoted to DELETED", async () => {
    setup({ sandboxes: [{ ...effective(FUTURE, "DESTROY") }] });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [
        {
          sandboxOwnerId: "user-1",
          root: null,
          sandboxId: "sbx-1",
          state: "absent",
          lease: hostLease({ action: "destroy", deadline: FUTURE }),
        },
      ]),
    );
    expect(sandbox()).toMatchObject({ state: "ERROR", lastErrorCode: "instance_missing" });
    expect(sandbox().sandboxHostId).toBe("host-1");
    expect(sandbox().hostExpiryConfirmedAt).toBeNull();
  });

  it("a server-side expiry queued while offline is completed by the host's stop, never redispatched", async () => {
    const key = leaseExpiryIdempotencyKey("sbx-1", 2, 1, "STOP");
    setup({
      sandboxes: [{ state: "STOPPING", generation: 2, ...effective(PAST) }],
      operations: [
        {
          id: "op-expire",
          userId: "user-1",
          sandboxId: "sbx-1",
          kind: "STOP_SANDBOX",
          state: "QUEUED",
          generation: 2,
          dispatchAttempt: 0,
          dispatchedHostId: null,
          dispatchedConnectionEpoch: null,
          idempotencyKey: key,
        },
      ],
      outbox: [
        {
          id: "evt-expire",
          userId: "user-1",
          aggregateType: "sandbox",
          aggregateId: "sbx-1",
          processedAt: null,
          payload: { operationId: "op-expire", generation: 2 },
        },
      ],
    });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [
        {
          sandboxOwnerId: "user-1",
          root: null,
          sandboxId: "sbx-1",
          state: "stopped",
          lease: hostLease({ deadline: PAST, expired: true }),
        },
      ]),
    );
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      generation: 2,
      liveResourcesHeld: false,
      hostExpiryConfirmedAt: NOW,
      hostExpiryRevision: 1,
    });
    expect(operationsFor()).toEqual([
      expect.objectContaining({
        id: "op-expire",
        state: "SUCCEEDED",
        result: { state: "stopped" },
      }),
    ]);
    expect(store.outbox.get("evt-expire")?.processedAt).toEqual(NOW);
    expect(host().liveCount).toBe(0);
  });

  it("a pending kill dispatched in an earlier epoch is completed by absence; its late result changes nothing", async () => {
    setup({
      sandboxes: [{ state: "RECLAIMING", generation: 2 }],
      operations: [
        {
          id: "op-kill",
          userId: "user-1",
          sandboxId: "sbx-1",
          kind: "KILL_SANDBOX",
          state: "ACCEPTED",
          generation: 2,
          dispatchAttempt: 1,
          dispatchedHostId: "host-1",
          dispatchedConnectionEpoch: 1,
          idempotencyKey: "user-kill",
        },
      ],
    });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "absent" }]),
    );
    expect(sandbox()).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      liveResourcesHeld: false,
    });
    expect(store.operations.get("op-kill")).toMatchObject({ state: "SUCCEEDED" });
    expect(host().liveCount).toBe(0);

    const late = await applyOperationResult(
      {
        sender: sender(),
        operationId: "op-kill",
        sandboxId: "sbx-1",
        generation: 2,
        attempt: 1,
        state: "failed",
        error: { code: "guest_operation_failed", message: "late" },
      },
      clock,
    );
    expect(late.written).toBe(false);
    expect(sandbox()).toMatchObject({ state: "DELETED", sandboxHostId: null });
    expect(store.operations.get("op-kill")).toMatchObject({ state: "SUCCEEDED" });
  });

  it("a late running report cannot resurrect a converged STOPPED sandbox", async () => {
    setup({ sandboxes: [{ state: "STOPPED", generation: 2, liveResourcesHeld: false }] });
    expect(
      await convergeInventoryEntry(
        sender(),
        {
          sandboxOwnerId: "user-1",
          root: null,
          sandboxId: "sbx-1",
          state: "ready",
          lease: hostLease(),
        },
        clock,
      ),
    ).toEqual({ converged: false });
    expect(sandbox()).toMatchObject({ state: "STOPPED", generation: 2, liveResourcesHeld: false });
  });

  it("an uncertain create or reconnect blocks every inference for that sandbox", async () => {
    setup({
      sandboxes: [{ state: "STOPPED", generation: 2, liveResourcesHeld: true }],
      operations: [
        {
          id: "op-reconnect",
          userId: "user-1",
          sandboxId: "sbx-1",
          kind: "RECONNECT_SANDBOX",
          state: "UNKNOWN_OUTCOME",
          generation: 2,
          dispatchAttempt: 1,
          dispatchedHostId: "host-1",
        },
      ],
    });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "absent" }]),
    );
    expect(sandbox()).toMatchObject({ state: "STOPPED", generation: 2, liveResourcesHeld: true });
    expect(store.operations.get("op-reconnect")?.state).toBe("UNKNOWN_OUTCOME");
    expect(host().liveCount).toBe(1);
  });

  it("two full stop/reconnect cycles converge exactly once each", async () => {
    setup({ sandboxes: [{}] });
    for (const [epoch, generation] of [
      [2, 2],
      [3, 4],
    ] as const) {
      store.hosts.get("host-1")!.connectionEpoch = epoch;
      await new InventoryCensus(sender(epoch), clock).acceptPage(
        page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "stopped" }]),
      );
      expect(sandbox()).toMatchObject({ state: "STOPPED", generation, liveResourcesHeld: false });
      // A reconnect that the host acknowledged running again.
      Object.assign(store.sandboxes.get("sbx-1")!, {
        state: "READY",
        generation: generation + 1,
        liveResourcesHeld: true,
      });
      store.hosts.get("host-1")!.liveCount = 1;
      store.hosts.get("host-1")!.memoryReservedMiB = 1344;
      store.hosts.get("host-1")!.vcpuReserved = 1;
    }
    expect(operationsFor().map((row) => row.idempotencyKey)).toEqual([
      inventoryObservationIdempotencyKey("sbx-1", 2),
      inventoryObservationIdempotencyKey("sbx-1", 4),
    ]);
  });
});

describe("lease receipts", () => {
  it("adopts a lease whose ACK was lost from the immutable dispatch payload", async () => {
    setup({
      sandboxes: [{ leaseRevision: 2, ...effective(FUTURE, "STOP", 1) }],
      operations: [op({ id: "op-renew", kind: "RENEW_SANDBOX_LEASE", state: "SUCCEEDED" })],
      outbox: [
        {
          id: "evt-renew",
          userId: "user-1",
          aggregateType: "sandbox",
          aggregateId: "sbx-1",
          processedAt: NOW,
          payload: {
            operationId: "op-renew",
            idempotencyKey: "key-op-renew",
            generation: 1,
            lease: {
              revision: 2,
              deadlineUnixMs: FUTURE + 1000,
              action: "destroy",
              expiryPolicy: "retry-force-60s",
            },
          },
        },
      ],
    });
    const entry = {
      sandboxOwnerId: "user-1",
      root: null,
      sandboxId: "sbx-1",
      state: "ready" as const,
      lease: hostLease({ revision: 2, deadline: FUTURE + 1000, action: "destroy" }),
    };
    expect(await convergeInventoryEntry(sender(), entry, clock)).toEqual({ converged: true });
    expect(sandbox()).toMatchObject({
      state: "READY",
      leaseRevisionEffective: 2,
      leaseExpiresAtEffective: new Date(FUTURE + 1000),
      leaseExpireActionEffective: "DESTROY",
    });
    // Replaying the same receipt adopts nothing; an older one never regresses.
    expect(await convergeInventoryEntry(sender(), entry, clock)).toEqual({ converged: false });
    expect(
      await convergeInventoryEntry(
        sender(),
        {
          sandboxOwnerId: "user-1",
          root: null,
          sandboxId: "sbx-1",
          state: "ready",
          lease: hostLease({ revision: 1 }),
        },
        clock,
      ),
    ).toEqual({ conflict: "lease_regressed" });
    expect(sandbox().leaseRevisionEffective).toBe(2);
  });

  it("an unverifiable lease tuple (payload pruned) is not adopted and proves no expiry", async () => {
    setup({ sandboxes: [{ leaseRevision: 2, ...effective(FUTURE, "STOP", 1) }] });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [
        {
          sandboxOwnerId: "user-1",
          root: null,
          sandboxId: "sbx-1",
          state: "absent",
          lease: hostLease({ revision: 2, deadline: PAST, action: "destroy", expired: true }),
        },
      ]),
    );
    expect(sandbox()).toMatchObject({
      state: "ERROR",
      leaseRevisionEffective: 1,
      hostExpiryConfirmedAt: null,
      sandboxHostId: "host-1",
    });
  });
});

describe("identity and lease conflicts are contained to their sandbox (E3-A-01)", () => {
  const cases: [string, Partial<SandboxRow>[], InventoryEntry, string][] = [
    [
      "unknown sandbox",
      [],
      { sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-x", state: "ready" },
      "unknown_sandbox",
    ],
    [
      "foreign sandbox",
      [{ sandboxHostId: "host-2" }],
      { sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "ready" },
      "foreign_sandbox",
    ],
    [
      "generation ahead",
      [{}],
      {
        sandboxOwnerId: "user-1",
        root: null,
        sandboxId: "sbx-1",
        state: "ready",
        lease: hostLease({ generation: 2 }),
      },
      "generation_ahead",
    ],
    [
      "lease revision ahead",
      [{}],
      {
        sandboxOwnerId: "user-1",
        root: null,
        sandboxId: "sbx-1",
        state: "ready",
        lease: hostLease({ revision: 2 }),
      },
      "lease_ahead",
    ],
    [
      "same revision, different deadline",
      [{ ...effective(FUTURE) }],
      {
        sandboxOwnerId: "user-1",
        root: null,
        sandboxId: "sbx-1",
        state: "stopped",
        lease: hostLease({ deadline: FUTURE + 1 }),
      },
      "lease_mismatch",
    ],
  ];
  it.each(cases)("%s", async (_name, sandboxes, entry, reason) => {
    setup({ sandboxes });
    const before = structuredClone([...store.sandboxes.values()]);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const census = new InventoryCensus(sender(), clock);
    expect(await census.acceptPage(page(0, [entry]))).toEqual({ ok: true });
    // The census completes and the node is not quarantined; the entry
    // concluded nothing about its sandbox, and the reason is logged.
    expect(census.complete).toBe(true);
    expect(census.contained).toEqual([{ sandboxId: entry.sandboxId, reason }]);
    expect(host()).toMatchObject({ quarantinedAt: null, quarantineReason: null, inventorySeq: 1 });
    expect([...store.sandboxes.values()]).toEqual(before);
    expect(store.operations.size).toBe(0);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining(`sandbox=${entry.sandboxId} reason=${reason}`),
    );
    warn.mockRestore();
  });

  it("a deleted sandbox's VM still present is contained: one charged, queued destroy, no quarantine", async () => {
    setup({
      sandboxes: [
        { state: "DELETED", sandboxHostId: null, hostOwnerId: "user-1", liveResourcesHeld: false },
      ],
    });
    const placement = store.placements.get("placement:sbx-1")!;
    placement.originHostId = "host-1";
    placement.storagePoolId = "storage:host-1";
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const entry = { sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "stopped" };
    for (const _report of [1, 2]) {
      const census = new InventoryCensus(sender(), clock);
      expect(await census.acceptPage(page(0, [entry as InventoryEntry]))).toEqual({ ok: true });
      expect(census.complete).toBe(true);
      expect(census.contained).toEqual([
        { sandboxId: "sbx-1", reason: "deleted_instance_present" },
      ]);
    }
    // The node keeps taking work; the remnant's boot charge is counted on it.
    expect(host()).toMatchObject({ quarantinedAt: null, quarantineReason: null, liveCount: 1 });
    expect(host().memoryReservedMiB).toBe(placement.chargedMemoryMiB);
    expect(sandbox()).toMatchObject({
      state: "DELETED",
      generation: 2,
      sandboxHostId: "host-1",
      liveResourcesHeld: true,
    });
    // Repeated reports keep exactly one obligation.
    expect(operationsFor()).toEqual([
      expect.objectContaining({
        kind: "KILL_SANDBOX",
        state: "QUEUED",
        generation: 2,
        idempotencyKey: inventoryObservationIdempotencyKey("sbx-1", 2),
      }),
    ]);
    expect([...store.outbox.values()]).toEqual([
      expect.objectContaining({
        eventType: "sandbox.kill_requested",
        payload: expect.objectContaining({ sandboxHostId: "host-1", generation: 2 }),
      }),
    ]);
    // A later census proving absence releases the charge and detaches again.
    await new InventoryCensus(sender(), clock).acceptPage(page(0, []));
    expect(sandbox()).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      liveResourcesHeld: false,
    });
    expect(host()).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
    expect(operationsFor()).toEqual([
      expect.objectContaining({ kind: "KILL_SANDBOX", state: "SUCCEEDED", generation: 2 }),
    ]);
    warn.mockRestore();
  });

  it("refuses new work on a quarantined host and clears on a clean complete census", async () => {
    setup({
      sandboxes: [{}],
      host: { quarantinedAt: new Date(PAST), quarantineReason: "unknown_sandbox" },
    });
    await expect(
      db.$transaction((tx) => lockWorkAdmissionHost(tx, "host-1", "user-1")),
    ).rejects.toMatchObject({ message: expect.stringMatching(/quarantined/) });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "ready" }]),
    );
    expect(host()).toMatchObject({ quarantinedAt: null, quarantineReason: null, inventorySeq: 1 });
    await expect(
      db.$transaction((tx) => lockWorkAdmissionHost(tx, "host-1", "user-1")),
    ).resolves.toBeUndefined();
  });
});

const op = (row: Partial<OperationRow> & Pick<OperationRow, "id" | "kind" | "state">) =>
  ({
    userId: "user-1",
    sandboxId: "sbx-1",
    generation: 1,
    dispatchAttempt: 1,
    dispatchedHostId: "host-1",
    dispatchedConnectionEpoch: 1,
    requestBodyHash: "a".repeat(64),
    idempotencyKey: `key-${row.id}`,
    ...row,
  }) as OperationRow;
const lateResult = (row: OperationRow, state: string, result: Record<string, unknown>, epoch = 2) =>
  applyOperationResult(
    {
      sender: sender(epoch),
      operationId: row.id,
      sandboxId: row.sandboxId,
      generation: row.generation,
      attempt: row.dispatchAttempt,
      state,
      result,
      receipt: {
        bodyHash: String(row.requestBodyHash),
        idempotencyKey: String(row.idempotencyKey),
        kind: relayDispatchKind(row.kind as never)!,
      },
    },
    clock,
  );
const snapshot = () =>
  structuredClone({
    sandboxes: [...store.sandboxes.values()],
    operations: [...store.operations.values()],
    liveCount: host().liveCount,
  });

describe("uncertain and failed teardowns converge on proof", () => {
  it.each(["STOP_SANDBOX", "KILL_SANDBOX"] as const)(
    "%s on VM absence settles only stop while retaining the unobserved root",
    async (kind) => {
      setup({
        sandboxes: [{ state: "STOPPING", generation: 2, diskReservationHeld: true }],
        operations: [op({ id: "teardown", kind, state: "UNKNOWN_OUTCOME", generation: 2 })],
      });
      expect(
        await convergeInventoryEntry(
          sender(),
          { sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "absent" },
          clock,
        ),
        // Codex WP2 r3 #2: a kill still waiting for root proof (live slot
        // freed, disk held) is not converged, so the host retries it.
      ).toEqual({ converged: kind === "STOP_SANDBOX" });
      expect(sandbox()).toMatchObject({
        state: kind === "STOP_SANDBOX" ? "STOPPED" : "STOPPING",
        liveResourcesHeld: false,
        diskReservationHeld: true,
        sandboxHostId: "host-1",
      });
      expect(store.operations.get("teardown")!.state).toBe(
        kind === "STOP_SANDBOX" ? "SUCCEEDED" : "UNKNOWN_OUTCOME",
      );
      expect(host()).toMatchObject({ liveCount: 0, rootCount: 1 });
      expect(store.storagePools.get("storage:host-1")!.diskReservedGiB).toBe(33);
    },
  );
  it("an uncertain stop receipt, then host expiry completion, then census settles once without redispatch", async () => {
    const stop = op({
      id: "op-stop",
      kind: "STOP_SANDBOX",
      state: "ACCEPTED",
      generation: 2,
      idempotencyKey: "user-stop",
    });
    setup({
      sandboxes: [{ state: "STOPPING", generation: 2, ...effective(PAST) }],
      operations: [stop],
      outbox: [
        {
          id: "evt-stop",
          userId: "user-1",
          aggregateType: "sandbox",
          aggregateId: "sbx-1",
          processedAt: null,
          payload: { operationId: "op-stop", generation: 2 },
        },
      ],
    });
    // Reconnect: the host reports an uncertain receipt, adopted into epoch 2.
    await lateResult(stop, "unknown_outcome", {});
    expect(store.operations.get("op-stop")).toMatchObject({
      state: "UNKNOWN_OUTCOME",
      dispatchedConnectionEpoch: 2,
    });
    // Meanwhile the host's expiry supervisor stopped the VM.
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [
        {
          sandboxOwnerId: "user-1",
          root: null,
          sandboxId: "sbx-1",
          state: "stopped",
          lease: hostLease({ deadline: PAST, expired: true }),
        },
      ]),
    );
    expect(sandbox()).toMatchObject({ state: "STOPPED", generation: 2, liveResourcesHeld: false });
    // The user's stop settled, but the host's timer did the stopping.
    expect(sandbox()).toMatchObject({
      hostExpiryAction: "STOP",
      hostExpiryRevision: 1,
      hostExpiryConfirmedAt: NOW,
    });
    expect(store.operations.get("op-stop")).toMatchObject({ state: "SUCCEEDED" });
    expect(store.outbox.get("evt-stop")?.processedAt).toEqual(NOW);
    expect(host().liveCount).toBe(0);
    expect(await finishHostReconciliation(sender(), clock)).toBe(true);
    expect(store.operations.get("op-stop")).toMatchObject({ state: "SUCCEEDED" });
    expect(operationsFor()).toHaveLength(1);
  });

  it("a kill already dispatched in this epoch is settled by absence", async () => {
    setup({
      sandboxes: [{ state: "RECLAIMING", generation: 2 }],
      operations: [
        op({
          id: "op-kill",
          kind: "KILL_SANDBOX",
          state: "DISPATCHED",
          generation: 2,
          dispatchedConnectionEpoch: 2,
        }),
      ],
    });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "absent" }]),
    );
    expect(sandbox()).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      liveResourcesHeld: false,
    });
    expect(store.operations.get("op-kill")?.state).toBe("SUCCEEDED");
    expect(host().liveCount).toBe(0);
  });

  it("failed stop -> ERROR -> host stop expiry -> reconnect converges STOPPED, releasing once", async () => {
    setup({
      sandboxes: [
        { state: "ERROR", generation: 2, lastErrorCode: "stop_failed", ...effective(PAST) },
      ],
      operations: [op({ id: "op-stop", kind: "STOP_SANDBOX", state: "FAILED", generation: 2 })],
    });
    const entry = {
      sandboxOwnerId: "user-1",
      root: null,
      sandboxId: "sbx-1",
      state: "stopped" as const,
      lease: hostLease({ deadline: PAST, expired: true }),
    };
    await new InventoryCensus(sender(), clock).acceptPage(page(0, [entry]));
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      generation: 3,
      liveResourcesHeld: false,
      lastErrorCode: null,
      hostExpiryAction: "STOP",
      hostExpiryRevision: 1,
    });
    expect(store.operations.get("op-stop")?.state).toBe("FAILED");
    expect(operationsFor().map((row) => [row.kind, row.state, row.idempotencyKey])).toEqual([
      ["STOP_SANDBOX", "FAILED", "key-op-stop"],
      ["STOP_SANDBOX", "SUCCEEDED", leaseExpiryIdempotencyKey("sbx-1", 3, 1, "STOP")],
    ]);
    expect(host().liveCount).toBe(0);
    const before = snapshot();
    store.hosts.get("host-1")!.connectionEpoch = 3;
    await new InventoryCensus(sender(3), clock).acceptPage(page(0, [entry]));
    expect(snapshot()).toEqual(before);
  });

  it("failed kill -> ERROR -> host destroy expiry -> reconnect converges DELETED", async () => {
    setup({
      sandboxes: [{ state: "ERROR", generation: 2, ...effective(PAST, "DESTROY") }],
      operations: [op({ id: "op-kill", kind: "KILL_SANDBOX", state: "FAILED", generation: 2 })],
    });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [
        {
          sandboxOwnerId: "user-1",
          root: null,
          sandboxId: "sbx-1",
          state: "absent",
          lease: hostLease({ deadline: PAST, action: "destroy", expired: true }),
        },
      ]),
    );
    expect(sandbox()).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      liveResourcesHeld: false,
      hostExpiryAction: "DESTROY",
    });
    expect(store.operations.get("op-kill")?.state).toBe("FAILED");
    expect(host().liveCount).toBe(0);
  });

  it("an ERROR sandbox whose instance is silently gone frees its slot once and stays ERROR", async () => {
    setup({ sandboxes: [{ state: "ERROR", generation: 2 }] });
    await new InventoryCensus(sender(), clock).acceptPage(page(0, []));
    expect(sandbox()).toMatchObject({
      state: "ERROR",
      generation: 3,
      liveResourcesHeld: false,
      lastErrorCode: "instance_missing",
    });
    expect(host().liveCount).toBe(0);
    const before = snapshot();
    store.hosts.get("host-1")!.connectionEpoch = 3;
    await new InventoryCensus(sender(3), clock).acceptPage(page(0, []));
    expect(snapshot()).toEqual(before);
  });

  it("an uncertain reconnect still blocks convergence of an ERROR sandbox", async () => {
    setup({
      sandboxes: [{ state: "ERROR", generation: 2 }],
      operations: [
        op({ id: "op-re", kind: "RECONNECT_SANDBOX", state: "UNKNOWN_OUTCOME", generation: 2 }),
      ],
    });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "stopped" }]),
    );
    expect(sandbox()).toMatchObject({ state: "ERROR", generation: 2, liveResourcesHeld: true });
  });
});

describe("the preceding lease arm proves a destroy of a stopped disk", () => {
  const destroyed = {
    sandboxOwnerId: "user-1",
    root: null,
    sandboxId: "sbx-1",
    state: "absent" as const,
    lease: hostLease({ deadline: PAST, action: "destroy", expired: true }),
  };

  it("explicit stop at gen 2, then the gen-1 destroy expiry deletes the disk offline", async () => {
    setup({
      sandboxes: [
        {
          state: "STOPPED",
          generation: 2,
          liveResourcesHeld: false,
          ...effective(PAST, "DESTROY"),
        },
      ],
      operations: [
        op({ id: "op-create", kind: "CREATE_SANDBOX", state: "SUCCEEDED" }),
        op({ id: "op-stop", kind: "STOP_SANDBOX", state: "SUCCEEDED", generation: 2 }),
      ],
    });
    await new InventoryCensus(sender(), clock).acceptPage(page(0, [destroyed]));
    expect(sandbox()).toMatchObject({
      state: "DELETED",
      generation: 3,
      sandboxHostId: null,
      hostExpiryRevision: 1,
      hostExpiryAction: "DESTROY",
    });
    expect(store.operations.get("op-stop")?.state).toBe("SUCCEEDED");
  });

  // Review integ2 P1: a reconnect that reached the host and failed may have
  // booted (and replaced) the instance before failing, so the older arm's
  // evidence concludes nothing about it, not even instance absence.
  it("not when a later reconnect reached the host: absence then proves nothing", async () => {
    setup({
      sandboxes: [
        {
          state: "STOPPED",
          generation: 3,
          liveResourcesHeld: false,
          ...effective(PAST, "DESTROY"),
        },
      ],
      operations: [
        op({ id: "op-create", kind: "CREATE_SANDBOX", state: "SUCCEEDED" }),
        op({ id: "op-re", kind: "RECONNECT_SANDBOX", state: "FAILED", generation: 3 }),
      ],
    });
    const before = structuredClone(sandbox());
    await new InventoryCensus(sender(), clock).acceptPage(page(0, [destroyed]));
    expect(sandbox()).toEqual(before);
  });

  it("a later reconnect the host proved it never issued does not fence the older arm", async () => {
    setup({
      sandboxes: [
        {
          state: "STOPPED",
          generation: 3,
          liveResourcesHeld: false,
          ...effective(PAST, "DESTROY"),
        },
      ],
      operations: [
        op({ id: "op-create", kind: "CREATE_SANDBOX", state: "SUCCEEDED" }),
        op({
          id: "op-re",
          kind: "RECONNECT_SANDBOX",
          state: "FAILED",
          generation: 3,
          errorCode: "host_effect_not_issued",
        }),
      ],
    });
    await new InventoryCensus(sender(), clock).acceptPage(page(0, [destroyed]));
    expect(sandbox()).toMatchObject({
      state: "ERROR",
      lastErrorCode: "instance_missing",
      sandboxHostId: "host-1",
      hostExpiryAction: null,
    });
  });
});

describe("late results after convergence", () => {
  it("a late renew result cannot move the lease or revive the sandbox", async () => {
    const renew = op({ id: "op-renew", kind: "RENEW_SANDBOX_LEASE", state: "ACCEPTED" });
    const lease = {
      revision: 2,
      deadlineUnixMs: FUTURE + 5000,
      action: "stop",
      expiryPolicy: "retry-force-60s",
    };
    setup({
      sandboxes: [{ leaseRevision: 2, ...effective(FUTURE) }],
      operations: [renew],
      outbox: [
        {
          id: "evt-renew",
          userId: "user-1",
          aggregateType: "sandbox",
          aggregateId: "sbx-1",
          processedAt: NOW,
          payload: { operationId: "op-renew", generation: 1, lease },
        },
      ],
    });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [
        {
          sandboxOwnerId: "user-1",
          root: null,
          sandboxId: "sbx-1",
          state: "stopped",
          lease: hostLease(),
        },
      ]),
    );
    expect(sandbox()).toMatchObject({ state: "STOPPED", generation: 2 });
    expect(await lateResult(renew, "succeeded", { lease })).toEqual({ written: false });
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      generation: 2,
      leaseRevisionEffective: 1,
      leaseExpiresAtEffective: new Date(FUTURE),
    });
  });

  it("a late create result cannot resurrect a converged sandbox", async () => {
    const create = op({ id: "op-create", kind: "CREATE_SANDBOX", state: "SUCCEEDED" });
    setup({ sandboxes: [{}], operations: [create] });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "stopped" }]),
    );
    expect(sandbox()).toMatchObject({ state: "STOPPED", generation: 2 });
    expect(await lateResult(create, "succeeded", { state: "ready" })).toEqual({ written: false });
    expect(sandbox()).toMatchObject({ state: "STOPPED", generation: 2, liveResourcesHeld: false });
    expect(host().liveCount).toBe(0);
  });
});

describe("server restart and a lost final inventory ACK", () => {
  it("a fresh server replaying the whole census converges nothing twice", async () => {
    setup({
      sandboxes: [
        { id: "sbx-a" },
        { id: "sbx-b", ...effective(PAST, "DESTROY") },
        { id: "sbx-c" },
        { id: "sbx-d" },
      ],
    });
    const pages = [
      page(
        0,
        [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-a", state: "stopped" }],
        false,
      ),
      page(1, [
        {
          sandboxOwnerId: "user-1",
          root: null,
          sandboxId: "sbx-b",
          state: "absent",
          lease: hostLease({ deadline: PAST, action: "destroy", expired: true }),
        },
        { sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-d", state: "ready" },
      ]),
    ];
    const first = new InventoryCensus(sender(), clock);
    for (const next of pages) await first.acceptPage(next);
    expect(first.complete).toBe(true);
    expect(["sbx-a", "sbx-b", "sbx-c", "sbx-d"].map((id) => sandbox(id).state)).toEqual([
      "STOPPED",
      "DELETED",
      "ERROR",
      "READY",
    ]);
    const before = snapshot();
    // The final inventory.ack never reached the host; the server process restarted.
    store.hosts.get("host-1")!.connectionEpoch = 3;
    const replay = new InventoryCensus(sender(3), clock);
    for (const next of pages) await replay.acceptPage(next);
    expect(replay.complete).toBe(true);
    expect(snapshot()).toEqual(before);
    expect(host()).toMatchObject({ liveCount: 1, inventorySeq: 2 });
  });

  it("a census interrupted mid-way by a restart is replayed from page 0", async () => {
    setup({ sandboxes: [{ id: "sbx-a" }, { id: "sbx-b" }] });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(
        0,
        [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-a", state: "stopped" }],
        false,
      ),
    );
    expect(sandbox("sbx-b").state).toBe("READY");
    store.hosts.get("host-1")!.connectionEpoch = 3;
    const replay = new InventoryCensus(sender(3), clock);
    await replay.acceptPage(
      page(
        0,
        [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-a", state: "stopped" }],
        false,
      ),
    );
    await replay.acceptPage(
      page(1, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-b", state: "ready" }]),
    );
    expect([sandbox("sbx-a").state, sandbox("sbx-b").state]).toEqual(["STOPPED", "READY"]);
    expect(operationsFor("sbx-a")).toHaveLength(1);
  });
});

describe("lease ACK loss across a generation advance", () => {
  const renewed = {
    revision: 2,
    deadlineUnixMs: FUTURE + 1000,
    action: "stop" as const,
    expiryPolicy: "retry-force-60s" as const,
  };
  const outbox: OutboxRow = {
    id: "evt-renew",
    userId: "user-1",
    aggregateType: "sandbox",
    aggregateId: "sbx-1",
    processedAt: NOW,
    payload: {
      operationId: "op-renew",
      idempotencyKey: "key-op-renew",
      generation: 1,
      lease: renewed,
    },
  };
  const entry = {
    sandboxOwnerId: "user-1",
    root: null,
    sandboxId: "sbx-1",
    state: "stopped" as const,
    lease: hostLease({ revision: 2, deadline: FUTURE + 1000 }),
  };

  it("adopts the gen-1 renewal after a stop advanced the generation", async () => {
    setup({
      sandboxes: [
        {
          state: "STOPPED",
          generation: 2,
          leaseRevision: 2,
          liveResourcesHeld: false,
          ...effective(FUTURE),
        },
      ],
      operations: [
        op({ id: "op-create", kind: "CREATE_SANDBOX", state: "SUCCEEDED" }),
        op({ id: "op-renew", kind: "RENEW_SANDBOX_LEASE", state: "SUCCEEDED" }),
      ],
      outbox: [outbox],
    });
    expect(await convergeInventoryEntry(sender(), entry, clock)).toEqual({ converged: true });
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      generation: 2,
      leaseRevisionEffective: 2,
      leaseExpiresAtEffective: new Date(FUTURE + 1000),
    });
  });

  it("does not adopt it once a later reconnect reached the host", async () => {
    setup({
      sandboxes: [
        {
          state: "STOPPED",
          generation: 3,
          leaseRevision: 2,
          liveResourcesHeld: false,
          ...effective(FUTURE),
        },
      ],
      operations: [op({ id: "op-re", kind: "RECONNECT_SANDBOX", state: "FAILED", generation: 3 })],
      outbox: [outbox],
    });
    expect(await convergeInventoryEntry(sender(), entry, clock)).toEqual({ converged: false });
    expect(sandbox().leaseRevisionEffective).toBe(1);
  });
});

describe("bounded silence never starves the remainder", () => {
  const silent = (ids: string[]) => ids.map((id) => ({ id }));
  it("interior overflow is deferred, and each replayed census converges the next slice", async () => {
    const gap = ["sbx-b", "sbx-c", "sbx-d", "sbx-e", "sbx-f"];
    setup({ sandboxes: silent(["sbx-a", ...gap, "sbx-z"]) });
    const replay = async (epoch: number) => {
      store.hosts.get("host-1")!.connectionEpoch = epoch;
      const census = new InventoryCensus(sender(epoch), clock, { pendingAbsentMax: 2 });
      expect(
        await census.acceptPage(
          page(0, [
            { sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-a", state: "ready" },
            { sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-z", state: "ready" },
          ]),
        ),
      ).toEqual({ ok: true });
      expect(census.complete).toBe(true);
      return gap.map((id) => sandbox(id).state);
    };
    expect(await replay(2)).toEqual(["ERROR", "ERROR", "READY", "READY", "READY"]);
    const converged = { ...sandbox("sbx-b") };
    expect(await replay(3)).toEqual(["ERROR", "ERROR", "ERROR", "ERROR", "READY"]);
    // Already-converged rows left the scan instead of refilling the bound.
    expect(sandbox("sbx-b")).toEqual(converged);
    expect(await replay(4)).toEqual(["ERROR", "ERROR", "ERROR", "ERROR", "ERROR"]);
    for (const id of gap)
      expect(sandbox(id)).toMatchObject({
        liveResourcesHeld: false,
        lastErrorCode: "instance_missing",
      });
    expect(host().liveCount).toBe(2);
  });

  it("tail silence after completion converges in bounded chunks, past the held bound", async () => {
    const tail = ["sbx-b", "sbx-c", "sbx-d", "sbx-e", "sbx-f"];
    setup({ sandboxes: silent(["sbx-a", ...tail]) });
    const census = new InventoryCensus(sender(), clock, { pendingAbsentMax: 1, scanPage: 2 });
    await census.acceptPage(
      page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-a", state: "ready" }]),
    );
    expect(tail.map((id) => sandbox(id).state)).toEqual(Array(5).fill("ERROR"));
    expect(census.convergedCount).toBe(5);
    expect(host()).toMatchObject({ liveCount: 1, inventorySeq: 1 });
  });
});

describe("host expiry failures are published, not waited out", () => {
  const failing = (reason = "unknown_outcome: stop failed") => ({
    sandboxOwnerId: "user-1",
    root: null,
    sandboxId: "sbx-1",
    state: "ready" as const,
    lease: hostLease({ deadline: PAST, expired: true, complete: false, failure: reason }),
  });
  const recovered = {
    sandboxOwnerId: "user-1",
    root: null,
    sandboxId: "sbx-1",
    state: "stopped" as const,
    lease: hostLease({ deadline: PAST, expired: true }),
  };

  it("a failing expiry shows ERROR with the host reason and keeps the slot until the host confirms", async () => {
    setup({ sandboxes: [{ ...effective(PAST) }] });
    await new InventoryCensus(sender(), clock).acceptPage(page(0, [failing()]));
    expect(sandbox()).toMatchObject({
      state: "ERROR",
      generation: 1,
      liveResourcesHeld: true,
      lastErrorCode: "expiry_failed",
      lastErrorDetail: "Host could not enforce sandbox expiry.",
      hostExpiryAction: null,
    });
    expect(host().liveCount).toBe(1);
    expect(operationsFor()).toHaveLength(0);
    const before = snapshot();
    store.hosts.get("host-1")!.connectionEpoch = 3;
    await new InventoryCensus(sender(3), clock).acceptPage(page(0, [failing()]));
    expect(snapshot()).toEqual(before);

    await new InventoryCensus(sender(3), clock).acceptPage(page(0, [recovered]));
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      liveResourcesHeld: false,
      lastErrorCode: null,
      lastErrorDetail: null,
      hostExpiryAction: "STOP",
    });
    expect(host().liveCount).toBe(0);
  });

  it("connected status frames publish the failure and the recovery; silence changes nothing", async () => {
    setup({ sandboxes: [{ ...effective(PAST) }, { id: "sbx-2" }] });
    expect(await judgeExpiryStatus(sender(), [failing("stop timed out")], clock)).toHaveProperty(
      "results",
    );
    expect(sandbox()).toMatchObject({
      state: "ERROR",
      lastErrorCode: "expiry_failed",
      lastErrorDetail: "Host could not enforce sandbox expiry.",
      liveResourcesHeld: true,
    });
    expect(sandbox("sbx-2")).toMatchObject({ state: "READY", liveResourcesHeld: true });
    // An entry without an expiry latch is not lifecycle evidence here.
    await judgeExpiryStatus(
      sender(),
      [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-2", state: "stopped" }],
      clock,
    );
    expect(sandbox("sbx-2")).toMatchObject({ state: "READY", liveResourcesHeld: true });

    await judgeExpiryStatus(sender(), [recovered], clock);
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      lastErrorCode: null,
      liveResourcesHeld: false,
    });
    expect(await judgeExpiryStatus(sender(1), [recovered], clock)).toEqual({ stale: true });
  });

  it.each([
    { state: "STOPPING", kind: "STOP_SANDBOX", action: "stop", retired: false },
    { state: "STOPPING", kind: "STOP_SANDBOX", action: "stop", retired: true },
    { state: "RECLAIMING", kind: "KILL_SANDBOX", action: "destroy", retired: false },
  ] as const)(
    "an offline-queued $kind from $state fails to ERROR, then recovery settles that operation (outbox retired: $retired)",
    async ({ state, kind, action, retired }) => {
      const wire = action === "destroy" ? "DESTROY" : "STOP";
      setup({
        sandboxes: [{ state, generation: 2, ...effective(PAST, wire) }],
        operations: [
          {
            id: "op-expire",
            userId: "user-1",
            sandboxId: "sbx-1",
            kind,
            state: "QUEUED",
            generation: 2,
            dispatchAttempt: 0,
            dispatchedHostId: null,
            dispatchedConnectionEpoch: null,
            idempotencyKey: leaseExpiryIdempotencyKey("sbx-1", 2, 1, wire),
          },
        ],
        outbox: [
          {
            id: "evt-expire",
            userId: "user-1",
            aggregateType: "sandbox",
            aggregateId: "sbx-1",
            processedAt: null,
            payload: { operationId: "op-expire", generation: 2 },
          },
        ],
      });
      const lease = (complete: boolean) =>
        hostLease({
          deadline: PAST,
          action,
          expired: true,
          complete,
          ...(complete ? {} : { failure: "unknown_outcome: forced stop failed" }),
        });
      await new InventoryCensus(sender(), clock).acceptPage(
        page(0, [
          {
            sandboxOwnerId: "user-1",
            root: null,
            sandboxId: "sbx-1",
            state: "ready",
            lease: lease(false),
          },
        ]),
      );
      expect(sandbox()).toMatchObject({
        state: "ERROR",
        generation: 2,
        liveResourcesHeld: true,
        lastErrorCode: "expiry_failed",
        lastErrorDetail: "Host could not enforce sandbox expiry.",
      });
      expect(host().liveCount).toBe(1);
      expect(operationsFor()).toEqual([
        expect.objectContaining({ id: "op-expire", state: "QUEUED" }),
      ]);
      expect(store.outbox.get("evt-expire")?.processedAt).toBeNull();
      if (retired) {
        // The outbox retires work for an ERROR sandbox as superseded, undispatched.
        Object.assign(store.operations.get("op-expire")!, {
          state: "UNKNOWN_OUTCOME",
          errorCode: "superseded",
          completedAt: NOW,
        });
        store.outbox.get("evt-expire")!.processedAt = NOW;
      }
      store.hosts.get("host-1")!.connectionEpoch = 3;
      await new InventoryCensus(sender(3), clock).acceptPage(
        page(0, [
          {
            sandboxOwnerId: "user-1",
            root: null,
            sandboxId: "sbx-1",
            state: action === "destroy" ? "absent" : "stopped",
            lease: lease(true),
          },
        ]),
      );
      expect(sandbox()).toMatchObject({
        state: action === "destroy" ? "DELETED" : "STOPPED",
        generation: 2,
        liveResourcesHeld: false,
        lastErrorCode: null,
        lastErrorDetail: null,
        hostExpiryAction: wire,
      });
      expect(operationsFor()).toEqual([
        expect.objectContaining({
          id: "op-expire",
          state: "SUCCEEDED",
          errorCode: null,
          result: { state: action === "destroy" ? "deleted" : "stopped" },
        }),
      ]);
      expect(store.outbox.get("evt-expire")?.processedAt).toEqual(NOW);
      expect(host().liveCount).toBe(0);
    },
  );

  it("a failure on an unverifiable lease tuple is not recorded", async () => {
    setup({ sandboxes: [{}] });
    await new InventoryCensus(sender(), clock).acceptPage(page(0, [failing()]));
    expect(sandbox()).toMatchObject({ state: "READY", liveResourcesHeld: true });
    expect(sandbox().lastErrorCode ?? null).toBeNull();
  });

  it("a renewal committed during an outage does not outlive the host's older effective deadline", async () => {
    setup({
      // The committed renewal bumped the requested revision, but the host never
      // acknowledged it: the effective rev-1 deadline already passed.
      sandboxes: [{ leaseRevision: 2, ...effective(PAST) }],
      operations: [
        {
          id: "op-renew",
          userId: "user-1",
          sandboxId: "sbx-1",
          kind: "RENEW_SANDBOX_LEASE",
          state: "QUEUED",
          generation: 1,
          dispatchAttempt: 0,
          dispatchedHostId: null,
          idempotencyKey: "renew",
        },
      ],
      outbox: [
        {
          id: "evt-renew",
          userId: "user-1",
          aggregateType: "sandbox",
          aggregateId: "sbx-1",
          processedAt: null,
          payload: { operationId: "op-renew", generation: 1 },
        },
      ],
    });
    // The host rejected the late renewal and expired the VM on first attempt.
    await new InventoryCensus(sender(), clock).acceptPage(page(0, [recovered]));
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      generation: 2,
      liveResourcesHeld: false,
      hostExpiryAction: "STOP",
      hostExpiryRevision: 1,
    });
    expect(host().liveCount).toBe(0);
    // The rejected renewal is retired without ever reaching the host; the
    // observed stop is recorded as its own succeeded operation.
    expect(operationsFor()).toEqual([
      expect.objectContaining({
        id: "op-renew",
        state: "CANCELLED",
        dispatchAttempt: 0,
        dispatchedHostId: null,
      }),
      expect.objectContaining({ kind: "STOP_SANDBOX", state: "SUCCEEDED", generation: 2 }),
    ]);
    expect(store.outbox.get("evt-renew")?.processedAt).toEqual(NOW);
  });
});

describe("stale arms and held slots on STOPPED", () => {
  const staleArm = {
    sandboxOwnerId: "user-1",
    root: null,
    sandboxId: "sbx-1",
    state: "stopped" as const,
    lease: hostLease({ generation: 1, revision: 1, deadline: PAST, expired: true }),
  };

  it("an expiry status captured before a successful cold reconnect cannot stop the new generation", async () => {
    setup({
      sandboxes: [{ generation: 2, leaseRevision: 2, ...effective(FUTURE, "STOP", 2) }],
      operations: [
        {
          id: "op-create",
          userId: "user-1",
          sandboxId: "sbx-1",
          kind: "CREATE_SANDBOX",
          state: "SUCCEEDED",
          generation: 1,
          dispatchAttempt: 1,
          dispatchedHostId: "host-1",
          idempotencyKey: "create",
        },
        {
          id: "op-reconnect",
          userId: "user-1",
          sandboxId: "sbx-1",
          kind: "RECONNECT_SANDBOX",
          state: "SUCCEEDED",
          generation: 2,
          dispatchAttempt: 1,
          dispatchedHostId: "host-1",
          idempotencyKey: "reconnect",
        },
      ],
    });
    // A recovery worker captured the expired gen-1 arm before the reconnect
    // result arrived; it is delivered only now, over status and census.
    expect(await judgeExpiryStatus(sender(), [staleArm], clock)).toHaveProperty("results");
    expect(sandbox()).toMatchObject({ state: "READY", generation: 2, liveResourcesHeld: true });
    await new InventoryCensus(sender(), clock).acceptPage(page(0, [staleArm]));
    expect(sandbox()).toMatchObject({ state: "READY", generation: 2, liveResourcesHeld: true });
    expect(host().liveCount).toBe(1);
    expect(operationsFor()).toHaveLength(2);
  });

  it("a completed current-arm expiry frees a STOPPED sandbox's held slot and settles its uncertain reconnect", async () => {
    setup({
      sandboxes: [
        { state: "STOPPED", generation: 2, leaseRevision: 2, ...effective(PAST, "STOP", 2) },
      ],
      operations: [
        {
          id: "op-reconnect",
          userId: "user-1",
          sandboxId: "sbx-1",
          kind: "RECONNECT_SANDBOX",
          state: "UNKNOWN_OUTCOME",
          generation: 2,
          dispatchAttempt: 1,
          dispatchedHostId: "host-1",
          dispatchedConnectionEpoch: 1,
          idempotencyKey: "reconnect",
        },
      ],
    });
    // While the arm is still failing, the uncertain reconnect blocks every
    // inference: the failure is not even recorded yet.
    expect(
      await judgeExpiryStatus(
        sender(),
        [
          {
            sandboxOwnerId: "user-1",
            root: null,
            sandboxId: "sbx-1",
            state: "ready" as const,
            lease: hostLease({
              generation: 2,
              revision: 2,
              deadline: PAST,
              expired: true,
              complete: false,
              failure: "stop timed out",
            }),
          },
        ],
        clock,
      ),
    ).toHaveProperty("results");
    expect(sandbox()).toMatchObject({ state: "STOPPED", liveResourcesHeld: true });
    expect(sandbox().lastErrorCode ?? null).toBeNull();
    expect(host().liveCount).toBe(1);
    expect(operationsFor()[0]).toMatchObject({ state: "UNKNOWN_OUTCOME" });

    expect(
      await judgeExpiryStatus(
        sender(),
        [
          {
            sandboxOwnerId: "user-1",
            root: null,
            sandboxId: "sbx-1",
            state: "stopped" as const,
            lease: hostLease({ generation: 2, revision: 2, deadline: PAST, expired: true }),
          },
        ],
        clock,
      ),
    ).toHaveProperty("results");
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      generation: 2,
      liveResourcesHeld: false,
      hostExpiryAction: "STOP",
      hostExpiryRevision: 2,
      hostExpiryConfirmedAt: NOW,
    });
    expect(sandbox().lastErrorCode ?? null).toBeNull();
    expect(host().liveCount).toBe(0);
    expect(operationsFor()).toEqual([
      expect.objectContaining({ id: "op-reconnect", state: "CANCELLED", completedAt: NOW }),
    ]);
  });

  it("a completed expiry for an older arm neither frees a held slot nor settles a newer allocation", async () => {
    setup({
      sandboxes: [{ state: "STOPPED", generation: 2, liveResourcesHeld: true, ...effective(PAST) }],
      operations: [
        {
          id: "op-reconnect",
          userId: "user-1",
          sandboxId: "sbx-1",
          kind: "RECONNECT_SANDBOX",
          state: "QUEUED",
          generation: 2,
          dispatchAttempt: 0,
          dispatchedHostId: null,
          idempotencyKey: "reconnect",
        },
      ],
    });
    // The gen-1 arm expired, but a gen-2 reconnect is still queued: nothing
    // about the current generation is proven.
    await new InventoryCensus(sender(), clock).acceptPage(page(0, [staleArm]));
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      generation: 2,
      liveResourcesHeld: true,
      hostExpiryRevision: 1,
    });
    expect(host().liveCount).toBe(1);
    expect(operationsFor()).toEqual([
      expect.objectContaining({ id: "op-reconnect", state: "QUEUED" }),
    ]);
  });
});

describe("only the host timer is expiry evidence", () => {
  it("an explicit-teardown latch converges the stop but records no host expiry", async () => {
    setup({
      sandboxes: [{ state: "ERROR", generation: 2, ...effective(PAST) }],
      operations: [op({ id: "op-stop", kind: "STOP_SANDBOX", state: "FAILED", generation: 2 })],
    });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [
        {
          sandboxOwnerId: "user-1",
          root: null,
          sandboxId: "sbx-1",
          state: "stopped",
          lease: hostLease({ deadline: PAST, expired: true, timer: false }),
        },
      ]),
    );
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      hostExpiryAction: null,
      hostExpiryConfirmedAt: null,
    });
    expect(operationsFor().map((row) => row.idempotencyKey)).toEqual([
      "key-op-stop",
      inventoryObservationIdempotencyKey("sbx-1", 3),
    ]);
  });

  it("a receipt that already settled STOPPED still gets the verified timer expiry, once", async () => {
    setup({
      sandboxes: [
        { state: "STOPPED", generation: 2, liveResourcesHeld: false, ...effective(PAST) },
      ],
    });
    const entry = {
      sandboxOwnerId: "user-1",
      root: null,
      sandboxId: "sbx-1",
      state: "stopped" as const,
      lease: hostLease({ deadline: PAST, expired: true }),
    };
    await new InventoryCensus(sender(), clock).acceptPage(page(0, [entry]));
    expect(sandbox()).toMatchObject({
      state: "STOPPED",
      generation: 2,
      hostExpiryAction: "STOP",
      hostExpiryRevision: 1,
      hostExpiryConfirmedAt: NOW,
    });
    const before = snapshot();
    store.hosts.get("host-1")!.connectionEpoch = 3;
    await new InventoryCensus(sender(3), clock).acceptPage(page(0, [entry]));
    expect(snapshot()).toEqual(before);
    expect(sandbox().hostExpiryConfirmedAt).toEqual(NOW);
  });

  it("an explicit-teardown latch on an already-STOPPED sandbox records nothing", async () => {
    setup({
      sandboxes: [
        { state: "STOPPED", generation: 2, liveResourcesHeld: false, ...effective(PAST) },
      ],
    });
    await new InventoryCensus(sender(), clock).acceptPage(
      page(0, [
        {
          sandboxOwnerId: "user-1",
          root: null,
          sandboxId: "sbx-1",
          state: "stopped",
          lease: hostLease({ deadline: PAST, expired: true, timer: false }),
        },
      ]),
    );
    expect(sandbox()).toMatchObject({ hostExpiryAction: null, hostExpiryConfirmedAt: null });
  });
});

describe("UNKNOWN targeted allocation attestation", () => {
  const allocation = () =>
    op({ id: "unknown-create", kind: "CREATE_SANDBOX", state: "UNKNOWN_OUTCOME" });
  function provision() {
    setup({
      host: {
        relayProtocolVersion: "1.0",
        relayProtocolEpoch: 2,
        admissionEpoch: 2,
        daemonFeatures: { journalId: "a".repeat(32) },
      },
      sandboxes: [{ state: "PROVISIONING" }],
      operations: [allocation()],
      outbox: [
        {
          id: "allocation-event",
          userId: "user-1",
          aggregateType: "sandbox",
          aggregateId: "sbx-1",
          eventType: "sandbox.create_requested",
          processedAt: new Date(PAST),
          payload: {
            operationId: "unknown-create",
            generation: 1,
            allocationJournalId: "a".repeat(32),
            allocationJournalAttempt: 1,
            allocationJournalEpoch: 1,
          },
        },
      ],
    });
  }
  async function attest(
    options: {
      settled?: boolean;
      epoch?: number;
      barrier?: number;
      journalId?: string;
      respond?: boolean;
    } = {},
  ) {
    const { AllocationAttestation } = await import("./allocation-attestation.js");
    const sent: import("./protocol.js").ServerControlMessage[] = [];
    const attestation = new AllocationAttestation(
      sender(),
      () => 10,
      (request) => sent.push(request),
    );
    await attestation.request();
    if (options.respond === false) {
      attestation.close();
      return { accepted: false, sent };
    }
    const accepted = await attestation.accept({
      type: "allocation.attest.result",
      connectionEpoch: options.epoch ?? 2,
      barrier: options.barrier ?? 10,
      journalId: options.journalId ?? "a".repeat(32),
      entries: [
        {
          sandboxOwnerId: "user-1",
          sandboxId: "sbx-1",
          settledNeverIssued: options.settled ?? true,
        },
      ],
    });
    attestation.close();
    return { accepted, sent };
  }
  it("UNKNOWN -> targeted request -> public failure releases once and fences late success", async () => {
    provision();
    const before = allocation();
    expect((await attest()).sent).toEqual([
      {
        type: "allocation.attest.request",
        connectionEpoch: 2,
        barrier: 10,
        sandboxIds: ["sbx-1"],
        allocations: [
          {
            sandboxOwnerId: "user-1",
            sandboxId: "sbx-1",
            allocation: {
              cpuCount: 1,
              memoryMiB: 1024,
              diskGiB: 32,
              storagePoolName: "default",
              storageMarker: "a".repeat(32),
              chargedMemoryMiB: 1344,
              chargedVcpu: 1,
              rootChargeGiB: 33,
            },
          },
        ],
      },
    ]);
    expect(sandbox()).toMatchObject({
      state: "ERROR",
      generation: 2,
      liveResourcesHeld: false,
      lastErrorCode: "host_effect_not_issued",
    });
    expect(host().liveCount).toBe(0);
    expect(operationsFor()[0]).toMatchObject({
      state: "FAILED",
      errorCode: "host_effect_not_issued",
    });
    await attest();
    expect(host().liveCount).toBe(0);
    expect(await lateResult(before, "succeeded", { state: "ready" })).toEqual({ written: false });
    expect(
      await new InventoryCensus(sender(), clock).acceptPage(
        page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "ready" }]),
      ),
    ).toEqual({ ok: true });
    expect(host().quarantineReason).toBe("released_instance_present");
    expect(sandbox()).toMatchObject({ state: "ERROR", liveResourcesHeld: false });
  });
  it.each([
    "host-not-settled",
    "no-attestation",
    "old-host",
    "new-generation",
    "stale-barrier",
    "stale-epoch",
  ])("%s keeps the hold", async (evidence) => {
    provision();
    if (evidence === "old-host") host().relayProtocolVersion = "10.7";
    if (evidence === "new-generation") sandbox().generation = 2;
    if (evidence === "no-attestation") {
      await new InventoryCensus(sender(), clock).acceptPage(page(0, []));
      await attest({ respond: false });
    }
    if (evidence !== "no-attestation")
      await attest({
        settled: evidence !== "host-not-settled",
        barrier: evidence === "stale-barrier" ? 9 : 10,
        epoch: evidence === "stale-epoch" ? 1 : 2,
      });
    expect(sandbox().liveResourcesHeld).toBe(true);
    expect(host().liveCount).toBe(1);
    expect(operationsFor()[0]!.state).toBe("UNKNOWN_OUTCOME");
  });
  it.each([undefined, 10, 11])(
    "in-flight dispatch sequence %s cannot pass the barrier",
    async (sequence) => {
      provision();
      store.operations.get("unknown-create")!.dispatchedConnectionEpoch = 2;
      Object.assign(store.outbox.get("allocation-event")!.payload, {
        allocationJournalEpoch: 2,
        allocationDispatchSequence: sequence,
      });
      await attest();
      expect(sandbox().liveResourcesHeld).toBe(true);
      expect(host().liveCount).toBe(1);
    },
  );
  it("a processed in-session dispatch before the barrier releases", async () => {
    provision();
    store.operations.get("unknown-create")!.dispatchedConnectionEpoch = 2;
    Object.assign(store.outbox.get("allocation-event")!.payload, {
      allocationJournalEpoch: 2,
      allocationDispatchSequence: 9,
    });
    await attest();
    expect(sandbox().liveResourcesHeld).toBe(false);
  });
  it.each([
    "missing-identity",
    "fresh-journal",
    "missing-history",
    "different-earlier-journal",
    "wrong-event-type",
  ])("%s supplies no journal continuity", async (evidence) => {
    provision();
    if (evidence === "missing-identity") host().daemonFeatures = {};
    if (evidence === "fresh-journal") host().daemonFeatures = { journalId: "b".repeat(32) };
    if (evidence === "missing-history") store.outbox.clear();
    if (evidence === "wrong-event-type")
      store.outbox.get("allocation-event")!.eventType = "sandbox.command_requested";
    if (evidence === "different-earlier-journal") {
      store.operations.set(
        "earlier",
        op({ id: "earlier", kind: "CREATE_SANDBOX", state: "FAILED" }),
      );
      store.outbox.set("earlier-event", {
        ...store.outbox.get("allocation-event")!,
        id: "earlier-event",
        payload: {
          operationId: "earlier",
          generation: 1,
          allocationJournalId: "b".repeat(32),
          allocationJournalEpoch: 1,
          allocationJournalAttempt: 1,
        },
      });
    }
    await attest({ journalId: evidence === "fresh-journal" ? "b".repeat(32) : undefined });
    expect(sandbox().liveResourcesHeld).toBe(true);
  });
  it("an unrelated earlier outbox event cannot shadow valid allocation lineage", async () => {
    provision();
    store.outbox.set("a-unrelated", {
      ...store.outbox.get("allocation-event")!,
      id: "a-unrelated",
      eventType: "sandbox.command_requested",
      payload: { operationId: "unknown-create" },
    });
    await attest();
    expect(sandbox().liveResourcesHeld).toBe(false);
  });
  it.each(["REQUESTED", "SCHEDULED", "PROVISIONING", "READY", "STOPPED"])(
    "settles never-issued %s allocation",
    async (state) => {
      provision();
      sandbox().state = state;
      if (state === "READY" || state === "STOPPED")
        store.operations.get("unknown-create")!.kind = "RECONNECT_SANDBOX";
      const completedAt = new Date(PAST);
      store.operations.get("unknown-create")!.completedAt = completedAt;
      await attest();
      expect(sandbox()).toMatchObject({ state: "ERROR", liveResourcesHeld: false });
      expect(operationsFor()[0]).toMatchObject({ state: "FAILED", completedAt });
    },
  );
  it("reconcile marks a lost UNKNOWN before targeted proof", async () => {
    provision();
    store.operations.get("unknown-create")!.state = "DISPATCHED";
    await new InventoryCensus(sender(), clock).acceptPage(page(0, []));
    expect(sandbox().liveResourcesHeld).toBe(true);
    await finishHostReconciliation(sender());
    await attest();
    expect(sandbox().liveResourcesHeld).toBe(false);
  });
  it.each(["STOPPED", "ERROR"])(
    "general census preserves %s absence convergence with host history",
    async (state) => {
      setup({ sandboxes: [{ state, liveResourcesHeld: state === "ERROR" }] });
      await new InventoryCensus(sender(), clock).acceptPage(page(0, []));
      expect(sandbox()).toMatchObject({
        state: "ERROR",
        liveResourcesHeld: false,
        lastErrorCode: "instance_missing",
      });
    },
  );
  it("instance_missing recovers to STOPPED and does not quarantine", async () => {
    setup({
      sandboxes: [{ state: "ERROR", liveResourcesHeld: false, lastErrorCode: "instance_missing" }],
    });
    expect(
      await new InventoryCensus(sender(), clock).acceptPage(
        page(0, [{ sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "stopped" }]),
      ),
    ).toEqual({ ok: true });
    expect(sandbox().state).toBe("STOPPED");
    expect(host().quarantinedAt).toBeNull();
  });
});

/** WP2 §9 (Codex review-integ3 diagnostics): evidence is judged per entry so
 * the host can re-offer it until it converges. Each case first reproduces the
 * refusal, then shows the re-offer under a current observation converging. */
/** The observation fence of a session that received no lifecycle result
 * for the sandbox since the observation began (non-expired evidence is then
 * judged); the default is closed. */
const unfenced = () => false;

describe("re-offered evidence (expiryStatusResults)", () => {
  const root = (sequence: number) => ({
    storagePoolName: "default",
    storageMarker: "a".repeat(32),
    diskGiB: 32,
    state: "present" as const,
    networkCleanupComplete: false,
    observationSequence: sequence,
  });
  const pool = () => store.storagePools.get("storage:host-1")!;
  const stopped = (sandboxId: string, sequence: number, lease = hostLease()): InventoryEntry => ({
    sandboxOwnerId: "user-1",
    sandboxId,
    state: "stopped",
    root: root(sequence),
    lease,
  });

  it("(1) connected expiry whose health aged out is judged stale_storage, then converges", async () => {
    vi.useFakeTimers();
    try {
      const at = new Date("2029-01-01T00:00:00Z");
      vi.setSystemTime(at);
      setup({ sandboxes: [{ diskReservationHeld: true, ...effective(PAST) }] });
      Object.assign(pool(), { observationSequence: 2n, reportedAt: at });
      vi.setSystemTime(at.getTime() + 16_000);
      const entry = stopped("sbx-1", 2, hostLease({ deadline: PAST, expired: true }));
      // Without results the refusal is silent: `ok`, still READY and charged.
      expect(await judgeExpiryStatus(sender(), [entry], clock)).toHaveProperty("results");
      expect(sandbox().state).toBe("READY");
      expect(await judgeExpiryStatus(sender(), [entry], clock)).toEqual({
        results: [{ sandboxId: "sbx-1", outcome: "stale_storage" }],
      });
      expect(sandbox().state).toBe("READY");
      // The host re-offers it under its next (fresh) observation.
      Object.assign(pool(), { observationSequence: 3n, reportedAt: new Date() });
      expect(await judgeExpiryStatus(sender(), [stopped("sbx-1", 3, entry.lease!)], clock)).toEqual(
        { results: [{ sandboxId: "sbx-1", outcome: "converged" }] },
      );
      expect(sandbox().state).toBe("STOPPED");
    } finally {
      vi.useRealTimers();
    }
  });

  it("(2) a census entry without an expiry arm judged stale_storage converges when re-offered", async () => {
    vi.useFakeTimers();
    try {
      const at = new Date("2029-01-01T00:00:00Z");
      vi.setSystemTime(at);
      setup({
        sandboxes: [
          { id: "sbx-a", diskReservationHeld: true },
          { id: "sbx-b", diskReservationHeld: true },
        ],
      });
      Object.assign(pool(), { observationSequence: 2n, reportedAt: at });
      let locks = 0;
      store.barriers.beforeHostLock = async () => {
        if (++locks === 2) vi.setSystemTime(at.getTime() + 16_000);
      };
      const census = new InventoryCensus(sender(), clock);
      expect(await census.acceptPage(page(0, [stopped("sbx-a", 2), stopped("sbx-b", 2)]))).toEqual({
        ok: true,
      });
      store.barriers.beforeHostLock = undefined;
      expect(census.pageResults).toEqual([
        { sandboxId: "sbx-a", outcome: "converged" },
        { sandboxId: "sbx-b", outcome: "stale_storage" },
      ]);
      expect(sandbox("sbx-b").state).toBe("READY");
      expect(sandbox("sbx-b").liveResourcesHeld).toBe(true);
      // Its lease is not expired: only the per-entry path judges it again.
      Object.assign(pool(), { observationSequence: 3n, reportedAt: new Date() });
      expect(await judgeExpiryStatus(sender(), [stopped("sbx-b", 3)], clock, unfenced)).toEqual({
        results: [{ sandboxId: "sbx-b", outcome: "converged" }],
      });
      expect(sandbox("sbx-b").state).toBe("STOPPED");
    } finally {
      vi.useRealTimers();
    }
  });

  it("(3) not_converged under an unavailable pool converges under the newer healthy sequence", async () => {
    setup({ sandboxes: [{ diskReservationHeld: true, ...effective(PAST) }] });
    Object.assign(pool(), {
      observationSequence: 2n,
      health: "unavailable",
      healthReason: "probe",
      reportedAt: new Date(),
    });
    const lease = hostLease({ deadline: PAST, expired: true });
    // The page observed the recovered root, but stamped the unavailable N.
    expect(await judgeExpiryStatus(sender(), [stopped("sbx-1", 2, lease)], clock)).toEqual({
      results: [{ sandboxId: "sbx-1", outcome: "not_converged" }],
    });
    expect(sandbox().state).toBe("READY");
    // Healthy N+1 is published; the host re-offers under it.
    Object.assign(pool(), {
      observationSequence: 3n,
      health: "healthy",
      healthReason: null,
      reportedAt: new Date(),
    });
    expect(await judgeExpiryStatus(sender(), [stopped("sbx-1", 3, lease)], clock)).toEqual({
      results: [{ sandboxId: "sbx-1", outcome: "converged" }],
    });
    expect(sandbox().state).toBe("STOPPED");
  });

  it("re-offered VM absence without root evidence never converges a held reservation", async () => {
    setup({ sandboxes: [{ diskReservationHeld: true }] });
    expect(
      await judgeExpiryStatus(
        sender(),
        [
          {
            sandboxOwnerId: "user-1",
            sandboxId: "sbx-1",
            state: "absent",
            root: null,
            lease: hostLease(),
          },
        ],
        clock,
        unfenced,
      ),
    ).toEqual({ results: [{ sandboxId: "sbx-1", outcome: "not_converged" }] });
    expect(sandbox().state).toBe("READY");
  });
});

/** a connected frame claiming expiry (`expired: true`)
 * with VM absence, no root evidence and a lease the server does not consider
 * due must not advance the generation or release capacity. */
describe("a host expiry flag never stands in for root evidence", () => {
  const attack = (): InventoryEntry => ({
    sandboxOwnerId: "user-1",
    sandboxId: "sbx-1",
    state: "absent",
    root: null,
    lease: hostLease({ deadline: FUTURE, expired: true, complete: false, timer: false }),
  });

  it("connected evidence refuses the attack frame", async () => {
    setup({ sandboxes: [{ diskReservationHeld: true, ...effective(FUTURE) }] });
    const before = { ...sandbox() };
    expect(await judgeExpiryStatus(sender(), [attack()], clock)).toEqual({
      results: [{ sandboxId: "sbx-1", outcome: "not_converged" }],
    });
    expect(sandbox()).toMatchObject({
      state: "READY",
      generation: before.generation,
      liveResourcesHeld: true,
      diskReservationHeld: true,
    });
  });

  it("a held ERROR row's pending stop still settles on rootless VM absence (server's own record)", async () => {
    setup({
      sandboxes: [
        {
          state: "ERROR",
          generation: 2,
          liveResourcesHeld: true,
          diskReservationHeld: true,
          ...effective(FUTURE),
        },
      ],
      operations: [
        op({ id: "stop", kind: "STOP_SANDBOX", state: "UNKNOWN_OUTCOME", generation: 2 }),
      ],
    });
    expect(
      await convergeInventoryEntry(
        sender(),
        { sandboxOwnerId: "user-1", root: null, sandboxId: "sbx-1", state: "absent" },
        clock,
      ),
    ).toEqual({ converged: true });
    expect(store.operations.get("stop")!.state).toBe("SUCCEEDED");
    expect(sandbox().liveResourcesHeld).toBe(false);
  });

  it("the server's own due lease still converges VM absence", async () => {
    setup({ sandboxes: [{ diskReservationHeld: true, ...effective(PAST) }] });
    const entry = {
      ...attack(),
      lease: hostLease({ deadline: PAST, expired: true, complete: true, timer: true }),
    };
    await judgeExpiryStatus(sender(), [entry], clock);
    expect(sandbox().state).not.toBe("READY");
  });
});

/** Codex WP2 r3 #2: completed, due destroy evidence whose root census
 * failed (`root: null`) moves the row and frees its live slot, but the disk
 * reservation stays held: that is not convergence, so the host keeps its
 * rootless retry, and the retry with root evidence releases the disk. */
describe("rootless partial convergence keeps the host retrying", () => {
  it("not_converged while the disk is held; root evidence then settles it", async () => {
    setup({ sandboxes: [{ diskReservationHeld: true, ...effective(PAST, "DESTROY") }] });
    Object.assign(store.storagePools.get("storage:host-1")!, {
      observationSequence: 2n,
      health: "healthy",
      healthReason: null,
      reportedAt: new Date(),
    });
    const rootless: InventoryEntry = {
      sandboxOwnerId: "user-1",
      sandboxId: "sbx-1",
      state: "absent",
      root: null,
      lease: hostLease({ deadline: PAST, action: "destroy", expired: true }),
    };
    expect(await judgeExpiryStatus(sender(), [rootless], clock)).toEqual({
      results: [{ sandboxId: "sbx-1", outcome: "not_converged" }],
    });
    expect(sandbox()).toMatchObject({ liveResourcesHeld: false, diskReservationHeld: true });
    // Retried while the root census still fails: still not converged.
    expect(await judgeExpiryStatus(sender(), [rootless], clock)).toEqual({
      results: [{ sandboxId: "sbx-1", outcome: "not_converged" }],
    });
    const rooted: InventoryEntry = {
      ...rootless,
      root: {
        storagePoolName: "default",
        storageMarker: "a".repeat(32),
        diskGiB: 32,
        state: "absent",
        networkCleanupComplete: true,
        observationSequence: 2,
      },
    };
    expect(await judgeExpiryStatus(sender(), [rooted], clock)).toEqual({
      results: [{ sandboxId: "sbx-1", outcome: "converged" }],
    });
    expect(sandbox()).toMatchObject({ diskReservationHeld: false });
  });
});

/** Codex WP2 r3 #3: census VM absence without root evidence still settles a
 * pending stop (the server's own record) for a teardown or held-ERROR row,
 * and still converges nothing else. */
describe("rootless census absence and pending teardowns", () => {
  const absent = (): InventoryEntry => ({
    sandboxOwnerId: "user-1",
    sandboxId: "sbx-1",
    state: "absent",
    root: null,
  });
  it.each([
    ["ERROR", true],
    ["STOPPING", true],
  ] as const)("%s (live held %s) settles its pending stop", async (state, liveResourcesHeld) => {
    setup({
      sandboxes: [
        {
          state,
          generation: 2,
          liveResourcesHeld,
          diskReservationHeld: true,
          ...effective(FUTURE),
        },
      ],
      operations: [
        op({ id: "stop", kind: "STOP_SANDBOX", state: "UNKNOWN_OUTCOME", generation: 2 }),
      ],
    });
    const census = new InventoryCensus(sender(), clock);
    expect(await census.acceptPage(page(0, [absent()]))).toEqual({ ok: true });
    expect(census.pageResults).toEqual([{ sandboxId: "sbx-1", outcome: "converged" }]);
    expect(store.operations.get("stop")!.state).toBe("SUCCEEDED");
    expect(sandbox().liveResourcesHeld).toBe(false);
    expect(sandbox().diskReservationHeld).toBe(true);
  });
  it("without a pending teardown a held ERROR row is left as is", async () => {
    setup({
      sandboxes: [
        {
          state: "ERROR",
          generation: 2,
          liveResourcesHeld: true,
          diskReservationHeld: true,
          ...effective(PAST),
        },
      ],
    });
    const census = new InventoryCensus(sender(), clock);
    await census.acceptPage(page(0, [absent()]));
    expect(sandbox()).toMatchObject({ state: "ERROR", liveResourcesHeld: true });
  });
  it("a READY row is not converged by rootless census absence", async () => {
    setup({ sandboxes: [{ diskReservationHeld: true, ...effective(PAST) }] });
    const census = new InventoryCensus(sender(), clock);
    await census.acceptPage(page(0, [absent()]));
    expect(sandbox()).toMatchObject({ state: "READY", liveResourcesHeld: true });
  });
});

/** Codex WP2 r3 P1, the interleaving end to end at the judge: a cold
 * reconnect installs its new lease (generation 2) before a targeted
 * observation snapshots it while the VM is still STOPPED; the reconnect's
 * READY result reaches the server first, then the queued observation. The
 * session's observation fence (the result arrived while observation 1 could
 * be in flight) refuses that entry: no downgrade, no capacity release. An
 * observation that began after the result (number 2) is judged, and a VM
 * that really stopped then converges. The older connected path ignores
 * non-expired entries either way. */
describe("a lifecycle result fences current-arm evidence observed before it", () => {
  const stopped = (): InventoryEntry => ({
    sandboxOwnerId: "user-1",
    sandboxId: "sbx-1",
    state: "stopped",
    root: {
      storagePoolName: "default",
      storageMarker: "a".repeat(32),
      diskGiB: 32,
      state: "present",
      networkCleanupComplete: false,
      observationSequence: 0,
    },
    lease: hostLease({ generation: 2 }),
  });

  it("refuses the stale observation, judges a later one", async () => {
    // The reconnect settled: READY on generation 2, charged.
    setup({ sandboxes: [{ generation: 2, diskReservationHeld: true, ...effective(FUTURE) }] });
    const fence = new ObservationFence();
    // Observation 1 is snapshotted (VM still stopped, new lease installed)
    // and queued; the reconnect's result arrives first.
    fence.noteResult("sbx-1");
    expect(fence.accept(1)).toBe(true);
    const before = { ...sandbox() };
    expect(
      await judgeExpiryStatus(sender(), [stopped()], clock, (id) => fence.predates(id, 1)),
    ).toEqual({ results: [{ sandboxId: "sbx-1", outcome: "superseded" }] });
    expect(sandbox()).toMatchObject({
      state: "READY",
      generation: before.generation,
      liveResourcesHeld: true,
      diskReservationHeld: true,
    });
    // The older connected path ignores the same frame.
    expect(await judgeExpiryStatus(sender(), [stopped()], clock)).toHaveProperty("results");
    expect(sandbox()).toMatchObject({ state: "READY", liveResourcesHeld: true });
    // Observation 2 began only after the server answered 1, which it did
    // after the result: judged. A stopped VM now really stopped after READY.
    expect(fence.accept(2)).toBe(true);
    expect(fence.predates("sbx-1", 2)).toBe(false);
    expect(
      await judgeExpiryStatus(sender(), [stopped()], clock, (id) => fence.predates(id, 2)),
    ).toEqual({ results: [{ sandboxId: "sbx-1", outcome: "converged" }] });
    expect(sandbox().state).toBe("STOPPED");
  });

  it("expired arms are judged whatever the fence says (the older path's rule)", async () => {
    setup({ sandboxes: [{ diskReservationHeld: true, ...effective(PAST) }] });
    const expired = {
      ...stopped(),
      lease: hostLease({ deadline: PAST, expired: true }),
    };
    expect(await judgeExpiryStatus(sender(), [expired], clock, () => true)).toEqual({
      results: [{ sandboxId: "sbx-1", outcome: "converged" }],
    });
    expect(sandbox().state).toBe("STOPPED");
  });
});
