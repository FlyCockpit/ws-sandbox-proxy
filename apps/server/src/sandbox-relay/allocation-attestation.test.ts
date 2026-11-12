import prisma from "@wssp/db";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AllocationAttestation } from "./allocation-attestation.js";
import {
  createFenceStore,
  type FenceStore,
  installFenceTransaction,
} from "./fenced-prisma-harness.js";
import type { ServerControlMessage } from "./protocol.js";

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4) },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("./session-manager.js", () => ({ sandboxRelaySessionManager: {} }));
// This suite exercises the scheduler; settlement and release are covered by
// inventory-reconcile unit/PG tests. Avoid 256 unrelated transactions per page.
vi.mock("./inventory-reconcile.js", () => ({
  convergeInventoryEntry: vi.fn().mockResolvedValue({ converged: true }),
}));

type Request = Extract<ServerControlMessage, { type: "allocation.attest.request" }>;
let attestation: AllocationAttestation;
let requests: Request[];
let store: FenceStore;
beforeEach(() => {
  vi.useFakeTimers();
  const sandboxes = Array.from({ length: 300 }, (_, i) => ({
    id: `s-${String(i).padStart(3, "0")}`,
    userId: "user",
    sandboxHostId: "host",
    generation: 1,
    state: "PROVISIONING",
    liveResourcesHeld: true,
  }));
  store = createFenceStore({
    hosts: [{ id: "host", userId: "user", connectionEpoch: 1 }],
    sandboxes,
    operations: sandboxes.map((row) => ({
      id: `op-${row.id}`,
      userId: "user",
      sandboxId: row.id,
      kind: "CREATE_SANDBOX",
      state: "UNKNOWN_OUTCOME",
      generation: 1,
      dispatchAttempt: 1,
      dispatchedHostId: "host",
      dispatchedConnectionEpoch: 1,
    })),
  });
  installFenceTransaction(vi.mocked(prisma, true), store);
  let sequence = 0;
  requests = [];
  attestation = new AllocationAttestation(
    { hostId: "host", userId: "user", connectionEpoch: 1 },
    () => ++sequence,
    (request) => requests.push(request),
  );
});
afterEach(() => {
  attestation.close();
  vi.useRealTimers();
});

it("bounds requests to 256 ids, permits one outstanding page and rejects partial/stale/duplicate answers", async () => {
  await attestation.request();
  await attestation.request();
  expect(requests).toHaveLength(1);
  expect(requests[0]!.sandboxIds).toHaveLength(256);
  const answer = {
    type: "allocation.attest.result" as const,
    connectionEpoch: 1,
    barrier: 1,
    journalId: "a".repeat(32),
    entries: requests[0]!.sandboxIds.map((sandboxId) => ({
      sandboxId,
      sandboxOwnerId: "user",
      settledNeverIssued: false,
    })),
  };
  expect(await attestation.accept({ ...answer, barrier: 2 })).toBe(false);
  expect(await attestation.accept({ ...answer, connectionEpoch: 2 })).toBe(false);
  expect(await attestation.accept({ ...answer, entries: answer.entries.slice(1) })).toBe(false);
  expect(await attestation.accept(answer)).toBe(true);
  expect(await attestation.accept(answer)).toBe(false);
  await vi.advanceTimersByTimeAsync(10 * 60_000 - 1);
  expect(requests).toHaveLength(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(requests).toHaveLength(2);
  expect(requests[1]!.sandboxIds).toHaveLength(44);
  expect(requests[1]!.sandboxIds[0]).toBe("s-256");
});

it("timeout advances the barrier and rejects the expired request; close cancels retries", async () => {
  await attestation.request();
  await vi.advanceTimersByTimeAsync(30_000);
  expect(requests).toHaveLength(1);
  await vi.advanceTimersByTimeAsync(2000);
  expect(requests).toHaveLength(2);
  expect(requests[1]!.barrier).toBe(2);
  expect(
    await attestation.accept({
      type: "allocation.attest.result",
      connectionEpoch: 1,
      barrier: 1,
      journalId: "a".repeat(32),
      entries: requests[0]!.sandboxIds.map((sandboxId) => ({
        sandboxId,
        sandboxOwnerId: "user",
        settledNeverIssued: true,
      })),
    }),
  ).toBe(false);
  attestation.close();
  await vi.advanceTimersByTimeAsync(120_000);
  expect(requests).toHaveLength(2);
});

it("a gathering transport failure keeps the session usable and retries with backoff", async () => {
  attestation.close();
  const send = vi.fn().mockImplementationOnce(() => {
    throw new Error("transport busy");
  });
  let sequence = 0;
  attestation = new AllocationAttestation(
    { userId: "user", hostId: "host", connectionEpoch: 1 },
    () => ++sequence,
    send,
  );
  await expect(attestation.request()).resolves.toBeUndefined();
  expect(send).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(999);
  expect(send).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(send).toHaveBeenCalledTimes(2);
});

it("no candidates parks the timer without acquiring owner or H locks; a fresh UNKNOWN re-arms it", async () => {
  for (const row of store.operations.values()) row.state = "SUCCEEDED";
  const tx = vi.mocked(prisma.$transaction);
  tx.mockClear();
  await attestation.request();
  expect(requests).toHaveLength(0);
  expect(tx).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
  store.operations.get("op-s-001")!.state = "UNKNOWN_OUTCOME";
  await attestation.request("op-s-001");
  expect(requests[0]!.sandboxIds).toEqual(["s-001"]);
  expect(tx).toHaveBeenCalledTimes(1);
  expect(vi.getTimerCount()).toBe(1);
});

it.each([256, 300])(
  "%s stale-generation UNKNOWN operations are not candidates and acquire no locks or timer",
  async (count) => {
    store.sandboxes = new Map([...store.sandboxes].slice(0, count));
    for (const row of store.sandboxes.values()) row.generation = 2;
    vi.mocked(prisma.$transaction).mockClear();
    await attestation.request();
    expect(requests).toHaveLength(0);
    expect(prisma.$transaction).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  },
);

it("a false id is not re-requested by scans or ordinary triggers within ten minutes", async () => {
  store.sandboxes = new Map([...store.sandboxes].slice(0, 1));
  await attestation.request();
  await attestation.accept({
    type: "allocation.attest.result",
    connectionEpoch: 1,
    barrier: 1,
    journalId: "a".repeat(32),
    entries: [{ sandboxOwnerId: "user", sandboxId: "s-000", settledNeverIssued: false }],
  });
  await attestation.request();
  await vi.advanceTimersByTimeAsync(10 * 60_000 - 1);
  expect(requests).toHaveLength(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(requests).toHaveLength(2);
  expect(requests[1]!.sandboxIds).toEqual(["s-000"]);
});

it("a fresh UNKNOWN during a pending request is asked after the answer despite the negative cooldown", async () => {
  await attestation.request("op-s-000");
  await attestation.request("op-s-001");
  await attestation.accept({
    type: "allocation.attest.result",
    connectionEpoch: 1,
    barrier: 1,
    journalId: "a".repeat(32),
    entries: [{ sandboxOwnerId: "user", sandboxId: "s-000", settledNeverIssued: false }],
  });
  await vi.advanceTimersByTimeAsync(0);
  expect(requests[1]!.sandboxIds).toEqual(["s-001"]);
});

it("a full stale page cannot starve current-generation UNKNOWN candidates on the next page", async () => {
  for (const row of [...store.sandboxes.values()].slice(0, 256)) row.generation = 2;
  await attestation.request();
  expect(requests).toHaveLength(1);
  expect(requests[0]!.sandboxIds).toHaveLength(44);
  expect(requests[0]!.sandboxIds[0]).toBe("s-256");
});

it("an unrelated UNKNOWN on the same sandbox cannot bypass a false allocation's cooldown", async () => {
  await attestation.request("op-s-000");
  await attestation.accept({
    type: "allocation.attest.result",
    connectionEpoch: 1,
    barrier: 1,
    journalId: "a".repeat(32),
    entries: [{ sandboxOwnerId: "user", sandboxId: "s-000", settledNeverIssued: false }],
  });
  store.operations.set("command", {
    ...store.operations.get("op-s-000")!,
    id: "command",
    kind: "RUN_COMMAND",
  });
  await attestation.request("command");
  expect(requests).toHaveLength(1);
  await vi.advanceTimersByTimeAsync(60_000);
  expect(requests).toHaveLength(1);
});

it("an empty command UNKNOWN trigger preserves the periodic deadline for page 2 of 300", async () => {
  await attestation.request();
  const first = requests[0]!;
  await attestation.accept({
    type: "allocation.attest.result",
    connectionEpoch: 1,
    barrier: first.barrier,
    journalId: "a".repeat(32),
    entries: first.sandboxIds.map((sandboxId) => ({
      sandboxId,
      sandboxOwnerId: "user",
      settledNeverIssued: true,
    })),
  });
  // Model the answered page leaving the candidate set after settlement.
  for (const id of first.sandboxIds) store.sandboxes.get(id)!.liveResourcesHeld = false;
  store.operations.set("command", {
    ...store.operations.get("op-s-000")!,
    id: "command",
    kind: "RUN_COMMAND",
  });
  await attestation.request("command");
  await vi.advanceTimersByTimeAsync(0);
  expect(requests).toHaveLength(1);
  // The existing deadline must survive even an empty targeted preflight.
  await vi.advanceTimersByTimeAsync(2000);
  expect(requests).toHaveLength(2);
  expect(requests[1]!.sandboxIds).toHaveLength(44);
  expect(requests[1]!.sandboxIds[0]).toBe("s-256");
});

it("an empty targeted trigger falls through to an idle scan and parks", async () => {
  for (const row of store.operations.values()) row.state = "SUCCEEDED";
  vi.mocked(prisma.$transaction).mockClear();
  await attestation.request("retired-allocation");
  await vi.advanceTimersByTimeAsync(30 * 60_000);
  expect(requests).toHaveLength(0);
  expect(prisma.$transaction).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

it.each([3, 300, 512, 513])(
  "retains %s fresh triggers, deduplicating and sweeping overflow before cooldown",
  { timeout: 15_000 },
  async (count) => {
    for (let i = 300; i < count; i++) {
      const id = `s-${String(i).padStart(3, "0")}`;
      store.sandboxes.set(id, { ...store.sandboxes.get("s-000")!, id });
      store.operations.set(`op-${id}`, {
        ...store.operations.get("op-s-000")!,
        id: `op-${id}`,
        sandboxId: id,
      });
    }
    await attestation.request("op-s-000");
    for (let i = 1; i < count; i++) {
      const id = `op-s-${String(i).padStart(3, "0")}`;
      await attestation.request(id);
      await attestation.request(id);
    }
    const startedAt = Date.now();
    const asked = new Set<string>();
    let consumed = 0;
    while (asked.size < count && consumed < count + 3) {
      const request = requests[consumed++];
      expect(request).toBeDefined();
      for (const id of request!.sandboxIds) asked.add(id);
      await attestation.accept({
        type: "allocation.attest.result",
        connectionEpoch: 1,
        barrier: request!.barrier,
        journalId: "a".repeat(32),
        entries: request!.sandboxIds.map((sandboxId) => ({
          sandboxId,
          sandboxOwnerId: "user",
          settledNeverIssued: false,
        })),
      });
      if (asked.size < count) await vi.advanceTimersToNextTimerAsync();
    }
    expect(asked.size).toBe(count);
    expect(Date.now() - startedAt).toBeLessThan(10 * 60_000);
    if (count > 256) {
      // Neither a short tail nor discovery of an exact full-page tail may
      // restart the scan before the last negative answer's ten-minute deadline.
      const sent = requests.length;
      await vi.advanceTimersByTimeAsync(10 * 60_000 - 1);
      expect(requests).toHaveLength(sent);
      await vi.advanceTimersByTimeAsync(1);
      expect(requests).toHaveLength(sent + 1);
    }
    if (count === 3)
      expect(requests.slice(0, 3).map((r) => r.sandboxIds)).toEqual([
        ["s-000"],
        ["s-001"],
        ["s-002"],
      ]);
  },
);
