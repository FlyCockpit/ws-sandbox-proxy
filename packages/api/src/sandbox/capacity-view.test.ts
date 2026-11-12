import { vmLiveMemoryChargeMiB, vmRootChargeGiB } from "@wssp/sandbox-contracts";
import { expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64) },
}));
vi.mock("./services/sharing", () => ({ getUsablePool: async () => ({ id: "pool-1" }) }));
vi.mock("./capacity-queue", () => ({ reservedHostIds: async () => [] }));
vi.mock("./lease-policy", async (original) => ({
  ...(await original<typeof import("./lease-policy")>()),
  poolLeaseViews: async () => new Map(),
}));

const { default: prisma } = await import("@wssp/db");
const db = vi.mocked(prisma, true);
const { dominantShareAfter, poolCapacityView } = await import("./capacity-view");
const { sessionPrincipal } = await import("./contracts");
const size = { cpuCount: 2, memoryMiB: 4096, diskGiB: 32 };

it("dominantShareAfter mirrors the SQL rank: max of RAM, vCPU and storage shares after the request (unit; SQL rank: placement.pg.test.ts)", () => {
  const host = {
    memoryReservedMiB: 0,
    daemonMemoryBudgetMiB: 65536,
    vcpuReserved: 0,
    daemonVcpuBudget: 64,
  };
  const storage = { capacityGiB: 1000, reservedGiB: 0 };
  expect(dominantShareAfter(host, storage, size)).toBeCloseTo(
    Math.max(vmLiveMemoryChargeMiB(4096) / 65536, 2 / 64, vmRootChargeGiB(32) / 1000),
  );
  // Disk-dominant.
  expect(dominantShareAfter(host, { capacityGiB: 100, reservedGiB: 50 }, size)).toBeCloseTo(
    (50 + vmRootChargeGiB(32)) / 100,
  );
  // vCPU-dominant.
  expect(dominantShareAfter({ ...host, vcpuReserved: 60 }, storage, size)).toBeCloseTo(62 / 64);
  // Unknown or zero budgets are skipped, never divided by.
  expect(
    dominantShareAfter({ ...host, daemonMemoryBudgetMiB: null, daemonVcpuBudget: 0 }, null, size),
  ).toBeNull();
});

it.each([true, false])(
  "includes capacity only when the shared guard predicate passes (%s)",
  async (guard) => {
    const now = new Date("2026-11-12T00:00:00Z");
    db.sandboxPool.findFirst.mockResolvedValue({
      id: "pool-1",
      userId: "owner-1",
      capacityWaitMaxMs: null,
      capacityQueuePerKeyMax: null,
      capacityQueuePerOwnerMax: null,
    } as never);
    db.sandboxCapacityWait.count.mockResolvedValue(0);
    db.sandboxCapacityWait.findMany.mockResolvedValue([]);
    db.$queryRaw.mockReset();
    db.$queryRaw
      .mockResolvedValueOnce([{ now }])
      .mockResolvedValueOnce([
        {
          id: "host-1",
          slug: "host",
          label: "Host",
          status: "CONNECTED",
          draining: false,
          own: true,
          ownerLocal: true,
          memoryBudget: 65536,
          memoryReserved: 0,
          vcpuBudget: 64,
          vcpuReserved: 0,
          rootCount: 0,
          liveCount: 0,
          memoryCap: null,
          vcpuCap: null,
          memberMaxLeaseMs: null,
          usageMemory: 0n,
          usageVcpu: 0n,
          enabled: true,
          compatible: true,
          startup: true,
          online: true,
          guard,
          known: true,
          current: true,
          leaseFits: true,
          perVm: true,
        },
      ])
      .mockResolvedValueOnce([
        {
          hostId: "host-1",
          name: "default",
          capacityGiB: 1000,
          reservedGiB: 0,
          usable: true,
        },
      ]);
    const view = await poolCapacityView(sessionPrincipal("owner-1"), { id: "pool-1", ...size });
    expect(view.hosts[0]?.schedulable).toBe(guard);
    if (guard) {
      expect(view.fits).toBeGreaterThan(0);
      expect(view.aggregate.free.memoryMiB).toBeGreaterThan(0);
    } else {
      expect(view.fits).toBe(0);
      expect(view.aggregate).toEqual({
        free: { memoryMiB: 0, vcpu: 0, diskGiB: 0 },
        budget: { memoryMiB: 0, vcpu: 0, diskGiB: 0 },
      });
    }
    // Exercise the real placement SQL builder: the view selects its full guard
    // predicate, including both connection epoch and the server-clock lease.
    const hostQuery = db.$queryRaw.mock.calls[1];
    const fragments = hostQuery
      ?.slice(1)
      .filter(
        (value) =>
          typeof value === "object" &&
          value !== null &&
          "sql" in value &&
          typeof value.sql === "string" &&
          value.sql.includes('h."daemonEgressGuardOk"'),
      );
    expect(fragments).toHaveLength(1);
    expect(fragments?.[0]).toEqual(
      expect.objectContaining({
        sql: expect.stringContaining('h."daemonEgressGuardEpoch" = h."connectionEpoch"'),
        values: [now],
      }),
    );
    expect(fragments?.[0]).toEqual(
      expect.objectContaining({
        sql: expect.stringContaining('h."daemonEgressGuardLeaseUntil" > ?'),
      }),
    );
  },
);
