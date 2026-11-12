import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/queue", () => ({ redisConnection: null }));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
const { default: db } = await import("@wssp/db");
const { listHosts } = await import("./hosts");
const health = {
  enabled: true,
  lastPassUnixMs: 123,
  verified: 2,
  drift: 1,
  inconclusive: 0,
  foreign: 0,
  absent: 0,
  pending: 3,
  reportedAt: "2030-01-01T00:00:00.000Z",
};
describe("owner host reconciler-health projection", () => {
  beforeEach(() => vi.clearAllMocks());
  it.each([health, null, { ...health, unexpected: "private" }])(
    "discloses only a validated bounded report, preserving owner scope",
    async (report) => {
      db.sandboxHost.findMany.mockResolvedValue([
        {
          id: "host-1",
          draining: false,
          liveCount: 0,
          memoryReservedMiB: 0,
          vcpuReserved: 0,
          rootCount: 0,
          StoragePools: [],
          egressEnforcement: false,
          createdAt: new Date("2030-01-01"),
          policyReconcilerHealth: report,
        },
      ] as never);
      const result = await listHosts({ kind: "session", ownerId: "owner-1" }, { limit: 10 });
      expect(db.sandboxHost.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { AND: [{ userId: "owner-1" }] },
          take: 11,
        }),
      );
      expect(result.items[0]).not.toHaveProperty("capabilities");
      expect(result.items[0]).not.toHaveProperty("policyReconcilerHealth");
      expect(result.items[0]).not.toHaveProperty("privateMetadata");
      expect(result.items[0]!.egressEnforcement).toBe(false);
      if (report === health) expect(result.items[0]!.policyReconciler).toEqual(health);
      else expect(result.items[0]).not.toHaveProperty("policyReconciler");
    },
  );
});
