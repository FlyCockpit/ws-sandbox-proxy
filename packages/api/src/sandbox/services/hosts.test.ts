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
it("projects only the last fifty audit metadata rows to the host owner's dashboard", async () => {
  db.sandboxHost.findFirst.mockResolvedValue({
    id: "host",
    userId: "owner",
    StoragePools: [],
    createdAt: new Date(),
    policyReconcilerHealth: null,
  } as never);
  db.hostAuditEvent.findMany.mockResolvedValue([]);
  const { getHost } = await import("./hosts");
  const result = await getHost({ kind: "session", ownerId: "owner" }, { id: "host" });
  expect(result.recentAudit).toEqual([]);
  expect(db.hostAuditEvent.findMany).toHaveBeenCalledWith({
    where: { userId: "owner", sandboxHostId: "host" },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: 50,
    select: { id: true, createdAt: true, actor: true, kind: true, program: true, state: true },
  });
});

it("projects only the owner's node-reported agent access", async () => {
  const { bindHostAccess } = await import("../host-access");
  const { mockDeep } = await import("vitest-mock-extended");
  const bridge = mockDeep<import("../host-access").HostAccessBridge>();
  bridge.read.mockReturnValue({
    hostCommands: true,
    hostFiles: false,
    agentPolicyRevision: 1,
    lowerPending: false,
  });
  bindHostAccess(bridge);
  try {
    db.sandboxHost.findMany.mockResolvedValue([
      { id: "h", userId: "owner", StoragePools: [], createdAt: new Date() },
    ] as never);
    const result = await listHosts({ kind: "session", ownerId: "owner" }, { limit: 10 });
    expect(result.items[0]!.agentAccess).toEqual({
      owned: true,
      hostCommands: true,
      hostFiles: false,
    });
    db.sandboxHost.findMany.mockResolvedValue([
      { id: "h", userId: "someone-else", StoragePools: [], createdAt: new Date() },
    ] as never);
    const foreign = await listHosts({ kind: "session", ownerId: "owner" }, { limit: 10 });
    expect(foreign.items[0]!.agentAccess).toEqual({ owned: false });
  } finally {
    bindHostAccess(null);
  }
});
