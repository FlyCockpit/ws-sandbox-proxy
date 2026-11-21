import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
const { default: prisma } = await import("@wssp/db");
const db = prisma as unknown as import("../test/mock-prisma").MockPrisma;
const { purgeConnectSessions } = await import("./connect-session-retention");

beforeEach(() => vi.clearAllMocks());

const DAY = 86_400_000;

describe("purgeConnectSessions", () => {
  it("deletes 90-day-old rows in bounded id batches, rechecking the cutoff", async () => {
    const now = new Date("2030-06-01T00:00:00Z");
    const cutoff = new Date(now.getTime() - 90 * DAY);
    db.sandboxConnectSession.findMany
      .mockResolvedValueOnce([{ id: "a" }, { id: "b" }] as never)
      .mockResolvedValueOnce([{ id: "c" }] as never);
    db.sandboxConnectSession.deleteMany
      .mockResolvedValueOnce({ count: 2 })
      .mockResolvedValueOnce({ count: 1 });
    await expect(purgeConnectSessions({ now, batch: 2 })).resolves.toBe(3);
    expect(db.sandboxConnectSession.findMany).toHaveBeenCalledTimes(2);
    expect(db.sandboxConnectSession.findMany).toHaveBeenCalledWith({
      where: { openedAt: { lt: cutoff } },
      orderBy: [{ openedAt: "asc" }, { id: "asc" }],
      take: 2,
      select: { id: true },
    });
    expect(db.sandboxConnectSession.deleteMany).toHaveBeenNthCalledWith(1, {
      where: { openedAt: { lt: cutoff }, id: { in: ["a", "b"] } },
    });
  });

  it("stops at maxBatches and clamps the batch size", async () => {
    db.sandboxConnectSession.findMany.mockResolvedValue(
      Array.from({ length: 1000 }, (_, i) => ({ id: `r${i}` })) as never,
    );
    db.sandboxConnectSession.deleteMany.mockResolvedValue({ count: 1000 });
    await expect(purgeConnectSessions({ batch: 50_000, maxBatches: 3 })).resolves.toBe(3000);
    expect(db.sandboxConnectSession.findMany).toHaveBeenCalledTimes(3);
    expect(db.sandboxConnectSession.findMany.mock.calls[0]?.[0]?.take).toBe(1000);
  });
});
