import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
const { default: prisma } = await import("@wssp/db");
const db = prisma as unknown as import("../test/mock-prisma").MockPrisma;
const { sweepHostAccessRetention } = await import("./host-retention");
beforeEach(() => vi.clearAllMocks());
it("bounds deletion, rechecks terminal state and ages, and expires pending rows", async () => {
  db.hostQueuedCommand.findMany.mockResolvedValue([{ id: "q" }] as never);
  db.hostQueuedCommand.deleteMany.mockResolvedValue({ count: 1 });
  db.hostAuditEvent.findMany.mockResolvedValue([{ id: "a" }] as never);
  db.hostAuditEvent.deleteMany.mockResolvedValue({ count: 1 });
  db.hostFileReceipt.findMany.mockResolvedValue([{ id: "r" }] as never);
  db.hostFileReceipt.deleteMany.mockResolvedValue({ count: 1 });
  const now = new Date("2030-01-01T00:00:00Z");
  expect(await sweepHostAccessRetention(now, 10)).toEqual({ queued: 1, audit: 1, fileReceipts: 1 });
  expect(db.hostFileReceipt.deleteMany).toHaveBeenCalledWith({
    where: { expiresAt: { lte: now }, id: { in: ["r"] } },
  });
  expect(db.hostQueuedCommand.findMany).toHaveBeenCalledWith(expect.objectContaining({ take: 10 }));
  expect(db.hostAuditEvent.deleteMany).toHaveBeenCalledWith({
    where: { createdAt: { lt: new Date(now.getTime() - 90 * 86400000) }, id: { in: ["a"] } },
  });
  expect(db.hostQueuedCommand.deleteMany).toHaveBeenCalledWith(
    expect.objectContaining({
      where: {
        AND: [expect.objectContaining({ state: { not: "QUEUED" } }), { id: { in: ["q"] } }],
      },
    }),
  );
});

it("pages expired host file receipts by id keyset until a short page", async () => {
  db.hostQueuedCommand.findMany.mockResolvedValue([] as never);
  db.hostAuditEvent.findMany.mockResolvedValue([] as never);
  db.hostFileReceipt.findMany
    .mockResolvedValueOnce([{ id: "a" }, { id: "b" }] as never)
    .mockResolvedValueOnce([{ id: "c" }] as never);
  db.hostFileReceipt.deleteMany
    .mockResolvedValueOnce({ count: 2 })
    .mockResolvedValueOnce({ count: 1 });
  const now = new Date("2030-01-01T00:00:00Z");
  expect((await sweepHostAccessRetention(now, 2)).fileReceipts).toBe(3);
  expect(db.hostFileReceipt.findMany).toHaveBeenNthCalledWith(2, {
    where: { expiresAt: { lte: now }, id: { gt: "b" } },
    orderBy: { id: "asc" },
    take: 2,
    select: { id: true },
  });
});
