vi.mock("../../../../packages/api/src/sandbox/host-retention.js", () => ({
  sweepHostAccessRetention: vi.fn(async () => ({ queued: 0, audit: 0 })),
}));
vi.mock("@wssp/api/sandbox/connect-session-retention", () => ({
  purgeConnectSessions: vi.fn(async () => 4),
}));

import type { ReapExpiredAuthTokensJobData } from "@wssp/queue";
import type { Job } from "bullmq";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});
// Real `@wssp/queue` constructs BullMQ Queues at import (IORedis sockets), but
// `@wssp/queue/jobs` is the side-effect-free half — so the job schema the
// handler validates with is the real one while no socket is opened.
vi.mock("@wssp/queue", async () => {
  const jobs = await import("@wssp/queue/jobs");
  return { ...jobs };
});

const { default: prisma } = await import("@wssp/db");
const { handleReapExpiredAuthTokensJob } = await import("./reap-expired-auth-tokens.js");

const db = prisma as unknown as {
  session: { findMany: MockInstance; deleteMany: MockInstance };
  verification: { findMany: MockInstance; deleteMany: MockInstance };
  deviceCode: { findMany: MockInstance; deleteMany: MockInstance };
};

const job = () =>
  ({ id: "job-1", data: { reason: "cron" } }) as unknown as Job<ReapExpiredAuthTokensJobData>;

function primeEmptySweeps() {
  db.session.findMany.mockResolvedValue([]);
  db.verification.findMany.mockResolvedValue([]);
  db.deviceCode.findMany.mockResolvedValue([]);
}

describe("handleReapExpiredAuthTokensJob", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "log").mockImplementation(() => {});
    primeEmptySweeps();
  });

  it("deletes only rows past expiresAt, per model, and reports the counts", async () => {
    const before = Date.now();
    db.session.findMany.mockResolvedValueOnce([{ id: "session-1" }, { id: "session-2" }]);
    db.session.deleteMany.mockResolvedValueOnce({ count: 2 });
    db.verification.findMany.mockResolvedValueOnce([{ id: "verification-1" }]);
    db.verification.deleteMany.mockResolvedValueOnce({ count: 1 });

    await expect(handleReapExpiredAuthTokensJob(job())).resolves.toEqual({
      reason: "cron",
      deleted: { sessions: 2, verifications: 1, deviceCodes: 0 },
    });

    for (const model of [db.session, db.verification, db.deviceCode]) {
      const where = model.findMany.mock.calls[0]?.[0]?.where;
      expect(where.expiresAt.lt).toBeInstanceOf(Date);
      expect((where.expiresAt.lt as Date).getTime()).toBeGreaterThanOrEqual(before);
    }
    expect(db.session.findMany.mock.calls[0]?.[0]).toMatchObject({
      select: { id: true },
      orderBy: { expiresAt: "asc" },
      take: 1000,
    });

    // Deletes are bounded id-page deletes, never a naked deleteMany, and they
    // recheck expiry so a row renewed between the page read and the delete survives.
    const cutoff = db.session.findMany.mock.calls[0]?.[0]?.where.expiresAt.lt;
    expect(db.session.deleteMany).toHaveBeenCalledWith({
      where: { id: { in: ["session-1", "session-2"] }, expiresAt: { lt: cutoff } },
    });
    expect(db.verification.deleteMany).toHaveBeenCalledWith({
      where: {
        id: { in: ["verification-1"] },
        expiresAt: { lt: db.verification.findMany.mock.calls[0]?.[0]?.where.expiresAt.lt },
      },
    });
  });

  it("keeps paging a model until a short page, without touching the others", async () => {
    const fullPage = Array.from({ length: 1000 }, (_, i) => ({ id: `session-${i}` }));
    db.session.findMany
      .mockResolvedValueOnce(fullPage)
      .mockResolvedValueOnce([{ id: "session-tail" }]);
    db.session.deleteMany
      .mockResolvedValueOnce({ count: 1000 })
      .mockResolvedValueOnce({ count: 1 });

    await expect(handleReapExpiredAuthTokensJob(job())).resolves.toMatchObject({
      deleted: { sessions: 1001, deviceCodes: 0 },
    });

    expect(db.session.findMany).toHaveBeenCalledTimes(2);
    const cutoff = db.session.findMany.mock.calls[0]?.[0]?.where.expiresAt.lt;
    expect(db.session.deleteMany).toHaveBeenNthCalledWith(1, {
      where: { id: { in: fullPage.map((row) => row.id) }, expiresAt: { lt: cutoff } },
    });
    expect(db.session.deleteMany).toHaveBeenNthCalledWith(2, {
      where: { id: { in: ["session-tail"] }, expiresAt: { lt: cutoff } },
    });
    // The short page (1 < 1000) ended the session sweep after two pages.

    expect(db.verification.findMany).toHaveBeenCalledTimes(1);
    expect(db.verification.deleteMany).not.toHaveBeenCalled();
    expect(db.deviceCode.findMany).toHaveBeenCalledTimes(1);
    expect(db.deviceCode.deleteMany).not.toHaveBeenCalled();
  });

  it("reports zero across the board when nothing has expired", async () => {
    await expect(handleReapExpiredAuthTokensJob(job())).resolves.toEqual({
      reason: "cron",
      deleted: { sessions: 0, verifications: 0, deviceCodes: 0 },
    });
    expect(db.session.deleteMany).not.toHaveBeenCalled();
    expect(db.verification.deleteMany).not.toHaveBeenCalled();
    expect(db.deviceCode.deleteMany).not.toHaveBeenCalled();
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("0 device code(s)"));
  });

  it("also purges CLI connection audit rows past retention", async () => {
    const { purgeConnectSessions } = await import("@wssp/api/sandbox/connect-session-retention");
    await handleReapExpiredAuthTokensJob(job());
    expect(purgeConnectSessions).toHaveBeenCalledTimes(1);
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("4 connect session(s)"));
  });

  it("rejects a payload the schema does not describe", async () => {
    const bad = {
      id: "job-2",
      data: { reason: "admin" },
    } as unknown as Job<ReapExpiredAuthTokensJobData>;

    await expect(handleReapExpiredAuthTokensJob(bad)).rejects.toThrow();
    expect(db.session.findMany).not.toHaveBeenCalled();
  });
});
