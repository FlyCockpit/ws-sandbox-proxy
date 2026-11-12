import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ reap: vi.fn() }));
vi.mock("@wssp/api/webhooks/ledger", () => ({ reapWebhookLog: state.reap }));
vi.mock("@wssp/queue", async () => await import("@wssp/queue/jobs"));
const { handleReapWebhookLogJob } = await import("./reap-webhook-log.js");

beforeEach(() => vi.clearAllMocks());

describe("reap-webhook-log (unit; batch deletes: webhook-ledger.pg.test.ts)", () => {
  it("runs the bounded prune for a cron job and reports the count", async () => {
    state.reap.mockResolvedValue(3);
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await expect(handleReapWebhookLogJob({ id: "j1", data: { reason: "cron" } })).resolves.toEqual({
      reason: "cron",
      deleted: 3,
    });
    expect(state.reap).toHaveBeenCalledOnce();
    log.mockRestore();
  });

  it("refuses unknown job data before touching the database", async () => {
    await expect(
      handleReapWebhookLogJob({ id: "j2", data: { reason: "manual" } as never }),
    ).rejects.toThrow();
    expect(state.reap).not.toHaveBeenCalled();
  });
});
