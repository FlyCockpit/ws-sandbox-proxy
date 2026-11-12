import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/env/server", () => ({ env: {} }));

const { CapacityQueueScheduler, headDecision } = await import("./capacity-queue");
const { HEAD_BYPASS_LIMIT, QUEUE_RECHECK_MS } = await import("./capacity-limits");

describe("head protection decision table — unit (pure; SQL gate proven in capacity-queue.pg.test.ts)", () => {
  it.each([
    [{ isHead: true, headExists: true, hostInHeadSet: true, bypassCount: 99 }, "place"],
    [{ isHead: false, headExists: false, hostInHeadSet: true, bypassCount: 0 }, "place"],
    [{ isHead: false, headExists: true, hostInHeadSet: false, bypassCount: 99 }, "place"],
    [{ isHead: false, headExists: true, hostInHeadSet: true, bypassCount: 0 }, "place_bypass"],
    [
      { isHead: false, headExists: true, hostInHeadSet: true, bypassCount: HEAD_BYPASS_LIMIT - 1 },
      "place_bypass",
    ],
    [
      { isHead: false, headExists: true, hostInHeadSet: true, bypassCount: HEAD_BYPASS_LIMIT },
      "deny",
    ],
  ] as const)("%o → %s", (input, outcome) => {
    expect(headDecision(input)).toBe(outcome);
  });
});

describe("CapacityQueueScheduler — unit (fake timers; real passes: capacity-queue.pg.test.ts)", () => {
  afterEach(() => vi.useRealTimers());

  it("coalesces hints into one pass, overflows to all, arms the deadline timer and stops cleanly", async () => {
    vi.useFakeTimers();
    let release: () => void = () => {};
    const hints: unknown[] = [];
    const pass = vi.fn(async (_stop: () => boolean, hint: unknown) => {
      hints.push(hint);
      if (hints.length === 1) await new Promise<void>((resolve) => (release = resolve));
      return hints.length === 2 ? 1_000 : null;
    });
    const scheduler = new CapacityQueueScheduler(pass);
    // The constructor runs one "all" pass; these coalesce behind it.
    scheduler.wake({ poolIds: ["p1"] });
    scheduler.wake({ hostIds: ["h1"] });
    scheduler.wake({ poolIds: ["p2"] });
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(hints[0]).toBe("all");
    expect(hints[1]).toEqual({ poolIds: ["p1", "p2"], hostIds: ["h1"] });
    expect(pass).toHaveBeenCalledTimes(2);
    // The second pass reported a deadline 1 s away: the timer wakes "all".
    await vi.advanceTimersByTimeAsync(1_100);
    expect(pass).toHaveBeenCalledTimes(3);
    expect(hints[2]).toBe("all");
    scheduler.wake({ poolIds: Array.from({ length: 300 }, (_, i) => `p${i}`) });
    await vi.advanceTimersByTimeAsync(0);
    expect(hints[3]).toBe("all");
    await vi.advanceTimersByTimeAsync(QUEUE_RECHECK_MS);
    expect(pass).toHaveBeenCalledTimes(5);
    await scheduler.stop();
    scheduler.wake();
    await vi.advanceTimersByTimeAsync(QUEUE_RECHECK_MS * 2);
    expect(pass).toHaveBeenCalledTimes(5);
  });

  it("a failing pass is logged and retried on the next wake", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const pass = vi.fn(async () => {
      throw new Error("boom");
    });
    const scheduler = new CapacityQueueScheduler(pass);
    await vi.waitFor(() => expect(pass).toHaveBeenCalledTimes(1));
    scheduler.wake();
    await vi.waitFor(() => expect(pass).toHaveBeenCalledTimes(2));
    await scheduler.stop();
  });
});
