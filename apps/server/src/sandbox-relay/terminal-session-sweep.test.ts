import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/env/server", () => ({ env: {} }));

const { startTerminalSessionSweep } = await import("./terminal-session-sweep.js");

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("sandbox-terminal-session-sweep", () => {
  it("sweeps at start and on every interval with a bounded budget, never overlapping", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    let release: (() => void) | undefined;
    const sweep = vi.fn(
      (_now?: Date, _options?: { budgetMs?: number }) =>
        new Promise<{ deleted: number }>((resolve) => {
          release = () => resolve({ deleted: 1 });
        }),
    );
    const stop = startTerminalSessionSweep(controller.signal, 1000, () => new Date(0), sweep);
    expect(sweep).toHaveBeenCalledTimes(1);
    expect(sweep.mock.calls[0]?.[1]).toMatchObject({ budgetMs: 30_000 });
    // A tick while the previous sweep is still running is skipped.
    await vi.advanceTimersByTimeAsync(1000);
    expect(sweep).toHaveBeenCalledTimes(1);
    release?.();
    await vi.advanceTimersByTimeAsync(1000);
    expect(sweep).toHaveBeenCalledTimes(2);
    release?.();
    controller.abort();
    await stop();
    await vi.advanceTimersByTimeAsync(5000);
    expect(sweep).toHaveBeenCalledTimes(2);
  });

  it("a failed sweep is logged by class and the next tick runs", async () => {
    vi.useFakeTimers();
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const sweep = vi.fn().mockRejectedValueOnce(new Error("db down")).mockResolvedValue({
      deleted: 0,
    });
    const controller = new AbortController();
    const stop = startTerminalSessionSweep(controller.signal, 1000, () => new Date(0), sweep);
    await vi.advanceTimersByTimeAsync(1000);
    expect(errors).toHaveBeenCalledTimes(1);
    expect(String(errors.mock.calls[0]?.[0])).toContain("sandbox-terminal-session-sweep");
    expect(sweep).toHaveBeenCalledTimes(2);
    controller.abort();
    await stop();
  });
});
