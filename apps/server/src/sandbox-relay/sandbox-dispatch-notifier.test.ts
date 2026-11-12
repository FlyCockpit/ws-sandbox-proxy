vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { inspect } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  SANDBOX_DISPATCH_RECOVERY_POLL_MS,
  SandboxDispatchNotifier,
} from "./sandbox-dispatch-notifier.js";

async function flushMicrotasks() {
  await Promise.resolve();
  await Promise.resolve();
}

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, resolve: () => release() };
}

describe("SandboxDispatchNotifier", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("drains immediately on wake before scheduling recovery", async () => {
    vi.useFakeTimers();
    const drainBatch = vi.fn().mockResolvedValue(0);
    const notifier = new SandboxDispatchNotifier({ drainBatch });
    notifier.wake();
    await vi.advanceTimersByTimeAsync(0);
    expect(drainBatch).toHaveBeenCalledTimes(1);
    notifier.stop();
  });

  it("coalesces overlapping wakes into one running drain", async () => {
    vi.useFakeTimers();
    const entered = gate();
    const resume = gate();
    const drainBatch = vi.fn().mockImplementation(async () => {
      entered.resolve();
      await resume.promise;
      return 0;
    });
    const notifier = new SandboxDispatchNotifier({ drainBatch });
    notifier.wake();
    await vi.advanceTimersByTimeAsync(0);
    await entered.promise;
    notifier.wake();
    notifier.wake();
    expect(drainBatch).toHaveBeenCalledTimes(1);
    resume.resolve();
    await flushMicrotasks();
    await vi.advanceTimersByTimeAsync(0);
    expect(drainBatch).toHaveBeenCalledTimes(2);
    notifier.stop();
  });

  it("re-drains when a wake arrives during drain", async () => {
    vi.useFakeTimers();
    let phase = 0;
    let notifier!: SandboxDispatchNotifier;
    const drainBatch = vi.fn().mockImplementation(async () => {
      phase += 1;
      if (phase === 1) notifier.wake();
      return phase === 1 ? 1 : 0;
    });
    notifier = new SandboxDispatchNotifier({ drainBatch });
    notifier.wake();
    await vi.advanceTimersByTimeAsync(0);
    await flushMicrotasks();
    expect(drainBatch).toHaveBeenCalledTimes(2);
    notifier.stop();
  });

  it("keeps draining while batches report work before the recovery clock", async () => {
    vi.useFakeTimers();
    const drainBatch = vi
      .fn()
      .mockResolvedValueOnce(3)
      .mockResolvedValueOnce(1)
      .mockResolvedValue(0);
    const notifier = new SandboxDispatchNotifier({ drainBatch, recoveryPollMs: 2_000 });
    notifier.wake();
    await vi.advanceTimersByTimeAsync(0);
    expect(drainBatch).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(SANDBOX_DISPATCH_RECOVERY_POLL_MS - 1);
    expect(drainBatch).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(1);
    expect(drainBatch).toHaveBeenCalledTimes(4);
    notifier.stop();
  });

  it("recovers a lost wake via the periodic recovery scan", async () => {
    vi.useFakeTimers();
    const drainBatch = vi.fn().mockResolvedValue(0);
    const notifier = new SandboxDispatchNotifier({ drainBatch, recoveryPollMs: 2_000 });
    notifier.wake();
    await vi.advanceTimersByTimeAsync(0);
    expect(drainBatch).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(drainBatch).toHaveBeenCalledTimes(2);
    notifier.stop();
  });

  it("stop drains once and suppresses further recovery ticks", async () => {
    vi.useFakeTimers();
    const entered = gate();
    const resume = gate();
    const drainBatch = vi.fn().mockImplementation(async () => {
      entered.resolve();
      await resume.promise;
      return 0;
    });
    const notifier = new SandboxDispatchNotifier({ drainBatch, recoveryPollMs: 2_000 });
    notifier.wake();
    await vi.advanceTimersByTimeAsync(0);
    await entered.promise;
    const stopped = notifier.stop();
    expect(notifier.stop()).toBe(stopped);
    let finished = false;
    void stopped.then(() => {
      finished = true;
    });
    await flushMicrotasks();
    expect(finished).toBe(false);
    resume.resolve();
    await stopped;
    expect(finished).toBe(true);
    await flushMicrotasks();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(drainBatch).toHaveBeenCalledTimes(1);
  });

  it("does not overlap async drain passes", async () => {
    vi.useFakeTimers();
    const entered = gate();
    const resume = gate();
    const drainBatch = vi.fn().mockImplementation(async () => {
      entered.resolve();
      await resume.promise;
      return 0;
    });
    const notifier = new SandboxDispatchNotifier({ drainBatch });
    notifier.wake();
    await vi.advanceTimersByTimeAsync(0);
    await entered.promise;
    notifier.wake();
    await vi.advanceTimersByTimeAsync(0);
    expect(drainBatch).toHaveBeenCalledTimes(1);
    resume.resolve();
    await flushMicrotasks();
    await vi.advanceTimersByTimeAsync(0);
    expect(drainBatch).toHaveBeenCalledTimes(2);
    notifier.stop();
  });
});

it("3A notifier raw-producer bypass is values-free and recovery keeps polling", async () => {
  vi.useFakeTimers();
  const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
  const sentinel = "synthetic-env-stdin-notifier-3a";
  const drainBatch = vi
    .fn()
    .mockRejectedValueOnce(
      new Error(sentinel, { cause: new Error(Buffer.from(sentinel).toString("base64")) }),
    )
    .mockResolvedValue(0);
  const notifier = new SandboxDispatchNotifier({ drainBatch });
  try {
    notifier.wake();
    await vi.advanceTimersByTimeAsync(0);
    expect(log).toHaveBeenCalledWith("[sandbox-relay] dispatch drain failed:", {
      code: "unhandled_error",
      errorClass: "Error",
    });
    expect(inspect(log.mock.calls, { depth: 20 })).not.toContain(sentinel);
    expect(inspect(log.mock.calls, { depth: 20 })).not.toContain(
      Buffer.from(sentinel).toString("base64"),
    );
    await vi.advanceTimersByTimeAsync(SANDBOX_DISPATCH_RECOVERY_POLL_MS);
    expect(drainBatch).toHaveBeenCalledTimes(2);
  } finally {
    await notifier.stop();
    log.mockRestore();
    vi.useRealTimers();
  }
});
