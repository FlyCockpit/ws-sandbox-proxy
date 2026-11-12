import { afterEach, expect, it, vi } from "vitest";
import { SharingAccessScheduler } from "./sharing-access-scheduler";

afterEach(() => vi.useRealTimers());
it("keeps a 15-second access clock independent of dispatch wakes", async () => {
  vi.useFakeTimers();
  const sweep = vi.fn(async () => {});
  const scanner = new SharingAccessScheduler(sweep);
  await vi.advanceTimersByTimeAsync(0);
  expect(sweep).toHaveBeenCalledTimes(1);
  // Ordinary dispatch has no reference to this scheduler and cannot reset its clock.
  for (let n = 0; n < 149; n++) await vi.advanceTimersByTimeAsync(100);
  expect(sweep).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(100);
  expect(sweep).toHaveBeenCalledTimes(2);
  await scanner.stop();
  await vi.advanceTimersByTimeAsync(60_000);
  expect(sweep).toHaveBeenCalledTimes(2);
});
it("coalesces hint/timer backlog without concurrent sweeps or restarting the active cursor", async () => {
  vi.useFakeTimers();
  let complete!: () => void;
  const held = new Promise<void>((resolve) => {
    complete = resolve;
  });
  const sweep = vi
    .fn()
    .mockImplementationOnce(async () => held)
    .mockResolvedValue(undefined);
  const scanner = new SharingAccessScheduler(sweep);
  scanner.wake("pool-a");
  scanner.wake("pool-b");
  await vi.advanceTimersByTimeAsync(45_000);
  expect(sweep).toHaveBeenCalledTimes(1);
  complete();
  await vi.advanceTimersByTimeAsync(0);
  expect(sweep).toHaveBeenCalledTimes(2);
  expect(sweep.mock.calls[1]![1]).toBeUndefined();
  await scanner.stop();
});
it("aborts an active sweep on shutdown and starts a fresh sweep after restart", async () => {
  vi.useFakeTimers();
  let check: (() => boolean) | undefined;
  let complete!: () => void;
  const held = new Promise<void>((resolve) => {
    complete = resolve;
  });
  const scanner = new SharingAccessScheduler(async (stop) => {
    check = stop;
    await held;
  });
  expect(check?.()).toBe(false);
  const stopping = scanner.stop();
  expect(check?.()).toBe(true);
  complete();
  await stopping;
  const sweep = vi.fn(async () => {});
  const restart = new SharingAccessScheduler(sweep);
  expect(sweep).toHaveBeenCalledOnce();
  await restart.stop();
});
