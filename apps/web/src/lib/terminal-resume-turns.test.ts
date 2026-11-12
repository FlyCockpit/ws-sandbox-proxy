import { afterEach, describe, expect, it, vi } from "vitest";
import { FakeLocks } from "@/test/terminal-fakes";
import { acquireResumeTurn, defaultResumeLocks } from "./terminal-resume-turns";

const NAME = "wssp.terminal.resume";

afterEach(() => vi.useRealTimers());

describe("WP8 reattach turn (Web Locks)", () => {
  it("one constant, data-free lock name; a single holder; release hands it on", async () => {
    const locks = new FakeLocks();
    const first = await acquireResumeTurn(locks, new AbortController().signal);
    expect(first).toBeTypeOf("function");
    let second: (() => void) | null | undefined;
    void acquireResumeTurn(locks, new AbortController().signal).then((turn) => {
      second = turn;
    });
    await Promise.resolve();
    expect(second).toBeUndefined();
    expect(locks.held.get(NAME)).toBe(1);
    first?.();
    first?.(); // idempotent
    await vi.waitFor(() => expect(second).toBeTypeOf("function"));
    second?.();
    await vi.waitFor(() => expect(locks.held.get(NAME)).toBe(0));
    expect(locks.maxHeld).toBe(1);
    expect(new Set(locks.requested)).toEqual(new Set([NAME]));
  });

  it("an abort withdraws a waiting request, and releases a granted turn", async () => {
    const locks = new FakeLocks();
    const holderSignal = new AbortController();
    expect(await acquireResumeTurn(locks, holderSignal.signal)).toBeTypeOf("function");
    const waiting = new AbortController();
    const pending = acquireResumeTurn(locks, waiting.signal);
    waiting.abort();
    expect(await pending).toBeNull();
    holderSignal.abort();
    await vi.waitFor(() => expect(locks.held.get(NAME)).toBe(0));
    expect(await acquireResumeTurn(locks, AbortSignal.abort())).toBeNull();
  });

  it("a lock taken away after the grant reports the loss once; a normal release does not", async () => {
    const locks = new FakeLocks();
    const lost = vi.fn();
    const release = await acquireResumeTurn(locks, new AbortController().signal, Math.random, lost);
    expect(release).toBeTypeOf("function");
    locks.revoke(NAME);
    await vi.waitFor(() => expect(lost).toHaveBeenCalledTimes(1));
    expect(locks.held.get(NAME)).toBe(0);
    release?.();
    const kept = vi.fn();
    const again = await acquireResumeTurn(locks, new AbortController().signal, Math.random, kept);
    again?.();
    await vi.waitFor(() => expect(locks.held.get(NAME)).toBe(0));
    expect(kept).not.toHaveBeenCalled();
    expect(lost).toHaveBeenCalledTimes(1);
  });

  it("fallback without navigator.locks: a random backoff, abortable", async () => {
    vi.useFakeTimers();
    let turn: unknown;
    void acquireResumeTurn(null, new AbortController().signal, () => 0.25).then((value) => {
      turn = value;
    });
    await vi.advanceTimersByTimeAsync(499);
    expect(turn).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    expect(turn).toBeTypeOf("function");
    const aborted = new AbortController();
    const pending = acquireResumeTurn(null, aborted.signal, () => 0.9);
    aborted.abort();
    expect(await pending).toBeNull();
    expect(
      defaultResumeLocks() === null || typeof defaultResumeLocks()?.request === "function",
    ).toBe(true);
  });
});
