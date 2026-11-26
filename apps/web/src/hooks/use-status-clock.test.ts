// @vitest-environment jsdom
import { act, renderHook } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { REFRESH_GRACE_MS, useStatusClock } from "./use-status-clock";

afterEach(() => vi.restoreAllMocks());

it("uses the wall clock online and the last fetch time offline", () => {
  vi.spyOn(Date, "now").mockReturnValue(10_000);
  const online = vi.spyOn(window.navigator, "onLine", "get").mockReturnValue(true);
  expect(renderHook(() => useStatusClock(4_000)).result.current).toBe(10_000);
  online.mockReturnValue(false);
  expect(renderHook(() => useStatusClock(4_000)).result.current).toBe(4_000);
  // Nothing fetched yet: fall back to the wall clock.
  expect(renderHook(() => useStatusClock(0)).result.current).toBe(10_000);
});

it("judges cached data as of its fetch while a refetch replaces it", () => {
  vi.spyOn(Date, "now").mockReturnValue(100_000);
  vi.spyOn(window.navigator, "onLine", "get").mockReturnValue(true);
  expect(renderHook(() => useStatusClock(4_000, true)).result.current).toBe(4_000);
  // The refetch settled (or failed): the wall clock again.
  expect(renderHook(() => useStatusClock(4_000, false)).result.current).toBe(100_000);
  expect(renderHook(() => useStatusClock(0, true)).result.current).toBe(100_000);
});

it("a refetch that hangs past the grace is judged by the wall clock again (Codex r1)", async () => {
  vi.useFakeTimers({ now: 100_000 });
  try {
    vi.spyOn(window.navigator, "onLine", "get").mockReturnValue(true);
    const { result } = renderHook(() => useStatusClock(4_000, true));
    expect(result.current).toBe(4_000);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(REFRESH_GRACE_MS - 1_000);
    });
    expect(result.current).toBe(4_000);
    // No other render happens: the hook's own timer ends the grace.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2_000);
    });
    expect(result.current).toBe(100_000 + REFRESH_GRACE_MS + 1_000);
  } finally {
    vi.useRealTimers();
  }
});
