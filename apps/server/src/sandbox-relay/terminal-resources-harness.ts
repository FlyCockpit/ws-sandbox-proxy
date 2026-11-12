/**
 * C55 end-of-scenario resource sweep for terminal tests: every listener,
 * timer, queue and counted session a terminal scenario created must be gone
 * at its end. A nonzero count fails the test with the full breakdown.
 *
 * `hostSockets` (required): host sockets that are still registered keep
 * their per-socket state (open-rate window, tombstones); pass how many the
 * scenario legitimately leaves connected. The global session index must be
 * empty too (`indexed`): a session released from its socket's count but left
 * in the index, or the reverse, fails the sweep.
 */
import { expect, vi } from "vitest";
import type { BrowserTerminalService } from "./browser-terminal.js";
import type { SandboxTerminalManager } from "./terminal-manager.js";

export function expectNoTerminalResources(
  manager: SandboxTerminalManager,
  options: { service?: BrowserTerminalService; hostSockets: number; timers?: boolean },
) {
  const resources = manager.resources();
  expect(resources).toEqual({
    sessions: 0,
    indexed: 0,
    unreaped: 0,
    openTimers: 0,
    queuedInputBytes: 0,
    pendingResizes: 0,
    deferredResizes: 0,
    sockets: options.hostSockets,
  });
  expect(manager.sessionCount()).toBe(0);
  if (options.service)
    expect(options.service.resources()).toEqual({ attached: 0, timers: 0, subscribed: 0 });
  // Fake timers only: nothing the scenario armed may still be pending.
  if (options.timers !== false && vi.isFakeTimers()) expect(vi.getTimerCount()).toBe(0);
}
