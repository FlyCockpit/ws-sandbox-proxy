/**
 * `sandbox-terminal-session-sweep` (WP8): the bounded cleanup of
 * `SandboxTerminalSession` rows. Each tick deletes, in `take`-limited
 * batches within a time budget, rows closed longer than the retention and
 * never-closed rows past the terminal lifetime (a crash or a missed close
 * leaves those; the resume gate already refuses them). Nothing here grants
 * or extends authority: a late sweep never makes a row resumable.
 */

import { safeErrorLog } from "@wssp/api/sandbox/sensitive-errors";
import { sweepTerminalSessions } from "@wssp/api/sandbox/terminal-sessions";

const TERMINAL_SESSION_SWEEP_NAME = "sandbox-terminal-session-sweep";
const TERMINAL_SESSION_SWEEP_MS = 10 * 60_000;
const TERMINAL_SESSION_SWEEP_BUDGET_MS = 30_000;

export function startTerminalSessionSweep(
  signal: AbortSignal,
  intervalMs = TERMINAL_SESSION_SWEEP_MS,
  clock: () => Date = () => new Date(),
  sweep: typeof sweepTerminalSessions = sweepTerminalSessions,
): () => Promise<void> {
  let running: Promise<unknown> = Promise.resolve();
  let active = false;
  const tick = () => {
    if (active || signal.aborted) return;
    active = true;
    running = sweep(clock(), { budgetMs: TERMINAL_SESSION_SWEEP_BUDGET_MS, signal })
      .catch((error: unknown) => {
        console.error(
          `[${TERMINAL_SESSION_SWEEP_NAME}] failed:`,
          safeErrorLog(error, "terminal_session_sweep_failed"),
        );
      })
      .finally(() => {
        active = false;
      });
  };
  const timer = setInterval(tick, intervalMs);
  timer.unref();
  const stop = async () => {
    clearInterval(timer);
    signal.removeEventListener("abort", onAbort);
    await running;
  };
  const onAbort = () => void stop();
  if (signal.aborted) void stop();
  else {
    signal.addEventListener("abort", onAbort, { once: true });
    tick();
  }
  return stop;
}
