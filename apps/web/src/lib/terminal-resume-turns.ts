/**
 * One reattach at a time across this browser's tabs (WP8).
 *
 * After a deploy or a relay drop every open terminal tab wants to reattach at
 * once. Each reattach costs one ticket mint (20 per 60 s per user) and one
 * upgrade (30 per 60 s per user), and neither budget is raised for this, so
 * tabs take turns. That keeps about 15 tabs inside the budgets; the rest show
 * "Attach again" once their own attempts run out.
 *
 * The turn is an exclusive Web Lock (`navigator.locks`), which guarantees a
 * single holder across every tab of the origin. It is held only for one
 * attempt: released on success, failure, the attempt timeout or the grace
 * deadline (an aborted `AbortSignal` also withdraws a request still waiting).
 * A tab that closes or crashes releases its lock with it. The lock name is a
 * constant: Web Locks are already scoped to the origin, and the name carries
 * no user, session or terminal data, so nothing leaks between accounts in one
 * browser profile (they merely share the queue).
 *
 * A lock can also be lost after it was granted: WebKit releases a suspended
 * page's locks and rejects their promises. Such a post-grant loss (the lock
 * request settling before this tab released it) is reported through `onLost`,
 * and the caller must abandon the attempt: another tab may already hold the
 * turn.
 *
 * Without `navigator.locks` (very old browsers, some embedded views) the
 * fallback is best-effort only: a random 0–2 s backoff before going ahead.
 * The server's budgets stay the enforcement either way.
 */

const TERMINAL_RESUME_LOCK = "wssp.terminal.resume";
/** Fallback only: the most a tab waits before attempting without a lock. */
const FALLBACK_BACKOFF_MAX_MS = 2_000;

/** The slice of the DOM `LockManager` the turn uses. */
export type ResumeLocks = {
  request(
    name: string,
    options: { mode: "exclusive"; signal: AbortSignal },
    callback: (lock: unknown) => Promise<void>,
  ): Promise<unknown>;
};

/** Releases a held turn (idempotent). */
export type ReleaseTurn = () => void;

export function defaultResumeLocks(): ResumeLocks | null {
  if (typeof navigator === "undefined") return null;
  const locks = (navigator as { locks?: ResumeLocks }).locks;
  return locks && typeof locks.request === "function" ? locks : null;
}

/**
 * Wait for this tab's turn. Resolves with the release function once the turn
 * is held, or `null` when `signal` aborted first (the request is withdrawn; a
 * lock granted after the abort is released at once). `onLost` runs at most
 * once, if the granted lock ends before the release function was called.
 */
export function acquireResumeTurn(
  locks: ResumeLocks | null,
  signal: AbortSignal,
  random: () => number = Math.random,
  onLost: () => void = () => undefined,
): Promise<ReleaseTurn | null> {
  if (signal.aborted) return Promise.resolve(null);
  if (!locks) return fallbackTurn(signal, random);
  return new Promise((resolve) => {
    let settled = false;
    let granted = false;
    let released = false;
    const settle = (value: ReleaseTurn | null) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    locks
      .request(TERMINAL_RESUME_LOCK, { mode: "exclusive", signal }, () => {
        if (signal.aborted) return Promise.resolve();
        return new Promise<void>((held) => {
          granted = true;
          const release = () => {
            if (released) return;
            released = true;
            signal.removeEventListener("abort", release);
            held();
          };
          // An abort after the grant (deadline, attempt timeout) releases too.
          signal.addEventListener("abort", release, { once: true });
          settle(release);
        });
      })
      // AbortError while waiting, or a failing lock manager: no turn.
      .catch(() => undefined)
      .finally(() => {
        // Settled while still held by us: the browser took the lock away.
        if (granted && !released) {
          released = true;
          onLost();
        }
        settle(null);
      });
  });
}

/** Best-effort serialization without Web Locks: a random backoff, then go. */
function fallbackTurn(signal: AbortSignal, random: () => number): Promise<ReleaseTurn | null> {
  return new Promise((resolve) => {
    const done = () => {
      signal.removeEventListener("abort", abort);
      resolve(() => undefined);
    };
    const timer = setTimeout(done, Math.floor(random() * FALLBACK_BACKOFF_MAX_MS));
    const abort = () => {
      clearTimeout(timer);
      resolve(null);
    };
    signal.addEventListener("abort", abort, { once: true });
  });
}
