import { OPERATION_WAIT_PROGRESS_HOLD_MS } from "@wssp/sandbox-contracts";

/**
 * In-process wakeups for operation long-polls (`waitMs` on the /v1 operation,
 * output and result reads).
 *
 * Every control-plane operation write runs inside `sandboxOutboxTransaction`,
 * which observes the `sandboxOperation` and `sandboxOperationResult`
 * delegates and calls `notifyOperationsChanged` only after its commit. A wake
 * carries no data and no authority: the waiting route re-runs its normal,
 * freshly authorized read and answers with whatever that read returns. A
 * missed wake only delays the answer to the periodic safety re-read.
 *
 * Wakes are process-local. The deployment runs one server replica
 * (docs/infra.md); `bindOperationChangeFanout` is the seam a cross-replica
 * transport (e.g. Redis pub/sub) would use to publish local changes.
 */

/**
 * What a commit touched: exact operation ids, and owners whose operations were
 * written without a resolvable id (those wake only that owner's waiters).
 * "all" is reserved for a write with neither, which no current path issues.
 */
export type OperationChange =
  | { operationIds: ReadonlySet<string>; ownerIds: ReadonlySet<string> }
  | "all";

export function operationChange(
  operationIds: Iterable<string> = [],
  ownerIds: Iterable<string> = [],
): OperationChange {
  return { operationIds: new Set(operationIds), ownerIds: new Set(ownerIds) };
}

/** Concurrent held long-polls per owner. Over the cap a read answers at once. */
export const OPERATION_WAIT_OWNER_MAX = 16;
/** Concurrent held long-polls per server process. */
export const OPERATION_WAIT_GLOBAL_MAX = 256;
/**
 * A held read re-runs at least this often even without a wake, for writers
 * that bypass the observed delegates (action receipts, future paths).
 */
export const OPERATION_WAIT_RECHECK_MS = 5_000;
/**
 * Most wake-triggered re-reads one held request performs. Lifecycle steps
 * (dispatched, accepted, running) each wake a held read that is still not
 * ready; it keeps holding, but after this many such re-reads it answers as is,
 * so a wake storm costs one request at most this many extra reads.
 */
export const OPERATION_WAIT_MAX_WAKE_REREADS = 8;
/**
 * After the wake budget is spent inside a progress hold, the read re-runs on
 * this tick until the hold ends (at most hold / tick = 8 more reads), so a
 * completion still answers within 250 ms.
 */
export const OPERATION_WAIT_THROTTLE_MS = 250;
/** Streamed-output pacing; defined (and justified) in the public contract. */
export { OPERATION_WAIT_PROGRESS_HOLD_MS };

export type OperationWaitEnd = "changed" | "timeout" | "aborted" | "shutdown";

type Waiter = { ownerId: string; fire: (end: OperationWaitEnd) => void };

const waitersById = new Map<string, Set<Waiter>>();
let held = 0;
const heldByOwner = new Map<string, number>();
let closed = false;
let fanout: ((change: OperationChange) => void) | null = null;

/** Future cross-replica publisher of local changes (no-op until bound). */
export function bindOperationChangeFanout(next: ((change: OperationChange) => void) | null): void {
  fanout = next;
}

let buildWake: (() => void) | null = null;

/** The template-build orchestrator's wake (§3.3: an operation result may
 * advance a build). Carries no data; the orchestrator re-reads its rows. */
export function bindOperationChangeBuildWake(next: (() => void) | null): void {
  buildWake = next;
}

/**
 * Acquire one waiter slot, or null when the owner/global cap is reached or the
 * process is shutting down: the caller then answers without holding. The
 * returned release is idempotent.
 */
export function admitOperationWaiter(ownerId: string): (() => void) | null {
  const owned = heldByOwner.get(ownerId) ?? 0;
  if (closed || held >= OPERATION_WAIT_GLOBAL_MAX || owned >= OPERATION_WAIT_OWNER_MAX) return null;
  held++;
  heldByOwner.set(ownerId, owned + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    held--;
    const left = (heldByOwner.get(ownerId) ?? 1) - 1;
    if (left) heldByOwner.set(ownerId, left);
    else heldByOwner.delete(ownerId);
  };
}

export type OperationWatch = {
  /**
   * Resolves on the first wake since the watch was created (a wake that
   * arrived before `wait` is latched), after `ms`, when `signal` aborts or
   * at shutdown. Call at most once.
   */
  wait(ms: number, signal?: AbortSignal): Promise<OperationWaitEnd>;
  /** Unregister. Idempotent; always call it (finally). */
  dispose(): void;
};

/**
 * Register interest in one operation BEFORE reading it, so a commit between
 * the read and the wait still wakes the waiter.
 */
export function watchOperation(operationId: string, ownerId: string): OperationWatch {
  let latched: OperationWaitEnd | null = closed ? "shutdown" : null;
  let resolveWait: ((end: OperationWaitEnd) => void) | null = null;
  const waiter: Waiter = {
    ownerId,
    fire: (end) => {
      if (resolveWait) {
        const resolve = resolveWait;
        resolveWait = null;
        resolve(end);
      } else latched ??= end;
    },
  };
  let set = waitersById.get(operationId);
  if (!set) {
    set = new Set();
    waitersById.set(operationId, set);
  }
  set.add(waiter);
  let disposed = false;
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    const current = waitersById.get(operationId);
    if (!current) return;
    current.delete(waiter);
    if (current.size === 0) waitersById.delete(operationId);
  };
  return {
    wait(ms, signal) {
      if (latched) return Promise.resolve(latched);
      if (signal?.aborted) return Promise.resolve("aborted");
      return new Promise<OperationWaitEnd>((resolve) => {
        const finish = (end: OperationWaitEnd) => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
          resolve(end);
        };
        const onAbort = () => waiter.fire("aborted");
        const timer = setTimeout(() => waiter.fire("timeout"), Math.max(0, ms));
        resolveWait = finish;
        signal?.addEventListener("abort", onAbort, { once: true });
      });
    },
    dispose,
  };
}

/**
 * Post-commit: wake the waiters of these operations, and every waiter of these
 * owners (no data, no authority). A woken read re-runs at most once and then
 * answers, so a burst of commits costs each held request one extra read.
 */
export function notifyOperationsChanged(change: OperationChange): void {
  try {
    if (change === "all") {
      for (const set of waitersById.values()) for (const waiter of [...set]) waiter.fire("changed");
    } else {
      for (const id of change.operationIds) {
        const set = waitersById.get(id);
        if (set) for (const waiter of [...set]) waiter.fire("changed");
      }
      if (change.ownerIds.size > 0)
        for (const set of waitersById.values())
          for (const waiter of [...set])
            if (change.ownerIds.has(waiter.ownerId)) waiter.fire("changed");
    }
    fanout?.(change);
    buildWake?.();
  } catch {
    // The write has committed; held reads still re-run on their recheck timer.
    console.error("[sandbox-operations] change notification failed; recheck pending");
  }
}

/**
 * Wake only the held reads registered under these keys: no owner wakes, no
 * fanout and no build-orchestrator wake. Template-build progress uses it
 * (key `templateBuildWatchKey`), so the orchestrator's own commits never
 * re-trigger the orchestrator.
 */
export function wakeOperationWatchers(keys: Iterable<string>): void {
  for (const key of keys) {
    const set = waitersById.get(key);
    if (set) for (const waiter of [...set]) waiter.fire("changed");
  }
}

/**
 * Shutdown: answer every held read now and refuse new holds, so draining HTTP
 * requests finish instead of riding out their waits.
 */
export function releaseAllOperationWaiters(): void {
  closed = true;
  for (const set of waitersById.values()) for (const waiter of [...set]) waiter.fire("shutdown");
}

/** Test seam: reopen admission after `releaseAllOperationWaiters`. */
export function reopenOperationWaitersForTesting(): void {
  closed = false;
}

/** Test seam: current held slots and registered watches. */
export function operationWaiterCounts(): { held: number; watches: number } {
  let watches = 0;
  for (const set of waitersById.values()) watches += set.size;
  return { held, watches };
}

/**
 * Hold one operation read until it is ready, a change commits, `waitMs`
 * elapses, the client disconnects or the server shuts down.
 *
 * `ready(value)` answers `true` (answer now), `false` (hold) or `"progress"`
 * (something new but not finished: hold at most
 * `OPERATION_WAIT_PROGRESS_HOLD_MS` more for the finish, then answer).
 *
 * 1. The normal, authorized read runs first. A ready answer, or any error other
 *    than `notReady` (a foreign or missing id is 404 here), returns at once:
 *    nothing is admitted or registered before ownership is proven.
 * 2. Only a not-ready answer takes a waiter slot (over the cap it is returned
 *    as is) and registers interest in the id, then reads again. That second
 *    read closes the race with a commit between step 1 and registration.
 * 3. A wake re-runs the read; a still-not-ready result keeps holding under a
 *    fresh registration, up to `OPERATION_WAIT_MAX_WAKE_REREADS` wakes, after
 *    which the next read is answered as is (inside a progress hold: the read
 *    re-runs every 250 ms until the hold ends, so streamed output keeps its
 *    pace and a completion still answers promptly). One request therefore
 *    costs at most 19 + floor(waitMs / 5 s) reads, however many commits wake it.
 * 4. At `waitMs` (or the end of a progress hold), or at shutdown, the read
 *    re-runs once and is returned as is; on client disconnect the last read is
 *    returned without another.
 *
 * No database connection is held while waiting.
 */
export async function withOperationWait<T>(input: {
  ownerId: string;
  operationId: string;
  waitMs: number | undefined;
  signal?: AbortSignal;
  read: () => Promise<T>;
  ready: (value: T) => boolean | "progress";
  /** An error that means "not ready yet" (held and retried), e.g. result NOT_READY. */
  notReady?: (error: unknown) => boolean;
}): Promise<T> {
  const waitMs = input.waitMs ?? 0;
  if (waitMs <= 0) return input.read();
  const deadline = Date.now() + waitMs;
  type Read = { ready: boolean | "progress"; value: T } | { ready: false; error: unknown };
  const attempt = async (): Promise<Read> => {
    try {
      const value = await input.read();
      return { ready: input.ready(value), value };
    } catch (error) {
      if (!input.notReady?.(error)) throw error;
      return { ready: false, error };
    }
  };
  const answer = (read: Read): T => {
    if ("value" in read) return read.value;
    throw read.error;
  };
  let last = await attempt();
  if (last.ready === true) return answer(last);
  const release = admitOperationWaiter(input.ownerId);
  if (!release) return answer(last);
  try {
    let final = false;
    let wakes = 0;
    let throttled = false;
    let progressUntil: number | null = null;
    for (;;) {
      const watch = throttled ? null : watchOperation(input.operationId, input.ownerId);
      try {
        last = await attempt();
        if (last.ready === true) return answer(last);
        if (last.ready === "progress")
          progressUntil ??= Date.now() + OPERATION_WAIT_PROGRESS_HOLD_MS;
        const remaining = Math.min(deadline, progressUntil ?? deadline) - Date.now();
        if (final || remaining <= 0) return answer(last);
        if (!watch) {
          // Wake budget spent inside a progress hold (a chatty command): poll
          // for the completion on a fixed slow tick until the hold ends, so
          // pacing is kept and reads stay bounded.
          const paused = await pause(Math.min(remaining, OPERATION_WAIT_THROTTLE_MS), input.signal);
          if (paused === "aborted") return answer(last);
          continue;
        }
        const end = await watch.wait(Math.min(remaining, OPERATION_WAIT_RECHECK_MS), input.signal);
        // Nobody is listening; skip the re-read and let the request end.
        if (end === "aborted") return answer(last);
        // Shutdown: one more read, answered as is.
        if (end === "shutdown") final = true;
        if (end === "changed" && ++wakes >= OPERATION_WAIT_MAX_WAKE_REREADS) {
          // Outside a progress hold the next read is answered as is; inside
          // one, answering early would raise a streaming command's request
          // rate, so it switches to the slow tick until the hold ends.
          if (progressUntil === null) final = true;
          else throttled = true;
        }
      } finally {
        watch?.dispose();
      }
    }
  } finally {
    release();
  }
}

/** A plain timer that ends early when `signal` aborts. */
function pause(ms: number, signal: AbortSignal | undefined): Promise<"elapsed" | "aborted"> {
  if (signal?.aborted) return Promise.resolve("aborted");
  return new Promise((resolve) => {
    const onAbort = () => {
      clearTimeout(timer);
      resolve("aborted");
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve("elapsed");
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
