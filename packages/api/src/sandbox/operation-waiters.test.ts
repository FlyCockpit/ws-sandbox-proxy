import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  admitOperationWaiter,
  bindOperationChangeFanout,
  notifyOperationsChanged,
  OPERATION_WAIT_GLOBAL_MAX,
  OPERATION_WAIT_MAX_WAKE_REREADS,
  OPERATION_WAIT_OWNER_MAX,
  OPERATION_WAIT_PROGRESS_HOLD_MS,
  OPERATION_WAIT_RECHECK_MS,
  OPERATION_WAIT_THROTTLE_MS,
  operationChange,
  operationWaiterCounts,
  releaseAllOperationWaiters,
  reopenOperationWaitersForTesting,
  watchOperation,
  withOperationWait,
} from "./operation-waiters";

beforeEach(() => {
  vi.useFakeTimers();
  reopenOperationWaitersForTesting();
});
afterEach(() => {
  vi.useRealTimers();
  bindOperationChangeFanout(null);
  expect(operationWaiterCounts()).toEqual({ held: 0, watches: 0 });
});

const ids = (...operationIds: string[]) => operationChange(operationIds);
const owners = (...ownerIds: string[]) => operationChange([], ownerIds);

/** A read whose answers are scripted; records each call time. */
function scripted<T>(...answers: Array<T | Error>) {
  const at: number[] = [];
  const read = vi.fn(async () => {
    at.push(Date.now());
    const next = answers.length > 1 ? answers.shift() : answers[0];
    if (next instanceof Error) throw next;
    return next as T;
  });
  return { read, at };
}

async function isSettled(promise: Promise<unknown>): Promise<boolean> {
  let settled = false;
  void promise.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  await vi.advanceTimersByTimeAsync(0);
  return settled;
}

describe("watchOperation", () => {
  it("latches a wake that arrives between registration and wait (register-before-read)", async () => {
    const watch = watchOperation("op_1", "owner-a");
    notifyOperationsChanged(ids("op_1"));
    await expect(watch.wait(10_000)).resolves.toBe("changed");
    watch.dispose();
  });

  it("wakes only the named operation, or only the named owner's waiters", async () => {
    const one = watchOperation("op_1", "owner-a");
    const two = watchOperation("op_2", "owner-a");
    const foreign = watchOperation("op_3", "owner-b");
    const first = one.wait(10_000);
    const second = two.wait(10_000);
    const third = foreign.wait(10_000);
    notifyOperationsChanged(ids("op_1"));
    await expect(first).resolves.toBe("changed");
    expect(await isSettled(second)).toBe(false);
    // An id-less write by owner-a wakes owner-a's waiters, never owner-b's.
    notifyOperationsChanged(owners("owner-a"));
    await expect(second).resolves.toBe("changed");
    expect(await isSettled(third)).toBe(false);
    notifyOperationsChanged("all");
    await expect(third).resolves.toBe("changed");
    for (const watch of [one, two, foreign]) watch.dispose();
  });

  it("times out, aborts and disposes without leaking", async () => {
    const watch = watchOperation("op_1", "owner-a");
    const timed = watch.wait(1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(timed).resolves.toBe("timeout");
    watch.dispose();
    const controller = new AbortController();
    const other = watchOperation("op_1", "owner-a");
    const aborted = other.wait(10_000, controller.signal);
    controller.abort();
    await expect(aborted).resolves.toBe("aborted");
    other.dispose();
    other.dispose(); // idempotent
  });

  it("a fan-out listener failure never throws into the committed writer", () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    bindOperationChangeFanout(() => {
      throw new Error("fanout broke");
    });
    expect(() => notifyOperationsChanged(ids("op_1"))).not.toThrow();
  });
});

describe("admission caps", () => {
  it("caps holds per owner and globally; releases are idempotent", () => {
    const owner = Array.from({ length: OPERATION_WAIT_OWNER_MAX }, () =>
      admitOperationWaiter("owner-a"),
    );
    expect(owner.every(Boolean)).toBe(true);
    expect(admitOperationWaiter("owner-a")).toBeNull();
    const other = admitOperationWaiter("owner-b");
    expect(other).not.toBeNull();
    for (const release of owner) {
      release?.();
      release?.();
    }
    other?.();
    const many = Array.from({ length: OPERATION_WAIT_GLOBAL_MAX }, (_, i) =>
      admitOperationWaiter(`owner-${i}`),
    );
    expect(many.every(Boolean)).toBe(true);
    expect(admitOperationWaiter("owner-new")).toBeNull();
    for (const release of many) release?.();
  });
});

describe("withOperationWait", () => {
  const base = { ownerId: "owner-a", operationId: "op_1" };
  const pending = { outcome: "pending" };

  it("waitMs absent or 0 is exactly one plain read", async () => {
    const { read } = scripted(pending);
    await withOperationWait({ ...base, waitMs: undefined, read, ready: () => false });
    await withOperationWait({ ...base, waitMs: 0, read, ready: () => false });
    expect(read).toHaveBeenCalledTimes(2);
  });

  it("answers at once when the first read is ready, registering nothing", async () => {
    const { read } = scripted({ outcome: "succeeded" });
    await expect(
      withOperationWait({ ...base, waitMs: 20_000, read, ready: (v) => v.outcome !== "pending" }),
    ).resolves.toEqual({ outcome: "succeeded" });
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("registers nothing while the first (authorizing) read is pending or failing", async () => {
    let fail!: (error: Error) => void;
    const read = vi.fn(
      () =>
        new Promise<typeof pending>((_, reject) => {
          fail = reject;
        }),
    );
    const answer = withOperationWait({ ...base, waitMs: 20_000, read, ready: () => false });
    const settled = answer.catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(10);
    expect(operationWaiterCounts()).toEqual({ held: 0, watches: 0 });
    const gone = new Error("NOT_FOUND"); // foreign and missing ids look the same
    fail(gone);
    expect(await settled).toBe(gone);
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("a commit between the first read and registration is caught by the second read", async () => {
    const { read } = scripted(pending, { outcome: "succeeded" });
    await expect(
      withOperationWait({ ...base, waitMs: 20_000, read, ready: (v) => v.outcome !== "pending" }),
    ).resolves.toEqual({ outcome: "succeeded" });
    expect(read).toHaveBeenCalledTimes(2);
  });

  it("a commit wake re-reads at once and answers the fresh read", async () => {
    const { read, at } = scripted(pending, pending, { outcome: "succeeded" });
    const started = Date.now();
    const answer = withOperationWait({
      ...base,
      waitMs: 20_000,
      read,
      ready: (v) => v.outcome !== "pending",
    });
    await vi.advanceTimersByTimeAsync(300);
    expect(operationWaiterCounts()).toEqual({ held: 1, watches: 1 });
    notifyOperationsChanged(ids("op_1"));
    await expect(answer).resolves.toEqual({ outcome: "succeeded" });
    expect(at.map((t) => t - started)).toEqual([0, 0, 300]);
  });

  it("regression (prod trace): lifecycle wakes before output keep holding until bytes arrive", async () => {
    // At 22d2de1 the first output read answered at the first lifecycle wake
    // (QUEUED → DISPATCHED) with an empty page, costing the SDK a round trip
    // plus a backoff. Pre-start wakes must keep the read held.
    const { read, at } = scripted<string>(
      "QUEUED",
      "QUEUED",
      "DISPATCHED",
      "ACCEPTED",
      "RUNNING",
      "BYTES",
    );
    const started = Date.now();
    const answer = withOperationWait({
      ...base,
      waitMs: 20_000,
      read,
      ready: (state) => state === "BYTES",
    });
    for (const ms of [50, 100, 150, 300]) {
      await vi.advanceTimersByTimeAsync(ms - (Date.now() - started));
      notifyOperationsChanged(ids("op_1"));
    }
    await expect(answer).resolves.toBe("BYTES");
    expect(at.map((t) => t - started)).toEqual([0, 0, 50, 100, 150, 300]);
  });

  it("progress holds briefly for the finish and answers with it", async () => {
    const { read, at } = scripted<string>("progress", "progress", "done");
    const started = Date.now();
    const answer = withOperationWait({
      ...base,
      waitMs: 20_000,
      read,
      ready: (v) => (v === "done" ? true : v === "progress" ? "progress" : false),
    });
    await vi.advanceTimersByTimeAsync(120);
    notifyOperationsChanged(ids("op_1"));
    await expect(answer).resolves.toBe("done");
    expect(at.map((t) => t - started)).toEqual([0, 0, 120]);
  });

  it("progress without a finish is answered after the progress hold, not the full wait", async () => {
    const { read, at } = scripted<string>("progress");
    const started = Date.now();
    const answer = withOperationWait({
      ...base,
      waitMs: 20_000,
      read,
      ready: (v) => (v === "progress" ? "progress" : false),
    });
    await vi.advanceTimersByTimeAsync(OPERATION_WAIT_PROGRESS_HOLD_MS);
    await expect(answer).resolves.toBe("progress");
    expect(at.map((t) => t - started)).toEqual([0, 0, OPERATION_WAIT_PROGRESS_HOLD_MS]);
  });

  it("a chatty 60 s command is answered at most 30 times a minute, with bounded reads", async () => {
    // Bytes commit every 50 ms for 60 s; the client re-issues each answer at
    // once (zero RTT, the worst case for the rate).
    const started = Date.now();
    let reads = 0;
    let maxReadsPerRequest = 0;
    const producer = setInterval(() => notifyOperationsChanged(ids("op_1")), 50);
    let requests = 0;
    const client = (async () => {
      while (Date.now() - started < 60_000) {
        let perRequest = 0;
        await withOperationWait({
          ...base,
          waitMs: 20_000,
          read: async () => {
            reads++;
            perRequest++;
            return "bytes";
          },
          ready: () => "progress" as const,
        });
        requests++;
        maxReadsPerRequest = Math.max(maxReadsPerRequest, perRequest);
      }
    })();
    await vi.advanceTimersByTimeAsync(60_000 + OPERATION_WAIT_PROGRESS_HOLD_MS);
    clearInterval(producer);
    await client;
    expect(requests).toBeLessThanOrEqual(31);
    expect(requests).toBeGreaterThanOrEqual(29); // paced by the hold, not stalled
    // 2 + 8 wake re-reads + hold / tick throttled re-reads + the final one
    expect(maxReadsPerRequest).toBeLessThanOrEqual(
      2 + 8 + OPERATION_WAIT_PROGRESS_HOLD_MS / OPERATION_WAIT_THROTTLE_MS + 1,
    );
    expect(reads).toBeLessThanOrEqual(requests * maxReadsPerRequest);
  });

  it("a multi-chunk quick command still answers promptly at completion after the wake budget", async () => {
    let state = "bytes";
    const at: number[] = [];
    const started = Date.now();
    const answer = withOperationWait({
      ...base,
      waitMs: 20_000,
      read: async () => {
        at.push(Date.now() - started);
        return state;
      },
      ready: (v) => (v === "done" ? true : "progress"),
    });
    for (let i = 0; i < 12; i++) {
      await vi.advanceTimersByTimeAsync(10);
      notifyOperationsChanged(ids("op_1")); // twelve output chunks commit
    }
    await vi.advanceTimersByTimeAsync(300);
    state = "done"; // the completion commits ~420 ms in
    notifyOperationsChanged(ids("op_1"));
    const doneAt = Date.now() - started;
    await vi.advanceTimersByTimeAsync(OPERATION_WAIT_THROTTLE_MS);
    await expect(answer).resolves.toBe("done");
    expect(at.at(-1)! - doneAt).toBeLessThanOrEqual(OPERATION_WAIT_THROTTLE_MS);
    expect(at.at(-1)!).toBeLessThan(OPERATION_WAIT_PROGRESS_HOLD_MS);
  });

  it("a notification storm costs each held request a bounded number of reads", async () => {
    const reads = Array.from({ length: 20 }, () => scripted(pending));
    const answers = reads.map(({ read }, i) =>
      withOperationWait({
        ownerId: `owner-${i % 4}`,
        operationId: `op_${i}`,
        waitMs: 20_000,
        read,
        ready: () => false,
      }),
    );
    await vi.advanceTimersByTimeAsync(10);
    for (let i = 0; i < 1_000; i++) {
      notifyOperationsChanged("all");
      notifyOperationsChanged(owners("owner-0", "owner-1", "owner-2", "owner-3"));
      notifyOperationsChanged(ids(...reads.map((_, n) => `op_${n}`)));
      await vi.advanceTimersByTimeAsync(1);
    }
    await Promise.all(answers);
    // initial authorizing read + post-registration read + the wake budget
    for (const { read } of reads)
      expect(read).toHaveBeenCalledTimes(2 + OPERATION_WAIT_MAX_WAKE_REREADS);
  });

  it("re-reads on the safety timer and returns the last read at the deadline", async () => {
    const { read, at } = scripted(pending);
    const started = Date.now();
    const answer = withOperationWait({ ...base, waitMs: 12_000, read, ready: () => false });
    await vi.advanceTimersByTimeAsync(12_000);
    await expect(answer).resolves.toEqual(pending);
    expect(at.map((t) => t - started)).toEqual([
      0,
      0,
      OPERATION_WAIT_RECHECK_MS,
      2 * OPERATION_WAIT_RECHECK_MS,
      12_000,
    ]);
  });

  it("holds a not-ready error and rethrows the last one at the deadline", async () => {
    const notReady = new Error("OPERATION_RESULT_NOT_READY");
    const { read } = scripted<{ ok: true }>(notReady);
    const answer = withOperationWait({
      ...base,
      waitMs: 2_000,
      read,
      ready: () => true,
      notReady: (e) => e === notReady,
    });
    const settled = answer.catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(await settled).toBe(notReady);
    expect(read).toHaveBeenCalledTimes(3);
  });

  it("a key revoked mid-wait: the post-wake read is freshly authorized and its error returned", async () => {
    const revoked = new Error("UNAUTHORIZED");
    const { read } = scripted<{ outcome: string }>(pending, pending, revoked);
    const answer = withOperationWait({ ...base, waitMs: 20_000, read, ready: () => false });
    const settled = answer.catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(10);
    notifyOperationsChanged(ids("op_1"));
    expect(await settled).toBe(revoked);
  });

  it("a client disconnect ends the hold without another read", async () => {
    const controller = new AbortController();
    const { read } = scripted(pending);
    const answer = withOperationWait({
      ...base,
      waitMs: 20_000,
      signal: controller.signal,
      read,
      ready: () => false,
    });
    await vi.advanceTimersByTimeAsync(10);
    controller.abort();
    await expect(answer).resolves.toEqual(pending);
    expect(read).toHaveBeenCalledTimes(2);
  });

  it("over the owner cap the read answers at once (no 429)", async () => {
    const releases = Array.from({ length: OPERATION_WAIT_OWNER_MAX }, () =>
      admitOperationWaiter("owner-a"),
    );
    const { read } = scripted(pending);
    await expect(
      withOperationWait({ ...base, waitMs: 20_000, read, ready: () => false }),
    ).resolves.toEqual(pending);
    expect(read).toHaveBeenCalledTimes(1);
    for (const release of releases) release?.();
  });

  it("shutdown answers held reads with one fresh read and refuses new holds", async () => {
    const { read } = scripted(pending);
    const answer = withOperationWait({ ...base, waitMs: 20_000, read, ready: () => false });
    await vi.advanceTimersByTimeAsync(10);
    releaseAllOperationWaiters();
    await expect(answer).resolves.toEqual(pending);
    expect(read).toHaveBeenCalledTimes(3);
    expect(admitOperationWaiter("owner-a")).toBeNull();
    await withOperationWait({ ...base, waitMs: 20_000, read, ready: () => false });
    expect(read).toHaveBeenCalledTimes(4);
  });
});

/**
 * Tripwire: every file that writes operation or operation-result rows was
 * reviewed to run inside `sandboxOutboxTransaction` (which wakes long-polls
 * after commit) or to be a write no long-poll waits on. A new writer file
 * fails here until it is reviewed and listed. A missed wake only delays a
 * held read to its 5 s recheck; it never leaks data.
 */
describe("operation writers are reviewed for long-poll wakes", () => {
  const REVIEWED = new Set([
    // Capture acceptance runs in operationTransaction; the host result runs in
    // relayTransaction; the finalizer runs in sandboxOutboxTransaction (wakes).
    "packages/api/src/sandbox/image-store/captures.ts",
    // The capture host result: called inside relayTransaction (operation-handlers).
    "packages/api/src/sandbox/image-store/capture-result.ts",
    // Relay handlers: every write runs in relayTransaction → sandboxOutboxTransaction.
    "apps/server/src/sandbox-relay/inventory-reconcile.ts",
    "apps/server/src/sandbox-relay/operation-handlers.ts",
    "apps/server/src/sandbox-relay/outbox-processor.ts",
    // The recorded-capture adoption (relayTransaction) moves only
    // dispatchedConnectionEpoch of an ACCEPTED/RUNNING capture operation, never
    // its state or result: nothing a long-poll waiter observes.
    "apps/server/src/sandbox-relay/image-handlers.ts",
    // Download acceptance creates an operation (no waiter can hold a new id).
    "apps/server/src/sandbox-transfers/store.ts",
    // Helpers that receive a transaction from an observed caller.
    // The capacity queue writes inside operationTransaction or its own
    // sandboxOutboxTransaction (placer, timeout, cancel).
    "packages/api/src/sandbox/capacity-queue.ts",
    // Live attach/free and the login finish: recordedOperation creates the
    // row (a new id no waiter can hold) inside operationTransaction
    // (sandboxOutboxTransaction) from live.ts and login-sessions.ts.
    "packages/api/src/credentials/live-ops.ts",
    "packages/api/src/sandbox/placement-materialize.ts",
    // Restore admission: inside operationTransaction (accept, cancel) or the
    // restore-wait pass's own sandboxOutboxTransaction (place, expire).
    "packages/api/src/sandbox/disk-offload/restore-admit.ts",
    // The restore exit: a helper called inside relayTransaction (outbox,
    // results, census) or the lease writers' sandboxOutboxTransaction.
    "packages/api/src/sandbox/disk-offload/restore-exit.ts",
    // The acceptance digest snapshot: written inside operationTransaction on
    // the row its work callback just created (a new id no waiter can hold).
    "packages/api/src/sandbox/operation-transaction.ts",
    "packages/api/src/sandbox/lease.ts",
    "packages/api/src/sandbox/operation-results.ts",
    "packages/api/src/sandbox/process-controls.ts",
    "packages/api/src/sandbox/process-signals.ts",
    "packages/api/src/sandbox/relay-fence.ts",
    "packages/api/src/sandbox/result-finalization.ts",
    "packages/api/src/sandbox/services/sandboxes.ts",
    "packages/api/src/sandbox/sharing-access.ts",
    // Test fixtures and account deletion (rows vanish; held reads 404 on recheck).
    "packages/api/src/sandbox/testing/resource-fixtures.ts",
    // The template-build fake daemon (pg tests only; plays the relay's writes).
    "packages/api/src/template-builds/testing/build-fixtures.ts",
    "packages/db/src/account-deletion.ts",
  ]);
  const root = join(__dirname, "../../../..");
  const WRITE =
    /\.sandboxOperation(?:Result)?\.(?:update|updateMany|upsert|create|createMany|delete|deleteMany)\(/;

  function sources(dir: string, out: string[] = []): string[] {
    for (const name of readdirSync(dir)) {
      if (name === "node_modules" || name === "dist") continue;
      const path = join(dir, name);
      if (statSync(path).isDirectory()) sources(path, out);
      else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name)) out.push(path);
    }
    return out;
  }

  it("no unreviewed file writes sandboxOperation / sandboxOperationResult rows", () => {
    const writers = ["apps/server/src", "apps/worker/src", "packages/api/src", "packages/db/src"]
      .flatMap((dir) => sources(join(root, dir)))
      .filter((path) => WRITE.test(readFileSync(path, "utf8")))
      .map((path) => relative(root, path));
    expect(writers).toContain("apps/server/src/sandbox-relay/operation-handlers.ts");
    expect(writers.filter((path) => !REVIEWED.has(path))).toEqual([]);
  });
});
