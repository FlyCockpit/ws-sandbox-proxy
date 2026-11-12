import { newCredentialRewrapCursor, rewrapCredentialKeys } from "@wssp/api/credentials/rewrap";
import { safeErrorLog } from "@wssp/api/sandbox/sensitive-errors";
import type { WebhookConfig } from "@wssp/api/webhooks/config";
import {
  type EnqueueJobs,
  enqueuePending,
  FAN_OUT_BATCH,
  fanOutEvents,
  newEnqueueCursor,
  newFanOutCursor,
  newRekeyCursor,
  runMaintenance,
} from "@wssp/api/webhooks/ledger";

/**
 * The webhook dispatcher: a long-lived loop inside the worker runtime (so it
 * also runs embedded in the server process). Every 2 s it fans out new events
 * and releases due deliveries to Redis, at most the in-flight cap per endpoint
 * (a finished attempt also releases its endpoint's next one at once); every
 * 60 s it reclaims expired leases,
 * fails expired deliveries and re-keys secrets, and (beside it) runs the
 * credential maintenance tick that rewraps vault DEKs and return private keys
 * after a data-key promote. Single-flight per process;
 * several processes are safe (SKIP LOCKED + CAS). No LISTEN/NOTIFY in v1
 * (review minor 13): a missed wake costs at most one poll interval and commit
 * paths stay free of NOTIFY serialization.
 */

export const DISPATCH_POLL_MS = 2_000;
export const MAINTENANCE_EVERY_MS = 60_000;

export type WebhookDispatcher = { stop(): Promise<void>; tick(): Promise<void> };

export function startWebhookDispatcher(options: {
  config: WebhookConfig | null;
  enqueue: EnqueueJobs;
  pollMs?: number;
  maintenanceMs?: number;
  /** Test seam: when false, no timer is armed and `tick()` drives it. */
  autoStart?: boolean;
  /** Test seam for ledger times; production uses the database clock. */
  now?: () => Date;
  /**
   * Monotonic milliseconds for the maintenance cadence (default
   * `performance.now`): a wall-clock correction can neither stall nor
   * stampede maintenance.
   */
  monotonic?: () => number;
}): WebhookDispatcher {
  const pollMs = options.pollMs ?? DISPATCH_POLL_MS;
  const maintenanceMs = options.maintenanceMs ?? MAINTENANCE_EVERY_MS;
  const monotonic = options.monotonic ?? (() => performance.now());
  let lastMaintenance = Number.NEGATIVE_INFINITY;
  let running: Promise<void> | null = null;
  let stopped = false;
  let timer: NodeJS.Timeout | undefined;
  // In-memory scan position across polls: fan-out resumes
  // after the last attempted event instead of restarting at the front.
  const cursor = newFanOutCursor();
  // Re-encryption resumes after the last row it looked at, so rows no key can
  // open never pin the batch (review: rekey starvation).
  const rekeyCursor = newRekeyCursor();
  const rewrapCursor = newCredentialRewrapCursor();
  // The release sweep resumes after the last endpoint it visited.
  const enqueueCursor = newEnqueueCursor();

  const report = (error: unknown) =>
    console.error(
      "[webhook-dispatcher] tick failed:",
      safeErrorLog(error, "webhook_dispatch_failed"),
    );

  const fanOut = async () => {
    // Drain a backlog in bounded batches; stop at a short batch or after lock
    // contention (the cursor carries the position to the next poll).
    for (let batch = 0; batch < 10; batch++) {
      const done = await fanOutEvents(undefined, options.now?.(), cursor);
      if (done < FAN_OUT_BATCH || cursor.contendedMs > 0) break;
    }
  };
  const credentialMaintenance = async () => {
    const result = await rewrapCredentialKeys({ cursor: rewrapCursor });
    // Counts only: never ids or key material.
    if (result.failed > 0)
      console.warn(
        `[credential-maintenance] ${result.failed} stored key(s) could not be rewrapped under any configured data key.`,
      );
    if (result.stale)
      console.warn(
        "[credential-maintenance] This process does not hold the data key the epoch names; rewrap skipped.",
      );
  };
  // Enqueue and maintenance run independently of fan-out's lock waits.
  const enqueueAndMaintain = async () => {
    await enqueuePending(options.enqueue, undefined, options.now?.(), enqueueCursor);
    const at = monotonic();
    if (at - lastMaintenance >= maintenanceMs) {
      lastMaintenance = at;
      // Its own failure never blocks the webhook maintenance below.
      const credentials = credentialMaintenance().catch((error: unknown) =>
        console.error(
          "[credential-maintenance] tick failed:",
          safeErrorLog(error, "credential_maintenance_failed"),
        ),
      );
      const result = await runMaintenance({
        now: options.now?.(),
        keys: options.config?.keys,
        rekeyCursor,
      });
      // A count only: never ids, URLs or key material.
      if (result.rekeyFailed > 0)
        console.warn(
          `[webhook-dispatcher] ${result.rekeyFailed} endpoint secret(s) could not be re-encrypted under any configured key; owners must rotate them.`,
        );
      await credentials;
    }
  };
  const once = async () => {
    const results = await Promise.allSettled([fanOut(), enqueueAndMaintain()]);
    for (const result of results) if (result.status === "rejected") report(result.reason);
  };
  const tick = () => {
    running ??= once().finally(() => {
      running = null;
    });
    return running;
  };
  const schedule = () => {
    if (stopped) return;
    timer = setTimeout(() => {
      void tick().finally(schedule);
    }, pollMs);
    timer.unref?.();
  };
  if (options.autoStart !== false) schedule();
  return {
    tick,
    async stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      await running;
    },
  };
}
