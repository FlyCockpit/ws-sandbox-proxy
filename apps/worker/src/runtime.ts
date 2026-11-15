import { readDataKeyring } from "@wssp/api/crypto/data-key";
import { startDataKeyHeartbeat } from "@wssp/api/crypto/data-key-heartbeat";
import { canRestore } from "@wssp/api/sandbox/disk-offload/availability";
import { imageDistributionMode } from "@wssp/api/sandbox/image-store/config";
import { safeErrorLog } from "@wssp/api/sandbox/sensitive-errors";
import { loadWebhookConfig } from "@wssp/api/webhooks/config";
import type { EnqueueJobs } from "@wssp/api/webhooks/ledger";
import { type InstanceHeartbeat, startInstanceHeartbeat } from "@wssp/db/instance-heartbeat";
import type {
  CheckBackupFreshnessJobData,
  ImageStoreMaintenanceJobData,
  NotifyDataDeletionsJobData,
  ReapExpiredAuthTokensJobData,
  ReapWebhookLogJobData,
  WebhookDeliveryJobData,
} from "@wssp/queue";
import {
  CHECK_BACKUP_FRESHNESS_CRON_PATTERN,
  checkBackupFreshnessQueue,
  createRedisConnection,
  IMAGE_STORE_SCHEDULES,
  imageStoreMaintenanceQueue,
  NOTIFY_DATA_DELETIONS_CRON_PATTERN,
  NOTIFY_DATA_DELETIONS_JOB_SCHEDULER_ID,
  notifyDataDeletionsQueue,
  QUEUE_NAMES,
  REAP_EXPIRED_AUTH_TOKENS_CRON_PATTERN,
  REAP_EXPIRED_AUTH_TOKENS_JOB_SCHEDULER_ID,
  REAP_WEBHOOK_LOG_CRON_PATTERN,
  REAP_WEBHOOK_LOG_JOB_SCHEDULER_ID,
  reapExpiredAuthTokensQueue,
  reapWebhookLogQueue,
  webhookDeliveryJobId,
  webhookDeliveryQueue,
} from "@wssp/queue";
import { createConsumerHeartbeat } from "@wssp/queue/consumer-health";
import { type Processor, Worker, type WorkerOptions } from "bullmq";
import { syncBackupFreshnessScheduler } from "./backup-freshness-scheduler.js";
import { handleCheckBackupFreshnessJob } from "./handlers/check-backup-freshness.js";
import { createDeliverWebhookHandler } from "./handlers/deliver-webhook.js";
import { handleImageStoreMaintenanceJob } from "./handlers/image-store-maintenance.js";
import { handleNotifyDataDeletionsJob } from "./handlers/notify-data-deletions.js";
import { handleReapExpiredAuthTokensJob } from "./handlers/reap-expired-auth-tokens.js";
import { handleReapWebhookLogJob } from "./handlers/reap-webhook-log.js";
import {
  closeOperationalAlertConnection,
  sendOperationalFailureAlert,
} from "./operational-alerts.js";
import { withTimeout } from "./runtime-lifecycle.js";
import { startWebhookDispatcher, type WebhookDispatcher } from "./webhook-dispatcher.js";

// One lifecycle per process.
// The host owns signals, fatal exit, and the shared Prisma/producer connections.
let claimed = false;
export type WorkerRuntime = {
  isReady(): boolean;
  stop(): Promise<void>;
};
export class WorkerDrainError extends Error {}

export async function startWorkerRuntime(options: {
  embedded: boolean;
  onFatal(error: unknown): void;
  signal?: AbortSignal;
}): Promise<WorkerRuntime> {
  if (claimed) throw new Error("Worker runtime already started; restart the process to re-enter.");
  claimed = true;
  const { embedded } = options;
  const connection = createRedisConnection();
  const heartbeatConnection = createRedisConnection({
    maxRetriesPerRequest: 1,
    commandTimeout: 3000,
  });
  const workers: Array<
    Pick<Worker, "name" | "close" | "run" | "isRunning" | "isPaused" | "waitUntilReady">
  > = [];
  const requiredQueues = Object.values(QUEUE_NAMES);
  let stopping = false;
  let ready = false;
  let failed = false;
  let stopPromise: Promise<void> | undefined;
  let dispatcher: WebhookDispatcher | undefined;
  let instanceHeartbeat: InstanceHeartbeat | undefined;
  const dataKeyHeartbeat = new AbortController();
  const heartbeat = createConsumerHeartbeat(
    heartbeatConnection,
    embedded ? "embedded" : "external",
    requiredQueues,
    () =>
      ready &&
      !stopping &&
      !failed &&
      connection.status === "ready" &&
      workers.length === requiredQueues.length &&
      requiredQueues.every((name) => workers.some((worker) => worker.name === name)) &&
      workers.every((worker) => worker.isRunning() && !worker.isPaused()),
  );
  function createWorker<T>(name: string, processor: Processor<T>, options: WorkerOptions) {
    const worker = new Worker<T>(name, processor, { ...options, autorun: false });
    workers.push(worker);
    worker.on("error", (error) =>
      console.error(
        "[worker] Consumer connection error:",
        safeErrorLog(error, "worker_connection_error"),
      ),
    );
    return worker;
  }
  function stop(): Promise<void> {
    if (stopPromise) return stopPromise;
    stopping = true;
    ready = false;
    dataKeyHeartbeat.abort();
    stopPromise = (async () => {
      // The dispatcher stops producing before consumers drain.
      const dispatcherStop = dispatcher?.stop() ?? Promise.resolve();
      // Closing consumers must begin even if a pending heartbeat cannot finish.
      // stop() closes BullMQ admission synchronously before awaiting active jobs.
      const workerDrains = Promise.allSettled(workers.map((worker) => worker.close()));
      const heartbeatFailure = await heartbeat.stop().then(
        () => false,
        () => true,
      );
      const results = await workerDrains;
      await dispatcherStop.catch(() => {});
      if (results.some((result) => result.status === "rejected")) {
        throw new Error("One or more job consumers did not close cleanly.");
      }
      await instanceHeartbeat?.stop();
      connection.disconnect();
      heartbeatConnection.disconnect();
      closeOperationalAlertConnection();
      if (heartbeatFailure) throw new Error("Consumer heartbeat did not close cleanly.");
    })();
    // Do not disconnect shared clients or pretend timed-out handlers stopped.
    // The host must exit on this rejection; its watchdog owns the hard deadline.
    stopPromise = withTimeout(
      stopPromise,
      15_000,
      "Worker drain timed out; process must exit.",
    ).catch((error: unknown) => {
      throw new WorkerDrainError(error instanceof Error ? error.message : "Worker drain failed.", {
        cause: error,
      });
    });
    return stopPromise;
  }
  options.signal?.addEventListener(
    "abort",
    () => {
      void stop().catch(() => {});
    },
    { once: true },
  );
  const requireRunning = () => {
    if (stopping || options.signal?.aborted) throw new Error("Worker startup cancelled.");
  };

  try {
    requireRunning();
    for (let attempt = 0; ; attempt++) {
      try {
        requireRunning();
        await withTimeout(connection.ping(), 5000, "Redis startup ping timed out");
        break;
      } catch (error) {
        requireRunning();
        if (attempt === 4) throw error;
        await new Promise((resolve) => setTimeout(resolve, 500 * 2 ** attempt));
      }
    }
    requireRunning();

    // Embedded consumers share the server's admitted instance row.
    if (!embedded) instanceHeartbeat = startInstanceHeartbeat({ role: "worker" });
    const noticeWorker = createWorker<NotifyDataDeletionsJobData>(
      QUEUE_NAMES.notifyDataDeletions,
      handleNotifyDataDeletionsJob,
      { connection, concurrency: 1 },
    );
    noticeWorker.on("failed", (job, error) => {
      console.error(
        "[notify-data-deletions] Job failed:",
        safeErrorLog(error, "data_deletion_job_failed"),
      );
      void reportJobFailure("notify-data-deletions", job, error);
    });
    requireRunning();
    try {
      await notifyDataDeletionsQueue.upsertJobScheduler(
        NOTIFY_DATA_DELETIONS_JOB_SCHEDULER_ID,
        { pattern: NOTIFY_DATA_DELETIONS_CRON_PATTERN },
        { name: "notify-data-deletions", data: { reason: "cron" } },
      );
    } catch (error) {
      console.error(
        "[notify-data-deletions] Failed to register job scheduler:",
        safeErrorLog(error, "data_deletion_scheduler_failed"),
      );
      throw error;
    }

    // Expired short-lived credentials (sessions, verifications) — a
    // bounded Postgres delete.
    // Concurrency 1: two overlapping sweeps would select the same id pages and
    // race the delete loops for no gain.
    const reapExpiredAuthTokensWorker = createWorker<ReapExpiredAuthTokensJobData>(
      QUEUE_NAMES.reapExpiredAuthTokens,
      handleReapExpiredAuthTokensJob,
      { connection, concurrency: 1 },
    );

    reapExpiredAuthTokensWorker.on("completed", (job) => {
      console.log(`[reap-expired-auth-tokens] Job ${job.id} completed`);
    });

    reapExpiredAuthTokensWorker.on("failed", (job, err) => {
      console.error(
        `[reap-expired-auth-tokens] Job ${job?.id} failed:`,
        safeErrorLog(err, "token_reaper_job_failed"),
      );
      void reportJobFailure("reap-expired-auth-tokens", job, err);
    });

    // Backup freshness: one listing of the backup bucket per run, so concurrency 1.
    // The worker is always constructed (a job enqueued from the admin UI must not
    // sit forever), but the schedule is registered only when backups are on.
    const checkBackupFreshnessWorker = createWorker<CheckBackupFreshnessJobData>(
      QUEUE_NAMES.checkBackupFreshness,
      handleCheckBackupFreshnessJob,
      { connection, concurrency: 1 },
    );

    checkBackupFreshnessWorker.on("completed", (job) => {
      console.log(`[check-backup-freshness] Job ${job.id} completed`);
    });

    checkBackupFreshnessWorker.on("failed", (job, err) => {
      console.error(
        `[check-backup-freshness] Job ${job?.id} failed:`,
        safeErrorLog(err, "backup_freshness_job_failed"),
      );
      void reportJobFailure("check-backup-freshness", job, err);
    });

    // Image store maintenance: always consumed (verify jobs come from the
    // server). The template-only jobs run only when image distribution is on;
    // the disk offload maintenance runs whenever an offloaded disk can be
    // restored (S3 plus the data key), whatever image distribution says (R12).
    // So does the bucket sweep: it is also the only reaper of orphaned disk
    // objects and stale multipart uploads, which offload leaves with
    // distribution off.
    const imageStoreWorker = createWorker<ImageStoreMaintenanceJobData>(
      QUEUE_NAMES.imageStoreMaintenance,
      handleImageStoreMaintenanceJob,
      { connection, concurrency: 1 },
    );
    imageStoreWorker.on("failed", (job, err) => {
      console.error(
        `[image-store-maintenance] Job ${job?.id} failed:`,
        safeErrorLog(err, "image_store_job_failed"),
      );
      void reportJobFailure("image-store-maintenance", job, err);
    });

    try {
      requireRunning();
      for (const schedule of IMAGE_STORE_SCHEDULES) {
        const enabled =
          schedule.data.kind === "disk_maintenance"
            ? canRestore()
            : schedule.data.kind === "sweep"
              ? imageDistributionMode() !== "off" || canRestore()
              : imageDistributionMode() !== "off";
        if (!enabled) await imageStoreMaintenanceQueue.removeJobScheduler(schedule.id);
        else
          await imageStoreMaintenanceQueue.upsertJobScheduler(
            schedule.id,
            { pattern: schedule.pattern },
            { name: schedule.data.kind, data: { ...schedule.data } },
          );
      }
      // Redis keeps a scheduler after its entry leaves IMAGE_STORE_SCHEDULES
      // (a retired kind such as the old community refresh would keep producing
      // jobs the schema refuses): the queue holds exactly the configured set.
      const configured = new Set<string>(IMAGE_STORE_SCHEDULES.map((schedule) => schedule.id));
      // A handful of schedulers exist; the bound only stops a runaway list.
      for (const scheduler of await imageStoreMaintenanceQueue.getJobSchedulers(0, 199)) {
        if (!configured.has(scheduler.key))
          await imageStoreMaintenanceQueue.removeJobScheduler(scheduler.key);
      }
    } catch (err) {
      console.error(
        "[image-store-maintenance] Failed to sync job schedulers:",
        safeErrorLog(err, "image_store_scheduler_failed"),
      );
      throw err;
    }

    // Webhooks. The allowlist is validated here (boot failure on a bad CIDR);
    // without DATA_ENCRYPTION_KEY the consumer still runs (consumer health needs
    // every queue) and defers each delivery as `not_configured`.
    const webhookConfig = loadWebhookConfig();
    // Only runnable work reaches Redis (at most the in-flight cap per
    // endpoint); the backlog and retry schedule stay in Postgres.
    const enqueueWebhook: EnqueueJobs = async (requests) => {
      await webhookDeliveryQueue.addBulk(
        requests.map((request) => {
          const data: WebhookDeliveryJobData = {
            deliveryId: request.deliveryId,
            attempt: request.attempt,
            seq: request.seq,
          };
          return { name: "deliver", data, opts: { jobId: webhookDeliveryJobId(data) } };
        }),
      );
    };
    if (!webhookConfig)
      console.log("[webhook-delivery] DATA_ENCRYPTION_KEY is not set; webhooks are disabled.");
    const webhookDeliveryWorker = createWorker<WebhookDeliveryJobData>(
      QUEUE_NAMES.webhookDelivery,
      createDeliverWebhookHandler({ config: webhookConfig, enqueue: enqueueWebhook }),
      { connection, concurrency: webhookConfig?.deliveryConcurrency ?? 8 },
    );
    webhookDeliveryWorker.on("failed", (job, err) => {
      // Fixed text only: a delivery failure must never put a URL in an alert.
      console.error(
        `[webhook-delivery] Job ${job?.id} failed:`,
        safeErrorLog(err, "webhook_delivery_job_failed"),
      );
    });
    const reapWebhookLogWorker = createWorker<ReapWebhookLogJobData>(
      QUEUE_NAMES.reapWebhookLog,
      handleReapWebhookLogJob,
      { connection, concurrency: 1 },
    );
    reapWebhookLogWorker.on("failed", (job, err) => {
      console.error(
        `[reap-webhook-log] Job ${job?.id} failed:`,
        safeErrorLog(err, "webhook_log_reaper_failed"),
      );
      void reportJobFailure("reap-webhook-log", job, err);
    });

    // Expired-auth-token pruning is registered unconditionally for the same
    // reason: reading `expiresAt` back is the only thing that ever happened to
    // an expired session or verification — the
    // rows piled up forever. The sweep needs nothing but Postgres.
    try {
      requireRunning();
      await reapExpiredAuthTokensQueue.upsertJobScheduler(
        REAP_EXPIRED_AUTH_TOKENS_JOB_SCHEDULER_ID,
        { pattern: REAP_EXPIRED_AUTH_TOKENS_CRON_PATTERN },
        { name: "reap-expired-auth-tokens", data: { reason: "cron" } },
      );
      console.log(
        `[reap-expired-auth-tokens] Registered job scheduler (${REAP_EXPIRED_AUTH_TOKENS_CRON_PATTERN}).`,
      );
    } catch (err) {
      console.error(
        "[reap-expired-auth-tokens] Failed to register job scheduler:",
        safeErrorLog(err, "token_reaper_scheduler_failed"),
      );
      throw err;
    }

    try {
      requireRunning();
      await reapWebhookLogQueue.upsertJobScheduler(
        REAP_WEBHOOK_LOG_JOB_SCHEDULER_ID,
        { pattern: REAP_WEBHOOK_LOG_CRON_PATTERN },
        { name: "reap-webhook-log", data: { reason: "cron" } },
      );
    } catch (err) {
      console.error(
        "[reap-webhook-log] Failed to register job scheduler:",
        safeErrorLog(err, "webhook_log_scheduler_failed"),
      );
      throw err;
    }

    // Backup freshness is gated on the BACKUP_* config, not on object storage:
    // backups use their own bucket and credentials. The default disabled profile
    // has nothing to measure, so it registers nothing.
    try {
      requireRunning();
      const action = await syncBackupFreshnessScheduler(checkBackupFreshnessQueue);
      if (action === "upserted") {
        console.log(
          `[check-backup-freshness] Registered job scheduler (${CHECK_BACKUP_FRESHNESS_CRON_PATTERN}).`,
        );
      }
    } catch (err) {
      console.error(
        "[check-backup-freshness] Failed to sync job scheduler:",
        safeErrorLog(err, "backup_freshness_scheduler_failed"),
      );
      throw err;
    }

    await withTimeout(
      Promise.all(workers.map((worker) => worker.waitUntilReady())),
      10_000,
      "Job consumer startup timed out",
    );
    requireRunning();
    ready = true;
    for (const worker of workers) {
      void worker.run().catch((error: unknown) => {
        failed = true;
        void sendOperationalFailureAlert({
          queue: "worker",
          jobId: "consumer-failure",
          message: error instanceof Error ? error.message : String(error),
        }).catch(() => {});
        options.onFatal(error);
      });
    }
    await heartbeat.start();
    requireRunning();
    if (heartbeat.isReady()) instanceHeartbeat?.markReady();
    dispatcher = startWebhookDispatcher({ config: webhookConfig, enqueue: enqueueWebhook });
    // Advisory data-key heartbeat; an embedded worker shares the server's.
    if (!embedded)
      startDataKeyHeartbeat({
        redis: heartbeatConnection,
        role: "worker",
        readRing: readDataKeyring,
        signal: dataKeyHeartbeat.signal,
      });
    console.log(
      embedded ? "[worker] Embedded consumers started." : "[worker] External consumers started.",
    );
    return { isReady: () => heartbeat.isReady(), stop };
  } catch (error) {
    // Propagate an unclean drain to the host. A rejected startup alone does not
    // prove that active jobs released their shared Prisma/producer dependencies.
    await stop();
    throw error;
  }
}

type FailedJob = {
  id?: string | number;
  attemptsMade: number;
  finishedOn?: number;
  opts: { attempts?: number };
};

// BullMQ emits `failed` on every attempt, not only the last one. Act (alert,
// mark FAILED) only once the job has exhausted its retries so a queue with
// `attempts > 1` doesn't fire one alert per retry. A missing job handle (rare:
// lock lost) is treated as terminal so the failure is still surfaced.
function isTerminalFailure(job: FailedJob | undefined, err?: Error): boolean {
  if (!job) return true;
  if (err?.name === "UnrecoverableError") return true;
  if (job.finishedOn !== undefined) return true;
  return job.attemptsMade >= (job.opts.attempts ?? 1);
}

async function reportJobFailure(
  queue: string,
  job: FailedJob | undefined,
  err: Error,
): Promise<void> {
  if (!isTerminalFailure(job, err)) return;
  try {
    await sendOperationalFailureAlert({ queue, jobId: job?.id, message: err.message });
  } catch (alertErr) {
    console.error(
      `[${queue}] Failed to send operational alert:`,
      safeErrorLog(alertErr, "operational_alert_failed"),
    );
  }
}
