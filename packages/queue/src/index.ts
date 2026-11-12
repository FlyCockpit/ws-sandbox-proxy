import { Queue } from "bullmq";
import { redisConnection } from "./connection.js";
import { QUEUE_NAMES } from "./jobs.js";

export { FlowProducer, Job, Queue, QueueEvents, Worker } from "bullmq";
export { createRedisConnection, redisConnection } from "./connection.js";
export { ensureRunnableJob } from "./ensure-job.js";
export {
  CHECK_BACKUP_FRESHNESS_CRON_PATTERN,
  CHECK_BACKUP_FRESHNESS_JOB_SCHEDULER_ID,
  type CheckBackupFreshnessJobData,
  checkBackupFreshnessJobSchema,
  IMAGE_STORE_SCHEDULES,
  type ImageStoreMaintenanceJobData,
  imageStoreMaintenanceJobSchema,
  NOTIFY_DATA_DELETIONS_CRON_PATTERN,
  NOTIFY_DATA_DELETIONS_JOB_SCHEDULER_ID,
  type NotifyDataDeletionsJobData,
  notifyDataDeletionsJobSchema,
  QUEUE_NAMES,
  REAP_EXPIRED_AUTH_TOKENS_CRON_PATTERN,
  REAP_EXPIRED_AUTH_TOKENS_JOB_SCHEDULER_ID,
  REAP_WEBHOOK_LOG_CRON_PATTERN,
  REAP_WEBHOOK_LOG_JOB_SCHEDULER_ID,
  type ReapExpiredAuthTokensJobData,
  type ReapWebhookLogJobData,
  reapExpiredAuthTokensJobSchema,
  reapWebhookLogJobSchema,
  type WebhookDeliveryJobData,
  webhookDeliveryJobId,
  webhookDeliveryJobSchema,
} from "./jobs.js";

const defaultJobOptions = {
  attempts: 3,
  backoff: { type: "exponential" as const, delay: 1000 },
  removeOnComplete: { age: 3600, count: 1000 },
  removeOnFail: { age: 86400, count: 5000 },
};

/**
 * Deletes expired short-lived credentials (sessions, verifications, device
 * codes, preview tokens). Cron-only and unconditional: a bounded Postgres delete
 * every install owes its users.
 * `attempts: 1` — the next daily firing is the retry.
 */
export const reapExpiredAuthTokensQueue = new Queue(QUEUE_NAMES.reapExpiredAuthTokens, {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
  },
});

/**
 * Backup freshness check. `attempts: 1` like the other sweeps: a listing error
 * is itself a verdict the handler records and alerts on, and the next firing
 * (6 hours later) is the retry.
 */
export const checkBackupFreshnessQueue = new Queue(QUEUE_NAMES.checkBackupFreshness, {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
  },
});

/**
 * Template image store maintenance. `attempts: 2`: a verify that hits a
 * transient store error retries once; the hourly sweeps are their own retry.
 */
export const imageStoreMaintenanceQueue = new Queue(QUEUE_NAMES.imageStoreMaintenance, {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 2,
  },
});

/**
 * Webhook delivery attempts. `attempts: 1`: the retry schedule lives in the
 * Postgres ledger, never in BullMQ backoff. Produced only by the worker (the
 * dispatcher and the delivery handler); the server writes ledger rows.
 */
export const webhookDeliveryQueue = new Queue(QUEUE_NAMES.webhookDelivery, {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
  },
});

/** Daily webhook log prune. `attempts: 1`: the next firing is the retry. */
export const reapWebhookLogQueue = new Queue(QUEUE_NAMES.reapWebhookLog, {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
  },
});

/** At-least-once notices; the next scheduled firing retries undelivered mail. */
export const notifyDataDeletionsQueue = new Queue(QUEUE_NAMES.notifyDataDeletions, {
  connection: redisConnection,
  defaultJobOptions: { ...defaultJobOptions, attempts: 1 },
});
