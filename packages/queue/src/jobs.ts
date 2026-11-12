import { z } from "zod";

/**
 * Job schemas — define the shape of each job's payload here.
 * Both producers and workers import from this file so the contract is shared.
 */

/**
 * Backup freshness check — lists the backup bucket, records the age of the
 * newest dump in Redis, and alerts admins when it exceeds BACKUP_MAX_AGE_HOURS.
 * Cron-only.
 */
export const checkBackupFreshnessJobSchema = z.object({
  reason: z.enum(["cron"]),
});

export type CheckBackupFreshnessJobData = z.infer<typeof checkBackupFreshnessJobSchema>;

/**
 * Delete short-lived credential rows past their `expiresAt` — Session,
 * Verification (`packages/api/src/lib/auth-token-retention.ts`).
 *
 * Nothing else prunes those tables: expiry was only ever enforced by rejecting
 * the credential at read time, so expired rows accumulated forever. This is a bounded Postgres delete that owes nothing to
 * object storage, so its scheduler is registered unconditionally.
 *
 * Cron-only; `attempts: 1` like the other sweeps, because the next daily
 * firing is the retry and the delete is idempotent by construction.
 */
export const reapExpiredAuthTokensJobSchema = z.object({
  reason: z.enum(["cron"]),
});

export type ReapExpiredAuthTokensJobData = z.infer<typeof reapExpiredAuthTokensJobSchema>;

/**
 * One webhook delivery attempt. Ids only: the URL, secret and body stay in
 * Postgres (the delivery ledger owns state, schedule and backlog; Redis only
 * holds due work, at most the in-flight cap per endpoint).
 * `seq` is the delivery's `enqueueSeq`; the job id is
 * `wh-<deliveryId>-<seq>-<attempt>` (no `:`), so a deliberate re-release
 * always gets a fresh id instead of colliding with a kept completed job.
 */
export const webhookDeliveryJobSchema = z.object({
  deliveryId: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
  attempt: z.number().int().min(1).max(64),
  seq: z.number().int().min(0),
});

export type WebhookDeliveryJobData = z.infer<typeof webhookDeliveryJobSchema>;

export function webhookDeliveryJobId(data: WebhookDeliveryJobData): string {
  return `wh-${data.deliveryId}-${data.seq}-${data.attempt}`;
}

/** Daily prune of webhook events past retention (deliveries/attempts cascade). Cron-only. */
export const reapWebhookLogJobSchema = z.object({
  reason: z.enum(["cron"]),
});

export type ReapWebhookLogJobData = z.infer<typeof reapWebhookLogJobSchema>;

/**
 * Queue names — use these constants instead of string literals.
 */
export const QUEUE_NAMES = {
  notifyDataDeletions: "notify-data-deletions",
  reapExpiredAuthTokens: "reap-expired-auth-tokens",
  checkBackupFreshness: "check-backup-freshness",
  imageStoreMaintenance: "image-store-maintenance",
  webhookDelivery: "webhook-delivery",
  reapWebhookLog: "reap-webhook-log",
} as const;

/** Stable BullMQ Job Scheduler ID for the webhook log prune. */
export const REAP_WEBHOOK_LOG_JOB_SCHEDULER_ID = "reap-webhook-log";

/** Daily at 03:53 UTC: off the 03:15 / 03:45 / 04:17 / 04:30 sweep marks. */
export const REAP_WEBHOOK_LOG_CRON_PATTERN = "53 3 * * *";

/**
 * Template image store maintenance (docs/operations/templates.md#image-store):
 * verify an uploaded object, GC unreferenced artifacts, sweep orphans and
 * stale uploads, auto-prune old untagged revisions, refresh community bases,
 * and verify and maintain offloaded sandbox disks. One queue, seven kinds.
 */
export const imageStoreMaintenanceJobSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("verify"), artifactId: z.string().min(1).max(128) }),
  z.object({ kind: z.literal("gc") }),
  z.object({ kind: z.literal("sweep") }),
  z.object({ kind: z.literal("prune") }),
  /** Community base templates: the daily upstream refresh scan (community-base S10). */
  z.object({ kind: z.literal("community_refresh") }),
  /** Disk offload: verify one completed disk object. */
  z.object({ kind: z.literal("disk_verify"), offloadId: z.string().min(1).max(128) }),
  /** Disk offload backstops, consumed-grace shred and row retention (§3, §6a). */
  z.object({ kind: z.literal("disk_maintenance") }),
]);
export type ImageStoreMaintenanceJobData = z.infer<typeof imageStoreMaintenanceJobSchema>;
/** GC and sweep hourly at :37; prune daily at 04:47 UTC; the community refresh scan daily at 05:23 UTC; disk offload maintenance at :07 and :22 (off the other sweeps' marks). */
export const IMAGE_STORE_SCHEDULES = [
  { id: "image-store-gc", pattern: "37 * * * *", data: { kind: "gc" } },
  { id: "image-store-sweep", pattern: "52 * * * *", data: { kind: "sweep" } },
  { id: "image-store-prune", pattern: "47 4 * * *", data: { kind: "prune" } },
  { id: "community-refresh", pattern: "23 5 * * *", data: { kind: "community_refresh" } },
  { id: "disk-offload-maintenance", pattern: "7,22 * * * *", data: { kind: "disk_maintenance" } },
] as const;

/** Stable BullMQ Job Scheduler ID for the expired-auth-token sweep. */
export const REAP_EXPIRED_AUTH_TOKENS_JOB_SCHEDULER_ID = "reap-expired-auth-tokens";

/**
 * Once a day at 04:17 UTC — deliberately off the 03:15 / 03:45 / 04:30 marks
 * the other daily sweeps fire on, so four bounded-delete loops never share a
 * window. Daily is the right cadence for rows whose only cost is existing:
 * an expired credential is dead the moment it ages out, and sweeping more
 * often would re-scan the same indexed range for nothing.
 */
export const REAP_EXPIRED_AUTH_TOKENS_CRON_PATTERN = "17 4 * * *";

/** Stable BullMQ Job Scheduler ID for the backup freshness check. */
export const CHECK_BACKUP_FRESHNESS_JOB_SCHEDULER_ID = "check-backup-freshness";

/**
 * Every 6 hours at :20. Nightly dumps land at 03:00 and BACKUP_MAX_AGE_HOURS
 * defaults to 36, so a missed run is noticed within a quarter-day of crossing
 * the threshold; more often would only re-list the bucket for the same answer.
 */
export const CHECK_BACKUP_FRESHNESS_CRON_PATTERN = "20 */6 * * *";

/** Cron-only notification of migration contracts that deleted data. */
export const notifyDataDeletionsJobSchema = z.object({ reason: z.literal("cron") });
export type NotifyDataDeletionsJobData = z.infer<typeof notifyDataDeletionsJobSchema>;
export const NOTIFY_DATA_DELETIONS_JOB_SCHEDULER_ID = "notify-data-deletions";
export const NOTIFY_DATA_DELETIONS_CRON_PATTERN = "*/15 * * * *";
