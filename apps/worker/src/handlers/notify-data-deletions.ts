import { safeErrorLog } from "@wssp/api/sandbox/sensitive-errors";
import {
  listUnnotifiedDataDeletions,
  markDataDeletionNotified,
} from "@wssp/db/data-deletion-notices";
import { isEmailConfigured } from "@wssp/mailer";
import { type NotifyDataDeletionsJobData, notifyDataDeletionsJobSchema } from "@wssp/queue";
import type { Job } from "bullmq";
import { sendDataDeletedAlert } from "../operational-alerts.js";

/** Send before marking: failed delivery or bookkeeping remains retryable. */
export async function handleNotifyDataDeletionsJob(
  job: Job<NotifyDataDeletionsJobData>,
): Promise<{ reason: "cron"; notified: number; retried: number }> {
  const { reason } = notifyDataDeletionsJobSchema.parse(job.data);
  if (!isEmailConfigured()) return { reason, notified: 0, retried: 0 };
  const notices = await listUnnotifiedDataDeletions();
  let notified = 0;
  let retried = 0;
  for (const notice of notices) {
    try {
      if ((await sendDataDeletedAlert(notice)) >= 1) {
        await markDataDeletionNotified(notice.name);
        notified++;
      } else {
        retried++;
      }
    } catch (error) {
      retried++;
      console.error(
        "[notify-data-deletions] Notice remains unrecorded; retrying on the next run:",
        safeErrorLog(error, "data_deletion_notice_failed"),
      );
    }
  }
  return { reason, notified, retried };
}
