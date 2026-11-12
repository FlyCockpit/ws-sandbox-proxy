import { reapWebhookLog } from "@wssp/api/webhooks/ledger";
import type { ReapWebhookLogJobData } from "@wssp/queue";
import { reapWebhookLogJobSchema } from "@wssp/queue";
import type { Job } from "bullmq";

export async function handleReapWebhookLogJob(
  job: Pick<Job<ReapWebhookLogJobData>, "data" | "id">,
): Promise<{ reason: "cron"; deleted: number }> {
  const { reason } = reapWebhookLogJobSchema.parse(job.data);
  const start = Date.now();
  const deleted = await reapWebhookLog();
  console.log(
    `[reap-webhook-log] Job ${job.id} (${reason}) deleted ${deleted} event(s) in ${Date.now() - start}ms`,
  );
  return { reason, deleted };
}
