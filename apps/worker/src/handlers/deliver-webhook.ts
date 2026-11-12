import type { WebhookConfig } from "@wssp/api/webhooks/config";
import { type DeliveryJobResult, runDeliveryJob } from "@wssp/api/webhooks/deliver";
import type { EnqueueJobs } from "@wssp/api/webhooks/ledger";
import prisma from "@wssp/db";
import { isEmailConfigured, renderWebhookEndpointDisabled, sendEmail } from "@wssp/mailer";
import { type WebhookDeliveryJobData, webhookDeliveryJobSchema } from "@wssp/queue";
import type { Job } from "bullmq";

/** Disable notice: once per disable (claimed in the disabling transaction). */
export async function notifyWebhookEndpointDisabled(input: {
  userId: string;
  host: string;
  consecutiveFailures: number;
}): Promise<void> {
  if (!isEmailConfigured()) return;
  const user = await prisma.user.findUnique({
    where: { id: input.userId },
    select: { email: true, locale: true, emailVerified: true },
  });
  if (!user?.emailVerified) return;
  const mail = renderWebhookEndpointDisabled({
    locale: user.locale,
    host: input.host,
    consecutiveFailures: input.consecutiveFailures,
  });
  await sendEmail({ to: user.email, subject: mail.subject, html: mail.html });
}

/**
 * BullMQ processor for `webhook-delivery`. Job data is ids only; everything
 * else is read from the ledger. A delivery outcome never fails the job.
 */
export function createDeliverWebhookHandler(deps: {
  config: WebhookConfig | null;
  enqueue: EnqueueJobs;
  notifyDisabled?: typeof notifyWebhookEndpointDisabled;
}) {
  return async (job: Pick<Job<WebhookDeliveryJobData>, "data">): Promise<DeliveryJobResult> => {
    const data = webhookDeliveryJobSchema.parse(job.data);
    return runDeliveryJob(data, {
      config: deps.config,
      enqueue: deps.enqueue,
      notifyDisabled: deps.notifyDisabled ?? notifyWebhookEndpointDisabled,
    });
  };
}
