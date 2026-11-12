import type { ReapedAuthTokens } from "@wssp/api/lib/auth-token-retention";
import { reapExpiredAuthTokens } from "@wssp/api/lib/auth-token-retention";
import type { ReapExpiredAuthTokensJobData } from "@wssp/queue";
import { reapExpiredAuthTokensJobSchema } from "@wssp/queue";
import type { Job } from "bullmq";

export async function handleReapExpiredAuthTokensJob(
  job: Job<ReapExpiredAuthTokensJobData>,
): Promise<{ reason: "cron"; deleted: ReapedAuthTokens }> {
  const { reason } = reapExpiredAuthTokensJobSchema.parse(job.data);
  const start = Date.now();
  const { deleted } = await reapExpiredAuthTokens();
  console.log(
    `[reap-expired-auth-tokens] Job ${job.id} (${reason}) deleted ` +
      `${deleted.deviceCodes} device code(s), ${deleted.sessions} session(s), ${deleted.verifications} verification(s) ` +
      `in ${Date.now() - start}ms`,
  );
  return { reason, deleted };
}
