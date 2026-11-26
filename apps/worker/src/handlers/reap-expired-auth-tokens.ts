import type { ReapedAuthTokens } from "@wssp/api/lib/auth-token-retention";
import { reapExpiredAuthTokens } from "@wssp/api/lib/auth-token-retention";
import { purgeConnectSessions } from "@wssp/api/sandbox/connect-session-retention";
import type { ReapExpiredAuthTokensJobData } from "@wssp/queue";
import { reapExpiredAuthTokensJobSchema } from "@wssp/queue";
import type { Job } from "bullmq";
import { sweepHostAccessRetention } from "../../../../packages/api/src/sandbox/host-retention.js";

export async function handleReapExpiredAuthTokensJob(
  job: Job<ReapExpiredAuthTokensJobData>,
): Promise<{ reason: "cron"; deleted: ReapedAuthTokens }> {
  const { reason } = reapExpiredAuthTokensJobSchema.parse(job.data);
  const start = Date.now();
  const { deleted } = await reapExpiredAuthTokens();
  await sweepHostAccessRetention();
  // CLI connection audit rows past 90 days, bounded batches.
  const connectSessions = await purgeConnectSessions();
  console.log(
    `[reap-expired-auth-tokens] Job ${job.id} (${reason}) deleted ` +
      `${deleted.deviceCodes} device code(s), ${deleted.sessions} session(s), ${deleted.verifications} verification(s), ` +
      `${connectSessions} connect session(s) in ${Date.now() - start}ms`,
  );
  return { reason, deleted };
}
