import { handleImageStoreJob } from "@wssp/api/sandbox/image-store/jobs";
import { VerifyCancelledError } from "@wssp/api/sandbox/image-store/verification-errors";
import type { ImageStoreMaintenanceJobData } from "@wssp/queue";
import { imageStoreMaintenanceJobSchema } from "@wssp/queue";
import { type Job, WaitingError } from "bullmq";

type Run = typeof handleImageStoreJob;

/**
 * Verify, GC, sweep and prune for the template image store (bounded per run).
 * The third parameter makes BullMQ hand the job an abort signal: a drain
 * cancels a long verify, which writes nothing and goes back to `wait` without
 * spending an attempt, so the next consumer runs it at once instead of after
 * stall detection. `shutdown` is the runtime's drain signal: a job that a
 * fetch already in flight starts after the drain's `cancelAllJobs` sees it
 * (it is combined with the per-job signal, and checked on entry).
 */
export function createImageStoreMaintenanceHandler(
  run: Run = handleImageStoreJob,
  shutdown?: AbortSignal,
) {
  return async (
    job: Job<ImageStoreMaintenanceJobData>,
    token?: string,
    signal?: AbortSignal,
  ): Promise<unknown> => {
    const cancel = signal && shutdown ? AbortSignal.any([signal, shutdown]) : (signal ?? shutdown);
    try {
      if (shutdown?.aborted) throw new VerifyCancelledError();
      return await run(imageStoreMaintenanceJobSchema.parse(job.data), cancel);
    } catch (error) {
      if (!(error instanceof VerifyCancelledError) || !token) throw error;
      // A failed move rethrows: the attempt then fails and retries as before.
      await job.moveToWait(token);
      throw new WaitingError();
    }
  };
}

export const handleImageStoreMaintenanceJob = createImageStoreMaintenanceHandler();
