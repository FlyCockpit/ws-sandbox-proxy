import { handleImageStoreJob } from "@wssp/api/sandbox/image-store/jobs";
import type { ImageStoreMaintenanceJobData } from "@wssp/queue";
import { imageStoreMaintenanceJobSchema } from "@wssp/queue";
import type { Job } from "bullmq";

/** Verify, GC, sweep and prune for the template image store (bounded per run). */
export async function handleImageStoreMaintenanceJob(
  job: Job<ImageStoreMaintenanceJobData>,
): Promise<unknown> {
  return handleImageStoreJob(imageStoreMaintenanceJobSchema.parse(job.data));
}
