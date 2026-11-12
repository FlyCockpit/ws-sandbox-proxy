/**
 * Disk offload worker jobs on the image store maintenance queue: `disk_verify` (decrypt, hash and size a
 * completed object, then `markStored`) and `disk_maintenance` (supersede and
 * stale backstops, the verify backstop, the consumed-grace shred and row
 * retention). Imported lazily by `image-store/jobs.ts`.
 */
export type DiskJob = { kind: "disk_verify"; offloadId: string } | { kind: "disk_maintenance" };

export async function handleDiskJob(job: DiskJob): Promise<unknown> {
  switch (job.kind) {
    case "disk_verify": {
      const { verifyDiskOffload } = await import("./verify");
      return verifyDiskOffload(job.offloadId);
    }
    case "disk_maintenance": {
      const { maintainDiskOffloads } = await import("./maintenance");
      return maintainDiskOffloads();
    }
  }
}
