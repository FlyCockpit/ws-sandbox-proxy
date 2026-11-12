import { beforeEach, describe, expect, it, vi } from "vitest";

const handle = vi.hoisted(() => vi.fn());
vi.mock("@wssp/api/sandbox/image-store/jobs", () => ({ handleImageStoreJob: handle }));
vi.mock("@wssp/queue", async () => {
  const jobs = await import("../../../../packages/queue/src/jobs.js");
  return { imageStoreMaintenanceJobSchema: jobs.imageStoreMaintenanceJobSchema };
});
const { handleImageStoreMaintenanceJob } = await import("./image-store-maintenance.js");

describe("image store maintenance job — unit (mocked handler; real store: image-store.s3.test.ts)", () => {
  beforeEach(() => handle.mockReset());
  it("dispatches a parsed job and refuses an unknown kind", async () => {
    handle.mockResolvedValue("stored");
    await expect(
      handleImageStoreMaintenanceJob({ data: { kind: "verify", artifactId: "a1" } } as never),
    ).resolves.toBe("stored");
    expect(handle).toHaveBeenCalledWith({ kind: "verify", artifactId: "a1" });
    await expect(
      handleImageStoreMaintenanceJob({ data: { kind: "drop-bucket" } } as never),
    ).rejects.toThrow();
  });
});
