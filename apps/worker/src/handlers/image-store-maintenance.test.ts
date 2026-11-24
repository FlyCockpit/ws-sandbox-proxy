import { VerifyCancelledError } from "@wssp/api/sandbox/image-store/verification-errors";
import { beforeEach, describe, expect, it, vi } from "vitest";

const handle = vi.hoisted(() => vi.fn());
vi.mock("@wssp/api/sandbox/image-store/jobs", () => ({ handleImageStoreJob: handle }));
vi.mock("@wssp/queue", async () => {
  const jobs = await import("../../../../packages/queue/src/jobs.js");
  return { imageStoreMaintenanceJobSchema: jobs.imageStoreMaintenanceJobSchema };
});
const { createImageStoreMaintenanceHandler, handleImageStoreMaintenanceJob } = await import(
  "./image-store-maintenance.js"
);

const verifyJob = () => ({
  data: { kind: "verify", artifactId: "a1" },
  moveToWait: vi.fn(async () => 0),
});

describe("image store maintenance job — unit (mocked handler; real store: image-store.s3.test.ts)", () => {
  beforeEach(() => handle.mockReset());
  it("dispatches a parsed job and refuses an unknown kind", async () => {
    handle.mockResolvedValue("stored");
    await expect(
      handleImageStoreMaintenanceJob({ data: { kind: "verify", artifactId: "a1" } } as never),
    ).resolves.toBe("stored");
    expect(handle).toHaveBeenCalledWith({ kind: "verify", artifactId: "a1" }, undefined);
    await expect(
      handleImageStoreMaintenanceJob({ data: { kind: "drop-bucket" } } as never),
    ).rejects.toThrow();
  });

  it("takes BullMQ's abort signal (third parameter) and passes it to the job", async () => {
    // BullMQ creates the per-job abort controller only for processors of arity ≥ 3.
    expect(handleImageStoreMaintenanceJob.length).toBe(3);
    handle.mockResolvedValue("stored");
    const signal = new AbortController().signal;
    await handleImageStoreMaintenanceJob(verifyJob() as never, "token-1", signal);
    expect(handle).toHaveBeenCalledWith({ kind: "verify", artifactId: "a1" }, signal);
  });

  it("a verify cancelled on shutdown goes back to wait without spending an attempt", async () => {
    handle.mockImplementationOnce(async () => {
      throw new VerifyCancelledError();
    });
    const job = verifyJob();
    const settled = handleImageStoreMaintenanceJob(
      job as never,
      "token-1",
      AbortSignal.abort(),
    ).catch((error: unknown) => error);
    expect(await settled).toMatchObject({ name: "WaitingError" });
    expect(job.moveToWait).toHaveBeenCalledExactlyOnceWith("token-1");
  });

  it("a job a fetch in flight starts after the drain began never runs and goes back to wait", async () => {
    const shutdown = new AbortController();
    const handler = createImageStoreMaintenanceHandler(handle, shutdown.signal);
    expect(handler.length).toBe(3);
    shutdown.abort("worker shutdown");
    const job = verifyJob();
    // BullMQ tracked the job after cancelAllJobs: its own signal never fires.
    const settled = handler(job as never, "token-1", new AbortController().signal).catch(
      (error: unknown) => error,
    );
    expect(await settled).toMatchObject({ name: "WaitingError" });
    expect(handle).not.toHaveBeenCalled();
    expect(job.moveToWait).toHaveBeenCalledExactlyOnceWith("token-1");
  });

  it("a running job sees the drain through either its own signal or the runtime's", async () => {
    for (const source of ["job", "runtime"] as const) {
      const shutdown = new AbortController();
      const own = new AbortController();
      let seen: AbortSignal | undefined;
      handle.mockImplementationOnce(async (_data: unknown, signal: AbortSignal) => {
        seen = signal;
        await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
        throw new VerifyCancelledError();
      });
      const job = verifyJob();
      const settled = createImageStoreMaintenanceHandler(handle, shutdown.signal)(
        job as never,
        "token-1",
        own.signal,
      ).catch((error: unknown) => error);
      await vi.waitFor(() => expect(seen).toBeDefined());
      (source === "job" ? own : shutdown).abort("worker shutdown");
      expect(await settled).toMatchObject({ name: "WaitingError" });
      expect(job.moveToWait).toHaveBeenCalledExactlyOnceWith("token-1");
    }
  });

  it("any other failure, a cancel without a lock token, or a failed move fails the attempt as before", async () => {
    const failure = new Error("store unavailable");
    handle.mockRejectedValueOnce(failure);
    const job = verifyJob();
    await expect(handleImageStoreMaintenanceJob(job as never, "token-1")).rejects.toBe(failure);
    expect(job.moveToWait).not.toHaveBeenCalled();

    const cancelled = new VerifyCancelledError();
    handle.mockRejectedValueOnce(cancelled);
    await expect(handleImageStoreMaintenanceJob(job as never, undefined)).rejects.toBe(cancelled);
    expect(job.moveToWait).not.toHaveBeenCalled();

    const moveFailure = new Error("redis gone");
    handle.mockRejectedValueOnce(new VerifyCancelledError());
    job.moveToWait.mockRejectedValueOnce(moveFailure);
    await expect(handleImageStoreMaintenanceJob(job as never, "token-1")).rejects.toBe(moveFailure);
  });
});
