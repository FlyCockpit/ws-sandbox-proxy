import { beforeEach, expect, it, vi } from "vitest";
import { mockDeep, mockReset } from "vitest-mock-extended";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("./keys", async (original) => ({
  ...(await original<typeof import("./keys")>()),
  loadDiskObjectKey: vi.fn(),
}));
vi.mock("./store", () => ({
  failLiveOffload: vi.fn(),
  finishEndedOffload: vi.fn(),
  markStored: vi.fn(),
}));

import prisma from "@wssp/db";
import { type ImageStore } from "../image-store/s3";
import { VerifyCancelledError } from "../image-store/verification-errors";
import { DiskKeyError, loadDiskObjectKey } from "./keys";
import { failLiveOffload, finishEndedOffload, markStored } from "./store";
import { verifyDiskOffload } from "./verify";

const db = vi.mocked(prisma, true);
const store = mockDeep<ImageStore>();
beforeEach(() => {
  vi.clearAllMocks();
  mockReset(store);
  db.sandboxDiskOffload.findFirst.mockResolvedValue({
    id: "offload-1",
    objectKey: "disk-key",
    completedSessionId: "session-1",
    fingerprint: `sha256:${"a".repeat(64)}`,
    sizeBytes: 5n,
  } as never);
});

it.each(["key read", "object read", "stream"])(
  "preserves the VERIFYING offload and its wraps after a transient %s failure",
  async (stage) => {
    const failure = new Error("temporary failure");
    const key = Buffer.alloc(32, 7);
    vi.mocked(loadDiskObjectKey).mockResolvedValue(key);
    if (stage === "key read") vi.mocked(loadDiskObjectKey).mockRejectedValueOnce(failure);
    if (stage === "object read") store.getObjectStream.mockRejectedValue(failure);
    if (stage === "stream") {
      store.getObjectStream.mockResolvedValue(
        (async function* () {
          yield Buffer.alloc(2);
          throw failure;
        })(),
      );
    }
    await expect(verifyDiskOffload("offload-1", store)).rejects.toBe(failure);
    expect(db.$transaction).not.toHaveBeenCalled();
    expect(failLiveOffload).not.toHaveBeenCalled();
    expect(finishEndedOffload).not.toHaveBeenCalled();
    expect(markStored).not.toHaveBeenCalled();
    expect(store.deleteObject).not.toHaveBeenCalled();
    if (stage !== "key read") expect(key).toEqual(Buffer.alloc(32));
  },
);

it("a shutdown mid-read is never a verdict: nothing is written, the wrap is kept and the key wiped", async () => {
  const key = Buffer.alloc(32, 7);
  vi.mocked(loadDiskObjectKey).mockResolvedValue(key);
  const shutdown = new AbortController();
  store.getObjectStream.mockResolvedValue(
    (async function* () {
      yield Buffer.alloc(2);
      // The aborted read surfaces as an error that alone would condemn the object.
      shutdown.abort("worker shutdown");
      throw new Error("Unsupported state or unable to authenticate data");
    })(),
  );
  await expect(verifyDiskOffload("offload-1", store, shutdown.signal)).rejects.toBeInstanceOf(
    VerifyCancelledError,
  );
  expect(store.getObjectStream).toHaveBeenCalledWith("disk-key", shutdown.signal);
  expect(db.$transaction).not.toHaveBeenCalled();
  expect(failLiveOffload).not.toHaveBeenCalled();
  expect(finishEndedOffload).not.toHaveBeenCalled();
  expect(markStored).not.toHaveBeenCalled();
  expect(store.deleteObject).not.toHaveBeenCalled();
  expect(key).toEqual(Buffer.alloc(32));
  // Already cancelled: not even the row is read.
  db.sandboxDiskOffload.findFirst.mockClear();
  await expect(verifyDiskOffload("offload-1", store, shutdown.signal)).rejects.toBeInstanceOf(
    VerifyCancelledError,
  );
  expect(db.sandboxDiskOffload.findFirst).not.toHaveBeenCalled();
});

it.each([
  new DiskKeyError("key_unavailable"),
  Object.assign(new Error(), { name: "NoSuchBucket", $metadata: { httpStatusCode: 404 } }),
])("preserves the offload and wraps on configuration drift (%j)", async (failure) => {
  if (failure instanceof DiskKeyError) vi.mocked(loadDiskObjectKey).mockRejectedValueOnce(failure);
  else {
    vi.mocked(loadDiskObjectKey).mockResolvedValueOnce(Buffer.alloc(32, 7));
    store.getObjectStream.mockRejectedValueOnce(failure);
  }
  await expect(verifyDiskOffload("offload-1", store)).rejects.toBe(failure);
  expect(db.$transaction).not.toHaveBeenCalled();
  expect(failLiveOffload).not.toHaveBeenCalled();
  expect(finishEndedOffload).not.toHaveBeenCalled();
});

it.each(["authentication_failed", "malformed", "not_stored"] as const)(
  "keeps a %s wrap failure terminal",
  async (code) => {
    vi.mocked(loadDiskObjectKey).mockRejectedValueOnce(new DiskKeyError(code));
    db.sandboxDiskOffload.findUnique.mockResolvedValue({ sandboxId: "sandbox-1" } as never);
    vi.mocked(failLiveOffload).mockResolvedValueOnce(null);
    expect(await verifyDiskOffload("offload-1", store)).toBe("skipped");
    expect(failLiveOffload).toHaveBeenCalledWith(db, "offload-1", "corrupt");
    expect(finishEndedOffload).toHaveBeenCalledWith(store, null);
  },
);
