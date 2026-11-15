import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mockDeep, mockReset } from "vitest-mock-extended";

const queue = vi.hoisted(() => ({
  ensureRunnableJob: vi.fn(async () => ({})),
  imageStoreMaintenanceQueue: { add: vi.fn() },
}));
vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/queue", () => queue);

import { diskStoreObjectKey, enqueueDiskVerify } from "../disk-offload/store";
import { enqueueImageVerify, parseImageObjectKey, verifyImageArtifact } from "./jobs";
import { type ImageStore, imageObjectKey, newImageSessionId, wrapDataKey } from "./s3";

const { default: prisma } = await import("@wssp/db");
const db = vi.mocked(prisma, true);

describe("verifyImageArtifact", () => {
  const store = mockDeep<ImageStore>();
  const plain = Buffer.from("image");
  const artifact = {
    id: "artifact-1",
    userId: "owner-1",
    state: "VERIFYING",
    objectKey: "image-key",
    updatedAt: new Date("2026-11-12T00:00:00Z"),
    encryption: null,
    sizeBytes: BigInt(plain.length),
    fingerprint: `sha256:${createHash("sha256").update(plain).digest("hex")}`,
  };
  beforeEach(() => {
    mockReset(store);
    store.deleteObject.mockResolvedValue(undefined);
    db.sandboxImageArtifact.findFirst.mockReset();
    db.sandboxImageArtifact.updateMany.mockReset();
    db.sandboxImageArtifact.findFirst.mockResolvedValue(artifact as never);
    db.sandboxImageArtifact.updateMany.mockResolvedValue({ count: 1 });
  });

  it("leaves VERIFYING and the object intact when the stream fails transiently", async () => {
    const failure = Object.assign(new Error("connection reset"), { code: "ECONNRESET" });
    store.getObjectStream.mockResolvedValue(
      (async function* () {
        yield plain.subarray(0, 2);
        throw failure;
      })(),
    );
    await expect(verifyImageArtifact(artifact.id, store)).rejects.toBe(failure);
    expect(db.sandboxImageArtifact.updateMany).not.toHaveBeenCalled();
    expect(store.deleteObject).not.toHaveBeenCalled();
  });

  afterEach(() => vi.unstubAllEnvs());

  it.each(["off", "missing"])("retries an unavailable encryption key (%s)", async (mode) => {
    vi.stubEnv("IMAGE_STORE_ENCRYPTION", mode === "off" ? "off" : "on");
    vi.stubEnv("IMAGE_STORE_ENCRYPTION_KEY", undefined);
    db.sandboxImageArtifact.findFirst.mockResolvedValue({
      ...artifact,
      encryption: "aes256gcm-r1",
      ...wrapDataKey(Buffer.alloc(32, 1), Buffer.alloc(32, 2), artifact.id, artifact.userId),
    } as never);
    store.getObjectStream.mockResolvedValue(
      (async function* () {
        yield plain;
      })(),
    );
    await expect(verifyImageArtifact(artifact.id, store)).rejects.toThrow(
      "image encryption key unavailable",
    );
    expect(db.sandboxImageArtifact.updateMany).not.toHaveBeenCalled();
    expect(store.deleteObject).not.toHaveBeenCalled();
  });

  it("still condemns a malformed wrap when the master key is configured", async () => {
    vi.stubEnv("IMAGE_STORE_ENCRYPTION", "on");
    vi.stubEnv("IMAGE_STORE_ENCRYPTION_KEY", Buffer.alloc(32, 1).toString("base64"));
    db.sandboxImageArtifact.findFirst.mockResolvedValue({
      ...artifact,
      encryption: "aes256gcm-r1",
      wrappedKey: Buffer.alloc(1),
      wrappedKeyNonce: Buffer.alloc(12),
    } as never);
    store.getObjectStream.mockResolvedValue(
      (async function* () {
        yield plain;
      })(),
    );
    expect(await verifyImageArtifact(artifact.id, store)).toBe("corrupt");
    expect(store.deleteObject).toHaveBeenCalledExactlyOnceWith(artifact.objectKey);
  });

  it.each(["NoSuchBucket", "AccessDenied", "InvalidObjectState"])(
    "retries an S3 %s without condemning the image",
    async (name) => {
      const failure = Object.assign(new Error(), {
        name,
        $metadata: {
          httpStatusCode: name === "NoSuchBucket" ? 404 : name === "AccessDenied" ? 403 : 400,
        },
      });
      store.getObjectStream.mockRejectedValue(failure);
      await expect(verifyImageArtifact(artifact.id, store)).rejects.toBe(failure);
      expect(db.sandboxImageArtifact.updateMany).not.toHaveBeenCalled();
      expect(store.deleteObject).not.toHaveBeenCalled();
    },
  );

  it("marks a definite missing object corrupt before deleting it", async () => {
    store.getObjectStream.mockRejectedValue(Object.assign(new Error(), { name: "NoSuchKey" }));
    expect(await verifyImageArtifact(artifact.id, store)).toBe("corrupt");
    expect(db.sandboxImageArtifact.updateMany).toHaveBeenCalledWith({
      where: {
        id: artifact.id,
        state: "VERIFYING",
        objectKey: artifact.objectKey,
        updatedAt: artifact.updatedAt,
      },
      data: { state: "CORRUPT", corruptReports: { increment: 1 } },
    });
    expect(store.deleteObject).toHaveBeenCalledExactlyOnceWith(artifact.objectKey);
  });

  it.each(["valid", "hash mismatch", "size mismatch"])(
    "checks completed bytes (%s)",
    async (kind) => {
      store.getObjectStream.mockResolvedValue(
        (async function* () {
          yield kind === "valid"
            ? plain
            : Buffer.from(kind === "hash mismatch" ? "other" : "shorter");
        })(),
      );
      expect(await verifyImageArtifact(artifact.id, store)).toBe(
        kind === "valid" ? "stored" : "corrupt",
      );
      expect(db.sandboxImageArtifact.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ state: kind === "valid" ? "STORED" : "CORRUPT" }),
        }),
      );
      expect(store.deleteObject).toHaveBeenCalledTimes(kind === "valid" ? 0 : 1);
    },
  );

  it.each([true, false])("skips a superseded verification (valid bytes: %s)", async (valid) => {
    store.getObjectStream.mockResolvedValue(
      (async function* () {
        yield valid ? plain : Buffer.from("bad");
      })(),
    );
    db.sandboxImageArtifact.updateMany.mockResolvedValue({ count: 0 });
    expect(await verifyImageArtifact(artifact.id, store)).toBe("skipped");
    expect(db.sandboxImageArtifact.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: artifact.id,
          state: "VERIFYING",
          objectKey: artifact.objectKey,
          updatedAt: artifact.updatedAt,
        },
      }),
    );
    expect(store.deleteObject).not.toHaveBeenCalled();
  });
});

describe("enqueueImageVerify", () => {
  // A retained verify job from an earlier upload of the same artifact would
  // otherwise deduplicate Queue.add and leave the re-upload VERIFYING.
  it("ensures a runnable deterministic job with a fresh attempt budget", async () => {
    await enqueueImageVerify("artifact-1");
    expect(queue.ensureRunnableJob).toHaveBeenCalledWith(
      queue.imageStoreMaintenanceQueue,
      "verify",
      { kind: "verify", artifactId: "artifact-1" },
      "verify-artifact-1",
      { resetAttemptsMade: true },
    );
    expect(queue.imageStoreMaintenanceQueue.add).not.toHaveBeenCalled();
  });
});

describe("object layouts (offload plan §6 sweeper)", () => {
  it("parses template images and disk session objects; anything else is unknown", () => {
    const fp = "a".repeat(64);
    const image = imageObjectKey("wssp", "o1", `sha256:${fp}`, "ises_1", true);
    expect(image).toBe(`wssp/owners/o1/${fp}/ises_1/image.tar.wsspenc`);
    expect(parseImageObjectKey("wssp", image)).toEqual({
      kind: "image",
      ownerId: "o1",
      fingerprint: `sha256:${fp}`,
      sessionId: "ises_1",
    });
    // The per-fingerprint layout without a session is not a template image.
    expect(parseImageObjectKey("wssp", `wssp/owners/o1/${fp}/image.tar`)).toBeNull();
    expect(() => imageObjectKey("wssp", "o1", `sha256:${fp}`, "a/b", false)).toThrow();
    expect(newImageSessionId()).toMatch(/^ises_[0-9a-f]{32}$/);
    expect(newImageSessionId()).not.toBe(newImageSessionId());
    const key = diskStoreObjectKey("wssp", {
      ownerId: "o1",
      sandboxId: "s1",
      offloadId: "f1",
      sessionId: "dses_1",
    });
    expect(key).toBe("wssp/owners/o1/sandboxes/s1/f1/dses_1.wsspenc");
    expect(parseImageObjectKey("wssp", key)).toEqual({
      kind: "disk",
      ownerId: "o1",
      sandboxId: "s1",
      offloadId: "f1",
      sessionId: "dses_1",
    });
    expect(parseImageObjectKey("wssp", "wssp/owners/o1/sandboxes/s1/f1/dses_1")).toBeNull();
    expect(parseImageObjectKey("other", key)).toBeNull();
    expect(() =>
      diskStoreObjectKey("wssp", {
        ownerId: "o/1",
        sandboxId: "s",
        offloadId: "f",
        sessionId: "x",
      }),
    ).toThrow();
  });

  it("the disk verify job is deterministic per offload", async () => {
    await enqueueDiskVerify("off-1");
    expect(queue.ensureRunnableJob).toHaveBeenCalledWith(
      queue.imageStoreMaintenanceQueue,
      "disk_verify",
      { kind: "disk_verify", offloadId: "off-1" },
      "disk-verify-off-1",
      { resetAttemptsMade: true },
    );
  });
});
