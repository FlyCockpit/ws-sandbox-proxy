import { createHash, randomBytes } from "node:crypto";
import { CreateBucketCommand } from "@aws-sdk/client-s3";
import {
  encryptedImageLength,
  IMAGE_ENCRYPTION_RECORD_BYTES,
  IMAGE_ENCRYPTION_TAG_BYTES,
} from "@wssp/sandbox-contracts";
import { beforeAll, describe, expect, it, vi } from "vitest";

// Real S3 (the disposable gateway started by `pnpm test:s3`); the database is
// mocked: these tests prove the disk store contract (encryption at rest,
// verify, the sweeper's keep set), not DB races (store.pg.test.ts).
const db = vi.hoisted(() => ({
  verifying: null as Record<string, unknown> | null,
  keyRow: null as Record<string, unknown> | null,
  kept: new Set<string>(),
}));
vi.mock("@wssp/db", () => {
  const client: Record<string, unknown> = {
    sandboxDiskOffload: {
      findFirst: vi.fn(async () => db.verifying),
      findUnique: vi.fn(async () => db.keyRow),
    },
    appSetting: { findUnique: vi.fn(async () => null), upsert: vi.fn(async () => ({})) },
    sandboxImageArtifact: {
      findMany: vi.fn(async () => []),
      findFirst: vi.fn(async () => null),
      updateMany: vi.fn(async () => ({ count: 0 })),
    },
    sandboxImageUploadSession: {
      updateMany: vi.fn(async () => ({ count: 0 })),
      findMany: vi.fn(async () => []),
    },
    sandboxImageTransfer: { updateMany: vi.fn(async () => ({ count: 0 })) },
    sandboxImageLink: { deleteMany: vi.fn(async () => ({ count: 0 })) },
    $executeRaw: vi.fn(async () => 0),
    // keptDiskObjectKeys: the keys the test marks as owned by a live row.
    $queryRaw: vi.fn(async (_strings: TemplateStringsArray, ...values: unknown[]) => {
      const keys = values.find((value): value is string[] => Array.isArray(value)) ?? [];
      return keys.filter((key) => db.kept.has(key)).map((key) => ({ key }));
    }),
  };
  client.$transaction = vi.fn(async (work: (tx: unknown) => unknown) => work(client));
  return { default: client };
});
vi.mock("@wssp/queue", () => ({
  imageStoreMaintenanceQueue: { add: vi.fn() },
  ensureRunnableJob: vi.fn(),
}));
const outcomes = vi.hoisted(() => ({ stored: vi.fn(), failed: vi.fn() }));
vi.mock("./store", async (importOriginal) => {
  const real = await importOriginal<typeof import("./store")>();
  return {
    ...real,
    markStored: outcomes.stored,
    failLiveOffload: outcomes.failed,
  };
});

const endpoint = process.env.WSSP_TEST_S3_ENDPOINT ?? "";
Object.assign(process.env, {
  IMAGE_S3_ENDPOINT: endpoint,
  IMAGE_S3_BUCKET: "wssp-disk-offload-test",
  IMAGE_S3_ACCESS_KEY_ID: process.env.WSSP_TEST_S3_ACCESS_KEY_ID ?? "",
  IMAGE_S3_SECRET_ACCESS_KEY: process.env.WSSP_TEST_S3_SECRET_ACCESS_KEY ?? "",
  IMAGE_S3_FORCE_PATH_STYLE: "true",
  IMAGE_S3_REGION: "us-east-1",
  IMAGE_S3_PREFIX: "wssp-disk",
  DATA_ENCRYPTION_KEY: randomBytes(32).toString("hex"),
});

const s3 = await import("../image-store/s3");
const jobs = await import("../image-store/jobs");
const keys = await import("./keys");
const store = await import("./store");
const { verifyDiskOffload } = await import("./verify");
const settings = s3.imageStoreSettings();
if (!settings) throw new Error("pnpm test:s3 provides the S3 gateway");
const objectStore = new s3.ImageStore(settings);
const MIB = 1024 * 1024;
const sha = (bytes: Uint8Array) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

beforeAll(async () => {
  await s3
    .createImageS3Client(settings)
    .send(new CreateBucketCommand({ Bucket: settings.bucket }))
    .catch((error: { name?: string }) => {
      if (error?.name !== "BucketAlreadyOwnedByYou") throw error;
    });
});

/** Seal `plain` in the `aes256gcm-r1` records the daemon writes, cut in the
 * server's disk part size, and upload it through presigned multipart. */
async function upload(key: string, plain: Buffer, dek: Buffer) {
  const records = Math.max(1, Math.ceil(plain.length / IMAGE_ENCRYPTION_RECORD_BYTES));
  const sealed = Buffer.concat(
    Array.from({ length: records }, (_, i) =>
      s3.encryptRecord(
        dek,
        i,
        i === records - 1,
        plain.subarray(i * IMAGE_ENCRYPTION_RECORD_BYTES, (i + 1) * IMAGE_ENCRYPTION_RECORD_BYTES),
      ),
    ),
  );
  expect(sealed.length).toBe(encryptedImageLength(plain.length));
  // 6 records per part here (the server uses 64+), still whole sealed records.
  const partSize = 6 * (IMAGE_ENCRYPTION_RECORD_BYTES + IMAGE_ENCRYPTION_TAG_BYTES);
  const uploadId = await objectStore.createMultipart(key);
  for (let n = 1; (n - 1) * partSize < sealed.length; n++) {
    const body = sealed.subarray((n - 1) * partSize, n * partSize);
    const url = await objectStore.presignUploadPart(key, uploadId, n, body.length);
    const response = await fetch(url, {
      method: "PUT",
      body,
      headers: { "content-length": String(body.length) },
    });
    expect(response.status).toBe(200);
  }
  await objectStore.completeMultipart(key, uploadId, await objectStore.listParts(key, uploadId));
  return sealed;
}

async function read(key: string): Promise<Buffer> {
  return Buffer.from(await (await fetch(await objectStore.presignGet(key))).arrayBuffer());
}

/** An offload row wrapping `dek` under the deployment root (the only key path). */
function offloadRows(input: {
  id: string;
  sessionId: string;
  dek: Buffer;
  plain: Buffer;
  key: string;
}) {
  const wrapKeys = keys.readDiskWrapKeys();
  if (!wrapKeys) throw new Error("data key");
  const context = {
    userId: "owner-d",
    sandboxId: "sbx-d",
    offloadId: input.id,
    seq: 1,
    sessionId: input.sessionId,
  };
  const wrap = keys.wrapDiskDek(wrapKeys.current, { ...context, dek: input.dek });
  db.verifying = {
    id: input.id,
    objectKey: input.key,
    completedSessionId: input.sessionId,
    fingerprint: sha(input.plain),
    sizeBytes: BigInt(input.plain.length),
  };
  db.keyRow = {
    id: input.id,
    userId: context.userId,
    sandboxId: context.sandboxId,
    seq: 1,
    completedSessionId: input.sessionId,
    encryption: keys.DISK_ENCRYPTION_SCHEME,
    wrappedKey: new Uint8Array(wrap.wrappedKey),
    wrapSalt: new Uint8Array(wrap.wrapSalt),
    wrapNonce: new Uint8Array(wrap.wrapNonce),
    rootKid: wrap.rootKid,
  };
}

describe("disk offload objects against a real S3 gateway", () => {
  it("I13: the stored bytes are ciphertext, open only with the session key, and verify → STORED", async () => {
    // A disk-like plaintext with a recognizable marker in every record.
    const marker = Buffer.from("WSSP-PLAINTEXT-LOGIN-TOKEN");
    const plain = Buffer.concat(
      Array.from({ length: 9 }, () => Buffer.concat([marker, randomBytes(MIB - marker.length)])),
    );
    const dek = keys.generateDiskDek();
    const sessionId = store.newDiskSessionId();
    const key = store.diskStoreObjectKey(settings.prefix, {
      ownerId: "owner-d",
      sandboxId: "sbx-d",
      offloadId: "off-good",
      sessionId,
    });
    await upload(key, plain, dek);
    const stored = await read(key);
    expect(stored.length).toBe(encryptedImageLength(plain.length));
    expect(stored.equals(plain)).toBe(false);
    expect(stored.includes(marker)).toBe(false);
    // Only the grant key opens it.
    const opened: Buffer[] = [];
    for await (const chunk of s3.decryptImageStream(dek, plain.length, [new Uint8Array(stored)]))
      opened.push(chunk);
    expect(Buffer.concat(opened).equals(plain)).toBe(true);
    await expect(
      (async () => {
        for await (const _ of s3.decryptImageStream(keys.generateDiskDek(), plain.length, [
          new Uint8Array(stored),
        ]));
      })(),
    ).rejects.toThrow();
    offloadRows({ id: "off-good", sessionId, dek, plain, key });
    outcomes.stored.mockResolvedValueOnce({ kind: "stored", offloadId: "off-good" });
    expect(await verifyDiskOffload("off-good", objectStore)).toBe("stored");
    expect(outcomes.stored).toHaveBeenCalledWith("off-good", {
      completedSessionId: sessionId,
      objectKey: key,
    });
  });

  it("a tampered object is never STORED: FAILED(corrupt) and deleted", async () => {
    const plain = randomBytes(2 * MIB + 5);
    const dek = keys.generateDiskDek();
    const sessionId = store.newDiskSessionId();
    const key = store.diskStoreObjectKey(settings.prefix, {
      ownerId: "owner-d",
      sandboxId: "sbx-d",
      offloadId: "off-bad",
      sessionId,
    });
    const sealed = await upload(key, plain, dek);
    sealed[100] = (sealed[100] ?? 0) ^ 1;
    // Re-upload the tampered bytes under the same key. Objects are
    // create-only, so the original is deleted first (a Complete onto it is
    // refused).
    await objectStore.deleteObject(key);
    const uploadId = await objectStore.createMultipart(key);
    const url = await objectStore.presignUploadPart(key, uploadId, 1, sealed.length);
    await fetch(url, {
      method: "PUT",
      body: sealed,
      headers: { "content-length": String(sealed.length) },
    });
    await objectStore.completeMultipart(key, uploadId, await objectStore.listParts(key, uploadId));
    offloadRows({ id: "off-bad", sessionId, dek, plain, key });
    outcomes.failed.mockResolvedValueOnce({
      offloadId: "off-bad",
      sandboxId: "sbx-d",
      userId: "owner-d",
      seq: 1,
      sourceHostId: "h",
      objectKey: key,
      sessions: [],
    });
    expect(await verifyDiskOffload("off-bad", objectStore)).toBe("corrupt");
    expect(outcomes.failed).toHaveBeenCalledWith(expect.anything(), "off-bad", "corrupt");
    expect((await fetch(await objectStore.presignGet(key))).status).toBe(404);
  });

  it("sweeper: a disk object outside the keep set is deleted after a day; a kept one stays", async () => {
    const kept = store.diskStoreObjectKey(settings.prefix, {
      ownerId: "owner-s",
      sandboxId: "sbx-s",
      offloadId: "off-kept",
      sessionId: store.newDiskSessionId(),
    });
    const orphan = store.diskStoreObjectKey(settings.prefix, {
      ownerId: "owner-s",
      sandboxId: "sbx-s",
      offloadId: "off-gone",
      sessionId: store.newDiskSessionId(),
    });
    for (const key of [kept, orphan]) await upload(key, randomBytes(1000), keys.generateDiskDek());
    db.kept = new Set([kept]);
    // Two days on: every object is past the sweeper's one-day age.
    const later = new Date(Date.now() + 2 * 86_400_000);
    await jobs.sweepImageStore(objectStore, later, async () => {});
    expect((await fetch(await objectStore.presignGet(kept))).status).toBe(200);
    expect((await fetch(await objectStore.presignGet(orphan))).status).toBe(404);
    expect(await objectStore.objectExists(kept)).toBe(true);
    expect(await objectStore.objectExists(orphan)).toBe(false);
  });
});
