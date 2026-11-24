import { createHash, randomBytes } from "node:crypto";
import { CreateBucketCommand } from "@aws-sdk/client-s3";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

// Real S3 (the disposable gateway started by `pnpm test:s3`); the database is
// mocked: these tests prove the store contract, not DB races.
const rows = vi.hoisted(() => new Map<string, Record<string, unknown>>());
vi.mock("@wssp/db", () => ({
  default: {
    sandboxImageArtifact: {
      findFirst: vi.fn(async ({ where }: { where: { id: string } }) => rows.get(where.id) ?? null),
      updateMany: vi.fn(
        async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
          const row = rows.get(where.id);
          if (!row) return { count: 0 };
          rows.set(where.id, { ...row, ...data });
          return { count: 1 };
        },
      ),
    },
  },
}));
vi.mock("@wssp/queue", () => ({ imageStoreMaintenanceQueue: { add: vi.fn() } }));

const endpoint = process.env.WSSP_TEST_S3_ENDPOINT ?? "";
const accessKeyId = process.env.WSSP_TEST_S3_ACCESS_KEY_ID ?? "";
const secretAccessKey = process.env.WSSP_TEST_S3_SECRET_ACCESS_KEY ?? "";
const masterKey = randomBytes(32).toString("base64");
Object.assign(process.env, {
  IMAGE_S3_ENDPOINT: endpoint,
  IMAGE_S3_BUCKET: "wssp-images-test",
  IMAGE_S3_ACCESS_KEY_ID: accessKeyId,
  IMAGE_S3_SECRET_ACCESS_KEY: secretAccessKey,
  IMAGE_S3_FORCE_PATH_STYLE: "true",
  // The gateway (like MinIO) wants a real region; R2 uses `auto`.
  IMAGE_S3_REGION: "us-east-1",
  IMAGE_STORE_ENCRYPTION: "on",
  IMAGE_STORE_ENCRYPTION_KEY: masterKey,
});

const s3 = await import("./s3");
const jobs = await import("./jobs");
const settings = s3.imageStoreSettings();
if (!settings) throw new Error("pnpm test:s3 provides the S3 gateway");
const store = new s3.ImageStore(settings);
const MIB = 1024 * 1024;

const sha = (bytes: Uint8Array) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

beforeAll(async () => {
  await s3.createImageS3Client(settings).send(new CreateBucketCommand({ Bucket: settings.bucket }));
});
afterAll(() => rows.clear());

async function put(url: string, body: Uint8Array) {
  return fetch(url, { method: "PUT", body, headers: { "content-length": String(body.length) } });
}

/** A one-part multipart upload of `body` to `key`, ready to complete. */
async function stage(key: string, body: Uint8Array) {
  const uploadId = await store.createMultipart(key);
  expect(
    (await put(await store.presignUploadPart(key, uploadId, 1, body.length), body)).status,
  ).toBe(200);
  return { uploadId, parts: await store.listParts(key, uploadId) };
}

async function stored(key: string): Promise<Uint8Array | null> {
  const response = await fetch(await store.presignGet(key));
  if (response.status === 404) return null;
  expect(response.status).toBe(200);
  return new Uint8Array(await response.arrayBuffer());
}

const freshKey = () =>
  s3.imageObjectKey(
    settings.prefix,
    "owner-c",
    sha(randomBytes(16)),
    s3.newImageSessionId(),
    false,
  );

describe("image store against a real S3 gateway", () => {
  it("presigned multipart upload (signed Content-Length, no checksum params), ListParts sizes, GET round trip", async () => {
    const image = randomBytes(5 * MIB + 123);
    const fp = sha(image);
    const key = s3.imageObjectKey(settings.prefix, "owner-a", fp, s3.newImageSessionId(), false);
    const uploadId = await store.createMultipart(key);
    const parts = [image.subarray(0, 5 * MIB), image.subarray(5 * MIB)];
    for (const [index, body] of parts.entries()) {
      const url = await store.presignUploadPart(key, uploadId, index + 1, body.length);
      expect(url).not.toMatch(/x-amz-checksum|x-amz-sdk-checksum-algorithm/i);
      expect(url).toMatch(/X-Amz-SignedHeaders=[^&]*content-length/i);
      expect((await put(url, body)).status).toBe(200);
    }
    const listed = await store.listParts(key, uploadId);
    expect(listed.map((p) => [p.n, p.size])).toEqual([
      [1, 5 * MIB],
      [2, 123],
    ]);
    await store.completeMultipart(key, uploadId, listed);
    const got = new Uint8Array(await (await fetch(await store.presignGet(key))).arrayBuffer());
    expect(sha(got)).toBe(fp);
  });

  it("refuses a part whose length differs from the signed Content-Length (M9)", async () => {
    const key = s3.imageObjectKey(
      settings.prefix,
      "owner-a",
      `sha256:${"c".repeat(64)}`,
      s3.newImageSessionId(),
      false,
    );
    const uploadId = await store.createMultipart(key);
    const url = await store.presignUploadPart(key, uploadId, 1, 10);
    const response = await put(url, randomBytes(11));
    expect(response.status).toBeGreaterThanOrEqual(400);
    await store.abortMultipart(key, uploadId);
  });

  it("verify: an encrypted object that hashes to its fingerprint becomes STORED; a tampered one CORRUPT and deleted", async () => {
    const master = s3.imageMasterKey();
    expect(master).not.toBeNull();
    for (const tamper of [false, true]) {
      const image = randomBytes(MIB + 77);
      const fp = sha(image);
      const id = `artifact-${tamper}`;
      const dataKey = s3.newDataKey();
      const wrapped = s3.wrapDataKey(master as Buffer, dataKey, id, "owner-b");
      const sealed = Buffer.concat([
        s3.encryptRecord(dataKey, 0, false, image.subarray(0, MIB)),
        s3.encryptRecord(dataKey, 1, true, image.subarray(MIB)),
      ]);
      if (tamper) sealed[10] ^= 1;
      const key = s3.imageObjectKey(settings.prefix, "owner-b", fp, s3.newImageSessionId(), true);
      const uploadId = await store.createMultipart(key);
      expect(
        (await put(await store.presignUploadPart(key, uploadId, 1, sealed.length), sealed)).status,
      ).toBe(200);
      await store.completeMultipart(key, uploadId, await store.listParts(key, uploadId));
      rows.set(id, {
        id,
        userId: "owner-b",
        fingerprint: fp,
        sizeBytes: BigInt(image.length),
        objectKey: key,
        state: "VERIFYING",
        encryption: "aes256gcm-r1",
        ...wrapped,
      });
      expect(await jobs.verifyImageArtifact(id, store)).toBe(tamper ? "corrupt" : "stored");
      expect(rows.get(id)?.state).toBe(tamper ? "CORRUPT" : "STORED");
      const after = await fetch(await store.presignGet(key));
      expect(after.status).toBe(tamper ? 404 : 200);
    }
  });

  it("verify cancelled on shutdown: the abort signal ends the S3 read mid-body; the artifact stays VERIFYING and the object intact", async () => {
    const image = randomBytes(8 * MIB);
    const key = freshKey();
    const { uploadId, parts } = await stage(key, image);
    await store.completeMultipart(key, uploadId, parts);
    // The SDK request itself is aborted: the body stream errors, not only our check.
    const raw = new AbortController();
    const body = await store.getObjectStream(key, raw.signal);
    raw.abort("worker shutdown");
    await expect(
      (async () => {
        for await (const _chunk of body);
      })(),
    ).rejects.toBeTruthy();
    const id = "artifact-cancelled";
    rows.set(id, {
      id,
      userId: "owner-c",
      fingerprint: sha(image),
      sizeBytes: BigInt(image.length),
      objectKey: key,
      state: "VERIFYING",
      encryption: null,
    });
    const shutdown = new AbortController();
    const reading = Object.assign(Object.create(store) as typeof store, {
      async getObjectStream(objectKey: string, signal?: AbortSignal) {
        const stream = await store.getObjectStream(objectKey, signal);
        return (async function* () {
          for await (const chunk of stream) {
            yield chunk;
            shutdown.abort("worker shutdown");
          }
        })();
      },
    });
    await expect(jobs.verifyImageArtifact(id, reading, shutdown.signal)).rejects.toMatchObject({
      name: "VerifyCancelledError",
    });
    expect(rows.get(id)?.state).toBe("VERIFYING");
    expect(await stored(key)).toEqual(new Uint8Array(image));
    // The next consumer's verify completes.
    expect(await jobs.verifyImageArtifact(id, store)).toBe("stored");
  });

  it("create-only: a multipart completion onto an existing object is refused, aborted, and the original is unchanged", async () => {
    const key = freshKey();
    const original = randomBytes(64 * 1024);
    const first = await stage(key, original);
    await store.completeMultipart(key, first.uploadId, first.parts);
    const second = await stage(key, randomBytes(64 * 1024));
    const refused = await store
      .completeMultipart(key, second.uploadId, second.parts)
      .catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(s3.ImageObjectExistsError);
    expect((refused as InstanceType<typeof s3.ImageObjectExistsError>).status).toBe(412);
    expect(Buffer.from((await stored(key))!).equals(original)).toBe(true);
    // The refused upload was aborted: its parts are gone.
    await expect(store.listParts(key, second.uploadId)).rejects.toMatchObject({
      name: "NoSuchUpload",
    });
    // A repeated Complete of the already-completed upload (an SDK retry after
    // a lost response) is refused the same way (412, not an idempotent 200):
    // the relay hands that object to the verify job instead of failing it.
    await expect(store.completeMultipart(key, first.uploadId, first.parts)).rejects.toMatchObject({
      name: "ImageObjectExistsError",
      status: 412,
    });
    expect(Buffer.from((await stored(key))!).equals(original)).toBe(true);
  });

  it("create-only race: two uploads of different bytes to one new key complete together; exactly one wins", async () => {
    for (let round = 0; round < 5; round++) {
      const key = freshKey();
      const bodies = [randomBytes(256 * 1024), randomBytes(256 * 1024)];
      const staged = await Promise.all(bodies.map((body) => stage(key, body)));
      expect(await stored(key)).toBeNull();
      const results = await Promise.allSettled(
        staged.map((s) => store.completeMultipart(key, s.uploadId, s.parts)),
      );
      const winners = results.flatMap((r, i) => (r.status === "fulfilled" ? [i] : []));
      expect(winners).toHaveLength(1);
      const loser = results[1 - winners[0]!] as PromiseRejectedResult;
      expect(loser.reason).toBeInstanceOf(s3.ImageObjectExistsError);
      expect(Buffer.from((await stored(key))!).equals(bodies[winners[0]!]!)).toBe(true);
      await expect(store.listParts(key, staged[1 - winners[0]!]!.uploadId)).rejects.toMatchObject({
        name: "NoSuchUpload",
      });
    }
  });

  it("lists bounded pages under the prefix and parses owner keys", async () => {
    const page = await store.listObjectsPage();
    expect(page.objects.length).toBeGreaterThan(0);
    for (const object of page.objects)
      expect(jobs.parseImageObjectKey(settings.prefix, object.key)).not.toBeNull();
  });
});
