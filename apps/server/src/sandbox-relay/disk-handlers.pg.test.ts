import { randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { seedAcceptedOperation } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "disk-handlers-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: { add: vi.fn() },
  ensureRunnableJob: vi.fn(),
}));
const budgets = vi.hoisted(() => ({ grantsExhausted: false }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeImageGrantBudget: async () => {
    if (budgets.grantsExhausted) throw new Error("budget exhausted");
  },
  consumeSandboxWriteBudget: async () => {},
}));

/** An in-memory S3: multipart ids, the parts a test says were uploaded, and
 * a call log. Presigned URLs are loopback (the wire allows HTTP there). */
const s3 = vi.hoisted(() => ({
  uploads: 0,
  listed: new Map<string, { n: number; size: number; etag: string }[]>(),
  calls: [] as string[],
  /** Thrown by the next Complete (then cleared). */
  completeError: null as unknown,
  /** Runs inside the next ListParts (then cleared). */
  duringList: null as null | (() => Promise<void>),
}));
vi.mock("@wssp/api/sandbox/image-store/s3", async (importOriginal) => {
  const real = await importOriginal<typeof import("@wssp/api/sandbox/image-store/s3")>();
  const settings = {
    endpoint: "http://127.0.0.1:9",
    publicEndpoint: "http://127.0.0.1:9",
    region: "us-east-1",
    bucket: "b",
    accessKeyId: "a",
    secretAccessKey: "s",
    forcePathStyle: true,
    prefix: "wssp",
    presignTtlSeconds: 600,
  };
  const store = {
    settings,
    createMultipart: async (key: string) => {
      s3.calls.push(`create ${key}`);
      return `up-${++s3.uploads}`;
    },
    presignUploadPart: async (key: string, uploadId: string, n: number) =>
      `http://127.0.0.1:9/${key}?uploadId=${uploadId}&partNumber=${n}`,
    listParts: async (_key: string, uploadId: string) => {
      const during = s3.duringList;
      s3.duringList = null;
      await during?.();
      return s3.listed.get(uploadId) ?? [];
    },
    completeMultipart: async (_key: string, uploadId: string) => {
      s3.calls.push(`complete ${uploadId}`);
      const error = s3.completeError;
      s3.completeError = null;
      if (error) throw error;
    },
    abortMultipart: async (_key: string, uploadId: string) => {
      s3.calls.push(`abort ${uploadId}`);
    },
    deleteObject: async (key: string) => {
      s3.calls.push(`delete ${key}`);
    },
  };
  return { ...real, imageStore: () => store, imageStoreSettings: () => settings };
});

/**
 * Disk offload upload frames against real PostgreSQL: create-only begin with a fresh DEK per session, refusal
 * while a session is authorized, supersede otherwise, Complete's two-row CAS,
 * the quota and ledger, the TEMPLATE-artifact collision (R1) and the
 * `OFFLOAD_UPLOAD` / `RESTORE_FETCH` transfer authority.
 */
const db = await pgTestDatabase();
afterAll(() => db.close());
const handlers = await import("./disk-handlers");
const { transferAuthorized, transferAuthoritySelect } = await import("./image-authority");
const { offloadSandboxForTest, seedStoppedOnHost, seedStoredOffload } = await import(
  "../../../../packages/api/src/sandbox/testing/offload-fixtures"
);
const { loadDiskObjectKey, loadOpenDiskSessionKey, readDiskWrapKeys } = await import(
  "@wssp/api/sandbox/disk-offload/keys"
);

const ENV = {
  DATA_ENCRYPTION_KEY: randomBytes(32).toString("hex"),
  IMAGE_S3_BUCKET: "b",
  IMAGE_S3_ENDPOINT: "http://127.0.0.1:9",
  IMAGE_S3_ACCESS_KEY_ID: "a",
  IMAGE_S3_SECRET_ACCESS_KEY: "s",
};
const saved: Record<string, string | undefined> = {};
beforeAll(() => {
  for (const [key, value] of Object.entries(ENV)) {
    saved[key] = process.env[key];
    process.env[key] = value;
  }
});
afterAll(() => {
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
});
beforeEach(() => {
  s3.calls.length = 0;
});

const FP = `sha256:${"e".repeat(64)}`;
const MIB = 1024 * 1024;

async function user() {
  const id = randomUUID();
  await db.inspect.user.create({ data: { id, name: "U", email: `${id}@example.test` } });
  return id;
}

/** A STOPPED sandbox on an offload-capable host, with one PENDING offload. */
async function world(sizeBytes = 3 * MIB) {
  const owner = await user();
  const { host, sandbox } = await seedStoppedOnHost(db.inspect, { userId: owner });
  await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { offloadSeq: 1 } });
  const offload = await db.inspect.sandboxDiskOffload.create({
    data: {
      sandboxId: sandbox.id,
      userId: owner,
      seq: 1,
      sourceGeneration: sandbox.generation,
      sourceHostId: host.id,
      sourceHostOwnerId: owner,
      liveSandboxId: sandbox.id,
    },
  });
  const replies: Array<Record<string, unknown> & { type: string }> = [];
  const ctx = (epoch = 1, hostId = host.id, userId = owner) => ({
    sender: { userId, hostId, connectionEpoch: epoch, isCurrent: () => true },
    reply: (frame: unknown) => replies.push(frame as Record<string, unknown> & { type: string }),
  });
  const ref = { sandboxId: sandbox.id, offloadId: offload.id, seq: 1 };
  const begin = (c = ctx()) =>
    handlers.handleDiskUploadBegin(c, {
      type: "disk.upload.begin",
      ...ref,
      generation: sandbox.generation,
      fingerprint: FP,
      sizeBytes,
      format: "unified",
    });
  const last = () => replies.at(-1)!;
  const row = () => db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: offload.id } });
  return { owner, host, sandbox, offload, replies, ctx, ref, begin, last, row };
}

/** A STORED offload, its wrap under the current data key (the epoch fence). */
function storedOffload(input: { userId: string; sandboxId: string; hostId: string; seq?: number }) {
  return db.prisma.$transaction((tx) =>
    seedStoredOffload(tx, { ...input, keys: readDiskWrapKeys() ?? undefined }),
  );
}

/** The sessions of an offload (no key columns but presence flags). */
async function sessions(offloadId: string) {
  const rows = await db.inspect.sandboxImageUploadSession.findMany({
    where: { diskOffloadId: offloadId },
    orderBy: { createdAt: "asc" },
  });
  return rows.map((s) => ({
    id: s.id,
    state: s.state,
    objectKey: s.objectKey,
    uploadId: s.uploadId,
    live: s.liveDiskOffloadId,
    wrapped: s.wrappedKey !== null || s.wrapSalt !== null || s.wrappedKeyNonce !== null,
    endReason: s.endReason,
    transferId: s.transferId,
  }));
}

describe("disk.upload.begin (S1)", () => {
  it("opens one session with its own object key and DEK, delivered only in the grant", async () => {
    const w = await world();
    await w.begin();
    const grant = w.last();
    expect(grant.type).toBe("disk.upload.grant");
    expect(grant.encryption).toEqual({ scheme: "aes256gcm-r1", key: expect.any(String) });
    const [session] = await sessions(w.offload.id);
    expect(session).toMatchObject({ state: "OPEN", live: w.offload.id, wrapped: true });
    expect(session?.objectKey).toBe(
      `wssp/owners/${w.owner}/sandboxes/${w.sandbox.id}/${w.offload.id}/${session?.id}.wsspenc`,
    );
    expect(grant.sessionId).toBe(session?.id);
    // The grant's key is the session's wrapped DEK, bound to its identity.
    const dek = await loadOpenDiskSessionKey(db.prisma, session!.id);
    expect(dek.toString("base64")).toBe((grant.encryption as { key: string }).key);
    const offload = await w.row();
    expect(offload).toMatchObject({
      state: "UPLOADING",
      fingerprint: FP,
      sizeBytes: 3n * BigInt(MIB),
    });
    const transfer = await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
      where: { id: session!.transferId },
    });
    expect(transfer).toMatchObject({
      purpose: "OFFLOAD_UPLOAD",
      diskOffloadId: w.offload.id,
      sourceHostId: w.host.id,
      sourceEpoch: 1,
      state: "OPEN",
    });
    // No key in the offload row before Complete; never in the transfer.
    expect(offload.wrappedKey).toBeNull();
  });

  it("pins the instance's cloud-init id once: first seen at begin, never overwritten (§7)", async () => {
    const w = await world();
    const id = "5f1c2a9e-1b2c-4d3e-8f90-0a1b2c3d4e5f";
    const beginWith = (cloudInitInstanceId: string, c = w.ctx()) =>
      handlers.handleDiskUploadBegin(c, {
        type: "disk.upload.begin",
        ...w.ref,
        generation: w.sandbox.generation,
        fingerprint: FP,
        sizeBytes: 3 * MIB,
        format: "unified",
        cloudInitInstanceId,
      });
    await beginWith(id);
    expect(w.last().type).toBe("disk.upload.grant");
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { connectionEpoch: 2 } });
    await beginWith("another-id", w.ctx(2));
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: w.sandbox.id } });
    expect(sandbox.cloudInitInstanceId).toBe(id);
  });

  it("a second begin while the session's job is authorized is refused upload_in_progress", async () => {
    const w = await world();
    await w.begin();
    await w.begin();
    expect(w.last()).toMatchObject({ type: "disk.offload.cancel", reason: "upload_in_progress" });
    expect(await sessions(w.offload.id)).toHaveLength(1);
    expect((await w.row()).state).toBe("UPLOADING");
  });

  it("after a reconnect the old session is superseded: aborted, wrap nulled, transfer cancelled, upload aborted", async () => {
    const w = await world();
    await w.begin();
    const firstKey = (w.last().encryption as { key: string }).key;
    const [first] = await sessions(w.offload.id);
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { connectionEpoch: 2 } });
    await w.begin(w.ctx(2));
    const second = w.last();
    expect(second.type).toBe("disk.upload.grant");
    const [old, fresh] = await sessions(w.offload.id);
    expect(old).toMatchObject({
      state: "ABORTED",
      live: null,
      wrapped: false,
      endReason: "superseded",
    });
    expect(fresh).toMatchObject({ state: "OPEN", live: w.offload.id, wrapped: true });
    // Two sessions never share an object key or a key.
    expect(fresh?.objectKey).not.toBe(old?.objectKey);
    expect((second.encryption as { key: string }).key).not.toBe(firstKey);
    const oldTransfer = await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
      where: { id: old!.transferId },
    });
    expect(oldTransfer).toMatchObject({ state: "CANCELLED", endReason: "superseded" });
    expect(s3.calls).toContain(`abort ${first?.uploadId}`);
    expect(old?.uploadId).toBeNull();
  });

  it("a begin from another host, another seq or another generation is refused stale", async () => {
    const w = await world();
    const other = await user();
    const { host: otherHost } = await seedStoppedOnHost(db.inspect, { userId: other });
    await w.begin(w.ctx(1, otherHost.id, other));
    expect(w.last()).toMatchObject({ type: "disk.offload.cancel", reason: "stale" });
    await handlers.handleDiskUploadBegin(w.ctx(), {
      type: "disk.upload.begin",
      ...w.ref,
      seq: 2,
      generation: w.sandbox.generation,
      fingerprint: FP,
      sizeBytes: MIB,
      format: "unified",
    });
    expect(w.last()).toMatchObject({ reason: "stale" });
    expect(await sessions(w.offload.id)).toHaveLength(0);
    expect((await w.row()).state).toBe("PENDING");
  });

  it("a sandbox that left STOPPED at the source generation supersedes the attempt", async () => {
    const w = await world();
    await db.inspect.sandbox.update({
      where: { id: w.sandbox.id },
      data: { generation: { increment: 1 } },
    });
    await w.begin();
    expect(w.last()).toMatchObject({ reason: "superseded" });
    expect(await w.row()).toMatchObject({ state: "SUPERSEDED", liveSandboxId: null });
    expect((await w.row()).shreddedAt).not.toBeNull();
  });

  it("collision (R1): a TEMPLATE artifact of the same fingerprint is never touched", async () => {
    const w = await world();
    const artifacts = [];
    for (const state of ["STORED", "FAILED", "UPLOADING"] as const) {
      const owner = state === "STORED" ? w.owner : await user();
      artifacts.push(
        await db.inspect.sandboxImageArtifact.create({
          data: {
            userId: owner,
            fingerprint: FP,
            architecture: "x86_64",
            sizeBytes: 10n,
            storeKind: "S3",
            state,
            objectKey: `wssp/owners/${owner}/${"e".repeat(64)}/image.tar`,
            ...(state === "STORED" ? { verifiedAt: new Date() } : {}),
          },
        }),
      );
    }
    await w.begin();
    expect(w.last().type).toBe("disk.upload.grant");
    for (const artifact of artifacts)
      expect(
        await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: artifact.id } }),
      ).toEqual(artifact);
    const [session] = await sessions(w.offload.id);
    expect(session?.objectKey).not.toContain("image.tar");
  });

  it("over the stored quota (admin cap 0) → FAILED(quota_exceeded), shredded, disk stays local", async () => {
    const w = await world();
    await db.inspect.accountImagePolicy.create({
      data: { userId: w.owner, adminOffloadGiBMax: 0 },
    });
    await w.begin();
    expect(w.last()).toMatchObject({ type: "disk.offload.cancel", reason: "quota_exceeded" });
    expect(await w.row()).toMatchObject({
      state: "FAILED",
      failureCode: "quota_exceeded",
      liveSandboxId: null,
    });
    expect(await sessions(w.offload.id)).toEqual([]);
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: w.sandbox.id } }),
    ).toMatchObject({ state: "STOPPED", diskOffloadId: null });
  });

  it("over today's spend ledger (R11) → FAILED(quota_exceeded)", async () => {
    const w = await world();
    await db.inspect.sandboxImageTransfer.create({
      data: {
        userId: w.owner,
        fingerprint: FP,
        purpose: "OFFLOAD_UPLOAD",
        mode: "S3",
        state: "COMPLETE",
        sizeBytes: 500n * 1_073_741_824n,
        bytesDone: 0n,
        partSize: 1,
        partCount: 1,
        expiresAt: new Date(Date.now() + 3_600_000),
      },
    });
    await w.begin();
    expect(w.last()).toMatchObject({ reason: "quota_exceeded" });
    expect((await w.row()).state).toBe("FAILED");
  });

  it("a declared size beyond the sandbox's disk is refused (R15.6)", async () => {
    const w = await world(200 * 1024 * MIB);
    await w.begin();
    expect(w.last()).toMatchObject({ reason: "size_exceeded" });
    expect((await w.row()).failureCode).toBe("size_exceeded");
  });
});

describe("disk.upload.parts / complete (S1)", () => {
  async function opened(sizeBytes = 3 * MIB) {
    const w = await world(sizeBytes);
    await w.begin();
    const grant = w.last();
    const [session] = await sessions(w.offload.id);
    return { ...w, grant, session: session! };
  }
  const listAll = (session: { uploadId: string | null }, sizes: number[]) =>
    s3.listed.set(
      session.uploadId!,
      sizes.map((size, i) => ({ n: i + 1, size, etag: `"e${i + 1}"` })),
    );

  it("parts past a 64-part window are granted the next window, without the key", async () => {
    const w = await opened(65 * 64 * MIB);
    expect((w.grant.parts as unknown[]).length).toBe(64);
    await handlers.handleDiskUploadParts(w.ctx(), {
      type: "disk.upload.parts",
      ...w.ref,
      sessionId: w.session.id,
      parts: Array.from({ length: 64 }, (_, i) => ({ n: i + 1, etag: `"e${i + 1}"` })),
    });
    const next = w.last();
    expect(next.type).toBe("disk.upload.grant");
    expect((next.parts as { n: number }[])[0]?.n).toBe(65);
    // The key went once, in the begin's grant.
    expect(w.grant.encryption).toEqual({ scheme: "aes256gcm-r1", key: expect.any(String) });
    expect(next).not.toHaveProperty("encryption");
    expect(
      await db.inspect.sandboxImageUploadPart.count({ where: { sessionId: w.session.id } }),
    ).toBe(64);
  });

  it("Complete moves the wrap to the offload (VERIFYING) and leaves the session without one", async () => {
    const w = await opened();
    const sealed = 3 * (MIB + 16);
    listAll(w.session, [sealed]);
    const enqueue = vi.fn(async () => {});
    await handlers.handleDiskUploadComplete(
      w.ctx(),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      enqueue,
    );
    expect(enqueue).toHaveBeenCalledWith(w.offload.id);
    expect(s3.calls).toContain(`complete ${w.session.uploadId}`);
    const offload = await w.row();
    expect(offload).toMatchObject({
      state: "VERIFYING",
      completedSessionId: w.session.id,
      objectKey: w.session.objectKey,
      storedBytes: BigInt(sealed),
    });
    const [session] = await sessions(w.offload.id);
    expect(session).toMatchObject({ state: "COMPLETE", live: null, wrapped: false });
    const key = await loadDiskObjectKey(db.prisma, w.offload.id);
    expect(key.toString("base64")).toBe((w.grant.encryption as { key: string }).key);
    // No Complete is accepted at VERIFYING or later; the completed upload is never aborted.
    s3.calls.length = 0;
    await handlers.handleDiskUploadComplete(
      w.ctx(),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      enqueue,
    );
    expect(w.last()).toMatchObject({ type: "disk.offload.cancel", reason: "stale" });
    expect(s3.calls).toEqual([]);
    expect(enqueue).toHaveBeenCalledTimes(1);
  });

  it("a create-only refusal at Complete keeps VERIFYING for the verify job; any other failure fails the attempt", async () => {
    const { ImageObjectExistsError } = await import("@wssp/api/sandbox/image-store/s3");
    const refused = await opened();
    listAll(refused.session, [3 * (MIB + 16)]);
    s3.completeError = new ImageObjectExistsError(refused.session.objectKey, 412);
    const enqueue = vi.fn(async () => {});
    await handlers.handleDiskUploadComplete(
      refused.ctx(),
      { type: "disk.upload.complete", ...refused.ref, sessionId: refused.session.id },
      enqueue,
    );
    // Nothing was overwritten; the existing object is not trusted, it is verified.
    expect(enqueue).toHaveBeenCalledWith(refused.offload.id);
    expect(await refused.row()).toMatchObject({
      state: "VERIFYING",
      completedSessionId: refused.session.id,
      objectKey: refused.session.objectKey,
    });
    const outage = await opened();
    listAll(outage.session, [3 * (MIB + 16)]);
    s3.completeError = Object.assign(new Error("InternalError"), { name: "InternalError" });
    const enqueueOutage = vi.fn(async () => {});
    await handlers.handleDiskUploadComplete(
      outage.ctx(),
      { type: "disk.upload.complete", ...outage.ref, sessionId: outage.session.id },
      enqueueOutage,
    );
    expect(enqueueOutage).not.toHaveBeenCalled();
    expect(outage.last()).toMatchObject({ reason: "store_unavailable" });
    expect((await outage.row()).state).toBe("FAILED");
  });

  it("a late Complete of a superseded session is refused and its upload aborted", async () => {
    const w = await opened();
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { connectionEpoch: 2 } });
    await w.begin(w.ctx(2));
    listAll(w.session, [3 * (MIB + 16)]);
    const enqueue = vi.fn(async () => {});
    await handlers.handleDiskUploadComplete(
      w.ctx(2),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      enqueue,
    );
    expect(w.last()).toMatchObject({ reason: "stale" });
    expect(enqueue).not.toHaveBeenCalled();
    expect((await w.row()).state).toBe("UPLOADING");
  });

  it("a Complete re-sent on a newer connection claims the upload without moving its transfer; parts need a resume", async () => {
    const w = await opened();
    listAll(w.session, [3 * (MIB + 16)]);
    // The relay dropped after the last part: the transfer is still bound to epoch 1.
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { connectionEpoch: 2 } });
    await handlers.handleDiskUploadParts(w.ctx(2), {
      type: "disk.upload.parts",
      ...w.ref,
      sessionId: w.session.id,
      parts: [{ n: 1, etag: '"e1"' }],
    });
    expect(w.last()).toMatchObject({ type: "disk.offload.cancel", reason: "stale" });
    expect(
      (
        await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
          where: { id: w.session.transferId },
        })
      ).sourceEpoch,
    ).toBe(1);
    // Another host (or another owner) never rebinds or claims it.
    const other = await user();
    await handlers.handleDiskUploadComplete(
      w.ctx(2, w.host.id, other),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      async () => {},
    );
    expect((await w.row()).state).toBe("UPLOADING");
    const enqueue = vi.fn(async () => {});
    await handlers.handleDiskUploadComplete(
      w.ctx(2),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      enqueue,
    );
    expect(enqueue).toHaveBeenCalledWith(w.offload.id);
    expect(await w.row()).toMatchObject({ state: "VERIFYING", completedSessionId: w.session.id });
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
        where: { id: w.session.transferId },
      }),
    ).toMatchObject({ sourceEpoch: 1, state: "COMPLETE" });
    // A copy of it that was still queued is answered stale and changes nothing.
    await handlers.handleDiskUploadComplete(
      w.ctx(2),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      enqueue,
    );
    expect(w.last()).toMatchObject({ reason: "stale" });
    expect(enqueue).toHaveBeenCalledTimes(1);
  });

  it("parts with a wrong size fail the attempt (upload_invalid) and abort the upload", async () => {
    const w = await opened();
    listAll(w.session, [123]);
    await handlers.handleDiskUploadComplete(
      w.ctx(),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      async () => {},
    );
    expect(w.last()).toMatchObject({ reason: "upload_invalid" });
    expect(await w.row()).toMatchObject({ state: "FAILED", failureCode: "upload_invalid" });
    const [session] = await sessions(w.offload.id);
    expect(session).toMatchObject({ state: "ABORTED", wrapped: false });
    expect(s3.calls).toContain(`abort ${w.session.uploadId}`);
  });

  it("a transfer that ended while ListParts ran is not claimed", async () => {
    // Round 1 (L3 #3): the claim re-checks the transfer, not only the session.
    const w = await opened();
    listAll(w.session, [3 * (MIB + 16)]);
    const transferId = (await sessions(w.offload.id))[0]!.transferId!;
    s3.duringList = async () => {
      await db.inspect.sandboxImageTransfer.update({
        where: { id: transferId },
        data: { state: "EXPIRED", endReason: "expired" },
      });
    };
    await handlers.handleDiskUploadComplete(
      w.ctx(),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      async () => {},
    );
    expect(w.last()).toMatchObject({ reason: "stale" });
    expect((await w.row()).state).toBe("UPLOADING");
    expect(s3.calls.filter((c) => c.startsWith("complete"))).toEqual([]);
    expect((await sessions(w.offload.id))[0]).toMatchObject({ state: "OPEN" });
  });

  it("a sandbox that moved on before Complete supersedes the attempt", async () => {
    const w = await opened();
    listAll(w.session, [3 * (MIB + 16)]);
    await db.inspect.sandbox.update({ where: { id: w.sandbox.id }, data: { state: "READY" } });
    await handlers.handleDiskUploadComplete(
      w.ctx(),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      async () => {},
    );
    // The transfer is no longer authorized (sandbox not STOPPED): refused as stale.
    expect(w.last()).toMatchObject({ reason: "stale" });
    expect(s3.calls.filter((c) => c.startsWith("complete"))).toEqual([]);
  });

  it("the stall rule ends an upload that moved no bytes for 30 min and frees the export slot; heartbeats keep a live one", async () => {
    const { endStalledOffloadUploads, OFFLOAD_UPLOAD_STALL_MS } = await import(
      "@wssp/api/sandbox/disk-offload/upload-stall"
    );
    const { hostExportBusy } = await import("@wssp/api/sandbox/disk-offload/enqueue");
    const { handleImageUploadProgress } = await import("./image-handlers");
    const now = new Date();
    const old = new Date(now.getTime() - OFFLOAD_UPLOAD_STALL_MS - 60_000);
    const stalled = await opened();
    const live = await opened();
    const transferOf = async (w: typeof stalled) => (await sessions(w.offload.id))[0]!.transferId!;
    for (const w of [stalled, live])
      await db.inspect.sandboxImageTransfer.update({
        where: { id: await transferOf(w) },
        data: { lastProgressAt: old },
      });
    const heartbeat = (
      transferId: string,
      ctx: ReturnType<typeof stalled.ctx>,
      wireBytes: number,
    ) =>
      handleImageUploadProgress(
        { ...ctx, spool: {} as never, sendTo: () => true, isHostCurrent: () => true } as never,
        { type: "image.upload.progress", transferId, bytesSent: 0, wireBytes },
        now,
      );
    const liveTransfer = await transferOf(live);
    const progress = async (id: string) =>
      (await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id } })).lastProgressAt;
    // Another host's heartbeat for this transfer moves nothing.
    await heartbeat(liveTransfer, stalled.ctx(), 5 * MIB);
    expect(await progress(liveTransfer)).toEqual(old);
    // Its own host's heartbeat (more bytes on the wire) keeps it alive.
    await heartbeat(liveTransfer, live.ctx(), 5 * MIB);
    expect(await progress(liveTransfer)).toEqual(now);
    expect(
      await db.inspect.sandboxDiskOffload.count({ where: hostExportBusy(stalled.host.id, now) }),
    ).toBe(1);
    const ended = await endStalledOffloadUploads(null, now);
    expect(ended).toEqual([
      {
        sandboxId: stalled.sandbox.id,
        offloadId: stalled.offload.id,
        seq: 1,
        sourceHostId: stalled.host.id,
      },
    ]);
    expect(await stalled.row()).toMatchObject({ state: "FAILED", failureCode: "upload_stalled" });
    expect((await live.row()).state).toBe("UPLOADING");
    // The ended attempt no longer holds its host's export slot.
    expect(
      await db.inspect.sandboxDiskOffload.count({ where: hostExportBusy(stalled.host.id, now) }),
    ).toBe(0);
    // A second pass ends nothing more.
    expect(await endStalledOffloadUploads(null, now)).toEqual([]);
  });

  it("a disk heartbeat keeps its upload alive while the shared grant budget is exhausted, once per interval", async () => {
    // Rounds 1 (L2 #1), 2 (B #2) and 3: template ids on the same connection
    // never crowd out the disk upload's liveness.
    const { OFFLOAD_UPLOAD_STALL_MS } = await import("@wssp/api/sandbox/disk-offload/upload-stall");
    const { handleImageUploadProgress } = await import("./image-handlers");
    const now = new Date();
    const later = new Date(now.getTime() + 10_001);
    const old = new Date(now.getTime() - OFFLOAD_UPLOAD_STALL_MS - 60_000);
    const w = await opened();
    const transferId = (await sessions(w.offload.id))[0]!.transferId!;
    await db.inspect.sandboxImageTransfer.update({
      where: { id: transferId },
      data: { lastProgressAt: old },
    });
    const allowance = new Map<string, number>();
    const beat = (id: string, at: Date, wireBytes: number) =>
      handleImageUploadProgress(
        {
          ...w.ctx(),
          spool: {} as never,
          sendTo: () => true,
          isHostCurrent: () => true,
          diskLiveness: allowance,
        } as never,
        { type: "image.upload.progress", transferId: id, bytesSent: 0, wireBytes },
        at,
      );
    const transfer = () =>
      db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transferId } });
    budgets.grantsExhausted = true;
    try {
      await beat(transferId, now, 5 * MIB);
      expect(await transfer()).toMatchObject({ lastProgressAt: now, wireBytes: BigInt(5 * MIB) });
      // A second one within the interval is absorbed.
      await beat(transferId, new Date(now.getTime() + 1000), 6 * MIB);
      expect((await transfer()).wireBytes).toBe(BigInt(5 * MIB));
      // Four template uploads' heartbeats fill the probes of the next interval ...
      for (let i = 0; i < 4; i++) await beat(`tr-template-${i}`, later, 1);
      // ... and the proven disk upload still moves.
      await beat(transferId, later, 7 * MIB);
      expect(await transfer()).toMatchObject({ lastProgressAt: later, wireBytes: BigInt(7 * MIB) });
    } finally {
      budgets.grantsExhausted = false;
    }
  });

  it("a cleanup failure after the stall rule committed loses no ended row's cancel", async () => {
    // Round 4: cleanup is best effort; every committed end is returned.
    const { endStalledOffloadUploads, OFFLOAD_UPLOAD_STALL_MS } = await import(
      "@wssp/api/sandbox/disk-offload/upload-stall"
    );
    const now = new Date();
    const old = new Date(now.getTime() - OFFLOAD_UPLOAD_STALL_MS - 60_000);
    const stalled = [await opened(), await opened()];
    for (const w of stalled)
      await db.inspect.sandboxImageTransfer.update({
        where: { id: (await sessions(w.offload.id))[0]!.transferId! },
        data: { lastProgressAt: old },
      });
    // The multipart upload is already gone: cleanup then clears its id in
    // the database, which fails once.
    const store = {
      abortMultipart: async () => {
        throw Object.assign(new Error("gone"), { name: "NoSuchUpload" });
      },
      deleteObject: async () => {},
    } as never;
    // Its first session write outside the ending transaction is cleanup's.
    const cleanup = db.pauseAt("stall", { before: "sandboxImageUploadSession.updateMany" });
    const stall = db.run("stall", () => endStalledOffloadUploads(store, now));
    await cleanup.waitReached();
    cleanup.fail(new Error("cleanup failed"));
    const ended = await stall;
    expect(ended.map((e) => e.offloadId).sort()).toEqual(stalled.map((w) => w.offload.id).sort());
    for (const w of stalled)
      expect(await w.row()).toMatchObject({ state: "FAILED", failureCode: "upload_stalled" });
  });

  it("a heartbeat racing the stall rule waits for its locked re-check and moves nothing after it", async () => {
    // Round 1 (L2 #2): the decision and the end are one locked step; a
    // heartbeat that arrives meanwhile cannot commit fresh progress under
    // an upload the rule is about to fail.
    const { endStalledOffloadUploads, OFFLOAD_UPLOAD_STALL_MS } = await import(
      "@wssp/api/sandbox/disk-offload/upload-stall"
    );
    const { handleImageUploadProgress } = await import("./image-handlers");
    const now = new Date();
    const old = new Date(now.getTime() - OFFLOAD_UPLOAD_STALL_MS - 60_000);
    const w = await opened();
    const transferId = (await sessions(w.offload.id))[0]!.transferId!;
    await db.inspect.sandboxImageTransfer.update({
      where: { id: transferId },
      data: { lastProgressAt: old },
    });
    const rechecked = db.pauseAt("stall", { after: /FOR UPDATE OF t/ });
    const stall = db.run("stall", () => endStalledOffloadUploads(null, now));
    let beat: Promise<void> | undefined;
    try {
      await rechecked.waitReached();
      beat = db.run("heartbeat", () =>
        handleImageUploadProgress(
          {
            ...w.ctx(),
            spool: {} as never,
            sendTo: () => true,
            isHostCurrent: () => true,
          } as never,
          { type: "image.upload.progress", transferId, bytesSent: 0, wireBytes: 5 * MIB },
          now,
        ),
      );
      // The heartbeat waits on the transfer row the rule holds.
      await db.waitUntilBlocked("heartbeat", { by: "stall" });
    } finally {
      rechecked.release();
    }
    expect(await stall).toHaveLength(1);
    await beat;
    expect(await w.row()).toMatchObject({ state: "FAILED", failureCode: "upload_stalled" });
    const transfer = await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
      where: { id: transferId },
    });
    expect(transfer).toMatchObject({ state: "CANCELLED", lastProgressAt: old });
  });

  it("a disk resume racing the stall rule takes sandbox → session → transfer as it does: no deadlock", async () => {
    // Round 2 (A #2 / B #1): sandbox → offload → session → transfer.
    const { endStalledOffloadUploads, OFFLOAD_UPLOAD_STALL_MS } = await import(
      "@wssp/api/sandbox/disk-offload/upload-stall"
    );
    const now = new Date();
    const old = new Date(now.getTime() - OFFLOAD_UPLOAD_STALL_MS - 60_000);
    const w = await opened();
    await db.inspect.sandboxImageTransfer.update({
      where: { id: w.session.transferId },
      data: { lastProgressAt: old },
    });
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { connectionEpoch: 2 } });
    const lockedSession = db.pauseAt("resume", {
      after: /FROM sandbox_image_upload_session WHERE id = .* FOR UPDATE/s,
    });
    const resume = db.run("resume", () =>
      handlers.handleDiskUploadResume(w.ctx(2), {
        type: "disk.upload.resume",
        ...w.ref,
        sessionId: w.session.id,
        transferId: w.session.transferId,
      }),
    );
    let stall: Promise<unknown[]> | undefined;
    try {
      await lockedSession.waitReached();
      stall = db.run("stall", () => endStalledOffloadUploads(null, now));
      await db.waitUntilBlocked("stall", { by: "resume" });
    } finally {
      lockedSession.release();
    }
    await resume;
    // The rebind is no progress: the rule then still saw none and ended it.
    expect(await stall).toHaveLength(1);
    expect(await w.row()).toMatchObject({ state: "FAILED", failureCode: "upload_stalled" });
  });

  it("disk.offload.failed ends only the host's own uploadable attempt", async () => {
    const w = await opened();
    const other = await user();
    const { host: otherHost } = await seedStoppedOnHost(db.inspect, { userId: other });
    // Another host's report: no effect, and nothing of that host is left for
    // it (`done`: its report store stops re-sending).
    expect(
      await handlers.handleDiskOffloadFailed(w.ctx(1, otherHost.id, other), {
        type: "disk.offload.failed",
        ...w.ref,
        code: "io",
      }),
    ).toBe("done");
    expect((await w.row()).state).toBe("UPLOADING");
    // A fenced report (a connection epoch the host no longer has): `retry`.
    expect(
      await handlers.handleDiskOffloadFailed(w.ctx(7), {
        type: "disk.offload.failed",
        ...w.ref,
        code: "io",
      }),
    ).toBe("retry");
    expect((await w.row()).state).toBe("UPLOADING");
    // A sandbox the server has no row for (the host's answer to a request
    // naming one): nothing can be left to end, `done`.
    expect(
      await handlers.handleDiskOffloadFailed(w.ctx(), {
        type: "disk.offload.failed",
        ...w.ref,
        sandboxId: "sbx-never-existed",
        code: "instance_missing",
      }),
    ).toBe("done");
    expect((await w.row()).state).toBe("UPLOADING");
    expect(
      await handlers.handleDiskOffloadFailed(w.ctx(), {
        type: "disk.offload.failed",
        ...w.ref,
        code: "staging_full",
      }),
    ).toBe("done");
    expect(await w.row()).toMatchObject({ state: "FAILED", failureCode: "staging_full" });
    // A repeat (the report re-sent after a lost ack): done, nothing changes.
    expect(
      await handlers.handleDiskOffloadFailed(w.ctx(), {
        type: "disk.offload.failed",
        ...w.ref,
        code: "io",
        reportId: "0123456789abcdef0123456789abcdef",
      }),
    ).toBe("done");
    expect(await w.row()).toMatchObject({ state: "FAILED", failureCode: "staging_full" });
    expect(await sessions(w.offload.id)).toEqual([
      expect.objectContaining({ state: "ABORTED", wrapped: false }),
    ]);
  });
});

describe("disk.upload.resume (after a relay connection change)", () => {
  /** An upload of `parts` 64-MiB parts, begun on epoch 1. */
  async function opened(parts: number) {
    const w = await world(parts * 64 * MIB);
    await w.begin();
    const grant = w.last();
    const [session] = await sessions(w.offload.id);
    const part = 64 * (MIB + 16);
    const resume = (c = w.ctx(2)) =>
      handlers.handleDiskUploadResume(c, {
        type: "disk.upload.resume",
        ...w.ref,
        sessionId: session!.id,
        transferId: session!.transferId!,
      });
    const report = (numbers: number[], c = w.ctx(2)) =>
      handlers.handleDiskUploadParts(c, {
        type: "disk.upload.parts",
        ...w.ref,
        sessionId: session!.id,
        parts: numbers.map((n) => ({ n, etag: `"e${n}"` })),
      });
    const store = (numbers: number[], size = part) =>
      s3.listed.set(
        session!.uploadId!,
        numbers.map((n) => ({ n, size, etag: `"s${n}"` })),
      );
    const transfer = () =>
      db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: session!.transferId! } });
    const recorded = async () =>
      (
        await db.inspect.sandboxImageUploadPart.findMany({
          where: { sessionId: session!.id },
          orderBy: { partNumber: "asc" },
        })
      ).map((p) => p.partNumber);
    const reconnect = (epoch = 2) =>
      db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { connectionEpoch: epoch } });
    return { ...w, grant, session: session!, resume, report, store, transfer, recorded, reconnect };
  }
  const numbers = (frame: Record<string, unknown>) =>
    (frame.parts as { n: number }[]).map((p) => p.n);
  const range = (first: number, last: number) =>
    Array.from({ length: last - first + 1 }, (_, i) => first + i);

  it("a part on a connection that did not resume is refused: no row, no grant, no key", async () => {
    const w = await opened(3);
    await w.report([1], w.ctx(1));
    await w.reconnect();
    const before = await w.recorded();
    const replies = w.replies.length;
    await w.report([2]);
    expect(w.replies.slice(replies)).toEqual([
      { type: "disk.offload.cancel", ...w.ref, reason: "stale" },
    ]);
    expect(await w.recorded()).toEqual(before);
    expect((await w.transfer()).sourceEpoch).toBe(1);
  });

  it("rebinds, reconciles to the store's listing and answers the stored ranges and the window from the first missing part", async () => {
    const w = await opened(70);
    // Recorded: 1..3 and 9 (9 is not in the store: dropped). Stored: 1..5
    // (4 and 5 went up but their report was lost) and 7; 6 has a wrong size.
    await w.report([1, 2, 3, 9], w.ctx(1));
    await w.reconnect();
    s3.listed.set(w.session.uploadId!, [
      ...[1, 2, 3, 4, 5, 7].map((n) => ({ n, size: 64 * (MIB + 16), etag: `"s${n}"` })),
      { n: 6, size: 5, etag: '"short"' },
    ]);
    await w.resume();
    const resumed = w.last();
    expect(resumed).toMatchObject({
      type: "disk.upload.resumed",
      sessionId: w.session.id,
      transferId: w.session.transferId,
      stored: [
        [1, 5],
        [7, 7],
      ],
    });
    expect(resumed).not.toHaveProperty("encryption");
    expect(numbers(resumed)).toEqual([6, ...range(8, 69)]);
    expect(await w.recorded()).toEqual([1, 2, 3, 4, 5, 7]);
    expect(await w.transfer()).toMatchObject({ sourceEpoch: 2, state: "OPEN" });
    // Parts now count on this connection; the next window follows the report.
    await w.report([6, ...range(8, 69)]);
    expect(numbers(w.last())).toEqual([70]);
    expect(w.last()).not.toHaveProperty("encryption");
  });

  it("a resumed upload ends byte-exact: Complete takes the store's own parts and ETags", async () => {
    const w = await opened(3);
    await w.reconnect();
    w.store([1]);
    await w.resume();
    expect(numbers(w.last())).toEqual([2, 3]);
    await w.report([2, 3]);
    w.store([1, 2, 3]);
    const enqueue = vi.fn(async () => {});
    await handlers.handleDiskUploadComplete(
      w.ctx(2),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      enqueue,
    );
    expect(enqueue).toHaveBeenCalledWith(w.offload.id);
    expect(await w.row()).toMatchObject({
      state: "VERIFYING",
      storedBytes: BigInt(3 * 64 * (MIB + 16)),
    });
  });

  it("after a resume the old connection's late parts and resumes change nothing", async () => {
    const w = await opened(3);
    await w.reconnect();
    w.store([]);
    await w.resume();
    const replies = w.replies.length;
    await w.report([1], w.ctx(1));
    expect(await w.recorded()).toEqual([]);
    await w.resume(w.ctx(1));
    expect(w.replies.slice(replies).filter((r) => r.type !== "disk.offload.cancel")).toEqual([]);
    expect((await w.transfer()).sourceEpoch).toBe(2);
  });

  it("a resume on a connection that is no longer current gets no answer and moves nothing", async () => {
    const w = await opened(3);
    await w.reconnect(3);
    const replies = w.replies.length;
    await w.resume(w.ctx(2));
    await w.resume({ ...w.ctx(3), sender: { ...w.ctx(3).sender, isCurrent: () => false } });
    expect(w.replies.length).toBe(replies);
    expect((await w.transfer()).sourceEpoch).toBe(1);
    // A second reconnect during a resume: the newest connection resumes.
    w.store([1]);
    await w.resume(w.ctx(3));
    expect(w.last()).toMatchObject({ type: "disk.upload.resumed", stored: [[1, 1]] });
    expect((await w.transfer()).sourceEpoch).toBe(3);
  });

  it("a repeated resume on one connection is idempotent and keeps the stall clock", async () => {
    const w = await opened(3);
    await w.reconnect();
    w.store([1]);
    await w.resume();
    const first = w.last();
    const progress = (await w.transfer()).lastProgressAt;
    await w.resume();
    expect({ ...w.last(), expiresAtUnixMs: 0, parts: numbers(w.last()) }).toEqual({
      ...first,
      expiresAtUnixMs: 0,
      parts: numbers(first),
    });
    expect((await w.transfer()).lastProgressAt).toEqual(progress);
    expect(await w.recorded()).toEqual([1]);
  });

  it("a resume that finds nothing new does not move the stall clock", async () => {
    const w = await opened(3);
    const old = new Date(Date.now() - 3_600_000);
    await db.inspect.sandboxImageTransfer.update({
      where: { id: w.session.transferId },
      data: { lastProgressAt: old },
    });
    await w.reconnect();
    w.store([]);
    await w.resume();
    expect(w.last().type).toBe("disk.upload.resumed");
    expect((await w.transfer()).lastProgressAt).toEqual(old);
  });

  it("a resume from another host is refused and changes nothing of this upload", async () => {
    const w = await opened(3);
    const other = await opened(1);
    await w.reconnect();
    await handlers.handleDiskUploadResume(other.ctx(1), {
      type: "disk.upload.resume",
      ...w.ref,
      sessionId: w.session.id,
      transferId: w.session.transferId,
    });
    expect(other.last()).toMatchObject({ type: "disk.offload.cancel", reason: "resume_refused" });
    expect(other.last()).not.toHaveProperty("parts");
    expect((await w.transfer()).sourceEpoch).toBe(1);
    // Nor with the right host but another session's transfer.
    await handlers.handleDiskUploadResume(w.ctx(2), {
      type: "disk.upload.resume",
      ...w.ref,
      sessionId: w.session.id,
      transferId: other.session.transferId,
    });
    expect(w.last()).toMatchObject({ reason: "resume_refused" });
    expect((await w.transfer()).sourceEpoch).toBe(1);
  });

  it.each([
    [
      "a cancelled transfer",
      async (w: Awaited<ReturnType<typeof opened>>) => {
        await db.inspect.sandboxImageTransfer.update({
          where: { id: w.session.transferId },
          data: { state: "CANCELLED" },
        });
      },
    ],
    [
      "an expired transfer",
      async (w: Awaited<ReturnType<typeof opened>>) => {
        await db.inspect.sandboxImageTransfer.update({
          where: { id: w.session.transferId },
          data: { expiresAt: new Date(Date.now() - 1000) },
        });
      },
    ],
    [
      "a failed (stalled) offload",
      async (w: Awaited<ReturnType<typeof opened>>) => {
        const { endLiveOffload } = await import("@wssp/api/sandbox/disk-offload/store");
        await db.prisma.$transaction((tx) =>
          endLiveOffload(tx, w.offload.id, "FAILED", "upload_stalled"),
        );
      },
    ],
    [
      "a sandbox that left STOPPED",
      async (w: Awaited<ReturnType<typeof opened>>) => {
        await db.inspect.sandbox.update({
          where: { id: w.sandbox.id },
          data: { generation: { increment: 1 } },
        });
      },
    ],
  ])("%s: the resume is refused resume_refused", async (_name, end) => {
    const w = await opened(3);
    await end(w);
    await w.reconnect();
    await w.resume();
    expect(w.last()).toMatchObject({ type: "disk.offload.cancel", reason: "resume_refused" });
  });

  it("a completed session is never resumed", async () => {
    const w = await opened(1);
    w.store([1]);
    await handlers.handleDiskUploadComplete(
      w.ctx(1),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      async () => {},
    );
    expect((await w.row()).state).toBe("VERIFYING");
    await w.reconnect();
    await w.resume();
    expect(w.last()).toMatchObject({ reason: "resume_refused" });
  });

  it("a Complete whose ListParts failed leaves the transfer where it was: parts still need a resume", async () => {
    const w = await opened(3);
    await w.reconnect();
    s3.duringList = async () => {
      throw new Error("store down");
    };
    await handlers.handleDiskUploadComplete(
      w.ctx(2),
      { type: "disk.upload.complete", ...w.ref, sessionId: w.session.id },
      async () => {},
    );
    expect(w.last()).toMatchObject({ reason: "store_unavailable" });
    expect((await w.transfer()).sourceEpoch).toBe(1);
    await w.report([1]);
    expect(w.last()).toMatchObject({ reason: "stale" });
    expect(await w.recorded()).toEqual([]);
  });

  it("a store outage or a spent budget is transient: nothing moves but the rebind, and a retry answers", async () => {
    const w = await opened(3);
    await w.reconnect();
    budgets.grantsExhausted = true;
    try {
      await w.resume();
    } finally {
      budgets.grantsExhausted = false;
    }
    expect(w.last()).toMatchObject({ reason: "rate_limited" });
    expect((await w.transfer()).sourceEpoch).toBe(1);
    s3.duringList = async () => {
      throw new Error("store down");
    };
    await w.resume();
    expect(w.last()).toMatchObject({ reason: "store_unavailable" });
    w.store([1, 2]);
    await w.resume();
    expect(w.last()).toMatchObject({ type: "disk.upload.resumed", stored: [[1, 2]] });
    expect(numbers(w.last())).toEqual([3]);
  });

  it("every stored part: an empty window, ready to complete", async () => {
    const w = await opened(2);
    await w.reconnect();
    w.store([1, 2]);
    await w.resume();
    expect(w.last()).toMatchObject({ stored: [[1, 2]], parts: [] });
  });

  it("many parts reconcile set-based; past 256 ranges the rest is granted again", async () => {
    const w = await opened(520);
    await w.report(range(1, 64), w.ctx(1));
    await w.reconnect();
    const odd = range(1, 520).filter((n) => n % 2 === 1);
    w.store(odd);
    await w.resume();
    const resumed = w.last();
    const stored = resumed.stored as [number, number][];
    expect(stored).toHaveLength(256);
    expect(stored.at(-1)).toEqual([511, 511]);
    expect(numbers(resumed)).toEqual(range(2, 65).filter((n) => n % 2 === 0));
    expect(await w.recorded()).toEqual(odd.filter((n) => n <= 511));
  });

  it("expiry racing a resume: it waits for a reconciliation in flight and is seen by one that starts after it", async () => {
    const lockedTransfer =
      /FROM sandbox_image_transfer t JOIN sandbox_image_upload_session s .* FOR UPDATE OF t/s;
    const expire = (transferId: string) =>
      db.prisma.$transaction(
        (tx) =>
          tx.$executeRaw`UPDATE sandbox_image_transfer SET state = 'EXPIRED', "endReason" = 'expired'
            WHERE id = ${transferId} AND state = 'OPEN'`,
      );
    // Reconciliation first: the expiry waits for its commit, then ends the
    // transfer; the answer that went out belongs to a still-OPEN transfer.
    const first = await opened(3);
    await first.reconnect();
    first.store([1]);
    let reconciling: ReturnType<typeof db.pauseAt> | undefined;
    s3.duringList = async () => {
      reconciling = db.pauseAt("resume", { after: lockedTransfer });
    };
    const resumeFirst = db.run("resume", () => first.resume());
    await vi.waitFor(() => expect(reconciling).toBeDefined());
    await reconciling!.waitReached();
    const expiring = db.run("expire", () => expire(first.session.transferId));
    await db.waitUntilBlocked("expire", { by: "resume" });
    reconciling!.release();
    await resumeFirst;
    await expiring;
    expect(first.last()).toMatchObject({ type: "disk.upload.resumed", stored: [[1, 1]] });
    expect(await first.recorded()).toEqual([1]);
    expect((await first.transfer()).state).toBe("EXPIRED");

    // Expiry first: the resume waits for it and is refused, writing nothing.
    const second = await opened(3);
    await second.reconnect();
    second.store([1]);
    const expired = db.pauseAt("expire", {
      after: /UPDATE sandbox_image_transfer SET state = 'EXPIRED'/,
    });
    const expiringFirst = db.run("expire", () => expire(second.session.transferId));
    await expired.waitReached();
    const resumeSecond = db.run("resume", () => second.resume());
    try {
      await db.waitUntilBlocked("resume", { by: "expire" });
    } finally {
      expired.release();
    }
    await expiringFirst;
    await resumeSecond;
    expect(second.last()).toMatchObject({ type: "disk.offload.cancel", reason: "resume_refused" });
    expect(await second.recorded()).toEqual([]);
    expect(await second.transfer()).toMatchObject({ state: "EXPIRED", sourceEpoch: 1 });
  });

  it("image.job.resume never rebinds a disk upload's transfer", async () => {
    const { handleImageJobResume } = await import("./image-handlers");
    const w = await opened(3);
    await w.reconnect();
    const replies: unknown[] = [];
    await handleImageJobResume(
      {
        ...w.ctx(2),
        reply: (frame: unknown) => replies.push(frame),
        spool: {} as never,
        sendTo: () => true,
        isHostCurrent: () => true,
      } as never,
      { type: "image.job.resume", transferId: w.session.transferId, role: "SOURCE", bytesDone: 0 },
    );
    expect(replies).toEqual([
      { type: "image.job.resume.result", transferId: w.session.transferId, continue: false },
    ]);
    expect((await w.transfer()).sourceEpoch).toBe(1);
  });
});

describe("transfer authority (T8)", () => {
  const authorized = (transferId: string) =>
    db.prisma.$transaction(async (tx) => {
      const transfer = await tx.sandboxImageTransfer.findUniqueOrThrow({
        where: { id: transferId },
        select: transferAuthoritySelect,
      });
      return transferAuthorized(tx, transfer, new Date());
    });

  it("OFFLOAD_UPLOAD: source host, its current epoch, an uploadable offload, the sandbox STOPPED at the source generation", async () => {
    const w = await world();
    await w.begin();
    const [session] = await sessions(w.offload.id);
    expect(await authorized(session!.transferId)).toBe(true);
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { connectionEpoch: 2 } });
    expect(await authorized(session!.transferId)).toBe(false);
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { connectionEpoch: 1 } });
    await db.inspect.sandbox.update({
      where: { id: w.sandbox.id },
      data: { generation: { increment: 1 } },
    });
    expect(await authorized(session!.transferId)).toBe(false);
  });

  it("OFFLOAD_UPLOAD is keyed on the offload, never the fingerprint alone", async () => {
    const w = await world();
    const transfer = await db.inspect.sandboxImageTransfer.create({
      data: {
        userId: w.owner,
        fingerprint: FP,
        purpose: "OFFLOAD_UPLOAD",
        mode: "S3",
        sourceHostId: w.host.id,
        sourceHostOwnerId: w.owner,
        sourceEpoch: 1,
        sizeBytes: 1n,
        partSize: 1,
        partCount: 1,
        expiresAt: new Date(Date.now() + 3_600_000),
      },
    });
    expect(await authorized(transfer.id)).toBe(false);
  });

  // The positive grant (a placed restore dispatched to its target, the
  // stored disk's fingerprint, a restore-eligible host) is the
  // `disk-dispatch.pg.test.ts` cell; this one keeps the refusals.
  it("RESTORE_FETCH: refused unless the admitted restore of the current STORED offload is placed on its destination", async () => {
    const owner = await user();
    const { host, sandbox, revision } = await seedStoppedOnHost(db.inspect, { userId: owner });
    const stored = await db.prisma.$transaction((tx) =>
      offloadSandboxForTest(tx, {
        userId: owner,
        sandboxId: sandbox.id,
        hostId: host.id,
        keys: readDiskWrapKeys() ?? undefined,
      }),
    );
    const op = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: owner,
        sandboxId: sandbox.id,
        kind: "RECONNECT_SANDBOX",
        state: "DISPATCHED",
        generation: 2,
        idempotencyKey: randomUUID(),
        requestBodyHash: "h",
        launchMode: "NEW_ROOT",
        restoreOffloadId: stored.offloadId,
        dispatchedHostId: host.id,
        dispatchedConnectionEpoch: 1,
        dispatchAttempt: 1,
      },
    });
    const pinned = await db.inspect.sandboxPlacement.findFirstOrThrow({
      where: { sandboxId: sandbox.id },
    });
    await db.inspect.sandboxPlacement.create({
      data: {
        userId: owner,
        hostOwnerId: owner,
        sandboxId: sandbox.id,
        generation: 2,
        operationId: op.id,
        kind: "DIRECT",
        originHostId: host.id,
        templateId: revision.templateId,
        templateRevisionId: revision.id,
        artifact: revision.incusFingerprint,
        architecture: revision.architecture,
        guestUid: 1000,
        guestGid: 1000,
        guestHome: "/home/user",
        guestShell: "/bin/bash",
        configId: (
          await db.inspect.sandboxExecutionConfig.findFirstOrThrow({
            where: { sandboxId: sandbox.id },
          })
        ).id,
        acceptedAt: new Date(),
        restoreOffloadId: stored.offloadId,
        storagePoolId: pinned.storagePoolId,
        storagePoolName: pinned.storagePoolName,
        storageMarker: pinned.storageMarker,
        rootChargeGiB: pinned.rootChargeGiB,
        chargedMemoryMiB: pinned.chargedMemoryMiB,
        chargedVcpu: pinned.chargedVcpu,
      },
    });
    const fetch = (diskOffloadId: string) =>
      db.inspect.sandboxImageTransfer.create({
        data: {
          userId: owner,
          fingerprint: FP,
          diskOffloadId,
          purpose: "RESTORE_FETCH",
          mode: "S3",
          destHostId: host.id,
          destHostOwnerId: owner,
          destEpoch: 1,
          operationId: op.id,
          dispatchAttempt: 1,
          sizeBytes: 1n,
          partSize: 1,
          partCount: 1,
          expiresAt: new Date(Date.now() + 3_600_000),
        },
      });
    const good = await fetch(stored.offloadId);
    // Not placed (the sandbox is still OFFLOADED, no host path) and not the
    // stored disk's fingerprint: refused.
    expect(await authorized(good.id)).toBe(false);
    // Another attempt or epoch is refused.
    await db.inspect.sandboxImageTransfer.update({
      where: { id: good.id },
      data: { dispatchAttempt: 2 },
    });
    expect(await authorized(good.id)).toBe(false);
    await db.inspect.sandboxImageTransfer.update({
      where: { id: good.id },
      data: { dispatchAttempt: 1 },
    });
    // A mismatched offload (an older, CONSUMED copy of the same sandbox) is refused.
    const consumed = await db.inspect.sandboxDiskOffload.create({
      data: {
        sandboxId: sandbox.id,
        userId: owner,
        seq: 7,
        sourceGeneration: 1,
        sourceHostId: host.id,
        sourceHostOwnerId: owner,
        state: "CONSUMED",
        consumedAt: new Date(),
        deleteAfter: new Date(Date.now() + 3_600_000),
      },
    });
    expect(await authorized((await fetch(consumed.id)).id)).toBe(false);
    // A transfer keyed on a template fingerprint alone never reaches a disk.
    const templateOnly = await db.inspect.sandboxImageTransfer.create({
      data: {
        userId: owner,
        fingerprint: FP,
        purpose: "RESTORE_FETCH",
        mode: "S3",
        destHostId: host.id,
        destHostOwnerId: owner,
        destEpoch: 1,
        operationId: op.id,
        dispatchAttempt: 1,
        sizeBytes: 1n,
        partSize: 1,
        partCount: 1,
        expiresAt: new Date(Date.now() + 3_600_000),
      },
    });
    expect(await authorized(templateOnly.id)).toBe(false);
  });
});

/**
 * Review r2 (2+3): the daemon reports its unfinished offloads after
 * reconciliation; each is answered from this host's own row, however old
 * or however many (pages of at most 256).
 */
describe("disk.offload.inventory (reconnect re-ack)", () => {
  const inventory = (
    w: Awaited<ReturnType<typeof world>>,
    entries: Array<{ sandboxId: string; offloadId: string; seq: number }>,
    c = w.ctx(),
  ) => handlers.handleDiskOffloadInventory(c, { type: "disk.offload.inventory", entries });

  it("STORED is acked, in flight is left alone, CONSUMED while the host was away is released", async () => {
    const w = await world();
    // In flight (PENDING): nothing to say yet.
    await inventory(w, [w.ref]);
    expect(w.replies).toEqual([]);
    // That attempt failed; a later one was STORED, then restored on another
    // host while this one was offline (CONSUMED).
    await db.inspect.sandboxDiskOffload.update({
      where: { id: w.offload.id },
      data: { state: "FAILED", liveSandboxId: null, failureCode: "io" },
    });
    const consumed = await storedOffload({
      userId: w.owner,
      sandboxId: w.sandbox.id,
      hostId: w.host.id,
      seq: 2,
    });
    await db.inspect.sandboxDiskOffload.update({
      where: { id: consumed.offloadId },
      data: {
        state: "CONSUMED",
        liveSandboxId: null,
        consumedAt: new Date(),
        deleteAfter: new Date(Date.now() + 3_600_000),
      },
    });
    const stored = await storedOffload({
      userId: w.owner,
      sandboxId: w.sandbox.id,
      hostId: w.host.id,
      seq: 3,
    });
    await db.inspect.sandboxDiskOffload.update({
      where: { id: stored.offloadId },
      data: { storedAt: new Date(Date.now() - 86_400_000) },
    });
    const ref = (offloadId: string, seq: number) => ({ sandboxId: w.sandbox.id, offloadId, seq });
    await inventory(w, [
      ref(w.offload.id, 1),
      ref(consumed.offloadId, 2),
      ref(stored.offloadId, 3),
    ]);
    expect(w.replies).toEqual([
      { type: "disk.offload.cancel", ...ref(w.offload.id, 1), reason: "released" },
      { type: "disk.offload.cancel", ...ref(consumed.offloadId, 2), reason: "released" },
      {
        type: "disk.offload.stored",
        ...ref(stored.offloadId, 3),
        fingerprint: `sha256:${"d".repeat(64)}`,
        generation: 1,
      },
    ]);
    // A seq that is not the row's is not that offload: released.
    w.replies.length = 0;
    await inventory(w, [ref(stored.offloadId, 4)]);
    expect(w.replies).toEqual([
      { type: "disk.offload.cancel", ...ref(stored.offloadId, 4), reason: "released" },
    ]);
  });

  it("more than one page: every entry of every page is answered", async () => {
    const w = await world();
    await db.inspect.sandboxDiskOffload.update({
      where: { id: w.offload.id },
      data: { state: "FAILED", liveSandboxId: null, failureCode: "io" },
    });
    // 299 over attempts, then the STORED one behind them.
    await db.inspect.sandboxDiskOffload.createMany({
      data: Array.from({ length: 299 }, (_, i) => ({
        sandboxId: w.sandbox.id,
        userId: w.owner,
        seq: i + 2,
        sourceGeneration: 1,
        sourceHostId: w.host.id,
        sourceHostOwnerId: w.owner,
        state: "SUPERSEDED" as const,
      })),
    });
    const stored = await storedOffload({
      userId: w.owner,
      sandboxId: w.sandbox.id,
      hostId: w.host.id,
      seq: 301,
    });
    const rows = await db.inspect.sandboxDiskOffload.findMany({
      where: { sandboxId: w.sandbox.id },
      select: { id: true, seq: true },
      orderBy: { seq: "asc" },
    });
    const entries = rows.map((r) => ({ sandboxId: w.sandbox.id, offloadId: r.id, seq: r.seq }));
    expect(entries).toHaveLength(301);
    for (let at = 0; at < entries.length; at += 256)
      await inventory(w, entries.slice(at, at + 256));
    expect(w.replies).toHaveLength(301);
    expect(w.replies.filter((f) => f.reason === "released")).toHaveLength(300);
    expect(w.replies.at(-1)).toMatchObject({
      type: "disk.offload.stored",
      offloadId: stored.offloadId,
      seq: 301,
    });
  });

  it("another host's offload, or an unknown id, is released with the reporter's own ids only", async () => {
    const mine = await world();
    const theirs = await world();
    await db.inspect.sandboxDiskOffload.update({
      where: { id: theirs.offload.id },
      data: { state: "FAILED", liveSandboxId: null, failureCode: "io" },
    });
    const stored = await storedOffload({
      userId: theirs.owner,
      sandboxId: theirs.sandbox.id,
      hostId: theirs.host.id,
      seq: 2,
    });
    // Host A claims B's STORED offload (right ids and seq), and an unknown one.
    const claim = { sandboxId: theirs.sandbox.id, offloadId: stored.offloadId, seq: 2 };
    const unknown = { sandboxId: mine.sandbox.id, offloadId: "off-unknown", seq: 9 };
    await inventory(mine, [claim, unknown]);
    expect(mine.replies).toEqual([
      { type: "disk.offload.cancel", ...claim, reason: "released" },
      { type: "disk.offload.cancel", ...unknown, reason: "released" },
    ]);
    expect(JSON.stringify(mine.replies)).not.toContain("sha256:");
    // The same host under another owner identity is not the source either.
    mine.replies.length = 0;
    await inventory(mine, [mine.ref], mine.ctx(1, mine.host.id, theirs.owner));
    expect(mine.replies).toEqual([
      { type: "disk.offload.cancel", ...mine.ref, reason: "released" },
    ]);
    // B's own row is untouched, and B is still acked.
    expect((await theirs.row()).state).toBe("FAILED");
    await inventory(theirs, [claim]);
    expect(theirs.replies.at(-1)).toMatchObject({ type: "disk.offload.stored", ...claim });
    // A stale session says nothing.
    mine.replies.length = 0;
    await handlers.handleDiskOffloadInventory(
      {
        sender: { ...mine.ctx().sender, isCurrent: () => false },
        reply: (frame) => mine.replies.push(frame as never),
      },
      { type: "disk.offload.inventory", entries: [unknown] },
    );
    expect(mine.replies).toEqual([]);
  });
});

/**
 * Review r3 (1): the daemon's `disk.offload.released` records that the
 * source host dropped a verified offload's alias, export and staging (the
 * host's export slot is free only then), once, on that host's own row.
 */
describe("disk.offload.released (export slot release)", () => {
  it("records the release once on the source host's verified row and wakes the scheduler", async () => {
    const { bindImageSchedulerWake } = await import("@wssp/api/sandbox/image-store/config");
    const wake = vi.fn();
    bindImageSchedulerWake(wake);
    try {
      const mine = await world();
      const theirs = await world();
      await db.inspect.sandboxDiskOffload.update({
        where: { id: mine.offload.id },
        data: { state: "FAILED", liveSandboxId: null, failureCode: "io" },
      });
      const stored = await storedOffload({
        userId: mine.owner,
        sandboxId: mine.sandbox.id,
        hostId: mine.host.id,
        seq: 2,
      });
      const ref = { sandboxId: mine.sandbox.id, offloadId: stored.offloadId, seq: 2 };
      const released = (c = mine.ctx(), r = ref) =>
        handlers.handleDiskOffloadReleased(c, { type: "disk.offload.released", ...r });
      const at = async () =>
        (
          await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
            where: { id: stored.offloadId },
            select: { sourceReleasedAt: true },
          })
        ).sourceReleasedAt;
      // Another host, another owner identity, a wrong seq, a stale session:
      // nothing recorded.
      expect(await released(theirs.ctx())).toBe("done");
      expect(await released(mine.ctx(1, mine.host.id, theirs.owner))).toBe("done");
      expect(await released(mine.ctx(), { ...ref, seq: 3 })).toBe("done");
      // A superseded session's report is retried on the next one.
      expect(
        await released({ ...mine.ctx(), sender: { ...mine.ctx().sender, isCurrent: () => false } }),
      ).toBe("retry");
      expect(await at()).toBeNull();
      expect(wake).not.toHaveBeenCalled();
      // An unverified offload (this one failed at upload) is never released
      // by the frame.
      await released(mine.ctx(), mine.ref);
      expect((await mine.row()).sourceReleasedAt).toBeNull();
      // The source host's own release: recorded, scheduler woken.
      await released();
      const first = await at();
      expect(first).toBeInstanceOf(Date);
      expect(wake).toHaveBeenCalledTimes(1);
      // A repeated release (a re-offered ack) keeps the first time.
      expect(await released()).toBe("done");
      expect(await at()).toEqual(first);
      expect(wake).toHaveBeenCalledTimes(1);
      expect(mine.replies).toEqual([]);
    } finally {
      bindImageSchedulerWake(null);
    }
  });
});
