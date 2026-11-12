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
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeImageGrantBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

/** An in-memory S3: multipart ids, the parts a test says were uploaded, and
 * a call log. Presigned URLs are loopback (the wire allows HTTP there). */
const s3 = vi.hoisted(() => ({
  uploads: 0,
  listed: new Map<string, { n: number; size: number; etag: string }[]>(),
  calls: [] as string[],
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
    listParts: async (_key: string, uploadId: string) => s3.listed.get(uploadId) ?? [],
    completeMultipart: async (_key: string, uploadId: string) => {
      s3.calls.push(`complete ${uploadId}`);
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

  it("parts past a 64-part window are granted the next window with the same key", async () => {
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
    expect(next.encryption).toEqual(w.grant.encryption);
    expect(
      await db.inspect.sandboxImageUploadPart.count({ where: { sessionId: w.session.id } }),
    ).toBe(64);
  });

  it("a resumed upload is re-granted from its lowest unrecorded part, only on the rebound epoch", async () => {
    const w = await opened(3 * 64 * MIB);
    expect((w.grant.parts as unknown[]).length).toBe(3);
    await handlers.handleDiskUploadParts(w.ctx(), {
      type: "disk.upload.parts",
      ...w.ref,
      sessionId: w.session.id,
      parts: [{ n: 1, etag: '"e1"' }],
    });
    const before = w.replies.length;
    // The relay dropped; the old epoch's resume is not answered with a grant.
    await db.inspect.sandboxHost.update({ where: { id: w.host.id }, data: { connectionEpoch: 2 } });
    await handlers.handleDiskUploadResume(w.ctx(2), w.session.transferId);
    expect(w.replies.length).toBe(before);
    // `image.job.resume` rebinds the transfer; the re-grant follows.
    await db.inspect.sandboxImageTransfer.update({
      where: { id: w.session.transferId },
      data: { sourceEpoch: 2 },
    });
    await handlers.handleDiskUploadResume(w.ctx(2), w.session.transferId);
    const regrant = w.last();
    expect(regrant.type).toBe("disk.upload.grant");
    expect((regrant.parts as { n: number }[]).map((p) => p.n)).toEqual([2, 3]);
    expect(regrant.sessionId).toBe(w.session.id);
    expect(regrant.encryption).toEqual(w.grant.encryption);
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

  it("disk.offload.failed ends only the host's own uploadable attempt", async () => {
    const w = await opened();
    const other = await user();
    const { host: otherHost } = await seedStoppedOnHost(db.inspect, { userId: other });
    await handlers.handleDiskOffloadFailed(w.ctx(1, otherHost.id, other), {
      type: "disk.offload.failed",
      ...w.ref,
      code: "io",
    });
    expect((await w.row()).state).toBe("UPLOADING");
    await handlers.handleDiskOffloadFailed(w.ctx(), {
      type: "disk.offload.failed",
      ...w.ref,
      code: "staging_full",
    });
    expect(await w.row()).toMatchObject({ state: "FAILED", failureCode: "staging_full" });
    expect(await sessions(w.offload.id)).toEqual([
      expect.objectContaining({ state: "ABORTED", wrapped: false }),
    ]);
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
      await released(theirs.ctx());
      await released(mine.ctx(1, mine.host.id, theirs.owner));
      await released(mine.ctx(), { ...ref, seq: 3 });
      await released({ ...mine.ctx(), sender: { ...mine.ctx().sender, isCurrent: () => false } });
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
      await released();
      expect(await at()).toEqual(first);
      expect(wake).toHaveBeenCalledTimes(1);
      expect(mine.replies).toEqual([]);
    } finally {
      bindImageSchedulerWake(null);
    }
  });
});
