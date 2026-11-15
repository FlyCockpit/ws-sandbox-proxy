import {
  seedAcceptedOperation,
  seedLaunchHost,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
  consumeImageGrantBudget: async () => {},
}));

import { randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { encryptedImageLength } from "@wssp/sandbox-contracts";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "image-authority-fixture",
    SANDBOX_MAX_TIMEOUT_MS: 86_400_000,
    IMAGE_RELAY_MAX_ACTIVE: 1000,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: { add: vi.fn() },
}));
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockResolvedValue("sent"),
    captureHostDispatchCredential: vi.fn(),
  },
}));

// Capture upload-begin tests switch the image store to a fake S3 store; every
// other test sees the real (unconfigured) modules.
// Upload-session tests (round-5 P2-2) also queue createMultipart results
// (a promise lets a test hold one begin's S3 call open), turn encryption on
// and read the S3 call log.
const fakeS3 = vi.hoisted(() => ({
  on: false,
  master: null as Buffer | null,
  created: [] as Array<string | Promise<string>>,
  calls: [] as string[],
  listed: [] as Array<{ n: number; size: number; etag: string }>,
  /** Thrown by the next Complete (then cleared). */
  completeError: null as unknown,
}));
vi.mock("@wssp/api/sandbox/image-store/s3", async (importOriginal) => {
  const real = await importOriginal<typeof import("@wssp/api/sandbox/image-store/s3")>();
  const store = {
    settings: { prefix: "test", presignTtlSeconds: 600 },
    createMultipart: async () => {
      fakeS3.calls.push("create");
      return (await fakeS3.created.shift()) ?? "upload-1";
    },
    presignUploadPart: async (_key: string, upload: string, n: number) =>
      `https://s3.example.test/part?upload=${upload}&n=${n}`,
    listParts: async (_key: string, upload: string) => {
      fakeS3.calls.push(`list:${upload}`);
      return fakeS3.listed;
    },
    completeMultipart: async (_key: string, upload: string) => {
      fakeS3.calls.push(`complete:${upload}`);
      const error = fakeS3.completeError;
      fakeS3.completeError = null;
      if (error) throw error;
    },
    abortMultipart: async (_key: string, upload: string) => {
      fakeS3.calls.push(`abort:${upload}`);
    },
  };
  return {
    ...real,
    imageStore: () => (fakeS3.on ? (store as never) : real.imageStore()),
    imageMasterKey: () => (fakeS3.on ? fakeS3.master : real.imageMasterKey()),
  };
});
vi.mock("@wssp/api/sandbox/image-store/config", async (importOriginal) => {
  const real = await importOriginal<typeof import("@wssp/api/sandbox/image-store/config")>();
  return {
    ...real,
    imageDistributionMode: () => (fakeS3.on ? "s3" : real.imageDistributionMode()),
  };
});

const db = await pgTestDatabase();
afterAll(() => db.close());
const { createSandbox } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
const { createSdkKey, revokeSdkKey } = await import(
  "../../../../packages/api/src/sandbox/services/sdk-keys"
);
const { SERVICE_SCOPES } = await import("@wssp/api/lib/service-scopes");
const {
  handleImageCached,
  handleImageFailure,
  handleImageFetchRequest,
  handleImageJobResume,
  handleImageLinksRequest,
  handleImageUploadBegin,
  handleImageUploadComplete,
  handleImageUploadParts,
} = await import("./image-handlers");
const { unwrapDataKey } = await import("@wssp/api/sandbox/image-store/s3");

const FEATURES = {
  egressPolicy: true,
  terminal: true,
  image: {
    fetch: true,
    serve: true,
    publish: true,
    capture: true,
    acceptForeign: false,
    leaseFromReady: false,
    captureStorageMarkers: [],
  },
};
const fpOf = () => `sha256:${(randomUUID() + randomUUID()).replaceAll("-", "").slice(0, 64)}`;

async function launchHost(userId: string, slug: string) {
  return seedLaunchHost(db.inspect, {
    data: {
      userId,
      slug,
      label: slug,
      status: "CONNECTED",
      connectionEpoch: 1,
      egressEnforcement: true,
      daemonFeatures: FEATURES,
      imageCacheEpoch: 1,
      imageCacheCapBytes: 1n << 34n,
      imageCacheUsedBytes: 0n,
      imageCacheForeignBytes: 0n,
    },
  });
}

/** An owner's source host holding the image and a destination host that must
 * fetch it; a create placed on the destination, dispatched on epoch 1. */
async function fixture() {
  const ownerId = `img-${randomUUID()}`;
  await db.inspect.user.create({
    data: {
      id: ownerId,
      name: "Owner",
      email: `${ownerId}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const source = await launchHost(ownerId, "src");
  const dest = await launchHost(ownerId, "dst");
  const fingerprint = fpOf();
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: source.id,
      slug: "base",
      label: "Base",
      incusFingerprint: fingerprint,
    },
  });
  await db.inspect.sandboxTemplateAvailability.updateMany({
    where: { revisionId: revision.id, hostId: source.id },
    data: { sizeBytes: 4096n, imageFormat: "unified" },
  });
  const owner = { kind: "session" as const, ownerId };
  const sandbox = await createSandbox(owner, {
    template: `revision/${revision.id}`,
    sandboxHostId: dest.id,
    idempotencyKey: randomUUID(),
  });
  const op = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
  });
  await db.inspect.sandboxOperation.update({
    where: { id: op.id },
    data: {
      state: "RUNNING",
      dispatchedHostId: dest.id,
      dispatchedConnectionEpoch: 1,
      dispatchAttempt: 1,
    },
  });
  return { ownerId, owner, source, dest, revision, fingerprint, sandbox, op };
}
type F = Awaited<ReturnType<typeof fixture>>;

function frameCtx(f: F, epoch = 1) {
  const replies: Array<Record<string, unknown>> = [];
  return {
    replies,
    ctx: {
      sender: {
        userId: f.ownerId,
        hostId: f.dest.id,
        connectionEpoch: epoch,
        isCurrent: () => true,
      },
      reply: (frame: unknown) => replies.push(frame as Record<string, unknown>),
      sendTo: () => true,
      isHostCurrent: () => true,
      spool: { dropTransfer: async () => {} } as never,
    },
  };
}
const fetchFrame = (f: F) => ({
  type: "image.fetch.request" as const,
  requestId: randomUUID(),
  operationId: f.op.id,
  sandboxId: f.sandbox.id,
  generation: f.op.generation,
  attempt: 1,
  fingerprint: f.fingerprint,
  resumeOffset: 0,
});
async function grant(f: F) {
  const { ctx, replies } = frameCtx(f);
  await handleImageFetchRequest(ctx, fetchFrame(f));
  return replies.at(-1);
}

describe("image grant workload fence (security review P1-1)", () => {
  it("grants a relay fetch for the live workload; a repeat while it is open mints nothing (P2-8)", async () => {
    const f = await fixture();
    expect(await grant(f)).toMatchObject({ type: "image.fetch.grant", mode: "RELAY" });
    expect(await grant(f)).toMatchObject({ type: "image.fetch.refused", code: "in_progress" });
    expect(await db.inspect.sandboxImageTransfer.count({ where: { operationId: f.op.id } })).toBe(
      1,
    );
  });

  it("refuses the initial fetch once the creator is banned or the authorizing key is revoked", async () => {
    const banned = await fixture();
    await db.inspect.user.update({ where: { id: banned.ownerId }, data: { banned: true } });
    expect(await grant(banned)).toMatchObject({
      type: "image.fetch.refused",
      code: "stale_operation",
    });

    const keyed = await fixture();
    const key = await createSdkKey(keyed.owner, {
      name: "k",
      scopes: [...SERVICE_SCOPES],
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
    });
    await db.inspect.sandboxOperation.update({
      where: { id: keyed.op.id },
      data: { authorizingKeyId: key.key.id },
    });
    // Still granted while the key is live.
    expect(await grant(keyed)).toMatchObject({ type: "image.fetch.grant" });
    await db.inspect.sandboxImageTransfer.updateMany({
      where: { operationId: keyed.op.id },
      data: { state: "FAILED" },
    });
    await revokeSdkKey(keyed.owner, { id: key.key.id });
    expect(await grant(keyed)).toMatchObject({
      type: "image.fetch.refused",
      code: "stale_operation",
    });
  });

  it("link renewal stops when the operation ends; resume rebinds only after adoption on the new epoch", async () => {
    const f = await fixture();
    expect(await grant(f)).toMatchObject({ mode: "RELAY" });
    const transfer = await db.inspect.sandboxImageTransfer.findFirstOrThrow({
      where: { operationId: f.op.id },
    });
    const links = frameCtx(f);
    await handleImageLinksRequest(links.ctx, {
      type: "image.links.request",
      transferId: transfer.id,
      role: "DEST",
      parts: [1],
    });
    expect(links.replies.at(-1)).toMatchObject({ type: "image.links.grant" });

    // Reconnect on epoch 2: no resume before the create is adopted there.
    await db.inspect.sandboxHost.update({
      where: { id: f.dest.id },
      data: { connectionEpoch: 2, imageCacheEpoch: 2 },
    });
    const resumed = frameCtx(f, 2);
    await handleImageJobResume(resumed.ctx, {
      type: "image.job.resume",
      transferId: transfer.id,
      role: "DEST",
      bytesDone: 0,
    });
    expect(resumed.replies.at(-1)).toMatchObject({ continue: false });
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { dispatchedConnectionEpoch: 2 },
    });
    await handleImageJobResume(resumed.ctx, {
      type: "image.job.resume",
      transferId: transfer.id,
      role: "DEST",
      bytesDone: 0,
    });
    expect(resumed.replies.at(-1)).toMatchObject({ continue: true });

    // The create is cancelled: the next renewal mints nothing.
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { state: "CANCELLED" },
    });
    const after = frameCtx(f, 2);
    await handleImageLinksRequest(after.ctx, {
      type: "image.links.request",
      transferId: transfer.id,
      role: "DEST",
      parts: [1],
    });
    expect(after.replies.at(-1)).toMatchObject({
      type: "image.job.cancel",
      reason: "stale_transfer",
    });
  });

  it("round-2 P2-3: a grant, renewal or resume binds the exact dispatch attempt", async () => {
    const f = await fixture();
    const request = (attempt: number) => {
      const { ctx, replies } = frameCtx(f);
      return handleImageFetchRequest(ctx, { ...fetchFrame(f), attempt }).then(() => replies.at(-1));
    };
    // A request naming another attempt than the operation's is stale.
    expect(await request(2)).toMatchObject({
      type: "image.fetch.refused",
      code: "stale_operation",
    });
    expect(await request(1)).toMatchObject({ type: "image.fetch.grant" });
    const first = await db.inspect.sandboxImageTransfer.findFirstOrThrow({
      where: { operationId: f.op.id },
    });
    expect(first.dispatchAttempt).toBe(1);
    // The operation is redispatched as attempt 2.
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { dispatchAttempt: 2 },
    });
    // The old attempt gets nothing: no new grant, no renewal of its transfer.
    expect(await request(1)).toMatchObject({
      type: "image.fetch.refused",
      code: "stale_operation",
    });
    const links = frameCtx(f);
    await handleImageLinksRequest(links.ctx, {
      type: "image.links.request",
      transferId: first.id,
      role: "DEST",
      parts: [1],
    });
    expect(links.replies.at(-1)).toMatchObject({
      type: "image.job.cancel",
      reason: "stale_transfer",
    });
    const resumed = frameCtx(f);
    await handleImageJobResume(resumed.ctx, {
      type: "image.job.resume",
      transferId: first.id,
      role: "DEST",
      bytesDone: 0,
    });
    expect(resumed.replies.at(-1)).toMatchObject({ continue: false });
    // The new attempt supersedes the old grant instead of being blocked by it.
    expect(await request(2)).toMatchObject({ type: "image.fetch.grant" });
    const rows = await db.inspect.sandboxImageTransfer.findMany({
      where: { operationId: f.op.id },
      orderBy: { createdAt: "asc" },
    });
    expect(rows.map((r) => [r.state, r.dispatchAttempt])).toEqual([
      ["CANCELLED", 1],
      ["OPEN", 2],
    ]);
  });

  it("round-2 P2-9: after image.fetch.failed ends the grant, the same attempt's retry is granted (and not counted twice)", async () => {
    const f = await fixture();
    expect(await grant(f)).toMatchObject({ type: "image.fetch.grant" });
    const first = await db.inspect.sandboxImageTransfer.findFirstOrThrow({
      where: { operationId: f.op.id },
    });
    // Without the failure frame the duplicate is still refused (P2-8).
    expect(await grant(f)).toMatchObject({ type: "image.fetch.refused", code: "in_progress" });
    const failed = frameCtx(f);
    await handleImageFailure(failed.ctx, {
      type: "image.fetch.failed",
      transferId: first.id,
      fingerprint: f.fingerprint,
      code: "io",
    });
    expect(await grant(f)).toMatchObject({ type: "image.fetch.grant" });
    const rows = await db.inspect.sandboxImageTransfer.findMany({
      where: { operationId: f.op.id },
      orderBy: { createdAt: "asc" },
    });
    expect(rows.map((r) => [r.state, r.countedDownload])).toEqual([
      ["FAILED", true],
      ["OPEN", false],
    ]);
  });

  it("round-2 P2-9: a grant left open on a previous connection never blocks the adopted create's retry", async () => {
    const f = await fixture();
    expect(await grant(f)).toMatchObject({ type: "image.fetch.grant" });
    await db.inspect.sandboxHost.update({
      where: { id: f.dest.id },
      data: { connectionEpoch: 2, imageCacheEpoch: 2 },
    });
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { dispatchedConnectionEpoch: 2 },
    });
    const { ctx, replies } = frameCtx(f, 2);
    await handleImageFetchRequest(ctx, fetchFrame(f));
    expect(replies.at(-1)).toMatchObject({ type: "image.fetch.grant" });
    const rows = await db.inspect.sandboxImageTransfer.findMany({
      where: { operationId: f.op.id },
      orderBy: { createdAt: "asc" },
    });
    expect(rows.map((r) => [r.state, r.destEpoch])).toEqual([
      ["CANCELLED", 1],
      ["OPEN", 2],
    ]);
  });

  it("P2-6: two hosts racing for the last download allowance get exactly one grant", async () => {
    const a = await fixture();
    await db.inspect.accountImagePolicy.create({
      data: { userId: a.ownerId, adminDownloadsPerHourMax: 1 },
    });
    // A second create of the same owner on a third host, same image.
    const third = await launchHost(a.ownerId, "third");
    const sandbox = await createSandbox(a.owner, {
      template: `revision/${a.revision.id}`,
      sandboxHostId: third.id,
      idempotencyKey: randomUUID(),
    });
    const op = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
    });
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: {
        state: "RUNNING",
        dispatchedHostId: third.id,
        dispatchedConnectionEpoch: 1,
        dispatchAttempt: 1,
      },
    });
    const b = { ...a, dest: third, sandbox, op };
    const [ra, rb] = await Promise.all([grant(a), grant(b)]);
    const kinds = [ra?.type, rb?.type].sort();
    expect(kinds).toEqual(["image.fetch.grant", "image.fetch.refused"]);
    expect([ra, rb].find((r) => r?.type === "image.fetch.refused")).toMatchObject({
      code: "download_quota",
    });
  });
});

describe("cache evidence binding (security review P1-2)", () => {
  const cached = (f: F, fingerprint: string, epoch = 1) => {
    const { ctx } = frameCtx(f, epoch);
    return handleImageCached(ctx, {
      type: "image.cached",
      fingerprint,
      imageOwnerId: f.ownerId,
      operationId: f.op.id,
      compressedBytes: 4096,
      origin: "fetched",
      totals: { usedBytes: 4096, foreignBytes: 0 },
    });
  };
  const evidence = (f: F, revisionId: string) =>
    db.inspect.sandboxTemplateAvailability.count({
      where: { hostId: f.dest.id, revisionId, status: "AVAILABLE" },
    });

  it("binds image.cached to the operation's own granted fetch: no grant, another fingerprint or a stale epoch prove nothing", async () => {
    const f = await fixture();
    // Another revision of the same owner, with a different image.
    const otherFp = fpOf();
    const other = await seedTemplateRevision(db.inspect, {
      data: { userId: f.ownerId, slug: "other", label: "Other", incusFingerprint: otherFp },
    });
    // No fetch was granted yet.
    await cached(f, f.fingerprint);
    expect(await evidence(f, f.revision.id)).toBe(0);
    expect(await grant(f)).toMatchObject({ type: "image.fetch.grant" });
    // The same operation cannot vouch for another image of the owner.
    await cached(f, otherFp);
    expect(await evidence(f, other.id)).toBe(0);
    // A report from a later connection is stale for this dispatch.
    await cached(f, f.fingerprint, 2);
    expect(await evidence(f, f.revision.id)).toBe(0);
    await cached(f, f.fingerprint);
    expect(await evidence(f, f.revision.id)).toBe(1);
  });

  it("a failed or cancelled create proves nothing", async () => {
    const f = await fixture();
    expect(await grant(f)).toMatchObject({ type: "image.fetch.grant" });
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { state: "FAILED" },
    });
    await cached(f, f.fingerprint);
    expect(await evidence(f, f.revision.id)).toBe(0);
  });
});

/** A capture of the fixture's sandbox, dispatched to `dest` on epoch 1. */
async function capture(f: F, attempt: number) {
  const op = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.ownerId,
      sandboxId: f.sandbox.id,
      kind: "CAPTURE_TEMPLATE",
      state: "RUNNING",
      generation: f.op.generation,
      idempotencyKey: randomUUID(),
      requestBodyHash: "h",
      dispatchedHostId: f.dest.id,
      dispatchedConnectionEpoch: 1,
      dispatchAttempt: attempt,
    },
  });
  await db.inspect.sandboxTemplateCapture.create({
    data: {
      operationId: op.id,
      userId: f.ownerId,
      sandboxId: f.sandbox.id,
      templateId: f.revision.templateId,
      tag: "latest",
      hostId: f.dest.id,
      hostOwnerId: f.ownerId,
      state: "CAPTURED",
      architecture: "x86_64",
    },
  });
  return op;
}
const begin = (
  operationId: string,
  attempt: number,
  requestId = randomUUID(),
  fingerprint = fpOf(),
) => ({
  type: "image.upload.begin" as const,
  operationId,
  requestId,
  attempt,
  fingerprint,
  sizeBytes: 4096,
  format: "unified" as const,
});

describe("capture upload-begin binds its originating attempt (round-3 P2-2)", () => {
  afterEach(() => {
    fakeS3.on = false;
  });

  it("a begin prepared under attempt 1 gets nothing once the operation moved to attempt 2", async () => {
    const f = await fixture();
    const op = await capture(f, 1);
    fakeS3.on = true;
    // The upload was prepared under attempt 1; the operation is redispatched first.
    const stale = begin(op.id, 1);
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: { dispatchAttempt: 2 },
    });
    const old = frameCtx(f);
    await handleImageUploadBegin(old.ctx, stale);
    expect(old.replies).toEqual([
      {
        type: "image.job.cancel",
        transferId: "none",
        reason: "stale_capture",
        requestId: stale.requestId,
      },
    ]);
    expect(await db.inspect.sandboxImageTransfer.count({ where: { operationId: op.id } })).toBe(0);
    // The current attempt is granted, answered by its request id and bound to attempt 2.
    const fresh = begin(op.id, 2);
    const current = frameCtx(f);
    await handleImageUploadBegin(current.ctx, fresh);
    expect(current.replies.at(-1)).toMatchObject({
      type: "image.upload.grant",
      requestId: fresh.requestId,
    });
    const transfer = await db.inspect.sandboxImageTransfer.findFirstOrThrow({
      where: { operationId: op.id },
    });
    expect([transfer.purpose, transfer.dispatchAttempt]).toEqual(["CAPTURE_UPLOAD", 2]);
    expect(current.replies.at(-1)).toMatchObject({ transferId: transfer.id });
  });
});

describe("each upload owns an immutable session (round-5 P2-2)", () => {
  const SIZE = 4096;
  const STORED = encryptedImageLength(SIZE);
  afterEach(() => {
    Object.assign(fakeS3, {
      on: false,
      master: null,
      created: [],
      calls: [],
      listed: [],
      completeError: null,
    });
  });
  function encrypted() {
    Object.assign(fakeS3, {
      on: true,
      master: randomBytes(32),
      created: [],
      calls: [],
      listed: [{ n: 1, size: STORED, etag: '"e1"' }],
    });
  }
  type Grant = { transferId: string; encryption?: { key: string } };
  /** Report the single part and complete, as the daemon does after a grant. */
  async function finish(f: F, grant: Grant) {
    const { ctx, replies } = frameCtx(f);
    await handleImageUploadParts(ctx, {
      type: "image.upload.parts",
      transferId: grant.transferId,
      parts: [{ n: 1, etag: '"e1"' }],
    });
    const verified: string[] = [];
    await handleImageUploadComplete(
      ctx,
      { type: "image.upload.complete", transferId: grant.transferId },
      async (id) => {
        verified.push(id);
      },
    );
    return { replies, verified };
  }
  /** The data key the artifact's stored object is encrypted with. */
  async function artifactKey(ownerId: string, fingerprint: string) {
    const a = await db.inspect.sandboxImageArtifact.findUniqueOrThrow({
      where: { userId_fingerprint: { userId: ownerId, fingerprint } },
    });
    expect(a.state).toBe("VERIFYING");
    return unwrapDataKey(
      fakeS3.master!,
      { wrappedKey: a.wrappedKey!, wrappedKeyNonce: a.wrappedKeyNonce! },
      a.id,
      a.userId,
    ).toString("base64");
  }

  it("a delayed begin from an older attempt cannot overwrite the newer session; its multipart is aborted", async () => {
    const f = await fixture();
    const op = await capture(f, 1);
    encrypted();
    const fingerprint = fpOf();
    // Attempt 1's begin passes its authority transaction, then its
    // CreateMultipartUpload stalls.
    let release!: (id: string) => void;
    fakeS3.created.push(
      new Promise<string>((resolve) => {
        release = resolve;
      }),
      "upload-new",
    );
    const old = frameCtx(f);
    const oldBegin = handleImageUploadBegin(old.ctx, begin(op.id, 1, randomUUID(), fingerprint));
    while (!fakeS3.calls.includes("create")) await new Promise((r) => setTimeout(r, 5));
    // The operation is redispatched and attempt 2 begins and is granted first.
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: { dispatchAttempt: 2 },
    });
    const fresh = begin(op.id, 2, randomUUID(), fingerprint);
    const current = frameCtx(f);
    await handleImageUploadBegin(current.ctx, fresh);
    const grant = current.replies.at(-1) as Grant & { type: string; requestId: string };
    expect(grant).toMatchObject({ type: "image.upload.grant", requestId: fresh.requestId });
    expect(JSON.stringify(grant)).toContain("upload=upload-new");
    // Attempt 1's S3 call finally returns: it binds nothing and is aborted.
    release("upload-old");
    await oldBegin;
    expect(old.replies.at(-1)).toMatchObject({ type: "image.job.cancel" });
    expect(old.replies.some((r) => r.type === "image.upload.grant")).toBe(false);
    expect(fakeS3.calls).toContain("abort:upload-old");
    // The newer upload completes on its own upload id, under its own key.
    const done = await finish(f, grant);
    expect(done.replies).toEqual([]);
    expect(done.verified).toHaveLength(1);
    expect(fakeS3.calls).toContain("complete:upload-new");
    expect(fakeS3.calls).not.toContain("complete:upload-old");
    expect(await artifactKey(f.ownerId, fingerprint)).toBe(grant.encryption?.key);
  });

  it("a second begin for the same owner and image while one is UPLOADING is refused; no transfer crosses keys", async () => {
    const f = await fixture();
    const a = await capture(f, 1);
    const b = await capture(f, 1);
    encrypted();
    fakeS3.created.push("upload-a", "upload-b");
    const fingerprint = fpOf();
    const first = frameCtx(f);
    const beginA = begin(a.id, 1, randomUUID(), fingerprint);
    await handleImageUploadBegin(first.ctx, beginA);
    const grant = first.replies.at(-1) as Grant & { type: string };
    expect(grant).toMatchObject({ type: "image.upload.grant", requestId: beginA.requestId });
    const second = frameCtx(f);
    const beginB = begin(b.id, 1, randomUUID(), fingerprint);
    await handleImageUploadBegin(second.ctx, beginB);
    expect(second.replies).toEqual([
      {
        type: "image.job.cancel",
        transferId: "none",
        reason: "upload_in_progress",
        requestId: beginB.requestId,
      },
    ]);
    expect(await db.inspect.sandboxImageTransfer.count({ where: { operationId: b.id } })).toBe(0);
    expect(fakeS3.calls.filter((c) => c === "create")).toHaveLength(1);
    // The first upload is untouched: it completes on its own id and key.
    const done = await finish(f, grant);
    expect(done.replies).toEqual([]);
    expect(fakeS3.calls).toContain("complete:upload-a");
    expect(await artifactKey(f.ownerId, fingerprint)).toBe(grant.encryption?.key);
  });

  it("every session of one image gets its own object key (create-only objects never share one)", async () => {
    const f = await fixture();
    const a = await capture(f, 1);
    const b = await capture(f, 1);
    encrypted();
    fakeS3.created.push("upload-a", "upload-b");
    const fingerprint = fpOf();
    const first = frameCtx(f);
    await handleImageUploadBegin(first.ctx, begin(a.id, 1, randomUUID(), fingerprint));
    const grantA = first.replies.at(-1) as Grant & { type: string };
    expect(grantA.type).toBe("image.upload.grant");
    // The first attempt's job ends; a new begin supersedes its session.
    await db.inspect.sandboxImageTransfer.update({
      where: { id: grantA.transferId },
      data: { state: "CANCELLED" },
    });
    const second = frameCtx(f);
    await handleImageUploadBegin(second.ctx, begin(b.id, 1, randomUUID(), fingerprint));
    expect(second.replies.at(-1)).toMatchObject({ type: "image.upload.grant" });
    const rows = await db.inspect.sandboxImageUploadSession.findMany({
      where: { userId: f.ownerId },
      select: { id: true, objectKey: true },
    });
    expect(rows).toHaveLength(2);
    for (const row of rows)
      expect(row.objectKey).toBe(
        `test/owners/${f.ownerId}/${fingerprint.slice(7)}/${row.id}/image.tar.wsspenc`,
      );
    expect(new Set(rows.map((r) => r.objectKey)).size).toBe(2);
  });

  it("a create-only refusal at Complete keeps VERIFYING and hands the object to verify; any other failure fails it", async () => {
    const { ImageObjectExistsError } = await import("@wssp/api/sandbox/image-store/s3");
    const f = await fixture();
    for (const refusal of [true, false]) {
      const op = await capture(f, 1);
      encrypted();
      fakeS3.created.push(refusal ? "upload-refused" : "upload-outage");
      const fingerprint = fpOf();
      const started = frameCtx(f);
      await handleImageUploadBegin(started.ctx, begin(op.id, 1, randomUUID(), fingerprint));
      const grant = started.replies.at(-1) as Grant & { type: string };
      expect(grant.type).toBe("image.upload.grant");
      fakeS3.completeError = refusal
        ? new ImageObjectExistsError("key", 412)
        : Object.assign(new Error("InternalError"), { name: "InternalError" });
      const done = await finish(f, grant);
      const artifact = await db.inspect.sandboxImageArtifact.findUniqueOrThrow({
        where: { userId_fingerprint: { userId: f.ownerId, fingerprint } },
      });
      if (refusal) {
        // Nothing was overwritten and nothing is assumed: the verify job decides.
        expect(done.replies).toEqual([]);
        expect(done.verified).toEqual([artifact.id]);
        expect(artifact.state).toBe("VERIFYING");
      } else {
        expect(done.replies).toEqual([
          { type: "image.job.cancel", transferId: grant.transferId, reason: "store_unavailable" },
        ]);
        expect(done.verified).toEqual([]);
        expect(artifact.state).toBe("FAILED");
        expect(fakeS3.calls).toContain("abort:upload-outage");
      }
    }
  });
});
