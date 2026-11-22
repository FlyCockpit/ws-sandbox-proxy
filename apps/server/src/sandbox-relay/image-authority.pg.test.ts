import {
  seedAcceptedOperation,
  seedLaunchHost,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

/** Rate-limit tests exhaust the per-host image grant budget. */
const grantBudget = vi.hoisted(() => ({ exhausted: false }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
  consumeImageGrantBudget: async () => {
    if (grantBudget.exhausted) throw new Error("budget exhausted");
  },
}));

import { randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import {
  encryptedImageLength,
  IMAGE_S3_PART_BYTES,
  IMAGE_UPLOAD_PARTS_MAX,
} from "@wssp/sandbox-contracts";
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
  /** Thrown by the next ListParts / UploadPart presign (then cleared). */
  listError: null as unknown,
  presignError: null as unknown,
  /** Runs inside the next ListParts (then cleared): a test acts while the
   * server waits on S3. */
  onList: null as (() => void) | null,
}));
vi.mock("@wssp/api/sandbox/image-store/s3", async (importOriginal) => {
  const real = await importOriginal<typeof import("@wssp/api/sandbox/image-store/s3")>();
  const store = {
    settings: { prefix: "test", presignTtlSeconds: 600 },
    createMultipart: async () => {
      fakeS3.calls.push("create");
      return (await fakeS3.created.shift()) ?? "upload-1";
    },
    presignUploadPart: async (_key: string, upload: string, n: number) => {
      const error = fakeS3.presignError;
      fakeS3.presignError = null;
      if (error) throw error;
      return `https://s3.example.test/part?upload=${upload}&n=${n}`;
    },
    listParts: async (_key: string, upload: string) => {
      fakeS3.calls.push(`list:${upload}`);
      const during = fakeS3.onList;
      fakeS3.onList = null;
      during?.();
      const error = fakeS3.listError;
      fakeS3.listError = null;
      if (error) throw error;
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
  handleImageUploadProgress,
  handleImageUploadRenew,
} = await import("./image-handlers");
const { finalizeCapture } = await import("@wssp/api/sandbox/image-store/captures");
const { endTemplateUpload } = await import("@wssp/api/sandbox/image-store/store-failure");
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
const range = (first: number, last: number) =>
  Array.from({ length: last - first + 1 }, (_, i) => first + i);
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
      listError: null,
      presignError: null,
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
        expect(artifact).toMatchObject({
          state: "FAILED",
          failureDetail: "store_complete_failed",
        });
        expect(fakeS3.calls).toContain("abort:upload-outage");
        // The whole upload ends with the cause: never COMPLETE beside a
        // FAILED artifact, and the waiting capture records it.
        expect(
          await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
            where: { id: grant.transferId },
          }),
        ).toMatchObject({ state: "FAILED", endReason: "store_complete_failed" });
        expect(
          await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
            where: { transferId: grant.transferId },
          }),
        ).toMatchObject({ state: "ABORTED", endReason: "store_complete_failed" });
        expect(
          await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
            where: { operationId: op.id },
          }),
        ).toMatchObject({ errorDetail: "store_complete_failed" });
      }
    }
  });
});

describe("capture upload failures end with their cause (I1-I4)", () => {
  afterEach(() => {
    Object.assign(fakeS3, {
      on: false,
      master: null,
      created: [],
      calls: [],
      listed: [],
      completeError: null,
      listError: null,
      presignError: null,
      onList: null,
    });
  });

  /** A recorded capture (STORING) whose begin was granted: its transfer. */
  async function begun(f: F) {
    fakeS3.on = true;
    const op = await capture(f, 1);
    const frame = begin(op.id, 1);
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: op.id },
      data: {
        fingerprint: frame.fingerprint,
        sizeBytes: 4096n,
        capturedAt: new Date(),
        state: "STORING",
      },
    });
    const { ctx, replies } = frameCtx(f);
    await handleImageUploadBegin(ctx, frame);
    const grant = replies.at(-1) as { type: string; transferId: string };
    expect(grant.type).toBe("image.upload.grant");
    return { op, fingerprint: frame.fingerprint, transferId: grant.transferId };
  }
  const captureOf = (operationId: string) =>
    db.inspect.sandboxTemplateCapture.findUniqueOrThrow({ where: { operationId } });

  it("image.job.failed on a capture upload ends session, artifact, multipart and capture with the cause", async () => {
    const f = await fixture();
    const { op, fingerprint, transferId } = await begun(f);
    const { ctx, replies } = frameCtx(f);
    await handleImageFailure(ctx, {
      type: "image.job.failed",
      transferId,
      code: "timeout",
      cause: "stalled",
      part: 1,
    });
    const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { transferId },
    });
    expect(session).toMatchObject({
      state: "ABORTED",
      liveArtifactId: null,
      endReason: "upload_stalled",
      uploadId: null,
    });
    expect(fakeS3.calls).toContain("abort:upload-1");
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({
        where: { id: session.artifactId! },
      }),
    ).toMatchObject({ state: "FAILED", failureDetail: "upload_stalled" });
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transferId } }),
    ).toMatchObject({ state: "FAILED", endReason: "upload_stalled" });
    expect(await captureOf(op.id)).toMatchObject({
      state: "FAILED",
      errorCode: "capture_store_failed",
      errorDetail: "upload_stalled",
    });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } }),
    ).toMatchObject({ state: "FAILED", errorCode: "capture_store_failed" });
    // The failed capture's origin pin is released at once.
    expect(replies).toContainEqual({
      type: "image.release",
      fingerprint,
      imageOwnerId: f.ownerId,
      reason: "gc",
    });
  });

  it("a store error at completion (ListParts) ends the upload with its cause, then the capture", async () => {
    const f = await fixture();
    fakeS3.on = true;
    const op = await capture(f, 1);
    const frame = begin(op.id, 1);
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: op.id },
      data: {
        fingerprint: frame.fingerprint,
        sizeBytes: 4096n,
        capturedAt: new Date(),
        state: "STORING",
      },
    });
    const { ctx, replies } = frameCtx(f);
    fakeS3.created.push("upload-list");
    const detail = "store_list_failed";
    await handleImageUploadBegin(ctx, frame);
    const transferId = (replies.at(-1) as { transferId: string }).transferId;
    fakeS3.listError = Object.assign(new Error("SlowDown"), { name: "SlowDown" });
    const verified: string[] = [];
    await handleImageUploadComplete(
      ctx,
      { type: "image.upload.complete", transferId },
      async (id) => {
        verified.push(id);
      },
    );
    expect(verified).toEqual([]);
    expect(replies.at(-1)).toEqual({ type: "image.job.cancel", transferId, reason: detail });
    const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { transferId },
    });
    expect(session).toMatchObject({ state: "ABORTED", endReason: detail, uploadId: null });
    expect(fakeS3.calls).toContain("abort:upload-list");
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({
        where: { id: session.artifactId! },
      }),
    ).toMatchObject({ state: "FAILED", failureDetail: detail });
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transferId } }),
    ).toMatchObject({ state: "FAILED", endReason: detail });
    // The capture records the cause at once and fails with it on the
    // next finalize; the build then reads it (decide: build_store_failed).
    expect(await captureOf(op.id)).toMatchObject({ state: "STORING", errorDetail: detail });
    expect(await finalizeCapture(op.id)).toMatchObject({ kind: "failed" });
    expect(await captureOf(op.id)).toMatchObject({
      state: "FAILED",
      errorCode: "capture_store_failed",
      errorDetail: detail,
    });
  });

  it("a store error presigning a renewed window ends the upload with its cause, then the capture", async () => {
    const f = await fixture();
    const { op, transferId } = await begun(f);
    const { ctx, replies } = frameCtx(f);
    fakeS3.presignError = Object.assign(new Error("CredentialsProviderError"), {
      name: "CredentialsProviderError",
    });
    await handleImageUploadRenew(ctx, { type: "image.upload.renew", transferId });
    expect(replies).toEqual([
      { type: "image.job.cancel", transferId, reason: "store_unavailable" },
    ]);
    expect(await uploadRows(op.id, transferId)).toEqual({
      transfer: ["FAILED", "store_unavailable"],
      session: ["ABORTED", "store_unavailable", null],
      artifact: { state: "FAILED", failureDetail: "store_unavailable" },
      capture: { state: "STORING", errorCode: null, errorDetail: "store_unavailable" },
    });
    expect(fakeS3.calls).toEqual(["create", "abort:upload-1"]);
    expect(await finalizeCapture(op.id)).toMatchObject({ kind: "failed" });
    expect(await captureOf(op.id)).toMatchObject({
      state: "FAILED",
      errorCode: "capture_store_failed",
      errorDetail: "store_unavailable",
    });
  });

  it("a completion whose connection is superseded during ListParts changes nothing", async () => {
    const f = await fixture();
    // Valid parts, invalid parts and a ListParts error: each would end or
    // claim the upload from the current connection.
    for (const outcome of ["valid", "invalid", "error"] as const) {
      const { op, transferId } = await begun(f);
      const before = await uploadRows(op.id, transferId);
      expect(before.transfer).toEqual(["OPEN", null]);
      let current = true;
      const { ctx, replies } = frameCtx(f);
      const sender = { ...ctx.sender, isCurrent: () => current };
      fakeS3.listed = outcome === "invalid" ? [] : [{ n: 1, size: 4096, etag: '"e1"' }];
      if (outcome === "error")
        fakeS3.listError = Object.assign(new Error("SlowDown"), { name: "SlowDown" });
      fakeS3.onList = () => {
        current = false;
      };
      fakeS3.calls = [];
      const verified: string[] = [];
      await handleImageUploadComplete(
        { ...ctx, sender },
        { type: "image.upload.complete", transferId },
        async (id) => {
          verified.push(id);
        },
      );
      expect(replies).toEqual([{ type: "image.job.cancel", transferId, reason: "stale_transfer" }]);
      expect(verified).toEqual([]);
      expect(fakeS3.calls).toEqual(["list:upload-1"]);
      expect(await uploadRows(op.id, transferId)).toEqual(before);
    }
  });

  it("an operation-ref failure counts only from the capture's host, epoch and attempt", async () => {
    const f = await fixture();
    fakeS3.on = true;
    const op = await capture(f, 1);
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: op.id },
      data: { fingerprint: fpOf(), sizeBytes: 4096n, capturedAt: new Date(), state: "STORING" },
    });
    const refused = {
      type: "image.job.failed" as const,
      operationId: op.id,
      attempt: 1,
      code: "cancelled" as const,
      cause: "refused" as const,
      refusal: "image_quota_exceeded",
    };
    const base = frameCtx(f).ctx;
    for (const ctx of [
      { ...base, sender: { ...base.sender, hostId: f.source.id } },
      { ...base, sender: { ...base.sender, connectionEpoch: 2 } },
    ]) {
      await handleImageFailure(ctx, refused);
      expect(await captureOf(op.id)).toMatchObject({ state: "STORING", errorDetail: null });
    }
    await handleImageFailure(base, { ...refused, attempt: 2 });
    expect(await captureOf(op.id)).toMatchObject({ state: "STORING", errorDetail: null });
    await handleImageFailure(base, refused);
    expect(await captureOf(op.id)).toMatchObject({
      state: "FAILED",
      errorCode: "capture_store_failed",
      errorDetail: "upload_refused.image_quota_exceeded",
    });
  });

  /** Every row of one capture upload, for "nothing changed" checks. */
  async function uploadRows(operationId: string, transferId: string) {
    const transfer = await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
      where: { id: transferId },
    });
    const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { transferId },
    });
    return {
      transfer: [transfer.state, transfer.endReason],
      session: [session.state, session.endReason, session.uploadId],
      artifact: await db.inspect.sandboxImageArtifact.findUniqueOrThrow({
        where: { id: session.artifactId! },
        select: { state: true, failureDetail: true },
      }),
      capture: await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
        where: { operationId },
        select: { state: true, errorCode: true, errorDetail: true },
      }),
    };
  }

  it("a stale transfer report (another host, an old epoch, a superseded attempt) changes nothing", async () => {
    const f = await fixture();
    const { op, fingerprint, transferId } = await begun(f);
    // The capture host's availability of this image: a stale split-export
    // report must not touch it either.
    const probe = await seedTemplateRevision(db.inspect, {
      data: {
        userId: f.ownerId,
        sandboxHostId: f.dest.id,
        slug: "split-probe",
        label: "Split probe",
        incusFingerprint: fingerprint,
      },
    });
    await db.inspect.sandboxTemplateAvailability.updateMany({
      where: { revisionId: probe.id, hostId: f.dest.id },
      data: { imageFormat: "unified" },
    });
    const formats = () =>
      db.inspect.sandboxTemplateAvailability
        .findMany({
          where: { userId: f.ownerId, localFingerprint: fingerprint },
          select: { hostId: true, imageFormat: true },
        })
        .then((rows) => rows.map((r) => [r.hostId, r.imageFormat]));
    expect(await formats()).toEqual([[f.dest.id, "unified"]]);
    const before = await uploadRows(op.id, transferId);
    expect(before.transfer).toEqual(["OPEN", null]);
    const failed = {
      type: "image.job.failed" as const,
      transferId,
      code: "io" as const,
      cause: "reset" as const,
    };
    const split = { ...failed, code: "format_unsupported" as const, cause: "export" as const };
    // A destination's report: an S3 upload has none, so it never counts,
    // from the current connection either.
    const fetchFailed = (code: "io" | "format_unsupported") => ({
      type: "image.fetch.failed" as const,
      transferId,
      fingerprint,
      code,
    });
    const base = frameCtx(f).ctx;
    for (const ctx of [
      { ...base, sender: { ...base.sender, hostId: f.source.id } },
      { ...base, sender: { ...base.sender, connectionEpoch: 2 } },
      { ...base, sender: { ...base.sender, isCurrent: () => false } },
      base,
    ]) {
      if (ctx !== base) {
        await handleImageFailure(ctx, failed);
        await handleImageFailure(ctx, split);
      }
      await handleImageFailure(ctx, fetchFailed("io"));
      await handleImageFailure(ctx, fetchFailed("format_unsupported"));
      expect(await uploadRows(op.id, transferId)).toEqual(before);
      expect(await formats()).toEqual([[f.dest.id, "unified"]]);
    }
    // The host reconnected (epoch 2): a report on the new connection about
    // the old connection's transfer is stale too.
    await db.inspect.sandboxHost.update({
      where: { id: f.dest.id },
      data: { connectionEpoch: 2, imageCacheEpoch: 2 },
    });
    for (const frame of [failed, split, fetchFailed("io"), fetchFailed("format_unsupported")])
      await handleImageFailure({ ...base, sender: { ...base.sender, connectionEpoch: 2 } }, frame);
    expect(await uploadRows(op.id, transferId)).toEqual(before);
    expect(await formats()).toEqual([[f.dest.id, "unified"]]);
    await db.inspect.sandboxHost.update({
      where: { id: f.dest.id },
      data: { connectionEpoch: 1, imageCacheEpoch: 1 },
    });
    // The capture moved on to attempt 2: attempt 1's upload report is stale.
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: { dispatchAttempt: 2 },
    });
    for (const frame of [failed, split, fetchFailed("io"), fetchFailed("format_unsupported")])
      await handleImageFailure(base, frame);
    expect(await uploadRows(op.id, transferId)).toEqual(before);
    expect(await formats()).toEqual([[f.dest.id, "unified"]]);
    expect(fakeS3.calls.filter((c) => c.startsWith("abort:"))).toEqual([]);
    // From the current connection and attempt it counts.
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: { dispatchAttempt: 1 },
    });
    await handleImageFailure(base, failed);
    expect(await uploadRows(op.id, transferId)).toMatchObject({
      transfer: ["FAILED", "upload_reset"],
      artifact: { state: "FAILED", failureDetail: "upload_reset" },
      capture: { state: "FAILED", errorDetail: "upload_reset" },
    });
    expect(fakeS3.calls).toContain("abort:upload-1");
  });

  it("an operation-ref failure ends the upload the server already opened for that attempt", async () => {
    const f = await fixture();
    const { op, transferId } = await begun(f);
    const { ctx } = frameCtx(f);
    // The grant never reached the daemon: it reports by operation.
    await handleImageFailure(ctx, {
      type: "image.job.failed",
      operationId: op.id,
      attempt: 1,
      code: "timeout",
      cause: "no_grant",
    });
    expect(await uploadRows(op.id, transferId)).toEqual({
      transfer: ["FAILED", "upload_no_grant"],
      session: ["ABORTED", "upload_no_grant", null],
      artifact: { state: "FAILED", failureDetail: "upload_no_grant" },
      capture: {
        state: "FAILED",
        errorCode: "capture_store_failed",
        errorDetail: "upload_no_grant",
      },
    });
    expect(fakeS3.calls).toContain("abort:upload-1");
  });

  it("a finalize driven by a report tells hosts to stop the uploads it ends", async () => {
    const f = await fixture();
    const { op, fingerprint, transferId } = await begun(f);
    // A second OPEN upload of the same attempt (no session), as a race leaves it.
    const other = await db.inspect.sandboxImageTransfer.create({
      data: {
        userId: f.ownerId,
        fingerprint,
        purpose: "CAPTURE_UPLOAD",
        mode: "S3",
        sourceHostId: f.dest.id,
        sourceHostOwnerId: f.ownerId,
        sourceEpoch: 1,
        operationId: op.id,
        dispatchAttempt: 1,
        sizeBytes: 4096n,
        partSize: 4096,
        partCount: 1,
        expiresAt: new Date(Date.now() + 3_600_000),
      },
    });
    const sent: Array<{ hostId: string; epoch: number; frame: unknown }> = [];
    const base = frameCtx(f).ctx;
    const ctx = {
      ...base,
      sendTo: (hostId: string, epoch: number, frame: unknown) => {
        sent.push({ hostId, epoch, frame });
        return true;
      },
    };
    await handleImageFailure(ctx, {
      type: "image.job.failed",
      transferId,
      code: "io",
      cause: "http_status",
      httpStatus: 503,
      part: 1,
    });
    expect(await captureOf(op.id)).toMatchObject({
      state: "FAILED",
      errorDetail: "upload_http_503",
    });
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: other.id } }),
    ).toMatchObject({ state: "FAILED", endReason: "upload_http_503" });
    expect(sent).toEqual([
      {
        hostId: f.dest.id,
        epoch: 1,
        frame: { type: "image.job.cancel", transferId: other.id, reason: "upload_http____" },
      },
    ]);
  });

  it("a failed publish upload ends its session, artifact and multipart with the cause and touches no capture; a split export is recorded with it", async () => {
    const f = await fixture();
    fakeS3.on = true;
    const bystander = await capture(f, 1);
    const publish = async () => {
      const transfer = await db.inspect.sandboxImageTransfer.create({
        data: {
          userId: f.ownerId,
          fingerprint: f.fingerprint,
          purpose: "PUBLISH",
          mode: "S3",
          sourceHostId: f.source.id,
          sourceHostOwnerId: f.ownerId,
          sourceEpoch: 1,
          sizeBytes: 4096n,
          partSize: 4096,
          partCount: 1,
          expiresAt: new Date(Date.now() + 3_600_000),
        },
      });
      const { ctx, replies } = frameCtx(f);
      const source = { ...ctx, sender: { ...ctx.sender, hostId: f.source.id } };
      await handleImageUploadBegin(source, {
        type: "image.upload.begin",
        transferId: transfer.id,
        fingerprint: f.fingerprint,
        sizeBytes: 4096,
        format: "unified",
      });
      expect(replies.at(-1)).toMatchObject({ type: "image.upload.grant" });
      return { transferId: transfer.id, source };
    };
    const first = await publish();
    await handleImageFailure(first.source, {
      type: "image.job.failed",
      transferId: first.transferId,
      code: "io",
      cause: "http_status",
      httpStatus: 503,
      part: 1,
    });
    const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { transferId: first.transferId },
    });
    expect(session).toMatchObject({
      state: "ABORTED",
      endReason: "upload_http_503",
      uploadId: null,
    });
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
        where: { id: first.transferId },
      }),
    ).toMatchObject({ state: "FAILED", endReason: "upload_http_503" });
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({
        where: { id: session.artifactId! },
      }),
    ).toMatchObject({ state: "FAILED", failureDetail: "upload_http_503" });
    expect(fakeS3.calls).toContain("abort:upload-1");
    expect(await captureOf(bystander.id)).toMatchObject({
      state: "CAPTURED",
      errorDetail: null,
    });
    // A split image found by the export: never picked as a peer source again.
    const second = await publish();
    await handleImageFailure(second.source, {
      type: "image.job.failed",
      transferId: second.transferId,
      code: "format_unsupported",
      cause: "export",
    });
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
        where: { id: second.transferId },
      }),
    ).toMatchObject({ state: "FAILED", endReason: "upload_export" });
    expect(
      await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
        where: { hostId: f.source.id, localFingerprint: f.fingerprint },
      }),
    ).toMatchObject({ imageFormat: "split" });
  });

  it("heartbeats refresh liveness only when bytes advance, at most every 10 s; silence past 10 min stalls the upload", async () => {
    const f = await fixture();
    const { op, transferId } = await begun(f);
    const { ctx } = frameCtx(f);
    const row = () =>
      db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transferId } });
    // The handler's clock is pinned relative to the recorded progress, so
    // both sides of the 10 s throttle are exact and no assertion depends on
    // how fast this test or the database runs (a recent base: the stall
    // rule below runs on the real clock).
    const at = new Date();
    await db.inspect.sandboxImageTransfer.update({
      where: { id: transferId },
      data: { lastProgressAt: at },
    });
    const beat = (bytesSent: number, afterMs: number, wireBytes = 0) =>
      handleImageUploadProgress(
        ctx,
        { type: "image.upload.progress", transferId, bytesSent, wireBytes },
        new Date(at.getTime() + afterMs),
      );
    // 9.9 s after the last progress: inside the throttle, nothing is written.
    await beat(1000, 9_900);
    expect(await row()).toMatchObject({ lastProgressAt: at, bytesDone: 0n });
    // 10.1 s after: an advance moves the transfer and its artifact.
    await beat(1000, 10_100);
    let moved = await row();
    expect(moved).toMatchObject({
      lastProgressAt: new Date(at.getTime() + 10_100),
      bytesDone: 1000n,
    });
    const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { transferId },
    });
    expect(
      (
        await db.inspect.sandboxImageArtifact.findUniqueOrThrow({
          where: { id: session.artifactId! },
        })
      ).lastProgressAt,
    ).toEqual(new Date(at.getTime() + 10_100));
    // A repeated or lower count is no progress, past the throttle or not.
    for (const bytes of [1000, 500, 0]) await beat(bytes, 60_000);
    expect(await row()).toMatchObject({
      lastProgressAt: new Date(at.getTime() + 10_100),
      bytesDone: 1000n,
    });
    // V3 (I5): a retry re-sending bytes below the offset reached moves
    // only `wireBytes`; that is liveness too, and the offset never moves back.
    await beat(500, 60_000, 1500);
    expect(await row()).toMatchObject({
      lastProgressAt: new Date(at.getTime() + 60_000),
      bytesDone: 1000n,
      wireBytes: 1500n,
    });
    // A lower or repeated wire count is not.
    await beat(500, 120_000, 1500);
    expect((await row()).lastProgressAt).toEqual(new Date(at.getTime() + 60_000));
    // An advance past the object is held to its stored size.
    await beat(1_000_000, 180_000, 1500);
    moved = await row();
    expect(moved.bytesDone).toBe(4096n);
    expect(moved.wireBytes).toBe(1500n);
    expect(await finalizeCapture(op.id)).toEqual({ kind: "waiting" });
    // No further progress: ten minutes later it is stalled and ended.
    const later = new Date(moved.lastProgressAt.getTime() + 11 * 60_000);
    expect(await finalizeCapture(op.id, later)).toMatchObject({
      kind: "failed",
      cancels: [{ transferId, hostId: f.dest.id, epoch: 1, reason: "upload_stalled" }],
    });
    expect(await captureOf(op.id)).toMatchObject({ errorDetail: "upload_stalled" });
    expect(fakeS3.calls).toContain("abort:upload-1");
  });
});

describe("capture uploads survive slow and flaky uplinks (increment B)", () => {
  const MiB = 1024 * 1024;
  afterEach(() => {
    vi.unstubAllEnvs();
    grantBudget.exhausted = false;
    Object.assign(fakeS3, {
      on: false,
      master: null,
      created: [],
      calls: [],
      listed: [],
      completeError: null,
      listError: null,
      presignError: null,
      onList: null,
    });
  });
  type UploadGrant = {
    type: string;
    transferId: string;
    requestId?: string;
    partSize: number;
    parts: { n: number; sizeBytes: number }[];
    ttlSeconds: number;
    encryption?: unknown;
  };

  /** A recorded (STORING) capture of `sizeBytes` whose begin was granted. */
  async function storing(f: F, sizeBytes: number) {
    fakeS3.on = true;
    const op = await capture(f, 1);
    const frame = { ...begin(op.id, 1), sizeBytes };
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: op.id },
      data: {
        fingerprint: frame.fingerprint,
        sizeBytes: BigInt(sizeBytes),
        capturedAt: new Date(),
        state: "STORING",
      },
    });
    const { ctx, replies } = frameCtx(f);
    await handleImageUploadBegin(ctx, frame);
    const grant = replies.at(-1) as UploadGrant;
    expect(grant).toMatchObject({ type: "image.upload.grant", requestId: frame.requestId });
    return { op, frame, grant, transferId: grant.transferId };
  }
  const captureOf = (operationId: string) =>
    db.inspect.sandboxTemplateCapture.findUniqueOrThrow({ where: { operationId } });
  const parts = (transferId: string, ns: number[]) => ({
    type: "image.upload.parts" as const,
    transferId,
    parts: ns.map((n) => ({ n, etag: `"e${n}"` })),
  });
  const renew = (transferId: string) => ({ type: "image.upload.renew" as const, transferId });
  const recorded = async (transferId: string) => {
    const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { transferId },
    });
    return (
      await db.inspect.sandboxImageUploadPart.findMany({
        where: { sessionId: session.id },
        orderBy: { partNumber: "asc" },
        take: 100,
      })
    ).map((p) => p.partNumber);
  };

  it("sizes parts per session from the image size and records it on the session and transfer", async () => {
    const f = await fixture();
    fakeS3.on = true;
    // The images below exceed the default per-account stored quota.
    vi.stubEnv("IMAGE_STORE_MAX_GIB_PER_ACCOUNT", "unlimited");
    const GiB = 1024 * MiB;
    for (const [sizeBytes, master, partSize] of [
      [40 * MiB, null, 16 * MiB],
      [40 * MiB, randomBytes(32), 16 * (MiB + 16)],
      [156 * GiB, null, 16 * MiB],
      [1024 * GiB, randomBytes(32), 105 * (MiB + 16)],
    ] as const) {
      fakeS3.master = master;
      const op = await capture(f, 1);
      const frame = { ...begin(op.id, 1), sizeBytes };
      const { ctx, replies } = frameCtx(f);
      await handleImageUploadBegin(ctx, frame);
      const grant = replies.at(-1) as UploadGrant;
      expect(grant).toMatchObject({ type: "image.upload.grant", partSize });
      const stored = master ? encryptedImageLength(sizeBytes) : sizeBytes;
      const count = Math.ceil(stored / partSize);
      expect(count).toBeLessThanOrEqual(10_000);
      expect(grant.parts.map((p) => p.n)).toEqual(
        range(1, Math.min(count, IMAGE_UPLOAD_PARTS_MAX)),
      );
      const transfer = await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
        where: { id: grant.transferId },
      });
      expect([transfer.partSize, transfer.partCount]).toEqual([partSize, count]);
      const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
        where: { transferId: grant.transferId },
      });
      expect(session.partSize).toBe(partSize);
      // Never the fixed 64 MiB part of earlier sessions.
      expect(partSize).not.toBe(IMAGE_S3_PART_BYTES);
    }
  });

  it("parts never push a grant; renew grants from the lowest unrecorded part, with a relative TTL and no key", async () => {
    const f = await fixture();
    fakeS3.master = randomBytes(32);
    // 3 parts of 16 sealed records.
    const { grant, transferId } = await storing(f, 40 * MiB);
    expect(grant.ttlSeconds).toBe(600);
    expect(grant.encryption).toBeDefined();
    expect(grant.parts.map((p) => p.n)).toEqual([1, 2, 3]);
    const { ctx, replies } = frameCtx(f);
    await handleImageUploadParts(ctx, parts(transferId, [1, 3]));
    expect(replies).toEqual([]);
    await handleImageUploadRenew(ctx, renew(transferId));
    const renewed = replies.at(-1) as UploadGrant;
    expect(renewed).toMatchObject({
      type: "image.upload.grant",
      transferId,
      partSize: grant.partSize,
      ttlSeconds: 600,
    });
    expect(renewed.parts.map((p) => p.n)).toEqual([2, 3]);
    expect(renewed.encryption).toBeUndefined();
    expect(renewed.requestId).toBeUndefined();
    await handleImageUploadParts(ctx, parts(transferId, [2]));
    await handleImageUploadRenew(ctx, renew(transferId));
    expect((replies.at(-1) as UploadGrant).parts).toEqual([]);
    expect(replies.filter((r) => r.type === "image.upload.grant")).toHaveLength(2);
    expect(await recorded(transferId)).toEqual([1, 2, 3]);
    // A whole first window reported (the old server pushed the next window
    // here): still no reply; the next window comes only on a renew.
    fakeS3.master = null;
    const big = await storing(f, IMAGE_UPLOAD_PARTS_MAX * 16 * MiB + 4096);
    expect(big.grant.parts.map((p) => p.n)).toEqual(range(1, IMAGE_UPLOAD_PARTS_MAX));
    const window = frameCtx(f);
    await handleImageUploadParts(
      window.ctx,
      parts(big.transferId, range(1, IMAGE_UPLOAD_PARTS_MAX)),
    );
    expect(window.replies).toEqual([]);
    await handleImageUploadRenew(window.ctx, renew(big.transferId));
    expect((window.replies.at(-1) as UploadGrant).parts.map((p) => p.n)).toEqual([
      IMAGE_UPLOAD_PARTS_MAX + 1,
    ]);
  });

  it("a renew from another connection or a superseded attempt is refused and grants nothing", async () => {
    const f = await fixture();
    const { op, transferId } = await storing(f, 40 * MiB);
    const before = await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
      where: { id: transferId },
    });
    const base = frameCtx(f);
    const stale = { type: "image.job.cancel", transferId, reason: "stale_transfer" };
    // Another epoch (the host is on epoch 1), a superseded connection.
    for (const sender of [
      { ...base.ctx.sender, connectionEpoch: 2 },
      { ...base.ctx.sender, isCurrent: () => false },
    ]) {
      const replies: Array<Record<string, unknown>> = [];
      await handleImageUploadRenew(
        { ...base.ctx, sender, reply: (r) => replies.push(r as Record<string, unknown>) },
        renew(transferId),
      );
      expect(replies).toEqual([stale]);
    }
    // The capture moved on to attempt 2.
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: { dispatchAttempt: 2 },
    });
    await handleImageUploadRenew(base.ctx, renew(transferId));
    expect(base.replies).toEqual([stale]);
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transferId } }),
    ).toEqual(before);
  });

  it("over the grant budget, parts, heartbeats and renews change nothing and send nothing", async () => {
    const f = await fixture();
    const { op, transferId } = await storing(f, 40 * MiB);
    const at = new Date(Date.now() - 60_000);
    await db.inspect.sandboxImageTransfer.update({
      where: { id: transferId },
      data: { lastProgressAt: at },
    });
    const rows = async () => ({
      transfer: await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
        where: { id: transferId },
      }),
      session: await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
        where: { transferId },
      }),
      capture: await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
        where: { operationId: op.id },
      }),
      // Heartbeats move the artifact's liveness too (test#9).
      artifact: await db.inspect.sandboxImageArtifact.findFirstOrThrow({
        where: { UploadSessions: { some: { transferId } } },
      }),
      parts: await recorded(transferId),
    });
    const before = await rows();
    grantBudget.exhausted = true;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { ctx, replies } = frameCtx(f);
    for (let i = 0; i < 2; i++) {
      await handleImageUploadParts(ctx, parts(transferId, [1]));
      await handleImageUploadProgress(ctx, {
        type: "image.upload.progress",
        transferId,
        bytesSent: 1000,
        wireBytes: 1000,
      });
      await handleImageUploadRenew(ctx, renew(transferId));
    }
    expect(replies).toEqual([]);
    expect(await rows()).toEqual(before);
    expect(fakeS3.calls).toEqual(["create"]);
    // FB-B6: the drops are logged once for the transfer, ids and frame only.
    const drops = warn.mock.calls.filter(([line]) => String(line).includes("grant budget"));
    expect(drops).toEqual([
      [
        "[sandbox-image] upload frame dropped over the grant budget:",
        { hostId: f.dest.id, transferId, frame: "image.upload.parts" },
      ],
    ]);
    warn.mockRestore();
    // Within budget again, the same frames count.
    grantBudget.exhausted = false;
    await handleImageUploadParts(ctx, parts(transferId, [1]));
    await handleImageUploadRenew(ctx, renew(transferId));
    expect(await recorded(transferId)).toEqual([1]);
    expect((replies.at(-1) as UploadGrant).parts.map((p) => p.n)).toEqual([2, 3]);
  });

  it("a begin the store refuses records no evidence; the capture waits and a retried begin is granted", async () => {
    const f = await fixture();
    for (const stage of ["create", "presign"] as const) {
      fakeS3.on = true;
      const op = await capture(f, 1);
      const frame = { ...begin(op.id, 1), sizeBytes: 40 * MiB };
      await db.inspect.sandboxTemplateCapture.update({
        where: { operationId: op.id },
        data: {
          fingerprint: frame.fingerprint,
          sizeBytes: BigInt(frame.sizeBytes),
          capturedAt: new Date(),
          state: "STORING",
        },
      });
      if (stage === "create") {
        const refused = Promise.reject(Object.assign(new Error("SlowDown"), { name: "SlowDown" }));
        refused.catch(() => {});
        fakeS3.created.push(refused);
      } else {
        fakeS3.created.push(`upload-${stage}`);
        fakeS3.presignError = Object.assign(new Error("CredentialsProviderError"), {
          name: "CredentialsProviderError",
        });
      }
      const { ctx, replies } = frameCtx(f);
      await handleImageUploadBegin(ctx, frame);
      const first = await db.inspect.sandboxImageTransfer.findFirstOrThrow({
        where: { operationId: op.id },
      });
      expect(replies).toEqual([
        {
          type: "image.job.cancel",
          transferId: first.id,
          reason: "store_unavailable",
          requestId: frame.requestId,
        },
      ]);
      expect([first.state, first.endReason]).toEqual([
        "CANCELLED",
        "begin_retry.store_unavailable",
      ]);
      const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
        where: { transferId: first.id },
      });
      expect([session.state, session.liveArtifactId]).toEqual(["ABORTED", null]);
      if (stage === "presign") expect(fakeS3.calls).toContain("abort:upload-presign");
      // Not a failure: no evidence, the artifact stays UPLOADING.
      expect(
        await db.inspect.sandboxImageArtifact.findUniqueOrThrow({
          where: { id: session.artifactId! },
        }),
      ).toMatchObject({ state: "UPLOADING", failureDetail: null });
      expect(await captureOf(op.id)).toMatchObject({ state: "STORING", errorDetail: null });
      expect(await finalizeCapture(op.id)).toEqual({ kind: "waiting" });
      // The host's retried begin (a new request) is granted a new transfer.
      fakeS3.created.push(`upload-retry-${stage}`);
      const retry = { ...frame, requestId: randomUUID() };
      const again = frameCtx(f);
      await handleImageUploadBegin(again.ctx, retry);
      const grant = again.replies.at(-1) as UploadGrant;
      expect(grant).toMatchObject({ type: "image.upload.grant", requestId: retry.requestId });
      expect(grant.transferId).not.toBe(first.id);
      expect(await finalizeCapture(op.id)).toEqual({ kind: "waiting" });
      // A begin that never succeeds is bounded by `upload_lost` (G).
      await db.inspect.sandboxImageTransfer.update({
        where: { id: grant.transferId },
        data: { state: "CANCELLED", endReason: "begin_retry.store_unavailable" },
      });
      expect(await finalizeCapture(op.id)).toEqual({ kind: "waiting" });
      expect(await finalizeCapture(op.id, new Date(Date.now() + 3 * 3_600_000))).toMatchObject({
        kind: "failed",
      });
      expect(await captureOf(op.id)).toMatchObject({ errorDetail: "upload_lost" });
    }
  });

  it("after a reconnect, resume rebinds a recorded capture's upload only from its own host and attempt; then its frames count on the new epoch", async () => {
    const f = await fixture();
    const { op, transferId } = await storing(f, 40 * MiB);
    const resumeFrame = {
      type: "image.job.resume" as const,
      transferId,
      role: "SOURCE" as const,
      bytesDone: 0,
    };
    const stale = { type: "image.job.cancel", transferId, reason: "stale_transfer" };
    // The host reconnects on epoch 2: before a resume, its upload frames on
    // the new connection are stale (the transfer is bound to epoch 1).
    await db.inspect.sandboxHost.update({
      where: { id: f.dest.id },
      data: { connectionEpoch: 2, imageCacheEpoch: 2 },
    });
    const next = frameCtx(f, 2);
    await handleImageUploadParts(next.ctx, parts(transferId, [1]));
    expect(next.replies).toEqual([stale]);
    expect(await recorded(transferId)).toEqual([]);
    const resume = async (ctx: ReturnType<typeof frameCtx>["ctx"]) => {
      const replies: Array<Record<string, unknown>> = [];
      await handleImageJobResume({ ...ctx, reply: (r) => replies.push(r as never) }, resumeFrame);
      return replies;
    };
    const refused = [{ type: "image.job.resume.result", transferId, continue: false }];
    // Another host of the owner (the source host, also on epoch 2).
    await db.inspect.sandboxHost.update({
      where: { id: f.source.id },
      data: { connectionEpoch: 2 },
    });
    expect(
      await resume({ ...next.ctx, sender: { ...next.ctx.sender, hostId: f.source.id } }),
    ).toEqual(refused);
    // A superseded attempt.
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: { dispatchAttempt: 2 },
    });
    expect(await resume(next.ctx)).toEqual(refused);
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: { dispatchAttempt: 1 },
    });
    // A capture whose result is not recorded runs on this connection only
    // once reconciliation adopts it; the resume never does that.
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: op.id },
      data: { state: "PENDING" },
    });
    expect(await resume(next.ctx)).toEqual(refused);
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: op.id },
      data: { state: "STORING" },
    });
    let transfer = await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
      where: { id: transferId },
    });
    expect(transfer.sourceEpoch).toBe(1);
    // Its own host and attempt: the recorded capture now runs here.
    expect(await resume(next.ctx)).toEqual([
      { type: "image.job.resume.result", transferId, continue: true },
    ]);
    transfer = await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
      where: { id: transferId },
    });
    expect([transfer.state, transfer.sourceEpoch]).toEqual(["OPEN", 2]);
    expect(
      (await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({ where: { transferId } }))
        .hostEpoch,
    ).toBe(2);
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } }))
        .dispatchedConnectionEpoch,
    ).toBe(2);
    // Parts, renews and heartbeats on the new epoch count.
    const after = frameCtx(f, 2);
    await handleImageUploadParts(after.ctx, parts(transferId, [1]));
    expect(await recorded(transferId)).toEqual([1]);
    await handleImageUploadRenew(after.ctx, renew(transferId));
    expect((after.replies.at(-1) as UploadGrant).parts.map((p) => p.n)).toEqual([2, 3]);
    const beatAt = new Date(transfer.lastProgressAt.getTime() + 60_000);
    await handleImageUploadProgress(
      after.ctx,
      { type: "image.upload.progress", transferId, bytesSent: 20 * MiB, wireBytes: 20 * MiB },
      beatAt,
    );
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transferId } }),
    ).toMatchObject({ lastProgressAt: beatAt, bytesDone: BigInt(20 * MiB) });
    expect(after.replies.filter((r) => r.type === "image.job.cancel")).toEqual([]);
    // The old connection's frames are stale now.
    const old = frameCtx(f, 1);
    await handleImageUploadRenew(old.ctx, renew(transferId));
    expect(old.replies).toEqual([stale]);
    expect(await finalizeCapture(op.id)).toEqual({ kind: "waiting" });
    // test#8: the upload completes on epoch 2: the remaining parts, then
    // Complete through the rebound session, verification, and the capture's
    // success path.
    await handleImageUploadParts(after.ctx, parts(transferId, [2, 3]));
    expect(await recorded(transferId)).toEqual([1, 2, 3]);
    fakeS3.listed = [
      { n: 1, size: 16 * MiB, etag: '"e1"' },
      { n: 2, size: 16 * MiB, etag: '"e2"' },
      { n: 3, size: 8 * MiB, etag: '"e3"' },
    ];
    const verified: string[] = [];
    await handleImageUploadComplete(
      after.ctx,
      { type: "image.upload.complete", transferId },
      async (id) => {
        verified.push(id);
      },
    );
    expect(after.replies.filter((r) => r.type === "image.job.cancel")).toEqual([]);
    expect(fakeS3.calls).toContain("complete:upload-1");
    const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { transferId },
    });
    expect(session.state).toBe("COMPLETE");
    expect(verified).toEqual([session.artifactId]);
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transferId } }),
    ).toMatchObject({ state: "COMPLETE", sourceEpoch: 2 });
    // The verify job proves the object; the capture then finalizes.
    await db.inspect.sandboxImageArtifact.update({
      where: { id: session.artifactId! },
      data: { state: "STORED", verifiedAt: new Date() },
    });
    expect(await finalizeCapture(op.id)).toMatchObject({ kind: "finalized" });
  });

  /** The rows a refused resume must leave as they were (test#7). */
  async function protectedRows(operationId: string) {
    return {
      operation: await db.inspect.sandboxOperation.findUniqueOrThrow({
        where: { id: operationId },
      }),
      capture: await captureOf(operationId),
      transfers: await db.inspect.sandboxImageTransfer.findMany({
        where: { operationId },
        orderBy: { createdAt: "asc" },
        take: 10,
      }),
      sessions: await db.inspect.sandboxImageUploadSession.findMany({
        where: { Transfer: { is: { operationId } } },
        orderBy: { createdAt: "asc" },
        take: 10,
      }),
    };
  }
  const setOperation = (id: string, data: Record<string, unknown>) =>
    db.inspect.sandboxOperation.update({ where: { id }, data: data as never });
  const reconnect = (f: F, epoch: number) =>
    db.inspect.sandboxHost.update({
      where: { id: f.dest.id },
      data: { connectionEpoch: epoch, imageCacheEpoch: epoch },
    });
  async function resumeOn(ctx: ReturnType<typeof frameCtx>["ctx"], frame: unknown) {
    const replies: Array<Record<string, unknown>> = [];
    await handleImageJobResume(
      { ...ctx, reply: (r) => replies.push(r as never) },
      frame as Parameters<typeof handleImageJobResume>[1],
    );
    return replies;
  }

  it("V5: a transfer resume is refused, its rows unchanged, for another owner, a superseded connection, an expired transfer, a cancel request, a terminal operation and a conflicting dispatch epoch; reconnects 1→3→5 rebind; a later cancel makes its frames stale", async () => {
    const f = await fixture();
    const { op, transferId } = await storing(f, 40 * MiB);
    await reconnect(f, 3);
    const on3 = frameCtx(f, 3);
    const frame = { type: "image.job.resume", transferId, role: "SOURCE", bytesDone: 0 };
    const refused = [{ type: "image.job.resume.result", transferId, continue: false }];
    const transfer0 = await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
      where: { id: transferId },
    });
    const cases: Array<{
      name: string;
      ctx: ReturnType<typeof frameCtx>["ctx"];
      arrange?: () => Promise<unknown>;
      restore?: () => Promise<unknown>;
    }> = [
      {
        name: "another owner",
        ctx: { ...on3.ctx, sender: { ...on3.ctx.sender, userId: `other-${randomUUID()}` } },
      },
      {
        name: "a superseded connection",
        ctx: { ...on3.ctx, sender: { ...on3.ctx.sender, isCurrent: () => false } },
      },
      {
        name: "an expired transfer",
        ctx: on3.ctx,
        arrange: () =>
          db.inspect.sandboxImageTransfer.update({
            where: { id: transferId },
            data: { expiresAt: new Date(Date.now() - 1000) },
          }),
        restore: () =>
          db.inspect.sandboxImageTransfer.update({
            where: { id: transferId },
            data: { expiresAt: transfer0.expiresAt },
          }),
      },
      {
        name: "a cancel request",
        ctx: on3.ctx,
        arrange: () => setOperation(op.id, { state: "CANCEL_REQUESTED" }),
        restore: () => setOperation(op.id, { state: "RUNNING" }),
      },
      {
        name: "a terminal operation",
        ctx: on3.ctx,
        arrange: () => setOperation(op.id, { state: "FAILED" }),
        restore: () => setOperation(op.id, { state: "RUNNING" }),
      },
      {
        name: "a conflicting dispatch epoch",
        ctx: on3.ctx,
        arrange: () => setOperation(op.id, { dispatchedConnectionEpoch: 2 }),
        restore: () => setOperation(op.id, { dispatchedConnectionEpoch: 1 }),
      },
    ];
    for (const c of cases) {
      await c.arrange?.();
      const before = await protectedRows(op.id);
      expect(await resumeOn(c.ctx, frame), c.name).toEqual(refused);
      expect(await protectedRows(op.id), c.name).toEqual(before);
      await c.restore?.();
    }
    // Reconnects 1 → 3 → 5: each resume rebinds the transfer, its session
    // and the operation to the newest epoch.
    expect(await resumeOn(on3.ctx, frame)).toEqual([{ ...refused[0], continue: true }]);
    await reconnect(f, 5);
    const on5 = frameCtx(f, 5);
    expect(await resumeOn(on5.ctx, frame)).toEqual([{ ...refused[0], continue: true }]);
    const rows = await protectedRows(op.id);
    expect(rows.operation.dispatchedConnectionEpoch).toBe(5);
    expect(rows.transfers.map((t) => t.sourceEpoch)).toEqual([5]);
    expect(rows.sessions.map((s) => s.hostEpoch)).toEqual([5]);
    // Epoch 3 is stale now.
    const on3Again = frameCtx(f, 3);
    await handleImageUploadParts(on3Again.ctx, parts(transferId, [1]));
    expect(on3Again.replies).toEqual([
      { type: "image.job.cancel", transferId, reason: "stale_transfer" },
    ]);
    await handleImageUploadParts(on5.ctx, parts(transferId, [1]));
    expect(await recorded(transferId)).toEqual([1]);
    // The build cancelled after the adoption: the upload's frames are stale.
    await setOperation(op.id, { state: "CANCEL_REQUESTED" });
    await handleImageUploadParts(on5.ctx, parts(transferId, [2]));
    expect(on5.replies.at(-1)).toEqual({
      type: "image.job.cancel",
      transferId,
      reason: "stale_transfer",
    });
    expect(await recorded(transferId)).toEqual([1]);
  });

  it("W4: a transfer resume whose transfer ends while it is read is refused, and its adoption rolls back", async () => {
    const f = await fixture();
    const { op, transferId } = await storing(f, 40 * MiB);
    await reconnect(f, 2);
    const on2 = frameCtx(f, 2);
    const frame = { type: "image.job.resume", transferId, role: "SOURCE", bytesDone: 0 };
    const before = await protectedRows(op.id);
    // Maintenance expires the transfer and holds its row lock: the resume
    // reads the transfer OPEN and authorized, then waits on that row.
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let locked!: () => void;
    const isLocked = new Promise<void>((resolve) => {
      locked = resolve;
    });
    const maintenance = db.inspect.$transaction(
      async (tx) => {
        await tx.sandboxImageTransfer.update({
          where: { id: transferId },
          data: { state: "EXPIRED", endReason: "expired" },
        });
        locked();
        await held;
      },
      { timeout: 30_000 },
    );
    await isLocked;
    const resumed = resumeOn(on2.ctx, frame);
    for (let tries = 0; ; tries++) {
      const [row] = await db.inspect.$queryRaw<{ n: bigint }[]>`
        SELECT count(*) AS n FROM pg_stat_activity
        WHERE wait_event_type = 'Lock' AND datname = current_database()`;
      if ((row?.n ?? 0n) > 0n) break;
      if (tries > 1000) throw new Error("the resume never waited on the transfer");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    release();
    await maintenance;
    expect(await resumed).toEqual([
      { type: "image.job.resume.result", transferId, continue: false },
    ]);
    const after = await protectedRows(op.id);
    expect(after.operation).toEqual(before.operation);
    expect(after.capture).toEqual(before.capture);
    expect(after.sessions).toEqual(before.sessions);
    expect(after.transfers.map((t) => [t.state, t.sourceEpoch])).toEqual([["EXPIRED", 1]]);
  });

  /** A recorded (STORING) capture of `fingerprint` whose begin the store
   * refused for now (CreateMultipart): its artifact stays UPLOADING. */
  async function refusedBegin(f: F, fingerprint: string) {
    fakeS3.on = true;
    const op = await capture(f, 1);
    const frame = { ...begin(op.id, 1, randomUUID(), fingerprint), sizeBytes: 40 * MiB };
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: op.id },
      data: {
        fingerprint,
        sizeBytes: BigInt(frame.sizeBytes),
        capturedAt: new Date(),
        state: "STORING",
      },
    });
    const refused = Promise.reject(Object.assign(new Error("SlowDown"), { name: "SlowDown" }));
    refused.catch(() => {});
    fakeS3.created.push(refused);
    await handleImageUploadBegin(frameCtx(f).ctx, frame);
    const session = await db.inspect.sandboxImageUploadSession.findFirstOrThrow({
      where: { Transfer: { is: { operationId: op.id } } },
    });
    expect([session.state, session.endReason]).toEqual([
      "ABORTED",
      "begin_retry.store_unavailable",
    ]);
    const artifactId = session.artifactId!;
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: artifactId } }),
    ).toMatchObject({ state: "UPLOADING" });
    return { op, frame, artifactId };
  }
  const artifactOf = (id: string) =>
    db.inspect.sandboxImageArtifact.findUniqueOrThrow({
      where: { id },
      select: { state: true, failureDetail: true },
    });
  const exhausted = (operationId: string) => ({
    type: "image.job.failed" as const,
    operationId,
    attempt: 1,
    code: "cancelled" as const,
    cause: "refused" as const,
    refusal: "store_unavailable",
  });

  it("fix 3 a#3: once a capture's begin retries are exhausted, the artifact they kept UPLOADING is failed (quota released), unless a newer live session owns it", async () => {
    const f = await fixture();
    // The terminal operation-ref report releases it, with the capture's cause.
    const fp1 = fpOf();
    const one = await refusedBegin(f, fp1);
    await handleImageFailure(frameCtx(f).ctx, exhausted(one.op.id));
    const cause = (await captureOf(one.op.id)).errorDetail;
    expect(cause).toMatch(/store_unavailable/);
    expect(await artifactOf(one.artifactId)).toEqual({ state: "FAILED", failureDetail: cause });
    // A publish (or any begin) of that image is no longer blocked: a new
    // begin re-opens the artifact.
    fakeS3.created.push("upload-after-release");
    const again = await capture(f, 1);
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: again.id },
      data: {
        fingerprint: fp1,
        sizeBytes: BigInt(40 * MiB),
        capturedAt: new Date(),
        state: "STORING",
      },
    });
    const reopened = frameCtx(f);
    await handleImageUploadBegin(reopened.ctx, {
      ...begin(again.id, 1, randomUUID(), fp1),
      sizeBytes: 40 * MiB,
    });
    expect(reopened.replies.at(-1)).toMatchObject({ type: "image.upload.grant" });
    expect(await artifactOf(one.artifactId)).toMatchObject({ state: "UPLOADING" });

    // The finalizer's failure path releases it too.
    const two = await refusedBegin(f, fpOf());
    expect(await finalizeCapture(two.op.id)).toEqual({ kind: "waiting" });
    expect(await artifactOf(two.artifactId)).toMatchObject({ state: "UPLOADING" });
    expect(await finalizeCapture(two.op.id, new Date(Date.now() + 3 * 3_600_000))).toMatchObject({
      kind: "failed",
    });
    expect(await artifactOf(two.artifactId)).toEqual({
      state: "FAILED",
      failureDetail: "upload_lost",
    });

    // A newer live session (another job's begin of the same image) owns
    // it: the report leaves it UPLOADING.
    const fp3 = fpOf();
    const three = await refusedBegin(f, fp3);
    const other = await capture(f, 1);
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: other.id },
      data: {
        fingerprint: fp3,
        sizeBytes: BigInt(40 * MiB),
        capturedAt: new Date(),
        state: "STORING",
      },
    });
    fakeS3.created.push("upload-other");
    const live = frameCtx(f);
    await handleImageUploadBegin(live.ctx, {
      ...begin(other.id, 1, randomUUID(), fp3),
      sizeBytes: 40 * MiB,
    });
    expect(live.replies.at(-1)).toMatchObject({ type: "image.upload.grant" });
    await handleImageFailure(frameCtx(f).ctx, exhausted(three.op.id));
    expect((await captureOf(three.op.id)).errorDetail).toMatch(/store_unavailable/);
    expect(await artifactOf(three.artifactId)).toEqual({ state: "UPLOADING", failureDetail: null });
  });

  it("fix 3 a#4: a resume racing a begin-failure cleanup of the same upload takes session then transfer, like the cleanup: no deadlock, the cleanup wins and the resume is refused", async () => {
    const f = await fixture();
    const { op, transferId } = await storing(f, 40 * MiB);
    const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { transferId },
    });
    await reconnect(f, 2);
    const on2 = frameCtx(f, 2);
    // The cleanup (`endTemplateUpload` by session, as a store failure ends
    // a begin) claims the session, then stops before its transfer write
    // until the resume waits on a lock.
    let claimed!: () => void;
    const sessionClaimed = new Promise<void>((resolve) => {
      claimed = resolve;
    });
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const cleanup = db.inspect.$transaction(
      async (tx) => {
        const barrier = new Proxy(tx, {
          get(target, model, receiver) {
            const value = Reflect.get(target, model, receiver);
            if (model !== "sandboxImageTransfer") return value;
            return new Proxy(value as object, {
              get(inner, method, innerReceiver) {
                const call = Reflect.get(inner, method, innerReceiver);
                if (method !== "updateMany" || typeof call !== "function") return call;
                return async (...args: unknown[]) => {
                  claimed();
                  await held;
                  return Reflect.apply(call, inner, args);
                };
              },
            });
          },
        });
        return endTemplateUpload(
          barrier as typeof tx,
          { sessionId: session.id, from: "OPEN" },
          { detail: "store_unavailable" },
        );
      },
      { timeout: 30_000 },
    );
    await sessionClaimed;
    const resumed = resumeOn(on2.ctx, {
      type: "image.job.resume",
      transferId,
      role: "SOURCE",
      bytesDone: 0,
    });
    for (let tries = 0; ; tries++) {
      const [row] = await db.inspect.$queryRaw<{ n: bigint }[]>`
        SELECT count(*) AS n FROM pg_stat_activity
        WHERE wait_event_type = 'Lock' AND datname = current_database()`;
      if ((row?.n ?? 0n) > 0n) break;
      if (tries > 1000) throw new Error("the resume never waited on a lock");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    release();
    // Both finish (a deadlock would abort one of them with an error).
    const [ended, answer] = await Promise.all([cleanup, resumed]);
    expect(ended.ended).toEqual([transferId]);
    expect(answer).toEqual([{ type: "image.job.resume.result", transferId, continue: false }]);
    const transfer = await db.inspect.sandboxImageTransfer.findUniqueOrThrow({
      where: { id: transferId },
    });
    expect([transfer.state, transfer.endReason, transfer.sourceEpoch]).toEqual([
      "FAILED",
      "store_unavailable",
      1,
    ]);
    const after = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
      where: { id: session.id },
    });
    expect([after.state, after.hostEpoch]).toEqual(["ABORTED", session.hostEpoch]);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } }),
    ).toMatchObject({ dispatchedConnectionEpoch: 1 });
  });

  it("W2: a resent begin that supersedes its lost-grant transfer, then is refused for now, leaves the capture waiting; the retried begin is granted", async () => {
    const f = await fixture();
    // T1: granted on epoch 1, its grant lost with the connection.
    const { op, frame, transferId: t1 } = await storing(f, 40 * MiB);
    await reconnect(f, 2);
    const on2 = frameCtx(f, 2);
    expect(
      await resumeOn(on2.ctx, {
        type: "image.job.resume",
        operationId: op.id,
        attempt: 1,
        role: "SOURCE",
        bytesDone: 0,
      }),
    ).toEqual([
      { type: "image.job.resume.result", operationId: op.id, attempt: 1, continue: true },
    ]);
    // The resent begin supersedes T1; the store refuses its multipart for now.
    const refused = Promise.reject(Object.assign(new Error("SlowDown"), { name: "SlowDown" }));
    refused.catch(() => {});
    fakeS3.created.push(refused);
    const resent = frameCtx(f, 2);
    await handleImageUploadBegin(resent.ctx, { ...frame, requestId: randomUUID() });
    expect(resent.replies.at(-1)).toMatchObject({
      type: "image.job.cancel",
      reason: "store_unavailable",
    });
    const transfers = async () =>
      (
        await db.inspect.sandboxImageTransfer.findMany({
          where: { operationId: op.id },
          orderBy: { createdAt: "asc" },
          take: 10,
        })
      ).map((t) => [t.id === t1 ? "T1" : "new", t.state, t.endReason]);
    expect(await transfers()).toEqual([
      ["T1", "CANCELLED", "superseded"],
      ["new", "CANCELLED", "begin_retry.store_unavailable"],
    ]);
    // Neither is the capture's failure: it keeps waiting.
    expect(await finalizeCapture(op.id)).toEqual({ kind: "waiting" });
    expect(await captureOf(op.id)).toMatchObject({ state: "STORING", errorDetail: null });
    // The host's retried begin is granted.
    const retried = frameCtx(f, 2);
    await handleImageUploadBegin(retried.ctx, { ...frame, requestId: randomUUID() });
    const grant = retried.replies.at(-1) as UploadGrant;
    expect(grant).toMatchObject({ type: "image.upload.grant" });
    expect(await finalizeCapture(op.id)).toEqual({ kind: "waiting" });
    // Bounded by G: a job whose transfers all ended as bookkeeping fails
    // `upload_lost` once that runs out.
    await db.inspect.sandboxImageTransfer.update({
      where: { id: grant.transferId },
      data: { state: "CANCELLED", endReason: "superseded" },
    });
    expect(await finalizeCapture(op.id)).toEqual({ kind: "waiting" });
    expect(await finalizeCapture(op.id, new Date(Date.now() + 3 * 3_600_000))).toMatchObject({
      kind: "failed",
    });
    expect(await captureOf(op.id)).toMatchObject({ errorDetail: "upload_lost" });
  });

  it("W5: a publish begin the store refuses ends the publish and its artifact FAILED with the cause (backfill retries it); nothing waits UPLOADING", async () => {
    const f = await fixture();
    // The second round begins the image whose artifact the first failed:
    // a FAILED artifact is what backfill begins again.
    const fingerprint = f.fingerprint;
    for (const stage of ["create", "presign"] as const) {
      fakeS3.on = true;
      const transfer = await db.inspect.sandboxImageTransfer.create({
        data: {
          userId: f.ownerId,
          fingerprint,
          purpose: "PUBLISH",
          mode: "S3",
          sourceHostId: f.source.id,
          sourceHostOwnerId: f.ownerId,
          sourceEpoch: 1,
          sizeBytes: 4096n,
          partSize: 4096,
          partCount: 1,
          expiresAt: new Date(Date.now() + 3_600_000),
        },
      });
      if (stage === "create") {
        const refused = Promise.reject(Object.assign(new Error("SlowDown"), { name: "SlowDown" }));
        refused.catch(() => {});
        fakeS3.created.push(refused);
      } else {
        fakeS3.created.push("upload-publish");
        fakeS3.presignError = Object.assign(new Error("CredentialsProviderError"), {
          name: "CredentialsProviderError",
        });
      }
      const { ctx, replies } = frameCtx(f);
      await handleImageUploadBegin(
        { ...ctx, sender: { ...ctx.sender, hostId: f.source.id } },
        {
          type: "image.upload.begin",
          transferId: transfer.id,
          fingerprint,
          sizeBytes: 4096,
          format: "unified",
        },
      );
      expect(replies).toEqual([
        { type: "image.job.cancel", transferId: transfer.id, reason: "store_unavailable" },
      ]);
      expect(
        await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transfer.id } }),
      ).toMatchObject({ state: "FAILED", endReason: "store_unavailable" });
      const session = await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({
        where: { transferId: transfer.id },
      });
      expect(session).toMatchObject({ state: "ABORTED", liveArtifactId: null });
      expect(
        await db.inspect.sandboxImageArtifact.findUniqueOrThrow({
          where: { id: session.artifactId! },
        }),
      ).toMatchObject({ state: "FAILED", failureDetail: "store_unavailable" });
      if (stage === "presign") expect(fakeS3.calls).toContain("abort:upload-publish");
    }
  });

  it("V1: a recorded capture with no transfer yet resumes by operation only on its own host, owner, attempt and live dispatch, then its begin is granted on the new epoch; refusals change nothing", async () => {
    const f = await fixture();
    fakeS3.on = true;
    const op = await capture(f, 1);
    await reconnect(f, 2);
    const on2 = frameCtx(f, 2);
    const frame = {
      type: "image.job.resume",
      operationId: op.id,
      attempt: 1,
      role: "SOURCE",
      bytesDone: 0,
    };
    const answer = (proceed: boolean, attempt = 1) => [
      { type: "image.job.resume.result", operationId: op.id, attempt, continue: proceed },
    ];
    // Before it, a begin on the new connection is stale.
    const early = frameCtx(f, 2);
    await handleImageUploadBegin(early.ctx, begin(op.id, 1));
    expect(early.replies.at(-1)).toMatchObject({
      type: "image.job.cancel",
      reason: "stale_capture",
    });
    await db.inspect.sandboxHost.update({
      where: { id: f.source.id },
      data: { connectionEpoch: 2 },
    });
    const cases: Array<{
      name: string;
      ctx: ReturnType<typeof frameCtx>["ctx"];
      frame?: Record<string, unknown>;
      arrange?: () => Promise<unknown>;
      restore?: () => Promise<unknown>;
    }> = [
      {
        name: "another host",
        ctx: { ...on2.ctx, sender: { ...on2.ctx.sender, hostId: f.source.id } },
      },
      {
        name: "another owner",
        ctx: { ...on2.ctx, sender: { ...on2.ctx.sender, userId: `other-${randomUUID()}` } },
      },
      {
        name: "a superseded connection",
        ctx: { ...on2.ctx, sender: { ...on2.ctx.sender, isCurrent: () => false } },
      },
      { name: "another attempt", ctx: on2.ctx, frame: { ...frame, attempt: 2 } },
      {
        name: "a cancel request",
        ctx: on2.ctx,
        arrange: () => setOperation(op.id, { state: "CANCEL_REQUESTED" }),
        restore: () => setOperation(op.id, { state: "RUNNING" }),
      },
      {
        name: "a terminal operation",
        ctx: on2.ctx,
        arrange: () => setOperation(op.id, { state: "FAILED" }),
        restore: () => setOperation(op.id, { state: "RUNNING" }),
      },
      {
        name: "a newer dispatch epoch",
        ctx: on2.ctx,
        arrange: () => setOperation(op.id, { dispatchedConnectionEpoch: 3 }),
        restore: () => setOperation(op.id, { dispatchedConnectionEpoch: 1 }),
      },
      {
        name: "an unrecorded capture the reconnect did not adopt",
        ctx: on2.ctx,
        arrange: () =>
          db.inspect.sandboxTemplateCapture.update({
            where: { operationId: op.id },
            data: { state: "PENDING" },
          }),
        restore: () =>
          db.inspect.sandboxTemplateCapture.update({
            where: { operationId: op.id },
            data: { state: "CAPTURED" },
          }),
      },
    ];
    for (const c of cases) {
      await c.arrange?.();
      const before = await protectedRows(op.id);
      const sent = (c.frame ?? frame) as { attempt: number };
      expect(await resumeOn(c.ctx, c.frame ?? frame), c.name).toEqual(answer(false, sent.attempt));
      expect(await protectedRows(op.id), c.name).toEqual(before);
      await c.restore?.();
    }
    expect(await resumeOn(on2.ctx, frame)).toEqual(answer(true));
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } }))
        .dispatchedConnectionEpoch,
    ).toBe(2);
    // Resumed again on the same connection: still yes, nothing moves.
    expect(await resumeOn(on2.ctx, frame)).toEqual(answer(true));
    const granted = frameCtx(f, 2);
    await handleImageUploadBegin(granted.ctx, begin(op.id, 1));
    expect(granted.replies.at(-1)).toMatchObject({ type: "image.upload.grant" });
    const transfer = await db.inspect.sandboxImageTransfer.findFirstOrThrow({
      where: { operationId: op.id, state: "OPEN" },
    });
    expect(transfer.sourceEpoch).toBe(2);
  });
});
