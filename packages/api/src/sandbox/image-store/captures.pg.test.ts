vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "captures-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
/** S3 mode and a fake store for the storage-wait tests; peer otherwise. */
const store = vi.hoisted(() => ({ s3: false, aborted: [] as string[] }));
vi.mock("./config", async (original) => ({
  ...(await original<typeof import("./config")>()),
  imageDistributionMode: () => (store.s3 ? "s3" : "peer"),
}));
vi.mock("./s3", async (original) => ({
  ...(await original<typeof import("./s3")>()),
  imageStore: () =>
    store.s3
      ? {
          abortMultipart: async (_key: string, uploadId: string) => {
            store.aborted.push(uploadId);
          },
        }
      : null,
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { lockOwnerPlacement } from "../direct-placement";
import { toOperationDto } from "../sdk-reads";
import {
  seedAcceptedOperation,
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../testing/resource-fixtures";
import {
  captureHold,
  captureSandbox,
  finalizeCapture,
  recordCaptureResult,
  sweepCaptures,
  UPLOAD_STALL_MS,
  uploadLostAfterMs,
} from "./captures";
import { endTemplateUpload } from "./store-failure";

const db = await pgTestDatabase();
afterAll(() => db.close());

const FEATURES = {
  egressPolicy: true,
  terminal: true,
  image: {
    fetch: true,
    serve: true,
    publish: true,
    capture: true,
    acceptForeign: false,
    leaseFromReady: true,
    captureStorageMarkers: [],
  },
};

async function fixture() {
  const ownerId = randomUUID();
  await db.inspect.user.create({
    data: { id: ownerId, name: "O", email: `${ownerId}@example.test`, twoFactorEnabled: true },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "cap",
      label: "cap",
      status: "CONNECTED",
      egressEnforcement: true,
      daemonFeatures: FEATURES,
      imageCacheEpoch: 1,
      imageCacheCapBytes: 1n << 34n,
      imageCacheUsedBytes: 0n,
      imageCacheForeignBytes: 0n,
    },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"1".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: ownerId,
      templateId: revision.id,
      sandboxHostId: host.id,
      originHostId: host.id,
      state: "STOPPED",
      // Smaller than the base revision's 32 GiB default (E1-A-04).
      diskGiB: 16,
    },
  });
  await db.inspect.sandboxTemplate.update({
    where: { id: revision.templateId },
    data: { captureKeep: 1 },
  });
  const owner = { kind: "session" as const, ownerId };
  const counters = async () => {
    const h = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } });
    const p = await db.inspect.sandboxHostStoragePool.findFirstOrThrow({
      where: { sandboxHostId: host.id },
    });
    return { memory: h.memoryReservedMiB, vcpu: h.vcpuReserved, disk: p.diskReservedGiB };
  };
  return { ownerId, owner, host, revision, sandbox, counters };
}

const fp = (n: number) => `sha256:${String(n).padStart(64, "0")}`;

async function capture(f: Awaited<ReturnType<typeof fixture>>, tag = "nightly") {
  const { operationId } = await captureSandbox(f.owner, {
    id: f.sandbox.id,
    idempotencyKey: randomUUID(),
    tag,
  });
  return operationId;
}

async function hostResult(f: Awaited<ReturnType<typeof fixture>>, operationId: string, n: number) {
  return db.inspect.$transaction((tx) =>
    recordCaptureResult(tx, {
      operationId,
      hostId: f.host.id,
      epoch: 1,
      result: { fingerprint: fp(n), sizeBytes: 4096, architecture: "x86_64" },
    }),
  );
}

describe("capture disk minimum and default", () => {
  it("a capture's floor is the sandbox's disk; an explicit default is kept and one below the floor is refused", async () => {
    const f = await fixture();
    await expect(
      captureSandbox(f.owner, {
        id: f.sandbox.id,
        idempotencyKey: randomUUID(),
        tag: "nightly",
        defaultDiskGiB: 8,
      }),
    ).rejects.toMatchObject({ data: { code: "sandbox.disk_below_image" } });
    const { operationId } = await captureSandbox(f.owner, {
      id: f.sandbox.id,
      idempotencyKey: randomUUID(),
      tag: "nightly",
      defaultDiskGiB: 24,
    });
    await db.inspect.sandboxOperation.update({
      where: { id: operationId },
      data: { state: "ACCEPTED" },
    });
    expect(await hostResult(f, operationId, 7)).toBe(true);
    const outcome = await finalizeCapture(operationId);
    expect(outcome.kind).toBe("finalized");
    expect(
      await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
        where: { id: outcome.kind === "finalized" ? outcome.revisionId : "" },
        select: { minDiskGiB: true, defaultDiskGiB: true },
      }),
    ).toEqual({ minDiskGiB: 16, defaultDiskGiB: 24 });
  });
});

describe("capture lifecycle against real PostgreSQL", () => {
  it("acceptance → host result → finalizer: revision, availability, artifact, tag, retention, hold released exactly once", async () => {
    const f = await fixture();
    const before = await f.counters();
    const hold = captureHold(f.sandbox.diskGiB);
    const first = await capture(f);
    expect(await f.counters()).toEqual({
      memory: before.memory + hold.memoryMiB,
      vcpu: before.vcpu + hold.vcpu,
      disk: before.disk + hold.diskGiB,
    });
    const row = await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
      where: { operationId: first },
    });
    expect(row).toMatchObject({ state: "PENDING", resourcesHeld: true, stoppedCapture: true });
    // A second capture of the same sandbox (or host) is busy.
    await expect(capture(f)).rejects.toMatchObject({ data: { code: "sandbox.capture_busy" } });
    // Reconnect is refused while the stopped root is being copied (M2).
    expect(await finalizeCapture(first)).toEqual({ kind: "waiting" });

    // The outbox dispatched it and the host accepted it before the result.
    await db.inspect.sandboxOperation.update({ where: { id: first }, data: { state: "ACCEPTED" } });
    expect(await hostResult(f, first, 1)).toBe(true);
    const running = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: first } });
    expect(running).toMatchObject({ state: "RUNNING", progressPhase: "finalizing" });
    // OD-1: the source could reach guest root, so the revision is tainted.
    await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { guestRoot: true } });
    const outcome = await finalizeCapture(first);
    expect(outcome.kind).toBe("finalized");
    const revisionId = outcome.kind === "finalized" ? outcome.revisionId : "";
    const revision = await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
      where: { id: revisionId },
    });
    expect(revision).toMatchObject({
      sourceKind: "CAPTURE",
      parentRevisionId: f.revision.id,
      capturedFromSandboxId: f.sandbox.id,
      captureTag: "nightly",
      incusFingerprint: fp(1),
      revision: 2,
      // The image is the captured VM's 16 GiB root (its floor); creates
      // still default to the parent's 32 GiB.
      minDiskGiB: 16,
      defaultDiskGiB: 32,
      capturedWithGuestRoot: true,
      builtWithWsspRecipe: false,
    });
    expect(
      await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
        where: { revisionId, hostId: f.host.id },
      }),
    ).toMatchObject({ status: "AVAILABLE", verifiedConnectionEpoch: 1, sizeBytes: 4096n });
    expect(
      await db.inspect.sandboxImageArtifact.findFirstOrThrow({
        where: { userId: f.ownerId, fingerprint: fp(1) },
      }),
    ).toMatchObject({ storeKind: "PEER", state: "LOCAL" });
    expect(
      await db.inspect.sandboxTemplateTag.findFirstOrThrow({
        where: { templateId: f.revision.templateId, tag: "nightly" },
      }),
    ).toMatchObject({ revisionId });
    const done = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: first },
      include: { Capture: { select: { revisionId: true } } },
    });
    expect(done.state).toBe("SUCCEEDED");
    expect(toOperationDto(done).capturedRevisionId).toBe(revisionId);
    expect(await f.counters()).toEqual(before);
    // Finalizing again changes nothing: the hold is released exactly once.
    expect(await finalizeCapture(first)).toEqual({ kind: "skipped" });
    expect(await f.counters()).toEqual(before);

    // A second capture under the same tag retires the first (captureKeep 1).
    const second = await capture(f);
    await hostResult(f, second, 2);
    const next = await finalizeCapture(second);
    expect(next.kind).toBe("finalized");
    expect(
      await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({ where: { id: revisionId } }),
    ).toMatchObject({ retiredReason: "retention" });
    expect(await f.counters()).toEqual(before);
  });

  it("a finalizer failure (template archived) fails the capture, releases the hold and reports the fingerprint for image.release", async () => {
    const f = await fixture();
    const before = await f.counters();
    const op = await capture(f);
    await hostResult(f, op, 3);
    await db.inspect.sandboxTemplate.update({
      where: { id: f.revision.templateId },
      data: { archivedAt: new Date() },
    });
    const outcomes = await sweepCaptures();
    expect(outcomes.find((o) => o.operationId === op)?.outcome).toEqual({
      kind: "failed",
      fingerprint: fp(3),
      hostId: f.host.id,
      ownerId: f.ownerId,
    });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op } }),
    ).toMatchObject({ state: "FAILED", errorCode: "capture_failed" });
    expect(await f.counters()).toEqual(before);
  });

  it("a host that fails the capture before a result releases the hold once", async () => {
    const f = await fixture();
    const before = await f.counters();
    const op = await capture(f);
    await db.inspect.sandboxOperation.update({
      where: { id: op },
      data: { state: "FAILED", errorCode: "capture_failed" },
    });
    expect(await finalizeCapture(op)).toEqual({
      kind: "failed",
      fingerprint: null,
      hostId: f.host.id,
      ownerId: f.ownerId,
    });
    expect(await finalizeCapture(op)).toEqual({ kind: "skipped" });
    expect(await f.counters()).toEqual(before);
  });
});

describe("the storage wait ends every capture with a cause (I1)", () => {
  afterEach(() => {
    store.s3 = false;
    store.aborted = [];
  });
  const MIN = 60_000;

  /** A recorded capture waiting in S3 mode (STORING); its clock and image. */
  async function storing(f: Awaited<ReturnType<typeof fixture>>, n: number) {
    store.s3 = true;
    const operationId = await capture(f);
    await db.inspect.sandboxOperation.update({
      where: { id: operationId },
      data: { state: "ACCEPTED", dispatchAttempt: 1 },
    });
    await hostResult(f, operationId, n);
    expect(await finalizeCapture(operationId)).toEqual({ kind: "waiting" });
    const row = await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
      where: { operationId },
    });
    expect(row.state).toBe("STORING");
    expect(row.capturedAt).not.toBeNull();
    return { operationId, fingerprint: fp(n), capturedAt: row.capturedAt! };
  }

  /** This capture's upload as the begin opens it: artifact, transfer, session. */
  async function upload(
    f: Awaited<ReturnType<typeof fixture>>,
    c: { operationId: string; fingerprint: string },
    transfer: { state?: "OPEN" | "FAILED"; endReason?: string; lastProgressAt?: Date } = {},
  ) {
    const artifact = await db.inspect.sandboxImageArtifact.create({
      data: {
        userId: f.ownerId,
        fingerprint: c.fingerprint,
        architecture: "x86_64",
        sizeBytes: 4096n,
        storeKind: "S3",
        state: "UPLOADING",
        uploadedByHostId: f.host.id,
        lastProgressAt: new Date(),
      },
    });
    const row = await db.inspect.sandboxImageTransfer.create({
      data: {
        userId: f.ownerId,
        fingerprint: c.fingerprint,
        artifactId: artifact.id,
        purpose: "CAPTURE_UPLOAD",
        mode: "S3",
        sourceHostId: f.host.id,
        sourceHostOwnerId: f.ownerId,
        sourceEpoch: 1,
        operationId: c.operationId,
        dispatchAttempt: 1,
        sizeBytes: 4096n,
        partSize: 4096,
        partCount: 1,
        expiresAt: new Date(Date.now() + 24 * 60 * MIN),
        state: transfer.state ?? "OPEN",
        endReason: transfer.endReason ?? null,
        ...(transfer.lastProgressAt ? { lastProgressAt: transfer.lastProgressAt } : {}),
      },
    });
    const session = await db.inspect.sandboxImageUploadSession.create({
      data: {
        transferId: row.id,
        artifactId: artifact.id,
        liveArtifactId: artifact.id,
        userId: f.ownerId,
        hostId: f.host.id,
        hostEpoch: 1,
        dispatchAttempt: 1,
        objectKey: `test/${randomUUID()}`,
        uploadId: `upload-${randomUUID()}`,
        sizeBytes: 4096n,
        storedBytes: 4096n,
        partSize: 4096,
      },
    });
    return { artifact, transfer: row, session };
  }

  const captureRow = (operationId: string) =>
    db.inspect.sandboxTemplateCapture.findUniqueOrThrow({ where: { operationId } });

  it("the incident state (transfer FAILED, session OPEN, artifact UPLOADING, capture STORING) fails in one sweep", async () => {
    const f = await fixture();
    const before = await f.counters();
    const c = await storing(f, 101);
    await upload(f, c, { state: "FAILED", endReason: "io" });
    const outcomes = await sweepCaptures();
    expect(outcomes.find((o) => o.operationId === c.operationId)?.outcome).toMatchObject({
      kind: "failed",
      fingerprint: c.fingerprint,
    });
    expect(await captureRow(c.operationId)).toMatchObject({
      state: "FAILED",
      errorCode: "capture_store_failed",
      errorDetail: "upload_io",
    });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: c.operationId } }),
    ).toMatchObject({ state: "FAILED", errorCode: "capture_store_failed" });
    expect(await f.counters()).toEqual(before);
  });

  it("a host-reported detail fails the capture with that detail", async () => {
    const f = await fixture();
    const c = await storing(f, 102);
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: c.operationId },
      data: { errorDetail: "upload_refused.image_quota_exceeded" },
    });
    expect(await finalizeCapture(c.operationId)).toMatchObject({ kind: "failed" });
    expect(await captureRow(c.operationId)).toMatchObject({
      errorCode: "capture_store_failed",
      errorDetail: "upload_refused.image_quota_exceeded",
    });
  });

  it("upload_lost fires once no upload began within 15 min + 2 min/GiB, and not before", async () => {
    const f = await fixture();
    const c = await storing(f, 103);
    const lost = uploadLostAfterMs(4096n);
    expect(lost).toBe(17 * MIN);
    expect(uploadLostAfterMs(10n * 1_073_741_824n)).toBe(35 * MIN);
    const at = (ms: number) => new Date(c.capturedAt.getTime() + ms);
    expect(await finalizeCapture(c.operationId, at(lost - MIN))).toEqual({ kind: "waiting" });
    expect(await finalizeCapture(c.operationId, at(lost + MIN))).toMatchObject({
      kind: "failed",
    });
    expect(await captureRow(c.operationId)).toMatchObject({
      state: "FAILED",
      errorDetail: "upload_lost",
    });
  });

  it("an open upload is never lost; one silent past 10 min is stalled and ended on the server", async () => {
    const f = await fixture();
    const c = await storing(f, 104);
    const t0 = new Date();
    const { artifact, transfer, session } = await upload(f, c, { lastProgressAt: t0 });
    const at = (ms: number) => new Date(t0.getTime() + ms);
    // Moving recently: waiting, even far past the lost bound.
    expect(await finalizeCapture(c.operationId, at(UPLOAD_STALL_MS - MIN))).toEqual({
      kind: "waiting",
    });
    const outcome = await finalizeCapture(c.operationId, at(UPLOAD_STALL_MS + MIN));
    expect(outcome).toMatchObject({
      kind: "failed",
      cancels: [{ transferId: transfer.id, hostId: f.host.id, epoch: 1, reason: "upload_stalled" }],
    });
    expect(await captureRow(c.operationId)).toMatchObject({
      state: "FAILED",
      errorDetail: "upload_stalled",
    });
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transfer.id } }),
    ).toMatchObject({ state: "FAILED", endReason: "upload_stalled" });
    expect(
      await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({ where: { id: session.id } }),
    ).toMatchObject({ state: "ABORTED", liveArtifactId: null, uploadId: null });
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: artifact.id } }),
    ).toMatchObject({ state: "FAILED", failureDetail: "upload_stalled" });
    expect(store.aborted).toEqual([session.uploadId]);
  });

  it("a stalled upload whose completion claims the session first is not failed: the capture waits", async () => {
    const f = await fixture();
    const c = await storing(f, 106);
    const t0 = new Date(Date.now() - UPLOAD_STALL_MS - 5 * MIN);
    const { artifact, transfer, session } = await upload(f, c, { lastProgressAt: t0 });
    // The completion's claim (session, artifact, transfer) is in flight,
    // parked before its commit.
    const completionCommit = db.pauseAt("completion", { before: "$transaction.commit" });
    const completion = db.run("completion", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.sandboxImageUploadSession.update({
          where: { id: session.id },
          data: { state: "COMPLETE", liveArtifactId: null, endReason: "uploaded" },
        });
        await tx.sandboxImageArtifact.update({
          where: { id: artifact.id },
          data: { state: "VERIFYING" },
        });
        await tx.sandboxImageTransfer.update({
          where: { id: transfer.id },
          data: { state: "COMPLETE", endReason: "uploaded" },
        });
      }),
    );
    await completionCommit.waitReached();
    const finalizing = db.run("finalizer", () => finalizeCapture(c.operationId));
    // The stall rule's claim waits on the session the completion holds.
    const blocked = await db.waitUntilBlocked("finalizer", { by: "completion" });
    expect(blocked.query).toContain("sandbox_image_upload_session");
    completionCommit.release();
    await completion;
    expect(await finalizing).toEqual({ kind: "waiting" });
    expect(await captureRow(c.operationId)).toMatchObject({ state: "STORING", errorDetail: null });
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transfer.id } }),
    ).toMatchObject({ state: "COMPLETE", endReason: "uploaded" });
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: artifact.id } }),
    ).toMatchObject({ state: "VERIFYING", failureDetail: null });
    expect(store.aborted).toEqual([]);
  });

  it("a capture that fails storing ends its own open upload with the same cause", async () => {
    const f = await fixture();
    const c = await storing(f, 107);
    const { artifact, transfer, session } = await upload(f, c, { lastProgressAt: new Date() });
    // A host report recorded by operation while the server had an upload open.
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: c.operationId },
      data: { errorDetail: "upload_no_grant" },
    });
    expect(await finalizeCapture(c.operationId)).toMatchObject({
      kind: "failed",
      cancels: [{ transferId: transfer.id, reason: "upload_no_grant" }],
    });
    expect(
      await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transfer.id } }),
    ).toMatchObject({ state: "FAILED", endReason: "upload_no_grant" });
    expect(
      await db.inspect.sandboxImageUploadSession.findUniqueOrThrow({ where: { id: session.id } }),
    ).toMatchObject({ state: "ABORTED", endReason: "upload_no_grant", uploadId: null });
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: artifact.id } }),
    ).toMatchObject({ state: "FAILED", failureDetail: "upload_no_grant" });
    expect(store.aborted).toEqual([session.uploadId]);
  });

  it("the cause precedence: the capture's own cause, else the artifact's, else CORRUPT → store_verify_failed, else store_failed", async () => {
    const rows: Array<{
      artifact: "CORRUPT" | "FAILED" | "DELETED";
      failureDetail: string | null;
      captureDetail: string | null;
      want: string;
    }> = [
      {
        artifact: "FAILED",
        failureDetail: "store_complete_failed",
        captureDetail: "upload_reset",
        want: "upload_reset",
      },
      {
        artifact: "CORRUPT",
        failureDetail: null,
        captureDetail: "upload_reset",
        want: "upload_reset",
      },
      {
        artifact: "FAILED",
        failureDetail: "upload_http_503",
        captureDetail: null,
        want: "upload_http_503",
      },
      {
        artifact: "DELETED",
        failureDetail: "upload_stale",
        captureDetail: null,
        want: "upload_stale",
      },
      {
        artifact: "CORRUPT",
        failureDetail: null,
        captureDetail: null,
        want: "store_verify_failed",
      },
      { artifact: "FAILED", failureDetail: null, captureDetail: null, want: "store_failed" },
      { artifact: "DELETED", failureDetail: null, captureDetail: null, want: "store_failed" },
    ];
    let n = 200;
    for (const row of rows) {
      const f = await fixture();
      const c = await storing(f, n++);
      const { artifact } = await upload(f, c, { lastProgressAt: new Date() });
      await db.inspect.sandboxImageArtifact.update({
        where: { id: artifact.id },
        data: { state: row.artifact, failureDetail: row.failureDetail },
      });
      // Another job's ended upload of the same image is never this capture's cause.
      await db.inspect.sandboxImageTransfer.create({
        data: {
          userId: f.ownerId,
          fingerprint: c.fingerprint,
          artifactId: artifact.id,
          purpose: "PUBLISH",
          mode: "S3",
          sourceHostId: f.host.id,
          sourceHostOwnerId: f.ownerId,
          sourceEpoch: 1,
          sizeBytes: 4096n,
          partSize: 4096,
          partCount: 1,
          expiresAt: new Date(Date.now() + 60 * MIN),
          state: "FAILED",
          endReason: "upload_tls",
        },
      });
      if (row.captureDetail)
        await db.inspect.sandboxTemplateCapture.update({
          where: { operationId: c.operationId },
          data: { errorDetail: row.captureDetail },
        });
      expect(await finalizeCapture(c.operationId)).toMatchObject({ kind: "failed" });
      expect(await captureRow(c.operationId), JSON.stringify(row)).toMatchObject({
        state: "FAILED",
        errorCode: "capture_store_failed",
        errorDetail: row.want,
      });
    }
  });

  it("two concurrent finalizers settle a capture once (the state is re-checked under the locks)", async () => {
    const f = await fixture();
    const operationId = await capture(f);
    await db.inspect.sandboxOperation.update({
      where: { id: operationId },
      data: { state: "ACCEPTED", dispatchAttempt: 1 },
    });
    await hostResult(f, operationId, 108);
    const before = await db.inspect.sandboxTemplateRevision.count({
      where: { templateId: f.revision.templateId },
    });
    // Both finalizers read the capture (CAPTURED) before either locks: a
    // holder of the owner's placement lock parks them both behind it.
    const holderCommit = db.pauseAt("holder", { before: "$transaction.commit" });
    const holder = db.run("holder", () =>
      db.prisma.$transaction((tx) => lockOwnerPlacement(tx, f.ownerId)),
    );
    await holderCommit.waitReached();
    const first = db.run("first", () => finalizeCapture(operationId));
    const second = db.run("second", () => finalizeCapture(operationId));
    await db.waitUntilBlocked("first", { by: "holder" });
    await db.waitUntilBlocked("second", { by: "holder" });
    holderCommit.release();
    await holder;
    const outcomes = await Promise.all([first, second]);
    expect(outcomes.map((o) => o.kind).sort()).toEqual(["finalized", "skipped"]);
    expect(
      await db.inspect.sandboxTemplateRevision.count({
        where: { templateId: f.revision.templateId },
      }),
    ).toBe(before + 1);
  });

  it("the sweep rotates a capture whose finalize throws, and logs it without row data", async () => {
    const f = await fixture();
    const c = await storing(f, 109);
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const original = db.prisma.sandboxTemplateCapture.findUnique.bind(
      db.prisma.sandboxTemplateCapture,
    );
    const lookup = vi
      .spyOn(db.prisma.sandboxTemplateCapture, "findUnique")
      .mockImplementation(((args: { where: { operationId?: string } }) =>
        args.where.operationId === c.operationId
          ? Promise.reject(new Error(`boom ${c.fingerprint}`))
          : original(args as never)) as never);
    try {
      // The oldest waiter: first on the sweep's page.
      const before = new Date("2000-01-01T00:00:00Z");
      await db.inspect.sandboxTemplateCapture.update({
        where: { operationId: c.operationId },
        data: { updatedAt: before },
      });
      const now = new Date(Date.now() + MIN);
      const outcomes = await sweepCaptures(now);
      expect(outcomes.find((o) => o.operationId === c.operationId)?.outcome).toEqual({
        kind: "skipped",
      });
      const after = (await captureRow(c.operationId)).updatedAt;
      expect(after.getTime()).toBeGreaterThan(before.getTime());
      const logged = errors.mock.calls.map((call) => String(call[0])).join("\n");
      expect(logged).toContain("capture_finalize_failed");
      expect(logged).toContain(c.operationId);
      expect(logged).not.toContain(c.fingerprint);
    } finally {
      lookup.mockRestore();
      errors.mockRestore();
    }
  });

  it("endTemplateUpload ends only a session it claims: a superseded one never fails the artifact a new upload re-opened", async () => {
    const f = await fixture();
    const c = await storing(f, 110);
    const { artifact, session } = await upload(f, c, { state: "FAILED", endReason: "io" });
    // A begin superseded the dead session and re-opened the artifact.
    await db.inspect.sandboxImageUploadSession.update({
      where: { id: session.id },
      data: { state: "ABORTED", liveArtifactId: null, endReason: "superseded" },
    });
    const fresh = await db.inspect.sandboxImageTransfer.create({
      data: {
        userId: f.ownerId,
        fingerprint: c.fingerprint,
        artifactId: artifact.id,
        purpose: "CAPTURE_UPLOAD",
        mode: "S3",
        sourceHostId: f.host.id,
        sourceHostOwnerId: f.ownerId,
        sourceEpoch: 1,
        operationId: c.operationId,
        dispatchAttempt: 1,
        sizeBytes: 4096n,
        partSize: 4096,
        partCount: 1,
        expiresAt: new Date(Date.now() + 60 * MIN),
      },
    });
    await db.inspect.sandboxImageUploadSession.create({
      data: {
        transferId: fresh.id,
        artifactId: artifact.id,
        liveArtifactId: artifact.id,
        userId: f.ownerId,
        hostId: f.host.id,
        hostEpoch: 1,
        dispatchAttempt: 1,
        objectKey: `test/${randomUUID()}`,
        uploadId: `upload-${randomUUID()}`,
        sizeBytes: 4096n,
        storedBytes: 4096n,
        partSize: 4096,
      },
    });
    // The hourly sweep's stale view of the dead session.
    const end = await db.inspect.$transaction((tx) =>
      endTemplateUpload(tx, { sessionId: session.id }, { detail: "upload_io" }),
    );
    expect(end).toEqual({ aborts: [], cancels: [], ended: [], sessions: [] });
    expect(
      await db.inspect.sandboxImageArtifact.findUniqueOrThrow({ where: { id: artifact.id } }),
    ).toMatchObject({ state: "UPLOADING", failureDetail: null });
    expect(await captureRow(c.operationId)).toMatchObject({ state: "STORING", errorDetail: null });
  });

  it("endTemplateUpload records evidence only for the capture's current attempt, and never over an earlier cause", async () => {
    const f = await fixture();
    const c = await storing(f, 111);
    const first = await upload(f, c, { lastProgressAt: new Date() });
    await db.inspect.sandboxOperation.update({
      where: { id: c.operationId },
      data: { dispatchAttempt: 2 },
    });
    const stale = await db.inspect.$transaction((tx) =>
      endTemplateUpload(tx, { transferId: first.transfer.id }, { detail: "upload_reset" }),
    );
    // The stale attempt's upload itself ends, the capture records nothing.
    expect(stale.ended).toEqual([first.transfer.id]);
    expect(await captureRow(c.operationId)).toMatchObject({ errorDetail: null });
    await db.inspect.sandboxTemplateCapture.update({
      where: { operationId: c.operationId },
      data: { errorDetail: "upload_export" },
    });
    await db.inspect.$transaction((tx) =>
      endTemplateUpload(tx, { operationId: c.operationId, attempt: 2 }, { detail: "upload_tls" }),
    );
    expect(await captureRow(c.operationId)).toMatchObject({ errorDetail: "upload_export" });
  });

  it("the absolute bound is 24 h (store_deadline), not 2 h", async () => {
    const f = await fixture();
    const c = await storing(f, 105);
    const op = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: c.operationId },
    });
    const at = (ms: number) => new Date(op.createdAt.getTime() + ms);
    // A live upload keeps progressing (its heartbeat moves lastProgressAt).
    const { transfer } = await upload(f, c, { lastProgressAt: at(3 * 60 * MIN) });
    expect(await finalizeCapture(c.operationId, at(3 * 60 * MIN + MIN))).toEqual({
      kind: "waiting",
    });
    await db.inspect.sandboxImageTransfer.update({
      where: { id: transfer.id },
      data: { lastProgressAt: at(24 * 60 * MIN) },
    });
    expect(await finalizeCapture(c.operationId, at(24 * 60 * MIN - MIN))).toEqual({
      kind: "waiting",
    });
    expect(await finalizeCapture(c.operationId, at(24 * 60 * MIN + MIN))).toMatchObject({
      kind: "failed",
    });
    expect(await captureRow(c.operationId)).toMatchObject({ errorDetail: "store_deadline" });
  });

  it("more than one page of waiting captures is rotated: every one is finalized within the sweeps it needs", async () => {
    const f = await fixture();
    store.s3 = true;
    const ours: string[] = [];
    for (let i = 0; i < 55; i++) {
      const op = await seedAcceptedOperation(db.inspect, {
        data: {
          userId: f.ownerId,
          sandboxId: f.sandbox.id,
          kind: "CAPTURE_TEMPLATE",
          state: "RUNNING",
          generation: 1,
          idempotencyKey: randomUUID(),
          requestBodyHash: "h",
          dispatchedHostId: f.host.id,
          dispatchedConnectionEpoch: 1,
          dispatchAttempt: 1,
        },
      });
      await db.inspect.sandboxTemplateCapture.create({
        data: {
          operationId: op.id,
          userId: f.ownerId,
          sandboxId: f.sandbox.id,
          templateId: f.revision.templateId,
          tag: "rotate",
          hostId: f.host.id,
          hostOwnerId: f.ownerId,
          state: "STORING",
          fingerprint: fp(1000 + i),
          sizeBytes: 4096n,
          architecture: "x86_64",
          capturedAt: new Date(),
        },
      });
      ours.push(op.id);
    }
    const active = await db.inspect.sandboxTemplateCapture.count({
      where: { state: { in: ["PENDING", "CAPTURED", "STORING"] } },
    });
    const seen = new Set<string>();
    for (let sweep = 0; sweep < Math.ceil(active / 50); sweep++)
      for (const { operationId, outcome } of await sweepCaptures()) {
        seen.add(operationId);
        if (ours.includes(operationId)) expect(outcome).toEqual({ kind: "waiting" });
      }
    expect(ours.filter((id) => !seen.has(id))).toEqual([]);
  });
});
