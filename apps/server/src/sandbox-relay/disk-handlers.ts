import { consumeImageGrantBudget } from "@wssp/api/sandbox/budgets";
import { canOffload } from "@wssp/api/sandbox/disk-offload/availability";
import { loginStateSettled } from "@wssp/api/sandbox/disk-offload/eligibility";
import {
  abortDiskSession,
  completeDiskSession,
  DISK_ENCRYPTION_SCHEME,
  generateDiskDek,
  loadDiskObjectKey,
  loadOpenDiskSessionKey,
  newDiskSessionWrap,
} from "@wssp/api/sandbox/disk-offload/keys";
import { GIB, offloadAdmits } from "@wssp/api/sandbox/disk-offload/quota";
import {
  diskStoreObjectKey,
  type EndedOffload,
  endLiveOffload,
  failLiveOffload,
  finishEndedOffload,
  lockSandboxRow,
  newDiskSessionId,
  UPLOADABLE_STATES,
} from "@wssp/api/sandbox/disk-offload/store";
import {
  hostImageFeatures,
  lockImageQuota,
  wakeImageScheduler,
} from "@wssp/api/sandbox/image-store/config";
import {
  IMAGE_ENCRYPTION_SCHEME,
  ImageObjectExistsError,
  type ImageStore,
  imageStore,
} from "@wssp/api/sandbox/image-store/s3";
import { OFFLOADABLE_SANDBOX_PURPOSES } from "@wssp/api/sandbox/managed-sandbox";
import {
  hostDatabaseNow,
  lockHostByEpoch,
  relayTransaction,
  requireRelayFence,
} from "@wssp/api/sandbox/relay-fence";
import prisma, { type Prisma } from "@wssp/db";
import { readImageStoreEnv } from "@wssp/env/image-store-config";
import {
  type DaemonDiskMessage,
  type DaemonImageMessage,
  encryptedImageLength,
  IMAGE_ENCRYPTION_RECORD_BYTES,
  IMAGE_ENCRYPTION_TAG_BYTES,
  IMAGE_S3_PART_BYTES,
  IMAGE_UPLOAD_PARTS_MAX,
  type ServerDiskMessage,
} from "@wssp/sandbox-contracts";
import {
  restoreFetchWorkload,
  transferAuthoritySelect,
  transferAuthorized,
} from "./image-authority.js";
import type { ImageFrameContext } from "./image-handlers.js";
import type { RelaySender } from "./operation-handlers.js";

/**
 * Host-plane disk offload upload frames.
 *
 * Separate from the template upload handlers (R1(a)): a disk object is a
 * `SandboxDiskOffload` row, never a `SandboxImageArtifact`. Every step runs
 * under owner (31, begin only) → host by epoch → sandbox row → offload row,
 * and CASes the offload's source generation with the sandbox still STOPPED
 * on its source host. A disk grant always carries `encryption` (I13): the
 * session's own DEK, drawn fresh at begin and wrapped under the disk root
 * key; it leaves the server only in that grant, never a log, row or frame
 * other than `disk.upload.grant`.
 */
export type DiskFrameContext = {
  sender: RelaySender;
  /** Send to the sender's socket. */
  reply: (frame: ServerDiskMessage) => void;
};

type OffloadRef = { sandboxId: string; offloadId: string; seq: number };

/** S3's part-count ceiling; disk parts grow past 64 records to stay under it. */
const S3_PARTS_MAX = 10_000;
const SEALED_RECORD_BYTES = IMAGE_ENCRYPTION_RECORD_BYTES + IMAGE_ENCRYPTION_TAG_BYTES;
/** Slack over the sandbox's disk size a unified export may declare (R15.6). */
const EXPORT_SLACK_BYTES = GIB;
const SESSION_TTL_MS = 24 * 3_600_000;

/** Ciphertext bytes per part: whole sealed records, at least 64 (64 MiB of
 * plaintext), and few enough parts for S3. */
export function diskPartSize(plainBytes: number): number {
  const records = Math.max(1, Math.ceil(plainBytes / IMAGE_ENCRYPTION_RECORD_BYTES));
  return Math.max(64, Math.ceil(records / S3_PARTS_MAX)) * SEALED_RECORD_BYTES;
}

function partBytes(total: bigint, size: number, part: number): number {
  const start = BigInt(part - 1) * BigInt(size);
  const remaining = total - start;
  return Number(remaining < BigInt(size) ? remaining : BigInt(size));
}

function partCount(storedBytes: bigint, size: number): number {
  return Math.max(1, Math.ceil(Number(storedBytes) / size));
}

async function grantBudget(hostId: string): Promise<boolean> {
  try {
    await consumeImageGrantBudget(hostId);
    return true;
  } catch {
    return false;
  }
}

function cancelFrame(ref: OffloadRef, reason: string): ServerDiskMessage {
  return {
    type: "disk.offload.cancel",
    sandboxId: ref.sandboxId,
    offloadId: ref.offloadId,
    seq: ref.seq,
    reason,
  };
}

/** Presigned part URLs from `from`, with the session's key (I13). */
async function diskGrant(
  store: ImageStore,
  ref: OffloadRef,
  session: {
    id: string;
    transferId: string;
    objectKey: string;
    uploadId: string;
    partSize: number;
    storedBytes: bigint;
  },
  from: number,
  dek: Buffer,
): Promise<ServerDiskMessage> {
  const parts = partCount(session.storedBytes, session.partSize);
  const urls = [];
  for (let n = from; n <= Math.min(parts, from + IMAGE_UPLOAD_PARTS_MAX - 1); n++) {
    const size = partBytes(session.storedBytes, session.partSize, n);
    urls.push({
      n,
      sizeBytes: size,
      url: await store.presignUploadPart(session.objectKey, session.uploadId, n, size),
    });
  }
  return {
    type: "disk.upload.grant",
    sandboxId: ref.sandboxId,
    offloadId: ref.offloadId,
    seq: ref.seq,
    sessionId: session.id,
    transferId: session.transferId,
    partSize: session.partSize,
    parts: urls,
    expiresAtUnixMs: Date.now() + store.settings.presignTtlSeconds * 1000,
    encryption: { scheme: DISK_ENCRYPTION_SCHEME, key: dek.toString("base64") },
  };
}

/** Ends an offload under its sandbox lock (FAILED), then cleans up after commit. */
async function failOffload(
  store: ImageStore | null,
  sandboxId: string,
  offloadId: string,
  code: string,
): Promise<boolean> {
  const ended = await prisma.$transaction(async (tx) => {
    await lockSandboxRow(tx, sandboxId);
    return failLiveOffload(tx, offloadId, code);
  });
  await finishEndedOffload(store, ended);
  return ended !== null;
}

type BeginOutcome =
  | { kind: "cancel"; reason: string; ended?: EndedOffload | null }
  | {
      kind: "grant";
      sessionId: string;
      transferId: string;
      objectKey: string;
      storedBytes: bigint;
      partSize: number;
      dek: Buffer;
    };

type SupersededSession = { id: string; objectKey: string; uploadId: string };

/** The begin's checks and writes (one transaction; see `handleDiskUploadBegin`). */
async function beginInTransaction(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  store: ImageStore,
  m: Extract<DaemonDiskMessage, { type: "disk.upload.begin" }>,
  superseded: SupersededSession[],
): Promise<BeginOutcome> {
  const head = await tx.sandboxDiskOffload.findFirst({
    where: { id: m.offloadId, sandboxId: m.sandboxId },
    select: { userId: true },
  });
  if (!head) return { kind: "cancel", reason: "stale" };
  await lockImageQuota(tx, head.userId);
  await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
  requireRelayFence(sender.isCurrent?.() !== false);
  requireRelayFence(await lockSandboxRow(tx, m.sandboxId));
  const now = await hostDatabaseNow(tx);
  const [offload] = await tx.$queryRaw<
    { state: string; seq: number; sourceGeneration: number; userId: string }[]
  >`SELECT state::text AS state, seq, "sourceGeneration", "userId" FROM sandbox_disk_offload
    WHERE id = ${m.offloadId} AND "sandboxId" = ${m.sandboxId}
      AND "sourceHostId" = ${sender.hostId} AND "sourceHostOwnerId" = ${sender.userId}
      AND "liveSandboxId" IS NOT NULL AND "completedSessionId" IS NULL
    FOR UPDATE`;
  if (
    !offload ||
    !(UPLOADABLE_STATES as readonly string[]).includes(offload.state) ||
    offload.seq !== m.seq ||
    offload.sourceGeneration !== m.generation
  )
    return { kind: "cancel", reason: "stale" };
  const sandbox = await tx.sandbox.findFirst({
    where: {
      id: m.sandboxId,
      userId: offload.userId,
      state: "STOPPED",
      generation: offload.sourceGeneration,
      sandboxHostId: sender.hostId,
      hostOwnerId: sender.userId,
      diskOffloadId: null,
      purpose: { in: [...OFFLOADABLE_SANDBOX_PURPOSES] },
    },
    select: { diskGiB: true, cloudInitInstanceId: true },
  });
  // The sandbox moved on: this attempt can never be stored.
  if (!sandbox)
    return {
      kind: "cancel",
      reason: "superseded",
      ended: await endLiveOffload(tx, m.offloadId, "SUPERSEDED", "superseded"),
    };
  const host = await tx.sandboxHost.findUnique({
    where: { id: sender.hostId },
    select: { daemonDiskOffload: true },
  });
  // `off` stops new offloads (R12); the attempt ends here.
  if (!canOffload(host?.daemonDiskOffload === true))
    return {
      kind: "cancel",
      reason: "offload_disabled",
      ended: await failLiveOffload(tx, m.offloadId, "offload_disabled"),
    };
  if (!(await loginStateSettled(tx, m.sandboxId)))
    return {
      kind: "cancel",
      reason: "login_unsettled",
      ended: await failLiveOffload(tx, m.offloadId, "login_unsettled"),
    };
  if (BigInt(m.sizeBytes) > BigInt(sandbox.diskGiB) * GIB + EXPORT_SLACK_BYTES)
    return {
      kind: "cancel",
      reason: "size_exceeded",
      ended: await failLiveOffload(tx, m.offloadId, "size_exceeded"),
    };
  const live = await tx.sandboxImageUploadSession.findUnique({
    where: { liveDiskOffloadId: m.offloadId },
    select: {
      id: true,
      objectKey: true,
      uploadId: true,
      transferId: true,
      Transfer: { select: { state: true, ...transferAuthoritySelect } },
    },
  });
  if (live) {
    if (live.Transfer.state === "OPEN" && (await transferAuthorized(tx, live.Transfer, now)))
      return { kind: "cancel", reason: "upload_in_progress" };
    // Supersede (S1, S3): state and wrap in one statement.
    await abortDiskSession(tx, live.id, "superseded");
    await tx.sandboxImageTransfer.updateMany({
      where: { id: live.transferId, state: "OPEN" },
      data: { state: "CANCELLED", endReason: "superseded" },
    });
    if (live.uploadId)
      superseded.push({ id: live.id, objectKey: live.objectKey, uploadId: live.uploadId });
  }
  const storedBytes = BigInt(encryptedImageLength(m.sizeBytes));
  if (
    !(await offloadAdmits(tx, {
      ownerId: offload.userId,
      offloadId: m.offloadId,
      storedBytes,
      now,
    }))
  )
    return {
      kind: "cancel",
      reason: "quota_exceeded",
      ended: await failLiveOffload(tx, m.offloadId, "quota_exceeded"),
    };
  const sessionPartSize = diskPartSize(m.sizeBytes);
  const sessionId = newDiskSessionId();
  const settings = store.settings;
  const objectKey = diskStoreObjectKey(settings.prefix, {
    ownerId: offload.userId,
    sandboxId: m.sandboxId,
    offloadId: m.offloadId,
    sessionId,
  });
  const transfer = await tx.sandboxImageTransfer.create({
    data: {
      userId: offload.userId,
      fingerprint: m.fingerprint,
      diskOffloadId: m.offloadId,
      purpose: "OFFLOAD_UPLOAD",
      mode: "S3",
      sourceHostId: sender.hostId,
      sourceHostOwnerId: sender.userId,
      sourceEpoch: sender.connectionEpoch,
      sizeBytes: storedBytes,
      partSize: sessionPartSize,
      partCount: partCount(storedBytes, sessionPartSize),
      expiresAt: new Date(now.getTime() + SESSION_TTL_MS),
    },
    select: { id: true },
  });
  const dek = generateDiskDek();
  try {
    const wrap = await newDiskSessionWrap(
      tx,
      {
        userId: offload.userId,
        sandboxId: m.sandboxId,
        offloadId: m.offloadId,
        seq: offload.seq,
        sessionId,
      },
      dek,
    );
    await tx.sandboxImageUploadSession.create({
      data: {
        id: sessionId,
        transferId: transfer.id,
        diskOffloadId: m.offloadId,
        liveDiskOffloadId: m.offloadId,
        userId: offload.userId,
        hostId: sender.hostId,
        hostEpoch: sender.connectionEpoch,
        objectKey,
        sizeBytes: BigInt(m.sizeBytes),
        storedBytes,
        partSize: sessionPartSize,
        ...wrap,
      },
      select: { id: true },
    });
  } catch (error) {
    dek.fill(0);
    throw error;
  }
  await tx.sandboxDiskOffload.update({
    where: { id: m.offloadId },
    data: { state: "UPLOADING", fingerprint: m.fingerprint, sizeBytes: BigInt(m.sizeBytes) },
    select: { id: true },
  });
  // The instance's cloud-init id, first seen here, is what a restore pins
  // (§7): the restored lineage keeps it, so it is never overwritten.
  if (m.cloudInitInstanceId !== undefined && sandbox.cloudInitInstanceId === null)
    await tx.sandbox.updateMany({
      where: { id: m.sandboxId, cloudInitInstanceId: null },
      data: { cloudInitInstanceId: m.cloudInitInstanceId },
    });
  return {
    kind: "grant",
    sessionId,
    transferId: transfer.id,
    objectKey,
    storedBytes,
    partSize: sessionPartSize,
    dek,
  };
}

/**
 * `disk.upload.begin` (S1): the export finished; open one upload session.
 *
 * Accepted only while the offload is live and PENDING | EXPORTING |
 * UPLOADING with no completed session, from its source host on the current
 * epoch, for its source generation and seq, with the sandbox still STOPPED
 * there and `loginStateSettled` holding (§4). The declared size is bounded by
 * the sandbox's disk (R15.6), the stored quota and the daily spend ledger
 * (R11) → FAILED(quota_exceeded): the disk stays local.
 *
 * A live session of this offload whose transfer is OPEN and still authorized
 * refuses the begin (`upload_in_progress`); any other live session is
 * superseded first (ABORTED, wrap nulled, transfer cancelled, multipart
 * aborted after commit). The new session has its own id, object key and DEK.
 */
export async function handleDiskUploadBegin(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.upload.begin" }>,
): Promise<void> {
  const store = imageStore();
  const { sender } = ctx;
  const cancel = (reason: string) => ctx.reply(cancelFrame(m, reason));
  if (!store) return cancel("store_unavailable");
  if (!(await grantBudget(sender.hostId))) return cancel("rate_limited");
  const { outcome, superseded } = await relayTransaction(
    async (tx) => {
      const superseded: SupersededSession[] = [];
      return {
        outcome: await beginInTransaction(tx, ctx.sender, store, m, superseded),
        superseded,
      };
    },
    {
      outcome: { kind: "cancel", reason: "stale" } as BeginOutcome,
      superseded: [] as SupersededSession[],
    },
  );
  for (const old of superseded)
    await finishEndedOffload(store, {
      offloadId: m.offloadId,
      sandboxId: m.sandboxId,
      userId: "",
      seq: m.seq,
      sourceHostId: sender.hostId,
      objectKey: null,
      sessions: [old],
    });
  if (outcome.kind === "cancel") {
    await finishEndedOffload(store, outcome.ended ?? null);
    return cancel(outcome.reason);
  }
  const { dek } = outcome;
  try {
    let uploadId: string;
    try {
      uploadId = await store.createMultipart(outcome.objectKey);
    } catch {
      await failOffload(store, m.sandboxId, m.offloadId, "store_unavailable");
      return cancel("store_unavailable");
    }
    // Set once, on this session only; it must still be the live one, or the
    // new upload is aborted here (a superseder could not see the id).
    await prisma.sandboxImageUploadSession.updateMany({
      where: { id: outcome.sessionId, uploadId: null },
      data: { uploadId },
    });
    const bound = await prisma.sandboxImageUploadSession.findFirst({
      where: { id: outcome.sessionId, state: "OPEN", uploadId },
      select: { id: true },
    });
    if (!bound) {
      await finishEndedOffload(store, {
        offloadId: m.offloadId,
        sandboxId: m.sandboxId,
        userId: "",
        seq: m.seq,
        sourceHostId: sender.hostId,
        objectKey: null,
        sessions: [{ id: outcome.sessionId, objectKey: outcome.objectKey, uploadId }],
      });
      return cancel("superseded");
    }
    ctx.reply(
      await diskGrant(
        store,
        m,
        {
          id: outcome.sessionId,
          transferId: outcome.transferId,
          objectKey: outcome.objectKey,
          uploadId,
          partSize: outcome.partSize,
          storedBytes: outcome.storedBytes,
        },
        1,
        dek,
      ),
    );
  } finally {
    dek.fill(0);
  }
}

const diskSessionSelect = {
  id: true,
  transferId: true,
  objectKey: true,
  uploadId: true,
  sizeBytes: true,
  storedBytes: true,
  partSize: true,
} satisfies Prisma.SandboxImageUploadSessionSelect;
type DiskSessionRow = Prisma.SandboxImageUploadSessionGetPayload<{
  select: typeof diskSessionSelect;
}>;

/**
 * A disk upload continuation: this host's current connection, the named
 * OPEN session that is its offload's live one, with its transfer OPEN on
 * this epoch and still authorized (`OFFLOAD_UPLOAD`: offload uploadable,
 * sandbox STOPPED at the source generation on this host). Locks host →
 * sandbox → session and runs `then` in the same transaction.
 */
async function withDiskSession<T>(
  sender: RelaySender,
  m: OffloadRef & { sessionId: string },
  then: (
    tx: Prisma.TransactionClient,
    session: DiskSessionRow & { uploadId: string },
  ) => Promise<T>,
): Promise<T | null> {
  return relayTransaction(async (tx) => {
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    requireRelayFence(await lockSandboxRow(tx, m.sandboxId));
    await tx.$queryRaw`SELECT id FROM sandbox_image_upload_session WHERE id = ${m.sessionId} FOR UPDATE`;
    const session = await tx.sandboxImageUploadSession.findFirst({
      where: {
        id: m.sessionId,
        state: "OPEN",
        liveDiskOffloadId: m.offloadId,
        hostId: sender.hostId,
        DiskOffload: { is: { sandboxId: m.sandboxId, seq: m.seq } },
        Transfer: {
          is: {
            state: "OPEN",
            mode: "S3",
            purpose: "OFFLOAD_UPLOAD",
            sourceHostId: sender.hostId,
            sourceHostOwnerId: sender.userId,
            sourceEpoch: sender.connectionEpoch,
          },
        },
      },
      select: { ...diskSessionSelect, Transfer: { select: transferAuthoritySelect } },
    });
    if (!session?.uploadId) return null;
    if (!(await transferAuthorized(tx, session.Transfer, await hostDatabaseNow(tx)))) return null;
    const { Transfer: _transfer, ...row } = session;
    return then(tx, { ...row, uploadId: session.uploadId });
  }, null);
}

/** `disk.upload.parts`: record uploaded parts; grant the next window (with
 * the session's key: every disk grant carries it) once one completes. */
export async function handleDiskUploadParts(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.upload.parts" }>,
): Promise<void> {
  const store = imageStore();
  if (!store) return ctx.reply(cancelFrame(m, "store_unavailable"));
  if (!(await grantBudget(ctx.sender.hostId))) return ctx.reply(cancelFrame(m, "rate_limited"));
  const found = await withDiskSession(ctx.sender, m, async (tx, session) => {
    const parts = partCount(session.storedBytes, session.partSize);
    for (const part of m.parts) {
      if (part.n > parts) continue;
      await tx.sandboxImageUploadPart.upsert({
        where: { sessionId_partNumber: { sessionId: session.id, partNumber: part.n } },
        create: {
          sessionId: session.id,
          partNumber: part.n,
          etag: part.etag,
          sizeBytes: partBytes(session.storedBytes, session.partSize, part.n),
        },
        update: { etag: part.etag },
      });
    }
    const done = await tx.sandboxImageUploadPart.count({ where: { sessionId: session.id } });
    await tx.sandboxImageTransfer.updateMany({
      where: { id: session.transferId, state: "OPEN" },
      data: {
        bytesDone: BigInt(Math.min(Number(session.storedBytes), done * session.partSize)),
        lastProgressAt: new Date(),
      },
    });
    const highest = Math.max(...m.parts.map((p) => p.n));
    const next = highest % IMAGE_UPLOAD_PARTS_MAX === 0 && highest < parts ? highest + 1 : null;
    return { session, next, dek: next ? await loadOpenDiskSessionKey(tx, session.id) : null };
  });
  if (!found) return ctx.reply(cancelFrame(m, "stale"));
  if (!found.next || !found.dek) return;
  try {
    ctx.reply(await diskGrant(store, m, found.session, found.next, found.dek));
  } finally {
    found.dek.fill(0);
  }
}

/**
 * After an accepted `image.job.resume` of a disk upload transfer (the grant
 * was lost with the relay): re-grant the session's window from its lowest
 * unrecorded part, with the session's key. A part sent but not recorded is
 * sent again: the same bytes under the same key and record nonces (the
 * daemon re-hashed its staging first), so S3 just replaces it. Nothing is
 * sent unless the transfer is this host's OPEN `OFFLOAD_UPLOAD` on its
 * current epoch (the resume rebound it) with a live OPEN session.
 */
export async function handleDiskUploadResume(
  ctx: DiskFrameContext,
  transferId: string,
): Promise<void> {
  const store = imageStore();
  const { sender } = ctx;
  if (!store) return;
  const live = await prisma.sandboxImageUploadSession.findFirst({
    where: {
      transferId,
      state: "OPEN",
      hostId: sender.hostId,
      liveDiskOffloadId: { not: null },
      Transfer: {
        is: {
          state: "OPEN",
          purpose: "OFFLOAD_UPLOAD",
          sourceHostId: sender.hostId,
          sourceHostOwnerId: sender.userId,
          sourceEpoch: sender.connectionEpoch,
        },
      },
    },
    select: { id: true, DiskOffload: { select: { id: true, sandboxId: true, seq: true } } },
  });
  const offload = live?.DiskOffload;
  if (!live || !offload) return;
  const ref = { sandboxId: offload.sandboxId, offloadId: offload.id, seq: offload.seq };
  if (!(await grantBudget(sender.hostId))) return ctx.reply(cancelFrame(ref, "rate_limited"));
  const found = await withDiskSession(
    sender,
    { ...ref, sessionId: live.id },
    async (tx, session) => {
      const parts = partCount(session.storedBytes, session.partSize);
      const recorded = await tx.sandboxImageUploadPart.findMany({
        where: { sessionId: session.id },
        select: { partNumber: true },
        orderBy: { partNumber: "asc" },
        take: parts,
      });
      let from = 1;
      for (const part of recorded) {
        if (part.partNumber !== from) break;
        from++;
      }
      return {
        session,
        from: Math.min(from, parts),
        dek: await loadOpenDiskSessionKey(tx, session.id),
      };
    },
  );
  if (!found) return;
  try {
    ctx.reply(await diskGrant(store, ref, found.session, found.from, found.dek));
  } finally {
    found.dek.fill(0);
  }
}

/**
 * `disk.upload.complete` (S1): ListParts of this session must show every
 * part at its exact size, summing to the stored size. Then, in one
 * transaction under host → sandbox, the sandbox must still be STOPPED at the
 * source generation and Complete's two-row CAS (`completeDiskSession`) must
 * move exactly one session (OPEN → COMPLETE, wrap nulled) and exactly one
 * offload (UPLOADING → VERIFYING, taking the wrap, object key and sizes).
 * Otherwise the call is refused. After CompleteMultipartUpload the worker
 * verifies the object (decrypt, hash, size) before `markStored`.
 */
export async function handleDiskUploadComplete(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.upload.complete" }>,
  enqueueVerify: (offloadId: string) => Promise<void>,
): Promise<void> {
  const store = imageStore();
  const stale = () => ctx.reply(cancelFrame(m, "stale"));
  const session = store ? await withDiskSession(ctx.sender, m, async (_tx, s) => s) : null;
  if (!store || !session) return stale();
  const expected = partCount(session.storedBytes, session.partSize);
  let listed: { n: number; size: number; etag: string }[];
  try {
    listed = await store.listParts(session.objectKey, session.uploadId);
  } catch {
    return ctx.reply(cancelFrame(m, "store_unavailable"));
  }
  const valid =
    listed.length === expected &&
    listed.every(
      (p) =>
        p.n >= 1 &&
        p.n <= expected &&
        p.size === partBytes(session.storedBytes, session.partSize, p.n),
    ) &&
    listed.reduce((sum, p) => sum + BigInt(p.size), 0n) === session.storedBytes;
  if (!valid) {
    await failOffload(store, m.sandboxId, m.offloadId, "upload_invalid");
    return ctx.reply(cancelFrame(m, "upload_invalid"));
  }
  const claimed = await relayTransaction<"claimed" | "refused" | { ended: EndedOffload | null }>(
    async (tx) => {
      const sender = ctx.sender;
      await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
      requireRelayFence(sender.isCurrent?.() !== false);
      requireRelayFence(await lockSandboxRow(tx, m.sandboxId));
      const [offload] = await tx.$queryRaw<{ sourceGeneration: number }[]>`SELECT "sourceGeneration"
        FROM sandbox_disk_offload WHERE id = ${m.offloadId} AND "sandboxId" = ${m.sandboxId}
          AND seq = ${m.seq} AND "sourceHostId" = ${sender.hostId} FOR UPDATE`;
      if (!offload) return "refused";
      const stopped = await tx.sandbox.count({
        where: {
          id: m.sandboxId,
          state: "STOPPED",
          generation: offload.sourceGeneration,
          sandboxHostId: sender.hostId,
          diskOffloadId: null,
        },
      });
      if (stopped !== 1)
        return { ended: await endLiveOffload(tx, m.offloadId, "SUPERSEDED", "superseded") };
      if (!(await completeDiskSession(tx, { offloadId: m.offloadId, sessionId: session.id })))
        return "refused";
      await tx.sandboxImageTransfer.updateMany({
        where: { id: session.transferId, state: "OPEN" },
        data: { state: "COMPLETE", endReason: "uploaded", bytesDone: session.storedBytes },
      });
      return "claimed";
    },
    "refused",
  );
  if (claimed !== "claimed") {
    if (claimed !== "refused") await finishEndedOffload(store, claimed.ended);
    else {
      // A superseded (ABORTED) session's upload is aborted; a session the
      // CAS already completed is never touched (its Complete may be running).
      const ended = await prisma.sandboxImageUploadSession.findFirst({
        where: { id: session.id, state: "ABORTED", uploadId: session.uploadId },
        select: { id: true },
      });
      if (ended)
        await finishEndedOffload(store, {
          offloadId: m.offloadId,
          sandboxId: m.sandboxId,
          userId: "",
          seq: m.seq,
          sourceHostId: ctx.sender.hostId,
          objectKey: null,
          sessions: [{ id: session.id, objectKey: session.objectKey, uploadId: session.uploadId }],
        });
    }
    return stale();
  }
  try {
    await store.completeMultipart(
      session.objectKey,
      session.uploadId,
      listed.map((p) => ({ n: p.n, etag: p.etag })),
    );
  } catch (error) {
    // Create-only refusal at this session's own key (a retried Complete whose
    // first response was lost): nothing was overwritten and the store aborted
    // the upload. The object is not assumed to be ours: it stays VERIFYING and
    // the disk verify job proves it (authenticated decryption under this
    // session's wrap, SHA-256 and size) or fails it as corrupt and deletes it.
    if (error instanceof ImageObjectExistsError) {
      await enqueueVerify(m.offloadId);
      return;
    }
    // The claimed object never appeared: the attempt fails (the disk stays
    // local) and the upload is aborted.
    await failOffload(store, m.sandboxId, m.offloadId, "store_unavailable");
    await prisma.sandboxImageUploadSession.updateMany({
      where: { id: session.id, state: "COMPLETE" },
      data: { state: "ABORTED", endReason: "complete_failed" },
    });
    await finishEndedOffload(store, {
      offloadId: m.offloadId,
      sandboxId: m.sandboxId,
      userId: "",
      seq: m.seq,
      sourceHostId: ctx.sender.hostId,
      objectKey: null,
      sessions: [{ id: session.id, objectKey: session.objectKey, uploadId: session.uploadId }],
    });
    return ctx.reply(cancelFrame(m, "store_unavailable"));
  }
  await enqueueVerify(m.offloadId);
}

/**
 * `disk.offload.failed`: the source host could not export or upload. Only
 * its own live, still-uploadable attempt ends FAILED(code) (a VERIFYING
 * object is the server's to judge); the disk stays local.
 */
export async function handleDiskOffloadFailed(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.offload.failed" }>,
): Promise<void> {
  const store = imageStore();
  const ended = await relayTransaction(async (tx) => {
    const sender = ctx.sender;
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    requireRelayFence(await lockSandboxRow(tx, m.sandboxId));
    const owned = await tx.sandboxDiskOffload.count({
      where: {
        id: m.offloadId,
        sandboxId: m.sandboxId,
        seq: m.seq,
        sourceHostId: sender.hostId,
        sourceHostOwnerId: sender.userId,
      },
    });
    if (owned !== 1) return null;
    return endLiveOffload(tx, m.offloadId, "FAILED", m.code, UPLOADABLE_STATES);
  }, null);
  await finishEndedOffload(store, ended);
}

/**
 * `image.job.failed` on a disk upload transfer (`transferId` of a disk
 * grant): its offload, if still uploading from that host, ends FAILED.
 * Returns false when the transfer is not a disk upload of that host.
 */
export async function handleDiskTransferFailure(
  ctx: Pick<DiskFrameContext, "sender">,
  transferId: string,
  code: string,
): Promise<boolean> {
  const transfer = await prisma.sandboxImageTransfer.findFirst({
    where: {
      id: transferId,
      purpose: "OFFLOAD_UPLOAD",
      sourceHostId: ctx.sender.hostId,
      sourceHostOwnerId: ctx.sender.userId,
    },
    select: { DiskOffload: { select: { id: true, sandboxId: true, seq: true } } },
  });
  const offload = transfer?.DiskOffload;
  if (!offload) return transfer !== null;
  await handleDiskOffloadFailed(
    { sender: ctx.sender, reply: () => {} },
    {
      type: "disk.offload.failed",
      sandboxId: offload.sandboxId,
      offloadId: offload.id,
      seq: offload.seq,
      code: code === "cancelled" ? "cancelled" : "io",
    },
  );
  return true;
}

/**
 * `disk.evict.request`: the evict CAS under
 * owner → host → sandbox (`grantEviction`); answered with the grant or the
 * refusal. A fenced (stale) session gets a `stale` refusal.
 */
export async function handleDiskEvictRequest(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.evict.request" }>,
): Promise<void> {
  const { grantEviction } = await import("@wssp/api/sandbox/disk-offload/evict");
  const frame = await relayTransaction<ServerDiskMessage>(
    (tx) => grantEviction(tx, ctx.sender, m),
    {
      type: "disk.evict.refused",
      sandboxId: m.sandboxId,
      offloadId: m.offloadId,
      seq: m.seq,
      code: "stale",
    },
  );
  ctx.reply(frame);
}

/**
 * `disk.evicted` (§7 step 6): accepted only for the matching grant on this
 * host; the sandbox detaches to OFFLOADED. The ack (`disk.offload.cancel`
 * with reason `evicted`) lets the daemon drop its journal entry (T16).
 */
export async function handleDiskEvicted(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.evicted" }>,
): Promise<void> {
  const { acceptEvicted } = await import("@wssp/api/sandbox/disk-offload/evict");
  const outcome = await relayTransaction(
    (tx) => acceptEvicted(tx, ctx.sender, m),
    "refused" as const,
  );
  if (outcome !== "ack") return;
  const offload = await prisma.sandboxDiskOffload.findFirst({
    where: { id: m.offloadId, sandboxId: m.sandboxId },
    select: { seq: true },
  });
  if (offload)
    ctx.reply(
      cancelFrame({ sandboxId: m.sandboxId, offloadId: m.offloadId, seq: offload.seq }, "evicted"),
    );
}

/** `disk.discarded` (§7 Discard): settle the copy row on a matching proof. */
export async function handleDiskDiscarded(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.discarded" }>,
): Promise<void> {
  const { settleDiscarded } = await import("@wssp/api/sandbox/disk-offload/discard");
  const outcome = await relayTransaction(
    (tx) => settleDiscarded(tx, ctx.sender, m),
    "unknown" as const,
  );
  if (outcome === "refused")
    console.info(`[sandbox-relay] disk discard refused (${m.code ?? "proof_mismatch"})`);
}

/**
 * `image.fetch.request` of a restore attempt: one
 * `RESTORE_FETCH` S3 transfer keyed on the offload (`diskOffloadId`), under
 * the restore workload fence (exact attempt on this connection, the
 * placement's offload, STORED and current, `restoreHostEligibility`). The
 * grant carries the disk object key unwrapped from the offload's own wrap;
 * restore bytes are never counted against a download or upload budget
 * (restores are never refused for quota).
 */
export async function handleRestoreFetchRequest(
  ctx: Pick<ImageFrameContext, "sender" | "reply">,
  m: Extract<DaemonImageMessage, { type: "image.fetch.request" }>,
  restoreOffloadId: string,
): Promise<void> {
  const refuse = (code: string) =>
    ctx.reply({ type: "image.fetch.refused", requestId: m.requestId, code });
  const store = imageStore();
  if (!store) return refuse("image_unavailable");
  const { sender } = ctx;
  type RestoreOutcome =
    | { kind: "refused"; code: string }
    | {
        kind: "s3";
        transferId: string;
        size: bigint;
        partSize: number;
        objectKey: string;
        key: string;
      };
  const outcome = await relayTransaction<RestoreOutcome>(
    async (tx) => {
      await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
      requireRelayFence(sender.isCurrent?.() !== false);
      const now = await hostDatabaseNow(tx);
      const host = await tx.sandboxHost.findFirst({
        where: { id: sender.hostId, userId: sender.userId },
        select: { daemonFeatures: true },
      });
      if (!hostImageFeatures(host?.daemonFeatures ?? null)?.fetch)
        return { kind: "refused", code: "unsupported" };
      const workload = await restoreFetchWorkload(tx, {
        operationId: m.operationId,
        hostId: sender.hostId,
        hostOwnerId: sender.userId,
        epoch: sender.connectionEpoch,
        generation: m.generation,
        sandboxId: m.sandboxId,
        attempt: m.attempt,
        fingerprint: m.fingerprint,
        restoreOffloadId,
      });
      if (!workload) return { kind: "refused", code: "stale_operation" };
      // One grant per attempt and connection (P2-8); an older one is
      // superseded (round-2 P2-3). S3 transfers hold no spool or source.
      const open = await tx.sandboxImageTransfer.findMany({
        where: {
          operationId: workload.operationId,
          diskOffloadId: restoreOffloadId,
          purpose: "RESTORE_FETCH",
          destHostId: sender.hostId,
          state: "OPEN",
        },
        select: { id: true, dispatchAttempt: true, destEpoch: true, expiresAt: true },
        take: 8,
      });
      if (
        open.some(
          (t) =>
            t.dispatchAttempt === m.attempt &&
            t.destEpoch === sender.connectionEpoch &&
            t.expiresAt > now,
        )
      )
        return { kind: "refused", code: "in_progress" };
      for (const stale of open) {
        await tx.sandboxImageTransfer.updateMany({
          where: { id: stale.id, state: "OPEN" },
          data: { state: "CANCELLED", endReason: "superseded" },
        });
        await tx.sandboxImageLink.deleteMany({ where: { transferId: stale.id } });
      }
      const offload = await tx.sandboxDiskOffload.findFirst({
        where: { id: restoreOffloadId, userId: workload.ownerId, state: "STORED" },
        select: { sizeBytes: true, objectKey: true, partSize: true },
      });
      if (!offload?.objectKey || !offload.sizeBytes || offload.sizeBytes <= 0n)
        return { kind: "refused", code: "image_unavailable" };
      const partSize = offload.partSize ?? IMAGE_S3_PART_BYTES;
      let dek: Buffer | undefined;
      try {
        dek = await loadDiskObjectKey(tx, restoreOffloadId);
      } catch {
        return { kind: "refused", code: "image_unavailable" };
      }
      const key = dek.toString("base64");
      dek.fill(0);
      const transfer = await tx.sandboxImageTransfer.create({
        data: {
          userId: workload.ownerId,
          fingerprint: m.fingerprint,
          purpose: "RESTORE_FETCH",
          mode: "S3",
          diskOffloadId: restoreOffloadId,
          destHostId: sender.hostId,
          destHostOwnerId: sender.userId,
          destEpoch: sender.connectionEpoch,
          operationId: workload.operationId,
          dispatchAttempt: m.attempt,
          sizeBytes: offload.sizeBytes,
          partSize,
          partCount: Math.max(1, Math.ceil(Number(offload.sizeBytes) / partSize)),
          expiresAt: new Date(
            now.getTime() + readImageStoreEnv().IMAGE_S3_PRESIGN_TTL_SECONDS * 1000,
          ),
        },
        select: { id: true },
      });
      return {
        kind: "s3",
        transferId: transfer.id,
        size: offload.sizeBytes,
        partSize,
        objectKey: offload.objectKey,
        key,
      };
    },
    { kind: "refused", code: "stale_operation" },
  );
  if (outcome.kind === "refused") return refuse(outcome.code);
  ctx.reply({
    type: "image.fetch.grant",
    requestId: m.requestId,
    transferId: outcome.transferId,
    mode: "S3",
    sizeBytes: Number(outcome.size),
    partSize: outcome.partSize,
    expiresAtUnixMs: Date.now() + store.settings.presignTtlSeconds * 1000,
    url: await store.presignGet(outcome.objectKey),
    encryption: { scheme: IMAGE_ENCRYPTION_SCHEME, key: outcome.key },
  });
}

/**
 * `disk.offload.released`: the source host dropped this verified
 * offload's alias image, export and staging. Recorded once
 * (`sourceReleasedAt`) on the host's own row (source host and owner scoped);
 * from then on the row no longer holds the host's export slot, so the
 * scheduler runs at once to send the host its next export.
 */
export async function handleDiskOffloadReleased(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.offload.released" }>,
): Promise<void> {
  if (ctx.sender.isCurrent?.() === false) return;
  const { count } = await prisma.sandboxDiskOffload.updateMany({
    where: {
      id: m.offloadId,
      sandboxId: m.sandboxId,
      seq: m.seq,
      sourceHostId: ctx.sender.hostId,
      sourceHostOwnerId: ctx.sender.userId,
      verifiedAt: { not: null },
      sourceReleasedAt: null,
    },
    data: { sourceReleasedAt: new Date() },
  });
  if (count > 0) wakeImageScheduler();
}

/** `disk.offload.inventory` pages one session may send (the daemon sends at
 * most this many; more are ignored). */
export const DISK_INVENTORY_PAGES_PER_SESSION = 16;
/** Offload states still in flight: an inventory entry of one is unanswered. */
const INVENTORY_IN_FLIGHT = new Set(["PENDING", "EXPORTING", "UPLOADING", "VERIFYING", "EVICTING"]);
/** `disk.offload.cancel` reason that releases an over or foreign offload. */
const OFFLOAD_RELEASED = "released";

/**
 * `disk.offload.inventory`: the
 * host's unfinished offloads, answered from the server's own rows of this
 * host only (source host and owner scoped in the query):
 * - STORED (same sandbox and seq) → `disk.offload.stored`;
 * - still in flight → nothing (the upload or verify flow answers it);
 * - anything else (CONSUMED, SUPERSEDED, FAILED, DELETING, DELETED, an
 *   unknown id, or another host's offload) → `disk.offload.cancel`
 *   `released`, echoing only the host's own ids: it drops its alias image,
 *   export, staging reservation and journal entry, never the VM.
 */
export async function handleDiskOffloadInventory(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.offload.inventory" }>,
): Promise<void> {
  if (ctx.sender.isCurrent?.() === false) return;
  const rows = await prisma.sandboxDiskOffload.findMany({
    where: {
      id: { in: m.entries.map((entry) => entry.offloadId) },
      sourceHostId: ctx.sender.hostId,
      sourceHostOwnerId: ctx.sender.userId,
    },
    select: {
      id: true,
      sandboxId: true,
      seq: true,
      state: true,
      fingerprint: true,
      sourceGeneration: true,
    } satisfies Prisma.SandboxDiskOffloadSelect,
    take: m.entries.length,
  });
  const byId = new Map(rows.map((row) => [row.id, row]));
  for (const entry of m.entries) {
    const row = byId.get(entry.offloadId);
    const same = row !== undefined && row.sandboxId === entry.sandboxId && row.seq === entry.seq;
    if (same && row.state === "STORED" && row.fingerprint) {
      ctx.reply({
        type: "disk.offload.stored",
        sandboxId: row.sandboxId,
        offloadId: row.id,
        seq: row.seq,
        fingerprint: row.fingerprint,
        generation: row.sourceGeneration,
      });
      continue;
    }
    if (same && INVENTORY_IN_FLIGHT.has(row.state)) continue;
    ctx.reply(cancelFrame(entry, OFFLOAD_RELEASED));
  }
}
