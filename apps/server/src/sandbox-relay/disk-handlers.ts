import { consumeImageGrantBudget } from "@wssp/api/sandbox/budgets";
import { canOffload } from "@wssp/api/sandbox/disk-offload/availability";
import { loginStateSettled } from "@wssp/api/sandbox/disk-offload/eligibility";
import {
  abortDiskSession,
  completeDiskSession,
  DISK_ENCRYPTION_SCHEME,
  generateDiskDek,
  loadDiskObjectKey,
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
  DISK_RESUME_RANGES_MAX,
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
 * on its source host. A session's first grant (the begin's) carries
 * `encryption` (I13): the session's own DEK, drawn fresh at begin and wrapped
 * under the disk root key; it leaves the server only in that grant, never a
 * log, row or later frame (next windows and resumes carry no key).
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
/** `disk.offload.cancel` reason: the upload is not this host's to resume. */
const RESUME_REFUSED = "resume_refused";

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

type GrantSession = {
  id: string;
  transferId: string;
  objectKey: string;
  uploadId: string;
  partSize: number;
  storedBytes: bigint;
};

/** Presigned URLs of the part numbers `numbers`. */
async function presignParts(store: ImageStore, session: GrantSession, numbers: readonly number[]) {
  const urls = [];
  for (const n of numbers) {
    const size = partBytes(session.storedBytes, session.partSize, n);
    urls.push({
      n,
      sizeBytes: size,
      url: await store.presignUploadPart(session.objectKey, session.uploadId, n, size),
    });
  }
  return urls;
}

/** Presigned part URLs of `numbers`; `dek` (the session's key, I13) only on
 * the session's first grant (the begin's): the host holds it from then on. */
async function diskGrant(
  store: ImageStore,
  ref: OffloadRef,
  session: GrantSession,
  numbers: readonly number[],
  dek: Buffer | null,
): Promise<ServerDiskMessage> {
  return {
    type: "disk.upload.grant",
    sandboxId: ref.sandboxId,
    offloadId: ref.offloadId,
    seq: ref.seq,
    sessionId: session.id,
    transferId: session.transferId,
    partSize: session.partSize,
    parts: await presignParts(store, session, numbers),
    expiresAtUnixMs: Date.now() + store.settings.presignTtlSeconds * 1000,
    ...(dek ? { encryption: { scheme: DISK_ENCRYPTION_SCHEME, key: dek.toString("base64") } } : {}),
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
        windowFrom(1, partCount(outcome.storedBytes, outcome.partSize), new Set()),
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
type DiskSession = DiskSessionRow & { uploadId: string };

/**
 * How a disk upload continuation finds its session's transfer:
 * - `bound`: on this connection's epoch (parts reports, the resume's
 *   reconciliation). Only `disk.upload.begin` and `disk.upload.resume` bind a
 *   transfer to an epoch, so no part counts on a connection that did neither.
 * - `authorize`: on this or an older epoch of this host, authorized as if
 *   bound here, but never moved (completion: its claim ends the transfer).
 * - `rebind`: as `authorize`, then moved to this epoch (`disk.upload.resume`).
 */
type SessionMode = "bound" | "authorize" | "rebind";

/** `fenced`: this connection is not the host's current one (no answer);
 * `refused`: the upload is not this host's live, authorized upload. */
type DiskSessionOutcome<T> = { kind: "fenced" } | { kind: "refused" } | { kind: "ok"; value: T };

/**
 * A disk upload continuation: this host's current connection, the named
 * OPEN session that is its offload's live one, with its transfer OPEN and
 * still authorized (`OFFLOAD_UPLOAD`: offload uploadable, sandbox STOPPED at
 * the source generation on this host), found as `mode` says. Locks host →
 * sandbox → session and runs `then` in the same transaction.
 */
async function withDiskSession<T>(
  sender: RelaySender,
  m: OffloadRef & { sessionId: string; transferId?: string },
  then: (tx: Prisma.TransactionClient, session: DiskSession) => Promise<T>,
  mode: SessionMode = "bound",
): Promise<DiskSessionOutcome<T>> {
  const refused = { kind: "refused" } as const;
  return relayTransaction<DiskSessionOutcome<T>>(
    async (tx) => {
      await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
      requireRelayFence(sender.isCurrent?.() !== false);
      if (!(await lockSandboxRow(tx, m.sandboxId))) return refused;
      await tx.$queryRaw`SELECT id FROM sandbox_image_upload_session WHERE id = ${m.sessionId} FOR UPDATE`;
      // Session → transfer (as the stall rule and `image.job.resume` take
      // them): a transfer ended meanwhile (expiry, cancel) is seen below, and
      // none ends before this transaction commits what it read.
      await tx.$queryRaw`SELECT t.id FROM sandbox_image_transfer t
        JOIN sandbox_image_upload_session s ON s."transferId" = t.id
        WHERE s.id = ${m.sessionId} FOR UPDATE OF t`;
      const session = await tx.sandboxImageUploadSession.findFirst({
        where: {
          id: m.sessionId,
          state: "OPEN",
          liveDiskOffloadId: m.offloadId,
          hostId: sender.hostId,
          DiskOffload: { is: { sandboxId: m.sandboxId, seq: m.seq } },
          Transfer: {
            is: {
              ...(m.transferId === undefined ? {} : { id: m.transferId }),
              state: "OPEN",
              mode: "S3",
              purpose: "OFFLOAD_UPLOAD",
              sourceHostId: sender.hostId,
              sourceHostOwnerId: sender.userId,
              sourceEpoch:
                mode === "bound" ? sender.connectionEpoch : { lte: sender.connectionEpoch },
            },
          },
        },
        select: {
          ...diskSessionSelect,
          Transfer: { select: { id: true, ...transferAuthoritySelect } },
        },
      });
      if (!session?.uploadId) return refused;
      const { Transfer: transfer, ...row } = session;
      const bound = { ...transfer, sourceEpoch: sender.connectionEpoch };
      if (!(await transferAuthorized(tx, bound, await hostDatabaseNow(tx)))) return refused;
      if (mode === "rebind" && transfer.sourceEpoch !== sender.connectionEpoch) {
        const moved = await tx.sandboxImageTransfer.updateMany({
          where: { id: transfer.id, state: "OPEN", sourceEpoch: transfer.sourceEpoch },
          data: { sourceEpoch: sender.connectionEpoch },
        });
        if (moved.count !== 1) return refused;
      }
      return { kind: "ok", value: await then(tx, { ...row, uploadId: session.uploadId }) };
    },
    { kind: "fenced" },
  );
}

/** The parts of `[from, from + 63]` not in `recorded`: the next window. */
function windowFrom(from: number, parts: number, recorded: ReadonlySet<number>): number[] {
  const window: number[] = [];
  for (let n = from; n <= Math.min(parts, from + IMAGE_UPLOAD_PARTS_MAX - 1); n++)
    if (!recorded.has(n)) window.push(n);
  return window;
}

/** The lowest part of `1..parts` not in `recorded`, or null. */
function lowestMissing(parts: number, recorded: ReadonlySet<number>): number | null {
  for (let n = 1; n <= parts; n++) if (!recorded.has(n)) return n;
  return null;
}

/** `disk.upload.parts`: record uploaded parts (on a transfer bound to this
 * connection only); once the report passes the lowest unrecorded part, grant
 * the next window from it (without the key: the host holds it). */
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
    const recorded = new Set(
      // A session has at most `S3_PARTS_MAX` parts (one row per part number).
      (
        await tx.sandboxImageUploadPart.findMany({
          where: { sessionId: session.id },
          select: { partNumber: true },
          take: S3_PARTS_MAX,
        })
      ).map((part) => part.partNumber),
    );
    await tx.sandboxImageTransfer.updateMany({
      where: { id: session.transferId, state: "OPEN" },
      data: {
        bytesDone: BigInt(Math.min(Number(session.storedBytes), recorded.size * session.partSize)),
        lastProgressAt: new Date(),
      },
    });
    const highest = Math.max(...m.parts.map((p) => p.n));
    const from = lowestMissing(parts, recorded);
    return {
      session,
      next: from !== null && from > highest ? windowFrom(from, parts, recorded) : [],
    };
  });
  if (found.kind !== "ok") return ctx.reply(cancelFrame(m, "stale"));
  if (found.value.next.length === 0) return;
  ctx.reply(await diskGrant(store, m, found.value.session, found.value.next, null));
}

/** Inclusive ranges of the ascending part numbers `numbers`. */
function rangesOf(numbers: readonly number[]): [number, number][] {
  const ranges: [number, number][] = [];
  for (const n of numbers) {
    const last = ranges[ranges.length - 1];
    if (last && last[1] === n - 1) last[1] = n;
    else ranges.push([n, n]);
  }
  return ranges;
}

/**
 * `disk.upload.resume` (after a relay connection change): the only way an
 * upload continues on a new connection. Re-authorizes the named session as
 * this host's live upload (host, owner, offload, sandbox STOPPED at its
 * source generation here, transfer OPEN and unexpired) and binds its transfer
 * to this connection; then reconciles the recorded parts to the object
 * store's own listing (ListParts: parts at their exact size count; rows the
 * store does not hold go) and answers `disk.upload.resumed` with the stored
 * ranges and the window from the lowest missing part. Never the key: the
 * host holds it from the session's first grant. A part sent but not listed
 * is sent again: the same bytes under the same key and record nonces (the
 * host re-hashed its staging), so the store just replaces it.
 *
 * `resume_refused` when the upload is no longer this host's; no answer when
 * this connection is no longer current (the host resumes on the new one);
 * `store_unavailable` / `rate_limited` are transient (the host resumes again;
 * a repeat on the same connection is idempotent).
 */
export async function handleDiskUploadResume(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.upload.resume" }>,
): Promise<void> {
  const store = imageStore();
  const { sender } = ctx;
  const cancel = (reason: string) => ctx.reply(cancelFrame(m, reason));
  if (!store) return cancel("store_unavailable");
  if (!(await grantBudget(sender.hostId))) return cancel("rate_limited");
  const bound = await withDiskSession(sender, m, async (_tx, session) => session, "rebind");
  if (bound.kind === "fenced") return;
  if (bound.kind === "refused") return cancel(RESUME_REFUSED);
  const session = bound.value;
  const parts = partCount(session.storedBytes, session.partSize);
  let listed: { n: number; size: number; etag: string }[];
  try {
    listed = await store.listParts(session.objectKey, session.uploadId);
  } catch {
    return cancel("store_unavailable");
  }
  const etags = new Map<number, string>();
  for (const part of listed)
    if (
      part.n >= 1 &&
      part.n <= parts &&
      part.size === partBytes(session.storedBytes, session.partSize, part.n)
    )
      etags.set(part.n, part.etag);
  // At most `DISK_RESUME_RANGES_MAX` ranges count as stored; parts past them
  // are granted again (same bytes, same key and nonces).
  const stored = rangesOf([...etags.keys()].sort((a, b) => a - b)).slice(0, DISK_RESUME_RANGES_MAX);
  const kept = new Set<number>();
  for (const [first, last] of stored) for (let n = first; n <= last; n++) kept.add(n);
  const reconciled = await withDiskSession(sender, m, async (tx, s) => {
    // A session has at most `S3_PARTS_MAX` parts (one row per part number).
    const rows = await tx.sandboxImageUploadPart.findMany({
      where: { sessionId: s.id },
      select: { partNumber: true },
      take: S3_PARTS_MAX,
    });
    const have = new Set(rows.map((row) => row.partNumber));
    const added = [...etags].filter(([n]) => kept.has(n) && !have.has(n));
    const dropped = rows.map((row) => row.partNumber).filter((n) => !kept.has(n));
    // Set-based and bounded (one insert, one delete), whatever the part count.
    if (added.length > 0)
      await tx.sandboxImageUploadPart.createMany({
        data: added.map(([n, etag]) => ({
          sessionId: s.id,
          partNumber: n,
          etag,
          sizeBytes: partBytes(s.storedBytes, s.partSize, n),
        })),
        skipDuplicates: true,
      });
    if (dropped.length > 0)
      await tx.sandboxImageUploadPart.deleteMany({
        where: { sessionId: s.id, partNumber: { in: dropped } },
      });
    // Progress (the stall rule's clock) only for parts the server did not
    // know of: a resume that finds nothing new never holds the attempt open.
    await tx.sandboxImageTransfer.updateMany({
      where: { id: s.transferId, state: "OPEN" },
      data: {
        bytesDone: BigInt(Math.min(Number(s.storedBytes), kept.size * s.partSize)),
        ...(added.length > 0 ? { lastProgressAt: new Date() } : {}),
      },
    });
    return s;
  });
  if (reconciled.kind === "fenced") return;
  if (reconciled.kind === "refused") return cancel(RESUME_REFUSED);
  const from = lowestMissing(parts, kept);
  const window = from === null ? [] : windowFrom(from, parts, kept);
  ctx.reply({
    type: "disk.upload.resumed",
    sandboxId: m.sandboxId,
    offloadId: m.offloadId,
    seq: m.seq,
    sessionId: session.id,
    transferId: session.transferId,
    partSize: session.partSize,
    stored,
    parts: await presignParts(store, session, window),
    expiresAtUnixMs: Date.now() + store.settings.presignTtlSeconds * 1000,
  });
}

/**
 * `disk.upload.complete` (S1): ListParts of this session must show every
 * part at its exact size, summing to the stored size. Then, in one
 * transaction under host → sandbox, the sandbox must still be STOPPED at the
 * source generation and Complete's two-row CAS (`completeDiskSession`) must
 * move exactly one session (OPEN → COMPLETE, wrap nulled) and exactly one
 * offload (UPLOADING → VERIFYING, taking the wrap, object key and sizes).
 * Otherwise the call is refused. After CompleteMultipartUpload the worker
 * verifies the object (decrypt, hash, size) before `markStored`. A session
 * whose transfer is still bound to an older epoch of this host is authorized
 * on this connection without moving it (`withDiskSession`'s `authorize`;
 * the claim ends the transfer): the host re-sends a completion lost with a
 * relay connection until its offload has a verdict, and no connection ever
 * gets a part accepted without a resume.
 */
export async function handleDiskUploadComplete(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.upload.complete" }>,
  enqueueVerify: (offloadId: string) => Promise<void>,
): Promise<void> {
  const store = imageStore();
  const stale = () => ctx.reply(cancelFrame(m, "stale"));
  const found = store
    ? await withDiskSession(ctx.sender, m, async (_tx, s) => s, "authorize")
    : null;
  if (!store || found?.kind !== "ok") return stale();
  const session = found.value;
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
          AND seq = ${m.seq} AND "sourceHostId" = ${sender.hostId}
          AND "sourceHostOwnerId" = ${sender.userId} FOR UPDATE`;
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
      // The transfer may have ended while ListParts ran (expired, cancelled):
      // the claim then rolls back whole (round 1 L3 #3).
      const moved = await tx.sandboxImageTransfer.updateMany({
        where: { id: session.transferId, state: "OPEN" },
        data: { state: "COMPLETE", endReason: "uploaded", bytesDone: session.storedBytes },
      });
      requireRelayFence(moved.count === 1);
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
 * How the server took a durable host report (a frame carrying `reportId`):
 * `done` when it took effect, or when nothing is left for it to end (no such
 * attempt of this host, or that attempt already ended), so the host stops
 * re-sending (`report.ack`); `retry` when a fence refused it or it could not
 * be decided now (no ack: the host sends it again).
 */
export type ReportOutcome = "done" | "retry";

/**
 * `disk.offload.failed`: the source host could not export or upload. Only
 * its own live, still-uploadable attempt ends FAILED(code) (a VERIFYING
 * object is the server's to judge); the disk stays local. A repeat, or a
 * report naming no row of this host and owner, changes nothing (`done`).
 */
export async function handleDiskOffloadFailed(
  ctx: DiskFrameContext,
  m: Extract<DaemonDiskMessage, { type: "disk.offload.failed" }>,
): Promise<ReportOutcome> {
  const store = imageStore();
  const taken = await relayTransaction<{ ended: EndedOffload | null } | null>(async (tx) => {
    const sender = ctx.sender;
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    // No sandbox row: no offload of it is left to end (a definite no-op).
    if (!(await lockSandboxRow(tx, m.sandboxId))) return { ended: null };
    const owned = await tx.sandboxDiskOffload.count({
      where: {
        id: m.offloadId,
        sandboxId: m.sandboxId,
        seq: m.seq,
        sourceHostId: sender.hostId,
        sourceHostOwnerId: sender.userId,
      },
    });
    if (owned !== 1) return { ended: null };
    return { ended: await endLiveOffload(tx, m.offloadId, "FAILED", m.code, UPLOADABLE_STATES) };
  }, null);
  if (!taken) return "retry";
  await finishEndedOffload(store, taken.ended);
  return "done";
}

/**
 * `image.job.failed` on a disk upload transfer (`transferId` of a disk
 * grant): its offload, if still uploading from that host, ends FAILED.
 * Its outcome is the offload report's (`done` when the transfer is not a
 * disk upload of that host: nothing of an offload is left for it).
 */
export async function handleDiskTransferFailure(
  ctx: Pick<DiskFrameContext, "sender">,
  transferId: string,
  code: string,
): Promise<ReportOutcome> {
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
  if (!offload) return "done";
  return handleDiskOffloadFailed(
    { sender: ctx.sender, reply: () => {} },
    {
      type: "disk.offload.failed",
      sandboxId: offload.sandboxId,
      offloadId: offload.id,
      seq: offload.seq,
      code: code === "cancelled" ? "cancelled" : "io",
    },
  );
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
): Promise<ReportOutcome> {
  if (ctx.sender.isCurrent?.() === false) return "retry";
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
  // Recorded now, or already (a repeat), or no verified row of this host
  // and owner: nothing is left for this report to do.
  return "done";
}

/** `disk.offload.inventory` pages one inventory run may send (the daemon
 * sends at most this many per run). */
const DISK_INVENTORY_PAGES_PER_SESSION = 16;
/** The inventory budget's window: the daemon runs its completion and
 * inventory pass after every reconnect and every 10 minutes on a live
 * connection (post-landing #1). */
export const DISK_INVENTORY_WINDOW_MS = 10 * 60_000;
/** Pages accepted per window: one full run plus as many one-entry verdict
 * asks; more are ignored until the window rolls over. */
export const DISK_INVENTORY_PAGES_PER_WINDOW = 2 * DISK_INVENTORY_PAGES_PER_SESSION;

export type DiskInventoryBudget = { pages: number; since: number };

/** Whether one more inventory page fits this connection's budget (a
 * window replenishes it, so a long-lived connection keeps its verdicts). */
export function admitDiskInventoryPage(
  budget: DiskInventoryBudget | undefined,
  now: number,
): { admitted: boolean; budget: DiskInventoryBudget } {
  const current =
    budget && now - budget.since < DISK_INVENTORY_WINDOW_MS ? budget : { pages: 0, since: now };
  const next = { pages: current.pages + 1, since: current.since };
  return { admitted: next.pages <= DISK_INVENTORY_PAGES_PER_WINDOW, budget: next };
}
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
