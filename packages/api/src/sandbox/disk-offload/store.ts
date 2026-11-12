import { randomBytes } from "node:crypto";
import prisma, { type Prisma } from "@wssp/db";
import type { ImageStore } from "../image-store/s3";
import { loginStateSettled } from "./eligibility";
import { shredOffloadKeys } from "./keys";

/**
 * The disk offload store: object layout, the
 * terminal writers, `markStored` and the admission supersede.
 *
 * Every terminal write that ends an offload goes through `endLiveOffload`,
 * which shreds the keys (`shredOffloadKeys`) in the same transaction: an
 * OPEN session is aborted first, then the wraps are nulled (T13). Object and
 * multipart deletes run after commit (`finishEndedOffload`), with the
 * sweeper (`image-store/jobs.ts`) as the backstop.
 */

type Tx = Prisma.TransactionClient;

/** States an offload is in before it is STORED (the supersede set, X2). */
export const PRE_STORED_STATES = ["PENDING", "EXPORTING", "UPLOADING", "VERIFYING"] as const;
/** States a disk upload begin or continuation is accepted in (S1). */
export const UPLOADABLE_STATES = ["PENDING", "EXPORTING", "UPLOADING"] as const;

const ID = /^[A-Za-z0-9_-]{1,128}$/;

/** `<prefix>/owners/<owner>/sandboxes/<sandbox>/<offload>/<session>.wsspenc`:
 * one object per upload session (S1); two sessions never share a key. */
export function diskStoreObjectKey(
  prefix: string,
  input: { ownerId: string; sandboxId: string; offloadId: string; sessionId: string },
): string {
  for (const id of [input.ownerId, input.sandboxId, input.offloadId, input.sessionId])
    if (!ID.test(id)) throw new Error("invalid disk object id");
  return `${prefix}/owners/${input.ownerId}/sandboxes/${input.sandboxId}/${input.offloadId}/${input.sessionId}.wsspenc`;
}

/** A disk upload session id, generated in code before the DEK wrap binds it (S10/R4). */
export function newDiskSessionId(): string {
  return `dses_${randomBytes(16).toString("hex")}`;
}

/** What an ended offload leaves to clean up after commit. Carries no key. */
export type EndedOffload = {
  offloadId: string;
  sandboxId: string;
  userId: string;
  seq: number;
  sourceHostId: string;
  /** The completed object (VERIFYING or later), to delete. */
  objectKey: string | null;
  /** Sessions whose multipart upload may still exist. */
  sessions: { id: string; objectKey: string; uploadId: string }[];
};

/**
 * Ends one live offload in `tx`: `{id, state ∈ from}` → `terminal` with
 * `liveSandboxId` null and `failureCode`, then `shredOffloadKeys` (OPEN
 * sessions aborted, every wrap nulled, `shreddedAt` set) and its OPEN
 * transfers cancelled. Null (nothing written) when the row is not in `from`.
 * The caller holds the sandbox lock.
 */
export async function endLiveOffload(
  tx: Tx,
  offloadId: string,
  terminal: "FAILED" | "SUPERSEDED",
  code: string,
  from: readonly string[] = PRE_STORED_STATES,
): Promise<EndedOffload | null> {
  const [row] = await tx.$queryRaw<
    {
      id: string;
      sandboxId: string;
      userId: string;
      seq: number;
      sourceHostId: string;
      objectKey: string | null;
    }[]
  >`SELECT id, "sandboxId", "userId", seq, "sourceHostId", "objectKey" FROM sandbox_disk_offload
    WHERE id = ${offloadId} AND state::text = ANY(${[...from]}::text[]) FOR UPDATE`;
  if (!row) return null;
  const sessions = await tx.sandboxImageUploadSession.findMany({
    where: { diskOffloadId: offloadId, uploadId: { not: null } },
    select: { id: true, objectKey: true, uploadId: true },
    take: 64, // pagination:audited — one offload's sessions (one per begin)
  });
  await tx.sandboxDiskOffload.update({
    where: { id: offloadId },
    data: { state: terminal, liveSandboxId: null, failureCode: code.slice(0, 64) },
    select: { id: true },
  });
  await shredOffloadKeys(tx, offloadId);
  await tx.sandboxImageTransfer.updateMany({
    where: { diskOffloadId: offloadId, state: "OPEN" },
    data: { state: "CANCELLED", endReason: code.slice(0, 64) },
  });
  return {
    offloadId: row.id,
    sandboxId: row.sandboxId,
    userId: row.userId,
    seq: row.seq,
    sourceHostId: row.sourceHostId,
    objectKey: row.objectKey,
    sessions: sessions.flatMap((s) =>
      s.uploadId ? [{ id: s.id, objectKey: s.objectKey, uploadId: s.uploadId }] : [],
    ),
  };
}

/**
 * Admission supersede (T1 step 2, X2), for every reconnect admission (cold,
 * cached or restore; C6) in its own transaction under the sandbox lock: a
 * live offload that is not STORED (PENDING | EXPORTING | UPLOADING |
 * VERIFYING) becomes SUPERSEDED, its OPEN session is aborted and its keys
 * shredded, its transfer cancelled. That frees `liveSandboxId`, so the next
 * stop's offload can insert. Returns the cleanup for `finishEndedOffload`
 * (after commit), or null when there was no such offload.
 */
export async function supersedeLiveOffload(
  tx: Tx,
  sandboxId: string,
): Promise<EndedOffload | null> {
  const live = await tx.sandboxDiskOffload.findUnique({
    where: { liveSandboxId: sandboxId },
    select: { id: true },
  });
  if (!live) return null;
  return endLiveOffload(tx, live.id, "SUPERSEDED", "superseded");
}

/** Ends a live, not-yet-STORED offload as FAILED(code). */
export function failLiveOffload(tx: Tx, offloadId: string, code: string) {
  return endLiveOffload(tx, offloadId, "FAILED", code);
}

/**
 * After the ending transaction committed: abort each session's multipart
 * upload (forgetting the id once S3 no longer knows it) and delete the
 * completed object. Best effort: the sweeper aborts ABORTED sessions' uploads
 * and deletes every disk object outside the keep set after a day.
 */
export async function finishEndedOffload(
  store: Pick<ImageStore, "abortMultipart" | "deleteObject"> | null,
  ended: EndedOffload | null,
): Promise<void> {
  if (!store || !ended) return;
  for (const session of ended.sessions) {
    try {
      await store.abortMultipart(session.objectKey, session.uploadId);
    } catch (error) {
      if ((error as { name?: string } | null)?.name !== "NoSuchUpload") continue;
    }
    await prisma.sandboxImageUploadSession.updateMany({
      where: { id: session.id, state: { not: "OPEN" }, uploadId: session.uploadId },
      data: { uploadId: null },
    });
  }
  if (ended.objectKey) await store.deleteObject(ended.objectKey).catch(() => {});
}

/** The sandbox row lock (application order: host → sandbox → offload). */
export async function lockSandboxRow(tx: Tx, sandboxId: string): Promise<boolean> {
  const rows = await tx.$queryRaw<
    { id: string }[]
  >`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} FOR UPDATE`;
  return rows.length === 1;
}

export type MarkStoredOutcome =
  | { kind: "stored"; offloadId: string }
  | { kind: "superseded"; ended: EndedOffload | null }
  | { kind: "login_unsettled"; ended: EndedOffload | null }
  | { kind: "noop" };

/**
 * VERIFYING → STORED (T1), after the worker verified the object, in one
 * transaction under the sandbox lock:
 *
 * 1. `loginStateSettled` is re-checked; failing it ends the offload
 *    FAILED(login_unsettled) with a shred (U8);
 * 2. the offload CAS `{id, VERIFYING, completedSessionId, objectKey}` → STORED
 *    (0 rows: admission already superseded it — a no-op, never a second
 *    terminal write);
 * 3. the sandbox CAS `{id, STOPPED, generation = sourceGeneration,
 *    diskOffloadId: null}` sets `diskOffloadId` and `cachedOffloadSeq`. If it
 *    does not update exactly one row (a cached reconnect advanced the
 *    generation, or the state changed), the offload becomes SUPERSEDED and is
 *    shredded instead.
 *
 * The object of a FAILED/SUPERSEDED outcome is deleted by the caller after
 * commit (`finishEndedOffload`).
 */
export async function markStored(
  offloadId: string,
  expected: { completedSessionId: string; objectKey: string },
  client: { $transaction: typeof prisma.$transaction } = prisma,
): Promise<MarkStoredOutcome> {
  return client.$transaction(async (tx) => {
    const head = await tx.sandboxDiskOffload.findUnique({
      where: { id: offloadId },
      select: { sandboxId: true },
    });
    if (!head || !(await lockSandboxRow(tx, head.sandboxId))) return { kind: "noop" as const };
    const [row] = await tx.$queryRaw<
      { state: string; seq: number; sourceGeneration: number; sandboxId: string }[]
    >`SELECT state::text AS state, seq, "sourceGeneration", "sandboxId" FROM sandbox_disk_offload
      WHERE id = ${offloadId} FOR UPDATE`;
    if (row?.state !== "VERIFYING") return { kind: "noop" as const };
    if (!(await loginStateSettled(tx, row.sandboxId)))
      return {
        kind: "login_unsettled" as const,
        ended: await failLiveOffload(tx, offloadId, "login_unsettled"),
      };
    const [clock] = await tx.$queryRaw<
      { now: Date }[]
    >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
    const now = clock?.now ?? new Date();
    const stored = await tx.sandboxDiskOffload.updateMany({
      where: {
        id: offloadId,
        state: "VERIFYING",
        completedSessionId: expected.completedSessionId,
        objectKey: expected.objectKey,
      },
      data: { state: "STORED", verifiedAt: now, storedAt: now },
    });
    if (stored.count !== 1) return { kind: "noop" as const };
    const bound = await tx.sandbox.updateMany({
      where: {
        id: row.sandboxId,
        state: "STOPPED",
        generation: row.sourceGeneration,
        diskOffloadId: null,
      },
      data: { diskOffloadId: offloadId, cachedOffloadSeq: row.seq },
    });
    if (bound.count !== 1)
      return {
        kind: "superseded" as const,
        ended: await endLiveOffload(tx, offloadId, "SUPERSEDED", "superseded", ["STORED"]),
      };
    return { kind: "stored" as const, offloadId };
  });
}

/**
 * Publish the deterministic disk verify job (the worker decrypts, hashes and
 * sizes the object). A retained job of the same id is requeued.
 */
export async function enqueueDiskVerify(offloadId: string): Promise<void> {
  // Loaded on use: the queue client is import-time IO, and admission
  // (`supersedeLiveOffload`) imports this module from request paths.
  const { ensureRunnableJob, imageStoreMaintenanceQueue } = await import("@wssp/queue");
  await ensureRunnableJob(
    imageStoreMaintenanceQueue,
    "disk_verify",
    { kind: "disk_verify", offloadId },
    `disk-verify-${offloadId}`,
    { resetAttemptsMade: true },
  );
}

/** The `disk.offload.stored` frame (§7 "Stored ack") of a STORED offload,
 * or null. The caller sends it to the source host's current session. */
export async function storedAckFrame(offloadId: string) {
  const row = await prisma.sandboxDiskOffload.findFirst({
    where: { id: offloadId, state: "STORED" },
    select: {
      id: true,
      sandboxId: true,
      seq: true,
      fingerprint: true,
      sourceGeneration: true,
      sourceHostId: true,
    },
  });
  if (!row?.fingerprint) return null;
  return {
    hostId: row.sourceHostId,
    frame: {
      type: "disk.offload.stored" as const,
      sandboxId: row.sandboxId,
      offloadId: row.id,
      seq: row.seq,
      fingerprint: row.fingerprint,
      generation: row.sourceGeneration,
    },
  };
}

/**
 * Sweeper keep set (§6 "Sweeper", R10/S1/T13): of `keys`, the disk objects
 * still needed: the object of an offload in VERIFYING | STORED | EVICTING, of
 * a CONSUMED row inside `deleteAfter` (or without one yet), of a DELETING row
 * inside `shredAfter` or not yet shredded, or of an OPEN disk session.
 */
export async function keptDiskObjectKeys(
  client: Pick<Prisma.TransactionClient, "$queryRaw">,
  keys: readonly string[],
  now: Date,
): Promise<Set<string>> {
  if (keys.length === 0) return new Set();
  const rows = await client.$queryRaw<{ key: string }[]>`
    SELECT o."objectKey" AS key FROM sandbox_disk_offload o
    WHERE o."objectKey" = ANY(${[...keys]}::text[]) AND (
      o.state::text IN ('VERIFYING', 'STORED', 'EVICTING')
      OR (o.state::text = 'CONSUMED' AND (o."deleteAfter" IS NULL OR o."deleteAfter" > ${now}))
      OR (o.state::text = 'DELETING' AND (o."shreddedAt" IS NULL OR o."shredAfter" IS NULL
        OR o."shredAfter" > ${now})))
    UNION
    SELECT s."objectKey" AS key FROM sandbox_image_upload_session s
    WHERE s."objectKey" = ANY(${[...keys]}::text[]) AND s.state::text = 'OPEN'
      AND s."diskOffloadId" IS NOT NULL`;
  return new Set(rows.map((row) => row.key));
}
