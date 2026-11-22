import prisma, { type Prisma } from "@wssp/db";
import type { ImageFailureCause } from "@wssp/sandbox-contracts";
import { lockImageQuota } from "./config";

/**
 * Capture storage failure details (docs/operations/templates.md#capture).
 *
 * A cause keeps its identity end to end: the daemon's `image.job.failed`
 * cause becomes the transfer's `endReason`, the capture's `errorDetail` and
 * the build's `errorDetail`, always code-shaped (CHECK `^[a-z0-9_.]{1,64}$`)
 * and mapped here from the enum, never from daemon text.
 */
export const STORE_DETAIL_PATTERN = /^[a-z0-9_.]{1,64}$/;

/** The finalizer's own details (no host report). */
export const STORE_RULE_DETAILS = [
  "store_verify_failed",
  "store_failed",
  "upload_lost",
  "upload_stalled",
  "store_deadline",
] as const;

/** Server-side upload ends (no host report): the session, artifact and
 * transfer carry these, and a capture of the current attempt records them. */
export const SERVER_UPLOAD_DETAILS = [
  "store_unavailable",
  "store_complete_failed",
  "store_list_failed",
  "upload_invalid",
  "upload_stale",
  "store_verify_timeout",
  "operation_ended",
] as const;

/**
 * End reason of a capture upload whose begin the store refused before any
 * host held a grant (CreateMultipartUpload or the first presign failed).
 * The host retries the begin (a new transfer), so this end is no capture
 * failure: no evidence, the artifact stays UPLOADING, and the finalizer
 * ignores such a transfer (its `upload_lost` rule bounds a begin that never
 * succeeds).
 */
export const BEGIN_RETRY_END_REASON = "begin_retry.store_unavailable";

/**
 * Transfer end reasons that are bookkeeping, never a capture's failure
 * evidence (W2): a begin the store refused for now (retried by the host), and
 * a transfer a later begin of the same job superseded (e.g. a begin re-sent
 * after its grant was lost in a relay reconnect). The capture's newer
 * transfer carries its real cause; `upload_lost` bounds a job with none.
 */
export const BOOKKEEPING_END_REASONS: readonly string[] = [BEGIN_RETRY_END_REASON, "superseded"];

function shaped(detail: string): string {
  const cut = detail.slice(0, 64);
  return STORE_DETAIL_PATTERN.test(cut) ? cut : "upload_failed";
}

/** The detail of a host-reported upload end. */
export function imageFailureDetail(m: {
  cause: ImageFailureCause;
  httpStatus?: number;
  refusal?: string;
}): string {
  switch (m.cause) {
    case "http_status":
      return shaped(`upload_http_${m.httpStatus ?? 0}`);
    case "refused":
      return shaped(`upload_refused.${m.refusal ?? "cancelled"}`);
    default:
      return shaped(`upload_${m.cause}`);
  }
}

/** The detail of an upload transfer that ended other than COMPLETE. */
export function transferEndDetail(endReason: string | null): string {
  if (!endReason) return "upload_failed";
  return shaped(
    endReason.startsWith("upload_") || endReason.startsWith("store_")
      ? endReason
      : `upload_${endReason}`,
  );
}

/**
 * Best-effort abort of a session's multipart upload; on success (or when S3
 * no longer knows it) the session forgets the id, otherwise the sweeper
 * retries (`sweepImageStore`). Only for a session that is no longer OPEN.
 */
export async function abortSessionUpload(
  store: { abortMultipart(key: string, uploadId: string): Promise<void> },
  session: { id: string; objectKey: string; uploadId: string },
): Promise<void> {
  try {
    await store.abortMultipart(session.objectKey, session.uploadId);
  } catch (error) {
    if ((error as { name?: string } | null)?.name !== "NoSuchUpload") return;
  }
  await prisma.sandboxImageUploadSession.updateMany({
    where: { id: session.id, state: { not: "OPEN" }, uploadId: session.uploadId },
    data: { uploadId: null },
  });
}

/** The `image.job.cancel` reason for a detail (`^[a-z_.]{1,64}$`). */
export function cancelReasonOf(detail: string): string {
  return detail.replace(/[^a-z_.]/g, "_").slice(0, 64) || "cancelled";
}

export type UploadAbort = { id: string; objectKey: string; uploadId: string };
export type UploadCancel = { transferId: string; hostId: string; epoch: number; reason: string };

/** What a caller does after the ending transaction commits. */
export type UploadEnd = {
  /** Multipart uploads to abort (`abortSessionUpload`). */
  aborts: UploadAbort[];
  /** Hosts to tell `image.job.cancel` (only with `notifyHost`). */
  cancels: UploadCancel[];
  /** Transfers this call ended. */
  ended: string[];
  /** Sessions this call claimed (ended). */
  sessions: string[];
};

/**
 * Which template upload to end: one transfer; every OPEN capture upload of
 * one (operation, dispatch attempt); or one session (in state `from`).
 */
export type UploadEndTarget =
  | { transferId: string }
  | { operationId: string; attempt: number }
  | { sessionId: string; from?: "OPEN" | "COMPLETE" };

const transferSelect = {
  id: true,
  purpose: true,
  operationId: true,
  dispatchAttempt: true,
  sourceHostId: true,
  sourceEpoch: true,
} satisfies Prisma.SandboxImageTransferSelect;

const sessionSelect = {
  id: true,
  state: true,
  transferId: true,
  artifactId: true,
  objectKey: true,
  uploadId: true,
} satisfies Prisma.SandboxImageUploadSessionSelect;

/**
 * End a template upload for a failure, with its cause (I1, I3, I4): the one
 * place that does it. In the caller's transaction (after its host lock, if
 * it holds one), each write conditional on the row's state:
 * - the session (OPEN, or COMPLETE when `from: "COMPLETE"`) → ABORTED with
 *   `endReason = detail`; its artifact → FAILED with `failureDetail`, while
 *   UPLOADING (or VERIFYING with that session's object);
 * - the transfer → `state` with `endReason = detail` (and its links gone),
 *   unless another writer already claimed its session (a completion);
 * - with `evidence` (default), a capture upload of the capture's current
 *   attempt records `detail` on the capture (first writer wins);
 * - with `keepArtifact`, the artifact is left as it is (a retried begin
 *   reopens it; see `BEGIN_RETRY_END_REASON`).
 * The caller aborts `aborts` and sends `cancels` after commit.
 */
export async function endTemplateUpload(
  tx: Prisma.TransactionClient,
  target: UploadEndTarget,
  options: {
    detail: string;
    state?: "FAILED" | "CANCELLED";
    evidence?: boolean;
    notifyHost?: boolean;
    keepArtifact?: boolean;
  },
): Promise<UploadEnd> {
  const detail = shaped(options.detail);
  const state = options.state ?? "FAILED";
  const evidence = options.evidence ?? true;
  const from = "sessionId" in target ? (target.from ?? "OPEN") : "OPEN";
  const result: UploadEnd = { aborts: [], cancels: [], ended: [], sessions: [] };
  const pairs: {
    transfer: Prisma.SandboxImageTransferGetPayload<{ select: typeof transferSelect }> | null;
    session: Prisma.SandboxImageUploadSessionGetPayload<{ select: typeof sessionSelect }> | null;
  }[] = [];
  if ("sessionId" in target) {
    const session = await tx.sandboxImageUploadSession.findFirst({
      where: { id: target.sessionId, state: from, artifactId: { not: null } },
      select: sessionSelect,
    });
    if (session)
      pairs.push({
        session,
        transfer: await tx.sandboxImageTransfer.findUnique({
          where: { id: session.transferId },
          select: transferSelect,
        }),
      });
  } else {
    const transfers = await tx.sandboxImageTransfer.findMany({
      where:
        "transferId" in target
          ? {
              id: target.transferId,
              state: "OPEN",
              mode: "S3",
              purpose: { in: ["CAPTURE_UPLOAD", "PUBLISH"] },
            }
          : {
              operationId: target.operationId,
              dispatchAttempt: target.attempt,
              purpose: "CAPTURE_UPLOAD",
              mode: "S3",
              state: "OPEN",
            },
      select: transferSelect,
      orderBy: { id: "asc" },
      take: 8,
    });
    for (const transfer of transfers)
      pairs.push({
        transfer,
        session: await tx.sandboxImageUploadSession.findFirst({
          where: { transferId: transfer.id, state: "OPEN", artifactId: { not: null } },
          select: sessionSelect,
        }),
      });
  }
  for (const { transfer, session } of pairs) {
    let claimed = false;
    if (session?.artifactId) {
      const claim = await tx.sandboxImageUploadSession.updateMany({
        where: { id: session.id, state: from, artifactId: session.artifactId },
        data: { state: "ABORTED", liveArtifactId: null, endReason: detail },
      });
      claimed = claim.count === 1;
      if (claimed) {
        result.sessions.push(session.id);
        if (!options.keepArtifact)
          await tx.sandboxImageArtifact.updateMany({
            where:
              from === "OPEN"
                ? { id: session.artifactId, state: "UPLOADING" }
                : { id: session.artifactId, state: "VERIFYING", objectKey: session.objectKey },
            data: { state: "FAILED", failureDetail: detail },
          });
        if (session.uploadId)
          result.aborts.push({
            id: session.id,
            objectKey: session.objectKey,
            uploadId: session.uploadId,
          });
      } else {
        // A completion that claimed the session owns this upload's end.
        const now = await tx.sandboxImageUploadSession.findUnique({
          where: { id: session.id },
          select: { state: true },
        });
        if (now?.state === "COMPLETE") continue;
      }
    }
    if (!transfer) continue;
    const ended = await tx.sandboxImageTransfer.updateMany({
      where: { id: transfer.id, state: from === "OPEN" ? "OPEN" : { in: ["OPEN", "COMPLETE"] } },
      data: { state, endReason: detail },
    });
    if (ended.count === 1) {
      result.ended.push(transfer.id);
      await tx.sandboxImageLink.deleteMany({ where: { transferId: transfer.id } });
      if (options.notifyHost && transfer.sourceHostId && transfer.sourceEpoch !== null)
        result.cancels.push({
          transferId: transfer.id,
          hostId: transfer.sourceHostId,
          epoch: transfer.sourceEpoch,
          reason: cancelReasonOf(detail),
        });
    }
    if (
      evidence &&
      (claimed || ended.count === 1) &&
      transfer.purpose === "CAPTURE_UPLOAD" &&
      transfer.operationId &&
      transfer.dispatchAttempt !== null
    )
      await recordCaptureEvidence(tx, {
        operationId: transfer.operationId,
        attempt: transfer.dispatchAttempt,
        hostId: transfer.sourceHostId,
        detail,
      });
  }
  // A capture's own report with no upload yet (export, no grant, refused
  // begin): the caller proved the attempt; the capture records the cause.
  if (evidence && "operationId" in target)
    await recordCaptureEvidence(tx, {
      operationId: target.operationId,
      attempt: target.attempt,
      hostId: null,
      detail,
    });
  return result;
}

/**
 * A capture whose job is over (its host's terminal operation-ref report, or
 * the finalizer failed it) may leave artifacts that its retried begins kept
 * UPLOADING (`BEGIN_RETRY_END_REASON`, a#3): no session is live on them,
 * yet they hold stored-byte quota and block a publish of that image until
 * stale maintenance. Each is failed here with the capture's cause, unless a
 * newer session owns it: under the owner's image quota lock (which every
 * begin takes first, so none re-opens it meanwhile), only while the
 * artifact is UPLOADING with no OPEN session and its newest session is one
 * of this capture's begin-retry sessions. One transaction per artifact,
 * after the caller's commit (the quota lock comes before any host lock).
 * Best effort: stale maintenance stays the backstop.
 */
export async function failAbandonedBeginArtifacts(operationId: string): Promise<void> {
  const abandoned = await prisma.sandboxImageUploadSession.findMany({
    where: {
      state: "ABORTED",
      endReason: BEGIN_RETRY_END_REASON,
      artifactId: { not: null },
      Transfer: { operationId, purpose: "CAPTURE_UPLOAD" },
    },
    select: { artifactId: true },
    orderBy: { id: "asc" },
    take: 64, // pagination:audited — one capture's retried begins (≤ 5 per attempt)
  });
  const artifactIds = [...new Set(abandoned.flatMap((s) => (s.artifactId ? [s.artifactId] : [])))];
  if (artifactIds.length === 0) return;
  const capture = await prisma.sandboxTemplateCapture.findUnique({
    where: { operationId },
    select: { errorDetail: true },
  });
  const detail = shaped(capture?.errorDetail ?? "store_unavailable");
  for (const artifactId of artifactIds) {
    const artifact = await prisma.sandboxImageArtifact.findUnique({
      where: { id: artifactId },
      select: { userId: true },
    });
    if (!artifact) continue;
    await prisma.$transaction(async (tx) => {
      await lockImageQuota(tx, artifact.userId);
      const newest = await tx.sandboxImageUploadSession.findFirst({
        where: { artifactId },
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        select: { state: true, endReason: true, Transfer: { select: { operationId: true } } },
      });
      if (
        newest?.state !== "ABORTED" ||
        newest.endReason !== BEGIN_RETRY_END_REASON ||
        newest.Transfer.operationId !== operationId
      )
        return;
      await tx.sandboxImageArtifact.updateMany({
        where: { id: artifactId, state: "UPLOADING", UploadSessions: { none: { state: "OPEN" } } },
        data: { state: "FAILED", failureDetail: detail },
      });
    });
  }
}

/** Host or server storage-failure evidence on a waiting capture of its
 * current dispatch attempt; never overwrites an earlier cause. */
async function recordCaptureEvidence(
  tx: Prisma.TransactionClient,
  input: { operationId: string; attempt: number; hostId: string | null; detail: string },
): Promise<void> {
  await tx.sandboxTemplateCapture.updateMany({
    where: {
      operationId: input.operationId,
      ...(input.hostId ? { hostId: input.hostId } : {}),
      state: { in: ["PENDING", "CAPTURED", "STORING"] },
      errorDetail: null,
      Operation: { dispatchAttempt: input.attempt },
    },
    data: { errorDetail: input.detail },
  });
}

/** After commit: abort every ended session's multipart upload (best effort;
 * the hourly sweep retries). */
export async function abortEndedUploads(
  store: { abortMultipart(key: string, uploadId: string): Promise<void> } | null,
  end: Pick<UploadEnd, "aborts">,
): Promise<void> {
  if (!store) return;
  for (const session of end.aborts) await abortSessionUpload(store, session).catch(() => {});
}
