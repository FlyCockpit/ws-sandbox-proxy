import { createHash, randomBytes } from "node:crypto";
import { consumeImageGrantBudget } from "@wssp/api/sandbox/budgets";
import { foreignImageAccessHolds } from "@wssp/api/sandbox/image-store/access";
import { finalizeCapture } from "@wssp/api/sandbox/image-store/captures";
import {
  accountImageQuotas,
  accountStoredImageBytes,
  hostImageFeatures,
  imageDistributionMode,
  lockImageQuota,
} from "@wssp/api/sandbox/image-store/config";
import { unrecordedForeignCaptureReleasable } from "@wssp/api/sandbox/image-store/references";
import {
  IMAGE_ENCRYPTION_SCHEME,
  ImageObjectExistsError,
  imageMasterKey,
  imageObjectKey,
  imageStore,
  newDataKey,
  newImageSessionId,
  unwrapDataKey,
  wrapDataKey,
} from "@wssp/api/sandbox/image-store/s3";
import {
  abortEndedUploads,
  abortSessionUpload,
  BEGIN_RETRY_END_REASON,
  cancelReasonOf,
  endTemplateUpload,
  failAbandonedBeginArtifacts,
  imageFailureDetail,
  type UploadEnd,
} from "@wssp/api/sandbox/image-store/store-failure";
import { restoreOffloadOf } from "@wssp/api/sandbox/launch-mode";
import {
  hostDatabaseNow,
  lockHostByEpoch,
  RECORDED_CAPTURE_WHERE,
  relayTransaction,
  requireRelayFence,
} from "@wssp/api/sandbox/relay-fence";
import prisma, { type Prisma } from "@wssp/db";
import { readImageStoreEnv } from "@wssp/env/image-store-config";
import { env } from "@wssp/env/server";
import {
  type DaemonImageMessage,
  encryptedImageLength,
  IMAGE_LINKS_MAX,
  IMAGE_RELAY_PART_BYTES,
  IMAGE_S3_PART_BYTES,
  IMAGE_UPLOAD_PARTS_MAX,
  IMAGE_WIRE_BYTES_MAX,
  type ImageRelayLinkV11,
  imageUploadPartBytes,
  type ServerImageMessage,
} from "@wssp/sandbox-contracts";
import type { ImageRelaySpool } from "../sandbox-image-relay/spool.js";
import {
  handleDiskTransferFailure,
  handleRestoreFetchRequest,
  type ReportOutcome,
} from "./disk-handlers.js";
import { confirmDiskLiveness, type DiskLiveness, takeDiskLivenessSlot } from "./disk-liveness.js";
import {
  captureWorkload,
  fetchWorkload,
  transferAuthoritySelect,
  transferAuthorized,
} from "./image-authority.js";
import type { RelaySender } from "./operation-handlers.js";

/**
 * Host-plane image frames (docs/operations/templates.md#image-distribution).
 *
 * Every request is re-checked under the sender's relay fence (host lock by
 * epoch). Grants are produced in memory and never written: only the transfer
 * row and one-time link digests are persisted. Link tokens, presigned URLs and
 * data keys never reach a log line, the outbox or a receipt.
 */
export type ImageFrameContext = {
  sender: RelaySender;
  /** Send to the sender's socket. */
  reply: (frame: ServerImageMessage) => void;
  /** Send to another host's current image-capable session; false when absent. */
  sendTo: (hostId: string, epoch: number, frame: ServerImageMessage) => boolean;
  /** The host has a current, reconciled, image-capable session on this epoch. */
  isHostCurrent: (hostId: string, epoch: number) => boolean;
  spool: ImageRelaySpool;
  /** This connection's disk liveness allowance outside the grant budget
   * (`takeDiskLivenessSlot`); none: no allowance. */
  diskLiveness?: DiskLiveness;
  /** A capture begin's grant budget was spent before its ordering lookup
   * (session manager): `handleImageUploadBegin` does not spend it again. */
  beginBudgetSpent?: boolean;
};

const LINK_TTL_MS = 10 * 60_000;
const SOURCE_WINDOW_PARTS = 4;

/** One point of the per-host image grant budget; false when over or unavailable. */
async function grantBudget(hostId: string): Promise<boolean> {
  try {
    await consumeImageGrantBudget(hostId);
    return true;
  } catch {
    return false;
  }
}

/** One point of the host's grant budget, spent before a capture begin's
 * ordering lookup (`CaptureBeginOrder.hold`); false: over budget. */
export const spendImageGrantBudget = grantBudget;

/** Transfers whose budget-dropped upload frame was logged (FB-B6), oldest first. */
const budgetDropLogged = new Set<string>();
const BUDGET_DROP_LOGGED_MAX = 4096;

/**
 * An upload frame (parts, heartbeat, renew) dropped over the host's grant
 * budget gets no reply, by design (the host retries). It is logged once per
 * transfer, with ids and the frame type only, so the drop is never silent.
 */
function noteBudgetDrop(hostId: string, transferId: string, frame: string): void {
  if (budgetDropLogged.has(transferId)) return;
  if (budgetDropLogged.size >= BUDGET_DROP_LOGGED_MAX) {
    const oldest = budgetDropLogged.values().next().value;
    if (oldest !== undefined) budgetDropLogged.delete(oldest);
  }
  budgetDropLogged.add(transferId);
  console.warn("[sandbox-image] upload frame dropped over the grant budget:", {
    hostId,
    transferId,
    frame,
  });
}

export function linkTokenDigest(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function partSize(total: bigint, partBytes: number, part: number): number {
  const start = BigInt(part - 1) * BigInt(partBytes);
  const remaining = total - start;
  return Number(remaining < BigInt(partBytes) ? remaining : BigInt(partBytes));
}

async function mintLinks(
  tx: Prisma.TransactionClient,
  input: {
    transferId: string;
    hostId: string;
    hostEpoch: number;
    role: "SOURCE" | "DEST";
    parts: number[];
    now: Date;
  },
): Promise<ImageRelayLinkV11[]> {
  const links: ImageRelayLinkV11[] = [];
  for (const part of input.parts.slice(0, IMAGE_LINKS_MAX)) {
    const token = randomBytes(32).toString("base64url");
    // A re-request replaces the previous (possibly expired) link for the part.
    await tx.sandboxImageLink.deleteMany({
      where: { transferId: input.transferId, role: input.role, partNumber: part },
    });
    const row = await tx.sandboxImageLink.create({
      data: {
        transferId: input.transferId,
        hostId: input.hostId,
        hostEpoch: input.hostEpoch,
        role: input.role,
        partNumber: part,
        tokenDigest: linkTokenDigest(token),
        expiresAt: new Date(input.now.getTime() + LINK_TTL_MS),
      },
      select: { id: true },
    });
    links.push({ part, linkId: row.id, token });
  }
  return links;
}

function range(first: number, last: number): number[] {
  const out: number[] = [];
  for (let n = first; n <= last; n++) out.push(n);
  return out;
}

type FetchOutcome =
  | { kind: "refused"; code: string }
  | {
      kind: "s3";
      transferId: string;
      size: bigint;
      partSize: number;
      objectKey: string;
      artifact: {
        id: string;
        userId: string;
        wrappedKey: Uint8Array | null;
        wrappedKeyNonce: Uint8Array | null;
      };
    }
  | {
      kind: "relay";
      transferId: string;
      size: bigint;
      ownerId: string;
      fingerprint: string;
      source: { id: string; epoch: number };
      sourceLinks: ImageRelayLinkV11[];
      destLinks: ImageRelayLinkV11[];
    };

/** `image.fetch.request`: authority, policy and quota under the sender's fence. */
export async function handleImageFetchRequest(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.fetch.request" }>,
): Promise<void> {
  const refuse = (code: string) =>
    ctx.reply({ type: "image.fetch.refused", requestId: m.requestId, code });
  const mode = imageDistributionMode();
  if (mode === "off") return refuse("image_unavailable");
  const { sender } = ctx;
  if (!(await grantBudget(sender.hostId))) return refuse("rate_limited");
  // A restore attempt fetches its stored disk, never a
  // template image. `launchMode` and `restoreOffloadId` are immutable, so
  // this unlocked read only routes; the fence below re-proves both.
  const head = await prisma.sandboxOperation.findFirst({
    where: { id: m.operationId },
    select: { kind: true, launchMode: true, restoreOffloadId: true },
  });
  const restoreOffloadId = head ? restoreOffloadOf(head) : null;
  if (restoreOffloadId !== null) return handleRestoreFetchRequest(ctx, m, restoreOffloadId);
  const superseded: { id: string; sourceHostId: string | null; sourceEpoch: number | null }[] = [];
  const outcome = await relayTransaction<FetchOutcome>(
    async (tx) => {
      // Account quota lock before H (P2-6); the fence below re-proves the owner.
      const claimed = await tx.sandboxOperation.findFirst({
        where: { id: m.operationId },
        select: { userId: true },
      });
      if (!claimed) return { kind: "refused", code: "stale_operation" };
      await lockImageQuota(tx, claimed.userId);
      await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
      requireRelayFence(sender.isCurrent?.() !== false);
      const now = await hostDatabaseNow(tx);
      const host = await tx.sandboxHost.findFirst({
        where: { id: sender.hostId, userId: sender.userId },
        select: { daemonFeatures: true },
      });
      const features = hostImageFeatures(host?.daemonFeatures ?? null);
      if (!features?.fetch) return { kind: "refused", code: "unsupported" };
      // The common workload fence (P1-1): exact operation and attempt on this
      // connection, sharing, authorizing key, creator policy and placement.
      const workload = await fetchWorkload(tx, {
        operationId: m.operationId,
        hostId: sender.hostId,
        hostOwnerId: sender.userId,
        epoch: sender.connectionEpoch,
        generation: m.generation,
        sandboxId: m.sandboxId,
        attempt: m.attempt,
        fingerprint: m.fingerprint,
      });
      if (!workload?.architecture || workload.ownerId !== claimed.userId)
        return { kind: "refused", code: "stale_operation" };
      // A repeat while a grant for this job is still open on this connection
      // and attempt mints nothing new (no second transfer, link set or
      // signature; P2-8). A host that gave up reports image.fetch.failed
      // first, which ends that transfer (round-2 P2-9). A grant held by an
      // older dispatch attempt or a previous connection can never be
      // continued by this request (round-2 P2-3): it is superseded here.
      const open = await tx.sandboxImageTransfer.findMany({
        where: {
          operationId: workload.operationId,
          fingerprint: m.fingerprint,
          purpose: "FETCH",
          destHostId: sender.hostId,
          state: "OPEN",
        },
        select: {
          id: true,
          dispatchAttempt: true,
          destEpoch: true,
          expiresAt: true,
          sourceHostId: true,
          sourceEpoch: true,
        },
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
        superseded.push(stale);
      }
      const op = { id: workload.operationId, Placement: { architecture: workload.architecture } };
      const ownerId = workload.ownerId;
      // Downloads per hour: only the first grant per (operation, image) counts.
      const counted = await tx.sandboxImageTransfer.findFirst({
        where: { operationId: op.id, fingerprint: m.fingerprint, countedDownload: true },
        select: { id: true },
      });
      const quotas = await accountImageQuotas(tx, ownerId);
      if (!counted && quotas.downloadsPerHour !== null) {
        const recent = await tx.sandboxImageTransfer.count({
          where: {
            userId: ownerId,
            countedDownload: true,
            createdAt: { gt: new Date(now.getTime() - 3_600_000) },
          },
        });
        if (recent >= quotas.downloadsPerHour) return { kind: "refused", code: "download_quota" };
      }
      if (mode === "s3") {
        const artifact = await tx.sandboxImageArtifact.findFirst({
          where: {
            userId: ownerId,
            fingerprint: m.fingerprint,
            architecture: op.Placement.architecture,
            state: "STORED",
            storeKind: "S3",
          },
          select: {
            id: true,
            userId: true,
            sizeBytes: true,
            objectKey: true,
            partSize: true,
            wrappedKey: true,
            wrappedKeyNonce: true,
          },
        });
        if (!artifact?.objectKey) return { kind: "refused", code: "image_unavailable" };
        const transfer = await tx.sandboxImageTransfer.create({
          data: {
            userId: ownerId,
            fingerprint: m.fingerprint,
            artifactId: artifact.id,
            purpose: "FETCH",
            mode: "S3",
            destHostId: sender.hostId,
            destHostOwnerId: sender.userId,
            destEpoch: sender.connectionEpoch,
            operationId: op.id,
            dispatchAttempt: m.attempt,
            sizeBytes: artifact.sizeBytes,
            partSize: artifact.partSize ?? IMAGE_S3_PART_BYTES,
            partCount: Math.max(
              1,
              Math.ceil(Number(artifact.sizeBytes) / (artifact.partSize ?? IMAGE_S3_PART_BYTES)),
            ),
            countedDownload: !counted,
            expiresAt: new Date(
              now.getTime() + readImageStoreEnv().IMAGE_S3_PRESIGN_TTL_SECONDS * 1000,
            ),
          },
          select: { id: true },
        });
        await tx.sandboxImageArtifact.update({
          where: { id: artifact.id },
          data: { lastFetchedAt: now },
        });
        return {
          kind: "s3",
          transferId: transfer.id,
          size: artifact.sizeBytes,
          partSize: artifact.partSize ?? IMAGE_S3_PART_BYTES,
          objectKey: artifact.objectKey,
          artifact,
        };
      }
      const active = await tx.sandboxImageTransfer.count({
        where: { mode: "RELAY", state: "OPEN" },
      });
      if (active >= (env.IMAGE_RELAY_MAX_ACTIVE ?? 4))
        return { kind: "refused", code: "relay_busy" };
      const sources = await tx.$queryRaw<{ id: string; epoch: number; size: bigint }[]>`
        SELECT src.id, src."connectionEpoch" AS epoch, a."sizeBytes" AS size
        FROM sandbox_template_availability a
        JOIN sandbox_host src ON src.id = a."hostId" AND src."userId" = a."hostOwnerId"
        WHERE a."userId" = ${ownerId} AND a."hostOwnerId" = ${ownerId}
          AND src.id <> ${sender.hostId} AND src.status = 'CONNECTED'
          AND src."deletionRequestedAt" IS NULL
          AND a."localFingerprint" = ${m.fingerprint} AND a.status = 'AVAILABLE'
          AND a."verifiedConnectionEpoch" = src."connectionEpoch"
          AND a."sizeBytes" IS NOT NULL
          AND (a."imageFormat" IS NULL OR a."imageFormat" = 'unified')
          AND (src."daemonFeatures"->'image'->'serve') = 'true'::jsonb
        ORDER BY src."lastHeartbeatAt" DESC NULLS LAST, src.id LIMIT 8`;
      const source = sources.find((s) => ctx.isHostCurrent(s.id, s.epoch));
      if (!source) return { kind: "refused", code: "image_unavailable" };
      const parts = Math.max(1, Math.ceil(Number(source.size) / IMAGE_RELAY_PART_BYTES));
      const startPart = Math.min(
        parts,
        Math.floor(Math.max(0, m.resumeOffset) / IMAGE_RELAY_PART_BYTES) + 1,
      );
      const transfer = await tx.sandboxImageTransfer.create({
        data: {
          userId: ownerId,
          fingerprint: m.fingerprint,
          purpose: "FETCH",
          mode: "RELAY",
          sourceHostId: source.id,
          sourceHostOwnerId: ownerId,
          sourceEpoch: source.epoch,
          destHostId: sender.hostId,
          destHostOwnerId: sender.userId,
          destEpoch: sender.connectionEpoch,
          operationId: op.id,
          dispatchAttempt: m.attempt,
          sizeBytes: source.size,
          partSize: IMAGE_RELAY_PART_BYTES,
          partCount: parts,
          bytesDone: BigInt(startPart - 1) * BigInt(IMAGE_RELAY_PART_BYTES),
          countedDownload: !counted,
          expiresAt: new Date(now.getTime() + 24 * 3_600_000),
        },
        select: { id: true },
      });
      const window = range(startPart, Math.min(parts, startPart + SOURCE_WINDOW_PARTS - 1));
      return {
        kind: "relay",
        transferId: transfer.id,
        size: source.size,
        ownerId,
        fingerprint: m.fingerprint,
        source: { id: source.id, epoch: source.epoch },
        sourceLinks: await mintLinks(tx, {
          transferId: transfer.id,
          hostId: source.id,
          hostEpoch: source.epoch,
          role: "SOURCE",
          parts: window,
          now,
        }),
        destLinks: await mintLinks(tx, {
          transferId: transfer.id,
          hostId: sender.hostId,
          hostEpoch: sender.connectionEpoch,
          role: "DEST",
          parts: window,
          now,
        }),
      };
    },
    { kind: "refused", code: "stale_operation" },
  );
  // Superseded grants (committed above) release their spool and source.
  for (const stale of superseded) {
    const ended = await prisma.sandboxImageTransfer.findFirst({
      where: { id: stale.id, state: "CANCELLED", endReason: "superseded" },
      select: { id: true },
    });
    if (!ended) continue;
    await endTransfer(
      ctx,
      stale.id,
      "CANCELLED",
      "superseded",
      stale.sourceHostId && stale.sourceEpoch
        ? { hostId: stale.sourceHostId, epoch: stale.sourceEpoch }
        : null,
    );
  }
  if (outcome.kind === "refused") return refuse(outcome.code);
  if (outcome.kind === "s3") {
    const store = imageStore();
    if (!store) return refuse("image_unavailable");
    const master = imageMasterKey();
    let encryption: { scheme: typeof IMAGE_ENCRYPTION_SCHEME; key: string } | undefined;
    if (outcome.artifact.wrappedKey && outcome.artifact.wrappedKeyNonce) {
      if (!master) return refuse("image_unavailable");
      encryption = {
        scheme: IMAGE_ENCRYPTION_SCHEME,
        key: unwrapDataKey(
          master,
          {
            wrappedKey: outcome.artifact.wrappedKey,
            wrappedKeyNonce: outcome.artifact.wrappedKeyNonce,
          },
          outcome.artifact.id,
          outcome.artifact.userId,
        ).toString("base64"),
      };
    }
    ctx.reply({
      type: "image.fetch.grant",
      requestId: m.requestId,
      transferId: outcome.transferId,
      mode: "S3",
      sizeBytes: Number(outcome.size),
      partSize: outcome.partSize,
      expiresAtUnixMs: Date.now() + store.settings.presignTtlSeconds * 1000,
      url: await store.presignGet(outcome.objectKey),
      ...(encryption ? { encryption } : {}),
    });
    return;
  }
  const served = ctx.sendTo(outcome.source.id, outcome.source.epoch, {
    type: "image.serve.request",
    transferId: outcome.transferId,
    imageOwnerId: outcome.ownerId,
    fingerprint: outcome.fingerprint,
    sizeBytes: Number(outcome.size),
    partSize: IMAGE_RELAY_PART_BYTES,
    links: outcome.sourceLinks,
  });
  if (!served) {
    await endTransfer(ctx, outcome.transferId, "FAILED", "source_offline");
    return refuse("image_unavailable");
  }
  ctx.reply({
    type: "image.fetch.grant",
    requestId: m.requestId,
    transferId: outcome.transferId,
    mode: "RELAY",
    sizeBytes: Number(outcome.size),
    partSize: IMAGE_RELAY_PART_BYTES,
    expiresAtUnixMs: Date.now() + LINK_TTL_MS,
    links: outcome.destLinks,
  });
}

/** Mark a transfer terminal, drop its spool and links, and tell the other side. */
async function endTransfer(
  ctx: Pick<ImageFrameContext, "sendTo" | "spool">,
  transferId: string,
  state: "COMPLETE" | "FAILED" | "EXPIRED" | "CANCELLED",
  reason: string,
  notify?: { hostId: string; epoch: number } | null,
): Promise<void> {
  await prisma.sandboxImageTransfer.updateMany({
    where: { id: transferId, state: "OPEN" },
    data: { state, endReason: reason },
  });
  await prisma.sandboxImageLink.deleteMany({ where: { transferId } });
  await ctx.spool.dropTransfer(transferId);
  if (notify)
    ctx.sendTo(notify.hostId, notify.epoch, {
      type: "image.job.cancel",
      transferId,
      reason: reason.replace(/[^a-z_.]/g, "_").slice(0, 64) || "cancelled",
    });
}

async function openTransferFor(sender: RelaySender, transferId: string, role: "SOURCE" | "DEST") {
  return prisma.sandboxImageTransfer.findFirst({
    where: {
      id: transferId,
      state: "OPEN",
      ...(role === "SOURCE"
        ? { sourceHostId: sender.hostId, sourceEpoch: sender.connectionEpoch }
        : { destHostId: sender.hostId, destEpoch: sender.connectionEpoch }),
    },
  });
}

export async function handleImageLinksRequest(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.links.request" }>,
): Promise<void> {
  if (!(await grantBudget(ctx.sender.hostId)))
    return ctx.reply({
      type: "image.job.cancel",
      transferId: m.transferId,
      reason: "rate_limited",
    });
  const links = await relayTransaction(async (tx) => {
    await lockHostByEpoch(tx, ctx.sender.hostId, ctx.sender.connectionEpoch, ctx.sender.userId);
    requireRelayFence(ctx.sender.isCurrent?.() !== false);
    const transfer = await openTransferFor(ctx.sender, m.transferId, m.role);
    if (!transfer || transfer.mode !== "RELAY") return null;
    const now = await hostDatabaseNow(tx);
    if (!(await transferAuthorized(tx, transfer, now))) return null;
    const acked = Number(transfer.bytesDone / BigInt(transfer.partSize));
    const allowed = m.parts.filter(
      (n) => n <= transfer.partCount && (m.role === "DEST" || n <= acked + SOURCE_WINDOW_PARTS),
    );
    if (allowed.length === 0) return [];
    return mintLinks(tx, {
      transferId: transfer.id,
      hostId: ctx.sender.hostId,
      hostEpoch: ctx.sender.connectionEpoch,
      role: m.role,
      parts: allowed,
      now,
    });
  }, null);
  if (links === null)
    return ctx.reply({
      type: "image.job.cancel",
      transferId: m.transferId,
      reason: "stale_transfer",
    });
  ctx.reply({ type: "image.links.grant", transferId: m.transferId, role: m.role, links });
}

/** Destination credit: the ACKed part's hash must equal the spooled part's. */
export async function handleImagePartAck(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.part.ack" }>,
): Promise<void> {
  const transfer = await openTransferFor(ctx.sender, m.transferId, "DEST");
  if (!transfer || transfer.mode !== "RELAY") return;
  const spooled = ctx.spool.get(transfer.id, m.part);
  const source =
    transfer.sourceHostId && transfer.sourceEpoch
      ? { hostId: transfer.sourceHostId, epoch: transfer.sourceEpoch }
      : null;
  if (!spooled || spooled.sha256 !== m.sha256) {
    await endTransfer(ctx, transfer.id, "FAILED", "corrupt", source);
    ctx.reply({ type: "image.job.cancel", transferId: transfer.id, reason: "corrupt" });
    return;
  }
  const expected = BigInt(m.part - 1) * BigInt(transfer.partSize);
  // Parts are ACKed in order; an out-of-order or repeated ACK changes nothing.
  if (transfer.bytesDone === expected) {
    const done = transfer.bytesDone + BigInt(spooled.size);
    await prisma.sandboxImageTransfer.updateMany({
      where: { id: transfer.id, state: "OPEN", bytesDone: transfer.bytesDone },
      data: {
        bytesDone: done,
        lastProgressAt: new Date(),
        ...(done >= transfer.sizeBytes ? { state: "COMPLETE", endReason: "complete" } : {}),
      },
    });
    if (done >= transfer.sizeBytes)
      await prisma.sandboxImageLink.deleteMany({ where: { transferId: transfer.id } });
  }
  await ctx.spool.drop(transfer.id, m.part);
}

/** Owners recorded for (host, fingerprint) only from a completed job (M4). */
async function upsertCachedEvidence(
  tx: Prisma.TransactionClient,
  input: {
    sender: RelaySender;
    imageOwnerId: string;
    fingerprint: string;
    compressedBytes: bigint;
    unpackedBytes: bigint | null;
    origin: "fetched" | "captured" | "replica";
    pinned: boolean;
    now: Date;
  },
) {
  const { sender } = input;
  await tx.sandboxHostImageCache.upsert({
    where: {
      hostId_fingerprint_imageOwnerId: {
        hostId: sender.hostId,
        fingerprint: input.fingerprint,
        imageOwnerId: input.imageOwnerId,
      },
    },
    create: {
      hostId: sender.hostId,
      hostOwnerId: sender.userId,
      imageOwnerId: input.imageOwnerId,
      fingerprint: input.fingerprint,
      compressedBytes: input.compressedBytes,
      unpackedBytes: input.unpackedBytes,
      origin: input.origin,
      pinned: input.pinned,
      connectionEpoch: sender.connectionEpoch,
      reportedAt: input.now,
    },
    update: {
      compressedBytes: input.compressedBytes,
      unpackedBytes: input.unpackedBytes,
      origin: input.origin,
      pinned: input.pinned,
      connectionEpoch: sender.connectionEpoch,
      reportedAt: input.now,
      // Evidence is only accepted while access holds (round-2 P1-1).
      accessLostAt: null,
      releaseSentAt: null,
    },
  });
  // Explicit, current-epoch evidence for every live revision of this owner
  // that pins this exact image.
  const revisions = await tx.sandboxTemplateRevision.findMany({
    where: { userId: input.imageOwnerId, incusFingerprint: input.fingerprint, retiredAt: null },
    select: { id: true, architecture: true, manifestDigest: true, sourceKind: true },
    take: 500,
  });
  // An UPSTREAM pin's import is a split image (community-base S7): it is
  // never a peer source or a store upload, which both require `unified`.
  const imageFormat = revisions.some((revision) => revision.sourceKind === "UPSTREAM")
    ? "split"
    : "unified";
  for (const revision of revisions)
    await tx.sandboxTemplateAvailability.upsert({
      where: { revisionId_hostId: { revisionId: revision.id, hostId: sender.hostId } },
      create: {
        userId: input.imageOwnerId,
        revisionId: revision.id,
        hostId: sender.hostId,
        hostOwnerId: sender.userId,
        localFingerprint: input.fingerprint,
        architecture: revision.architecture,
        manifestDigest: revision.manifestDigest,
        status: "AVAILABLE",
        verifiedConnectionEpoch: sender.connectionEpoch,
        observedAt: input.now,
        sizeBytes: input.compressedBytes,
        imageFormat,
      },
      update: {
        status: "AVAILABLE",
        verifiedConnectionEpoch: sender.connectionEpoch,
        observedAt: input.now,
        sizeBytes: input.compressedBytes,
        imageFormat,
      },
    });
}

async function writeCacheTotals(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  totals: { usedBytes: number; foreignBytes: number },
) {
  await tx.sandboxHost.updateMany({
    where: {
      id: sender.hostId,
      userId: sender.userId,
      connectionEpoch: sender.connectionEpoch,
      imageCacheEpoch: sender.connectionEpoch,
    },
    data: {
      imageCacheUsedBytes: BigInt(totals.usedBytes),
      imageCacheForeignBytes: BigInt(totals.foreignBytes),
    },
  });
}

/**
 * `image.cached`: evidence only from the exact successful job that put this
 * image on this host connection (P1-2):
 * - a create: dispatched to this host on THIS epoch, not failed or cancelled,
 *   whose placement pins exactly this fingerprint and which was granted a
 *   FETCH of it to this host;
 * - a capture: its recorded host result names exactly this fingerprint on
 *   this host and epoch (the finalizer writes the capture's own evidence);
 * - a transfer: a COMPLETE fetch of exactly this image to this host epoch.
 * Anything else (a historical or foreign operation, another fingerprint, a
 * stale epoch) is ignored.
 */
export async function handleImageCached(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.cached" }>,
): Promise<void> {
  const { sender } = ctx;
  const outcome = await relayTransaction<"recorded" | "ignored" | "access_lost">(async (tx) => {
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    const now = await hostDatabaseNow(tx);
    let authorized = false;
    if (m.operationId) {
      const op = await tx.sandboxOperation.findFirst({
        where: {
          id: m.operationId,
          userId: m.imageOwnerId,
          dispatchedHostId: sender.hostId,
          dispatchedConnectionEpoch: sender.connectionEpoch,
          kind: { in: ["CREATE_SANDBOX", "CAPTURE_TEMPLATE"] },
          state: { in: ["DISPATCHED", "ACCEPTED", "RUNNING", "SUCCEEDED"] },
        },
        select: {
          id: true,
          kind: true,
          dispatchAttempt: true,
          Placement: { select: { artifact: true } },
          Sandbox: {
            select: {
              purpose: true,
              SandboxTemplateRevision: { select: { sourceKind: true, incusFingerprint: true } },
            },
          },
        },
      });
      // A community build VM's create imports its UPSTREAM pin from the
      // index host itself (no grant exists): the evidence is the dispatched
      // create of that exact pin on this host and epoch.
      const upstreamCreate =
        op?.kind === "CREATE_SANDBOX" &&
        op.Sandbox.purpose === "TEMPLATE_BUILD" &&
        op.Sandbox.SandboxTemplateRevision.sourceKind === "UPSTREAM" &&
        op.Sandbox.SandboxTemplateRevision.incusFingerprint === m.fingerprint &&
        op.Placement?.artifact === m.fingerprint;
      if (upstreamCreate && op) {
        authorized = true;
        await tx.sandboxPlacement.updateMany({
          where: { operationId: op.id, userId: m.imageOwnerId, artifact: m.fingerprint },
          data: { imageFetchBytes: null },
        });
      } else if (op?.kind === "CREATE_SANDBOX") {
        const granted = await tx.sandboxImageTransfer.findFirst({
          where: {
            operationId: op.id,
            userId: m.imageOwnerId,
            fingerprint: m.fingerprint,
            purpose: "FETCH",
            destHostId: sender.hostId,
            destHostOwnerId: sender.userId,
            dispatchAttempt: op.dispatchAttempt,
            state: { in: ["OPEN", "COMPLETE", "EXPIRED"] },
          },
          select: { id: true },
        });
        authorized = op.Placement?.artifact === m.fingerprint && granted !== null;
        if (authorized)
          await tx.sandboxPlacement.updateMany({
            where: { operationId: op.id, userId: m.imageOwnerId, artifact: m.fingerprint },
            data: { imageFetchBytes: null },
          });
      } else if (op?.kind === "CAPTURE_TEMPLATE") {
        authorized =
          (await tx.sandboxTemplateCapture.findFirst({
            where: {
              operationId: op.id,
              userId: m.imageOwnerId,
              hostId: sender.hostId,
              fingerprint: m.fingerprint,
              resultEpoch: sender.connectionEpoch,
            },
            select: { operationId: true },
          })) !== null;
      }
    } else if (m.transferId) {
      authorized =
        (await tx.sandboxImageTransfer.findFirst({
          where: {
            id: m.transferId,
            userId: m.imageOwnerId,
            fingerprint: m.fingerprint,
            purpose: "FETCH",
            state: "COMPLETE",
            destHostId: sender.hostId,
            destHostOwnerId: sender.userId,
            destEpoch: sender.connectionEpoch,
          },
          select: { id: true },
        })) !== null;
    }
    if (!authorized) return "ignored";
    // Round-2 P1-1: a job proves the copy arrived, not that it may stay. A
    // foreign copy is recorded only while every access gate holds now (the
    // owner's placement policy, the host's accept-foreign, pool use, bans);
    // historical evidence never revives a copy the access scan revoked.
    if (
      !(await foreignImageAccessHolds(tx, {
        hostId: sender.hostId,
        hostOwnerId: sender.userId,
        imageOwnerId: m.imageOwnerId,
        fingerprint: m.fingerprint,
      }))
    )
      return "access_lost";
    await upsertCachedEvidence(tx, {
      sender,
      imageOwnerId: m.imageOwnerId,
      fingerprint: m.fingerprint,
      compressedBytes: BigInt(m.compressedBytes),
      unpackedBytes: m.unpackedBytes !== undefined ? BigInt(m.unpackedBytes) : null,
      origin: m.origin,
      pinned: m.origin === "captured",
      now,
    });
    await writeCacheTotals(tx, sender, m.totals);
    return "recorded";
  }, "ignored");
  if (outcome === "access_lost")
    ctx.reply({
      type: "image.release",
      fingerprint: m.fingerprint,
      imageOwnerId: m.imageOwnerId,
      reason: "access_lost",
    });
}

/** `image.evicted`: explicit MISSING evidence and the cache row removed. */
export async function handleImageEvicted(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.evicted" }>,
): Promise<void> {
  const { sender } = ctx;
  await relayTransaction(async (tx) => {
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    const now = await hostDatabaseNow(tx);
    await tx.sandboxHostImageCache.deleteMany({
      where: { hostId: sender.hostId, fingerprint: m.fingerprint, imageOwnerId: m.imageOwnerId },
    });
    await tx.sandboxTemplateAvailability.updateMany({
      where: {
        hostId: sender.hostId,
        hostOwnerId: sender.userId,
        userId: m.imageOwnerId,
        localFingerprint: m.fingerprint,
      },
      data: { status: "MISSING", verifiedConnectionEpoch: sender.connectionEpoch, observedAt: now },
    });
    await writeCacheTotals(tx, sender, m.totals);
    return true;
  }, false);
}

/** One census run on a session: the copies it reported, and when it began. */
export type ImageCensusRun = { seen: Set<string>; startedAt: Date | null };

/**
 * `image.cache.census`: refreshes rows the server already has for this host.
 * It never creates evidence for an owner without a prior row (M4); a complete
 * census deletes rows the host no longer reports, except rows written after
 * the run began (the host's page snapshot predates them: a capture finalized
 * mid-census, now that a census also runs periodically on a live session).
 */
export async function handleImageCensus(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.cache.census" }>,
  run: ImageCensusRun,
): Promise<void> {
  const { seen } = run;
  const { sender } = ctx;
  const unrecorded: { fingerprint: string; imageOwnerId: string }[] = [];
  await relayTransaction(async (tx) => {
    unrecorded.length = 0;
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    const now = await hostDatabaseNow(tx);
    run.startedAt ??= now;
    for (const entry of m.entries)
      for (const owner of entry.owners) {
        const updated = await tx.sandboxHostImageCache.updateMany({
          where: { hostId: sender.hostId, fingerprint: entry.fingerprint, imageOwnerId: owner },
          data: {
            compressedBytes: BigInt(entry.compressedBytes),
            unpackedBytes: entry.unpackedBytes !== undefined ? BigInt(entry.unpackedBytes) : null,
            origin: entry.origin,
            pinned: entry.pinned,
            connectionEpoch: sender.connectionEpoch,
            reportedAt: now,
          },
        });
        if (updated.count > 0 || owner === sender.userId) seen.add(`${entry.fingerprint}:${owner}`);
        // A foreign origin pin with no row (its capture result was never
        // recorded, E2-A-01) is checked for release below.
        if (
          updated.count === 0 &&
          owner !== sender.userId &&
          entry.origin === "captured" &&
          entry.pinned
        )
          unrecorded.push({ fingerprint: entry.fingerprint, imageOwnerId: owner });
        // The host owner's own images need no transfer proof.
        if (updated.count === 0 && owner === sender.userId)
          await tx.sandboxHostImageCache.create({
            data: {
              hostId: sender.hostId,
              hostOwnerId: sender.userId,
              imageOwnerId: owner,
              fingerprint: entry.fingerprint,
              compressedBytes: BigInt(entry.compressedBytes),
              unpackedBytes: entry.unpackedBytes !== undefined ? BigInt(entry.unpackedBytes) : null,
              origin: entry.origin,
              pinned: entry.pinned,
              connectionEpoch: sender.connectionEpoch,
              reportedAt: now,
            },
          });
      }
    if (m.complete) {
      const rows = await tx.sandboxHostImageCache.findMany({
        where: { hostId: sender.hostId, reportedAt: { lt: run.startedAt ?? now } },
        select: { id: true, fingerprint: true, imageOwnerId: true },
        take: 4096,
      });
      const stale = rows.filter((r) => !seen.has(`${r.fingerprint}:${r.imageOwnerId}`));
      if (stale.length)
        await tx.sandboxHostImageCache.deleteMany({
          where: { id: { in: stale.map((r) => r.id) } },
        });
      await writeCacheTotals(tx, sender, m.totals);
    }
    return true;
  }, false);
  ctx.reply({ type: "image.cache.census.ack", page: m.page });
  for (const copy of unrecorded)
    if (await unrecordedForeignCaptureReleasable({ hostId: sender.hostId, ...copy }))
      ctx.reply({ type: "image.release", ...copy, reason: "gc" });
}

/**
 * Returns how a durable `image.job.failed` report was taken (`ReportOutcome`;
 * `image.fetch.failed` carries no report id, its outcome is unused): `done`
 * once nothing of this host is left open for it, `retry` when a fence
 * refused it.
 */
export async function handleImageFailure(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.fetch.failed" | "image.job.failed" }>,
): Promise<ReportOutcome> {
  if (m.type === "image.job.failed" && m.transferId === undefined)
    return handleCaptureJobFailure(ctx, m);
  if (!m.transferId) return "done";
  // A disk upload transfer also ends its offload attempt;
  // the transfer itself is ended below like any other.
  const disk =
    m.type === "image.job.failed"
      ? await handleDiskTransferFailure(ctx, m.transferId, m.code).catch(() => "retry" as const)
      : null;
  const transfer = await prisma.sandboxImageTransfer.findFirst({
    where: {
      id: m.transferId,
      state: "OPEN",
      OR: [{ sourceHostId: ctx.sender.hostId }, { destHostId: ctx.sender.hostId }],
    },
  });
  if (!transfer) return disk === "retry" ? "retry" : "done";
  // An S3 upload (a capture or a publish) is ended by a host report only
  // through the fenced path (I3): `image.job.failed` from its source, with
  // the host's cause as the detail (I4) and any split-export evidence in that
  // same transaction. `image.fetch.failed` is a destination's report and an
  // S3 upload has no destination: it changes nothing.
  if (
    transfer.mode === "S3" &&
    (transfer.purpose === "CAPTURE_UPLOAD" || transfer.purpose === "PUBLISH")
  ) {
    if (m.type !== "image.job.failed") return "done";
    return endReportedUpload(
      ctx,
      { transferId: transfer.id },
      imageFailureDetail(m),
      m.code === "format_unsupported",
    );
  }
  const senderIsSource = transfer.sourceHostId === ctx.sender.hostId;
  if (senderIsSource && m.code === "format_unsupported")
    await markExportSplit(prisma, ctx.sender.hostId, transfer);
  const other = senderIsSource
    ? transfer.destHostId && transfer.destEpoch
      ? { hostId: transfer.destHostId, epoch: transfer.destEpoch }
      : null
    : transfer.sourceHostId && transfer.sourceEpoch
      ? { hostId: transfer.sourceHostId, epoch: transfer.sourceEpoch }
      : null;
  await endTransfer(ctx, transfer.id, "FAILED", m.code, other);
  return disk === "retry" ? "retry" : "done";
}

/**
 * A host's report that its S3 template upload ended (by transfer), or that a
 * capture upload ended before or without one (by operation + attempt). One
 * fenced transaction: the sender's host lock by epoch, the transfer sourced
 * by this connection (or the capture this connection runs, on that dispatch
 * attempt) with its workload still authorized, then `endTemplateUpload`
 * (session, artifact, transfer and the capture's evidence together). A stale
 * report changes nothing. A capture is finalized afterwards; the 15 s sweep
 * is the backstop (I1).
 *
 * Outcome (`ReportOutcome`): `done` when it ended the upload, or when nothing
 * of this host is left for it (no OPEN transfer of this host and owner by
 * that id; no live capture of this operation on this host, or a newer
 * dispatch attempt runs it). `retry` when a fence refused it while its
 * upload is still open (e.g. the transfer not yet rebound to this
 * connection): the host re-sends it behind the job's resume.
 */
async function endReportedUpload(
  ctx: ImageFrameContext,
  target: { transferId: string } | { operationId: string; attempt: number },
  detail: string,
  split = false,
): Promise<ReportOutcome> {
  const { sender } = ctx;
  const done = await relayTransaction<
    { end: UploadEnd; operationId: string | null } | "moot" | null
  >(async (tx) => {
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    let operationId: string | null;
    if ("transferId" in target) {
      const transfer = await tx.sandboxImageTransfer.findFirst({
        where: {
          id: target.transferId,
          state: "OPEN",
          mode: "S3",
          purpose: { in: ["CAPTURE_UPLOAD", "PUBLISH"] },
          sourceHostId: sender.hostId,
          sourceHostOwnerId: sender.userId,
          sourceEpoch: sender.connectionEpoch,
        },
        select: { id: true, ...transferAuthoritySelect },
      });
      if (!transfer) {
        const open = await tx.sandboxImageTransfer.count({
          where: {
            id: target.transferId,
            state: "OPEN",
            sourceHostId: sender.hostId,
            sourceHostOwnerId: sender.userId,
          },
        });
        return open === 0 ? "moot" : null;
      }
      if (!(await transferAuthorized(tx, transfer, await hostDatabaseNow(tx)))) return null;
      if (split) await markExportSplit(tx, sender.hostId, transfer);
      operationId = transfer.purpose === "CAPTURE_UPLOAD" ? transfer.operationId : null;
    } else {
      const capture = await captureWorkload(tx, {
        operationId: target.operationId,
        hostId: sender.hostId,
        hostOwnerId: sender.userId,
        epoch: sender.connectionEpoch,
        attempt: target.attempt,
      });
      if (!capture || capture.dispatchAttempt !== target.attempt) {
        // Moot when this host runs no live capture of the operation, or the
        // operation moved to another dispatch attempt; otherwise (e.g. not
        // yet adopted on this connection) the report is retried.
        const live = await tx.sandboxTemplateCapture.count({
          where: {
            operationId: target.operationId,
            hostId: sender.hostId,
            state: { in: ["PENDING", "CAPTURED", "STORING"] },
          },
        });
        const sameAttempt = await tx.sandboxOperation.count({
          where: { id: target.operationId, dispatchAttempt: target.attempt },
        });
        return live === 0 || sameAttempt === 0 ? "moot" : null;
      }
      operationId = target.operationId;
    }
    return { end: await endTemplateUpload(tx, target, { detail }), operationId };
  }, null);
  if (!done) return "retry";
  if (done === "moot") return "done";
  await abortEndedUploads(imageStore(), done.end);
  // The capture's job is over: artifacts its retried begins kept UPLOADING
  // are released (a#3).
  if ("operationId" in target)
    await failAbandonedBeginArtifacts(target.operationId).catch(() => {});
  if (done.operationId) await finalizeReportedCapture(ctx, done.operationId);
  return "done";
}

/** The source's export was split: never pick this copy as a peer source. */
async function markExportSplit(
  db: Pick<Prisma.TransactionClient, "sandboxTemplateAvailability">,
  hostId: string,
  transfer: { userId: string; fingerprint: string },
): Promise<void> {
  await db.sandboxTemplateAvailability.updateMany({
    where: { hostId, userId: transfer.userId, localFingerprint: transfer.fingerprint },
    data: { imageFormat: "split" },
  });
}

/** Finalize a capture whose upload a report ended, and act on the outcome
 * as the scheduler does: tell hosts to stop uploads the finalizer ended, and
 * release the origin pin of a capture that will never become a revision. */
async function finalizeReportedCapture(ctx: ImageFrameContext, operationId: string) {
  const outcome = await finalizeCapture(operationId);
  if (outcome.kind !== "failed") return;
  for (const cancel of outcome.cancels ?? [])
    ctx.sendTo(cancel.hostId, cancel.epoch, {
      type: "image.job.cancel",
      transferId: cancel.transferId,
      reason: cancel.reason,
    });
  if (outcome.fingerprint && outcome.hostId === ctx.sender.hostId)
    ctx.reply({
      type: "image.release",
      fingerprint: outcome.fingerprint,
      imageOwnerId: outcome.ownerId,
      reason: "gc",
    });
}

/**
 * `image.job.failed` by operation: a capture upload that never got a
 * transfer the host knows of (export failure, no grant, refused begin).
 * Honoured only for the capture this host's current connection runs, on that
 * dispatch attempt; any upload the server opened for that attempt ends too.
 */
async function handleCaptureJobFailure(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.job.failed" }>,
): Promise<ReportOutcome> {
  if (m.operationId === undefined || m.attempt === undefined) return "done";
  return endReportedUpload(
    ctx,
    { operationId: m.operationId, attempt: m.attempt },
    imageFailureDetail(m),
  );
}

/**
 * `image.upload.progress`: the upload is alive (I5). Moves the transfer's
 * and its artifact's `lastProgressAt` and raises `bytesDone`, at most every
 * ten seconds per transfer. It spends the host's grant budget like every
 * upload frame; over it the heartbeat is dropped (no reply, nothing changes:
 * the next one carries the furthest offset).
 */
export async function handleImageUploadProgress(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.upload.progress" }>,
  /** The handler's clock (tests pin it either side of the throttle). */
  now: Date = new Date(),
): Promise<void> {
  if (!(await grantBudget(ctx.sender.hostId))) {
    // A disk offload's liveness is not spent from the shared grant budget
    // (round 1 L2 #1: other image traffic or an unavailable budget store
    // would let the stall rule fail a moving upload): per connection, at
    // most one attempt per transfer per interval; a proven disk upload keeps
    // its own slot, other ids share `DISK_LIVENESS_PROBES_MAX` probes (another
    // host's or a template's traffic never spends a disk upload's).
    if (ctx.diskLiveness && takeDiskLivenessSlot(ctx.diskLiveness, m.transferId, now.getTime())) {
      const disk = await diskUploadHeartbeat(ctx.sender, m, now);
      confirmDiskLiveness(ctx.diskLiveness, m.transferId, disk, now.getTime());
    }
    return noteBudgetDrop(ctx.sender.hostId, m.transferId, m.type);
  }
  const template = await withUploadSession(ctx.sender, m.transferId, async (tx, session) => {
    // Liveness is bytes moving (I5): logical progress (an offset beyond the
    // recorded one) or physical activity (more body bytes on the wire than
    // recorded, a retry re-sending a part included) refreshes it; repeated,
    // zero or lower counts never do. Neither count ever moves back.
    const bytes = BigInt(Math.min(m.bytesSent, Number(session.storedBytes)));
    const wire = BigInt(Math.min(m.wireBytes, IMAGE_WIRE_BYTES_MAX));
    const since = new Date(now.getTime() - PROGRESS_MIN_INTERVAL_MS);
    const moved = await tx.$executeRaw`
      UPDATE sandbox_image_transfer
      SET "lastProgressAt" = ${now},
          "bytesDone" = GREATEST("bytesDone", ${bytes}),
          "wireBytes" = GREATEST("wireBytes", ${wire})
      WHERE id = ${session.transferId} AND state = 'OPEN'
        AND ("bytesDone" < ${bytes} OR "wireBytes" < ${wire})
        AND "lastProgressAt" < ${since}`;
    if (moved !== 1) return true;
    await tx.sandboxImageArtifact.updateMany({
      where: { id: session.artifactId, state: "UPLOADING" },
      data: { lastProgressAt: now },
    });
    return true;
  });
  if (template === null) {
    const disk = await diskUploadHeartbeat(ctx.sender, m, now);
    // A budgeted heartbeat proves its transfer too (it keeps its own slot
    // for intervals the budget is spent).
    if (ctx.diskLiveness) confirmDiskLiveness(ctx.diskLiveness, m.transferId, disk, now.getTime());
  }
}

/**
 * A disk offload upload's heartbeat (`image.upload.progress` on its
 * `OFFLOAD_UPLOAD` transfer): liveness only, for the stall rule
 * (`endStalledOffloadUploads`). Moves `lastProgressAt` and `wireBytes` when
 * more body bytes went on the wire, at most every ten seconds, for this
 * host and owner's OPEN transfer on this or an older connection of this host
 * (a reconnected upload is rebound only by its next resume; a heartbeat
 * never rebinds and never grants). Parts stay counted by `disk.upload.parts`.
 */
async function diskUploadHeartbeat(
  sender: RelaySender,
  m: Extract<DaemonImageMessage, { type: "image.upload.progress" }>,
  now: Date,
): Promise<boolean> {
  const wire = BigInt(Math.min(m.wireBytes, IMAGE_WIRE_BYTES_MAX));
  const since = new Date(now.getTime() - PROGRESS_MIN_INTERVAL_MS);
  return relayTransaction(async (tx) => {
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    const own = await tx.sandboxImageTransfer.count({
      where: {
        id: m.transferId,
        state: "OPEN",
        purpose: "OFFLOAD_UPLOAD",
        sourceHostId: sender.hostId,
        sourceHostOwnerId: sender.userId,
        sourceEpoch: { lte: sender.connectionEpoch },
      },
    });
    if (own !== 1) return false;
    await tx.$executeRaw`
      UPDATE sandbox_image_transfer
      SET "lastProgressAt" = ${now}, "wireBytes" = GREATEST("wireBytes", ${wire})
      WHERE id = ${m.transferId} AND state = 'OPEN' AND purpose::text = 'OFFLOAD_UPLOAD'
        AND "sourceHostId" = ${sender.hostId} AND "sourceHostOwnerId" = ${sender.userId}
        AND "sourceEpoch" <= ${sender.connectionEpoch}
        AND "wireBytes" < ${wire} AND "lastProgressAt" < ${since}`;
    return true;
  }, false);
}

/** Heartbeats closer than this are absorbed (the daemon sends every 30 s). */
const PROGRESS_MIN_INTERVAL_MS = 10_000;

/**
 * After a reconnect a background job re-binds its transfer to the new epoch,
 * only while its workload is still authorized (P1-1): a FETCH destination
 * only after its create operation was adopted on this epoch; a FETCH source
 * only while the destination's create is; a capture upload only while the
 * capture runs on this connection.
 */
export async function handleImageJobResume(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.job.resume" }>,
): Promise<void> {
  const { sender } = ctx;
  const transferId = m.transferId;
  if (transferId === undefined) return handleCaptureOperationResume(ctx, m);
  const resumed = await relayTransaction(async (tx) => {
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    const now = await hostDatabaseNow(tx);
    const transfer = await tx.sandboxImageTransfer.findFirst({
      where: {
        id: transferId,
        state: "OPEN",
        ...(m.role === "SOURCE"
          ? { sourceHostId: sender.hostId, sourceHostOwnerId: sender.userId }
          : { destHostId: sender.hostId, destHostOwnerId: sender.userId }),
      },
      select: { id: true, ...transferAuthoritySelect },
    });
    if (!transfer) return false;
    const rebound =
      m.role === "SOURCE"
        ? { ...transfer, sourceEpoch: sender.connectionEpoch }
        : { ...transfer, destEpoch: sender.connectionEpoch };
    const plain = await transferAuthorized(tx, rebound, now);
    if (!plain && !(m.role === "SOURCE" && transfer.purpose === "CAPTURE_UPLOAD")) return false;
    // Lock order session → transfer (a#4), as `endTemplateUpload`, the
    // begin's supersession, completion and every `withUploadSession` frame
    // take them: the upload's session row first (none for a fetch).
    await tx.$queryRaw`SELECT id FROM sandbox_image_upload_session
      WHERE "transferId" = ${transfer.id} FOR UPDATE`;
    // The transfer claim comes before any other change (W4): a transfer
    // ended since it was read (e.g. expired by maintenance, or by a
    // begin-failure cleanup that held the session) rolls the whole resume
    // back, the adoption below included.
    const updated = await tx.sandboxImageTransfer.updateMany({
      where: { id: transfer.id, state: "OPEN" },
      data:
        m.role === "SOURCE"
          ? { sourceEpoch: sender.connectionEpoch }
          : { destEpoch: sender.connectionEpoch },
    });
    requireRelayFence(updated.count === 1);
    if (!plain) requireRelayFence(await adoptRecordedCaptureUpload(tx, sender, transfer, now));
    // A template upload's session follows its transfer (supersession tells
    // the host on this epoch); disk offload sessions are left as they are.
    if (m.role === "SOURCE")
      await tx.sandboxImageUploadSession.updateMany({
        where: { transferId: transfer.id, state: "OPEN", artifactId: { not: null } },
        data: { hostEpoch: sender.connectionEpoch },
      });
    // Links minted for the old epoch die with it.
    await tx.sandboxImageLink.deleteMany({
      where: {
        transferId: transfer.id,
        hostId: sender.hostId,
        hostEpoch: { lt: sender.connectionEpoch },
      },
    });
    return true;
  }, false);
  ctx.reply({ type: "image.job.resume.result", transferId, continue: resumed });
}

/**
 * `image.job.resume` by operation: a capture upload with no transfer yet
 * (its begin in flight or in retry backoff) after a relay reconnect of its
 * host. It continues when the capture runs on this connection: already
 * (`captureWorkload` on this epoch: an unrecorded capture the reconnect
 * re-adopted), or through the recorded-capture adoption from the
 * operation's own older epoch (`adoptRecordedCapture`). Otherwise no.
 */
async function handleCaptureOperationResume(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.job.resume" }>,
): Promise<void> {
  const { sender } = ctx;
  const { operationId, attempt } = m;
  if (operationId === undefined || attempt === undefined) return;
  const resumed = await relayTransaction(async (tx) => {
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    const target = { operationId, hostId: sender.hostId, hostOwnerId: sender.userId, attempt };
    const current = await captureWorkload(tx, { ...target, epoch: sender.connectionEpoch });
    if (current) return current.dispatchAttempt === attempt;
    const operation = await tx.sandboxOperation.findFirst({
      where: { id: operationId, dispatchedHostId: sender.hostId },
      select: { dispatchedConnectionEpoch: true },
    });
    const fromEpoch = operation?.dispatchedConnectionEpoch;
    if (fromEpoch === null || fromEpoch === undefined) return false;
    return adoptRecordedCapture(tx, sender, { operationId, attempt, fromEpoch });
  }, false);
  ctx.reply({ type: "image.job.resume.result", operationId, attempt, continue: resumed });
}

/**
 * The recorded-capture adoption (V1). A recorded capture (CAPTURED/STORING:
 * its result is in, only the upload runs) keeps its operation on the
 * dispatch connection, which reconnect reconciliation deliberately never
 * settles or re-adopts (RECORDED_CAPTURE_WHERE). After a relay reconnect of
 * its host, its upload may go on on the new connection only when the
 * capture was authorized on exactly `fromEpoch` (`captureWorkload`: host,
 * owner, kind, attempt, sharing and credential policy) and the operation is
 * still exactly that dispatch (this host, that epoch, that attempt,
 * ACCEPTED/RUNNING, capture CAPTURED/STORING on this host). Then only the
 * operation's dispatch epoch moves to this connection, and the capture must
 * pass `captureWorkload` there, or the caller's whole transaction rolls back.
 * The finalizer still owns the terminal write. Anything else (another host
 * or owner, a newer attempt or epoch, CANCEL_REQUESTED, a terminal
 * operation, an unrecorded capture the host did not re-adopt) is refused.
 */
async function adoptRecordedCapture(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  capture: { operationId: string; attempt: number; fromEpoch: number },
): Promise<boolean> {
  if (capture.fromEpoch >= sender.connectionEpoch) return false;
  const target = {
    operationId: capture.operationId,
    hostId: sender.hostId,
    hostOwnerId: sender.userId,
    attempt: capture.attempt,
  };
  const before = await captureWorkload(tx, { ...target, epoch: capture.fromEpoch });
  if (!before || before.dispatchAttempt !== capture.attempt) return false;
  const adopted = await tx.sandboxOperation.updateMany({
    where: {
      id: capture.operationId,
      dispatchedHostId: sender.hostId,
      dispatchedConnectionEpoch: capture.fromEpoch,
      dispatchAttempt: capture.attempt,
      state: { in: ["ACCEPTED", "RUNNING"] },
      ...RECORDED_CAPTURE_WHERE,
      Capture: { is: { hostId: sender.hostId, state: { in: ["CAPTURED", "STORING"] } } },
    },
    data: { dispatchedConnectionEpoch: sender.connectionEpoch },
  });
  if (adopted.count !== 1) return false;
  // Never a moved operation that does not authorize its capture here: a
  // failure rolls the whole resume back.
  const after = await captureWorkload(tx, { ...target, epoch: sender.connectionEpoch });
  requireRelayFence(after !== null && after.dispatchAttempt === capture.attempt);
  return true;
}

/**
 * A capture upload's transfer resumed after a relay reconnect of its host:
 * the transfer must have been authorized on its own (older) epoch, then the
 * recorded-capture adoption moves the operation from that epoch, and the
 * rebound transfer must pass `transferAuthorized` (else the whole resume
 * rolls back).
 */
async function adoptRecordedCaptureUpload(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  transfer: Parameters<typeof transferAuthorized>[1],
  now: Date,
): Promise<boolean> {
  if (
    transfer.purpose !== "CAPTURE_UPLOAD" ||
    transfer.operationId === null ||
    transfer.dispatchAttempt === null ||
    transfer.sourceEpoch === null ||
    !(await transferAuthorized(tx, transfer, now))
  )
    return false;
  const adopted = await adoptRecordedCapture(tx, sender, {
    operationId: transfer.operationId,
    attempt: transfer.dispatchAttempt,
    fromEpoch: transfer.sourceEpoch,
  });
  if (!adopted) return false;
  requireRelayFence(
    await transferAuthorized(tx, { ...transfer, sourceEpoch: sender.connectionEpoch }, now),
  );
  return true;
}

// ---------------------------------------------------------------- S3 uploads

/** Presigned UploadPart URLs (signed exact Content-Length) for the next parts. */
async function uploadGrant(
  transferId: string,
  session: { objectKey: string; uploadId: string; partSize: number; storedBytes: bigint },
  from: number,
  encryption?: { scheme: typeof IMAGE_ENCRYPTION_SCHEME; key: string },
): Promise<ServerImageMessage | null> {
  const store = imageStore();
  if (!store) return null;
  const parts = Math.max(1, Math.ceil(Number(session.storedBytes) / session.partSize));
  const urls = [];
  for (let n = from; n <= Math.min(parts, from + IMAGE_UPLOAD_PARTS_MAX - 1); n++) {
    const size = partSize(session.storedBytes, session.partSize, n);
    urls.push({
      n,
      sizeBytes: size,
      url: await store.presignUploadPart(session.objectKey, session.uploadId, n, size),
    });
  }
  return {
    type: "image.upload.grant",
    transferId,
    partSize: session.partSize,
    parts: urls,
    expiresAtUnixMs: Date.now() + store.settings.presignTtlSeconds * 1000,
    ttlSeconds: store.settings.presignTtlSeconds,
    ...(encryption ? { encryption } : {}),
  };
}

/** A VERIFYING artifact this recent is still being verified, not wedged. */
const VERIFYING_FRESH_MS = 24 * 3_600_000;

/**
 * `image.upload.begin`: a publish job (transfer) or a capture (operation) on
 * this host opens one upload session (round-5 P2-2). The declared size is
 * capped by the owner's stored-GiB quota (M9).
 *
 * At most one session per artifact is live. While a live session's own job
 * is still authorized, another begin for the same owner and image is refused
 * (`upload_in_progress`): its result (the STORED artifact) is the one the
 * second job waits for anyway, and joining would share one upload id and data
 * key across jobs again. A live session whose job lost its authority (an older
 * dispatch attempt, an ended or expired transfer) is superseded: it ends, and
 * its multipart upload is aborted.
 */
export async function handleImageUploadBegin(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.upload.begin" }>,
): Promise<void> {
  const store = imageStore();
  // A capture's begin is answered by its request id (round-3 P2-4): the
  // daemon routes this grant or cancel only to that capture's upload.
  const answers = m.requestId !== undefined ? { requestId: m.requestId } : {};
  const cancel = (reason: string, transferId = m.transferId ?? "none") =>
    ctx.reply({ type: "image.job.cancel", transferId, reason, ...answers });
  if (!store || imageDistributionMode() !== "s3") return cancel("store_unavailable");
  const { sender } = ctx;
  if (!ctx.beginBudgetSpent && !(await grantBudget(sender.hostId))) return cancel("rate_limited");
  const master = imageMasterKey();
  const superseded: {
    id: string;
    objectKey: string;
    uploadId: string | null;
    transferId: string;
    hostId: string;
    hostEpoch: number;
  }[] = [];
  const outcome = await relayTransaction<
    | { kind: "cancel"; reason: string; transferId?: string }
    | { kind: "stored"; transferId: string; artifactId: string }
    | {
        kind: "grant";
        transferId: string;
        sessionId: string;
        objectKey: string;
        storedBytes: bigint;
        partSize: number;
        dataKey: Buffer | null;
      }
  >(
    async (tx) => {
      // Account quota lock before H (P2-6); the checks below re-prove the
      // owner. It also serializes every begin of this owner's images.
      const claimed = m.transferId
        ? await tx.sandboxImageTransfer.findFirst({
            where: { id: m.transferId },
            select: { userId: true },
          })
        : m.operationId
          ? await tx.sandboxTemplateCapture.findFirst({
              where: { operationId: m.operationId },
              select: { userId: true },
            })
          : null;
      if (!claimed) return { kind: "cancel", reason: "stale" };
      await lockImageQuota(tx, claimed.userId);
      await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
      requireRelayFence(sender.isCurrent?.() !== false);
      const now = await hostDatabaseNow(tx);
      let ownerId: string;
      let transferId = m.transferId;
      // A capture upload binds to the attempt that produced it (round-3
      // P2-2): granted only while that attempt is still current.
      let captureAttempt: number | null = null;
      if (m.transferId) {
        const transfer = await tx.sandboxImageTransfer.findFirst({
          where: {
            id: m.transferId,
            state: "OPEN",
            purpose: "PUBLISH",
            sourceHostId: sender.hostId,
            sourceHostOwnerId: sender.userId,
            sourceEpoch: sender.connectionEpoch,
            fingerprint: m.fingerprint,
          },
          select: { id: true, UploadSession: { select: { id: true } }, ...transferAuthoritySelect },
        });
        // One session per job: a repeated begin never reopens it.
        if (!transfer || transfer.UploadSession || !(await transferAuthorized(tx, transfer, now)))
          return { kind: "cancel", reason: "stale_transfer" };
        ownerId = transfer.userId;
      } else {
        if (!m.operationId || m.attempt === undefined)
          return { kind: "cancel", reason: "stale_capture" };
        const capture = await captureWorkload(tx, {
          operationId: m.operationId,
          hostId: sender.hostId,
          hostOwnerId: sender.userId,
          epoch: sender.connectionEpoch,
          attempt: m.attempt,
        });
        if (!capture || capture.dispatchAttempt !== m.attempt)
          return { kind: "cancel", reason: "stale_capture" };
        ownerId = capture.ownerId;
        captureAttempt = m.attempt;
      }
      if (ownerId !== claimed.userId) return { kind: "cancel", reason: "stale" };
      const quotas = await accountImageQuotas(tx, ownerId);
      const existing = await tx.sandboxImageArtifact.findUnique({
        where: { userId_fingerprint: { userId: ownerId, fingerprint: m.fingerprint } },
      });
      if (existing?.state === "STORED")
        return {
          kind: "stored",
          transferId: transferId ?? "none",
          artifactId: existing.id,
        };
      // GC committed this object's deletion and may still be retrying the
      // DeleteObject (round-2 P2-7): reviving the row could lose the new
      // upload to that delete. The host retries once the row is DELETED.
      if (existing?.state === "DELETING") return { kind: "cancel", reason: "artifact_deleting" };
      const refuseInProgress = async () => {
        // A refused publish job ends here (a capture's begin opened none).
        if (m.transferId)
          await tx.sandboxImageTransfer.updateMany({
            where: { id: m.transferId, state: "OPEN" },
            data: { state: "CANCELLED", endReason: "upload_in_progress" },
          });
        return { kind: "cancel" as const, reason: "upload_in_progress" };
      };
      if (existing) {
        const live = await tx.sandboxImageUploadSession.findUnique({
          where: { liveArtifactId: existing.id },
          select: {
            id: true,
            objectKey: true,
            uploadId: true,
            transferId: true,
            hostId: true,
            hostEpoch: true,
            Transfer: { select: { state: true, ...transferAuthoritySelect } },
          },
        });
        if (live) {
          if (live.Transfer.state === "OPEN" && (await transferAuthorized(tx, live.Transfer, now)))
            return refuseInProgress();
          await tx.sandboxImageUploadSession.update({
            where: { id: live.id },
            data: { state: "ABORTED", liveArtifactId: null, endReason: "superseded" },
          });
          await tx.sandboxImageTransfer.updateMany({
            where: { id: live.transferId, state: "OPEN" },
            data: { state: "CANCELLED", endReason: "superseded" },
          });
          superseded.push(live);
        } else if (
          existing.state === "VERIFYING" &&
          (existing.lastProgressAt?.getTime() ?? 0) > now.getTime() - VERIFYING_FRESH_MS
        )
          // Completed and awaiting verification: that object is the result.
          return refuseInProgress();
      }
      const counted =
        existing && ["UPLOADING", "VERIFYING"].includes(existing.state) ? existing.sizeBytes : 0n;
      if (
        quotas.maxStoredGiB !== null &&
        (await accountStoredImageBytes(tx, ownerId)) - counted + BigInt(m.sizeBytes) >
          BigInt(quotas.maxStoredGiB) * 1_073_741_824n
      )
        return { kind: "cancel", reason: "image_quota_exceeded" };
      const encrypted = master !== null;
      // One object key per session: completion is create-only, and two
      // sessions never write the same key.
      const sessionId = newImageSessionId();
      const objectKey = imageObjectKey(
        store.settings.prefix,
        ownerId,
        m.fingerprint,
        sessionId,
        encrypted,
      );
      const storedBytes = BigInt(encrypted ? encryptedImageLength(m.sizeBytes) : m.sizeBytes);
      // Adaptive, whole records (16 MiB normally; ≤ 10 000 parts).
      const sessionPartSize = imageUploadPartBytes(m.sizeBytes, encrypted);
      const architecture =
        (
          await tx.sandboxTemplateRevision.findFirst({
            where: { userId: ownerId, incusFingerprint: m.fingerprint },
            select: { architecture: true },
          })
        )?.architecture ??
        (m.operationId
          ? (
              await tx.sandboxTemplateCapture.findFirst({
                where: { operationId: m.operationId },
                select: { architecture: true },
              })
            )?.architecture
          : null);
      if (!architecture) return { kind: "cancel", reason: "unknown_architecture" };
      // The artifact records only what the account is charged for while
      // uploading; the object's key, encryption and size are copied from the
      // session that completes it.
      const artifact = await tx.sandboxImageArtifact.upsert({
        where: { userId_fingerprint: { userId: ownerId, fingerprint: m.fingerprint } },
        create: {
          userId: ownerId,
          fingerprint: m.fingerprint,
          architecture,
          sizeBytes: BigInt(m.sizeBytes),
          unpackedBytes: m.unpackedBytes !== undefined ? BigInt(m.unpackedBytes) : null,
          storeKind: "S3",
          state: "UPLOADING",
          uploadedByHostId: sender.hostId,
          lastProgressAt: now,
        },
        update: {
          sizeBytes: BigInt(m.sizeBytes),
          storeKind: "S3",
          state: "UPLOADING",
          objectKey: null,
          partSize: null,
          uploadedByHostId: sender.hostId,
          lastProgressAt: now,
          encryption: null,
          wrappedKey: null,
          wrappedKeyNonce: null,
          keyId: null,
          failureDetail: null,
        },
        select: { id: true },
      });
      const partCount = Math.max(1, Math.ceil(Number(storedBytes) / sessionPartSize));
      if (!transferId) {
        const transfer = await tx.sandboxImageTransfer.create({
          data: {
            userId: ownerId,
            fingerprint: m.fingerprint,
            artifactId: artifact.id,
            purpose: "CAPTURE_UPLOAD",
            mode: "S3",
            sourceHostId: sender.hostId,
            sourceHostOwnerId: sender.userId,
            sourceEpoch: sender.connectionEpoch,
            operationId: m.operationId,
            dispatchAttempt: captureAttempt,
            sizeBytes: storedBytes,
            partSize: sessionPartSize,
            partCount,
            expiresAt: new Date(now.getTime() + 24 * 3_600_000),
          },
          select: { id: true },
        });
        transferId = transfer.id;
      } else {
        await tx.sandboxImageTransfer.update({
          where: { id: transferId },
          data: {
            artifactId: artifact.id,
            sizeBytes: storedBytes,
            partSize: sessionPartSize,
            partCount,
          },
        });
      }
      let dataKey: Buffer | null = null;
      let wrapped: ReturnType<typeof wrapDataKey> | null = null;
      if (master) {
        dataKey = newDataKey();
        // Bound to the artifact, so the completing session's key can become
        // the stored object's key unchanged.
        wrapped = wrapDataKey(master, dataKey, artifact.id, ownerId);
      }
      const session = await tx.sandboxImageUploadSession.create({
        data: {
          id: sessionId,
          transferId,
          artifactId: artifact.id,
          liveArtifactId: artifact.id,
          userId: ownerId,
          hostId: sender.hostId,
          hostEpoch: sender.connectionEpoch,
          dispatchAttempt: captureAttempt,
          requestId: m.requestId ?? null,
          objectKey,
          sizeBytes: BigInt(m.sizeBytes),
          storedBytes,
          partSize: sessionPartSize,
          ...(wrapped
            ? {
                encryption: IMAGE_ENCRYPTION_SCHEME,
                wrappedKey: new Uint8Array(wrapped.wrappedKey),
                wrappedKeyNonce: new Uint8Array(wrapped.wrappedKeyNonce),
                keyId: wrapped.keyId,
              }
            : {}),
        },
        select: { id: true },
      });
      return {
        kind: "grant",
        transferId,
        sessionId: session.id,
        objectKey,
        storedBytes,
        partSize: sessionPartSize,
        dataKey,
      };
    },
    { kind: "cancel", reason: "stale" },
  );
  // Superseded sessions (ended above) lose their multipart upload, and their
  // host is told to stop. A session whose CreateMultipartUpload is still in
  // flight has no id yet: its own begin aborts it (below).
  for (const old of superseded) {
    if (old.uploadId)
      await abortSessionUpload(store, {
        id: old.id,
        objectKey: old.objectKey,
        uploadId: old.uploadId,
      });
    await endTransfer(ctx, old.transferId, "CANCELLED", "superseded", {
      hostId: old.hostId,
      epoch: old.hostEpoch,
    });
  }
  if (outcome.kind === "cancel") return cancel(outcome.reason, outcome.transferId);
  if (outcome.kind === "stored") {
    await onArtifactStored(ctx, outcome.artifactId);
    return cancel("already_stored", outcome.transferId);
  }
  // A capture's begin the store refuses for now is retried by its host; a
  // publish's is not (W5): it ends FAILED with the cause, so server
  // backfill asks again.
  const endRefusedBegin = (sessionId: string) =>
    m.transferId !== undefined
      ? endServerUpload(sessionId, "store_unavailable")
      : endRetryableBegin(sessionId);
  let uploadId: string;
  try {
    uploadId = await store.createMultipart(outcome.objectKey);
  } catch {
    await endRefusedBegin(outcome.sessionId);
    return cancel("store_unavailable", outcome.transferId);
  }
  // Set once, on this session only. Then the session must still be the
  // live one: one superseded meanwhile never binds a grant, and its upload
  // is aborted here (the superseder could not see the id).
  await prisma.sandboxImageUploadSession.updateMany({
    where: { id: outcome.sessionId, uploadId: null },
    data: { uploadId },
  });
  const bound = await prisma.sandboxImageUploadSession.findFirst({
    where: { id: outcome.sessionId, state: "OPEN", uploadId },
    select: { id: true },
  });
  if (!bound) {
    await abortSessionUpload(store, {
      id: outcome.sessionId,
      objectKey: outcome.objectKey,
      uploadId,
    });
    return cancel("superseded", outcome.transferId);
  }
  // A store error presigning the first grant ends the upload with its
  // cause, as a refused createMultipart does (never OPEN with no grant).
  let grant: ServerImageMessage | null;
  try {
    grant = await uploadGrant(
      outcome.transferId,
      {
        objectKey: outcome.objectKey,
        uploadId,
        partSize: outcome.partSize,
        storedBytes: outcome.storedBytes,
      },
      1,
      outcome.dataKey
        ? { scheme: IMAGE_ENCRYPTION_SCHEME, key: outcome.dataKey.toString("base64") }
        : undefined,
    );
  } catch {
    await endRefusedBegin(outcome.sessionId);
    return cancel("store_unavailable", outcome.transferId);
  }
  if (grant) ctx.reply({ ...grant, ...answers });
}

/**
 * The store refused a capture's begin before any host held a grant
 * (createMultipart or the first presign): the host retries the begin (`store_unavailable`), so
 * this session and transfer end without failing anything else. No capture
 * evidence, the artifact stays UPLOADING for the retried begin, and the
 * finalizer ignores the transfer (`BEGIN_RETRY_END_REASON`).
 */
async function endRetryableBegin(sessionId: string): Promise<void> {
  const end = await prisma.$transaction((tx) =>
    endTemplateUpload(
      tx,
      { sessionId, from: "OPEN" },
      {
        detail: BEGIN_RETRY_END_REASON,
        state: "CANCELLED",
        evidence: false,
        keepArtifact: true,
      },
    ),
  );
  await abortEndedUploads(imageStore(), end);
}

/**
 * The server ends one template upload session for a store failure on a
 * session it already claimed (a failed Complete), or for a publish begin the
 * store refused (W5: the publish and its artifact end FAILED, so backfill
 * retries it):
 * `endTemplateUpload` in one transaction, then the multipart abort. A
 * capture's waiting row records the cause; the 15 s sweep then fails it.
 * Failures seen while serving a host's frame on a granted session go
 * through `endUploadAndCancel` (fenced).
 */
async function endServerUpload(
  sessionId: string,
  detail: string,
  from: "OPEN" | "COMPLETE" = "OPEN",
): Promise<void> {
  const end = await prisma.$transaction((tx) =>
    endTemplateUpload(tx, { sessionId, from }, { detail }),
  );
  await abortEndedUploads(imageStore(), end);
}

/** A failure the server saw while serving this host's upload frame (S3
 * refused ListParts or a renew's presign, invalid parts): the session ends with that
 * cause only through the same fence as the frame (`withUploadSession`: the
 * sender's current connection still sources it, workload authorized), then
 * (after its commit) the multipart abort and the host cancel;
 * `stale_transfer` when the fence fails or another writer ended it first. */
async function endUploadAndCancel(
  ctx: Pick<ImageFrameContext, "reply" | "sender">,
  transferId: string,
  sessionId: string,
  detail: string,
): Promise<void> {
  const end = await withUploadSession(ctx.sender, transferId, (tx, session) =>
    session.id === sessionId
      ? endTemplateUpload(tx, { sessionId, from: "OPEN" }, { detail })
      : Promise.resolve(null),
  );
  if (end) await abortEndedUploads(imageStore(), end);
  ctx.reply({
    type: "image.job.cancel",
    transferId,
    reason: end && end.sessions.length > 0 ? cancelReasonOf(detail) : "stale_transfer",
  });
}

/** An upload continuation: the OPEN S3 transfer this host's current
 * connection sources, with its workload still authorized (P1-1), and that
 * transfer's own OPEN session (never the artifact's "current" one). Runs
 * `then` in the same transaction, with the session row locked. */
async function withUploadSession<T>(
  sender: RelaySender,
  transferId: string,
  then: (
    tx: Prisma.TransactionClient,
    session: UploadSessionRow & { uploadId: string; artifactId: string },
  ) => Promise<T>,
): Promise<T | null> {
  return relayTransaction(async (tx) => {
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    const row = await tx.sandboxImageTransfer.findFirst({
      where: {
        id: transferId,
        state: "OPEN",
        mode: "S3",
        sourceHostId: sender.hostId,
        sourceHostOwnerId: sender.userId,
        sourceEpoch: sender.connectionEpoch,
      },
      select: { id: true, ...transferAuthoritySelect },
    });
    if (!row || !(await transferAuthorized(tx, row, await hostDatabaseNow(tx)))) return null;
    await tx.$queryRaw`SELECT id FROM sandbox_image_upload_session
      WHERE "transferId" = ${row.id} FOR UPDATE`;
    const session = await tx.sandboxImageUploadSession.findFirst({
      where: { transferId: row.id, state: "OPEN" },
      select: uploadSessionSelect,
    });
    // Template sessions only: a disk offload session (no artifact) has its
    // own handlers and is never resolved here.
    if (!session?.uploadId || !session.artifactId) return null;
    return then(tx, { ...session, uploadId: session.uploadId, artifactId: session.artifactId });
  }, null);
}

const uploadSessionSelect = {
  id: true,
  transferId: true,
  artifactId: true,
  objectKey: true,
  uploadId: true,
  sizeBytes: true,
  storedBytes: true,
  partSize: true,
  encryption: true,
  wrappedKey: true,
  wrappedKeyNonce: true,
  keyId: true,
} satisfies Prisma.SandboxImageUploadSessionSelect;
type UploadSessionRow = Prisma.SandboxImageUploadSessionGetPayload<{
  select: typeof uploadSessionSelect;
}>;

/**
 * `image.upload.parts`: record reported ETags. It never grants URLs (the
 * host pulls them with `image.upload.renew`). Over the host's grant budget
 * the report is dropped without a reply: nothing changes, and the host
 * re-reports those parts when a renewed grant names them again.
 */
export async function handleImageUploadParts(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.upload.parts" }>,
): Promise<void> {
  if (!(await grantBudget(ctx.sender.hostId)))
    return noteBudgetDrop(ctx.sender.hostId, m.transferId, m.type);
  const found = await withUploadSession(ctx.sender, m.transferId, async (tx, session) => {
    const parts = Math.max(1, Math.ceil(Number(session.storedBytes) / session.partSize));
    for (const part of m.parts) {
      if (part.n > parts) continue;
      await tx.sandboxImageUploadPart.upsert({
        where: { sessionId_partNumber: { sessionId: session.id, partNumber: part.n } },
        create: {
          sessionId: session.id,
          partNumber: part.n,
          etag: part.etag,
          sizeBytes: partSize(session.storedBytes, session.partSize, part.n),
        },
        update: { etag: part.etag },
      });
    }
    const done = await tx.sandboxImageUploadPart.count({ where: { sessionId: session.id } });
    const now = new Date();
    await tx.sandboxImageTransfer.updateMany({
      where: { id: session.transferId, state: "OPEN" },
      data: { lastProgressAt: now },
    });
    // bytesDone never moves back (heartbeats may have raised it further).
    const reported = BigInt(Math.min(Number(session.storedBytes), done * session.partSize));
    await tx.sandboxImageTransfer.updateMany({
      where: { id: session.transferId, state: "OPEN", bytesDone: { lt: reported } },
      data: { bytesDone: reported },
    });
    // The session is OPEN, so it is this artifact's live one.
    await tx.sandboxImageArtifact.updateMany({
      where: { id: session.artifactId, state: "UPLOADING" },
      data: { lastProgressAt: now },
    });
    return { session, parts };
  });
  if (!found)
    return ctx.reply({
      type: "image.job.cancel",
      transferId: m.transferId,
      reason: "stale_transfer",
    });
}

/**
 * `image.upload.renew`: fresh presigned URLs for this host's upload, from
 * the session's lowest unrecorded part (a report the host sent but the
 * server dropped is named again, so the host re-reports it), through the
 * same fence as every upload frame. No data key. Over the grant budget the
 * renew is dropped without a reply (the host asks again after a backoff); a
 * store error presigning ends the upload with its cause.
 */
export async function handleImageUploadRenew(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.upload.renew" }>,
): Promise<void> {
  if (!(await grantBudget(ctx.sender.hostId)))
    return noteBudgetDrop(ctx.sender.hostId, m.transferId, m.type);
  const found = await withUploadSession(ctx.sender, m.transferId, async (tx, session) => {
    const parts = Math.max(1, Math.ceil(Number(session.storedBytes) / session.partSize));
    const [gap] = await tx.$queryRaw<{ n: number | null }[]>`
      SELECT MIN(s.n)::int AS n FROM generate_series(1, ${parts}::int) AS s(n)
      WHERE NOT EXISTS (
        SELECT 1 FROM sandbox_image_upload_part p
        WHERE p."sessionId" = ${session.id} AND p."partNumber" = s.n
      )`;
    return { session, from: gap?.n ?? parts + 1 };
  });
  if (!found)
    return ctx.reply({
      type: "image.job.cancel",
      transferId: m.transferId,
      reason: "stale_transfer",
    });
  let grant: ServerImageMessage | null;
  try {
    grant = await uploadGrant(m.transferId, found.session, found.from);
  } catch {
    return endUploadAndCancel(ctx, m.transferId, found.session.id, "store_unavailable");
  }
  if (grant) ctx.reply(grant);
}

/**
 * `image.upload.complete`: ListParts of this transfer's own session must show
 * every part at its exact size (last part shorter) summing to the stored size
 * (M9). The session is then claimed (OPEN → COMPLETE, conditional on its
 * identity) before Complete, and the artifact takes the session's object key,
 * size and data key; the worker re-reads and hashes the object before STORED.
 *
 * Outcome (`ReportOutcome`): `done` once the upload was claimed or ended
 * here, or when no OPEN template upload of this host and owner has that id
 * (a repeat of a handled report); `retry` while it is still open but this
 * connection may not take it (not rebound yet, store unavailable).
 */
export async function handleImageUploadComplete(
  ctx: ImageFrameContext,
  m: Extract<DaemonImageMessage, { type: "image.upload.complete" }>,
  enqueueVerify: (artifactId: string) => Promise<void>,
): Promise<ReportOutcome> {
  const store = imageStore();
  const stale = async (): Promise<ReportOutcome> => {
    ctx.reply({ type: "image.job.cancel", transferId: m.transferId, reason: "stale_transfer" });
    return store && !(await openTemplateUpload(ctx.sender, m.transferId)) ? "done" : "retry";
  };
  const session = store
    ? await withUploadSession(ctx.sender, m.transferId, async (_tx, s) => s)
    : null;
  if (!store || !session) return stale();
  const expectedParts = Math.max(1, Math.ceil(Number(session.storedBytes) / session.partSize));
  // A store error here ends the upload with its cause (the daemon already
  // returned after sending complete), never leaving it to the stall rule.
  const listed = await store.listParts(session.objectKey, session.uploadId).catch(() => null);
  if (!listed) {
    await endUploadAndCancel(ctx, m.transferId, session.id, "store_list_failed");
    return (await openTemplateUpload(ctx.sender, m.transferId)) ? "retry" : "done";
  }
  const valid =
    listed.length === expectedParts &&
    listed.every(
      (p) =>
        p.n >= 1 &&
        p.n <= expectedParts &&
        p.size === partSize(session.storedBytes, session.partSize, p.n),
    ) &&
    listed.reduce((sum, p) => sum + BigInt(p.size), 0n) === session.storedBytes;
  if (!valid) {
    await endUploadAndCancel(ctx, m.transferId, session.id, "upload_invalid");
    return (await openTemplateUpload(ctx.sender, m.transferId)) ? "retry" : "done";
  }
  // The claim re-checks the frame's fence (the connection may have been
  // superseded during ListParts): a stale complete changes nothing.
  const claimed = await withUploadSession(ctx.sender, m.transferId, async (tx, live) => {
    if (live.id !== session.id || live.uploadId !== session.uploadId) return false;
    const now = new Date();
    const updated = await tx.sandboxImageUploadSession.updateMany({
      where: { id: session.id, state: "OPEN", uploadId: session.uploadId },
      data: { state: "COMPLETE", liveArtifactId: null, endReason: "uploaded" },
    });
    if (updated.count !== 1) return false;
    const artifact = await tx.sandboxImageArtifact.updateMany({
      where: { id: session.artifactId, state: "UPLOADING" },
      data: {
        state: "VERIFYING",
        sizeBytes: session.sizeBytes,
        objectKey: session.objectKey,
        partSize: session.partSize,
        encryption: session.encryption,
        wrappedKey: session.wrappedKey,
        wrappedKeyNonce: session.wrappedKeyNonce,
        keyId: session.keyId,
        storedAt: now,
        lastProgressAt: now,
      },
    });
    // The artifact lost its live session: roll the claim back.
    requireRelayFence(artifact.count === 1);
    await tx.sandboxImageTransfer.updateMany({
      where: { id: session.transferId, state: "OPEN" },
      data: { state: "COMPLETE", endReason: "uploaded", bytesDone: session.storedBytes },
    });
    return true;
  });
  if (!claimed) return stale();
  try {
    await store.completeMultipart(
      session.objectKey,
      session.uploadId,
      listed.map((p) => ({ n: p.n, etag: p.etag })),
    );
  } catch (error) {
    // Create-only refusal: an object already sits at this session's own key
    // (in practice the SDK retried a Complete whose first response was lost).
    // Nothing was overwritten and the store already aborted the upload. The
    // object is not assumed to be ours: the artifact stays VERIFYING and the
    // verify job re-reads it, which proves it is exactly this image (its
    // SHA-256 and size, and for an encrypted object authenticated decryption
    // under this session's data key) before it is STORED; anything else is
    // CORRUPT and deleted.
    if (error instanceof ImageObjectExistsError) {
      await enqueueVerify(session.artifactId);
      return "done";
    }
    // The claimed object never appeared: the session, artifact and transfer
    // fail with `store_complete_failed` (its waiting capture records it) and
    // the upload is aborted.
    await endServerUpload(session.id, "store_complete_failed", "COMPLETE");
    ctx.reply({
      type: "image.job.cancel",
      transferId: m.transferId,
      reason: "store_unavailable",
    });
    return "done";
  }
  await enqueueVerify(session.artifactId);
  return "done";
}

/** Whether a template upload transfer of this host and owner by this id is
 * still OPEN (whatever its epoch): a report about it is not moot yet. */
async function openTemplateUpload(sender: RelaySender, transferId: string): Promise<boolean> {
  const open = await prisma.sandboxImageTransfer.count({
    where: {
      id: transferId,
      state: "OPEN",
      mode: "S3",
      purpose: { in: ["CAPTURE_UPLOAD", "PUBLISH"] },
      sourceHostId: sender.hostId,
      sourceHostOwnerId: sender.userId,
    },
  });
  return open > 0;
}

/** Artifact became STORED: release origin pins (the bytes are durable now). */
export async function onArtifactStored(
  ctx: Pick<ImageFrameContext, "sendTo">,
  artifactId: string,
): Promise<void> {
  const artifact = await prisma.sandboxImageArtifact.findUnique({
    where: { id: artifactId },
    select: { userId: true, fingerprint: true, uploadedByHostId: true, state: true },
  });
  if (artifact?.state !== "STORED" || !artifact.uploadedByHostId) return;
  const host = await prisma.sandboxHost.findUnique({
    where: { id: artifact.uploadedByHostId },
    select: { connectionEpoch: true },
  });
  if (host)
    ctx.sendTo(artifact.uploadedByHostId, host.connectionEpoch, {
      type: "image.release",
      fingerprint: artifact.fingerprint,
      imageOwnerId: artifact.userId,
      reason: "stored",
    });
}
