import {
  enqueueOffload,
  failUndeliveredOffload,
  OFFLOAD_RELEASE_WAIT_MS,
  offloadCandidates,
} from "@wssp/api/sandbox/disk-offload/enqueue";
import { storedAckFrame } from "@wssp/api/sandbox/disk-offload/store";
import { endStalledOffloadUploads } from "@wssp/api/sandbox/disk-offload/upload-stall";
import { foreignImageAccessLost } from "@wssp/api/sandbox/image-store/access";
import { sweepCaptures } from "@wssp/api/sandbox/image-store/captures";
import { imageDistributionMode } from "@wssp/api/sandbox/image-store/config";
import {
  endTransfersOfEndedOperations,
  originImagesToRelease,
} from "@wssp/api/sandbox/image-store/jobs";
import prisma from "@wssp/db";
import {
  IMAGE_S3_PART_BYTES,
  type ServerDiskMessage,
  type ServerImageMessage,
} from "@wssp/sandbox-contracts";
import { onArtifactStored } from "../sandbox-relay/image-handlers.js";
import { reconcileImageRelaySpool } from "./index.js";

type Send = (hostId: string, epoch: number, frame: ServerImageMessage) => boolean;
type SendDisk = (hostId: string, epoch: number, frame: ServerDiskMessage) => boolean;

const SWEEP_MS = 15_000;

async function hostEpoch(hostId: string): Promise<number | null> {
  return (
    (
      await prisma.sandboxHost.findUnique({
        where: { id: hostId },
        select: { connectionEpoch: true },
      })
    )?.connectionEpoch ?? null
  );
}

/** Open auto-publish uploads one account may have at a time (documented). */
const PUBLISH_BACKFILL_PER_ACCOUNT = 2;

/**
 * Auto-publish backfill (S3 mode): live revisions with no STORED artifact that
 * are AVAILABLE on an owned, connected, publish-capable host are uploaded,
 * at most one per host and two per account at a time: the query skips an
 * account that already has two open publishes, and one tick starts no more
 * than the account's remaining room.
 */
export async function publishBackfill(send: Send, now = new Date()): Promise<number> {
  if (imageDistributionMode() !== "s3") return 0;
  const candidates = await prisma.$queryRaw<
    {
      userId: string;
      fingerprint: string;
      hostId: string;
      epoch: number;
      size: bigint;
      openPublishes: number;
    }[]
  >`SELECT * FROM (SELECT DISTINCT ON (a."userId", a."localFingerprint")
      a."userId", a."localFingerprint" AS fingerprint, h.id AS "hostId",
      h."connectionEpoch" AS epoch, COALESCE(a."sizeBytes", 1) AS size,
      (SELECT count(*)::int FROM sandbox_image_transfer t WHERE t.state = 'OPEN'
        AND t.purpose = 'PUBLISH' AND t."userId" = a."userId") AS "openPublishes"
    FROM sandbox_template_availability a
    JOIN sandbox_template_revision r ON r.id = a."revisionId" AND r."retiredAt" IS NULL
      AND r."sourceKind"::text <> 'UPSTREAM' AND r."pendingVerifyBuildId" IS NULL
    JOIN sandbox_host h ON h.id = a."hostId" AND h."userId" = a."userId"
    WHERE a.status = 'AVAILABLE' AND a."verifiedConnectionEpoch" = h."connectionEpoch"
      AND h.status = 'CONNECTED' AND (h."daemonFeatures"->'image'->'publish') = 'true'::jsonb
      AND (a."imageFormat" IS NULL OR a."imageFormat" = 'unified')
      AND NOT EXISTS (SELECT 1 FROM sandbox_image_artifact x WHERE x."userId" = a."userId"
        AND x.fingerprint = a."localFingerprint" AND x.state IN ('UPLOADING', 'VERIFYING', 'STORED'))
      AND NOT EXISTS (SELECT 1 FROM sandbox_image_transfer t WHERE t.state = 'OPEN'
        AND t.purpose = 'PUBLISH' AND t."sourceHostId" = h.id)
    ORDER BY a."userId", a."localFingerprint", h."lastHeartbeatAt" DESC NULLS LAST) c
    WHERE c."openPublishes" < ${PUBLISH_BACKFILL_PER_ACCOUNT}
    ORDER BY c."userId", c.fingerprint
    LIMIT 8`;
  let started = 0;
  const hosts = new Set<string>();
  const perAccount = new Map<string, number>();
  for (const c of candidates) {
    if (hosts.has(c.hostId)) continue;
    const open = perAccount.get(c.userId) ?? Number(c.openPublishes);
    if (open >= PUBLISH_BACKFILL_PER_ACCOUNT) continue;
    const transfer = await prisma.sandboxImageTransfer.create({
      data: {
        userId: c.userId,
        fingerprint: c.fingerprint,
        purpose: "PUBLISH",
        mode: "S3",
        sourceHostId: c.hostId,
        sourceHostOwnerId: c.userId,
        sourceEpoch: c.epoch,
        sizeBytes: c.size,
        partSize: IMAGE_S3_PART_BYTES,
        partCount: 1,
        expiresAt: new Date(now.getTime() + 24 * 3_600_000),
      },
      select: { id: true },
    });
    if (
      send(c.hostId, c.epoch, {
        type: "image.publish.request",
        transferId: transfer.id,
        imageOwnerId: c.userId,
        fingerprint: c.fingerprint,
      })
    ) {
      hosts.add(c.hostId);
      perAccount.set(c.userId, open + 1);
      started++;
    } else
      await prisma.sandboxImageTransfer.update({
        where: { id: transfer.id },
        data: { state: "FAILED", endReason: "source_offline" },
      });
  }
  return started;
}

/** Re-send a release to one host copy at most this often while it remains. */
/**
 * P2-5: foreign copies whose access was lost (sharing, policy, accept-foreign,
 * ban, account deletion) are invalidated and released. The retry schedule is
 * durable (`releaseSentAt`, see image-store/access.ts): a copy still reported
 * is released again after RELEASE_RETRY_MS and on the host's next census.
 */
export async function releaseLostForeignImages(send: Send, hostId?: string) {
  let sent = 0;
  for (const lost of await foreignImageAccessLost(hostId))
    if (
      send(lost.hostId, lost.connectionEpoch, {
        type: "image.release",
        fingerprint: lost.fingerprint,
        imageOwnerId: lost.imageOwnerId,
        reason: "access_lost",
      })
    )
      sent++;
  return sent;
}

/**
 * Origin-pin GC: pinned capture copies nothing references any more (their
 * revisions retired; see `originImagesToRelease`) are released with reason
 * `gc`, which unpins the copy so the host's GC and `wssp host images prune` can
 * evict it. The only copy of a live revision is never selected.
 */
async function releaseUnreferencedOriginImages(send: Send) {
  let sent = 0;
  for (const copy of await originImagesToRelease())
    if (
      send(copy.hostId, copy.connectionEpoch, {
        type: "image.release",
        fingerprint: copy.fingerprint,
        imageOwnerId: copy.imageOwnerId,
        reason: "gc",
      })
    )
      sent++;
  return sent;
}

/**
 * The offload upload stall rule on the 15 s tick (`endStalledOffloadUploads`):
 * each ended attempt's source host, if connected, gets `disk.offload.cancel`
 * (`upload_stalled`) so a still-running job stops and drops its staging.
 */
export async function stallOffloadUploads(sendDisk: SendDisk, now = new Date()): Promise<number> {
  const ended = await endStalledOffloadUploads(undefined, now);
  for (const offload of ended) {
    const epoch = await hostEpoch(offload.sourceHostId);
    if (epoch === null) continue;
    sendDisk(offload.sourceHostId, epoch, {
      type: "disk.offload.cancel",
      sandboxId: offload.sandboxId,
      offloadId: offload.offloadId,
      seq: offload.seq,
      reason: "upload_stalled",
    });
  }
  return ended.length;
}

/**
 * Stopped-sandbox disk offload: enqueue candidates (one
 * export per host, two per account; re-checked under locks by
 * `enqueueOffload`) and send each its `disk.offload.request` on the host's
 * current epoch. An undeliverable request ends that attempt FAILED.
 */
export async function offloadScheduling(sendDisk: SendDisk, now = new Date()): Promise<number> {
  let started = 0;
  const hosts = new Set<string>();
  for (const candidate of await offloadCandidates(now)) {
    if (hosts.has(candidate.hostId)) continue;
    const enqueued = await enqueueOffload(candidate, now);
    if (!enqueued) continue;
    hosts.add(candidate.hostId);
    if (
      sendDisk(enqueued.hostId, enqueued.epoch, {
        type: "disk.offload.request",
        sandboxId: enqueued.sandboxId,
        offloadId: enqueued.offloadId,
        seq: enqueued.seq,
        generation: enqueued.generation,
      })
    )
      started++;
    else await failUndeliveredOffload(enqueued);
  }
  return started;
}

/** How long a STORED offload's ack is offered to its source host. */
const STORED_ACK_WINDOW_MS = OFFLOAD_RELEASE_WAIT_MS;
/** Stored acks already sent: offload id → the host epoch it went to (and when). */
const sentStoredAcks = new Map<string, { epoch: number; at: number }>();
/** Unreleased STORED offloads one tick looks at. */
const STORED_ACKS_PER_TICK = 100;

/**
 * §7 "Stored ack": STORED offloads whose source host has not yet confirmed
 * the release tell that host
 * (`disk.offload.stored`), which journals `stored`, drops the alias and
 * staging and answers `disk.offload.released`. Sent once per source-host
 * session (connection epoch) while the row holds the host's export slot
 * (`OFFLOAD_RELEASE_WAIT_MS`): a reconnect gets it again (the daemon is
 * idempotent and answers `released` for an offload it holds nothing of).
 * A host away longer reports an unfinished entry in its
 * `disk.offload.inventory` after reconciliation and is answered there
 * (disk-handlers.ts).
 */
export async function sendStoredAcks(sendDisk: SendDisk, now = new Date()): Promise<number> {
  for (const [id, sent] of sentStoredAcks)
    if (now.getTime() - sent.at >= STORED_ACK_WINDOW_MS) sentStoredAcks.delete(id);
  let sent = 0;
  const recent = await prisma.sandboxDiskOffload.findMany({
    where: {
      state: "STORED",
      sourceReleasedAt: null,
      storedAt: { gt: new Date(now.getTime() - STORED_ACK_WINDOW_MS) },
    },
    select: { id: true },
    orderBy: { storedAt: "desc" },
    take: STORED_ACKS_PER_TICK,
  });
  for (const row of recent) if (await onDiskStored(sendDisk, row.id, now)) sent++;
  return sent;
}

/** A STORED offload tells its source host's current session (§7 "Stored
 * ack"), at most once per session. */
async function onDiskStored(
  sendDisk: SendDisk,
  offloadId: string,
  now = new Date(),
): Promise<boolean> {
  const ack = await storedAckFrame(offloadId);
  if (!ack) return false;
  const host = await prisma.sandboxHost.findUnique({
    where: { id: ack.hostId },
    select: { connectionEpoch: true },
  });
  if (host === null || sentStoredAcks.get(offloadId)?.epoch === host.connectionEpoch) return false;
  if (!sendDisk(ack.hostId, host.connectionEpoch, ack.frame)) return false;
  sentStoredAcks.set(offloadId, { epoch: host.connectionEpoch, at: now.getTime() });
  return true;
}

/** One suggestion per cached copy per this long (the daemon then asks). */
const EVICT_SUGGEST_EVERY_MS = 5 * 60_000;
const suggestedAt = new Map<string, number>();
/** Server-issued evict grants already sent (grant id → when). */
const sentServerGrants = new Map<string, number>();

/**
 * Discards of stale copies on connected hosts, the
 * placement disk-miss suggestions (`disk.evict.suggest`) and the expiry of
 * grants their own session outlived. Each step is bounded.
 */
async function diskEvictionMaintenance(sendDisk: SendDisk, now = new Date()) {
  const { discardFrames } = await import("@wssp/api/sandbox/disk-offload/discard");
  const { clearOutlivedEvictGrants, evictSuggestions, serverEvictGrantFrames } = await import(
    "@wssp/api/sandbox/disk-offload/evict"
  );
  let discards = 0;
  for (const { hostId, epoch, frame } of await discardFrames(now))
    if (sendDisk(hostId, epoch, frame)) discards++;
  let suggestions = 0;
  for (const [key, at] of suggestedAt)
    if (now.getTime() - at >= EVICT_SUGGEST_EVERY_MS) suggestedAt.delete(key);
  for (const { hostId, epoch, frame } of await evictSuggestions()) {
    if (frame.type !== "disk.evict.suggest") continue;
    const key = `${frame.offloadId}:${frame.seq}`;
    if (suggestedAt.has(key)) continue;
    if (sendDisk(hostId, epoch, frame)) {
      suggestedAt.set(key, now.getTime());
      suggestions++;
    }
  }
  // §5 order 3: grants a start issued for a cached host that may not take
  // its copy back; each grant id is sent once per process (a lost frame
  // expires unused and the next start issues another).
  let grants = 0;
  for (const [grantId, at] of sentServerGrants)
    if (now.getTime() - at >= EVICT_SUGGEST_EVERY_MS) sentServerGrants.delete(grantId);
  for (const { hostId, epoch, grantId, frame } of await serverEvictGrantFrames(now)) {
    if (sentServerGrants.has(grantId)) continue;
    if (sendDisk(hostId, epoch, frame)) {
      sentServerGrants.set(grantId, now.getTime());
      grants++;
    }
  }
  const cleared = await clearOutlivedEvictGrants(now);
  return { discards, suggestions, grants, cleared };
}

/** Captures, origin-pin releases, publish backfill and disk offload, every 15 seconds. */
export function startImageScheduler(
  send: Send,
  signal: AbortSignal,
  sendDisk: SendDisk = () => false,
): () => void {
  let running = false;
  let wake = false;
  const tick = async () => {
    if (running) {
      wake = true;
      return;
    }
    running = true;
    try {
      if (imageDistributionMode() !== "off") {
        for (const { outcome } of await sweepCaptures()) {
          // Uploads the finalizer ended: their hosts stop them (I3).
          if (outcome.kind === "failed")
            for (const cancel of outcome.cancels ?? [])
              send(cancel.hostId, cancel.epoch, {
                type: "image.job.cancel",
                transferId: cancel.transferId,
                reason: cancel.reason,
              });
          if (outcome.kind === "failed" && outcome.fingerprint) {
            const epoch = await hostEpoch(outcome.hostId);
            // A capture that will never become a revision must not keep its
            // origin pin (the image belongs to the capturing account).
            if (epoch !== null)
              send(outcome.hostId, epoch, {
                type: "image.release",
                fingerprint: outcome.fingerprint,
                imageOwnerId: outcome.ownerId,
                reason: "gc",
              });
          }
        }
        const stored = await prisma.sandboxImageArtifact.findMany({
          where: { state: "STORED", verifiedAt: { gt: new Date(Date.now() - 10 * 60_000) } },
          select: { id: true },
          take: 50,
        });
        for (const artifact of stored) await onArtifactStored({ sendTo: send }, artifact.id);
        await publishBackfill(send);
        // Transfers whose operation ended stop now; their relayed parts and
        // any expired transfer's parts leave the spool (P2-13).
        await endTransfersOfEndedOperations();
        await reconcileImageRelaySpool();
        await releaseLostForeignImages(send);
        await releaseUnreferencedOriginImages(send);
      }
      // Disk offload needs only the store and the data key (its own gates),
      // never the template distribution mode.
      await sendStoredAcks(sendDisk);
      // Stalled uploads free their host's export slot first, so the same
      // tick can send that host its next export.
      await stallOffloadUploads(sendDisk);
      await offloadScheduling(sendDisk);
      await diskEvictionMaintenance(sendDisk);
    } catch (error) {
      console.error(
        "[image-scheduler] sweep failed:",
        error instanceof Error ? error.name : "error",
      );
    } finally {
      running = false;
      if (wake) {
        wake = false;
        void tick();
      }
    }
  };
  const timer = setInterval(() => void tick(), SWEEP_MS);
  signal.addEventListener("abort", () => clearInterval(timer), { once: true });
  return () => void tick();
}
