import { createHash } from "node:crypto";
import prisma from "@wssp/db";
import { readImageStoreEnv } from "@wssp/env/image-store-config";
import { ensureRunnableJob, imageStoreMaintenanceQueue } from "@wssp/queue";
import type { DiskJob } from "../disk-offload/jobs";
import { keptDiskObjectKeys } from "../disk-offload/store";
import { RELEASE_RETRY_MS } from "./access";
import { ACTIVE_OPERATION_STATES, artifactReferenced, originImageReferenced } from "./references";
import {
  decryptImageStream,
  type ImageStore,
  imageMasterKey,
  imageStore,
  unwrapDataKey,
} from "./s3";
import { ImageIntegrityError, isTerminalImageVerificationError } from "./verification-errors";

/**
 * Image store maintenance (one BullMQ queue, four job kinds): verify an
 * uploaded object, GC unreferenced artifacts, sweep orphans/stale uploads and
 * expired links, and auto-prune old untagged revisions. Every list is bounded.
 */
export type ImageStoreJob =
  | { kind: "verify"; artifactId: string }
  | { kind: "gc" }
  | { kind: "sweep" }
  | { kind: "prune" }
  | { kind: "community_refresh" }
  | DiskJob;

/**
 * Publish the deterministic verify job. A retained completed/failed job with
 * the same id (an earlier upload of the same artifact) is requeued with a
 * fresh attempt budget instead of silently deduplicating the new upload.
 */
export async function enqueueImageVerify(artifactId: string): Promise<void> {
  await ensureRunnableJob(
    imageStoreMaintenanceQueue,
    "verify",
    { kind: "verify", artifactId },
    `verify-${artifactId}`,
    { resetAttemptsMade: true },
  );
}

const PAGE = 200;
const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;

/**
 * Re-read the object as a stream (decrypting when needed), hash it and
 * compare with the fingerprint and size. Pass → STORED; fail → CORRUPT and the
 * object is deleted (the dependent capture or publish fails on its own sweep).
 * Store/stream outages rethrow for retry and leave the artifact VERIFYING.
 */
export async function verifyImageArtifact(
  artifactId: string,
  store: ImageStore | null = imageStore(),
): Promise<"stored" | "corrupt" | "skipped"> {
  if (!store) return "skipped";
  const artifact = await prisma.sandboxImageArtifact.findFirst({
    where: { id: artifactId, state: "VERIFYING" },
  });
  if (!artifact?.objectKey) return "skipped";
  let ok = false;
  try {
    const body = await store.getObjectStream(artifact.objectKey);
    const hash = createHash("sha256");
    let size = 0n;
    let source: AsyncIterable<Uint8Array> = body;
    if (artifact.encryption) {
      const master = imageMasterKey();
      if (!master) throw new Error("image encryption key unavailable");
      if (!artifact.wrappedKey || !artifact.wrappedKeyNonce)
        throw new ImageIntegrityError("invalid image key wrap");
      const key = unwrapDataKey(
        master,
        { wrappedKey: artifact.wrappedKey, wrappedKeyNonce: artifact.wrappedKeyNonce },
        artifact.id,
        artifact.userId,
      );
      source = decryptImageStream(key, Number(artifact.sizeBytes), body);
    }
    for await (const chunk of source) {
      hash.update(chunk);
      size += BigInt(chunk.length);
    }
    ok = size === artifact.sizeBytes && `sha256:${hash.digest("hex")}` === artifact.fingerprint;
  } catch (error) {
    if (!isTerminalImageVerificationError(error)) throw error;
    ok = false;
  }
  if (ok) {
    const stored = await prisma.sandboxImageArtifact.updateMany({
      where: {
        id: artifact.id,
        state: "VERIFYING",
        objectKey: artifact.objectKey,
        updatedAt: artifact.updatedAt,
      },
      data: { state: "STORED", verifiedAt: new Date() },
    });
    return stored.count === 1 ? "stored" : "skipped";
  }
  const failed = await prisma.sandboxImageArtifact.updateMany({
    where: {
      id: artifact.id,
      state: "VERIFYING",
      objectKey: artifact.objectKey,
      updatedAt: artifact.updatedAt,
    },
    data: { state: "CORRUPT", corruptReports: { increment: 1 } },
  });
  if (failed.count !== 1) return "skipped";
  await store.deleteObject(artifact.objectKey).catch(() => {});
  return "corrupt";
}

/** Durable maintenance cursors (P2-14): each run continues where the last
 * stopped and wraps at the end, so later rows are never starved. */
const CURSOR = {
  gc: "image-store.gc.cursor",
  objects: "image-store.sweep.objects",
  uploads: "image-store.sweep.uploads",
  prune: "image-store.prune.cursor",
  origin: "image-store.origin-release.cursor",
} as const;
async function readCursor(key: string): Promise<string | undefined> {
  const row = await prisma.appSetting.findUnique({ where: { key }, select: { value: true } });
  return row?.value ? row.value : undefined;
}
async function writeCursor(key: string, value: string | undefined): Promise<void> {
  await prisma.appSetting.upsert({
    where: { key },
    create: { key, value: value ?? "" },
    update: { value: value ?? "" },
  });
}

export type ReleasableOriginImage = {
  hostId: string;
  connectionEpoch: number;
  imageOwnerId: string;
  fingerprint: string;
};

/**
 * Origin-pin GC (peer mode keeps a capture pinned on its origin node until
 * it is STORED, which never happens there): a pinned `captured` copy that
 * nothing references any more (its revisions retired or never created, see
 * `originImageReferenced`) is released, so the host unpins it and its own
 * GC or `wssp images prune` can evict it. A copy any live revision uses is
 * never released, so the only copy of a live revision always stays pinned.
 * One page per run from a durable rotating cursor (connected hosts only);
 * a release is re-sent at most every RELEASE_RETRY_MS (`releaseSentAt`)
 * until the host's census reports the copy unpinned or gone. Returned copies
 * are stamped as attempted; the caller sends `image.release` (reason `gc`).
 */
export async function originImagesToRelease(now = new Date()): Promise<ReleasableOriginImage[]> {
  const cursor = await readCursor(CURSOR.origin);
  const rows = await prisma.$queryRaw<
    (ReleasableOriginImage & { id: string; releaseSentAt: Date | null })[]
  >`SELECT c.id, c."hostId", h."connectionEpoch", c."imageOwnerId", c.fingerprint, c."releaseSentAt"
    FROM sandbox_host_image_cache c
    JOIN sandbox_host h ON h.id = c."hostId" AND h."userId" = c."hostOwnerId"
    WHERE c.origin = 'captured' AND c.pinned AND c."accessLostAt" IS NULL
      AND h.status = 'CONNECTED' AND c.id > ${cursor ?? ""}
    ORDER BY c.id
    LIMIT ${PAGE}`;
  // A short page ends the pass: the next run starts again from the beginning.
  await writeCursor(CURSOR.origin, rows.length < PAGE ? undefined : rows.at(-1)?.id);
  const due: ReleasableOriginImage[] = [];
  for (const row of rows) {
    if (row.releaseSentAt && now.getTime() - row.releaseSentAt.getTime() < RELEASE_RETRY_MS)
      continue;
    if (await originImageReferenced(prisma, row.imageOwnerId, row.fingerprint, row)) continue;
    const stamped = await prisma.sandboxHostImageCache.updateMany({
      where: { id: row.id, pinned: true, accessLostAt: null, releaseSentAt: row.releaseSentAt },
      data: { releaseSentAt: now },
    });
    if (stamped.count === 1)
      due.push({
        hostId: row.hostId,
        connectionEpoch: row.connectionEpoch,
        imageOwnerId: row.imageOwnerId,
        fingerprint: row.fingerprint,
      });
  }
  return due;
}

/**
 * GC: mark unreferenced artifacts with a grace deadline (a new reference
 * clears it); when due, re-check under owner placement → artifact FOR
 * UPDATE (the order placement's suffix uses), commit DELETING before the
 * DeleteObject call, then DELETED. A DELETING row is terminal-bound: a
 * failed DeleteObject leaves it DELETING and a later run retries the delete
 * (round-2 P2-7); finalization is conditional on the row still being DELETING.
 */
export async function gcImageArtifacts(
  store: ImageStore | null = imageStore(),
  now = new Date(),
): Promise<{ marked: number; deleted: number }> {
  let marked = 0;
  let deleted = 0;
  const cursor = await readCursor(CURSOR.gc);
  const candidates = await prisma.sandboxImageArtifact.findMany({
    where: {
      state: { in: ["STORED", "CORRUPT", "FAILED", "LOCAL", "DELETING"] },
      ...(cursor ? { id: { gt: cursor } } : {}),
    },
    select: {
      id: true,
      userId: true,
      fingerprint: true,
      deleteAfter: true,
      state: true,
      objectKey: true,
    },
    orderBy: { id: "asc" },
    take: PAGE,
  });
  // A short page ends the pass: the next run starts again from the beginning.
  await writeCursor(CURSOR.gc, candidates.length < PAGE ? undefined : candidates.at(-1)?.id);
  for (const artifact of candidates) {
    if (artifact.state === "DELETING") {
      // A previous DeleteObject failed (or the process died after DELETING).
      if (await finishArtifactDelete(store, artifact.id, artifact.objectKey)) deleted++;
      continue;
    }
    const referenced = await artifactReferenced(prisma, artifact.userId, artifact.fingerprint);
    if (referenced) {
      if (artifact.deleteAfter)
        await prisma.sandboxImageArtifact.update({
          where: { id: artifact.id },
          data: { unreferencedSince: null, deleteAfter: null },
        });
      continue;
    }
    if (!artifact.deleteAfter) {
      await prisma.sandboxImageArtifact.update({
        where: { id: artifact.id },
        data: {
          unreferencedSince: now,
          deleteAfter: new Date(now.getTime() + readImageStoreEnv().IMAGE_GC_GRACE_DAYS * DAY_MS),
        },
      });
      marked++;
      if (readImageStoreEnv().IMAGE_GC_GRACE_DAYS > 0) continue;
    } else if (artifact.deleteAfter > now) continue;
    const key = await prisma.$transaction(async (tx) => {
      // Owner placement (the same advisory lock `lockOwnerPlacement` takes).
      await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${artifact.userId}, 31))`;
      const [row] = await tx.$queryRaw<{ id: string; objectKey: string | null }[]>`
        SELECT id, "objectKey" FROM sandbox_image_artifact WHERE id = ${artifact.id} FOR UPDATE`;
      if (!row || (await artifactReferenced(tx, artifact.userId, artifact.fingerprint)))
        return undefined;
      await tx.sandboxImageArtifact.update({
        where: { id: artifact.id },
        data: { state: "DELETING" },
      });
      return row.objectKey;
    });
    if (key === undefined) continue;
    if (await finishArtifactDelete(store, artifact.id, key)) deleted++;
  }
  return { marked, deleted };
}

/**
 * DeleteObject, then DELETING → DELETED only if the row is still DELETING.
 * A failure keeps DELETING (retried by the next GC run) instead of aborting
 * the run; without a store the object cannot be deleted, so the row waits.
 */
async function finishArtifactDelete(
  store: ImageStore | null,
  artifactId: string,
  key: string | null,
): Promise<boolean> {
  if (key) {
    if (!store) return false;
    try {
      await store.deleteObject(key);
    } catch {
      return false;
    }
  }
  const done = await prisma.sandboxImageArtifact.updateMany({
    where: { id: artifactId, state: "DELETING" },
    // credential-settlement: exempt — an image artifact row, not a sandbox.
    data: { state: "DELETED", objectKey: null },
  });
  return done.count === 1;
}

export type ParsedObjectKey =
  | { kind: "image"; ownerId: string; fingerprint: string }
  | { kind: "disk"; ownerId: string; sandboxId: string; offloadId: string; sessionId: string };

/**
 * `<prefix>/owners/<owner>/<fphex>/image.tar[.wsspenc]` (a template image) or
 * `<prefix>/owners/<owner>/sandboxes/<sandbox>/<offload>/<session>.wsspenc`
 * → its parts, or null.
 */
export function parseImageObjectKey(prefix: string, key: string): ParsedObjectKey | null {
  const base = prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const id = "[A-Za-z0-9_-]{1,128}";
  const image = new RegExp(`^${base}/owners/(${id})/([0-9a-f]{64})/image\\.tar(\\.wsspenc)?$`).exec(
    key,
  );
  if (image) return { kind: "image", ownerId: image[1]!, fingerprint: `sha256:${image[2]}` };
  const disk = new RegExp(
    `^${base}/owners/(${id})/sandboxes/(${id})/(${id})/(${id})\\.wsspenc$`,
  ).exec(key);
  return disk
    ? {
        kind: "disk",
        ownerId: disk[1]!,
        sandboxId: disk[2]!,
        offloadId: disk[3]!,
        sessionId: disk[4]!,
      }
    : null;
}

/**
 * Sweeper: orphan objects (no row) older than a day, multipart uploads older
 * than a day, UPLOADING artifacts with no progress for a day, expired links
 * and transfers. Bounded pages; the next run continues.
 */
export async function sweepImageStore(
  store: ImageStore | null = imageStore(),
  now = new Date(),
  enqueueVerify: (artifactId: string) => Promise<void> = enqueueImageVerify,
) {
  const dayAgo = new Date(now.getTime() - DAY_MS);
  let orphans = 0;
  if (store) {
    let next: string | undefined;
    let after = await readCursor(CURSOR.objects);
    let finished = false;
    for (let page = 0; page < 10; page++) {
      const listing = await store.listObjectsPage(next, after);
      // One read per listing page prefilters the objects a row still owns;
      // each remaining candidate is re-checked right before its delete, so a
      // row created after the prefilter still protects its object.
      const aged = listing.objects
        .filter((object) => object.lastModified && object.lastModified <= dayAgo)
        .map((object) => object.key);
      // Disk offload objects follow their own keep set;
      // every other key is a template image or an orphan. The
      // listing is already scoped to the store prefix.
      const isDisk = (key: string) =>
        parseImageObjectKey(key.split("/owners/")[0] ?? "", key)?.kind === "disk";
      const agedImages = aged.filter((key) => !isDisk(key));
      const owned = new Set(
        agedImages.length === 0
          ? []
          : (
              await prisma.sandboxImageArtifact.findMany({
                where: { objectKey: { in: agedImages }, state: { notIn: ["DELETED", "DELETING"] } },
                select: { objectKey: true },
                take: agedImages.length,
              })
            ).map((row) => row.objectKey),
      );
      for (const object of listing.objects) {
        after = object.key;
        if (!object.lastModified || object.lastModified > dayAgo) continue;
        if (owned.has(object.key)) continue;
        if (isDisk(object.key)) {
          // Re-checked right before the delete, like the template rows.
          if ((await keptDiskObjectKeys(prisma, [object.key], now)).size === 0) {
            await store.deleteObject(object.key);
            orphans++;
          }
          continue;
        }
        const known = await prisma.sandboxImageArtifact.findFirst({
          // A DELETING row's object is already condemned: deleting it here
          // is the same idempotent DeleteObject GC retries.
          where: { objectKey: object.key, state: { notIn: ["DELETED", "DELETING"] } },
          select: { id: true },
        });
        if (!known) {
          await store.deleteObject(object.key);
          orphans++;
        }
      }
      if (!listing.next) {
        finished = true;
        break;
      }
      next = listing.next;
    }
    await writeCursor(CURSOR.objects, finished ? undefined : after);
    const saved = await readCursor(CURSOR.uploads);
    let marker: { keyMarker?: string; uploadIdMarker?: string } | undefined = saved
      ? (JSON.parse(saved) as { keyMarker?: string; uploadIdMarker?: string })
      : undefined;
    let uploadsDone = false;
    for (let page = 0; page < 10; page++) {
      const listing = await store.listUploadsPage(marker?.keyMarker, marker?.uploadIdMarker);
      for (const upload of listing.uploads)
        if (upload.initiated && upload.initiated < dayAgo)
          await store.abortMultipart(upload.key, upload.uploadId).catch(() => {});
      if (!listing.next) {
        uploadsDone = true;
        break;
      }
      marker = listing.next;
    }
    await writeCursor(CURSOR.uploads, uploadsDone || !marker ? undefined : JSON.stringify(marker));
  }
  // Upload sessions (round-5 P2-2): a live session whose job ended, or whose
  // artifact made no progress for a day, is aborted; then every ended
  // session's multipart upload is aborted (bounded; the bucket-wide sweep
  // above is the backstop after a day).
  // Template sessions only: a disk session holds its wrap while OPEN and is
  // ended with its offload by the disk maintenance job.
  await prisma.sandboxImageUploadSession.updateMany({
    where: {
      state: "OPEN",
      artifactId: { not: null },
      OR: [
        { Transfer: { state: { not: "OPEN" } } },
        { Artifact: { state: "UPLOADING", lastProgressAt: { lt: dayAgo } } },
      ],
    },
    data: { state: "ABORTED", liveArtifactId: null, endReason: "stale" },
  });
  const stale = await prisma.sandboxImageArtifact.updateMany({
    where: { state: "UPLOADING", lastProgressAt: { lt: dayAgo } },
    data: { state: "FAILED" },
  });
  let abortedUploads = 0;
  if (store) {
    const ended = await prisma.sandboxImageUploadSession.findMany({
      where: { state: "ABORTED", uploadId: { not: null } },
      select: { id: true, objectKey: true, uploadId: true },
      orderBy: { updatedAt: "asc" },
      take: PAGE,
    });
    for (const session of ended) {
      try {
        await store.abortMultipart(session.objectKey, session.uploadId!);
      } catch (error) {
        if ((error as { name?: string } | null)?.name !== "NoSuchUpload") continue;
      }
      await prisma.sandboxImageUploadSession.updateMany({
        where: { id: session.id, state: "ABORTED", uploadId: session.uploadId },
        data: { uploadId: null },
      });
      abortedUploads++;
    }
  }
  // Verify backstop: a VERIFYING artifact whose verify job was lost (a crash
  // between the VERIFYING commit and the enqueue, or a dropped job) is
  // re-published after an hour. Give up after a day without claiming corruption,
  // even if this worker's store configuration is unavailable. storedAt records
  // upload completion (entry to VERIFYING); older rows fall back to updatedAt.
  let reverified = 0;
  {
    const hourAgo = new Date(now.getTime() - HOUR_MS);
    const stuck = await prisma.sandboxImageArtifact.findMany({
      where: {
        state: "VERIFYING",
        OR: [
          { lastProgressAt: { lt: hourAgo } },
          { lastProgressAt: null, updatedAt: { lt: hourAgo } },
        ],
      },
      select: { id: true, storedAt: true, updatedAt: true, objectKey: true },
      orderBy: { id: "asc" },
      take: PAGE,
    });
    for (const artifact of stuck) {
      if ((artifact.storedAt ?? artifact.updatedAt) <= dayAgo) {
        await prisma.sandboxImageArtifact.updateMany({
          where: {
            id: artifact.id,
            state: "VERIFYING",
            objectKey: artifact.objectKey,
            updatedAt: artifact.updatedAt,
          },
          // There is no artifact failure-reason column. FAILED leaves the
          // corruption counter alone; normal GC cleans up the abandoned object.
          data: { state: "FAILED" },
        });
        continue;
      }
      if (!store) continue;
      try {
        await enqueueVerify(artifact.id);
        reverified++;
      } catch {
        // The next sweep retries; one unreachable job must not end the run.
      }
    }
  }
  const expiredTransfers = await prisma.sandboxImageTransfer.updateMany({
    where: { state: "OPEN", expiresAt: { lt: now } },
    data: { state: "EXPIRED", endReason: "expired" },
  });
  await endTransfersOfEndedOperations();
  const links = await prisma.$executeRaw`DELETE FROM sandbox_image_link WHERE id IN (
    SELECT id FROM sandbox_image_link WHERE "expiresAt" < ${now} ORDER BY id LIMIT 1000)`;
  return {
    orphans,
    staleUploads: stale.count,
    abortedUploads,
    reverified,
    expiredTransfers: expiredTransfers.count,
    links,
  };
}

/**
 * OPEN transfers whose create or capture operation already ended are
 * cancelled and their links dropped (P2-13); the web process's spool
 * reconciliation then releases their relayed parts. Bounded per call.
 */
export async function endTransfersOfEndedOperations(): Promise<string[]> {
  const ended = await prisma.$queryRaw<{ id: string }[]>`
    UPDATE sandbox_image_transfer SET state = 'CANCELLED', "endReason" = 'operation_ended',
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id IN (SELECT x.id FROM sandbox_image_transfer x
      JOIN sandbox_mutation_operation o ON o.id = x."operationId"
      WHERE x.state = 'OPEN' AND NOT (o.state::text = ANY(${ACTIVE_OPERATION_STATES}::text[]))
      ORDER BY x.id LIMIT 500)
      AND state = 'OPEN'
    RETURNING id`;
  const ids = ended.map((row) => row.id);
  if (ids.length > 0)
    await prisma.sandboxImageLink.deleteMany({ where: { transferId: { in: ids } } });
  return ids;
}

/**
 * Daily auto-prune (`pruneAfterDays`): retire revisions with no tag, older
 * than the template's threshold, and not among the newest `captureKeep` of
 * their capture tag. Never the only revision a sandbox is pinned to.
 * Bounded per run; a durable cursor rotates through every template.
 */
export async function pruneTemplateRevisions(now = new Date()): Promise<number> {
  // A durable rotating cursor (round-3 P2-5): processed templates stay
  // eligible, so a fixed first page would starve every later template.
  const cursor = await readCursor(CURSOR.prune);
  const templates = await prisma.sandboxTemplate.findMany({
    where: {
      pruneAfterDays: { not: null },
      archivedAt: null,
      ...(cursor ? { id: { gt: cursor } } : {}),
    },
    select: { id: true, userId: true, pruneAfterDays: true, captureKeep: true },
    orderBy: { id: "asc" },
    take: PAGE,
  });
  // A short page ends the pass: the next run starts again from the beginning.
  await writeCursor(CURSOR.prune, templates.length < PAGE ? undefined : templates.at(-1)?.id);
  let retired = 0;
  for (const template of templates) {
    const cutoff = new Date(now.getTime() - (template.pruneAfterDays ?? 0) * DAY_MS);
    const rows = await prisma.$executeRaw`
      UPDATE sandbox_template_revision r SET "retiredAt" = ${now}, "retiredReason" = 'auto_prune'
      WHERE r.id IN (
        SELECT c.id FROM sandbox_template_revision c
        WHERE c."templateId" = ${template.id} AND c."userId" = ${template.userId}
          AND c."retiredAt" IS NULL AND c."createdAt" < ${cutoff}
          -- Never a revision pending its verify VM, nor an active build's base (community-base I1).
          AND c."pendingVerifyBuildId" IS NULL
          AND NOT EXISTS (SELECT 1 FROM sandbox_template_build b
            WHERE b."baseRevisionId" = c.id AND b."userId" = c."userId"
              AND b.state::text IN ('AWAITING_CONTEXT', 'QUEUED', 'PLACING', 'RUNNING', 'STOPPING', 'CAPTURING', 'CANCELLING'))
          AND NOT EXISTS (SELECT 1 FROM sandbox_template_tag g WHERE g."revisionId" = c.id)
          AND NOT EXISTS (SELECT 1 FROM sandbox_instance s
            WHERE s."templateRevisionId" = c.id AND s.state <> 'DELETED')
          AND c.id NOT IN (SELECT k.id FROM sandbox_template_revision k
            WHERE k."templateId" = c."templateId" AND k."retiredAt" IS NULL
              AND k."captureTag" IS NOT DISTINCT FROM c."captureTag"
            ORDER BY k.revision DESC LIMIT ${template.captureKeep})
        ORDER BY c.revision ASC LIMIT 100)`;
    retired += rows;
  }
  return retired;
}

export async function handleImageStoreJob(job: ImageStoreJob): Promise<unknown> {
  switch (job.kind) {
    case "verify":
      return verifyImageArtifact(job.artifactId);
    case "gc":
      return gcImageArtifacts();
    case "sweep":
      return sweepImageStore();
    case "prune":
      return pruneTemplateRevisions();
    case "disk_verify":
    case "disk_maintenance": {
      const { handleDiskJob } = await import("../disk-offload/jobs");
      return handleDiskJob(job);
    }
    case "community_refresh": {
      // Imported lazily: the community service reaches the build modules,
      // which the image store's other jobs never need.
      const { runCommunityRefreshScan } = await import("../../template-builds/community/service");
      return runCommunityRefreshScan();
    }
  }
}
