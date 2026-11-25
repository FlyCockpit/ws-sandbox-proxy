/**
 * What still references an image (artifact GC and origin-pin GC), and the
 * relay-side release decisions built on it. Kept free of queue and store
 * imports: the relay's frame handlers load it.
 */
import prisma, { type Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";

export const ACTIVE_OPERATION_STATES = [
  "QUEUED",
  "DISPATCHED",
  "ACCEPTED",
  "RUNNING",
  "CANCEL_REQUESTED",
];

/**
 * The one definition of a live revision: not retired, and its template not
 * archived. `r` is a `sandbox_template_revision` alias and `t` its own
 * `sandbox_logical_template`, joined on id and owner. Archiving keeps the
 * revisions' `retiredAt` unset, so a query that checks only `retiredAt`
 * disagrees with GC (the churn loop: GC deleted an archived template's image
 * and the publish backfill uploaded it again from a host copy).
 */
export function liveRevisionSql(
  r: Prisma.Sql = PrismaValue.raw("r"),
  t: Prisma.Sql = PrismaValue.raw("t"),
): Prisma.Sql {
  return PrismaValue.sql`${r}."retiredAt" IS NULL AND ${t}."archivedAt" IS NULL`;
}

/**
 * Live references keep an artifact: a live revision, an open transfer, an
 * in-flight create, or an unfinished capture (its result or its upload).
 * The SQL boolean GC deletes by. The publish backfill uploads only images
 * this holds for, so GC never deletes what the backfill would upload again.
 * `owner` and `fingerprint` are SQL expressions (a bound value or a column).
 */
export function artifactReferencedSql(owner: Prisma.Sql, fingerprint: Prisma.Sql): Prisma.Sql {
  return PrismaValue.sql`(EXISTS (SELECT 1 FROM sandbox_template_revision r
        JOIN sandbox_logical_template t ON t.id = r."templateId" AND t."userId" = r."userId"
        WHERE r."userId" = ${owner} AND r."incusFingerprint" = ${fingerprint}
          AND ${liveRevisionSql()})
      OR EXISTS (SELECT 1 FROM sandbox_image_transfer x
        WHERE x."userId" = ${owner} AND x.fingerprint = ${fingerprint} AND x.state = 'OPEN')
      OR EXISTS (SELECT 1 FROM sandbox_placement p
        JOIN sandbox_mutation_operation o ON o.id = p."operationId"
        WHERE p."userId" = ${owner} AND p.artifact = ${fingerprint}
          AND o.state::text = ANY(${ACTIVE_OPERATION_STATES}::text[]))
      OR EXISTS (SELECT 1 FROM sandbox_template_capture c
        WHERE c."userId" = ${owner} AND c.fingerprint = ${fingerprint}
          AND c.state::text IN ('PENDING', 'CAPTURED', 'STORING'))
      OR EXISTS (SELECT 1 FROM sandbox_image_transfer x
        JOIN sandbox_template_capture c ON c."operationId" = x."operationId"
        WHERE x."userId" = ${owner} AND x.fingerprint = ${fingerprint}
          AND c.state::text IN ('PENDING', 'CAPTURED', 'STORING')))`;
}

/** Whether `artifactReferencedSql` holds for `owner`'s image `fingerprint`. */
export async function artifactReferenced(
  tx: Prisma.TransactionClient,
  ownerId: string,
  fingerprint: string,
): Promise<boolean> {
  const rows = await tx.$queryRaw<{ referenced: boolean }[]>`
    SELECT ${artifactReferencedSql(PrismaValue.sql`${ownerId}`, PrismaValue.sql`${fingerprint}`)} AS referenced`;
  return rows[0]?.referenced === true;
}

/**
 * An origin capture copy is still needed: any artifact reference (a live
 * revision of a live template, an open transfer such as a pending fetch from
 * this origin, an in-flight create, an unfinished capture), or any live
 * sandbox or unfinished build whose revision is this image, retired or not.
 * On a host, a PENDING capture of this owner (other than `exceptOperationId`)
 * also keeps it: its result, not yet recorded, may name exactly this image
 * (a copy the census reported before its capture's result arrived).
 */
export async function originImageReferenced(
  tx: Prisma.TransactionClient,
  ownerId: string,
  fingerprint: string,
  host: { hostId: string; exceptOperationId?: string },
): Promise<boolean> {
  if (await artifactReferenced(tx, ownerId, fingerprint)) return true;
  const rows = await tx.$queryRaw<{ referenced: boolean }[]>`
    SELECT (EXISTS (SELECT 1 FROM sandbox_template_capture c
        WHERE c."userId" = ${ownerId} AND c."hostId" = ${host.hostId}
          AND c.state::text = 'PENDING'
          AND c."operationId" <> ${host.exceptOperationId ?? ""})
      OR EXISTS (SELECT 1 FROM sandbox_instance s
        JOIN sandbox_template_revision r ON r.id = s."templateRevisionId"
        WHERE r."userId" = ${ownerId} AND r."incusFingerprint" = ${fingerprint}
          AND s.state::text <> 'DELETED')
      OR EXISTS (SELECT 1 FROM sandbox_template_build b
        JOIN sandbox_template_revision r ON r.id = b."baseRevisionId"
        WHERE r."userId" = ${ownerId} AND r."incusFingerprint" = ${fingerprint}
          AND b.state::text NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED'))) AS referenced`;
  return rows[0]?.referenced === true;
}

/**
 * A host census reported a pinned captured copy for another account that
 * the server has no row for (the census never creates foreign evidence, M4),
 * so the origin-pin GC cannot see it: release it when nothing references it
 * and no unrecorded capture of that account on this host could name it.
 */
export async function unrecordedForeignCaptureReleasable(input: {
  hostId: string;
  imageOwnerId: string;
  fingerprint: string;
}): Promise<boolean> {
  return !(await originImageReferenced(prisma, input.imageOwnerId, input.fingerprint, {
    hostId: input.hostId,
  }));
}

/**
 * E2-A-01: a capture result the relay could not record (its operation was
 * superseded, e.g. a cancel's cleanup kill fenced the in-flight capture, or
 * it already ended) never becomes a revision, so nothing would ever release
 * the image the host published and pinned for it. Returns the copy to
 * release (`image.release` reason `gc`, which unpins and evicts a captured
 * copy) only when the result can never be recorded any more and nothing
 * references the image; `null` otherwise (an operation that may still
 * accept a receipt, a result the capture row already recorded, a foreign
 * operation, or a referenced image).
 */
export async function droppedCaptureImageToRelease(input: {
  operationId: string;
  hostId: string;
  fingerprint: unknown;
}): Promise<{ imageOwnerId: string; fingerprint: string } | null> {
  const fingerprint = input.fingerprint;
  if (typeof fingerprint !== "string" || !/^sha256:[0-9a-f]{64}$/.test(fingerprint)) return null;
  const op = await prisma.sandboxOperation.findFirst({
    where: { id: input.operationId, kind: "CAPTURE_TEMPLATE" },
    select: { userId: true, state: true, errorCode: true },
  });
  if (!op) return null;
  // The capture row binds the operation to the host that ran it.
  const capture = await prisma.sandboxTemplateCapture.findFirst({
    where: { operationId: input.operationId, userId: op.userId, hostId: input.hostId },
    select: { state: true, fingerprint: true },
  });
  // A recorded result belongs to the finalizer (revision or failure).
  if (!capture || capture.fingerprint !== null) return null;
  // Only PENDING accepts a result, and only from an operation still fenced
  // for it: superseded authority and a terminal state are both final.
  const unrecordable =
    capture.state !== "PENDING" ||
    op.errorCode === "superseded" ||
    op.state === "CANCELLED" ||
    op.state === "FAILED";
  if (!unrecordable) return null;
  if (
    await originImageReferenced(prisma, op.userId, fingerprint, {
      hostId: input.hostId,
      exceptOperationId: input.operationId,
    })
  )
    return null;
  return { imageOwnerId: op.userId, fingerprint };
}
