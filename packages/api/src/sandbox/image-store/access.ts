import prisma, { type Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";

/**
 * Foreign image copies whose access was lost (security review P2-5).
 *
 * A copy of an account's image on another account's host is only allowed
 * while every gate that admitted the fetch still holds: the image owner is
 * active (not banned, not deleting, still exists), the host still accepts
 * other accounts' images, the owner can still use a pool the host is an
 * active member of (own pool or a usable share), and some live revision of
 * the owner pins that image with an effective ANY_NODE placement.
 *
 * The same predicate guards every way such a copy is used: accepting
 * `image.cached` evidence for it (round-2 P1-1), reusing an AVAILABLE copy
 * at placement, and the background scan here.
 *
 * The scan (the server's image scheduler, every 15 s, and after a host's
 * census) walks the cache from a durable rotating cursor (round-2 P2-4), so
 * a page of copies that hosts never evict cannot starve later rows. Each lost
 * copy is marked once (`accessLostAt`) and its evidence invalidated at once
 * (availability MISSING). Releases run on their own schedule: connected
 * hosts' lost copies, least recently attempted first, again every
 * RELEASE_RETRY_MS until the host reports the eviction (or a complete census
 * omits it); a reconnecting host's census releases all of its lost copies.
 */
export type LostForeignImage = {
  hostId: string;
  hostOwnerId: string;
  connectionEpoch: number;
  imageOwnerId: string;
  fingerprint: string;
};

const BATCH = 200;
const HOST_PAGES = 10;
export const RELEASE_RETRY_MS = 60_000;
const CURSOR_KEY = "image-store.access.cursor";

/**
 * True when a copy of `owner`'s image `fingerprint` on host alias `host`
 * (a `sandbox_host` row) is no longer allowed. Only meaningful for a host
 * that `owner` does not own.
 */
export function foreignAccessLostSql(
  owner: Prisma.Sql,
  fingerprint: Prisma.Sql,
  host: Prisma.Sql = PrismaValue.raw("h"),
): Prisma.Sql {
  return PrismaValue.sql`(
      NOT EXISTS (SELECT 1 FROM "user" o WHERE o.id = ${owner}
        AND o."deletionRequestedAt" IS NULL
        AND (o.banned IS NOT TRUE OR (o."banExpires" IS NOT NULL
          AND o."banExpires" <= (clock_timestamp() AT TIME ZONE 'UTC'))))
      OR (${host}."daemonFeatures"->'image'->'acceptForeign') IS DISTINCT FROM 'true'::jsonb
      OR NOT EXISTS (SELECT 1 FROM sandbox_pool_member m
        JOIN sandbox_pool p ON p.id = m."poolId" AND p."deletedAt" IS NULL
        WHERE m."sandboxHostId" = ${host}.id AND m."removedAt" IS NULL
          AND (p."userId" = ${owner} OR EXISTS (SELECT 1 FROM share s
            WHERE s."poolId" = p.id AND s."granteeUserId" = ${owner} AND s."canUse")))
      OR NOT EXISTS (SELECT 1 FROM sandbox_template_revision r
        JOIN sandbox_logical_template t ON t.id = r."templateId" AND t."userId" = r."userId"
        LEFT JOIN account_image_policy ap ON ap."userId" = r."userId"
        WHERE r."userId" = ${owner} AND r."incusFingerprint" = ${fingerprint}
          AND r."retiredAt" IS NULL AND t."archivedAt" IS NULL
          AND (t."imagePlacement"::text = 'ANY_NODE' OR (t."imagePlacement"::text = 'INHERIT'
            AND COALESCE(ap."imagePlacement"::text, 'ANY_NODE') = 'ANY_NODE'))))`;
}

/**
 * Placement reuse guard (round-2 P1-1, defense in depth): an AVAILABLE row
 * on host alias `host` may serve `owner`'s placement unless it is a
 * distributed foreign copy (a cache row of that owner on another account's
 * host) that was marked lost or whose access no longer holds.
 */
export function foreignCopyUsableSql(
  owner: string,
  fingerprint: string,
  host: Prisma.Sql = PrismaValue.raw("h"),
): Prisma.Sql {
  return PrismaValue.sql`NOT EXISTS (SELECT 1 FROM sandbox_host_image_cache fc
      WHERE fc."hostId" = ${host}.id AND fc."hostOwnerId" = ${host}."userId"
        AND fc."imageOwnerId" = ${owner} AND fc.fingerprint = ${fingerprint}
        AND fc."hostOwnerId" <> fc."imageOwnerId"
        AND (fc."accessLostAt" IS NOT NULL
          OR ${foreignAccessLostSql(PrismaValue.sql`${owner}`, PrismaValue.sql`${fingerprint}`, host)}))`;
}

/** Whether `owner` may currently hold a copy of `fingerprint` on this host. */
export async function foreignImageAccessHolds(
  tx: Pick<Prisma.TransactionClient, "$queryRaw">,
  input: { hostId: string; hostOwnerId: string; imageOwnerId: string; fingerprint: string },
): Promise<boolean> {
  if (input.hostOwnerId === input.imageOwnerId) return true;
  const rows = await tx.$queryRaw<{ lost: boolean }[]>`
    SELECT ${foreignAccessLostSql(
      PrismaValue.sql`${input.imageOwnerId}`,
      PrismaValue.sql`${input.fingerprint}`,
    )} AS lost
    FROM sandbox_host h WHERE h.id = ${input.hostId} AND h."userId" = ${input.hostOwnerId}`;
  return rows[0]?.lost === false;
}

const lostCopies = (hostId: string | null, after: string | null) => PrismaValue.sql`
    SELECT c.id FROM sandbox_host_image_cache c
    JOIN sandbox_host h ON h.id = c."hostId" AND h."userId" = c."hostOwnerId"
    WHERE c."imageOwnerId" <> c."hostOwnerId" AND c."accessLostAt" IS NULL
      AND (${hostId}::text IS NULL OR c."hostId" = ${hostId})
      AND (${after}::text IS NULL OR c.id > ${after})
      AND ${foreignAccessLostSql(PrismaValue.raw(`c."imageOwnerId"`), PrismaValue.raw("c.fingerprint"))}
    ORDER BY c.id LIMIT ${BATCH}`;

/** Mark one page of newly lost copies and invalidate their evidence. */
async function markLost(hostId: string | null, after: string | null): Promise<string[]> {
  const marked = await prisma.$queryRaw<
    { id: string; hostId: string; hostOwnerId: string; imageOwnerId: string; fingerprint: string }[]
  >`
    UPDATE sandbox_host_image_cache SET "accessLostAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id IN (${lostCopies(hostId, after)}) AND "accessLostAt" IS NULL
    RETURNING id, "hostId", "hostOwnerId", "imageOwnerId", fingerprint`;
  // Invalidate at once: the copy no longer satisfies placement anywhere.
  for (const row of marked)
    await prisma.sandboxTemplateAvailability.updateMany({
      where: {
        hostId: row.hostId,
        hostOwnerId: row.hostOwnerId,
        userId: row.imageOwnerId,
        localFingerprint: row.fingerprint,
        status: "AVAILABLE",
      },
      data: { status: "MISSING", observedAt: new Date() },
    });
  return marked.map((row) => row.id).sort();
}

async function readCursor(): Promise<string | null> {
  const row = await prisma.appSetting.findUnique({
    where: { key: CURSOR_KEY },
    select: { value: true },
  });
  return row?.value ? row.value : null;
}

async function writeCursor(value: string | null): Promise<void> {
  await prisma.appSetting.upsert({
    where: { key: CURSOR_KEY },
    create: { key: CURSOR_KEY, value: value ?? "" },
    update: { value: value ?? "" },
  });
}

/**
 * One scan step, then the releases that are due. Without `hostId`: one
 * page from the durable cursor (a short page wraps it), and connected
 * hosts' lost copies whose last release attempt is older than
 * RELEASE_RETRY_MS, least recently attempted first. With `hostId` (after
 * that host's census): every page of that host, and all of its lost copies.
 * Returned copies are stamped as attempted (`releaseSentAt`).
 */
export async function foreignImageAccessLost(hostId?: string): Promise<LostForeignImage[]> {
  if (hostId) {
    let after: string | null = null;
    for (let page = 0; page < HOST_PAGES; page++) {
      const ids = await markLost(hostId, after);
      if (ids.length < BATCH) break;
      after = ids.at(-1) ?? null;
    }
  } else {
    const ids = await markLost(null, await readCursor());
    await writeCursor(ids.length < BATCH ? null : (ids.at(-1) ?? null));
  }
  const retryBefore = PrismaValue.sql`((clock_timestamp() AT TIME ZONE 'UTC') - make_interval(secs => ${RELEASE_RETRY_MS / 1000}))`;
  return prisma.$queryRaw<LostForeignImage[]>`
    WITH due AS (
      SELECT c.id FROM sandbox_host_image_cache c
      JOIN sandbox_host h ON h.id = c."hostId" AND h."userId" = c."hostOwnerId"
      WHERE c."accessLostAt" IS NOT NULL
        AND ${
          hostId
            ? PrismaValue.sql`c."hostId" = ${hostId}`
            : PrismaValue.sql`h.status = 'CONNECTED'
                AND (c."releaseSentAt" IS NULL OR c."releaseSentAt" < ${retryBefore})`
        }
      ORDER BY c."releaseSentAt" ASC NULLS FIRST, c.id
      LIMIT ${BATCH}
      FOR UPDATE OF c SKIP LOCKED)
    UPDATE sandbox_host_image_cache c
    SET "releaseSentAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    FROM due, sandbox_host h
    WHERE c.id = due.id AND h.id = c."hostId" AND h."userId" = c."hostOwnerId"
    RETURNING c."hostId", c."hostOwnerId", h."connectionEpoch", c."imageOwnerId", c.fingerprint`;
}
