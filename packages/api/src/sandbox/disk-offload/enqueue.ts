import prisma, { type Prisma } from "@wssp/db";
import { lockImageQuota } from "../image-store/config";
import { OFFLOADABLE_SANDBOX_PURPOSES } from "../managed-sandbox";
import { lockHostByEpoch, relayTransaction, requireRelayFence } from "../relay-fence";
import { canOffload } from "./availability";
import { loginStateSettled, offloadReceiptsSettled } from "./eligibility";
import { offloadQuotaBytes, offloadUsageBytes } from "./quota";
import { failLiveOffload, lockSandboxRow, PRE_STORED_STATES, UPLOADABLE_STATES } from "./store";

/**
 * Offload candidates and enqueue (one export
 * per host, two per account; §4 safeguard 1 at enqueue; §4a N4).
 *
 * A candidate is a STOPPED sandbox of an offloadable purpose (R15.1) with no
 * current stored disk and no live offload, on a connected host whose hello
 * reported `diskOffload`, with `canOffload` true. A failed attempt of the
 * same generation backs off, and a generation stops retrying after a few
 * attempts (a retry always uses a new offload id, R13).
 */

/** Exports one account may have in flight (PENDING | EXPORTING | UPLOADING). */
export const OFFLOADS_PER_ACCOUNT = 2;
/** A failed or superseded attempt of the same generation waits this long. */
export const OFFLOAD_RETRY_BACKOFF_MS = 30 * 60_000;
/**
 * A `staging_full` attempt waits only this long: staging is the
 * host's own, so room usually returns soon.
 */
export const OFFLOAD_STAGING_RETRY_MS = 2 * 60_000;
/** Attempts per stopped generation before it stays local. */
export const OFFLOAD_ATTEMPTS_PER_GENERATION = 3;
const CANDIDATES_PER_TICK = 16;
/**
 * A host's export is in flight until STORED, and a STORED one holds the
 * host's slot until the daemon confirms (`disk.offload.released`,
 * `sourceReleasedAt`) that it dropped the export's alias, staging and
 * reservation: a next request that reached the daemon before
 * its stored ack would fail `staging_full` against the previous
 * reservation. The scheduler offers the ack to every session of the host
 * until then; an unreleased row stops holding the slot after
 * `OFFLOAD_RELEASE_WAIT_MS` (liveness backstop for a daemon that cannot
 * journal the ack).
 */
const HOST_BUSY_STATES = PRE_STORED_STATES;
/** How long an unreleased STORED offload holds its host's export slot. */
export const OFFLOAD_RELEASE_WAIT_MS = 10 * 60_000;

/** Prisma filter: this host's offloads that still hold its export slot. */
export function hostExportBusy(hostId: string, now: Date): Prisma.SandboxDiskOffloadWhereInput {
  return {
    sourceHostId: hostId,
    OR: [
      { state: { in: [...HOST_BUSY_STATES] } },
      {
        state: "STORED",
        sourceReleasedAt: null,
        storedAt: { gt: new Date(now.getTime() - OFFLOAD_RELEASE_WAIT_MS) },
      },
    ],
  };
}

export type OffloadCandidate = {
  sandboxId: string;
  userId: string;
  generation: number;
  hostId: string;
  hostOwnerId: string;
  epoch: number;
};

/** One bounded page of offload candidates (re-checked under locks by `enqueueOffload`). */
export async function offloadCandidates(now = new Date()): Promise<OffloadCandidate[]> {
  // Deployment gates first (store, data key, SANDBOX_OFFLOAD); the host's
  // capability is the query's own filter.
  if (!canOffload(true)) return [];
  return prisma.$queryRaw<OffloadCandidate[]>`
    SELECT s.id AS "sandboxId", s."userId", s.generation, h.id AS "hostId",
      h."userId" AS "hostOwnerId", h."connectionEpoch" AS epoch
    FROM sandbox_instance s
    JOIN sandbox_host h ON h.id = s."sandboxHostId" AND h."userId" = s."hostOwnerId"
    WHERE s.state::text = 'STOPPED' AND s."diskOffloadId" IS NULL
      AND s.purpose::text = ANY(${[...OFFLOADABLE_SANDBOX_PURPOSES]}::text[])
      AND h.status::text = 'CONNECTED' AND h."daemonDiskOffload"
      AND NOT EXISTS (SELECT 1 FROM sandbox_disk_offload o WHERE o."liveSandboxId" = s.id)
      AND NOT EXISTS (SELECT 1 FROM sandbox_disk_offload o WHERE o."sourceHostId" = h.id
        AND (o.state::text = ANY(${[...HOST_BUSY_STATES]}::text[])
          OR (o.state::text = 'STORED' AND o."sourceReleasedAt" IS NULL
            AND o."storedAt" > ${new Date(now.getTime() - OFFLOAD_RELEASE_WAIT_MS)})))
      AND (SELECT count(*) FROM sandbox_disk_offload o WHERE o."userId" = s."userId"
        AND o.state::text = ANY(${[...UPLOADABLE_STATES]}::text[])) < ${OFFLOADS_PER_ACCOUNT}
      AND NOT EXISTS (SELECT 1 FROM sandbox_disk_offload o WHERE o."sandboxId" = s.id
        AND o."sourceGeneration" = s.generation
        AND o."createdAt" > ${new Date(now.getTime() - OFFLOAD_RETRY_BACKOFF_MS)}
        -- A staging_full attempt waits only OFFLOAD_STAGING_RETRY_MS.
        AND (o.state::text <> 'FAILED' OR o."failureCode" IS DISTINCT FROM 'staging_full'
          OR o."createdAt" > ${new Date(now.getTime() - OFFLOAD_STAGING_RETRY_MS)}))
      AND (SELECT count(*) FROM sandbox_disk_offload o WHERE o."sandboxId" = s.id
        AND o."sourceGeneration" = s.generation) < ${OFFLOAD_ATTEMPTS_PER_GENERATION}
    -- A host draining with --offload goes first.
    ORDER BY (h.draining AND h."drainOffload") DESC, s."lastStoppedAt" ASC NULLS FIRST, s.id
    LIMIT ${CANDIDATES_PER_TICK}`;
}

export type EnqueuedOffload = {
  offloadId: string;
  sandboxId: string;
  seq: number;
  generation: number;
  hostId: string;
  epoch: number;
};

/**
 * Insert one PENDING offload for `candidate`, re-checking everything under
 * owner (31) → host by epoch → sandbox: STOPPED at that generation on that
 * host, no stored disk, no live offload, the per-host and per-account
 * limits, `canOffload`, `loginStateSettled`, the receipt gate and room in
 * the stored quota. `seq` is `++Sandbox.offloadSeq` (never reused). Null when
 * any check fails; nothing is written then.
 */
export async function enqueueOffload(
  candidate: OffloadCandidate,
  now = new Date(),
): Promise<EnqueuedOffload | null> {
  return relayTransaction(async (tx) => {
    await lockImageQuota(tx, candidate.userId);
    await lockHostByEpoch(tx, candidate.hostId, candidate.epoch, candidate.hostOwnerId);
    requireRelayFence(await lockSandboxRow(tx, candidate.sandboxId));
    const host = await tx.sandboxHost.findUnique({
      where: { id: candidate.hostId },
      select: { status: true, daemonDiskOffload: true },
    });
    if (host?.status !== "CONNECTED" || !canOffload(host.daemonDiskOffload)) return null;
    const sandbox = await tx.sandbox.findFirst({
      where: {
        id: candidate.sandboxId,
        userId: candidate.userId,
        state: "STOPPED",
        generation: candidate.generation,
        sandboxHostId: candidate.hostId,
        hostOwnerId: candidate.hostOwnerId,
        diskOffloadId: null,
        purpose: { in: [...OFFLOADABLE_SANDBOX_PURPOSES] },
      },
      select: { id: true },
    });
    if (!sandbox) return null;
    const busy = await tx.sandboxDiskOffload.count({
      where: {
        OR: [{ liveSandboxId: candidate.sandboxId }, hostExportBusy(candidate.hostId, now)],
      },
    });
    if (busy > 0) return null;
    const accountOpen = await tx.sandboxDiskOffload.count({
      where: { userId: candidate.userId, state: { in: [...UPLOADABLE_STATES] } },
    });
    if (accountOpen >= OFFLOADS_PER_ACCOUNT) return null;
    if (!(await loginStateSettled(tx, candidate.sandboxId))) return null;
    if (!(await offloadReceiptsSettled(tx, candidate.sandboxId, candidate.generation))) return null;
    // A full quota never starts an export it would refuse at begin.
    if (
      (await offloadUsageBytes(tx, candidate.userId)) >=
      (await offloadQuotaBytes(tx, candidate.userId))
    )
      return null;
    const [bumped] = await tx.$queryRaw<{ offloadSeq: number }[]>`UPDATE sandbox_instance
      SET "offloadSeq" = "offloadSeq" + 1 WHERE id = ${candidate.sandboxId}
      RETURNING "offloadSeq"`;
    requireRelayFence(bumped != null);
    const offload = await tx.sandboxDiskOffload.create({
      data: {
        sandboxId: candidate.sandboxId,
        userId: candidate.userId,
        seq: bumped.offloadSeq,
        sourceGeneration: candidate.generation,
        sourceHostId: candidate.hostId,
        sourceHostOwnerId: candidate.hostOwnerId,
        liveSandboxId: candidate.sandboxId,
      },
      select: { id: true, seq: true },
    });
    return {
      offloadId: offload.id,
      sandboxId: candidate.sandboxId,
      seq: offload.seq,
      generation: candidate.generation,
      hostId: candidate.hostId,
      epoch: candidate.epoch,
    };
  }, null);
}

/** The request frame could not be delivered: the attempt ends FAILED(source_offline). */
export async function failUndeliveredOffload(enqueued: EnqueuedOffload): Promise<void> {
  await prisma.$transaction(async (tx: Prisma.TransactionClient) => {
    await lockSandboxRow(tx, enqueued.sandboxId);
    await failLiveOffload(tx, enqueued.offloadId, "source_offline");
  });
}
