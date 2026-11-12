import { randomBytes } from "node:crypto";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import type { RootObservationV11, ServerDiskMessage } from "@wssp/sandbox-contracts";
import { hostDatabaseNow, lockHostByEpoch, requireRelayFence } from "../relay-fence";
import { ACTIVE_OPERATION_STATES } from "../state-transitions";
import { canOffload } from "./availability";
import { clearEvictMarker, detachToOffloaded, rootProofMatches } from "./detach";
import {
  loginStateSettled,
  offloadablePurpose,
  offloadReceiptsSettled,
  RESTORE_SANDBOX_FACTS_SELECT,
  type RestoreSandboxFacts,
  restoreHostEligibility,
} from "./eligibility";

/**
 * Eviction of a cached copy.
 *
 * `grantEviction` answers a `disk.evict.request` under owner → host (by
 * epoch) → sandbox locks. It CASes every step-2 condition and, when they all
 * hold, marks the offload EVICTING with a grant (`evictGrantId`, the
 * granting host and epoch, +10 min) and answers `disk.evict.grant`; any
 * failed condition answers `disk.evict.refused` and leaves the copy cached.
 * While the marker is set, reconnect admission refuses `sandbox.disk_evicting`.
 *
 * `acceptEvicted` takes `disk.evicted` only for the matching
 * `(offloadId, evictGrantId, evictHostId)` (the epoch may differ after a
 * reconnect) with a root-absence proof of the sandbox's exact root: it
 * releases the root reservation once and detaches to OFFLOADED
 * (`detachToOffloaded`, the offload back to STORED, the marker cleared).
 *
 * "Expired grant without proof": the marker is cleared back to STORED only
 * once the host's census shows the VM present (or root absence, which
 * completes the eviction; `inventory-reconcile.ts`), or once the very
 * session that held the grant outlived it without a proof
 * (`clearOutlivedEvictGrants`; the copy is then unusable and its next start
 * discards it). It is never wedged.
 */

type Tx = Prisma.TransactionClient;

export { clearEvictMarker, rootProofMatches };

/** The sandbox row lock (as `store.ts::lockSandboxRow`; not imported from
 * there: the store's queue client is import-time IO for relay modules). */
async function lockSandboxRow(tx: Tx, sandboxId: string): Promise<boolean> {
  const rows = await tx.$queryRaw<
    { id: string }[]
  >`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} FOR UPDATE`;
  return rows.length === 1;
}

export type EvictSender = {
  userId: string;
  hostId: string;
  connectionEpoch: number;
  isCurrent?: () => boolean;
};

export type EvictRef = { sandboxId: string; offloadId: string; seq: number };

/** How long a grant lets the daemon delete the VM. */
export const EVICT_GRANT_TTL_MS = 10 * 60_000;
/** A grant whose own session outlived its expiry by this much without a
 * proof was refused or failed by the daemon. */
export const EVICT_GRANT_OUTLIVED_MS = 2 * 60_000;
/** Bounded candidate reads for the restore-host check. */
const RESTORE_HOST_CANDIDATES = 64;

export type EvictRefusal =
  | "stale"
  | "managed"
  | "offload_disabled"
  | "operation_in_flight"
  | "receipt_unretired"
  | "capture_busy"
  | "login_unsettled"
  | "no_restore_host";

/**
 * R8: whether at least one host may take a restore of `sandbox`: its
 * owner's own hosts, then the members of its origin pool, through THE
 * predicate (`restoreHostEligibility`). Bounded reads; never writes.
 */
export async function anyRestoreHost(
  tx: Tx,
  sandbox: RestoreSandboxFacts & { originPoolId: string | null },
  now?: Date,
): Promise<boolean> {
  const own = await tx.sandboxHost.findMany({
    where: { userId: sandbox.userId, status: "CONNECTED" },
    select: { id: true },
    orderBy: { id: "asc" },
    take: RESTORE_HOST_CANDIDATES,
  });
  for (const host of own)
    if ((await restoreHostEligibility(tx, sandbox, { hostId: host.id }, null, now)).ok) return true;
  if (!sandbox.originPoolId) return false;
  const members = await tx.sandboxPoolMember.findMany({
    where: { poolId: sandbox.originPoolId, enabled: true, removedAt: null },
    select: { sandboxHostId: true },
    orderBy: { id: "asc" },
    take: RESTORE_HOST_CANDIDATES,
  });
  for (const member of members)
    if (
      (
        await restoreHostEligibility(
          tx,
          sandbox,
          { hostId: member.sandboxHostId, poolId: sandbox.originPoolId },
          null,
          now,
        )
      ).ok
    )
      return true;
  return false;
}

/** Owner(s) → host by epoch → sandbox: the eviction lock order. */
async function lockEviction(tx: Tx, sender: EvictSender, sandboxId: string) {
  const head = await tx.sandbox.findFirst({
    where: { id: sandboxId },
    select: { userId: true },
  });
  for (const id of [...new Set([head?.userId ?? sender.userId, sender.userId])].sort())
    await lockOwnerForAdmission(tx, id);
  await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
  requireRelayFence(sender.isCurrent?.() !== false);
  requireRelayFence(await lockSandboxRow(tx, sandboxId));
  return head?.userId ?? null;
}

const evictSandboxSelect = {
  ...RESTORE_SANDBOX_FACTS_SELECT,
  generation: true,
  originPoolId: true,
} satisfies Prisma.SandboxSelect;

/** The step-2 CAS (§7) for `ref` on the sender's host: a refusal, or the sandbox. */
async function evictRefusal(
  tx: Tx,
  sender: EvictSender,
  ref: EvictRef,
  now: Date,
): Promise<EvictRefusal | { sandbox: { generation: number } }> {
  const sandbox = await tx.sandbox.findFirst({
    where: {
      id: ref.sandboxId,
      state: "STOPPED",
      sandboxHostId: sender.hostId,
      hostOwnerId: sender.userId,
      diskOffloadId: ref.offloadId,
      cachedOffloadSeq: ref.seq,
    },
    select: evictSandboxSelect,
  });
  if (!sandbox) return "stale";
  const [offload] = await tx.$queryRaw<
    { state: string; seq: number }[]
  >`SELECT state::text AS state,
    seq FROM sandbox_disk_offload WHERE id = ${ref.offloadId} AND "sandboxId" = ${ref.sandboxId}
    FOR UPDATE`;
  if (offload?.state !== "STORED" || offload.seq !== ref.seq) return "stale";
  // Managed purposes are never evicted (a policy-table action, R15.1).
  if (!offloadablePurpose(sandbox.purpose)) return "managed";
  const host = await tx.sandboxHost.findUnique({
    where: { id: sender.hostId },
    select: { daemonDiskOffload: true },
  });
  // `off` stops evictions as well as new offloads (I9).
  if (!canOffload(host?.daemonDiskOffload === true)) return "offload_disabled";
  const inFlight = await tx.sandboxOperation.count({
    where: {
      sandboxId: sandbox.id,
      userId: sandbox.userId,
      state: { in: [...ACTIVE_OPERATION_STATES] },
    },
  });
  if (inFlight > 0) return "operation_in_flight";
  if (!(await offloadReceiptsSettled(tx, sandbox.id, sandbox.generation)))
    return "receipt_unretired";
  const capture = await tx.$queryRaw<{ id: string }[]>`SELECT "operationId" AS id
    FROM sandbox_template_capture WHERE "sandboxId" = ${sandbox.id}
      AND state::text IN ('PENDING', 'CAPTURED', 'STORING') LIMIT 1`;
  if (capture.length > 0) return "capture_busy";
  if (!(await loginStateSettled(tx, sandbox.id))) return "login_unsettled";
  if (!(await anyRestoreHost(tx, sandbox, now))) return "no_restore_host";
  return { sandbox };
}

function refusedFrame(ref: EvictRef, code: string): ServerDiskMessage {
  return {
    type: "disk.evict.refused",
    sandboxId: ref.sandboxId,
    offloadId: ref.offloadId,
    seq: ref.seq,
    code,
  };
}

/**
 * `disk.evict.request` (§7 steps 2–3). The answer frame: a grant after the
 * EVICTING marker is written, or a refusal with its code.
 */
export async function grantEviction(
  tx: Tx,
  sender: EvictSender,
  ref: EvictRef,
): Promise<ServerDiskMessage> {
  await lockEviction(tx, sender, ref.sandboxId);
  const now = await hostDatabaseNow(tx);
  const verdict = await evictRefusal(tx, sender, ref, now);
  if (typeof verdict === "string") return refusedFrame(ref, verdict);
  const grantId = `evg_${randomBytes(16).toString("hex")}`;
  const expiresAt = new Date(now.getTime() + EVICT_GRANT_TTL_MS);
  const marked = await tx.sandboxDiskOffload.updateMany({
    where: { id: ref.offloadId, sandboxId: ref.sandboxId, state: "STORED", evictGrantId: null },
    data: {
      state: "EVICTING",
      evictGrantId: grantId,
      evictHostId: sender.hostId,
      evictGrantEpoch: sender.connectionEpoch,
      evictGrantedAt: now,
      evictGrantExpiresAt: expiresAt,
    },
  });
  if (marked.count !== 1) return refusedFrame(ref, "stale");
  return {
    type: "disk.evict.grant",
    sandboxId: ref.sandboxId,
    offloadId: ref.offloadId,
    seq: ref.seq,
    grantId,
    expiresAtUnixMs: expiresAt.getTime(),
  };
}

export type EvictedOutcome = "ack" | "refused";

/**
 * `disk.evicted` (§7 step 6). `ack`: the sandbox is (now, or already was,
 * through this offload) OFFLOADED; the daemon drops its journal entry.
 */
export async function acceptEvicted(
  tx: Tx,
  sender: EvictSender,
  m: {
    sandboxId: string;
    offloadId: string;
    grantId: string;
    rootAbsenceProof: RootObservationV11;
  },
): Promise<EvictedOutcome> {
  await lockEviction(tx, sender, m.sandboxId);
  const [offload] = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM sandbox_disk_offload
    WHERE id = ${m.offloadId} AND "sandboxId" = ${m.sandboxId} AND state::text = 'EVICTING'
      AND "evictGrantId" = ${m.grantId} AND "evictHostId" = ${sender.hostId} FOR UPDATE`;
  if (!offload) {
    // A repeated report of an eviction already complete is acked again.
    // credential-settlement: exempt — a read of a detach already settled.
    const done = await tx.sandbox.count({
      where: { id: m.sandboxId, state: "OFFLOADED", diskOffloadId: m.offloadId },
    });
    return done === 1 ? "ack" : "refused";
  }
  const sandbox = await tx.sandbox.findFirst({
    where: {
      id: m.sandboxId,
      state: "STOPPED",
      sandboxHostId: sender.hostId,
      diskOffloadId: m.offloadId,
    },
    select: {
      userId: true,
      generation: true,
      storageMarker: true,
      storagePoolName: true,
      diskGiB: true,
    },
  });
  if (!sandbox || !rootProofMatches(m.rootAbsenceProof, sandbox)) return "refused";
  const detached = await detachToOffloaded(tx, {
    sandboxId: m.sandboxId,
    userId: sandbox.userId,
    hostId: sender.hostId,
    generation: sandbox.generation,
    proof: { kind: "root_absent" },
  });
  return detached ? "ack" : "refused";
}

/**
 * Tick: an expired grant whose granting session is still the host's
 * current one (same epoch, connected) and outlived its expiry by
 * `EVICT_GRANT_OUTLIVED_MS` without a proof was refused or failed by the
 * daemon (it never acts within 60 s of expiry, S11): the marker is cleared.
 * A host that reconnected or went away is left to its census.
 */
export async function clearOutlivedEvictGrants(now: Date): Promise<number> {
  const rows = await prisma.$queryRaw<{ id: string; sandboxId: string }[]>`
    SELECT o.id, o."sandboxId" FROM sandbox_disk_offload o
    JOIN sandbox_host h ON h.id = o."evictHostId"
    WHERE o.state::text = 'EVICTING'
      AND o."evictGrantExpiresAt" < ${new Date(now.getTime() - EVICT_GRANT_OUTLIVED_MS)}
      AND h.status::text = 'CONNECTED' AND h."connectionEpoch" = o."evictGrantEpoch"
    ORDER BY o.id LIMIT 50`;
  let cleared = 0;
  for (const row of rows) {
    const done = await prisma.$transaction(async (tx) => {
      await lockSandboxRow(tx, row.sandboxId);
      const [still] = await tx.$queryRaw<{ ok: boolean }[]>`SELECT (o.state::text = 'EVICTING'
          AND o."evictGrantExpiresAt" < ${new Date(now.getTime() - EVICT_GRANT_OUTLIVED_MS)}
          AND h.status::text = 'CONNECTED' AND h."connectionEpoch" = o."evictGrantEpoch") AS ok
        FROM sandbox_disk_offload o JOIN sandbox_host h ON h.id = o."evictHostId"
        WHERE o.id = ${row.id}`;
      if (still?.ok !== true || !(await clearEvictMarker(tx, row.id))) return false;
      // The daemon refused the grant (its journal does not hold this copy as
      // stored at that seq): the copy is unusable, so the next start routes
      // it to the discard and restores (`detachStaleCachedCopy`) instead of
      // asking for another grant it would refuse again.
      await tx.sandbox.updateMany({
        where: { id: row.sandboxId, state: "STOPPED", diskOffloadId: row.id },
        data: { cachedOffloadSeq: null },
      });
      return true;
    });
    if (done) cleared++;
  }
  return cleared;
}

/**
 * Placement disk-miss → `disk.evict.suggest` (§10 C5): hosts of pools whose
 * waiting creates are blocked on disk, storage or the root ceiling, plus
 * hosts draining with `--offload` (§10 C7), and each such host's least
 * recently stopped cached copy (one per host). The daemon then asks
 * (`disk.evict.request`) and the CAS decides: an eviction is still refused
 * without an eligible restore host (R8), so the copy then stays cached.
 */
export async function evictSuggestions(): Promise<
  { hostId: string; epoch: number; frame: ServerDiskMessage }[]
> {
  const rows = await prisma.$queryRaw<
    { hostId: string; epoch: number; sandboxId: string; offloadId: string; seq: number }[]
  >`
    SELECT DISTINCT ON (s."sandboxHostId") s."sandboxHostId" AS "hostId",
      h."connectionEpoch" AS epoch, s.id AS "sandboxId", o.id AS "offloadId", o.seq
    FROM sandbox_instance s
    JOIN sandbox_disk_offload o ON o.id = s."diskOffloadId" AND o.state::text = 'STORED'
    JOIN sandbox_host h ON h.id = s."sandboxHostId" AND h.status::text = 'CONNECTED'
      AND h."daemonDiskOffload"
    WHERE s.state::text = 'STOPPED' AND s."cachedOffloadSeq" = o.seq
      AND ((h.draining AND h."drainOffload") OR s."sandboxHostId" IN (
        SELECT m."sandboxHostId" FROM sandbox_pool_member m
        JOIN sandbox_capacity_wait w ON w."poolId" = m."poolId"
        WHERE m.enabled AND m."removedAt" IS NULL
          AND w."lastBlocker" IN ('disk', 'storage', 'ceiling')))
    ORDER BY s."sandboxHostId", s."lastStoppedAt" ASC NULLS FIRST, s.id
    LIMIT 20`;
  return rows.map((row) => ({
    hostId: row.hostId,
    epoch: row.epoch,
    frame: {
      type: "disk.evict.suggest",
      sandboxId: row.sandboxId,
      offloadId: row.offloadId,
      seq: row.seq,
    },
  }));
}

/** Server-issued grants (§5 order 3) carry this prefix: the scheduler
 * delivers them, while a daemon-requested grant is answered in its session. */
export const SERVER_EVICT_GRANT_PREFIX = "evs_";

/**
 * §5 order 3: a start found the cached host online but not eligible to take
 * its copy back. In its own transaction, under the eviction lock order and
 * the same CAS as a daemon request (`evictRefusal`: no work in flight,
 * receipts settled, no capture, logins settled, at least one eligible
 * restore host), write the EVICTING marker with a server-issued grant at
 * the host's current epoch. The scheduler sends the grant
 * (`serverEvictGrantFrames`); the start meanwhile answers
 * `sandbox.disk_evicting`. False (nothing written) on any refusal: the copy
 * then stays cached.
 */
export async function grantServerEviction(sandboxId: string): Promise<boolean> {
  return prisma.$transaction(async (tx) => {
    const sandbox = await tx.sandbox.findFirst({
      where: { id: sandboxId, state: "STOPPED", diskOffloadId: { not: null } },
      select: {
        sandboxHostId: true,
        hostOwnerId: true,
        diskOffloadId: true,
        cachedOffloadSeq: true,
      },
    });
    if (
      !sandbox?.sandboxHostId ||
      !sandbox.hostOwnerId ||
      !sandbox.diskOffloadId ||
      sandbox.cachedOffloadSeq === null
    )
      return false;
    const host = await tx.sandboxHost.findUnique({
      where: { id: sandbox.sandboxHostId },
      select: { connectionEpoch: true, status: true },
    });
    if (host?.status !== "CONNECTED") return false;
    const sender: EvictSender = {
      hostId: sandbox.sandboxHostId,
      connectionEpoch: host.connectionEpoch,
      userId: sandbox.hostOwnerId,
    };
    const ref = { sandboxId, offloadId: sandbox.diskOffloadId, seq: sandbox.cachedOffloadSeq };
    await lockEviction(tx, sender, sandboxId);
    const now = await hostDatabaseNow(tx);
    const verdict = await evictRefusal(tx, sender, ref, now);
    if (typeof verdict === "string") return false;
    const marked = await tx.sandboxDiskOffload.updateMany({
      where: { id: ref.offloadId, sandboxId, state: "STORED", evictGrantId: null },
      data: {
        state: "EVICTING",
        evictGrantId: `${SERVER_EVICT_GRANT_PREFIX}${randomBytes(16).toString("hex")}`,
        evictHostId: sender.hostId,
        evictGrantEpoch: sender.connectionEpoch,
        evictGrantedAt: now,
        evictGrantExpiresAt: new Date(now.getTime() + EVICT_GRANT_TTL_MS),
      },
    });
    return marked.count === 1;
  });
}

/** Unexpired server-issued grants whose host is connected at the grant's
 * epoch, as `disk.evict.grant` frames (bounded; the scheduler sends each
 * grant id once per process). */
export async function serverEvictGrantFrames(
  now: Date,
): Promise<{ hostId: string; epoch: number; grantId: string; frame: ServerDiskMessage }[]> {
  const rows = await prisma.$queryRaw<
    {
      hostId: string;
      epoch: number;
      sandboxId: string;
      offloadId: string;
      seq: number;
      grantId: string;
      expiresAt: Date;
    }[]
  >`SELECT o."evictHostId" AS "hostId", o."evictGrantEpoch" AS epoch, o."sandboxId",
      o.id AS "offloadId", o.seq, o."evictGrantId" AS "grantId", o."evictGrantExpiresAt" AS "expiresAt"
    FROM sandbox_disk_offload o JOIN sandbox_host h ON h.id = o."evictHostId"
    WHERE o.state::text = 'EVICTING' AND starts_with(o."evictGrantId", ${SERVER_EVICT_GRANT_PREFIX})
      AND o."evictGrantExpiresAt" > ${now}
      AND h.status::text = 'CONNECTED' AND h."connectionEpoch" = o."evictGrantEpoch"
    ORDER BY o.id LIMIT 50`;
  return rows.map((row) => ({
    hostId: row.hostId,
    epoch: row.epoch,
    grantId: row.grantId,
    frame: {
      type: "disk.evict.grant",
      sandboxId: row.sandboxId,
      offloadId: row.offloadId,
      seq: row.seq,
      grantId: row.grantId,
      expiresAtUnixMs: row.expiresAt.getTime(),
    },
  }));
}
