import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { authorityTicket } from "@wssp/db/authority";
import { settleTerminalTeardown } from "../credentials/teardown";
import {
  isOwnerCredentialPolicySatisfied,
  ownerCredentialPolicyUserSelect,
} from "../lib/owner-credential-policy";
import { getForcedTwoFactorSettingsRecord } from "../lib/two-factor-policy";
import { notifyCapacityChanged } from "./capacity-queue-wake";
import {
  commitLockedSandboxLeaseExpiry,
  type LeaseClock,
  leaseNow,
  leaseTransactionNow,
} from "./lease";
import { pullInLeaseLocked } from "./lease-pull-in";
import { outboxOperationWhere } from "./outbox-operation";
import {
  lockPoolGraph,
  MAX_ACTIVE_POOL_MEMBERSHIPS,
  MAX_POOL_GRAPH_PATHS,
  poolGraphOverflow,
} from "./pool-locks";
import { lockCurrentHostEpoch, relayTransaction, requireRelayFence } from "./relay-fence";
import { SandboxIntegrityError } from "./sensitive-errors";
import {
  memberQuotaFailure,
  memberUsage,
  type ResourceCharge,
  shareQuotaFailure,
  shareUsage,
} from "./sharing-quota";

/** A hint never grants authority. The periodic scanner covers SQL writers and lost hints. */
let accessWake: ((poolId?: string) => void) | null = null;
type AccessNotice = {
  creatorId: string;
  sandboxId: string;
  kind: "loss" | "restore";
  deadline: Date;
};
const committedNotices = new WeakMap<object, AccessNotice>();

/** Called only with an outcome returned by a committed sandbox transaction. */
async function deliverAccessNotice(notice: AccessNotice) {
  try {
    const user = await prisma.user.findUnique({
      where: { id: notice.creatorId },
      select: { email: true, locale: true },
    });
    if (!user) return;
    const { renderPoolAccessNotice, sendEmail } = await import("@wssp/mailer");
    await sendEmail({
      to: user.email,
      ...renderPoolAccessNotice({ ...notice, locale: user.locale }),
    });
  } catch {
    // The access transition is committed. SMTP uncertainty must not undo it or
    // claim delivery, and diagnostics must never include addresses or bodies.
    console.error("[sharing-access] notice delivery unconfirmed");
  }
}
export function bindSharingAccessWake(wake: typeof accessWake) {
  accessWake = wake;
}
export function notifySharingAccessChanged(poolId?: string) {
  try {
    accessWake?.(poolId);
  } catch {
    /* Durable discovery will retry. */
  }
  // Every access/policy hint (pool, membership, share, drain, hello, lease
  // ceiling) can also place, or end, a waiting create.
  notifyCapacityChanged(poolId ? { poolIds: [poolId] } : "all");
}

/** Discover BEFORE User/G/H. Keep the old (possibly deleted) attribution in G. */
export async function discoverHostPaths(
  tx: Prisma.TransactionClient,
  hostId: string | null,
  oldPoolId: string | null,
) {
  const ids = new Set<string>(oldPoolId ? [oldPoolId] : []);
  let cursor = "";
  let activeCount = 0;
  if (hostId)
    for (;;) {
      const rows = await tx.sandboxPoolMember.findMany({
        where: { sandboxHostId: hostId, removedAt: null, poolId: { gt: cursor } },
        select: { poolId: true },
        orderBy: { poolId: "asc" },
        take: 100,
      });
      for (const row of rows) ids.add(row.poolId);
      activeCount += rows.length;
      if (activeCount > MAX_ACTIVE_POOL_MEMBERSHIPS) throw poolGraphOverflow();
      if (rows.length < 100) break;
      cursor = rows[rows.length - 1]!.poolId;
    }
  const pools = await tx.sandboxPool.findMany({
    where: { id: { in: [...ids] } },
    select: { id: true, userId: true },
    take: MAX_POOL_GRAPH_PATHS,
    orderBy: { id: "asc" },
  });
  return { ids: [...ids].sort(), owners: [...new Set(pools.map((p) => p.userId))].sort() };
}
function samePaths(
  a: Awaited<ReturnType<typeof discoverHostPaths>>,
  b: Awaited<ReturnType<typeof discoverHostPaths>>,
) {
  return JSON.stringify(a) === JSON.stringify(b);
}
const policySelect = ownerCredentialPolicyUserSelect;
function policyAllows(
  user: Prisma.UserGetPayload<{ select: typeof policySelect }> | null,
  now: Date,
) {
  return (
    user != null &&
    user.deletionRequestedAt == null &&
    !(user.banned && (!user.banExpires || user.banExpires > now))
  );
}

/** Internal predicate shared by retained IO and the locked scanner. enabled only gates new holds. */
export async function currentHostUsability(
  tx: Prisma.TransactionClient,
  creatorId: string,
  sandboxId: string,
  onActiveAuthority?: (current: () => boolean) => void,
) {
  const row = await tx.sandbox.findFirst({
    where: { id: sandboxId, userId: creatorId },
    select: {
      sandboxHostId: true,
      hostOwnerId: true,
      usagePoolId: true,
      usageMemberId: true,
      accessGraceUntil: true,
      SandboxHost: {
        select: { userId: true, deletionRequestedAt: true, User: { select: policySelect } },
      },
      CurrentPlacement: { select: { hostOwnerId: true, originHostId: true } },
    },
  });
  if (
    !row?.SandboxHost ||
    row.accessGraceUntil != null ||
    !row.CurrentPlacement ||
    row.hostOwnerId !== row.SandboxHost.userId ||
    row.CurrentPlacement.hostOwnerId !== row.hostOwnerId ||
    row.CurrentPlacement.originHostId !== row.sandboxHostId ||
    row.SandboxHost.deletionRequestedAt != null
  )
    return false;
  const current = authorityTicket({ ownerId: row.hostOwnerId!, hostId: row.sandboxHostId! });
  // Re-read after sampling transport authority; a credential/policy change cannot
  // slip between a stale joined row and a fresh ticket.
  const host = await tx.sandboxHost.findFirst({
    where: { id: row.sandboxHostId!, userId: row.hostOwnerId!, deletionRequestedAt: null },
    select: { User: { select: policySelect } },
  });
  const [clock] = await tx.$queryRaw<
    { now: Date }[]
  >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
  const settings = await getForcedTwoFactorSettingsRecord(tx);
  if (!host || !(await isOwnerCredentialPolicySatisfied(host.User, clock!.now, settings)))
    return false;
  if (row.hostOwnerId === creatorId) {
    if (!current()) return false;
    onActiveAuthority?.(current);
    return true;
  }
  if (!row.usagePoolId || !row.usageMemberId) return false;
  const pool = await tx.sandboxPool.findUnique({
    where: { id: row.usagePoolId },
    select: { userId: true },
  });
  if (!pool) return false;
  const poolCurrent = authorityTicket({ ownerId: pool.userId });
  const paths = await usablePaths(tx, creatorId, row.sandboxHostId!, [row.usagePoolId], clock!.now);
  const path = paths.find((p) => p.id === row.usageMemberId);
  const allowed =
    path != null &&
    (await isOwnerCredentialPolicySatisfied(path.Pool.User, clock!.now, settings)) &&
    current() &&
    poolCurrent();
  if (allowed) onActiveAuthority?.(() => current() && poolCurrent());
  return allowed;
}
export async function requireCurrentHostUsability(
  tx: Prisma.TransactionClient,
  creatorId: string,
  sandboxId: string,
) {
  let current = () => false;
  if (
    !(await currentHostUsability(tx, creatorId, sandboxId, (ticket) => {
      current = ticket;
    }))
  )
    throw new ORPCError("FORBIDDEN", { message: "Sandbox access is unavailable." });
  return current;
}

async function usablePaths(
  tx: Prisma.TransactionClient,
  creatorId: string,
  hostId: string,
  ids: string[],
  now: Date,
  ignoreBans = false,
) {
  const members = await tx.sandboxPoolMember.findMany({
    where: {
      sandboxHostId: hostId,
      removedAt: null,
      poolId: { in: ids },
      Pool: { deletedAt: null },
    },
    select: {
      id: true,
      poolId: true,
      userId: true,
      hostOwnerId: true,
      memoryCapPercent: true,
      vcpuCapPercent: true,
      Pool: {
        select: {
          ownHostsOnly: true,
          userId: true,
          User: { select: policySelect },
          Shares: {
            where: { granteeUserId: { in: [creatorId] } },
            select: {
              granteeUserId: true,
              canUse: true,
              maxMemoryMiB: true,
              maxVcpu: true,
              maxDiskGiB: true,
            },
            take: 1,
          },
        },
      },
      Share: { select: { canContribute: true, granteeUserId: true } },
    },
    take: MAX_ACTIVE_POOL_MEMBERSHIPS + 1,
    orderBy: { poolId: "asc" },
  });
  if (members.length > MAX_ACTIVE_POOL_MEMBERSHIPS) throw poolGraphOverflow();
  return members.filter((m) => {
    const share = m.Pool.Shares[0];
    return (
      (ignoreBans || policyAllows(m.Pool.User, now)) &&
      (m.userId === creatorId || share?.canUse) &&
      (m.hostOwnerId === m.userId ||
        (!m.Pool.ownHostsOnly && m.Share?.canContribute && m.Share.granteeUserId === m.hostOwnerId))
    );
  });
}

/** One suspect row, User → sorted G → one H → S. No IO or unbounded fanout under locks. */
export async function reconcileSandboxAccess(
  tx: Prisma.TransactionClient,
  sandboxId: string,
  clock: LeaseClock = leaseNow,
) {
  const discovered = await tx.sandbox.findUnique({
    where: { id: sandboxId },
    select: { userId: true, sandboxHostId: true, hostOwnerId: true, usagePoolId: true },
  });
  if (!discovered) return false;
  const paths = await discoverHostPaths(tx, discovered.sandboxHostId, discovered.usagePoolId);
  const users = [
    ...new Set([
      discovered.userId,
      ...(discovered.hostOwnerId ? [discovered.hostOwnerId] : []),
      ...paths.owners,
    ]),
  ].sort();
  // Cleanup must run even for a banned/deleting principal. These locks serialize deletion, not admission.
  await tx.$queryRaw`SELECT id FROM "user" WHERE id = ANY(${users}::text[]) ORDER BY id FOR SHARE`;
  await lockPoolGraph(tx, paths.ids);
  if (discovered.sandboxHostId) {
    const host = await lockCurrentHostEpoch(tx, discovered.sandboxHostId);
    requireRelayFence(host.userId === discovered.hostOwnerId);
  }
  await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} AND "userId" = ${discovered.userId} FOR UPDATE`;
  const s = await tx.sandbox.findUniqueOrThrow({
    where: { id: sandboxId },
    include: { CurrentPlacement: true },
  });
  requireRelayFence(
    s.sandboxHostId === discovered.sandboxHostId &&
      s.hostOwnerId === discovered.hostOwnerId &&
      s.usagePoolId === discovered.usagePoolId,
  );
  requireRelayFence(samePaths(paths, await discoverHostPaths(tx, s.sandboxHostId, s.usagePoolId)));
  // An OFFLOADED sandbox holds no host, pool usage or grace: nothing to
  // reconcile; its restore re-authorizes placement.
  if (s.state === "DELETED" || s.state === "OFFLOADED") return false;
  const now = await leaseTransactionNow(tx, clock);
  const host = s.sandboxHostId
    ? await tx.sandboxHost.findUnique({
        where: { id: s.sandboxHostId },
        select: {
          id: true,
          userId: true,
          deletionRequestedAt: true,
          daemonMemoryBudgetMiB: true,
          daemonVcpuBudget: true,
          User: { select: policySelect },
        } satisfies Prisma.SandboxHostSelect,
      })
    : null;
  if (host)
    requireRelayFence(
      s.hostOwnerId === host.userId &&
        s.CurrentPlacement?.hostOwnerId === host.userId &&
        s.CurrentPlacement.originHostId === host.id,
    );
  // Review #2: a banned (or deleting) owner's sandboxes on their OWN host are
  // stopped, finite or unlimited alike: the disk is kept and no deletion grace
  // starts (a ban never starts deletion), so unbanning lets the owner start
  // them again. Host deletion is handled below like any other access loss
  // (stop → grace → destroy).
  if (
    host?.userId === s.userId &&
    host.deletionRequestedAt == null &&
    !policyAllows(host.User, now)
  ) {
    if (await provisioningInFlight(tx, s)) return false;
    return commitLockedSandboxLeaseExpiry(
      tx,
      { ...s, accessGraceUntil: null },
      now,
      false,
      "access",
    );
  }
  const hostAllowed =
    host != null && host.deletionRequestedAt == null && policyAllows(host.User, now);
  const candidates = host ? await usablePaths(tx, s.userId, host.id, paths.ids, now) : [];
  let destination =
    hostAllowed && s.accessGraceUntil == null
      ? candidates.find((p) => p.poolId === s.usagePoolId && p.id === s.usageMemberId)
      : undefined;
  const owned = hostAllowed && host!.userId === s.userId;
  const fits = async (path: Awaited<ReturnType<typeof usablePaths>>[number]) => {
    const boot = s.CurrentPlacement;
    if (
      (s.liveResourcesHeld && (boot?.chargedMemoryMiB == null || boot.chargedVcpu == null)) ||
      (s.diskReservationHeld && s.rootChargeGiB == null)
    )
      throw new SandboxIntegrityError("sandbox_allocation_mismatch");
    const added: ResourceCharge = {
      memoryMiB: BigInt(s.liveResourcesHeld ? boot!.chargedMemoryMiB! : 0),
      vcpu: BigInt(s.liveResourcesHeld ? boot!.chargedVcpu! : 0),
      diskGiB: BigInt(s.diskReservationHeld ? s.rootChargeGiB! : 0),
    };
    const share = path.Pool.Shares[0];
    if (share && shareQuotaFailure(share, await shareUsage(tx, path.poolId, s.userId, s.id), added))
      return false;
    if (
      memberQuotaFailure(
        {
          ownerLocal: path.userId === host!.userId,
          memoryBudgetMiB: host!.daemonMemoryBudgetMiB ?? 0,
          vcpuBudget: host!.daemonVcpuBudget ?? 0,
          memoryCapPercent: path.memoryCapPercent,
          vcpuCapPercent: path.vcpuCapPercent,
        },
        await memberUsage(tx, path.poolId, host!.id, s.id),
        added,
      )
    )
      return false;
    return true;
  };
  if (!destination && !owned && hostAllowed) {
    for (const path of candidates)
      if (await fits(path)) {
        destination = path;
        break;
      }
  }
  if (owned || destination) {
    // An already sent/claimed automatic destroy must settle before restoration/restart.
    const pending = await tx.sandboxOperation.findFirst({
      where: {
        sandboxId: s.id,
        userId: s.userId,
        kind: "KILL_SANDBOX",
        idempotencyKey: { startsWith: "access-expire:" },
        state: { in: ["DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED", "UNKNOWN_OUTCOME"] },
      },
      select: { id: true },
    });
    if (pending) return false;
    const queued = await tx.sandboxOperation.findMany({
      where: {
        sandboxId: s.id,
        userId: s.userId,
        kind: "KILL_SANDBOX",
        idempotencyKey: { startsWith: "access-expire:" },
        state: "QUEUED",
        dispatchAttempt: 0,
      },
      select: { id: true },
      take: 250,
    });
    if (queued.length) {
      await tx.sandboxOperation.updateMany({
        where: { id: { in: queued.map((o) => o.id) }, state: "QUEUED", dispatchAttempt: 0 },
        data: { state: "CANCELLED", completedAt: now },
      });
      for (const op of queued)
        await tx.outboxEvent.updateMany({
          where: {
            userId: s.userId,
            aggregateType: "sandbox",
            aggregateId: s.id,
            sentAt: null,
            processedAt: null,
            ...outboxOperationWhere(op.id),
          },
          data: { processedAt: now, claimToken: null, claimedAt: null },
        });
      // Only a never-issued automatic destroy can be undone. Preserve stopped proof;
      // a live allocation remains in ERROR until reconciled rather than inventing READY.
      await tx.sandbox.updateMany({
        where: { id: s.id, state: "STOPPING", generation: s.generation },
        data: { state: s.liveResourcesHeld ? "ERROR" : "STOPPED" },
      });
      // CLI logins (§7.1 P3-5): the cancelled KILL ends without stop/destroy
      // proof and without a new generation; its RELEASING leases settle.
      for (const op of queued)
        await settleTerminalTeardown(tx, { id: op.id, sandboxId: s.id, dispatchAttempt: 0 });
    }
    await tx.sandbox.updateMany({
      where: { id: s.id, generation: s.generation, leaseRevision: s.leaseRevision },
      data: {
        usagePoolId: owned ? null : destination!.poolId,
        usageMemberId: owned ? null : destination!.id,
        accessGraceUntil: null,
        accessGraceReason: null,
      },
    });
    // S6: a foreign sandbox moved to another usage path takes that path's
    // lease limit now (User, G over every host path, H and S are held).
    // Own-host rows keep their origin path, which this never changes.
    if (
      !owned &&
      destination &&
      (destination.poolId !== s.usagePoolId || destination.id !== s.usageMemberId)
    )
      await pullInLeaseLocked(tx, { id: s.id, userId: s.userId }, now);
    if (s.accessGraceUntil)
      committedNotices.set(tx, {
        creatorId: s.userId,
        sandboxId: s.id,
        kind: "restore",
        deadline: s.accessGraceUntil,
      });
    if (queued.length && s.liveResourcesHeld) {
      // The cancelled generation cannot be rolled back. Obtain positive STOP proof
      // before a subsequent cold boot; never revive an older guest permit.
      return commitLockedSandboxLeaseExpiry(
        tx,
        { ...s, state: "ERROR", accessGraceUntil: null },
        now,
        false,
        "access",
      );
    }
    return false;
  }
  // Ban alone stops foreign use; the structural path survives and creates no deletion deadline.
  let structural = false;
  if (host && host.deletionRequestedAt == null) {
    const unbanned = await usablePaths(tx, s.userId, host.id, paths.ids, now, true);
    structural =
      host.userId === s.userId ||
      unbanned.some((p) => p.poolId === s.usagePoolId && p.id === s.usageMemberId);
    if (!structural)
      for (const path of unbanned)
        if (await fits(path)) {
          structural = true;
          break;
        }
  }
  if (!s.accessGraceUntil && !structural) {
    const old = s.usagePoolId
      ? await tx.sandboxPool.findUnique({
          where: { id: s.usagePoolId },
          select: { disconnectGraceSeconds: true },
        })
      : null;
    const seconds = Math.max(
      s.CurrentPlacement?.acceptedGraceSeconds ?? 259200,
      old?.disconnectGraceSeconds ?? 0,
    );
    const deadline = new Date(now.getTime() + seconds * 1000);
    const pin = await tx.sandbox.updateMany({
      where: {
        id: s.id,
        state: s.state,
        generation: s.generation,
        leaseRevision: s.leaseRevision,
        accessGraceUntil: null,
      },
      data: { accessGraceUntil: deadline, accessGraceReason: "access" },
    });
    requireRelayFence(pin.count === 1);
    s.accessGraceUntil = deadline;
    committedNotices.set(tx, {
      creatorId: s.userId,
      sandboxId: s.id,
      kind: "loss",
      deadline,
    });
  }
  if (await provisioningInFlight(tx, s)) return false;
  return commitLockedSandboxLeaseExpiry(tx, s, now, false, "access");
}

/** An issued create/reconnect of this generation must settle before access cleanup. */
async function provisioningInFlight(
  tx: Prisma.TransactionClient,
  s: { id: string; userId: string; generation: number },
) {
  return (
    (await tx.sandboxOperation.findFirst({
      where: {
        sandboxId: s.id,
        userId: s.userId,
        generation: s.generation,
        kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },
        dispatchAttempt: { gt: 0 },
        state: { in: ["DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED", "UNKNOWN_OUTCOME"] },
      },
      select: { id: true },
    })) != null
  );
}

/** Lock-free filter BEFORE LIMIT. Valid retained attribution can remain over cap. */
export async function scanSandboxAccess(
  clock: LeaseClock = leaseNow,
  shouldStop: () => boolean = () => false,
  pools?: ReadonlySet<string>,
): Promise<number> {
  let cursor = "",
    queued = 0;
  while (!shouldStop()) {
    const rows = await prisma.$queryRaw<{ id: string }[]>`
      SELECT s.id FROM sandbox_instance s LEFT JOIN sandbox_host h ON h.id = s."sandboxHostId" AND h."userId" = s."hostOwnerId"
      LEFT JOIN "user" hu ON hu.id = h."userId"
      LEFT JOIN sandbox_placement boot ON boot.id = s."currentPlacementId" AND boot."sandboxId" = s.id AND boot."userId" = s."userId"
      WHERE (${pools === undefined} OR s."usagePoolId" = ANY(${[...(pools ?? [])]}::text[]) OR EXISTS (
        SELECT 1 FROM sandbox_pool_member hinted WHERE hinted."sandboxHostId" = s."sandboxHostId" AND hinted."poolId" = ANY(${[...(pools ?? [])]}::text[])))
      AND s.id > ${cursor} AND s.state <> 'DELETED'
      -- A waiting create holds no host or disk; the capacity queue owns its
      -- access loss (it fails the wait). Never rely on NULL logic here.
      AND s.state <> 'WAITING_FOR_CAPACITY'
      -- An offloaded sandbox holds no host, pool usage or grace either; its
      -- restore re-authorizes placement.
      AND s.state <> 'OFFLOADED'
      AND (s."hostOwnerId" <> s."userId" OR s."usagePoolId" IS NOT NULL OR s."accessGraceUntil" IS NOT NULL
        -- Review #2: own-host rows (usage cleared) still end on host deletion,
        -- and still stop while their owner is banned or deleting.
        OR h."deletionRequestedAt" IS NOT NULL
        OR (s.state NOT IN ('STOPPED', 'STOPPING', 'RECLAIMING', 'HOST_LOST')
          AND (hu."deletionRequestedAt" IS NOT NULL
            OR (hu.banned AND (hu."banExpires" IS NULL OR hu."banExpires" > (clock_timestamp() AT TIME ZONE 'UTC'))))))
      AND (s."accessGraceUntil" IS NOT NULL OR (h."userId" = s."userId" AND s."usagePoolId" IS NOT NULL)
        OR boot."hostOwnerId" IS DISTINCT FROM s."hostOwnerId" OR boot."originHostId" IS DISTINCT FROM s."sandboxHostId"
        OR h.id IS NULL OR h."deletionRequestedAt" IS NOT NULL OR hu."deletionRequestedAt" IS NOT NULL
        OR (hu.banned AND (hu."banExpires" IS NULL OR hu."banExpires" > (clock_timestamp() AT TIME ZONE 'UTC')))
        OR NOT EXISTS (
          SELECT 1 FROM sandbox_pool_member m JOIN sandbox_pool p ON p.id = m."poolId" JOIN "user" pu ON pu.id = p."userId"
          LEFT JOIN share u ON u."poolId" = p.id AND u."granteeUserId" = s."userId" AND u."canUse"
          LEFT JOIN share c ON c.id = m."shareId" AND c."canContribute"
          WHERE m.id = s."usageMemberId" AND p.id = s."usagePoolId" AND m."sandboxHostId" = s."sandboxHostId"
            AND m."hostOwnerId" = s."hostOwnerId" AND m."removedAt" IS NULL AND p."deletedAt" IS NULL
            AND pu."deletionRequestedAt" IS NULL AND (NOT COALESCE(pu.banned, false) OR pu."banExpires" <= (clock_timestamp() AT TIME ZONE 'UTC'))
            AND (p."userId" = s."userId" OR u.id IS NOT NULL)
            AND (m."hostOwnerId" = p."userId" OR (NOT p."ownHostsOnly" AND c."granteeUserId" = m."hostOwnerId"))
        )) ORDER BY s.id LIMIT 32`;
    for (const row of rows) {
      if (shouldStop()) return queued;
      try {
        const outcome = await relayTransaction<{
          queued: boolean;
          notice: AccessNotice | undefined;
        } | null>(async (tx) => {
          const queued = await reconcileSandboxAccess(tx, row.id, clock);
          return { queued, notice: committedNotices.get(tx) };
        }, null);
        if (outcome?.queued) queued++;
        if (outcome?.notice) await deliverAccessNotice(outcome.notice);
      } catch (error) {
        if (
          !(error instanceof SandboxIntegrityError) &&
          !(error instanceof ORPCError && error.code === "CONFLICT")
        )
          console.error("[sharing-access] row deferred; periodic retry pending");
      }
      cursor = row.id;
    }
    if (rows.length < 32) return queued;
  }
  return queued;
}
