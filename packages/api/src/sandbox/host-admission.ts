import prisma, {
  type OperationState,
  type Prisma,
  type SandboxOperationKind,
  type SandboxState,
} from "@wssp/db";
import {
  type AuthorityChangeHold,
  holdAuthorityChange,
  withAuthorityChange,
} from "@wssp/db/authority";
import {
  hostInventoryUpdateV11Schema,
  hostStaticCapacityV11Schema,
  VM_SIZE_LIMITS,
  type VmSize,
  vmLiveMemoryChargeMiB,
} from "@wssp/sandbox-contracts";
import { noteCapacityChanged } from "./capacity-queue-wake";
import {
  hostCapacityConflict,
  hostDeleteConflict,
  hostDrainingConflict,
  hostUnavailable,
  vmSizeUnsupported,
} from "./errors";
import {
  hostDatabaseNow,
  lockCurrentHostEpoch,
  lockHostByEpoch,
  RelayFenceRejected,
  requireRelayFence,
  transactionHoldsHostLock,
} from "./relay-fence";
import { requireSandboxIntegrity, SandboxIntegrityError } from "./sensitive-errors";
import { ACTIVE_OPERATION_STATES, type LifecycleOperationKind } from "./state-transitions";

/** H MUST already be held by a separate lockHostByEpoch statement in READ
 * COMMITTED. An UPDATE that first waits for H would aggregate a stale snapshot.
 * Only startup/admission initialize; ordinary writers never repair the ledger. */
export async function initializeHostMemoryReservation(
  tx: Prisma.TransactionClient,
  hostId: string,
  ownerId: string,
): Promise<void> {
  requireRelayFence(transactionHoldsHostLock(tx, hostId));
  // Active allocations must have a placement and storage identity.
  const invalid = await tx.sandbox.findFirst({
    where: {
      sandboxHostId: hostId,
      hostOwnerId: ownerId,
      OR: [
        {
          liveResourcesHeld: true,
          OR: [{ CurrentPlacement: { is: null } }],
        },
        { state: { not: "DELETED" }, OR: [{ storagePoolId: null }, { rootChargeGiB: null }] },
        { diskReservationHeld: true, OR: [{ storagePoolId: null }, { rootChargeGiB: null }] },
      ],
    },
    select: { id: true },
  });
  requireSandboxIntegrity(!invalid, "sandbox_reservation_unbound");
  const initialized = await tx.$executeRaw`
    UPDATE sandbox_host h SET
      "liveCount" = (SELECT COUNT(*)::integer FROM sandbox_instance s
        WHERE s."sandboxHostId" = h.id AND s."hostOwnerId" = h."userId" AND s."liveResourcesHeld"),
      "memoryReservedMiB" = (SELECT COALESCE(SUM(p."chargedMemoryMiB"), 0)::integer
        FROM sandbox_instance s JOIN sandbox_placement p ON p.id = s."currentPlacementId"
        AND p."sandboxId" = s.id AND p."userId" = s."userId"
        WHERE s."sandboxHostId" = h.id AND s."hostOwnerId" = h."userId" AND s."liveResourcesHeld")
        -- Transient capture-VM holds (M3): a restart must not erase them.
        + (SELECT COALESCE(SUM(c."chargedMemoryMiB"), 0)::integer FROM sandbox_template_capture c
          WHERE c."hostId" = h.id AND c."hostOwnerId" = h."userId" AND c."resourcesHeld"),
      "vcpuReserved" = (SELECT COALESCE(SUM(p."chargedVcpu"), 0)::integer
        FROM sandbox_instance s JOIN sandbox_placement p ON p.id = s."currentPlacementId"
        AND p."sandboxId" = s.id AND p."userId" = s."userId"
        WHERE s."sandboxHostId" = h.id AND s."hostOwnerId" = h."userId" AND s."liveResourcesHeld")
        + (SELECT COALESCE(SUM(c."chargedVcpu"), 0)::integer FROM sandbox_template_capture c
          WHERE c."hostId" = h.id AND c."hostOwnerId" = h."userId" AND c."resourcesHeld"),
      "rootCount" = (SELECT COUNT(*)::integer FROM sandbox_instance s
        WHERE s."sandboxHostId" = h.id AND s."hostOwnerId" = h."userId" AND s."diskReservationHeld")
        -- Detached stale copies still hold their root (offload plan I5).
        + (SELECT COUNT(*)::integer FROM sandbox_disk_copy c
          WHERE c."hostId" = h.id AND c."hostOwnerId" = h."userId" AND c."diskReservationHeld")
    WHERE h.id = ${hostId} AND h."userId" = ${ownerId}`;
  requireRelayFence(initialized === 1);
  await tx.$executeRaw`
    UPDATE sandbox_host_storage_pool p SET "diskReservedGiB" = (
      SELECT COALESCE(SUM(s."rootChargeGiB"), 0)::integer FROM sandbox_instance s
      WHERE s."storagePoolId" = p.id AND s."sandboxHostId" = p."sandboxHostId"
        AND s."hostOwnerId" = p."userId" AND s."diskReservationHeld")
      + (SELECT COALESCE(SUM(c."diskChargeGiB"), 0)::integer FROM sandbox_template_capture c
        WHERE c."storagePoolId" = p.id AND c."hostId" = p."sandboxHostId"
          AND c."hostOwnerId" = p."userId" AND c."resourcesHeld")
      + (SELECT COALESCE(SUM(d."rootChargeGiB"), 0)::integer FROM sandbox_disk_copy d
        WHERE d."storagePoolId" = p.id AND d."hostId" = p."sandboxHostId"
          AND d."hostOwnerId" = p."userId" AND d."diskReservationHeld")
    WHERE p."sandboxHostId" = ${hostId} AND p."userId" = ${ownerId}`;
}

/** Bounded keyset walk, before listener/outbox even with relay disabled.
 * One owner → H per transaction; offline pre-admission releases need this too. */
export async function initializeHostMemoryReservations(): Promise<void> {
  let cursor = "";
  for (;;) {
    const hosts = await prisma.sandboxHost.findMany({
      where: { id: { gt: cursor } },
      orderBy: { id: "asc" },
      take: 100,
      select: { id: true, userId: true },
    });
    for (const host of hosts) {
      // A rolling deployment can accept a hello between the epoch read and H.
      // Retry at most twice in fresh transactions; initialization stays AFTER H.
      for (let attempt = 0; ; attempt++) {
        try {
          await prisma.$transaction(async (tx) => {
            // Bootstrap includes deletion-pending owners: it neither admits work nor
            // creates resources, and their cleanup must have an initialized ledger.
            await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${host.userId} FOR SHARE`;
            const current = await tx.sandboxHost.findFirst({
              where: { id: host.id, userId: host.userId },
              select: { connectionEpoch: true },
            });
            if (!current) return;
            await lockHostByEpoch(tx, host.id, current.connectionEpoch, host.userId);
            await initializeHostMemoryReservation(tx, host.id, host.userId);
          });
          break;
        } catch (error) {
          if (!(error instanceof RelayFenceRejected) || attempt >= 2) throw error;
        }
      }
    }
    if (hosts.length < 100) return;
    cursor = hosts[hosts.length - 1]!.id;
  }
}

/** The required report tuple is shared by direct/SQL placement and cold boot. */
export type HostVmCapacity = {
  liveCount: number;
  rootCount: number;
  memoryReservedMiB: number;
  vcpuReserved: number;
  daemonMemoryBudgetMiB: number | null;
  daemonVcpuBudget: number | null;
  daemonMaxCpuCount: number | null;
  admissionEpoch: number | null;
  connectionEpoch: number;
};

export function hostVmCapacity(host: HostVmCapacity) {
  const budget = host.daemonMemoryBudgetMiB;
  const vcpu = host.daemonVcpuBudget;
  return {
    memoryBudgetMiB: budget,
    vcpuBudget: vcpu,
    maxCpuCount: host.daemonMaxCpuCount,
    maxMemoryMiB:
      budget === null
        ? null
        : Math.max(
            0,
            Math.min(VM_SIZE_LIMITS.memoryMiBMax, budget - VM_SIZE_LIMITS.vmHostOverheadMiB),
          ),
    current:
      budget !== null &&
      vcpu !== null &&
      host.daemonMaxCpuCount !== null &&
      host.admissionEpoch === host.connectionEpoch,
    retainedRootCount: host.rootCount,
    memoryReservedMiB: host.memoryReservedMiB,
    vcpuReserved: host.vcpuReserved,
    memoryAvailableMiB: budget === null ? null : Math.max(0, budget - host.memoryReservedMiB),
    memoryOvercommittedMiB: budget === null ? null : Math.max(0, host.memoryReservedMiB - budget),
    vcpuAvailable: vcpu === null ? null : Math.max(0, vcpu - host.vcpuReserved),
    vcpuOvercommitted: vcpu === null ? null : Math.max(0, host.vcpuReserved - vcpu),
  };
}

/** Offline cold acceptance may use the last report. Held charges add zero;
 * actual cold starts still require aggregate RAM/vCPU fit after a shrink. */
export function requireHostVmCapacity(
  host: HostVmCapacity,
  size: VmSize,
  held = false,
  pinned?: { chargedMemoryMiB: number; chargedVcpu: number },
  newRoot = false,
): void {
  const capacity = hostVmCapacity(host);
  if (
    capacity.memoryBudgetMiB === null ||
    capacity.vcpuBudget === null ||
    capacity.maxCpuCount === null ||
    capacity.maxMemoryMiB === null
  )
    throw hostUnavailable();
  if (
    size.cpuCount > capacity.maxCpuCount ||
    size.memoryMiB > VM_SIZE_LIMITS.memoryMiBMax ||
    (pinned?.chargedMemoryMiB ?? vmLiveMemoryChargeMiB(size.memoryMiB)) > capacity.memoryBudgetMiB
  )
    throw vmSizeUnsupported();
  const addedMemory = held
    ? 0
    : (pinned?.chargedMemoryMiB ?? vmLiveMemoryChargeMiB(size.memoryMiB));
  const addedVcpu = held ? 0 : (pinned?.chargedVcpu ?? size.cpuCount);
  const reserved = host.memoryReservedMiB + addedMemory;
  const vcpu = host.vcpuReserved + addedVcpu;
  requireRelayFence(Number.isSafeInteger(reserved) && Number.isSafeInteger(vcpu));
  // Retryable unless this charge alone exceeds the host's budget.
  if (reserved > capacity.memoryBudgetMiB)
    throw hostCapacityConflict("ram", addedMemory <= capacity.memoryBudgetMiB);
  if (newRoot && host.rootCount >= VM_SIZE_LIMITS.hostManagedSandboxCeiling)
    throw hostCapacityConflict("ceiling", true);
  if (vcpu > capacity.vcpuBudget)
    throw hostCapacityConflict("vcpu", addedVcpu <= capacity.vcpuBudget);
}

/**
 * With no live sandbox, the host's reservations are exactly its template
 * capture holds (a capture of a STOPPED VM charges memory and vCPU while the
 * VM is not live, E2-A-04). Callers hold H so `held` and the counters are
 * one consistent view; read projections never assert this.
 */
export function assertZeroLiveResources(
  host: {
    liveCount: number;
    memoryReservedMiB: number;
    vcpuReserved: number;
  },
  held: CaptureHoldTotals = NO_CAPTURE_HOLDS,
) {
  if (host.liveCount === 0)
    requireSandboxIntegrity(
      host.memoryReservedMiB === held.memoryMiB && host.vcpuReserved === held.vcpu,
      "sandbox_reservation_nonzero_resources",
    );
}

export type CaptureHoldTotals = { memoryMiB: number; vcpu: number };
const NO_CAPTURE_HOLDS: CaptureHoldTotals = { memoryMiB: 0, vcpu: 0 };

/** The memory and vCPU the host's in-progress template captures hold. */
export async function hostCaptureHolds(
  tx: Prisma.TransactionClient,
  hostId: string,
): Promise<CaptureHoldTotals> {
  const sum = await tx.sandboxTemplateCapture.aggregate({
    where: { hostId, resourcesHeld: true },
    _sum: { chargedMemoryMiB: true, chargedVcpu: true },
  });
  return { memoryMiB: sum._sum.chargedMemoryMiB ?? 0, vcpu: sum._sum.chargedVcpu ?? 0 };
}

/** Caller already owns H, then S. A fresh S has no placement yet; every
 * retained allocation must agree with its pinned boot before any new hold. */
async function reservationTransportOwner(
  tx: Prisma.TransactionClient,
  input: { hostId: string; ownerId: string; sandboxId: string },
): Promise<string> {
  const row = await tx.sandbox.findFirst({
    where: { id: input.sandboxId, userId: input.ownerId, sandboxHostId: input.hostId },
    select: { hostOwnerId: true, SandboxHost: { select: { userId: true } } },
  });
  requireRelayFence(row?.hostOwnerId != null && row.hostOwnerId === row.SandboxHost?.userId);
  return row.hostOwnerId;
}

async function reservationSandbox(
  tx: Prisma.TransactionClient,
  input: { hostId: string; ownerId: string; sandboxId: string },
) {
  await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${input.sandboxId} AND "userId" = ${input.ownerId} FOR NO KEY UPDATE`;
  const sandbox = await tx.sandbox.findFirst({
    where: { id: input.sandboxId, userId: input.ownerId, sandboxHostId: input.hostId },
    select: {
      hostOwnerId: true,
      SandboxHost: { select: { userId: true } },
      liveResourcesHeld: true,
      cpuCount: true,
      memoryMiB: true,
      diskGiB: true,
      storagePoolId: true,
      storageMarker: true,
      storagePoolName: true,
      rootChargeGiB: true,
      diskReservationHeld: true,
      currentPlacementId: true,
    },
  });
  if (sandbox)
    requireSandboxIntegrity(
      sandbox.hostOwnerId != null && sandbox.hostOwnerId === sandbox.SandboxHost?.userId,
      "sandbox_allocation_mismatch",
    );
  if (sandbox?.currentPlacementId) {
    const placement = await tx.sandboxPlacement.findFirst({
      where: { id: sandbox.currentPlacementId, sandboxId: input.sandboxId, userId: input.ownerId },
      select: {
        hostOwnerId: true,
        cpuCount: true,
        memoryMiB: true,
        diskGiB: true,
        chargedMemoryMiB: true,
        chargedVcpu: true,
        storagePoolId: true,
        storagePoolName: true,
        storageMarker: true,
        rootChargeGiB: true,
      },
    });
    requireSandboxIntegrity(
      placement != null &&
        placement.hostOwnerId === sandbox.hostOwnerId &&
        placement.cpuCount === sandbox.cpuCount &&
        placement.memoryMiB === sandbox.memoryMiB &&
        placement.diskGiB === sandbox.diskGiB &&
        placement.storagePoolId === sandbox.storagePoolId &&
        placement.storagePoolName === sandbox.storagePoolName &&
        placement.storageMarker === sandbox.storageMarker &&
        placement.rootChargeGiB === sandbox.rootChargeGiB,
      "sandbox_allocation_mismatch",
    );
  }
  return sandbox;
}

async function liveCharges(
  tx: Prisma.TransactionClient,
  input: { sandboxId: string; ownerId: string },
  placementId: string | null,
) {
  const boot = placementId
    ? await tx.sandboxPlacement.findFirst({
        where: { id: placementId, sandboxId: input.sandboxId, userId: input.ownerId },
        select: { chargedMemoryMiB: true, chargedVcpu: true },
      })
    : null;
  requireSandboxIntegrity(
    boot?.chargedMemoryMiB != null && boot.chargedVcpu != null,
    "sandbox_reservation_unbound",
  );
  return { chargedMemoryMiB: boot.chargedMemoryMiB, chargedVcpu: boot.chargedVcpu };
}

/**
 * Host admission row lock (`lockCurrentHostEpoch` / `lockHostByEpoch`) is the
 * same `sandbox_host` row mutated here. Capacity reservation always runs
 * with H already held by create/cold reconnect, before operation/outbox writes.
 * Re-locking that same H and updating S acquires no new host lock after S.
 * Releases likewise revisit H/S already held by every terminal writer.
 */
export async function reserveLiveResources(
  tx: Prisma.TransactionClient,
  input: { hostId: string; ownerId: string; sandboxId: string },
): Promise<void> {
  const host = await lockCurrentHostEpoch(tx, input.hostId);
  const transportOwnerId = await reservationTransportOwner(tx, input);
  requireRelayFence(host.userId === transportOwnerId);
  await lockWorkAdmissionHost(tx, input.hostId, transportOwnerId);
  const sandbox = await reservationSandbox(tx, input);
  requireRelayFence(sandbox != null);
  const row = await tx.sandboxHost.findFirst({
    where: { id: input.hostId, userId: transportOwnerId },
    select: {
      liveCount: true,
      rootCount: true,
      daemonVcpuBudget: true,
      vcpuReserved: true,
      memoryReservedMiB: true,
      daemonMemoryBudgetMiB: true,
      daemonMaxCpuCount: true,
      admissionEpoch: true,
      connectionEpoch: true,
    },
  });
  requireRelayFence(row != null);
  const charges = await liveCharges(tx, input, sandbox.currentPlacementId);
  requireHostVmCapacity(row, sandbox, sandbox.liveResourcesHeld, charges);
  if (sandbox.liveResourcesHeld) return;
  const held = await tx.sandbox.updateMany({
    where: {
      id: input.sandboxId,
      userId: input.ownerId,
      sandboxHostId: input.hostId,
      liveResourcesHeld: false,
    },
    data: { liveResourcesHeld: true },
  });
  requireRelayFence(held.count === 1);
  const reserved = await tx.sandboxHost.updateMany({
    where: {
      id: input.hostId,
      userId: transportOwnerId,
      liveCount: row.liveCount,
      memoryReservedMiB: row.memoryReservedMiB,
      vcpuReserved: row.vcpuReserved,
    },
    data: {
      liveCount: { increment: 1 },
      memoryReservedMiB: { increment: charges.chargedMemoryMiB },
      vcpuReserved: { increment: charges.chargedVcpu },
    },
  });
  requireRelayFence(reserved.count === 1);
}

/** Own H → S. A complete census proving the instance is not running is
 * release evidence by itself; the sandbox CAS keeps it exactly once. */
export async function releaseLiveResourcesOnInventoryProof(
  tx: Prisma.TransactionClient,
  input: { hostId: string; ownerId: string; sandboxId: string },
): Promise<boolean> {
  return releaseLiveResources(tx, input);
}

async function releaseLiveResources(
  tx: Prisma.TransactionClient,
  input: {
    hostId: string;
    ownerId: string;
    sandboxId: string;
    sandboxFailure?: { lastErrorCode: string; lastErrorDetail: string };
    endReason?: "stopped" | "destroyed" | "not_issued";
    releaseRoot?: boolean;
  },
): Promise<boolean> {
  const host = await lockCurrentHostEpoch(tx, input.hostId);
  const transportOwnerId = await reservationTransportOwner(tx, input);
  requireRelayFence(host.userId === transportOwnerId);
  const sandbox = await reservationSandbox(tx, input);
  if (!sandbox) return false;
  const live = sandbox.liveResourcesHeld;
  const root = input.releaseRoot === true && sandbox.diskReservationHeld;
  const charges = live ? await liveCharges(tx, input, sandbox.currentPlacementId) : null;
  if (root)
    requireSandboxIntegrity(
      sandbox.storagePoolId != null && sandbox.rootChargeGiB != null,
      "sandbox_root_unbound",
    );
  if (!live && !root && !input.sandboxFailure) return false;
  // One S mutation and one H mutation release both lifetimes together. A
  // second UPDATE of a tuple written in this transaction makes PostgreSQL
  // recheck unchanged owner FKs, acquiring owner after H in dispatch cleanup.
  const released = await tx.sandbox.updateMany({
    where: {
      id: input.sandboxId,
      userId: input.ownerId,
      sandboxHostId: input.hostId,
      liveResourcesHeld: live,
      ...(root ? { diskReservationHeld: true } : {}),
    },
    data: {
      liveResourcesHeld: false,
      ...(root ? { diskReservationHeld: false } : {}),
      ...(input.sandboxFailure ? { state: "ERROR", ...input.sandboxFailure } : {}),
    },
  });
  requireRelayFence(released.count === 1);
  if (!live && !root) return false;
  if (live)
    await tx.sandboxPlacement.updateMany({
      where: {
        sandboxId: input.sandboxId,
        userId: input.ownerId,
        endedAt: null,
        CurrentFor: { is: { id: input.sandboxId, userId: input.ownerId } },
      },
      data: { endedAt: await hostDatabaseNow(tx), endReason: input.endReason ?? "not_running" },
    });
  const decremented = await tx.sandboxHost.updateMany({
    where: {
      id: input.hostId,
      userId: transportOwnerId,
      ...(live ? { liveCount: { gt: 0 } } : {}),
      ...(root ? { rootCount: { gt: 0 } } : {}),
      memoryReservedMiB: { gte: charges?.chargedMemoryMiB ?? 0 },
      vcpuReserved: { gte: charges?.chargedVcpu ?? 0 },
    },
    data: {
      ...(live
        ? {
            liveCount: { decrement: 1 },
            memoryReservedMiB: { decrement: charges!.chargedMemoryMiB },
            vcpuReserved: { decrement: charges!.chargedVcpu },
          }
        : {}),
      ...(root ? { rootCount: { decrement: 1 } } : {}),
    },
  });
  requireSandboxIntegrity(decremented.count === 1, "sandbox_reservation_underflow");
  if (root) await decrementRootPool(tx, input, sandbox);
  noteHostBlockerReleased(tx, input.hostId, transportOwnerId);
  return live;
}

/** Health is independent of heartbeat and frozen capacity. All readers below
 * run after H; every report/counter writer uses that same H. */
export const STORAGE_HEALTH_STALE_MS = 15_000;
export async function selectStoragePool(
  tx: Prisma.TransactionClient,
  hostId: string,
  ownerId: string,
  epoch: number,
  chargeGiB?: number,
) {
  const now = await hostDatabaseNow(tx);
  const pools = await tx.sandboxHostStoragePool.findMany({
    where: {
      sandboxHostId: hostId,
      userId: ownerId,
      connectionEpoch: epoch,
      newRootsAllowed: true,
      health: "healthy",
      draining: false,
      reportedAt: { gte: new Date(now.getTime() - STORAGE_HEALTH_STALE_MS), lte: now },
    },
    take: VM_SIZE_LIMITS.storagePoolMax,
    orderBy: { marker: "asc" },
  });
  return pools
    .filter((p) => chargeGiB === undefined || p.capacityGiB - p.diskReservedGiB >= chargeGiB)
    .sort((a, b) => b.capacityGiB - b.diskReservedGiB - (a.capacityGiB - a.diskReservedGiB))[0];
}

export async function requireRetainedStorage(
  tx: Prisma.TransactionClient,
  input: {
    hostId: string;
    ownerId: string;
    sandboxId: string;
    allowOffline?: boolean;
  },
) {
  requireRelayFence(transactionHoldsHostLock(tx, input.hostId));
  const transportOwnerId = await reservationTransportOwner(tx, input);
  const sandbox = await tx.sandbox.findFirst({
    where: { id: input.sandboxId, userId: input.ownerId, sandboxHostId: input.hostId },
    select: {
      storagePoolId: true,
      storagePoolName: true,
      storageMarker: true,
      diskReservationHeld: true,
    },
  });
  if (!sandbox?.diskReservationHeld || !sandbox.storagePoolId)
    throw hostCapacityConflict("storage", true);
  const host = await tx.sandboxHost.findFirstOrThrow({
    where: { id: input.hostId, userId: transportOwnerId },
    select: { status: true, connectionEpoch: true },
  });
  const pool = await tx.sandboxHostStoragePool.findFirst({
    where: {
      id: sandbox.storagePoolId,
      sandboxHostId: input.hostId,
      userId: transportOwnerId,
      name: sandbox.storagePoolName!,
      marker: sandbox.storageMarker!,
    },
  });
  // Storage health is reported state: it can recover.
  if (pool?.health !== "healthy") throw hostCapacityConflict("storage", true);
  if (input.allowOffline && host.status !== "CONNECTED") return pool;
  const now = await hostDatabaseNow(tx);
  if (
    pool.connectionEpoch !== host.connectionEpoch ||
    pool.reportedAt > now ||
    now.getTime() - pool.reportedAt.getTime() > STORAGE_HEALTH_STALE_MS
  )
    throw hostCapacityConflict("storage", true);
  return pool;
}

/** A new root is reserved once, independently of live holds. A stopped root
 * keeps its bridge/guard position; cold boot never increments these counters. */
export async function reserveRootResources(
  tx: Prisma.TransactionClient,
  input: {
    hostId: string;
    ownerId: string;
    sandboxId: string;
  },
) {
  requireRelayFence(transactionHoldsHostLock(tx, input.hostId));
  const transportOwnerId = await reservationTransportOwner(tx, input);
  const sandbox = await reservationSandbox(tx, input);
  requireRelayFence(sandbox != null);
  if (sandbox.diskReservationHeld) return;
  requireSandboxIntegrity(
    sandbox.storagePoolId != null && sandbox.rootChargeGiB != null,
    "sandbox_root_unbound",
  );
  const host = await tx.sandboxHost.findFirstOrThrow({
    where: { id: input.hostId, userId: transportOwnerId },
  });
  const pool = await selectStoragePool(
    tx,
    input.hostId,
    transportOwnerId,
    host.connectionEpoch,
    sandbox.rootChargeGiB,
  );
  // The chosen identity is immutable even if another pool would now fit.
  // The bound pool lacks free space or health now; other roots can release it.
  if (!pool || pool.id !== sandbox.storagePoolId) throw hostCapacityConflict("disk", true);
  if (host.rootCount >= VM_SIZE_LIMITS.hostManagedSandboxCeiling)
    throw hostCapacityConflict("ceiling", true);
  const held = await tx.sandbox.updateMany({
    where: {
      id: input.sandboxId,
      userId: input.ownerId,
      sandboxHostId: input.hostId,
      diskReservationHeld: false,
    },
    data: { diskReservationHeld: true },
  });
  requireRelayFence(held.count === 1);
  const counted = await tx.sandboxHost.updateMany({
    where: { id: input.hostId, userId: transportOwnerId, rootCount: host.rootCount },
    data: { rootCount: { increment: 1 } },
  });
  const reserved = await tx.sandboxHostStoragePool.updateMany({
    where: {
      id: pool.id,
      sandboxHostId: input.hostId,
      userId: transportOwnerId,
      diskReservedGiB: pool.diskReservedGiB,
    },
    data: { diskReservedGiB: { increment: sandbox.rootChargeGiB } },
  });
  requireRelayFence(counted.count === 1 && reserved.count === 1);
}

/** A root reservation's holder: a sandbox on its host, or a detached
 * `SandboxDiskCopy` (offload plan I5) on the copy's host. */
export type RootHolder =
  | { hostId: string; ownerId: string; sandboxId: string }
  | { hostId: string; copyId: string };

/** Only exact-root deletion/network cleanup or a proven never-issued first
 * create may reach this helper (for a copy: a discard's matching root
 * proof). It works after live release and is idempotent: the holder's flag
 * CAS releases once. */
export async function releaseRootResources(tx: Prisma.TransactionClient, input: RootHolder) {
  requireRelayFence(transactionHoldsHostLock(tx, input.hostId));
  if ("copyId" in input) return releaseCopyRoot(tx, input);
  const transportOwnerId = await reservationTransportOwner(tx, input);
  const sandbox = await reservationSandbox(tx, input);
  if (!sandbox?.diskReservationHeld) return false;
  requireSandboxIntegrity(
    sandbox.storagePoolId != null && sandbox.rootChargeGiB != null,
    "sandbox_root_unbound",
  );
  const released = await tx.sandbox.updateMany({
    where: {
      id: input.sandboxId,
      userId: input.ownerId,
      sandboxHostId: input.hostId,
      diskReservationHeld: true,
    },
    data: { diskReservationHeld: false },
  });
  requireRelayFence(released.count === 1);
  const counted = await tx.sandboxHost.updateMany({
    where: { id: input.hostId, userId: transportOwnerId, rootCount: { gt: 0 } },
    data: { rootCount: { decrement: 1 } },
  });
  requireSandboxIntegrity(counted.count === 1, "sandbox_root_underflow");
  await decrementRootPool(tx, input, sandbox);
  noteHostBlockerReleased(tx, input.hostId, transportOwnerId);
  return true;
}

async function releaseCopyRoot(
  tx: Prisma.TransactionClient,
  input: { hostId: string; copyId: string },
): Promise<boolean> {
  const [copy] = await tx.$queryRaw<
    {
      hostOwnerId: string;
      storagePoolId: string;
      rootChargeGiB: number;
      diskReservationHeld: boolean;
    }[]
  >`SELECT "hostOwnerId", "storagePoolId", "rootChargeGiB", "diskReservationHeld"
    FROM sandbox_disk_copy WHERE id = ${input.copyId} AND "hostId" = ${input.hostId} FOR UPDATE`;
  if (!copy?.diskReservationHeld) return false;
  const released = await tx.sandboxDiskCopy.updateMany({
    where: { id: input.copyId, hostId: input.hostId, diskReservationHeld: true },
    data: { diskReservationHeld: false },
  });
  requireRelayFence(released.count === 1);
  const counted = await tx.sandboxHost.updateMany({
    where: { id: input.hostId, userId: copy.hostOwnerId, rootCount: { gt: 0 } },
    data: { rootCount: { decrement: 1 } },
  });
  requireSandboxIntegrity(counted.count === 1, "sandbox_root_underflow");
  const pool = await tx.sandboxHostStoragePool.updateMany({
    where: {
      id: copy.storagePoolId,
      sandboxHostId: input.hostId,
      userId: copy.hostOwnerId,
      diskReservedGiB: { gte: copy.rootChargeGiB },
    },
    data: { diskReservedGiB: { decrement: copy.rootChargeGiB } },
  });
  requireSandboxIntegrity(pool.count === 1, "sandbox_root_underflow");
  noteHostBlockerReleased(tx, input.hostId, copy.hostOwnerId);
  return true;
}

async function decrementRootPool(
  tx: Prisma.TransactionClient,
  input: { hostId: string; ownerId: string; sandboxId: string },
  sandbox: { storagePoolId: string | null; rootChargeGiB: number | null },
) {
  requireSandboxIntegrity(
    sandbox.storagePoolId != null && sandbox.rootChargeGiB != null,
    "sandbox_root_unbound",
  );
  const transportOwnerId = await reservationTransportOwner(tx, input);
  const pool = await tx.sandboxHostStoragePool.updateMany({
    where: {
      id: sandbox.storagePoolId,
      sandboxHostId: input.hostId,
      userId: transportOwnerId,
      diskReservedGiB: { gte: sandbox.rootChargeGiB },
    },
    data: { diskReservedGiB: { decrement: sandbox.rootChargeGiB } },
  });
  requireSandboxIntegrity(pool.count === 1, "sandbox_root_underflow");
}

/**
 * C21-11 structural finalization. Every write that can move a row out of an
 * `assertHostDeletable` blocker predicate (live slot release, liveCount
 * decrement, DELETED detach, operation terminalization, template retire) notes
 * its host here. `sandboxOutboxTransaction` then calls `tryFinalizeTombstonedHost`
 * for each noted host as the transaction's LAST step, after every detach/settle.
 */
const releasedHostsByTransaction = new WeakMap<object, Map<string, string>>();

export function noteHostBlockerReleased(
  tx: Prisma.TransactionClient,
  hostId: string | null | undefined,
  ownerId: string,
): void {
  if (!hostId) return;
  // A released live/root hold may let a waiting create place (post-commit wake).
  noteCapacityChanged(tx, { hostIds: [hostId] });
  let hosts = releasedHostsByTransaction.get(tx);
  if (!hosts) {
    hosts = new Map();
    releasedHostsByTransaction.set(tx, hosts);
  }
  hosts.set(hostId, ownerId);
}

/** Last step of every sandbox transaction; see `noteHostBlockerReleased`.
 * `holds` collects the finalizations' authority changes so the transaction's
 * owner can release them only after its commit or rollback. */
export async function finalizeReleasedHosts(
  tx: Prisma.TransactionClient,
  holds?: AuthorityChangeHold[],
): Promise<void> {
  const hosts = releasedHostsByTransaction.get(tx);
  if (!hosts) return;
  releasedHostsByTransaction.delete(tx);
  for (const [hostId] of [...hosts].sort(([a], [b]) => a.localeCompare(b))) {
    if (!transactionHoldsHostLock(tx, hostId)) continue;
    const host = await tx.sandboxHost.findUnique({
      where: { id: hostId },
      select: { userId: true },
    });
    if (!host) continue;
    await clearRetiredReleaseQuarantine(tx, hostId, host.userId);
    await tryFinalizeTombstonedHost(tx, hostId, host.userId, holds);
  }
}

/** Run after detach/settle, before commit, only for a provably held H.
 * Noted dispatched hosts can differ from the locked current placement. At this
 * point S/O may already be held, so leave those hosts to the next census rather
 * than acquiring H out of order. */
export async function clearRetiredReleaseQuarantine(
  tx: Prisma.TransactionClient,
  hostId: string,
  ownerId: string,
): Promise<void> {
  if (!transactionHoldsHostLock(tx, hostId)) return;
  const quarantined = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: ownerId, quarantineReason: "released_instance_present" },
    select: { id: true, inventorySeq: true, inventoryAcknowledgedEpoch: true },
  });
  if (!quarantined) return;
  // H is already held. Recheck after every detach/settle, including releases
  // whose slot CAS was already consumed by never-issued settlement. Retain
  // quarantine only for an unretired placement witnessed present in the latest
  // (or in-progress) census. Its FAILED operation survives teardown errors and
  // generations; a later completed census supersedes the witness.
  const unreclaimed = await tx.sandbox.findFirst({
    where: {
      hostOwnerId: ownerId,
      sandboxHostId: hostId,
      state: { not: "DELETED" },
      Operations: {
        some: {
          state: "FAILED",
          kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },
          errorCode: "host_effect_not_issued",
          AND: [
            { result: { path: ["allocationPresenceCensus"], gte: quarantined.inventorySeq } },
            {
              result: {
                path: ["allocationPresenceEpoch"],
                gte: quarantined.inventoryAcknowledgedEpoch ?? 0,
              },
            },
          ],
        },
      },
    },
    select: { id: true },
  });
  if (!unreclaimed)
    await tx.sandboxHost.updateMany({
      where: { id: hostId, userId: ownerId, quarantineReason: "released_instance_present" },
      data: { quarantinedAt: null, quarantineReason: null },
    });
}

/** Candidate evidence only; releaseLiveResourcesIfHeld also checks other attempts. */
export function isLiveResourcesReleaseCandidate(input: {
  kind: SandboxOperationKind;
  opState: OperationState;
  sandboxStateBeforeResult: SandboxState;
  endState?: unknown;
}): boolean {
  if (input.opState === "UNKNOWN_OUTCOME") return false;
  if (input.kind === "STOP_SANDBOX") {
    return (
      input.opState === "SUCCEEDED" && (input.endState === "stopped" || input.endState === "absent")
    );
  }
  if (input.kind === "KILL_SANDBOX") {
    return input.opState === "SUCCEEDED" && input.endState === "deleted";
  }
  if (input.opState === "SUCCEEDED") return false;
  if (input.kind === "CREATE_SANDBOX") {
    return input.opState === "FAILED" || input.opState === "CANCELLED";
  }
  if (input.kind === "RECONNECT_SANDBOX") {
    if (input.opState !== "FAILED" && input.opState !== "CANCELLED") return false;
    // Cold reconnect leaves the guest STOPPED until success; warm failure stays READY.
    return input.sandboxStateBeforeResult === "STOPPED";
  }
  return false;
}

export async function releaseLiveResourcesIfHeld(
  tx: Prisma.TransactionClient,
  input: {
    hostId: string | null | undefined;
    ownerId: string;
    sandboxId: string;
    operationId: string;
    endState?: unknown;
    sandboxFailure?: { lastErrorCode: string; lastErrorDetail: string };
    kind: LifecycleOperationKind;
    opState: OperationState;
    sandboxStateBeforeResult: SandboxState;
    neverIssued?: boolean;
    /**
     * Positive evidence the guest is still running although the operation is
     * recorded FAILED (CLI logins: a cold start the host reported ready that
     * the READY gate failed because a login was not installed). A FAILED
     * cold reconnect otherwise proves no live VM; this one does not.
     */
    guestRunning?: boolean;
  },
): Promise<void> {
  if (input.hostId == null || input.guestRunning === true) return;
  if (
    !isLiveResourcesReleaseCandidate({
      kind: input.kind,
      opState: input.opState,
      sandboxStateBeforeResult: input.sandboxStateBeforeResult,
      endState: input.endState,
    })
  ) {
    return;
  }
  if (
    input.opState !== "SUCCEEDED" &&
    (await hasPossiblyLiveSandboxAttempt(tx, input.ownerId, input.sandboxId, input.operationId))
  )
    return;
  // A successful release notes the host; finalization runs last in this transaction.
  await releaseLiveResources(tx, {
    hostId: input.hostId,
    ownerId: input.ownerId,
    sandboxId: input.sandboxId,
    sandboxFailure: input.sandboxFailure,
    releaseRoot:
      (input.kind === "KILL_SANDBOX" &&
        input.opState === "SUCCEEDED" &&
        input.endState === "deleted") ||
      (input.kind === "CREATE_SANDBOX" && input.neverIssued === true),
    endReason:
      input.opState !== "SUCCEEDED"
        ? "not_issued"
        : input.kind === "KILL_SANDBOX"
          ? "destroyed"
          : "stopped",
  });
}

/** H excludes bound-child insertion. Never acquire a parent from this suffix.
 * Keyset pages keep enrollment history bounded without relying on FK triggers. */
export async function prelockHostDeviceCredentials(
  tx: Prisma.TransactionClient,
  hostId: string,
): Promise<void> {
  let cursor = "";
  for (;;) {
    const rows = await tx.$queryRaw<
      { id: string }[]
    >`SELECT id FROM host_device_credential WHERE "sandboxHostId" = ${hostId} AND id > ${cursor} ORDER BY id LIMIT 100 FOR UPDATE`;
    if (rows.length < 100) return;
    cursor = rows[rows.length - 1]!.id;
  }
}

async function prelockHostDeletionSuffix(
  tx: Prisma.TransactionClient,
  hostId: string,
): Promise<void> {
  let cursor = "";
  for (;;) {
    const rows = await tx.$queryRaw<
      { id: string }[]
    >`SELECT id FROM host_token WHERE "sandboxHostId" = ${hostId} AND id > ${cursor} ORDER BY id LIMIT 100 FOR UPDATE`;
    if (rows.length < 100) break;
    cursor = rows[rows.length - 1]!.id;
  }
  await prelockHostDeviceCredentials(tx, hostId);
  cursor = "";
  for (;;) {
    const rows = await tx.$queryRaw<
      { id: string }[]
    >`SELECT id FROM sdk_key_host_allowlist WHERE "sandboxHostId" = ${hostId} AND id > ${cursor} ORDER BY id LIMIT 100 FOR UPDATE`;
    if (rows.length < 100) return;
    cursor = rows[rows.length - 1]!.id;
  }
}

/** Deletes a tombstoned host when cleanup evidence shows it is safe to finalize.
 * With `holds`, the authority change stays in flight until the CALLER settles it
 * after the outer transaction's commit or rollback; without it, the change wraps
 * only the statements (safe for statement-scoped callers). */
export async function tryFinalizeTombstonedHost(
  tx: Prisma.TransactionClient,
  hostId: string,
  ownerId: string,
  holds?: AuthorityChangeHold[],
): Promise<boolean> {
  // This suffix may have noted an older dispatched host. Never acquire its H
  // implicitly through DELETE after holding another placement's S/O locks.
  if (!transactionHoldsHostLock(tx, hostId)) return false;
  const tombstoned = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: ownerId, deletionRequestedAt: { not: null } },
    select: {
      id: true,
      liveCount: true,
      memoryReservedMiB: true,
      vcpuReserved: true,
      rootCount: true,
    },
  });
  if (!tombstoned) return false;
  // Integrity failure must escape the ordinary still-draining blocker catch.
  assertZeroLiveResources(tombstoned, await hostCaptureHolds(tx, hostId));
  try {
    await assertHostDeletable(tx, hostId, ownerId);
  } catch (error) {
    if (error instanceof SandboxIntegrityError) throw error;
    return false;
  }
  const placed = await tx.sandbox.findFirst({
    where: { sandboxHostId: hostId },
    select: { id: true },
  });
  if (placed) return false;
  // Finalization cascades the SDK allowlist rows that granted this host. The
  // owner+host-scoped authority change fences every in-flight read whose ticket
  // named this host (e.g. a retained-sandbox read authorized before the delete):
  // its post-read check fails instead of disclosing post-grant-removal data. The
  // revision bump lands before this transaction's commit; a rollback leaves a
  // spuriously invalidated ticket, which fails closed and heals on retry.
  const finalize = async () => {
    await tx.sandboxTemplateAvailability.deleteMany({ where: { hostId, hostOwnerId: ownerId } });
    await tx.sandboxPoolMember.deleteMany({
      where: { sandboxHostId: hostId, hostOwnerId: ownerId, removedAt: { not: null } },
    });
    await prelockHostDeletionSuffix(tx, hostId);
    // CLI logins (§7.4.2): the host's quarantined envelopes are discarded with it.
    await tx.credentialCaptureRejection.updateMany({
      where: { hostId, discardedAt: null },
      data: { discardedAt: new Date() },
    });
    const deleted = await tx.sandboxHost.deleteMany({
      where: {
        id: hostId,
        userId: ownerId,
        liveCount: 0,
        rootCount: 0,
        memoryReservedMiB: 0,
        vcpuReserved: 0,
      },
    });
    requireRelayFence(deleted.count === 1);
  };
  if (holds) {
    // The in-flight mark outlives these statements until the caller settles it
    // AFTER the outer transaction commits or rolls back. A read admitted in
    // between would otherwise authorize against the still-committed old grant,
    // sample the post-bump revision, and disclose metadata whose grant this
    // uncommitted deletion removes.
    holds.push(holdAuthorityChange({ ownerId, hostId }));
    await finalize();
  } else {
    await withAuthorityChange({ ownerId, hostId }, finalize);
  }
  return true;
}

/** Own H → S. A refusal proves only this attempt did not allocate. All
 * generations, including superseded and lease-expired effects, share the slot. */
export async function hasPossiblyLiveSandboxAttempt(
  tx: Prisma.TransactionClient,
  ownerId: string,
  sandboxId: string,
  exceptOperationId: string,
): Promise<boolean> {
  // A confirmed later stop/kill is terminal evidence for earlier effects,
  // including FAILED/lease_expired receipts retained for API history.
  const cleanup = await tx.sandboxOperation.findFirst({
    where: {
      userId: ownerId,
      sandboxId,
      state: "SUCCEEDED",
      OR: [
        { kind: "STOP_SANDBOX", result: { path: ["state"], equals: "stopped" } },
        { kind: "STOP_SANDBOX", result: { path: ["state"], equals: "absent" } },
        { kind: "KILL_SANDBOX", result: { path: ["state"], equals: "deleted" } },
      ],
    },
    orderBy: { generation: "desc" },
    select: { generation: true },
  });
  return (
    (await tx.sandboxOperation.findFirst({
      where: {
        userId: ownerId,
        sandboxId,
        id: { not: exceptOperationId },
        ...(cleanup ? { generation: { gt: cleanup.generation } } : {}),
        OR: [
          // Pending supersession settles to UNKNOWN on failure, even for an
          // undispatched predecessor. Keep its shared slot through settlement.
          { state: { in: ["UNKNOWN_OUTCOME", "CANCEL_REQUESTED"] } },
          {
            dispatchAttempt: { gt: 0 },
            OR: [
              {
                state: { in: ["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED"] },
              },
              { state: "FAILED", errorCode: { in: ["lease_expired", "guest_unavailable"] } },
            ],
          },
        ],
      },
      select: { id: true },
    })) != null
  );
}

// OFFLOADED is deliberately absent: an offloaded sandbox is hostless (its
// disk lives in the store), so it never pins a host.
const HOST_DELETE_BLOCKING_SANDBOX_STATES: readonly SandboxState[] = [
  "REQUESTED",
  "SCHEDULED",
  "PROVISIONING",
  "READY",
  "STOPPING",
  "RECLAIMING",
  "UNREACHABLE",
  "RECOVERED",
  "ERROR",
  "STOPPED",
];

export async function assertHostDeletable(
  tx: Prisma.TransactionClient,
  hostId: string,
  ownerId: string,
): Promise<void> {
  const host = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: ownerId },
    select: { liveCount: true, memoryReservedMiB: true, vcpuReserved: true, rootCount: true },
  });
  if (host == null) return;
  if (host.liveCount > 0) {
    throw hostDeleteConflict("Host still has reserved live sandbox capacity.");
  }
  const held = await hostCaptureHolds(tx, hostId);
  assertZeroLiveResources(host, held);
  if (held.memoryMiB > 0 || held.vcpu > 0)
    throw hostDeleteConflict("Host is still capturing a template.");
  // Detached stale disk copies (offload plan S10) block until discarded.
  const copy = await tx.sandboxDiskCopy.findFirst({
    where: { hostId, hostOwnerId: ownerId },
    select: { id: true },
  });
  if (copy) throw hostDeleteConflict("Host still has stale disk copies to discard.");
  if (host.rootCount > 0) throw hostDeleteConflict("Host still has retained root capacity.");
  const retainedPool = await tx.sandboxHostStoragePool.findFirst({
    where: { sandboxHostId: hostId, userId: ownerId, diskReservedGiB: { gt: 0 } },
    select: { id: true },
  });
  requireSandboxIntegrity(!retainedPool, "sandbox_root_underflow");
  const blockingSandbox = await tx.sandbox.findFirst({
    where: {
      sandboxHostId: hostId,
      hostOwnerId: ownerId,
      OR: [
        { liveResourcesHeld: true },
        { diskReservationHeld: true },
        { state: { in: [...HOST_DELETE_BLOCKING_SANDBOX_STATES] } },
      ],
    },
    select: { id: true },
  });
  if (blockingSandbox != null) {
    throw hostDeleteConflict("Host still has sandboxes or retained disks.");
  }
  // Reserved content belongs to the host accepted by the transfer.
  const transfer = await tx.sandboxTransfer.findFirst({
    where: {
      reservationHeld: true,
      acceptedHostId: hostId,
    },
    select: { id: true },
  });
  if (transfer) throw hostDeleteConflict("Host still has reserved transfer content.");
  const unknownWork = await tx.sandboxOperation.findFirst({
    where: {
      Sandbox: { hostOwnerId: ownerId },
      dispatchedHostId: hostId,
      state: { in: [...ACTIVE_OPERATION_STATES, "UNKNOWN_OUTCOME"] },
    },
    select: { id: true },
  });
  if (unknownWork != null) {
    throw hostDeleteConflict("Host still has work with unknown outcome.");
  }
}

export async function lockHostForSandboxOperation(
  tx: Prisma.TransactionClient,
  hostId: string | null | undefined,
  ownerId: string,
  sandboxId?: string,
) {
  if (hostId) {
    const host = await lockCurrentHostEpoch(tx, hostId);
    if (sandboxId && host.userId !== ownerId) {
      const sandbox = await tx.sandbox.findFirst({
        where: { id: sandboxId, userId: ownerId, sandboxHostId: hostId, hostOwnerId: host.userId },
        select: { CurrentPlacement: { select: { hostOwnerId: true, originHostId: true } } },
      });
      requireRelayFence(
        sandbox?.CurrentPlacement?.hostOwnerId === host.userId &&
          sandbox.CurrentPlacement.originHostId === hostId,
      );
    } else {
      requireRelayFence(host.userId === ownerId);
    }
    const active = await tx.sandboxHost.findFirst({
      where: { id: hostId, User: { deletionRequestedAt: null } },
      select: { id: true },
    });
    requireRelayFence(active != null);
  }
}

export async function lockAdmissionHost(
  tx: Prisma.TransactionClient,
  hostId: string | null | undefined,
  ownerId: string,
) {
  if (hostId) {
    const host = await lockCurrentHostEpoch(tx, hostId);
    requireRelayFence(host.userId === ownerId);
    const active = await tx.sandboxHost.findFirst({
      where: { id: hostId, deletionRequestedAt: null, User: { deletionRequestedAt: null } },
      select: { id: true },
    });
    if (!active) {
      const tombstoned = await tx.sandboxHost.findFirst({
        where: { id: hostId, userId: ownerId, deletionRequestedAt: { not: null } },
        select: { id: true },
      });
      if (tombstoned) {
        throw hostDeleteConflict("Sandbox host is pending deletion.");
      }
      requireRelayFence(false);
    }
  }
}

/** New guest work only. Token minting and existing guest operations remain allowed.
 * Called with H before S by create/template, and with the SAME H already held
 * by cold reconnect's capacity reservation. No network IO under this lock.
 */
export async function lockWorkAdmissionHost(
  tx: Prisma.TransactionClient,
  hostId: string,
  ownerId: string,
): Promise<void> {
  await lockHostForSandboxOperation(tx, hostId, ownerId);
  const host = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: ownerId },
    select: { draining: true, quarantinedAt: true },
  });
  requireRelayFence(host != null);
  if (host.quarantinedAt) throw hostUnavailable("Host is quarantined: its inventory conflicts.");
  if (host.draining) throw hostDrainingConflict();
}

/** Derived from durable reservations: pending/unknown guests count until confirmed gone. */
export function hostDrainStatus<
  T extends {
    id: string;
    draining: boolean;
    liveCount: number;
    memoryReservedMiB: number;
    vcpuReserved: number;
  },
>(host: T) {
  // A read projection: it never asserts the reservation invariant. With no
  // live sandbox, a template capture's hold is a legitimate reservation, and
  // the counters and the holds cannot be read as one view here (E2-A-04:
  // asserting it turned every /v1/hosts read during a capture into a 500).
  return {
    ...host,
    liveSandboxCount: host.liveCount,
    drained: host.draining && host.liveCount === 0,
  };
}

export type HostStaticCapacity = import("zod").infer<
  typeof import("@wssp/sandbox-contracts").hostStaticCapacityV11Schema
>;
export type HostStorageObservation = import("zod").infer<
  typeof import("@wssp/sandbox-contracts").hostInventoryUpdateV11Schema
>;

function canonicalCapacity(input: HostStaticCapacity) {
  const parsed = hostStaticCapacityV11Schema.parse(input);
  return JSON.stringify({
    vmCapacity: parsed.vmCapacity,
    storagePools: [...parsed.storagePools].sort((a, b) => a.marker.localeCompare(b.marker)),
  });
}

/** Hello freezes a complete, bounded tuple. Only a new epoch can change it;
 * health/usage reports cannot rewrite capacity or re-enable an omitted pool. */
export async function bindHostStaticCapacity(
  tx: Prisma.TransactionClient,
  input: {
    hostId: string;
    ownerId: string;
    epoch: number;
    capacity: HostStaticCapacity;
  },
) {
  requireRelayFence(transactionHoldsHostLock(tx, input.hostId));
  const host = await tx.sandboxHost.findFirstOrThrow({
    where: { id: input.hostId, userId: input.ownerId },
  });
  requireRelayFence(host.connectionEpoch === input.epoch);
  input.capacity = hostStaticCapacityV11Schema.parse(input.capacity);
  const encoded = canonicalCapacity(input.capacity);
  if (host.capacityReport !== null) {
    requireRelayFence(host.capacityReport === encoded);
    return;
  }
  const now = await hostDatabaseNow(tx);
  await tx.sandboxHostStoragePool.updateMany({
    where: { sandboxHostId: input.hostId, userId: input.ownerId },
    data: { newRootsAllowed: false, configured: false },
  });
  for (const p of input.capacity.storagePools) {
    const {
      reason,
      totalBytes,
      usedBytes,
      freeBytes,
      derivationTotalBytes,
      derivationFreeBytes,
      derivationCommittedBytes,
      derivationActualBytes,
      derivationHeadroomBytes,
      ...staticFields
    } = p;
    const bigint = (value: number | null) => (value === null ? null : BigInt(value));
    const data = {
      ...staticFields,
      healthReason: reason,
      totalBytes: bigint(totalBytes),
      usedBytes: bigint(usedBytes),
      freeBytes: bigint(freeBytes),
      derivationTotalBytes: bigint(derivationTotalBytes),
      derivationFreeBytes: bigint(derivationFreeBytes),
      derivationCommittedBytes: bigint(derivationCommittedBytes),
      derivationActualBytes: bigint(derivationActualBytes),
      derivationHeadroomBytes: bigint(derivationHeadroomBytes),
      connectionEpoch: input.epoch,
      observationSequence: 0n,
      reportedAt: now,
      configured: true,
      newRootsAllowed: p.health === "healthy",
    };
    await tx.sandboxHostStoragePool.upsert({
      where: { sandboxHostId_marker: { sandboxHostId: input.hostId, marker: p.marker } },
      create: { ...data, userId: input.ownerId, sandboxHostId: input.hostId },
      update: data,
    });
  }
  await tx.sandboxHost.update({
    where: { id: input.hostId, userId: input.ownerId },
    data: {
      capacityReport: encoded,
      daemonMemoryBudgetMiB: input.capacity.vmCapacity.memoryBudgetMiB,
      daemonMaxCpuCount: input.capacity.vmCapacity.maxCpuCount,
      daemonVcpuBudget: input.capacity.vmCapacity.vcpuBudget,
    },
  });
}

export async function requireStaticCapacityMatch(
  tx: Prisma.TransactionClient,
  hostId: string,
  ownerId: string,
  capacity: HostStaticCapacity,
) {
  const host = await tx.sandboxHost.findFirstOrThrow({
    where: { id: hostId, userId: ownerId },
    select: { capacityReport: true },
  });
  requireRelayFence(host.capacityReport === canonicalCapacity(capacity));
}

/** Monotonic, complete configured-pool reports; current H fences sender/epoch.
 * Equal sequences must be byte-equivalent observations, and never refresh age. */
export async function recordStorageObservation(
  tx: Prisma.TransactionClient,
  input: {
    hostId: string;
    ownerId: string;
    epoch: number;
    report: HostStorageObservation;
  },
) {
  requireRelayFence(transactionHoldsHostLock(tx, input.hostId));
  input.report = hostInventoryUpdateV11Schema.parse(input.report);
  requireRelayFence(input.report.connectionEpoch === input.epoch);
  const host = await tx.sandboxHost.findFirstOrThrow({
    where: { id: input.hostId, userId: input.ownerId },
    select: { capacityReport: true, connectionEpoch: true },
  });
  requireRelayFence(
    host.connectionEpoch === input.epoch && typeof host.capacityReport === "string",
  );
  const frozen: HostStaticCapacity = JSON.parse(host.capacityReport);
  requireRelayFence(
    frozen.storagePools.length === input.report.storagePools.length &&
      frozen.storagePools.every((p) =>
        input.report.storagePools.some((q) => q.marker === p.marker && q.name === p.name),
      ),
  );
  const now = await hostDatabaseNow(tx);
  for (const p of input.report.storagePools) {
    const pool = await tx.sandboxHostStoragePool.findFirstOrThrow({
      where: {
        sandboxHostId: input.hostId,
        userId: input.ownerId,
        marker: p.marker,
        name: p.name,
        connectionEpoch: input.epoch,
      },
    });
    const seq = BigInt(input.report.observationSequence);
    requireRelayFence(seq >= pool.observationSequence);
    const bigint = (value: number | null) => (value === null ? null : BigInt(value));
    if (seq === pool.observationSequence) {
      requireRelayFence(
        pool.health === p.health &&
          pool.healthReason === p.reason &&
          pool.totalBytes === bigint(p.totalBytes) &&
          pool.usedBytes === bigint(p.usedBytes) &&
          pool.freeBytes === bigint(p.freeBytes),
      );
      continue;
    }
    await tx.sandboxHostStoragePool.update({
      where: { id: pool.id },
      data: {
        health: p.health,
        healthReason: p.reason,
        totalBytes: bigint(p.totalBytes),
        usedBytes: bigint(p.usedBytes),
        freeBytes: bigint(p.freeBytes),
        observationSequence: seq,
        reportedAt: now,
      },
    });
  }
}
