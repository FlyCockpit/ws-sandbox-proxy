import { HOST_HEARTBEAT_STALE_AFTER_MS } from "@wssp/config/host-status";
import type { Prisma } from "@wssp/db";
import {
  resolveVmSize,
  VM_SIZE_LIMITS,
  type VmSize,
  type VmSizeOverrides,
  vmRootChargeGiB,
} from "@wssp/sandbox-contracts";
import { type CredentialPlacementContext, requireCredentialHost } from "../credentials/placement";
import { deviceDatabaseNow } from "../lib/device-code-transitions";
import { authorizeServiceAction } from "../lib/sdk-key-access";
import type { Principal } from "./contracts";
import { egressGuardLeased } from "./egress-guard";
import type { EgressHostFacts } from "./egress-policy";
import {
  egressRefused,
  hostCapacityConflict,
  hostNotFound,
  hostUnavailable,
  templateImageMissing,
  templateImageRejected,
  unsupportedCapability,
  vmSizeUnsupported,
} from "./errors";
import type { GuestSudoHostFacts } from "./guest-sudo-policy";
import {
  lockAdmissionHost,
  lockWorkAdmissionHost,
  requireHostVmCapacity,
  selectStoragePool,
} from "./host-admission";
import { requireHostJournalKeyAck } from "./idempotency";
import { directFetchDecision, type ImageFetchPlan } from "./image-placement";
import { foreignCopyUsableSql } from "./image-store/access";
import { requirePlacementPrincipals, requirePoolUse } from "./sharing-authority";
import { resolveTemplateRevision } from "./template-resolution";
import { assertDiskFitsImage } from "./vm-size-input";

export async function lockOwnerPlacement(tx: Prisma.TransactionClient, ownerId: string) {
  await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${ownerId}, 31))`;
}

/** K is held by the replay-first boundary. H precedes every revision/S write.
 * Availability is exact and current-epoch; cached image state is irrelevant to
 * original-disk reconnect, which deliberately does not call this function. */
export async function resolveDirectPlacement(
  tx: Prisma.TransactionClient,
  owner: Principal,
  hostId: string,
  selector: string,
  originPoolId: string | null = null,
  observedAt?: Date,
  overrides: VmSizeOverrides & { diskGiB?: number } = {},
  resolved?: { revision: Awaited<ReturnType<typeof resolveTemplateRevision>>; size: VmSize },
  credential: CredentialPlacementContext | null = null,
) {
  await lockOwnerPlacement(tx, owner.ownerId);
  const revision = resolved?.revision ?? (await resolveTemplateRevision(tx, owner, selector));
  const size =
    resolved?.size ??
    resolveVmSize(
      {
        cpuCount: revision.cpuCount,
        memoryMiB: revision.memoryMiB,
        diskGiB: revision.defaultDiskGiB,
      },
      overrides,
    );
  await authorizeServiceAction(
    owner,
    "sandboxes.create",
    { sandboxHostId: hostId, templateRevisionId: revision.id, originPoolId },
    tx,
  );
  assertDiskFitsImage(revision, size.diskGiB);
  // Direct host targeting stays owner-only. A pool target must be resolved
  // from the active member relation while G is already held.
  const owned = await tx.sandboxHost.findFirst({
    where: { id: hostId, ...(originPoolId ? {} : { userId: owner.ownerId }) },
    select: { id: true, userId: true },
  });
  if (!owned) throw hostNotFound();
  const hostOwnerId = owned.userId;
  if (originPoolId) {
    const { pool } = await requirePoolUse(tx, owner, originPoolId);
    requirePlacementPrincipals(tx, [owner.ownerId, pool.userId, hostOwnerId]);
    const member = await tx.sandboxPoolMember.findFirst({
      where: {
        poolId: originPoolId,
        sandboxHostId: hostId,
        hostOwnerId,
        enabled: true,
        removedAt: null,
      },
      select: { id: true },
    });
    if (!member) throw hostNotFound();
  }
  const target = await selectDirectTarget(tx, {
    ownerId: owner.ownerId,
    hostId,
    hostOwnerId,
    size,
    observedAt,
    credential,
    image: async (host, now) => {
      await tx.$queryRaw`SELECT id FROM sandbox_logical_template WHERE id = ${revision.templateId} AND "userId" = ${owner.ownerId} FOR SHARE`;
      await tx.$queryRaw`SELECT id FROM sandbox_template_revision WHERE id = ${revision.id} AND "userId" = ${owner.ownerId} FOR SHARE`;
      const availability = await tx.sandboxTemplateAvailability.findFirst({
        where: {
          revisionId: revision.id,
          hostId,
          userId: owner.ownerId,
          localFingerprint: revision.incusFingerprint,
          architecture: revision.architecture,
          manifestDigest: revision.manifestDigest,
          verifiedConnectionEpoch: host.connectionEpoch,
        },
        select: { id: true, status: true },
      });
      // A distributed foreign copy is reused only while its access holds
      // (round-2 P1-1); otherwise it counts as missing here.
      const status =
        availability?.status === "AVAILABLE" &&
        hostOwnerId !== owner.ownerId &&
        (
          await tx.$queryRaw<{ ok: boolean }[]>`
              SELECT ${foreignCopyUsableSql(owner.ownerId, revision.incusFingerprint)} AS ok
              FROM sandbox_host h WHERE h.id = ${hostId} AND h."userId" = ${hostOwnerId}`
        )[0]?.ok !== true
          ? "MISSING"
          : availability?.status;
      // No current verified copy: the image may still be fetchable to this host
      // (docs/operations/templates.md#image-distribution). Never on a REJECTED row.
      let imageFetch: ImageFetchPlan | null = null;
      if (status !== "AVAILABLE" && status !== "REJECTED") {
        const pool = originPoolId
          ? await tx.sandboxPool.findFirst({
              where: { id: originPoolId },
              select: { userId: true, memberImageCacheMaxGiB: true },
            })
          : null;
        imageFetch = await directFetchDecision(tx, {
          ownerId: owner.ownerId,
          hostId,
          hostOwnerId,
          revision,
          daemonFeatures: host.daemonFeatures,
          now,
          poolOwnerId: pool?.userId ?? null,
          memberCapGiB: pool?.memberImageCacheMaxGiB ?? null,
        });
      }
      if (!imageFetch) {
        if (status === "MISSING") throw templateImageMissing();
        if (status !== "AVAILABLE")
          throw templateImageRejected("Exact revision is not verified on this host connection.");
      }
      return imageFetch;
    },
  });
  const { connectionEpoch: _epoch, ...admitted } = target;
  return { revision, ...admitted };
}

export type DirectTargetInput = {
  ownerId: string;
  hostId: string;
  hostOwnerId: string;
  size: VmSize;
  observedAt?: Date;
  credential?: CredentialPlacementContext | null;
  /** Create only: the image half of the admission (availability or a fetch
   * plan), run under H after the journal-key ack and before the fit checks.
   * A restore fetches its stored disk and passes none. */
  image?: (
    host: { connectionEpoch: number; daemonFeatures: Prisma.JsonObject },
    now: Date,
  ) => Promise<ImageFetchPlan | null>;
};

/**
 * Authorization-neutral direct target admission:
 * takes H for `hostId` (the caller proved the host owner and any pool member
 * and holds owner placement), then requires current launch admission
 * evidence, the credential host rule, an active egress guard lease, the
 * journal-key ack, VM size support and a storage pool with room for the
 * root. It authorizes nothing: `resolveDirectPlacement` (create) authorizes
 * `sandboxes.create` first; restore admission authorizes its own intent.
 */
export async function selectDirectTarget(tx: Prisma.TransactionClient, input: DirectTargetInput) {
  const { hostId, hostOwnerId, size, credential = null } = input;
  const owner = { ownerId: input.ownerId };
  await lockAdmissionHost(tx, hostId, hostOwnerId);
  await lockWorkAdmissionHost(tx, hostId, hostOwnerId);
  const now = input.observedAt ?? (await deviceDatabaseNow(tx));
  const host = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: hostOwnerId },
    select: {
      status: true,
      lastHeartbeatAt: true,
      connectionEpoch: true,
      admissionEpoch: true,
      inventoryAcknowledgedEpoch: true,
      daemonSchedulable: true,
      daemonFeatures: true,
      daemonVcpuBudget: true,
      vcpuReserved: true,
      rootCount: true,
      liveCount: true,
      memoryReservedMiB: true,
      daemonMemoryBudgetMiB: true,
      daemonMaxCpuCount: true,
      admissionRuntime: true,
      egressEnforcement: true,
      daemonMaxLeaseMs: true,
      daemonOpenEgressForOthers: true,
      daemonGuestSudoForOthers: true,
      daemonEgressGuardOk: true,
      daemonEgressGuardEpoch: true,
      daemonEgressGuardLeaseUntil: true,
    },
  });
  const age = host?.lastHeartbeatAt ? now.getTime() - host.lastHeartbeatAt.getTime() : -1;
  if (host && !host.egressEnforcement) throw unsupportedCapability("egress");
  if (
    host?.status !== "CONNECTED" ||
    age < 0 ||
    age > HOST_HEARTBEAT_STALE_AFTER_MS ||
    host.admissionEpoch !== host.connectionEpoch ||
    host.inventoryAcknowledgedEpoch !== host.connectionEpoch ||
    host.daemonSchedulable !== true ||
    host.daemonVcpuBudget === null ||
    host.daemonMemoryBudgetMiB === null ||
    host.daemonMaxCpuCount === null ||
    !["FAKE", "INCUS_KVM"].includes(host.admissionRuntime ?? "") ||
    !host.egressEnforcement ||
    !host.daemonFeatures ||
    typeof host.daemonFeatures !== "object" ||
    Array.isArray(host.daemonFeatures) ||
    host.daemonFeatures.egressPolicy !== true
  )
    throw hostUnavailable("Host has no current launch admission evidence.");
  // CLI logins (§8): a foreign host (including a pool member, which drops
  // the owner filter above) needs every attached login opted in, and every
  // target needs the credential capability.
  requireCredentialHost(credential, {
    ownerId: owner.ownerId,
    hostOwnerId,
    daemonFeatures: host.daemonFeatures,
  });
  // M11/M18: no active egress guard lease → never a candidate, in either
  // mode (old daemons never report one: refused, not downgraded).
  if (!egressGuardLeased(host, now)) throw egressRefused("egress_guard_unavailable");
  await requireHostJournalKeyAck(tx, hostId, hostOwnerId);
  const imageFetch = input.image
    ? await input.image(
        { connectionEpoch: host.connectionEpoch, daemonFeatures: host.daemonFeatures },
        now,
      )
    : null;
  if (
    size.cpuCount > host.daemonMaxCpuCount ||
    size.memoryMiB >
      Math.min(
        VM_SIZE_LIMITS.memoryMiBMax,
        host.daemonMemoryBudgetMiB - VM_SIZE_LIMITS.vmHostOverheadMiB,
      )
  )
    throw vmSizeUnsupported();
  // No healthy, current storage pool reported right now.
  if (!(await selectStoragePool(tx, hostId, hostOwnerId, host.connectionEpoch)))
    throw hostCapacityConflict("storage", true);
  const supportedDisk = await tx.sandboxHostStoragePool.findFirst({
    where: {
      sandboxHostId: hostId,
      userId: hostOwnerId,
      connectionEpoch: host.connectionEpoch,
      capacityGiB: { gte: vmRootChargeGiB(size.diskGiB) },
    },
    select: { id: true },
  });
  if (!supportedDisk) throw vmSizeUnsupported();
  requireHostVmCapacity(host, size, false, undefined, true);
  const storagePool = await selectStoragePool(
    tx,
    hostId,
    hostOwnerId,
    host.connectionEpoch,
    vmRootChargeGiB(size.diskGiB),
  );
  // A pool can hold this root (`supportedDisk` above); free space is short now.
  if (!storagePool) throw hostCapacityConflict("disk", true);
  // Read under H: the host lease ceiling writer (hello/report) takes H too.
  return {
    size,
    storagePool,
    hostOwnerId,
    connectionEpoch: host.connectionEpoch,
    hostMaxLeaseMs: host.daemonMaxLeaseMs,
    imageFetch,
    // Read under H: the host facts the effective egress policy is resolved from at materialization.
    egressHost: {
      ownerId: hostOwnerId,
      egressOpen: host.daemonFeatures.egressOpen === true,
      openEgressForOthers: host.daemonOpenEgressForOthers,
    } satisfies EgressHostFacts,
    // Read under H: the guestSudo resolver's facts (current admission only).
    guestSudoHost: {
      ownerId: hostOwnerId,
      guestSudo: host.daemonFeatures.guestSudo === true,
      guestSudoForOthers: host.daemonGuestSudoForOthers,
    } satisfies GuestSudoHostFacts,
  };
}
