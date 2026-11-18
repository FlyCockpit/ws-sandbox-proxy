import { ORPCError } from "@orpc/server";
import { HOST_HEARTBEAT_STALE_AFTER_MS } from "@wssp/config/host-status";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import {
  type AuthorityChangeHold,
  authorityTicket,
  holdAuthorityChange,
  withAuthorityChange,
} from "@wssp/db/authority";
import {
  type HostAgentAccess,
  hostStoragePoolSchema,
  policyReconcilerHealthSchema,
  VM_SIZE_LIMITS,
} from "@wssp/sandbox-contracts";
import {
  digestHostTokenSecret,
  generateHostTokenSecret,
  hostTokenLookupPrefix,
} from "../../lib/host-token-access";
import {
  isOwnerCredentialPolicySatisfied,
  ownerCredentialPolicyUserSelect,
} from "../../lib/owner-credential-policy";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../../lib/pagination";
import { isPrismaForeignKeyViolation, isPrismaUniqueViolation } from "../../lib/prisma-errors";
import {
  authorizeServiceAction,
  serviceProcedure,
  serviceResourceFilter,
} from "../../lib/sdk-key-access";
import { getForcedTwoFactorSettingsRecord } from "../../lib/two-factor-policy";
import { notifyCapacityChanged } from "../capacity-queue-wake";
import type {
  CreateHostInput,
  CreateHostTokenInput,
  HostIdInput,
  ListDeviceCredentialsInput,
  ListHostsInput,
  ListHostTokensInput,
  Principal,
  RevokeDeviceCredentialInput,
  RevokeHostTokenInput,
  SetHostDrainingInput,
  UpdateHostInput,
} from "../contracts";
import { forgetOffloadedDisks, forgetSandboxOwners } from "../disk-offload/forget";
import { egressGuardLeased } from "../egress-guard";
import { readHostAgentPolicy } from "../host-access";
import {
  assertHostDeletable,
  hostDrainStatus,
  hostVmCapacity,
  lockAdmissionHost,
  STORAGE_HEALTH_STALE_MS,
  tryFinalizeTombstonedHost,
} from "../host-admission";
import { auditHostDrain, setHostDrainInTransaction } from "../host-drain";
import { readHostTerminalPolicy } from "../host-terminal-policy";
import { LEASE_UNLIMITED_DEADLINE_MS } from "../lease-limits";
import { assertOwnerHostCapacity } from "../owner-host-cap";
import { lockPoolGraph } from "../pool-locks";
import { isBrowserSession } from "../principal-kinds";
import { lockCurrentHostEpoch, RelayFenceRejected, requireRelayFence } from "../relay-fence";
import { discoverHostPaths, notifySharingAccessChanged } from "../sharing-access";
import { readContributionPool } from "./sharing";

const storageSelect = {
  id: true,
  name: true,
  marker: true,
  capacityGiB: true,
  totalBasedCapacityGiB: true,
  derivationTotalBytes: true,
  derivationFreeBytes: true,
  derivationCommittedBytes: true,
  derivationActualBytes: true,
  derivationHeadroomBytes: true,
  implicitCeilingGiB: true,
  capacitySource: true,
  draining: true,
  health: true,
  healthReason: true,
  reportedAt: true,
  diskReservedGiB: true,
  totalBytes: true,
  usedBytes: true,
  freeBytes: true,
} satisfies Prisma.SandboxHostStoragePoolSelect;
function storageView(
  row: Prisma.SandboxHostStoragePoolGetPayload<{ select: typeof storageSelect }>,
) {
  const { healthReason, reportedAt, ...fields } = row;
  const stale =
    reportedAt.getTime() > Date.now() ||
    Date.now() - reportedAt.getTime() > STORAGE_HEALTH_STALE_MS;
  const scalar = (value: bigint | null) => (value === null ? null : Number(value));
  return hostStoragePoolSchema.parse({
    ...fields,
    health: stale ? "unavailable" : fields.health,
    reason: stale ? "incomplete" : healthReason,
    reportedAt: reportedAt.toISOString(),
    derivationTotalBytes: scalar(row.derivationTotalBytes),
    derivationFreeBytes: scalar(row.derivationFreeBytes),
    derivationCommittedBytes: scalar(row.derivationCommittedBytes),
    derivationActualBytes: scalar(row.derivationActualBytes),
    derivationHeadroomBytes: scalar(row.derivationHeadroomBytes),
    totalBytes: scalar(row.totalBytes),
    usedBytes: scalar(row.usedBytes),
    freeBytes: scalar(row.freeBytes),
  });
}
const hostSelect = {
  id: true,
  userId: true,
  agentHostCommandsVetoedAt: true,
  hostTerminalVetoedAt: true,
  StoragePools: {
    where: { configured: true },
    orderBy: { marker: "asc" },
    take: VM_SIZE_LIMITS.storagePoolMax,
    select: storageSelect,
  },
  deletionRequestedAt: true,
  slug: true,
  label: true,
  status: true,
  lastConnectedAt: true,
  lastHeartbeatAt: true,
  connectionCount: true,
  daemonVcpuBudget: true,
  vcpuReserved: true,
  rootCount: true,
  memoryReservedMiB: true,
  daemonMemoryBudgetMiB: true,
  daemonMaxCpuCount: true,
  admissionEpoch: true,
  admissionReportedAt: true,
  connectionEpoch: true,
  inventoryAcknowledgedEpoch: true,
  daemonSchedulable: true,
  liveCount: true,
  draining: true,
  drainOffload: true,
  // The owner's own node: why the server refuses its inventory (E3-B-02).
  quarantinedAt: true,
  quarantineReason: true,
  egressEnforcement: true,
  daemonFeatures: true,
  daemonOpenEgressForOthers: true,
  daemonGuestSudoForOthers: true,
  daemonEgressGuardOk: true,
  daemonEgressGuardReason: true,
  daemonEgressGuardEpoch: true,
  daemonEgressGuardLeaseUntil: true,
  policyReconcilerHealth: true,
  daemonRuntime: true,
  daemonVersion: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.SandboxHostSelect;

function hostView(
  row: Prisma.SandboxHostGetPayload<{ select: typeof hostSelect }>,
  ownerId?: string,
) {
  const {
    userId: _userId,
    agentHostCommandsVetoedAt: _agentLower,
    hostTerminalVetoedAt: _terminalLower,
    policyReconcilerHealth,
    StoragePools,
    memoryReservedMiB,
    daemonMemoryBudgetMiB,
    daemonMaxCpuCount,
    admissionEpoch,
    admissionReportedAt,
    connectionEpoch,
    inventoryAcknowledgedEpoch,
    daemonSchedulable,
    daemonFeatures,
    daemonOpenEgressForOthers,
    daemonGuestSudoForOthers,
    daemonEgressGuardOk,
    daemonEgressGuardReason,
    daemonEgressGuardEpoch,
    daemonEgressGuardLeaseUntil,
    ...visible
  } = row;
  const features =
    daemonFeatures && typeof daemonFeatures === "object" && !Array.isArray(daemonFeatures)
      ? daemonFeatures
      : {};
  const capacity = hostVmCapacity(row);
  const age = row.lastHeartbeatAt ? Date.now() - row.lastHeartbeatAt.getTime() : -1;
  const health = policyReconcilerHealthSchema.safeParse(policyReconcilerHealth);
  // Explicit disclosure projection: no raw capabilities/unknown metadata.
  const agent = readHostAgentPolicy(row.id, row.userId);
  const agentAccess: HostAgentAccess =
    ownerId === row.userId
      ? {
          owned: true as const,
          hostCommands:
            !row.deletionRequestedAt &&
            !row.agentHostCommandsVetoedAt &&
            agent?.hostCommands === true,
          hostFiles:
            !row.deletionRequestedAt && !row.agentHostCommandsVetoedAt && agent?.hostFiles === true,
          ...(agent?.hostCommandMaxMs === undefined
            ? {}
            : { hostCommandMaxMs: agent.hostCommandMaxMs }),
        }
      : { owned: false as const };
  return {
    agentAccess,
    ...hostDrainStatus({ ...visible, memoryReservedMiB, vcpuReserved: row.vcpuReserved }),
    capacity: {
      ...capacity,
      reportedAt: admissionReportedAt?.toISOString() ?? null,
      current:
        capacity.current &&
        row.status === "CONNECTED" &&
        daemonSchedulable === true &&
        inventoryAcknowledgedEpoch === connectionEpoch &&
        age >= 0 &&
        age <= HOST_HEARTBEAT_STALE_AFTER_MS,
    },
    retainedRootCount: row.rootCount,
    // Default-open egress: capability, node-owner consent and guard lease.
    egressOpen: admissionEpoch === connectionEpoch && features.egressOpen === true,
    openEgressForOthers: daemonOpenEgressForOthers,
    // guestSudo consent (OD-2): the daemon default is allow.
    guestSudoForOthers: daemonGuestSudoForOthers,
    egressGuard: {
      ok: daemonEgressGuardOk && daemonEgressGuardEpoch === connectionEpoch,
      reason: daemonEgressGuardOk ? null : daemonEgressGuardReason,
      leaseActive: egressGuardLeased(
        {
          connectionEpoch,
          daemonEgressGuardOk,
          daemonEgressGuardEpoch,
          daemonEgressGuardLeaseUntil,
        },
        new Date(),
      ),
    },
    storagePools: (StoragePools ?? []).map(storageView),
    ...(health.success ? { policyReconciler: health.data } : {}),
  };
}

import { hostDeviceCredentialListSelect, hostTokenListSelect } from "../../lib/host-token-access";

const hostTokenSelect = hostTokenListSelect;

async function ownedHost(id: string, ownerId: string) {
  const row = await prisma.sandboxHost.findFirst({
    where: { id, userId: ownerId, deletionRequestedAt: null },
    select: { id: true },
  });
  if (!row) {
    throw new ORPCError("NOT_FOUND", { message: "Sandbox host not found." });
  }
  return row;
}

export const listHosts = serviceProcedure(
  { action: "hosts.list" },
  async (owner: Principal, input: ListHostsInput) => {
    if (input.excludePoolId)
      await authorizeServiceAction(owner, "pools.members", { poolId: input.excludePoolId });
    const pool = input.excludePoolId
      ? await readContributionPool(owner, input.excludePoolId)
      : null;
    const rows = await prisma.sandboxHost.findMany({
      where: withCursor(
        {
          ...serviceResourceFilter(owner, "host"),
          ...(input.excludePoolId
            ? {
                PoolMemberships: {
                  none: { poolId: input.excludePoolId, removedAt: null },
                },
              }
            : {}),
        },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: hostSelect,
    });
    await authorizeServiceAction(owner, "hosts.list");
    await pool?.check();
    return cursorPage(
      rows.map((row) => hostView(row, owner.ownerId)),
      input.limit,
      "createdAt",
    );
  },
);

/** Owner-only dashboard detail. Foreign pool use never resolves this selector. */
export const getHost = serviceProcedure(
  { action: "hosts.get", target: (input: HostIdInput) => ({ sandboxHostId: input.id }) },
  async (owner: Principal, input: HostIdInput) => {
    const row = await prisma.sandboxHost.findFirst({
      where: { id: input.id, ...serviceResourceFilter(owner, "host") },
      select: hostSelect,
    });
    if (!row) throw new ORPCError("NOT_FOUND");
    return {
      ...hostView(row, owner.ownerId),
      terminalPolicy:
        row.userId !== owner.ownerId || row.deletionRequestedAt
          ? null
          : (() => {
              const policy = readHostTerminalPolicy(row.id, owner.ownerId);
              return policy
                ? { ...policy, hostTerminal: policy.hostTerminal && !row.hostTerminalVetoedAt }
                : null;
            })(),
      lease:
        isBrowserSession(owner) && row.userId === owner.ownerId
          ? await hostLeaseView(row.id, owner.ownerId)
          : { ceilingMs: null, drain: { live: 0, unlimited: 0, emptyBy: null } },
      recentAudit:
        isBrowserSession(owner) && row.userId === owner.ownerId
          ? await prisma.hostAuditEvent.findMany({
              where: { userId: owner.ownerId, sandboxHostId: row.id },
              orderBy: [{ createdAt: "desc" }, { id: "desc" }],
              take: cursorPageInput.parse({ limit: 50 }).limit,
              select: {
                id: true,
                createdAt: true,
                actor: true,
                kind: true,
                program: true,
                state: true,
              },
            })
          : [],
      agentPolicy:
        isBrowserSession(owner) && row.userId === owner.ownerId
          ? readHostAgentPolicy(row.id, owner.ownerId)
          : null,
      agentHostCommandsVetoedAt: isBrowserSession(owner) ? row.agentHostCommandsVetoedAt : null,
      hostTerminalVetoedAt: isBrowserSession(owner) ? row.hostTerminalVetoedAt : null,
    };
  },
);

/**
 * Host lease ceiling (read-only: only the daemon sets it) and drain "empty by":
 * over sandboxes holding live resources, each ends at the earlier of the
 * deadline the host enforces and its access grace. Unlimited sandboxes
 * without grace never end on their own. Host owners already see these
 * deadlines per guest; nothing new is disclosed.
 */
async function hostLeaseView(hostId: string, ownerId: string) {
  const ceiling = await prisma.sandboxHost.findFirst({
    where: { id: hostId, userId: ownerId },
    select: { daemonMaxLeaseMs: true },
  });
  const unlimited = new Date(LEASE_UNLIMITED_DEADLINE_MS);
  const [drain] = await prisma.$queryRaw<
    { live: number; unlimited: number; emptyBy: Date | null }[]
  >`
    SELECT count(*)::int AS live,
      (count(*) FILTER (WHERE e.enforced >= ${unlimited} AND e."accessGraceUntil" IS NULL))::int AS unlimited,
      max(LEAST(e.enforced, COALESCE(e."accessGraceUntil", e.enforced)))
        FILTER (WHERE NOT (e.enforced >= ${unlimited} AND e."accessGraceUntil" IS NULL)) AS "emptyBy"
    FROM (
      SELECT COALESCE(GREATEST(s."leaseExpiresAt", COALESCE(s."leaseExpiresAtEffective", s."leaseExpiresAt")),
          s."accessGraceUntil") AS enforced, s."accessGraceUntil"
      FROM sandbox_instance s
      WHERE s."sandboxHostId" = ${hostId} AND s."hostOwnerId" = ${ownerId} AND s."liveResourcesHeld"
    ) e`;
  return {
    ceilingMs: ceiling?.daemonMaxLeaseMs ?? null,
    drain: {
      live: drain?.live ?? 0,
      unlimited: drain?.unlimited ?? 0,
      emptyBy: drain?.emptyBy ?? null,
    },
  };
}

/** Physical custody grants allocation metadata only, never creator identity or guest IO. */
export const listHostGuests = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: HostIdInput & ListHostsInput) => {
    const scope = authorityTicket({ ownerId: owner.ownerId, hostId: input.id });
    const host = await prisma.sandboxHost.findFirst({
      where: { id: input.id, userId: owner.ownerId },
      select: { id: true },
    });
    if (!host) throw new ORPCError("NOT_FOUND");
    const rows = await prisma.sandbox.findMany({
      where: withCursor(
        {
          sandboxHostId: input.id,
          hostOwnerId: owner.ownerId,
          userId: { not: owner.ownerId },
          state: { not: "DELETED" },
        },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: {
        id: true,
        state: true,
        purpose: true,
        cpuCount: true,
        memoryMiB: true,
        diskGiB: true,
        leaseExpiresAt: true,
        accessGraceUntil: true,
        createdAt: true,
      } satisfies Prisma.SandboxSelect,
    });
    if (
      !scope() ||
      !(await prisma.sandboxHost.findFirst({
        where: { id: input.id, userId: owner.ownerId },
        select: { id: true },
      }))
    )
      throw new ORPCError("NOT_FOUND");
    return cursorPage(rows, input.limit, "createdAt");
  },
);

export const listHostStoragePools = serviceProcedure(
  {
    action: "hosts.storagePools",
    target: (input: HostIdInput & ListHostsInput) => ({ sandboxHostId: input.id }),
  },
  async (owner: Principal, input: HostIdInput & ListHostsInput) => {
    const host = await prisma.sandboxHost.findFirst({
      where: { id: input.id, userId: owner.ownerId },
      select: { id: true },
    });
    if (!host) throw new ORPCError("NOT_FOUND");
    const rows = await prisma.sandboxHostStoragePool.findMany({
      where: withCursor(
        { sandboxHostId: input.id, userId: owner.ownerId },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: { ...storageSelect, createdAt: true },
    });
    await authorizeServiceAction(owner, "hosts.storagePools", { sandboxHostId: input.id });
    const page = cursorPage(rows, input.limit, "createdAt");
    return {
      ...page,
      items: page.items.map(({ createdAt: _createdAt, ...row }) => storageView(row)),
    };
  },
);

export const createHost = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: CreateHostInput) => {
    try {
      return await prisma
        .$transaction(async (tx) => {
          // C21-13: owner lock precedes the owner-row INSERT.
          await lockOwnerForAdmission(tx, owner.ownerId);
          // C52-R2-3: per-owner host cap, serialized per owner (owner → cap lock).
          await assertOwnerHostCapacity(tx, owner.ownerId);
          return tx.sandboxHost.create({
            data: {
              userId: owner.ownerId,
              slug: input.slug,
              label: input.label,
            },
            select: hostSelect,
          });
        })
        .then((row) => hostView(row, owner.ownerId));
    } catch (error) {
      if (isPrismaUniqueViolation(error)) {
        throw new ORPCError("CONFLICT", { message: "A host with this slug already exists." });
      }
      throw error;
    }
  },
);

/** Owner label edit; resource budgets belong to local node configuration. */
export const updateHost = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: UpdateHostInput) => {
    return prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, owner.ownerId);
      const owned = await tx.sandboxHost.findFirst({
        where: { id: input.id, userId: owner.ownerId },
        select: { id: true },
      });
      if (!owned) throw new ORPCError("NOT_FOUND", { message: "Sandbox host not found." });
      await lockAdmissionHost(tx, input.id, owner.ownerId);
      const data: Prisma.SandboxHostUpdateInput = {};
      if (input.label != null) data.label = input.label;
      const host =
        Object.keys(data).length === 0
          ? await tx.sandboxHost.findFirst({
              where: { id: input.id, userId: owner.ownerId },
              select: hostSelect,
            })
          : await tx.sandboxHost.update({
              where: { id: input.id, userId: owner.ownerId },
              data,
              select: hostSelect,
            });
      requireRelayFence(host != null);
      return hostView(host, owner.ownerId);
    });
  },
);

export const setHostDraining = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: SetHostDrainingInput) => {
    const current = authorityTicket({ ownerId: owner.ownerId, hostId: input.id });
    const result = await prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, owner.ownerId);
      return setHostDrainInTransaction(tx, owner.ownerId, input, async () => {
        const user = await tx.user.findUnique({
          where: { id: owner.ownerId },
          select: ownerCredentialPolicyUserSelect,
        });
        if (
          !user ||
          !(await isOwnerCredentialPolicySatisfied(
            user,
            new Date(),
            await getForcedTwoFactorSettingsRecord(tx),
          )) ||
          !current()
        )
          throw new ORPCError("FORBIDDEN");
      });
    });
    auditHostDrain(owner.ownerId, "session", result);
    // Committed: an undrained host may let waiting creates place.
    notifyCapacityChanged({ hostIds: [input.id] });
    return result;
  },
);

/** The host-deletion request (tombstone, then finalize when nothing blocks),
 * in the caller's transaction after its owner lock. Shared by delete and
 * Forget unreachable host. */
async function requestHostDeletionInTransaction(
  tx: Prisma.TransactionClient,
  owner: Principal,
  hostId: string,
  finalizationHolds: AuthorityChangeHold[],
  beforeTombstone?: () => Promise<void>,
): Promise<{ ok: true; pending: boolean }> {
  await lockOwnerForAdmission(tx, owner.ownerId);
  const row = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: owner.ownerId },
    select: { id: true },
  });
  if (row == null) {
    throw new ORPCError("NOT_FOUND", { message: "Sandbox host not found." });
  }
  const paths = await discoverHostPaths(tx, hostId, null);
  await lockPoolGraph(tx, paths.ids);
  const locked = await lockCurrentHostEpoch(tx, hostId);
  requireRelayFence(locked.userId === owner.ownerId);
  const currentPaths = await discoverHostPaths(tx, hostId, null);
  if (JSON.stringify(paths) !== JSON.stringify(currentPaths))
    throw new ORPCError("CONFLICT", {
      message: "Host memberships changed. Retry the operation.",
    });
  await beforeTombstone?.();
  await tx.sandboxPoolMember.updateMany({
    where: { sandboxHostId: hostId, hostOwnerId: owner.ownerId, removedAt: null },
    data: {
      removedAt: new Date(),
      enabled: false,
      shareId: null,
      contributeWitness: null,
      ownHostsOnlyWitness: null,
    },
  });
  await tx.sandboxHost.updateMany({
    where: { id: hostId, userId: owner.ownerId },
    data: { deletionRequestedAt: new Date() },
  });
  try {
    await assertHostDeletable(tx, hostId, owner.ownerId);
  } catch (error) {
    if (error instanceof ORPCError && error.code === "CONFLICT")
      return { ok: true as const, pending: true };
    throw error;
  }
  const finalized = await tryFinalizeTombstonedHost(tx, hostId, owner.ownerId, finalizationHolds);
  requireRelayFence(finalized);
  return { ok: true as const, pending: false };
}

/** Runs a host-deletion transaction; authority holds settle after it. */
async function withHostFinalization<T>(
  owner: Principal,
  hostId: string,
  work: (tx: Prisma.TransactionClient, holds: AuthorityChangeHold[]) => Promise<T>,
): Promise<T> {
  // An immediate finalization's authority hold settles only after THIS
  // transaction commits or rolls back, exactly like the deferred path in
  // sandboxOutboxTransaction.
  const finalizationHolds: AuthorityChangeHold[] = [
    holdAuthorityChange({ ownerId: owner.ownerId, hostId }),
  ];
  let committed = false;
  try {
    const result = await prisma.$transaction((tx) => work(tx, finalizationHolds));
    committed = true;
    notifySharingAccessChanged();
    return result;
  } finally {
    for (const hold of finalizationHolds) hold.settle(committed);
  }
}

export const deleteHost = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: HostIdInput) =>
    withHostFinalization(owner, input.id, (tx, holds) =>
      requestHostDeletionInTransaction(tx, owner, input.id, holds),
    ),
);

/**
 * Forget unreachable host: owner session
 * only, type-to-confirm in the dashboard. Sandboxes with a stored disk on
 * the host detach to OFFLOADED through the safe-detachment gate and the
 * host's stale copy rows are dropped; a possibly-live sandbox refuses the
 * whole request (`sandbox.host_forget_unsafe`, listed). Then the host is
 * deleted like `deleteHost`: anything else still on it keeps it pending.
 * Never writes DELETED.
 */
export const forgetHost = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: HostIdInput) =>
    withHostFinalization(owner, input.id, async (tx, holds) => {
      const owned = await tx.sandboxHost.findFirst({
        where: { id: input.id, userId: owner.ownerId },
        select: { id: true },
      });
      if (!owned) throw new ORPCError("NOT_FOUND", { message: "Sandbox host not found." });
      // Every owner of a sandbox the forget may detach, in id order, before
      // the host lock (cleanup locks: a deleting owner's rows still detach).
      const owners = new Set([owner.ownerId, ...(await forgetSandboxOwners(tx, input.id))]);
      await tx.$queryRaw`SELECT id FROM "user" WHERE id = ANY(${[...owners].sort()}::text[]) ORDER BY id FOR SHARE`;
      let forgotten = { detached: 0, copiesForgotten: 0 };
      const result = await requestHostDeletionInTransaction(
        tx,
        owner,
        input.id,
        holds,
        async () => {
          forgotten = await forgetOffloadedDisks(tx, input.id, owners);
        },
      );
      return { ...result, ...forgotten };
    }),
);

type HostTokenListRow = Prisma.HostTokenGetPayload<{ select: typeof hostTokenSelect }>;
type DeviceCredentialListRow = Prisma.HostDeviceCredentialGetPayload<{
  select: typeof hostDeviceCredentialListSelect;
}>;

/** Browser projection: the credential's metadata plus its host summary. */
function serializeHostToken({ SandboxHost, ...token }: HostTokenListRow) {
  return { ...token, host: SandboxHost };
}

function serializeDeviceCredential({ SandboxHost, ...credential }: DeviceCredentialListRow) {
  return { ...credential, host: SandboxHost };
}

export const listHostTokens = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: ListHostTokensInput) => {
    const hostId = input.hostId;
    const rows = await prisma.hostToken.findMany({
      where: withCursor(
        {
          userId: owner.ownerId,
          ...(hostId ? { sandboxHostId: hostId, SandboxHost: { userId: owner.ownerId } } : {}),
          ...(input.includeRevoked ? {} : { revokedAt: null }),
        },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: hostTokenSelect,
    });
    const page = cursorPage(rows, input.limit, "createdAt");
    return { items: page.items.map(serializeHostToken), nextCursor: page.nextCursor };
  },
);

/** `wssp host enroll` device credentials. Minted only by the device exchange (C19). */
export const listDeviceCredentials = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: ListDeviceCredentialsInput) => {
    const hostId = input.hostId;
    const rows = await prisma.hostDeviceCredential.findMany({
      where: withCursor(
        {
          userId: owner.ownerId,
          SandboxHost: { userId: owner.ownerId },
          ...(hostId ? { sandboxHostId: hostId } : {}),
          ...(input.includeRevoked ? {} : { revokedAt: null }),
        },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: hostDeviceCredentialListSelect,
    });
    const page = cursorPage(rows, input.limit, "createdAt");
    return { items: page.items.map(serializeDeviceCredential), nextCursor: page.nextCursor };
  },
);

/**
 * Revoke one device credential. Like host tokens, the authority change closes
 * any socket that authenticated with it (session-manager revalidation) and the
 * next `wssp host run` with it fails; the host itself is untouched.
 */
export const revokeDeviceCredential = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: RevokeDeviceCredentialInput) => {
    // Unknown ids answer before the change: each change keys process memory by id.
    const known = await prisma.hostDeviceCredential.findFirst({
      where: { id: input.id, userId: owner.ownerId, revokedAt: null },
      select: { id: true },
    });
    if (!known) throw new ORPCError("NOT_FOUND", { message: "Device credential not found." });
    return withAuthorityChange({ ownerId: owner.ownerId, credentialId: input.id }, () =>
      prisma.$transaction(async (tx) => {
        const updated = await tx.hostDeviceCredential.updateMany({
          where: { id: input.id, userId: owner.ownerId, revokedAt: null },
          data: { revokedAt: new Date() },
        });
        if (updated.count === 0)
          throw new ORPCError("NOT_FOUND", { message: "Device credential not found." });
        const row = await tx.hostDeviceCredential.findFirstOrThrow({
          where: { id: input.id, userId: owner.ownerId },
          select: hostDeviceCredentialListSelect,
        });
        return serializeDeviceCredential(row);
      }),
    );
  },
);

export const createHostToken = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: CreateHostTokenInput) => {
    const host = await ownedHost(input.hostId, owner.ownerId);
    const credential = generateHostTokenSecret();
    try {
      const token = await prisma.$transaction(async (tx) => {
        // C21-13 owner lock, then C21-11 enrollment admission (tombstone rejects).
        await lockOwnerForAdmission(tx, owner.ownerId);
        await lockAdmissionHost(tx, host.id, owner.ownerId);
        return tx.hostToken.create({
          data: {
            userId: owner.ownerId,
            sandboxHostId: host.id,
            name: input.name,
            lookupPrefix: hostTokenLookupPrefix(credential),
            secretDigest: digestHostTokenSecret(credential),
            expiresAt: input.expiresAt ?? null,
          },
          select: hostTokenSelect,
        });
      });
      return { token: serializeHostToken(token), secret: credential.raw };
    } catch (error) {
      if (error instanceof RelayFenceRejected)
        throw new ORPCError("CONFLICT", { message: "Host changed during token mint." });
      if (isPrismaForeignKeyViolation(error)) {
        throw new ORPCError("CONFLICT", {
          message: "Host was removed during token mint.",
        });
      }
      throw error;
    }
  },
);

export const revokeHostToken = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: RevokeHostTokenInput) => {
    // Unknown ids answer before the change: each change keys process memory by id.
    const known = await prisma.hostToken.findFirst({
      where: { id: input.id, userId: owner.ownerId, revokedAt: null },
      select: { id: true },
    });
    if (!known) throw new ORPCError("NOT_FOUND", { message: "Host token not found." });
    return withAuthorityChange({ ownerId: owner.ownerId, credentialId: input.id }, () =>
      prisma.$transaction(async (tx) => {
        const updated = await tx.hostToken.updateMany({
          where: { id: input.id, userId: owner.ownerId, revokedAt: null },
          data: { revokedAt: new Date() },
        });
        if (updated.count === 0)
          throw new ORPCError("NOT_FOUND", { message: "Host token not found." });
        const row = await tx.hostToken.findFirstOrThrow({
          where: { id: input.id, userId: owner.ownerId },
          select: hostTokenSelect,
        });
        return serializeHostToken(row);
      }),
    );
  },
);

export {
  liftAgentHostCommandsVeto,
  liftHostTerminalVeto,
  lowerAgentHostCommands,
  lowerHostTerminal,
} from "./host-policy";
