import { ORPCError } from "@orpc/server";
import prisma, { type Prisma, type SandboxState } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { Prisma as PrismaValue } from "@wssp/db/client";
import {
  CAPACITY_WAIT_MAX_MS,
  type CapacityWaitRequest,
  type OperationErrorCode,
  VM_SIZE_LIMITS,
  vmLiveMemoryChargeMiB,
  vmRootChargeGiB,
} from "@wssp/sandbox-contracts";
import { credentialError } from "../../credentials/errors";
import { writeLaunchSpec } from "../../credentials/launch";
import { sandboxCredentialPlacementContext } from "../../credentials/placement";
import { assertOffloadedCredentialDrain, claimResumeLeases } from "../../credentials/resume";
import type { CredentialClaimRequest } from "../../credentials/selection";
import { preflightCredentialSpec } from "../../credentials/specs";
import {
  authorizeRestoreIntent,
  authorizeServiceAction,
  type RestoreIntentShape,
} from "../../lib/sdk-key-access";
import { deploymentWaitMaxMs } from "../capacity-limits";
import type { CapacityHint } from "../capacity-queue-wake";
import { OPERATION_DISPATCH_KIND, type Principal, sessionPrincipal } from "../contracts";
import { digestContextSnapshot, RESTORE_INTENT_DIGEST_DOMAIN } from "../digest-context";
import { lockOwnerPlacement, selectDirectTarget } from "../direct-placement";
import { recordedEgressPolicy } from "../egress-policy";
import { restoreNoAllowedHost, sandboxStateConflict } from "../errors";
import { reserveLiveResources, reserveRootResources } from "../host-admission";
import { privateConfigBinding, requestDigestMetadata } from "../idempotency";
import { defaultIncusInstanceName } from "../incus-name";
import {
  acceptedLeaseFields,
  type LeaseClock,
  leaseTransactionNow,
  rememberedLeaseTimeoutMs,
  resolveLeaseTimeout,
} from "../lease";
import { leaseRequestOf, readLockedPathLimit, requireLeaseWithinPolicy } from "../lease-policy";
import { createSandboxOutboxEvent, sandboxOutboxTransaction } from "../outbox";
import { lockPoolGraph } from "../pool-locks";
import {
  PLACEMENT_STAGES,
  type PlacementStage,
  revisionNeedsStartup,
  selectPoolTarget,
} from "../pool-placement";
import { attributionOf, type PlacementViewer, recordedKeyIdOf, viewerOf } from "../principal-kinds";
import { hostDatabaseNow, lockCurrentHostEpoch, retireSupersededOperations } from "../relay-fence";
import { safeOperationError } from "../sensitive-errors";
import {
  discoverPlacementPrincipals,
  lockPlacementPrincipals,
  requirePlacementPrincipals,
  requirePoolUse,
} from "../sharing-authority";
import { requirePoolMemberAcquisition, requirePoolShareAcquisition } from "../sharing-quota";
import { resolveStoredPrincipal } from "../stored-principal";
import { detachToOffloaded, hostOnline, staleCopyIdentity, staleDetachSafe } from "./detach";
import {
  RESTORE_SANDBOX_FACTS_SELECT,
  type RestoreHostRestriction,
  restoreHostEligibility,
} from "./eligibility";
import {
  PERMANENT_RESTORE_LOGIN_CODES,
  TRANSIENT_RESTORE_LOGIN_CODES,
} from "./restore-login-codes";
import { supersedeLiveOffload } from "./store";

/**
 * Restore admission of an `OFFLOADED` sandbox. Split in two (V3):
 *
 * - `acceptRestore`, in the reconnect's `operationTransaction` callback,
 *   creates the RECONNECT_SANDBOX operation with its immutable
 *   `launchMode = NEW_ROOT`, `restoreOffloadId` and hostless
 *   `restore-intent:v1` digest snapshot, then places it at once or records
 *   a durable `SandboxRestoreWait`;
 * - `placeRestore` resumes a waiting restore (the restore-wait pass, on the
 *   capacity scheduler's wake and timer) after re-validating the stored
 *   principal and the sandbox CAS.
 *
 * Placement never calls `materializePlacement` (no REQUESTED, no
 * CREATE_SANDBOX, no egress re-resolution, no fresh config, no
 * `originHostId` rewrite): it inserts a POOL/DIRECT placement of generation
 * g + 1 with `restoreOffloadId` provenance, binds the sandbox to the target,
 * reserves a new root and the live charge, rebinds the execution config in
 * place (§8.5), keeps the recorded egress byte-identical, writes
 * OFFLOADED → PROVISIONING and the outbox dispatch. `Sandbox.originHostId`,
 * `originPoolId`, `templateRevisionId` and the CREATE operation are history
 * and are never rewritten (R14).
 *
 * Lock order: owner(s) (placement principals) → K → G (pool graph) → H
 * (exactly one target host) → S → O.
 */

type Tx = Prisma.TransactionClient;

/** The one state a restore leaves (written only by `detachToOffloaded`). */
const RESTORABLE_STATE = "OFFLOADED" satisfies SandboxState;

/** The normalized restore request (the private `SandboxRestoreWait.intent`). */
type RestoreRequest = {
  timeoutMs: number;
  credentials?: readonly CredentialClaimRequest[];
  target: { hostId: string } | { poolId: string } | null;
  waitForCapacityMs?: CapacityWaitRequest;
  overrideCreatorAllowlist: boolean;
};

/** A reconnect's restore request; omitted `timeoutMs` is the sandbox's
 * remembered lease (`rememberedLeaseTimeoutMs`), resolved by `acceptRestore`. */
export type RestoreRequestInput = Omit<RestoreRequest, "timeoutMs"> & { timeoutMs?: number };

const intentSchema = {
  parse(value: Prisma.JsonValue | null): RestoreRequest | null {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
    const v = value as Record<string, unknown>;
    const target =
      typeof v.hostId === "string"
        ? { hostId: v.hostId }
        : typeof v.poolId === "string"
          ? { poolId: v.poolId }
          : null;
    if (typeof v.timeoutMs !== "number") return null;
    return {
      timeoutMs: v.timeoutMs,
      target,
      overrideCreatorAllowlist: v.overrideCreatorAllowlist === true,
      ...(Array.isArray(v.credentials)
        ? { credentials: v.credentials as CredentialClaimRequest[] }
        : {}),
    };
  },
  store(request: RestoreRequest): Prisma.InputJsonObject {
    return {
      timeoutMs: request.timeoutMs,
      ...(request.target && "hostId" in request.target ? { hostId: request.target.hostId } : {}),
      ...(request.target && "poolId" in request.target ? { poolId: request.target.poolId } : {}),
      overrideCreatorAllowlist: request.overrideCreatorAllowlist,
      ...(request.credentials?.length
        ? {
            credentials: request.credentials.map((pin) => ({
              credentialId: pin.credentialId,
              ...(pin.accountId ? { accountId: pin.accountId } : {}),
              ...(pin.instanceId ? { instanceId: pin.instanceId } : {}),
            })),
          }
        : {}),
    };
  },
};

const restoreSandboxSelect = {
  ...RESTORE_SANDBOX_FACTS_SELECT,
  state: true,
  generation: true,
  diskOffloadId: true,
  templateRevisionId: true,
  originPoolId: true,
  cpuCount: true,
  memoryMiB: true,
  leaseRevision: true,
  leaseExpireAction: true,
  egressPolicy: true,
  egressPolicyHash: true,
  buildId: true,
  verifyBuildId: true,
} satisfies Prisma.SandboxSelect;

type RestoreSandbox = Prisma.SandboxGetPayload<{ select: typeof restoreSandboxSelect }>;

/** A selected, locked destination (H held; G held for a pool target). */
type RestoreTarget = {
  hostId: string;
  hostOwnerId: string;
  poolId: string | null;
  memberId: string | null;
  poolOwnerId: string | null;
  originShareId: string | null;
  acceptedGraceSeconds: number;
  storagePool: { id: string; marker: string; name: string };
};

/** Pool stages a restore needs: no template image stages (the root comes
 * from the stored disk) and no builder (managed sandboxes never offload). */
const RESTORE_POOL_STAGES: readonly PlacementStage[] = PLACEMENT_STAGES.filter(
  (stage) => stage !== "templateKnown" && stage !== "templateCurrent" && stage !== "builder",
);
/** Own-host candidates one page of a selection reads. */
const OWN_HOST_CANDIDATES = 64;
/** Own-host candidates one selection scans at most (pages of
 * `OWN_HOST_CANDIDATES`): an ineligible head never hides a later host. */
const OWN_HOST_SCAN_MAX = 1024;

/** The private intent's target, normalized. */
function targetOf(input: { sandboxHostId?: string; poolId?: string }): RestoreRequest["target"] {
  if (input.sandboxHostId) return { hostId: input.sandboxHostId };
  if (input.poolId) return { poolId: input.poolId };
  return null;
}

/** Build the normalized request from the reconnect input. */
export function restoreRequestOf(input: {
  timeoutMs?: number;
  credentials?: readonly CredentialClaimRequest[];
  sandboxHostId?: string;
  poolId?: string;
  waitForCapacityMs?: CapacityWaitRequest;
  overrideCreatorAllowlist?: boolean;
}): RestoreRequestInput {
  return {
    ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
    ...(input.credentials?.length ? { credentials: input.credentials } : {}),
    target: targetOf(input),
    ...(input.waitForCapacityMs !== undefined
      ? { waitForCapacityMs: input.waitForCapacityMs }
      : {}),
    overrideCreatorAllowlist: input.overrideCreatorAllowlist === true,
  };
}

function intentShape(
  request: Pick<RestoreRequest, "target" | "overrideCreatorAllowlist">,
): RestoreIntentShape {
  return { target: request.target, overrideCreatorAllowlist: request.overrideCreatorAllowlist };
}

/** `deadlineAt = now + min(waitForCapacityMs, deploymentWaitMaxMs())`
 * (§8.3c); "unlimited" is the deployment maximum (itself bounded). */
function waitDeadline(request: CapacityWaitRequest, now: Date): Date {
  const deployment = deploymentWaitMaxMs() ?? CAPACITY_WAIT_MAX_MS;
  const ms = request === "unlimited" ? deployment : Math.min(request, deployment);
  return new Date(now.getTime() + Math.max(1, ms));
}

/**
 * §5a: the restriction one candidate is checked under: the requester's own
 * grants (an SDK key's allowlists) intersected with the creating key's live
 * allowlists, unless the owner overrode the latter from the dashboard. A
 * host leg applies to the owner's own hosts only (a foreign host is reached
 * through a pool, whose pool leg decides); a direct placement passes a pool
 * leg.
 */
function candidateRestriction(
  legs: readonly ({
    hostIds: ReadonlySet<string> | null;
    poolIds: ReadonlySet<string> | null;
  } | null)[],
  candidate: { hostId: string; own: boolean; poolId: string | null },
): RestoreHostRestriction | null {
  const active = legs.filter((leg) => leg !== null);
  const hostLegs = candidate.own ? active.filter((leg) => leg.hostIds !== null) : [];
  const poolLegs = candidate.poolId === null ? [] : active.filter((leg) => leg.poolIds !== null);
  if (hostLegs.length === 0 && poolLegs.length === 0) return null;
  const hostAllowed = hostLegs.every((leg) => leg.hostIds?.has(candidate.hostId));
  const poolAllowed = poolLegs.every((leg) =>
    candidate.poolId === null ? true : leg.poolIds?.has(candidate.poolId),
  );
  return {
    hostIds: hostLegs.length ? new Set(hostAllowed ? [candidate.hostId] : []) : null,
    poolIds: poolLegs.length ? new Set(poolAllowed ? [candidate.poolId] : []) : null,
  };
}

type PlacementRestriction = {
  hostIds: ReadonlySet<string> | null;
  poolIds: ReadonlySet<string> | null;
} | null;

/** A viewer's own placement restriction: its host allowlist and pool
 * selection (null legs impose no limit; a session imposes none). */
function placementRestriction(viewer: PlacementViewer): PlacementRestriction {
  const hostIds = viewer.allowedHostIds === "allOwned" ? null : viewer.allowedHostIds;
  const poolIds = viewer.allowedPoolIds === "allUsable" ? null : viewer.allowedPoolIds;
  return hostIds === null && poolIds === null ? null : { hostIds, poolIds };
}

/**
 * §5a: the creating key's live placement restriction, read now through the
 * stored-principal resolver: the CREATE operation's `authorizingKeyId`. A
 * revoked, expired or deleted key, an unrestricted key and a session
 * creator impose none.
 */
async function creatingKeyRestriction(
  tx: Tx,
  sandbox: { id: string; userId: string; buildId: string | null; verifyBuildId: string | null },
): Promise<PlacementRestriction> {
  const creation = await tx.sandboxOperation.findFirst({
    where: { sandboxId: sandbox.id, userId: sandbox.userId, kind: "CREATE_SANDBOX" },
    orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    select: { authorizingKeyId: true },
  });
  const creator = await resolveStoredPrincipal(tx, {
    userId: sandbox.userId,
    authorizingKeyId: creation?.authorizingKeyId ?? null,
    sandboxBuildId: sandbox.buildId,
    sandboxVerifyBuildId: sandbox.verifyBuildId,
  });
  return creator ? placementRestriction(viewerOf(creator)) : null;
}

/**
 * Select and lock the restore destination for `principal` (§5 order 2):
 * the owner's own hosts (direct), then the origin pool (or the hint).
 * Candidates pass `restoreHostEligibility` under the candidate restriction
 * and the requester's destination grants before anything is locked or
 * reserved (a refused destination is skipped, never reserved and released).
 * Then exactly one H is locked (after G for a pool) and the admission
 * re-checked. The outcome is typed: a target, a transient login refusal
 * (`credential.host_forbidden` from the target's credential host rule), or
 * capacity (no candidate, or an admission refusal such as a lost capacity
 * race at H): only the last is a capacity verdict.
 */
async function selectRestoreTarget(
  tx: Tx,
  principal: Principal,
  sandbox: RestoreSandbox,
  request: RestoreRequest,
): Promise<RestoreSelection> {
  const seen: AdmissionRefusals = { login: null };
  const target = await selectRestoreTargetOrNull(tx, principal, sandbox, request, seen);
  if (target) return { kind: "target", target };
  return seen.login ? { kind: "login", code: seen.login } : { kind: "capacity" };
}

type RestoreSelection =
  | { kind: "target"; target: RestoreTarget }
  | { kind: "login"; code: TransientRestoreLoginCode }
  | { kind: "capacity" };

/** The transient login refusal an admission step swallowed, if any. */
type AdmissionRefusals = { login: TransientRestoreLoginCode | null };

async function selectRestoreTargetOrNull(
  tx: Tx,
  principal: Principal,
  sandbox: RestoreSandbox,
  request: RestoreRequest,
  seen: AdmissionRefusals,
): Promise<RestoreTarget | null> {
  const ownerId = sandbox.userId;
  await lockOwnerPlacement(tx, ownerId);
  const viewer = viewerOf(principal);
  const requester = placementRestriction(viewerOf(principal));
  const creator = request.overrideCreatorAllowlist
    ? null
    : await creatingKeyRestriction(tx, sandbox);
  const legs = [requester, creator];
  const size = {
    cpuCount: sandbox.cpuCount,
    memoryMiB: sandbox.memoryMiB,
    diskGiB: sandbox.diskGiB,
  };
  const charge = vmLiveMemoryChargeMiB(size.memoryMiB);
  const root = vmRootChargeGiB(size.diskGiB);
  const now = await hostDatabaseNow(tx);
  const hint = request.target;
  // Declared tunnel ports ride the restore's dispatch: only daemons that
  // compile them into the network plan can take it.
  const tunnelGate = sandbox.tunnelEnabled
    ? PrismaValue.sql`AND h."daemonTunnelPorts"`
    : PrismaValue.empty;
  const poolId = hint && "poolId" in hint ? hint.poolId : hint ? null : sandbox.originPoolId;
  // G before any H: the pool path the lease policy reads (own host: the
  // origin pool) and the pool a pool target is placed through.
  await lockPoolGraph(
    tx,
    [sandbox.originPoolId, poolId].filter((id): id is string => typeof id === "string"),
  );
  const facts = sandbox;
  // CLI logins (§4 safeguard 2, §8.3): the attached logins narrow the
  // candidates exactly as a create's do (foreign opt-in, the credential
  // capability); the claim gate at bind re-reads them under their locks.
  const credential = await sandboxCredentialPlacementContext(tx, sandbox.id);
  // 1. Own hosts (direct placements), unless the hint names a pool.
  if (!(hint && "poolId" in hint)) {
    const hostFilter =
      hint && "hostId" in hint ? PrismaValue.sql`AND h.id = ${hint.hostId}` : PrismaValue.empty;
    // Pages by host id: an ineligible head (e.g. no disk offload) never
    // hides an eligible host behind it; the scan stays bounded.
    let after = "";
    for (let scanned = 0; scanned < OWN_HOST_SCAN_MAX; scanned += OWN_HOST_CANDIDATES) {
      const own = await tx.$queryRaw<{ id: string }[]>`
        SELECT h.id FROM sandbox_host h
        WHERE h."userId" = ${ownerId} AND h.status::text = 'CONNECTED'
          AND h."deletionRequestedAt" IS NULL ${hostFilter} AND h.id > ${after}
          AND h."daemonDiskOffload" ${tunnelGate}
          AND h."daemonMemoryBudgetMiB" IS NOT NULL AND h."daemonVcpuBudget" IS NOT NULL
          AND h."memoryReservedMiB"::bigint + ${charge}::bigint <= h."daemonMemoryBudgetMiB"
          AND h."vcpuReserved" + ${size.cpuCount} <= h."daemonVcpuBudget"
          AND h."rootCount" < ${VM_SIZE_LIMITS.hostManagedSandboxCeiling}
          AND EXISTS (SELECT 1 FROM sandbox_host_storage_pool p
            WHERE p."sandboxHostId" = h.id AND p."userId" = h."userId"
              AND p."connectionEpoch" = h."connectionEpoch" AND p."newRootsAllowed"
              AND p.health = 'healthy' AND NOT p.draining
              AND p."capacityGiB" - p."diskReservedGiB" >= ${root})
        ORDER BY h.id ASC LIMIT ${OWN_HOST_CANDIDATES}`;
      for (const host of own) {
        const restriction = candidateRestriction(legs, {
          hostId: host.id,
          own: true,
          poolId: null,
        });
        if (!(await restoreHostEligibility(tx, facts, { hostId: host.id }, restriction, now)).ok)
          continue;
        // Destination grant for the requester (§8.3b): an owned host it may use.
        if (viewer.allowedHostIds !== "allOwned" && !viewer.allowedHostIds.has(host.id)) continue;
        requirePlacementPrincipals(tx, [ownerId]);
        const admitted = await admitOrNull(
          () =>
            selectDirectTarget(tx, {
              ownerId,
              hostId: host.id,
              hostOwnerId: ownerId,
              size,
              credential,
            }),
          seen,
        );
        if (!admitted) return null;
        return {
          hostId: host.id,
          hostOwnerId: ownerId,
          poolId: null,
          memberId: null,
          poolOwnerId: null,
          originShareId: null,
          acceptedGraceSeconds: 0,
          storagePool: admitted.storagePool,
        };
      }
      const last = own.at(-1);
      if (!last || own.length < OWN_HOST_CANDIDATES) break;
      after = last.id;
    }
    if (hint) return null;
  }
  // 2. The origin pool (or the hinted one).
  if (!poolId) return null;
  // The requester's pool use grant (and its share quota on acquisition).
  const pooled = await admitOrNull(() => requirePoolUse(tx, principal, poolId), seen);
  if (!pooled) return null;
  const revision = await tx.sandboxTemplateRevision.findFirst({
    where: { id: sandbox.templateRevisionId, userId: ownerId },
    select: { id: true, incusFingerprint: true, architecture: true, manifestDigest: true },
  });
  if (!revision) return null;
  const selected = await selectPoolTarget(
    tx,
    {
      viewer,
      poolId,
      revision,
      size,
      now,
      lease: leaseRequestOf(request.timeoutMs),
      plan: null,
      startup: await revisionNeedsStartup(tx, ownerId, revision.id, null),
      credential,
    },
    {
      stages: RESTORE_POOL_STAGES,
      // Restore eligibility's capability gate in SQL; the rest per candidate.
      where: PrismaValue.sql`h."daemonDiskOffload" ${tunnelGate}`,
      admit: async (candidate) => {
        const own = candidate.hostOwnerId === ownerId;
        const restriction = candidateRestriction(legs, { hostId: candidate.id, own, poolId });
        return (
          await restoreHostEligibility(
            tx,
            facts,
            { hostId: candidate.id, poolId },
            restriction,
            now,
          )
        ).ok;
      },
    },
  );
  if (!selected) return null;
  const added = {
    memoryMiB: BigInt(charge),
    vcpu: BigInt(size.cpuCount),
    diskGiB: BigInt(root),
  };
  const context = await admitOrNull(
    () => requirePoolShareAcquisition(tx, principal, poolId, added),
    seen,
  );
  if (!context) return null;
  requirePlacementPrincipals(tx, [ownerId, context.pool.userId, selected.hostOwnerId]);
  const admitted = await admitOrNull(async () => {
    const target = await selectDirectTarget(tx, {
      ownerId,
      hostId: selected.id,
      hostOwnerId: selected.hostOwnerId,
      size,
      credential,
    });
    await requirePoolMemberAcquisition(
      tx,
      {
        poolId,
        memberId: selected.memberId,
        hostId: selected.id,
        hostOwnerId: selected.hostOwnerId,
        newRoot: true,
      },
      added,
    );
    return target;
  }, seen);
  if (!admitted) return null;
  return {
    hostId: selected.id,
    hostOwnerId: selected.hostOwnerId,
    poolId,
    memberId: selected.memberId,
    poolOwnerId: context.pool.userId,
    originShareId: context.share?.id ?? null,
    acceptedGraceSeconds: context.pool.disconnectGraceSeconds,
    storagePool: admitted.storagePool,
  };
}

/** An admission refusal (capacity, quota, a lost race, a login's host
 * rule) means "no target now", never a failed request; a transient login
 * refusal is noted in `seen`; database errors still propagate. */
async function admitOrNull<T>(work: () => Promise<T>, seen: AdmissionRefusals): Promise<T | null> {
  try {
    return await work();
  } catch (error) {
    if (!(error instanceof ORPCError)) throw error;
    seen.login = knownCode(TRANSIENT_RESTORE_LOGIN_CODES, refusalCode(error)) ?? seen.login;
    return null;
  }
}

/** S, then the restore CAS facts. */
async function lockRestoreSandbox(tx: Tx, ownerId: string, sandboxId: string) {
  await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} AND "userId" = ${ownerId} FOR NO KEY UPDATE`;
  return tx.sandbox.findFirst({
    where: { id: sandboxId, userId: ownerId },
    select: restoreSandboxSelect,
  });
}

/**
 * Bind an accepted restore operation to its locked target (§8.3 items
 * 2.1, 2.3–2.9, §8.5). The caller holds owner → G → H → S and passed the
 * CAS facts read under S.
 */
async function bindRestore(
  tx: Tx,
  principal: Principal,
  sandbox: RestoreSandbox & { diskOffloadId: string },
  target: RestoreTarget,
  operation: { id: string; idempotencyKey: string },
  request: RestoreRequest,
  clock: LeaseClock,
): Promise<void> {
  const ownerId = sandbox.userId;
  // credential-settlement: exempt — a restore leaves OFFLOADED, which holds
  // no live lease (every lease settled before STORED, I6; a detach settles
  // the attempt's leases, U5); it claims its attached logins below exactly
  // as a cold reconnect does, and the launch result settles those claims.
  const generation = sandbox.generation + 1;
  // 2.1 Admission supersede of a non-STORED live offload (X2). The stored
  // offload this restore fetches is the live row and is left alone; any
  // object an ended upload left is reclaimed by the disk sweeper.
  await supersedeOnAdmission(tx, sandbox.id);
  const previous = await tx.sandboxPlacement.findFirst({
    where: { sandboxId: sandbox.id, userId: ownerId },
    orderBy: [{ generation: "desc" }, { acceptedAt: "desc" }],
  });
  if (!previous) throw sandboxStateConflict("Sandbox placement is missing.");
  const now = await leaseTransactionNow(tx, clock);
  // 2.4 Bind host, host owner, storage, usage pool/member (2.8 is the CAS).
  const bound = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: ownerId,
      state: RESTORABLE_STATE,
      generation: sandbox.generation,
      diskOffloadId: sandbox.diskOffloadId,
    },
    data: {
      state: "PROVISIONING",
      generation,
      sandboxHostId: target.hostId,
      hostOwnerId: target.hostOwnerId,
      storagePoolId: target.storagePool.id,
      storageMarker: target.storagePool.marker,
      storagePoolName: target.storagePool.name,
      rootChargeGiB: vmRootChargeGiB(sandbox.diskGiB),
      usagePoolId: target.poolId,
      usageMemberId: target.memberId,
      lastErrorCode: null,
    },
  });
  if (bound.count !== 1) throw sandboxStateConflict();
  // 2.9 prerequisites: the operation carries the new generation.
  await tx.sandboxOperation.updateMany({
    where: { id: operation.id, userId: ownerId, state: "QUEUED" },
    data: { generation },
  });
  // 2.3 The target placement (provenance only: `restoreOffloadId`).
  const placement = await tx.sandboxPlacement.create({
    data: {
      userId: ownerId,
      hostOwnerId: target.hostOwnerId,
      sandboxId: sandbox.id,
      generation,
      operationId: operation.id,
      kind: target.poolId ? "POOL" : "DIRECT",
      originHostId: target.hostId,
      originPoolId: target.poolId,
      originMemberId: target.memberId,
      originShareId: target.originShareId,
      acceptedGraceSeconds: target.acceptedGraceSeconds,
      templateId: previous.templateId,
      templateRevisionId: previous.templateRevisionId,
      cpuCount: previous.cpuCount,
      memoryMiB: previous.memoryMiB,
      diskGiB: previous.diskGiB,
      storagePoolId: target.storagePool.id,
      storageMarker: target.storagePool.marker,
      storagePoolName: target.storagePool.name,
      rootChargeGiB: vmRootChargeGiB(previous.diskGiB),
      chargedMemoryMiB: vmLiveMemoryChargeMiB(previous.memoryMiB),
      chargedVcpu: previous.cpuCount,
      artifact: previous.artifact,
      architecture: previous.architecture,
      guestUid: previous.guestUid,
      guestGid: previous.guestGid,
      guestHome: previous.guestHome,
      guestShell: previous.guestShell,
      configId: previous.configId,
      acceptedAt: now,
      restoreOffloadId: sandbox.diskOffloadId,
    },
  });
  await tx.sandbox.update({
    where: { id: sandbox.id },
    data: { currentPlacementId: placement.id },
  });
  // 2.6 / §8.5 Rebind the execution config in place: same merged values,
  // the target host, the MAC under the target's host owner, config
  // generation g + 1 (V6), acknowledgement reset (re-acked on the target).
  const config = await tx.sandboxExecutionConfig.findFirst({
    where: { id: previous.configId, sandboxId: sandbox.id, userId: ownerId },
    select: { id: true, authorizingKeyId: true, mergedDefaults: true },
  });
  if (!config) throw sandboxStateConflict("Sandbox configuration is missing.");
  const env = Object.entries((config.mergedDefaults ?? {}) as Record<string, string>).sort(
    ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0),
  );
  const binding = privateConfigBinding(
    { configId: config.id, sandboxId: sandbox.id, generation, env },
    {
      ownerId,
      hostOwnerId: target.hostOwnerId,
      hostId: target.hostId,
      authorizingKeyId: config.authorizingKeyId,
    },
  );
  await tx.sandboxExecutionConfig.update({
    where: { id: config.id },
    data: {
      hostId: target.hostId,
      generation,
      bindingScheme: binding.bindingScheme,
      bindingKeyId: binding.bindingKeyId,
      bindingMac: binding.bindingMac,
      acknowledgedEpoch: null,
      acknowledgedAt: null,
    },
  });
  // CLI logins (§4 safeguard 2, §8.3): drain (hostless), the worst-case spec
  // preflight, then the resume claims on the target, after S and H and once
  // the config is bound there (the claim gate's disjointness check reads it;
  // it re-reads foreign opt-in and capability under the credential locks:
  // `credential.host_forbidden`). Any refusal rolls the whole bind back.
  const credentialed = await claimRestoreLeases(tx, principal, sandbox.id, {
    operationId: operation.id,
    hostId: target.hostId,
    generation,
    pins: request.credentials,
  });
  // 2.5 A new root on the target and the live charge.
  await reserveLiveResources(tx, { hostId: target.hostId, ownerId, sandboxId: sandbox.id });
  await reserveRootResources(tx, { hostId: target.hostId, ownerId, sandboxId: sandbox.id });
  // 2.8 Re-arm the lease (a launch starts a fresh lease), under the new path.
  requireLeaseWithinPolicy(
    leaseRequestOf(request.timeoutMs),
    await readLockedPathLimit(tx, sandbox),
  );
  if (sandbox.leaseRevision >= 2_147_483_647)
    throw sandboxStateConflict("Lease revision exhausted.");
  const expiresAt = resolveLeaseTimeout(request.timeoutMs, now.getTime());
  const leaseExpiresAt = expiresAt;
  const revision = sandbox.leaseRevision + 1;
  await tx.sandbox.update({
    where: { id: sandbox.id },
    data: {
      leaseRevision: revision,
      leaseExpiresAt,
      leaseExpiresAtRequested: leaseExpiresAt,
      leaseExpireActionRequested: sandbox.leaseExpireAction,
      leaseRevisionEffective: null,
      leaseExpiresAtEffective: null,
      leaseExpireActionEffective: null,
      startedAt: null,
      readyAt: null,
    },
  });
  await tx.sandboxOperation.update({
    where: { id: operation.id },
    data: acceptedLeaseFields({
      now,
      timeoutMs: request.timeoutMs,
      revision,
      expiresAt,
      action: sandbox.leaseExpireAction,
    }),
  });
  // credential-settlement: exempt — see the generation advance above.
  await retireSupersededOperations(tx, ownerId, sandbox.id, generation);
  // 2.7 Egress is copied byte-identically: the recorded policy rides the
  // dispatch verbatim (never re-resolved; the target's consent is a hard
  // filter of `restoreHostEligibility`).
  const recorded = recordedEgressPolicy(sandbox);
  // CLI logins (§6.1): the restore's spec (inject the claimed leases, scrub
  // the stored disk's residue) is stored with the operation.
  const credentialSpec = credentialed
    ? await writeLaunchSpec(tx, { sandboxId: sandbox.id, operationId: operation.id })
    : null;
  await createSandboxOutboxEvent(tx, {
    authorizingPrincipal: attributionOf(principal),
    userId: ownerId,
    aggregateId: sandbox.id,
    eventType: "sandbox.reconnect_requested",
    payload: {
      sandboxId: sandbox.id,
      sandboxHostId: target.hostId,
      generation,
      dispatchAttempt: 0,
      operationId: operation.id,
      idempotencyKey: operation.idempotencyKey,
      kind: OPERATION_DISPATCH_KIND.RECONNECT_SANDBOX,
      incusName: defaultIncusInstanceName(sandbox.id),
      egressPolicy: recorded.wire,
      egressPolicyHash: recorded.hash,
      ...(credentialSpec ? { credentialSpec } : {}),
    },
  });
}

/** The restore facts every admission requires of the row it locked. */
function requireRestorable(
  sandbox: RestoreSandbox | null,
): asserts sandbox is RestoreSandbox & { diskOffloadId: string } {
  if (sandbox?.state !== RESTORABLE_STATE || sandbox.diskOffloadId === null)
    throw sandboxStateConflict("Sandbox cannot be restored from this state.");
}

/** The sandbox's active attachments (at most 8, the attach bound). */
async function attachedLoginIds(tx: Tx, sandboxId: string): Promise<string[]> {
  const rows = await tx.sandboxCredential.findMany({
    where: { sandboxId, detachedAt: null },
    select: { credentialId: true },
    orderBy: { credentialId: "asc" },
    take: 8,
  });
  return rows.map((row) => row.credentialId);
}

/**
 * Acceptance-time login checks (§4 safeguard 2): every pin names an attached
 * login (`credential.not_attached`, as a cold reconnect refuses it) and the
 * hostless drain holds. Claims wait for the placement, which knows the host.
 */
async function requireRestorableLogins(tx: Tx, sandboxId: string, request: RestoreRequest) {
  const attached = await attachedLoginIds(tx, sandboxId);
  for (const pin of request.credentials ?? [])
    if (!attached.includes(pin.credentialId)) throw credentialError("credential.not_attached");
  await assertOffloadedCredentialDrain(tx, { sandboxId });
}

/**
 * The restore's login claims on its target (§4 safeguard 2, §8.3): the
 * cold-reconnect resume rules (`claimResumeLeases`, its claim gate over every
 * attachment) under the new generation and the restore operation. Returns
 * whether the sandbox is credentialed. Caller holds S and the target's H.
 */
async function claimRestoreLeases(
  tx: Tx,
  principal: Principal,
  sandboxId: string,
  input: {
    operationId: string;
    hostId: string;
    generation: number;
    pins?: readonly CredentialClaimRequest[];
  },
): Promise<boolean> {
  if (!(await assertOffloadedCredentialDrain(tx, { sandboxId }))) {
    if ((input.pins?.length ?? 0) > 0) throw credentialError("credential.not_attached");
    return false;
  }
  // §6.1: the worst-case spec must fit before any claim.
  await preflightCredentialSpec(tx, {
    sandboxId,
    credentialIds: await attachedLoginIds(tx, sandboxId),
  });
  await claimResumeLeases(tx, {
    principal,
    ownerId: principal.ownerId,
    sandboxId,
    operationId: input.operationId,
    hostId: input.hostId,
    generation: input.generation,
    ...(input.pins ? { pins: input.pins } : {}),
  });
  return true;
}

/**
 * Accept a restore of the OFFLOADED sandbox `sandboxId` (§8.3c
 * "Acceptance"), inside the reconnect's `operationTransaction` callback
 * (owner, K and the placement principals held). Places it at once when an
 * allowed host has room; otherwise records a `SandboxRestoreWait` (with a
 * capacity wait requested) or refuses `restore_no_allowed_host`.
 */
export async function acceptRestore(
  tx: Tx,
  principal: Principal,
  input: {
    sandboxId: string;
    idempotencyKey: string;
    bodyHash: () => string;
    request: RestoreRequestInput;
    clock: LeaseClock;
  },
): Promise<{ id: string; state: "QUEUED" }> {
  authorizeRestoreIntent(principal, intentShape(input.request));
  const ownerId = principal.ownerId;
  const head = await tx.sandbox.findFirst({
    where: { id: input.sandboxId, userId: ownerId },
    select: restoreSandboxSelect,
  });
  requireRestorable(head);
  // A start without a lease reuses the remembered one; the stored wait intent
  // carries the resolved value. A concurrent acceptance moves the generation,
  // which the locked re-read below refuses.
  const request: RestoreRequest = {
    ...input.request,
    timeoutMs: input.request.timeoutMs ?? (await rememberedLeaseTimeoutMs(tx, head)),
  };
  await requireRestorableLogins(tx, head.id, request);
  const selection = await selectRestoreTarget(tx, principal, head, request);
  const target = selection.kind === "target" ? selection.target : null;
  const sandbox = await lockRestoreSandbox(tx, ownerId, input.sandboxId);
  requireRestorable(sandbox);
  if (sandbox.generation !== head.generation || sandbox.diskOffloadId !== head.diskOffloadId)
    throw sandboxStateConflict();
  if (!target && request.waitForCapacityMs === undefined) throw restoreNoAllowedHost();
  const operation = await tx.sandboxOperation.create({
    data: {
      authorizingKeyId: recordedKeyIdOf(principal),
      userId: ownerId,
      sandboxId: sandbox.id,
      kind: "RECONNECT_SANDBOX",
      state: "QUEUED",
      generation: sandbox.generation,
      idempotencyKey: input.idempotencyKey,
      requestBodyHash: input.bodyHash(),
      ...requestDigestMetadata("RECONNECT_SANDBOX"),
      // §8.4: immutable launch semantics, set only here (CHECK
      // `sandbox_operation_launch_mode`).
      launchMode: "NEW_ROOT",
      restoreOffloadId: sandbox.diskOffloadId,
      // §8.3a: the hostless acceptance snapshot (acceptance generation).
      digestContext: digestContextSnapshot(
        { domain: RESTORE_INTENT_DIGEST_DOMAIN },
        { generation: sandbox.generation },
      ),
    },
    select: { id: true, idempotencyKey: true },
  });
  if (target) {
    await bindRestore(tx, principal, sandbox, target, operation, request, input.clock);
    return { id: operation.id, state: "QUEUED" };
  }
  const now = await hostDatabaseNow(tx);
  await tx.sandboxRestoreWait.create({
    data: {
      operationId: operation.id,
      sandboxId: sandbox.id,
      userId: ownerId,
      authorizingKeyId: recordedKeyIdOf(principal),
      expectedGeneration: sandbox.generation,
      intent: intentSchema.store(request),
      enqueuedAt: now,
      deadlineAt: waitDeadline(request.waitForCapacityMs ?? 1000, now),
      // The acceptance's own verdict, should no later pass reach one.
      ...(selection.kind === "login" ? { lastLoginRefusal: selection.code } : {}),
    },
  });
  return { id: operation.id, state: "QUEUED" };
}

type WaitRow = {
  operationId: string;
  sandboxId: string;
  userId: string;
  authorizingKeyId: string | null;
  expectedGeneration: number;
  intent: Prisma.JsonValue | null;
  deadlineAt: Date;
  lastLoginRefusal: string | null;
};

/** End one locked WAITING row and fail (or cancel) its QUEUED operation. */
async function endRestoreWait(
  tx: Tx,
  wait: Pick<WaitRow, "operationId" | "userId">,
  end: "CANCELLED" | "TIMED_OUT" | "FAILED",
  code: string,
  detail: string | null,
  now: Date,
): Promise<boolean> {
  const ended = await tx.sandboxRestoreWait.updateMany({
    where: { operationId: wait.operationId, state: "WAITING" },
    data: { state: end, intent: PrismaValue.DbNull, endedAt: now, endReason: code.slice(0, 64) },
  });
  if (ended.count !== 1) return false;
  await tx.sandboxOperation.updateMany({
    where: { id: wait.operationId, userId: wait.userId, state: "QUEUED" },
    data: {
      state: code === "cancelled" ? "CANCELLED" : "FAILED",
      errorCode: code,
      errorDetail: detail,
      completedAt: now,
      failure: { resource: "sandbox", effect: "none" },
    },
  });
  return true;
}

/** Lock a WAITING row (`FOR UPDATE SKIP LOCKED`: a concurrent pass skips). */
async function lockWaiting(tx: Tx, operationId: string): Promise<WaitRow | null> {
  const [row] = await tx.$queryRaw<WaitRow[]>`
    SELECT "operationId", "sandboxId", "userId", "authorizingKeyId", "expectedGeneration",
      intent, "deadlineAt", "lastLoginRefusal"
    FROM sandbox_restore_wait WHERE "operationId" = ${operationId} AND state::text = 'WAITING'
    FOR UPDATE SKIP LOCKED`;
  return row ?? null;
}

export type PlaceRestoreOutcome = "placed" | "waiting" | "ended" | "skipped";

/**
 * Resume one waiting restore (§8.3c "placeRestore on resume"), in `tx`
 * under the placement principals the caller locked
 * (`restorePlacementPrincipals`):
 * 1. lock the wait row (SKIP LOCKED) and require WAITING;
 * 2. CAS the sandbox `{OFFLOADED, expectedGeneration, diskOffloadId =
 *    op.restoreOffloadId}`, else end CANCELLED and fail `state_conflict`;
 * 3. revalidate the stored principal (`resolveStoredPrincipal`; revoked →
 *    `forbidden`) and the restore intent, with the creating-key rule read now;
 * 4. select and authorize the destination, then bind (§8.3 item 2);
 * 5. end the wait PLACED and scrub the intent in the same transaction.
 */
export async function placeRestore(
  tx: Tx,
  operationId: string,
  clock: LeaseClock,
): Promise<PlaceRestoreOutcome> {
  const wait = await lockWaiting(tx, operationId);
  if (!wait) return "skipped";
  const now = await hostDatabaseNow(tx);
  // An overdue row is never attempted: the deadline ends it, with the
  // verdict recorded before it.
  if (wait.deadlineAt <= now) return "skipped";
  const operation = await tx.sandboxOperation.findFirst({
    where: { id: operationId, userId: wait.userId, state: "QUEUED" },
    select: { id: true, idempotencyKey: true, restoreOffloadId: true, authorizingKeyId: true },
  });
  const head = await tx.sandbox.findFirst({
    where: { id: wait.sandboxId, userId: wait.userId },
    select: restoreSandboxSelect,
  });
  if (
    !operation ||
    !head ||
    head.state !== RESTORABLE_STATE ||
    head.generation !== wait.expectedGeneration ||
    head.diskOffloadId === null ||
    head.diskOffloadId !== operation.restoreOffloadId
  ) {
    await endRestoreWait(tx, wait, "CANCELLED", "state_conflict", "superseded", now);
    return "ended";
  }
  const request = intentSchema.parse(wait.intent);
  const principal = await resolveStoredPrincipal(tx, {
    userId: wait.userId,
    authorizingKeyId: wait.authorizingKeyId,
    sandboxBuildId: head.buildId,
    sandboxVerifyBuildId: head.verifyBuildId,
  });
  // Public operation codes (`OPERATION_ERROR_CODES`): a revoked or expired
  // key is `credential_inactive` (as a queued create's), any other lost
  // authority `access_denied`.
  if (!principal || !request) {
    await endRestoreWait(
      tx,
      wait,
      "CANCELLED",
      principal ? "access_denied" : "credential_inactive",
      "Restore authority was revoked.",
      now,
    );
    return "ended";
  }
  try {
    authorizeRestoreIntent(principal, intentShape(request));
    await authorizeServiceAction(principal, "sandboxes.reconnect", { sandboxId: head.id }, tx);
  } catch (error) {
    if (!(error instanceof ORPCError)) throw error;
    await endRestoreWait(
      tx,
      wait,
      "CANCELLED",
      "access_denied",
      "Restore authority was revoked.",
      now,
    );
    return "ended";
  }
  const selection = await selectRestoreTarget(tx, principal, head, { ...request });
  if (selection.kind !== "target")
    return recordVerdict(tx, operationId, selection.kind === "login" ? selection.code : null, now);
  const target = selection.target;
  const sandbox = await lockRestoreSandbox(tx, wait.userId, wait.sandboxId);
  requireRestorable(sandbox);
  if (sandbox.generation !== wait.expectedGeneration) throw sandboxStateConflict();
  // A transient login refusal at the bind's claims undoes only the bind
  // (savepoint): the wait row stays locked, so the refusal is recorded in
  // this transaction and no other pass or the deadline sees the row between.
  await tx.$executeRaw`SAVEPOINT restore_bind`;
  try {
    await bindRestore(tx, principal, sandbox, target, operation, request, clock);
  } catch (error) {
    const login = knownCode(TRANSIENT_RESTORE_LOGIN_CODES, refusalCode(error));
    if (!login) throw error;
    await tx.$executeRaw`ROLLBACK TO SAVEPOINT restore_bind`;
    return recordVerdict(tx, operationId, login, now);
  }
  await tx.$executeRaw`RELEASE SAVEPOINT restore_bind`;
  const placed = await tx.sandboxRestoreWait.updateMany({
    where: { operationId, state: "WAITING" },
    data: { state: "PLACED", intent: PrismaValue.DbNull, endedAt: now, lastAttemptAt: now },
  });
  if (placed.count !== 1) throw sandboxStateConflict();
  return "placed";
}

/**
 * Destroy or cancel of a sandbox whose restore waits (§8.3c): end the wait
 * CANCELLED and the operation `cancelled`, in the caller's transaction
 * (the `cancelCapacityWaitIfWaiting` pattern). Returns the ended operation
 * id, or null when no restore was waiting.
 */
export async function cancelRestoreWaitIfWaiting(
  tx: Tx,
  ownerId: string,
  target: { sandboxId: string } | { operationId: string },
): Promise<{ operationId: string; generation: number } | null> {
  const row = await tx.sandboxRestoreWait.findFirst({
    where: { userId: ownerId, state: "WAITING", ...target },
    select: { operationId: true, sandboxId: true },
  });
  if (!row) return null;
  const wait = await lockWaiting(tx, row.operationId);
  if (!wait) throw sandboxStateConflict("The restore is being placed. Retry the request.");
  const now = await hostDatabaseNow(tx);
  if (!(await endRestoreWait(tx, wait, "CANCELLED", "cancelled", null, now))) return null;
  return { operationId: row.operationId, generation: wait.expectedGeneration };
}

/** Rows one pass expires or evaluates. */
const RESTORE_PASS_MAX = 64;

type TransientRestoreLoginCode = (typeof TRANSIENT_RESTORE_LOGIN_CODES)[number];

/**
 * Record one evaluation's verdict on the locked WAITING row: a transient
 * login refusal, or null for capacity (which clears an earlier refusal).
 */
async function recordVerdict(
  tx: Tx,
  operationId: string,
  login: TransientRestoreLoginCode | null,
  now: Date,
): Promise<"waiting"> {
  await tx.sandboxRestoreWait.updateMany({
    where: { operationId, state: "WAITING" },
    data: { lastAttemptAt: now, lastLoginRefusal: login },
  });
  return "waiting";
}

function knownCode<const T extends readonly string[]>(codes: T, code: unknown): T[number] | null {
  return codes.find((known) => known === code) ?? null;
}

function refusalCode(error: unknown): unknown {
  if (!(error instanceof ORPCError)) return undefined;
  return (error.data as { code?: unknown } | undefined)?.code;
}

/** The failure code and detail of a restore whose wait reached its deadline. */
function deadlineFailure(wait: Pick<WaitRow, "lastLoginRefusal">): {
  code: OperationErrorCode;
  detail: string;
} {
  const login = knownCode(TRANSIENT_RESTORE_LOGIN_CODES, wait.lastLoginRefusal);
  if (login) return { code: login, detail: safeOperationError(login).message };
  return {
    code: "restore_no_allowed_host",
    detail: "No host this restore may use had room before the wait ended.",
  };
}

/** End a waiting restore whose placement a permanent login refusal stopped. */
async function endRestoreWaitForLogin(
  operationId: string,
  code: (typeof PERMANENT_RESTORE_LOGIN_CODES)[number],
): Promise<void> {
  await sandboxOutboxTransaction(async (tx) => {
    const wait = await lockWaiting(tx, operationId);
    if (!wait) return;
    await endRestoreWait(
      tx,
      wait,
      "FAILED",
      code,
      safeOperationError(code).message,
      await hostDatabaseNow(tx),
    );
  });
}

/**
 * The restore-wait pass (§8.3c "Reusing the scheduler"), run right after
 * `runCapacityQueuePass` on the same wake and timer: expire due rows first
 * (TIMED_OUT, intent scrubbed, operation `restore_no_allowed_host`, or the
 * recorded `lastLoginRefusal` when the latest pass was refused by a login;
 * the sandbox stays OFFLOADED), then evaluate WAITING rows oldest first,
 * bounded, one transaction each. Returns ms until the next deadline (≤ 15 s)
 * or null. The hint is accepted for the scheduler's signature; a restore
 * may place on any host, so every pass evaluates every waiting row.
 */
export async function runRestoreWaitPass(
  clock: LeaseClock,
  shouldStop: () => boolean = () => false,
  _hint?: CapacityHint,
): Promise<number | null> {
  const due = await prisma.sandboxRestoreWait.findMany({
    where: { state: "WAITING", deadlineAt: { lte: new Date() } },
    orderBy: { deadlineAt: "asc" },
    select: { operationId: true, userId: true },
    take: RESTORE_PASS_MAX,
  });
  for (const row of due) {
    if (shouldStop()) break;
    await expireRestoreWait(row.operationId);
  }
  const waiting = await prisma.sandboxRestoreWait.findMany({
    where: { state: "WAITING" },
    orderBy: [{ enqueuedAt: "asc" }, { operationId: "asc" }],
    select: { operationId: true, userId: true, sandboxId: true, intent: true },
    take: RESTORE_PASS_MAX,
  });
  for (const row of waiting) {
    if (shouldStop()) break;
    try {
      await sandboxOutboxTransaction(async (tx) => {
        const request = intentSchema.parse(row.intent);
        await lockPlacementPrincipals(
          tx,
          await discoverPlacementPrincipals(tx, sessionPrincipal(row.userId), {
            sandboxId: row.sandboxId,
            // Never an existing key: the operation exists, so look it up by
            // a key no operation can have and discover the full set.
            idempotencyKey: "",
            restoreTarget: request?.target ?? null,
          }),
        );
        return placeRestore(tx, row.operationId, clock);
      });
    } catch (error) {
      // One row's lost race or refusal never stops the pass; the next wake
      // or the timer retries it. A permanent login refusal ends it now (a
      // transient one was recorded by `placeRestore` itself).
      const permanent = knownCode(PERMANENT_RESTORE_LOGIN_CODES, refusalCode(error));
      if (permanent) await endRestoreWaitForLogin(row.operationId, permanent);
      else if (!(error instanceof ORPCError))
        console.error("[restore-wait] placement failed", error);
    }
  }
  const next = await prisma.sandboxRestoreWait.findFirst({
    where: { state: "WAITING" },
    orderBy: { deadlineAt: "asc" },
    select: { deadlineAt: true },
  });
  if (!next) return null;
  return Math.max(0, Math.min(15_000, next.deadlineAt.getTime() - Date.now()));
}

/** End one due WAITING row TIMED_OUT (§8.3c) with `deadlineFailure`; a row
 * an evaluation holds is skipped (that evaluation never places an overdue
 * row) and expired by the next pass. */
async function expireRestoreWait(operationId: string): Promise<void> {
  await sandboxOutboxTransaction(async (tx) => {
    const wait = await lockWaiting(tx, operationId);
    if (!wait) return;
    const now = await hostDatabaseNow(tx);
    if (wait.deadlineAt > now) return;
    const failure = deadlineFailure(wait);
    await endRestoreWait(tx, wait, "TIMED_OUT", failure.code, failure.detail, now);
  });
}

// ------------------------------------------------- §8.1 / §5 order 1, 3, 4

/**
 * The admission supersede of every reconnect admission (cold, cached or
 * restore; §6 T1, X2): a live offload not yet STORED is superseded under S.
 */
export async function supersedeOnAdmission(tx: Tx, sandboxId: string): Promise<void> {
  // Any object or multipart upload the ended offload left is reclaimed by
  // the disk sweeper (`finishEndedOffload` is best effort anyway).
  await supersedeLiveOffload(tx, sandboxId);
}

/** The cached host may not take its STORED copy back (§5 order 3/4). */
export class CachedCopyIneligible extends Error {
  constructor(
    readonly hostOnline: boolean,
    readonly reason: string,
  ) {
    super("cached copy ineligible");
  }
}

const cachedFactsSelect = {
  ...RESTORE_SANDBOX_FACTS_SELECT,
  sandboxHostId: true,
  diskOffloadId: true,
  cachedOffloadSeq: true,
} satisfies Prisma.SandboxSelect;

/**
 * §5 order 4 (cold reconnect of a STOPPED sandbox, S held): a STORED cached
 * copy whose host is offline cannot boot there, and the start would stop at
 * the host checks (journal-key ack: `host_unavailable`) before
 * `cachedDiskExpectation` ran. Raise `CachedCopyIneligible` first, so the
 * caller tries the gated STALE detach and restores elsewhere. No-op for any
 * other sandbox.
 */
export async function requireCachedHostOnline(
  tx: Tx,
  ownerId: string,
  sandboxId: string,
): Promise<void> {
  const sandbox = await tx.sandbox.findFirst({
    where: { id: sandboxId, userId: ownerId, state: "STOPPED" },
    select: { sandboxHostId: true, diskOffloadId: true },
  });
  if (!sandbox?.diskOffloadId || !sandbox.sandboxHostId) return;
  const [offload] = await tx.$queryRaw<{ state: string }[]>`SELECT state::text AS state
    FROM sandbox_disk_offload WHERE id = ${sandbox.diskOffloadId} AND "sandboxId" = ${sandboxId}`;
  if (offload?.state !== "STORED") return;
  if (!(await hostOnline(tx, sandbox.sandboxHostId, await hostDatabaseNow(tx))))
    throw new CachedCopyIneligible(false, "host_unavailable");
}

/**
 * §8.1 (cold reconnect of a STOPPED sandbox, S held): the `expectDisk`
 * binding when its disk is a cached STORED copy at `cachedOffloadSeq`, or
 * null (no cached copy). The cached host must pass `restoreHostEligibility`
 * (§5 order 1); otherwise `CachedCopyIneligible` (the caller rolls back and
 * evicts or detaches). `stayCached`: eviction or detachment was refused, so
 * the copy boots where it is.
 */
export async function cachedDiskExpectation(
  tx: Tx,
  ownerId: string,
  sandboxId: string,
  stayCached: boolean,
): Promise<{ seq: number; fingerprint: string } | null> {
  const sandbox = await tx.sandbox.findFirst({
    where: { id: sandboxId, userId: ownerId },
    select: cachedFactsSelect,
  });
  if (!sandbox?.diskOffloadId || !sandbox.sandboxHostId) return null;
  const [offload] = await tx.$queryRaw<
    { state: string; seq: number; fingerprint: string | null }[]
  >`SELECT state::text AS state, seq, fingerprint FROM sandbox_disk_offload
    WHERE id = ${sandbox.diskOffloadId} AND "sandboxId" = ${sandbox.id} FOR SHARE`;
  if (offload?.state !== "STORED" || !offload.fingerprint) return null;
  // §8.1 (C6c): a host copy that refused `disk_stale` (its `cachedOffloadSeq`
  // cleared by the result) is never booted: the stored copy is authoritative
  // until READY (I20). The caller evicts it or, the host offline, detaches;
  // if neither is possible the start is refused rather than booting it.
  if (sandbox.cachedOffloadSeq !== offload.seq) {
    if (stayCached) throw sandboxStateConflict("The cached disk is stale. Retry the request.");
    const now = await hostDatabaseNow(tx);
    throw new CachedCopyIneligible(await hostOnline(tx, sandbox.sandboxHostId, now), "disk_stale");
  }
  if (!stayCached) {
    const now = await hostDatabaseNow(tx);
    const verdict = await restoreHostEligibility(
      tx,
      sandbox,
      { hostId: sandbox.sandboxHostId },
      null,
      now,
    );
    if (!verdict.ok)
      throw new CachedCopyIneligible(
        await hostOnline(tx, sandbox.sandboxHostId, now),
        verdict.reason,
      );
  }
  return { seq: offload.seq, fingerprint: offload.fingerprint };
}

/**
 * §5 order 4 / §8.2 "Offline cached host, at restore request", and §7
 * "Cached cold reconnect" / Discard (§5 order 3): the gated STALE detach, in
 * its own transaction (owner → host by epoch → sandbox). Allowed while the
 * host is offline, or — online — once its copy is known unusable: it
 * refused `disk_stale` (the result cleared `cachedOffloadSeq`), or it let a
 * server evict grant outlive its expiry unused (its journal does not hold
 * that copy as stored; `clearOutlivedEvictGrants` cleared the seq). Either
 * way only through the one safe-detachment gate (`detach.ts`
 * `staleDetachSafe`, shared with Forget). The root hold moves to a
 * `SandboxDiskCopy(STALE)`, whose discard deletes it on that host (at once
 * when it is connected).
 * Returns whether the sandbox is now OFFLOADED.
 */
export async function detachStaleCachedCopy(ownerId: string, sandboxId: string): Promise<boolean> {
  return sandboxOutboxTransaction(async (tx) => {
    const head = await tx.sandbox.findFirst({
      where: { id: sandboxId, userId: ownerId },
      select: { sandboxHostId: true, hostOwnerId: true },
    });
    if (!head?.sandboxHostId || !head.hostOwnerId) return false;
    for (const id of [...new Set([ownerId, head.hostOwnerId])].sort())
      await lockOwnerForAdmission(tx, id);
    await lockCurrentHostEpoch(tx, head.sandboxHostId);
    const now = await hostDatabaseNow(tx);
    const online = await hostOnline(tx, head.sandboxHostId, now);
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} AND "userId" = ${ownerId} FOR NO KEY UPDATE`;
    const sandbox = await tx.sandbox.findFirst({
      where: {
        id: sandboxId,
        userId: ownerId,
        state: "STOPPED",
        sandboxHostId: head.sandboxHostId,
        diskOffloadId: { not: null },
        liveResourcesHeld: false,
        // Online: only a copy its host refused (no usable cached seq).
        ...(online ? { cachedOffloadSeq: null } : {}),
      },
      select: {
        id: true,
        userId: true,
        generation: true,
        templateRevisionId: true,
        diskBaseFingerprint: true,
      },
    });
    if (!sandbox) return false;
    if (!(await staleDetachSafe(tx, { ownerId, sandboxId, hostId: head.sandboxHostId })))
      return false;
    const identity = await staleCopyIdentity(tx, sandbox);
    return detachToOffloaded(tx, {
      sandboxId,
      userId: ownerId,
      hostId: head.sandboxHostId,
      generation: sandbox.generation,
      proof: { kind: "stale_copy", ...identity },
    });
  });
}
