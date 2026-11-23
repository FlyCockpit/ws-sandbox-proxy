import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma, type SandboxState } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import {
  type BuildCopyV11,
  buildCopyV11Schema,
  buildIdOfContextPath,
  failureSchema,
  metadataSchema,
  normalizeTunnelPorts,
  publicOperationErrorCode,
  RESULT_LIMITS,
  type RunAsV11,
  runAsV11Schema,
  STDIN_CHUNK_MAX_BYTES,
  sandboxNameSchema,
  vmLiveMemoryChargeMiB,
} from "@wssp/sandbox-contracts";
import { credentialError } from "../../credentials/errors";
import {
  requireCreateCredentialsAllowed,
  requireUsableLogins,
  writeLaunchSpec,
} from "../../credentials/launch";
import {
  type CredentialPlacementContext,
  credentialPlacementContextFor,
} from "../../credentials/placement";
import { assertCredentialDrain, claimResumeLeases } from "../../credentials/resume";
import { type CredentialClaimRequest, refuseUnclaimableLogin } from "../../credentials/selection";
import { preflightCredentialSpec } from "../../credentials/specs";
import {
  dropSupersededSpecs,
  hasSupersededLaunchLeases,
  killNeedsRecovery,
  resolveTeardownPriorState,
  settleCredentialsOnDeleted,
  settleCredentialTeardown,
  settleSupersededLaunchLeases,
} from "../../credentials/teardown";
import { findOwnedOrThrow } from "../../lib/ownership";
import {
  authorizeServiceAction,
  buildRoleOf,
  insufficientScope,
  queuedPoolContext,
  serviceActionForOperationKind,
  serviceAdmissionError,
  serviceProcedure,
} from "../../lib/sdk-key-access";
import type { BuildRole } from "../../template-builds/build-authority";
import { rebuildAfterRefusal } from "../../template-builds/rebuild";
import { notifyTemplateBuildsChanged } from "../../template-builds/wake";
import {
  canTransitionSandboxState,
  defaultIncusInstanceName,
  HEALTHY_GUEST_STATES,
  invalidSandboxTransition,
  KILLABLE_SANDBOX_STATES,
  operationNotFound,
  requestDigestMetadata,
  sandboxStateConflict,
  templateNotFound,
  tunnelRefused,
  unsupportedCapability,
} from "..";
import { consumeCreateConnectBudget, consumeSandboxWriteBudget } from "../budgets";
import {
  admitCapacityWait,
  type CapacityEntryPlan,
  cancelCapacityWaitIfWaiting,
  capacityGate,
  capacityWaitViews,
  enqueueCapacityWait,
  recordWaitingTeardown,
  requireEntryWaitWithinPolicy,
} from "../capacity-queue";
import { readCommandOutputPage } from "../command-output";
import {
  buildRunCommandInput,
  type CancelOperationInput,
  type CommandOutputInput,
  type CreateSandboxInput,
  type CreateSnapshotInput,
  type DispatchableOperationKind,
  effectiveCommandTimeoutMs,
  encodeCommandTimeoutMs,
  type ForkSandboxInput,
  type KillSandboxInput,
  type ListDirInput,
  type ListProcessesInput,
  type ListSandboxesInput,
  type MkdirInput,
  type MovePathInput,
  OPERATION_DISPATCH_KIND,
  type OperationIdInput,
  type Principal,
  type ReadFileInput,
  type ReconnectSandboxInput,
  type RemovePathInput,
  type RestoreSnapshotInput,
  type RunCommandInput,
  runCommandInput,
  type SandboxIdInput,
  type SetSandboxTimeoutInput,
  type StatPathInput,
  type StopSandboxInput,
  type UpdateSandboxInput,
  type WriteStdinInput,
} from "../contracts";
import { operationDigestContext } from "../digest-context";
import { lockOwnerPlacement } from "../direct-placement";
import { canRestore } from "../disk-offload/availability";
import { endOffloadForDestroy } from "../disk-offload/destroy";
import { sandboxDiskSelect } from "../disk-offload/disk-view";
import { grantServerEviction } from "../disk-offload/evict";
import { type OffloadPolicyColumns, offloadPolicyColumns } from "../disk-offload/policy";
import {
  acceptRestore,
  CachedCopyIneligible,
  cachedDiskExpectation,
  cancelRestoreWaitIfWaiting,
  detachStaleCachedCopy,
  type RestoreRequest,
  requireCachedHostOnline,
  restoreRequestOf,
  supersedeOnAdmission,
} from "../disk-offload/restore-admit";
import { supersedeLiveOffload } from "../disk-offload/store";
import { recordedEgressPolicy, resolveCreateEgressPolicy } from "../egress-policy";
import {
  capacityWaitExceedsPolicy,
  captureBusy,
  diskEvicting,
  diskUnavailable,
  sandboxNameInvalid,
  sandboxNameTaken,
  sandboxRestoring,
} from "../errors";
import {
  executionEnvPairs,
  loadExecutionConfig,
  validateCommandEnvironmentUnion,
} from "../execution-config";
import {
  lockHostForSandboxOperation,
  requireRetainedStorage,
  reserveLiveResources,
} from "../host-admission";
import { probeHostSandbox } from "../host-image-verifier";
import { requireHostJournalKeyAck } from "../idempotency";
import { isReservedInternalIdempotencyKey } from "../idempotency-key-reserved";
import { requireKeySandboxAllowance } from "../key-sandbox-limit";
import { acceptedLaunchMode, currentlyRestoring } from "../launch-mode";
import {
  acceptedLeaseFields,
  commitSandboxLeaseRenewal,
  isLeaseDeadlinePassed,
  LEASE_DEFAULT_MS,
  LEASE_RENEWABLE_STATES,
  type LeaseClock,
  leaseNow,
  leaseTransactionNow,
  requeueRestoreCleanup,
  resolveLeaseTimeout,
} from "../lease";
import {
  leasePathPools,
  leaseRequestOf,
  readLockedPathLimit,
  requireLeaseWithinPolicy,
  sameLeasePath,
} from "../lease-policy";
import { pullInLeaseLocked } from "../lease-pull-in";
import {
  initialProcessFields,
  initialResultFields,
  isContentResultKind,
  readResultContinuationInTransaction,
  reserveOperationResult,
} from "../operation-results";
import { operationTransaction } from "../operation-transaction";
import { createSandboxOutboxEvent, sandboxOutboxTransaction } from "../outbox";
import {
  type CreateIntent,
  type ManagedCreate,
  materializePlacement,
} from "../placement-materialize";
import { lockPoolGraph, lockPoolGraphShared } from "../pool-locks";
import { type PlacedResult, resolvePlacement, retryPlacement } from "../pool-placement";
import {
  attributionOf,
  budgetSubjectOf,
  buildIdOf,
  isBrowserSession,
  recordedKeyIdOf,
} from "../principal-kinds";
import { cancelAction, writeStdinAction } from "../process-controls";
import { redactSandbox } from "../public-dto";
import { readinessReasonOfFailure } from "../readiness-detail";
import { RelayFenceRejected, requireRelayFence, retireSupersededOperations } from "../relay-fence";
import { sandboxListPage, sandboxListReadQuery } from "../sandbox-list";
import { assertSandboxNameFree, isSandboxNameViolation } from "../sandbox-names";
import { rethrowSensitiveSandboxError } from "../sensitive-errors";
import {
  discoverPlacementPrincipals,
  requireOwnedSandboxPlacement,
  requirePlacementPrincipals,
} from "../sharing-authority";
import { requirePoolMemberAcquisition, requirePoolShareAcquisition } from "../sharing-quota";
import { ACTIVE_OPERATION_STATES, STOPPABLE_SANDBOX_STATES } from "../state-transitions";
import { pinnedLaunchSource, templateDispatchPayload } from "../template-dispatch";
import { tunnelConfigured } from "../tunnels/config";
import { validateVmSizeOverrides } from "../vm-size-input";

const NOT_FOUND = "Sandbox not found";

const sandboxSelect = {
  id: true,
  name: true,
  diskOffloadId: true,
  hostOwnerId: true,
  usagePoolId: true,
  usageMemberId: true,
  accessGraceUntil: true,
  state: true,
  generation: true,
  templateId: true,
  templateRevisionId: true,
  cpuCount: true,
  memoryMiB: true,
  diskGiB: true,
  storagePoolId: true,
  storagePoolName: true,
  storageMarker: true,
  rootChargeGiB: true,
  diskReservationHeld: true,
  liveResourcesHeld: true,
  currentPlacementId: true,
  CurrentPlacement: { select: { acceptedGraceSeconds: true } },
  originPoolId: true,
  sandboxHostId: true,
  leaseExpiresAt: true,
  leaseRevision: true,
  leaseExpireAction: true,
  leaseExpiresAtRequested: true,
  leaseExpireActionRequested: true,
  leaseRevisionEffective: true,
  leaseExpiresAtEffective: true,
  leasePendingReady: true,
  leaseExpireActionEffective: true,
  startedAt: true,
  readyAt: true,
  metadata: true,
  egressPolicy: true,
  egressPolicyHash: true,
  egressRequest: true,
  egressModeReason: true,
  egressDeniedGrants: true,
  guestSudo: true,
  guestSudoRequested: true,
  guestSudoReason: true,
  tunnelEnabled: true,
  tunnelPorts: true,
  guestRoot: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.SandboxSelect;

/** The `/v1` read projection: the row plus its disk facts (`sandboxDiskDto`). */
const sandboxReadSelect = { ...sandboxSelect, ...sandboxDiskSelect } satisfies Prisma.SandboxSelect;

const operationPublicSelect = {
  id: true,
  sandboxId: true,
  kind: true,
  state: true,
  generation: true,
  errorCode: true,
  failure: true,
  leaseAcceptedAt: true,
  leaseTimeoutMs: true,
  leaseRevisionAccepted: true,
  leaseExpiresAtAccepted: true,
  leaseExpireActionAccepted: true,
  leaseAcknowledgedAt: true,
  leaseAcknowledgedAttempt: true,
  leaseAcknowledgedEpoch: true,
  leaseFromReady: true,
  progressPhase: true,
  progressBytesDone: true,
  progressBytesTotal: true,
  progressAt: true,
  Capture: { select: { revisionId: true, errorDetail: true } },
  dispatchedAt: true,
  completedAt: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.SandboxOperationSelect;

const RECONNECT_STATES: ReadonlySet<SandboxState> = new Set(["READY", "STOPPED"]);

function ownerWhere(ownerId: string) {
  return { userId: ownerId, Sandbox: { userId: ownerId } };
}

async function ownedSandbox(id: string, ownerId: string, tx: Prisma.TransactionClient = prisma) {
  return findOwnedOrThrow({
    find: (args) => tx.sandbox.findFirst(args),
    args: { where: { id }, select: sandboxSelect },
    owner: { field: "userId", id: ownerId },
    notFound: NOT_FOUND,
  });
}

async function ownedOperation<TSelect extends Prisma.SandboxOperationSelect>(
  operationId: string,
  ownerId: string,
  select: TSelect,
) {
  const row = await prisma.sandboxOperation.findFirst({
    where: { id: operationId, ...ownerWhere(ownerId) },
    select,
  });
  if (row == null) {
    throw operationNotFound();
  }
  return row;
}

/** Stdin is one bounded chunk carried in the outbox payload; file bytes never
 * travel through this path (C30: transfers own every file payload). */
function stdinByteLength(contentBase64: string): number {
  const bytes = Buffer.from(contentBase64, "base64");
  if (bytes.byteLength > STDIN_CHUNK_MAX_BYTES) {
    throw new ORPCError("BAD_REQUEST", {
      message: `Stdin exceeds ${STDIN_CHUNK_MAX_BYTES} bytes.`,
    });
  }
  return bytes.byteLength;
}

function requireState(
  sandbox: { state: SandboxState },
  allowed: ReadonlySet<SandboxState>,
  message: string,
) {
  if (!allowed.has(sandbox.state)) {
    throw sandboxStateConflict(message);
  }
}

async function casExistingSandboxState(
  tx: Prisma.TransactionClient,
  sandbox: { id: string; state: SandboxState; generation: number },
  to: SandboxState | undefined,
  options: { advanceGeneration: boolean },
): Promise<number> {
  if (to != null && !canTransitionSandboxState(sandbox.state, to)) {
    throw invalidSandboxTransition(sandbox.state, to);
  }
  // credential-settlement: exempt — the CAS helper; every caller passing
  // `advanceGeneration: true` is enumerated and settles at its own site.
  const nextGeneration = options.advanceGeneration ? sandbox.generation + 1 : sandbox.generation;
  const written = await tx.sandbox.updateMany({
    where: { id: sandbox.id, state: sandbox.state, generation: sandbox.generation },
    data: {
      ...(to != null ? { state: to } : {}),
      generation: nextGeneration,
    },
  });
  if (written.count !== 1) {
    throw sandboxStateConflict();
  }
  return nextGeneration;
}

/** STOPPING retains its slot on uncertainty. Kill may also supersede an
 * in-flight stop: destroy intent wins. Stop can only retry an UNKNOWN stop.
 * Call only under the existing owner/host admission locks. */
async function hasSupersedableTeardown(
  tx: Prisma.TransactionClient,
  sandbox: { id: string; state: SandboxState; generation: number },
  ownerId: string,
  kinds: ("KILL_SANDBOX" | "STOP_SANDBOX")[] = ["KILL_SANDBOX", "STOP_SANDBOX"],
  includeActiveStops = false,
): Promise<boolean> {
  if (sandbox.state !== "STOPPING") return false;
  return (
    (await tx.sandboxOperation.findFirst({
      where: {
        userId: ownerId,
        sandboxId: sandbox.id,
        generation: sandbox.generation,
        kind: { in: kinds },
        OR: [
          { state: "UNKNOWN_OUTCOME" },
          ...(includeActiveStops
            ? [{ kind: "STOP_SANDBOX" as const, state: { in: [...ACTIVE_OPERATION_STATES] } }]
            : []),
        ],
      },
      select: { id: true },
    })) !== null
  );
}

async function enqueueOwnedOperation(
  owner: Principal,
  sandboxId: string,
  idempotencyKeyValue: string,
  spec: {
    kind: Exclude<DispatchableOperationKind, "CREATE_SANDBOX" | "KILL_SANDBOX" | "SIGNAL_PROCESS">;
    eventType: string;
    body: unknown;
    payload: Record<string, unknown>;
    nextState?: SandboxState;
    allowedStates: ReadonlySet<SandboxState>;
    conflictMessage: string;
    skipStateUpdate?: boolean;
    advanceGeneration?: boolean | ((state: SandboxState) => boolean);
    rearmLease?: { timeoutMs: number; clock: LeaseClock };
    /** CLI logins: resume pins passed on this cold start (§7.2 rule 4). */
    credentialPins?: readonly CredentialClaimRequest[];
    /** Staged 10.5 admission (6A callers only); see operationTransaction. */
    fsProcess?: { commandEnvironment?: boolean };
    /** Reconnect only: the restore an OFFLOADED sandbox resumes through. */
    restore?: { request: RestoreRequest; clock: LeaseClock };
    /** Stop only: the offload policy written with the accepted stop (never on replay). */
    offloadPolicy?: OffloadPolicyColumns;
  },
) {
  const action = serviceActionForOperationKind(spec.kind);
  if (!action) throw sandboxStateConflict("Unsupported operation authority.");
  // §5 order 3/4: set when the cached host refused eviction or detachment,
  // so the cached copy cold-boots where it is (stay cached).
  let cachedFallback = false;
  const accept = () =>
    operationTransaction(
      owner,
      {
        key: idempotencyKeyValue,
        intent: spec.body,
        kind: spec.kind,
        action,
        target: { sandboxId },
        ...(spec.kind === "RECONNECT_SANDBOX"
          ? {
              admissionPrincipals: (tx: Prisma.TransactionClient) =>
                discoverPlacementPrincipals(tx, owner, {
                  sandboxId,
                  idempotencyKey: idempotencyKeyValue,
                  restoreTarget: spec.restore?.request.target ?? null,
                }),
            }
          : {}),
        ...(spec.fsProcess ? { fsProcess: spec.fsProcess } : {}),
      },
      async (tx, bodyHash) => {
        // Stop of a create still waiting for capacity ends it (no disk exists,
        // like "stop before instance → DELETED"); completed server-side.
        if (spec.kind === "STOP_SANDBOX") {
          const cancelled = await cancelCapacityWaitIfWaiting(tx, owner.ownerId, sandboxId);
          if (cancelled)
            return recordWaitingTeardown(tx, owner, sandboxId, idempotencyKeyValue, bodyHash, {
              kind: "STOP_SANDBOX",
              generation: cancelled.generation,
            });
        }
        const located = await tx.sandbox.findFirst({
          where: { id: sandboxId, userId: owner.ownerId },
          select: sandboxSelect,
        });
        if (!located) throw new ORPCError("NOT_FOUND");
        // an OFFLOADED sandbox resumes only through
        // restore admission (a new root on an eligible host), never the
        // cold reconnect below. A warm request cannot restore.
        if (spec.kind === "RECONNECT_SANDBOX" && located.state === "OFFLOADED") {
          if (!spec.restore || !spec.allowedStates.has("STOPPED"))
            throw sandboxStateConflict(spec.conflictMessage);
          // §6 (R12): restore needs the image store and the data key; without
          // either the stored disk is unusable here right now (nothing written).
          if (!canRestore()) throw diskUnavailable();
          return acceptRestore(tx, owner, {
            sandboxId,
            idempotencyKey: idempotencyKeyValue,
            bodyHash,
            request: spec.restore.request,
            clock: spec.restore.clock,
          });
        }
        // §8.4: an owner stop is refused while a restore attempt is active.
        if (
          spec.kind === "STOP_SANDBOX" &&
          (await currentlyRestoring(tx, { ...located, userId: owner.ownerId }))
        )
          throw sandboxRestoring();
        const cold = spec.kind === "RECONNECT_SANDBOX" && located.state === "STOPPED";
        let resumeCredentials = false;
        let coldPool: Awaited<ReturnType<typeof requirePoolShareAcquisition>> | null = null;
        const added = {
          memoryMiB:
            !cold || located.liveResourcesHeld
              ? 0n
              : BigInt(vmLiveMemoryChargeMiB(located.memoryMiB)),
          vcpu: !cold || located.liveResourcesHeld ? 0n : BigInt(located.cpuCount),
          diskGiB: 0n,
        };
        // A reconnect re-arms the lease: it reads the lease-path policy under
        // G (§3.3). Cold already takes its usage pool exclusively; warm takes
        // the path pool shared, so it waits for a pool or membership write.
        const leasePools = spec.rearmLease
          ? leasePathPools({ ...located, userId: owner.ownerId })
          : [];
        if (cold) {
          const exclusive = [...(located.usagePoolId ? [located.usagePoolId] : []), ...leasePools];
          if (exclusive.length) {
            await lockPoolGraph(tx, exclusive);
          }
          if (located.usagePoolId && located.hostOwnerId !== owner.ownerId) {
            coldPool = await requirePoolShareAcquisition(tx, owner, located.usagePoolId, added);
          }
          requirePlacementPrincipals(tx, [
            owner.ownerId,
            ...(located.hostOwnerId ? [located.hostOwnerId] : []),
            ...(coldPool ? [coldPool.pool.userId] : []),
          ]);
        } else if (leasePools.length) {
          await lockPoolGraphShared(tx, leasePools);
        }
        await lockHostForSandboxOperation(tx, located.sandboxHostId, owner.ownerId, sandboxId);
        const pinned = located.sandboxHostId
          ? await requireOwnedSandboxPlacement(
              tx,
              owner.ownerId,
              sandboxId,
              cold || spec.kind === "STOP_SANDBOX",
            )
          : null;
        if (
          cold &&
          located.hostOwnerId !== owner.ownerId &&
          located.usagePoolId &&
          located.usageMemberId &&
          pinned
        )
          await requirePoolMemberAcquisition(
            tx,
            {
              poolId: located.usagePoolId,
              memberId: located.usageMemberId,
              hostId: pinned.host.id,
              hostOwnerId: pinned.hostOwnerId,
              newRoot: false,
            },
            added,
          );
        const sandbox = await tx.sandbox.findFirst({
          where: { id: sandboxId, userId: owner.ownerId },
          select: sandboxSelect,
        });
        if (!sandbox) throw new ORPCError("NOT_FOUND");
        if (
          spec.kind === "RECONNECT_SANDBOX" &&
          (sandbox.state !== located.state ||
            sandbox.usagePoolId !== located.usagePoolId ||
            sandbox.usageMemberId !== located.usageMemberId ||
            sandbox.hostOwnerId !== located.hostOwnerId ||
            !sameLeasePath(
              { ...located, userId: owner.ownerId },
              { ...sandbox, userId: owner.ownerId },
            ))
        )
          throw sandboxStateConflict("Reconnect placement changed. Retry the request.");
        // Preserve the existing state-write lock strength: FK KEY SHARE for
        // a concurrent idempotency winner remains compatible (real PG proof).
        await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} AND "userId" = ${owner.ownerId} FOR NO KEY UPDATE`;
        if (cold && sandbox.hostOwnerId === owner.ownerId && sandbox.usagePoolId) {
          await tx.sandbox.update({
            where: { id: sandbox.id },
            data: { usagePoolId: null, usageMemberId: null },
          });
        }
        if (spec.kind === "RECONNECT_SANDBOX" && sandbox.state === "STOPPED") {
          if (!sandbox.currentPlacementId)
            throw sandboxStateConflict("Sandbox placement is missing.");
          // Reuse these existing parent locks for the new placement's FKs.
          // Acquire them after S and before inserting O, never as a suffix FK.
          await tx.$queryRaw`SELECT id FROM sandbox_placement WHERE id = ${sandbox.currentPlacementId} AND "sandboxId" = ${sandbox.id} AND "userId" = ${owner.ownerId} FOR SHARE`;
          await tx.$queryRaw`SELECT id FROM sandbox_execution_config WHERE "sandboxId" = ${sandbox.id} AND "userId" = ${owner.ownerId} FOR SHARE`;
        }
        const config = ["RUN_COMMAND", "RECONNECT_SANDBOX"].includes(spec.kind)
          ? await loadExecutionConfig(tx, sandbox.id, owner.ownerId)
          : null;
        if (spec.kind === "RUN_COMMAND")
          validateCommandEnvironmentUnion(spec.payload, config?.env ?? []);
        // §5 order 4: an offline cached host is detached (then restored)
        // before the host checks below refuse the start.
        if (spec.kind === "RECONNECT_SANDBOX" && sandbox.state === "STOPPED" && !cachedFallback)
          await requireCachedHostOnline(tx, owner.ownerId, sandbox.id);
        if (config || (Array.isArray(spec.payload.env) && spec.payload.env.length > 0))
          await requireHostJournalKeyAck(
            tx,
            sandbox.sandboxHostId,
            pinned?.hostOwnerId ?? owner.ownerId,
          );
        if (
          !(
            spec.kind === "STOP_SANDBOX" &&
            (await hasSupersedableTeardown(tx, sandbox, owner.ownerId, ["STOP_SANDBOX"]))
          )
        ) {
          requireState(sandbox, spec.allowedStates, spec.conflictMessage);
        }
        // A capture copies the stopped root directly (M2): no start or reconnect
        // until it settles. Kill still preempts it.
        if (
          spec.kind === "RECONNECT_SANDBOX" &&
          sandbox.state === "STOPPED" &&
          (
            await tx.$queryRaw<
              { id: string }[]
            >`SELECT "operationId" AS id FROM sandbox_template_capture
            WHERE "sandboxId" = ${sandbox.id} AND state::text IN ('PENDING', 'CAPTURED', 'STORING') LIMIT 1`
          )?.length
        )
          throw captureBusy();
        // step 4: while an eviction of the cached copy is
        // granted (EVICTING), a start waits for the restore that follows.
        if (
          spec.kind === "RECONNECT_SANDBOX" &&
          sandbox.state === "STOPPED" &&
          sandbox.diskOffloadId != null &&
          (
            await tx.$queryRaw<{ id: string }[]>`SELECT id FROM sandbox_disk_offload
            WHERE id = ${sandbox.diskOffloadId} AND state::text = 'EVICTING' FOR SHARE`
          ).length > 0
        )
          throw diskEvicting();
        // §8.1: a cold start first supersedes a not-yet-STORED offload (X2),
        // and a cached STORED copy boots only on an eligible cached host,
        // with `expectDisk` binding the copy it expects.
        let expectDisk: { seq: number; fingerprint: string } | null = null;
        if (spec.kind === "RECONNECT_SANDBOX" && sandbox.state === "STOPPED") {
          await supersedeOnAdmission(tx, sandbox.id);
          expectDisk = await cachedDiskExpectation(tx, owner.ownerId, sandbox.id, cachedFallback);
        }
        if (
          spec.kind === "RECONNECT_SANDBOX" &&
          sandbox.state === "STOPPED" &&
          sandbox.sandboxHostId != null
        ) {
          // A cold reconnect relaunches the VM, so it is a launch: the current
          // egress capability is re-checked under the host lock taken above,
          // before the launch intent (operation, slot, outbox) exists.
          const capable = await tx.sandboxHost.findFirst({
            where: { id: sandbox.sandboxHostId, userId: pinned?.hostOwnerId ?? owner.ownerId },
            select: { egressEnforcement: true },
          });
          if (!capable?.egressEnforcement) throw unsupportedCapability("egress");
          // CLI logins (§7.4.2): a credentialed cold start waits for its host's
          // census to settle every envelope; an offline host is pending_drain.
          resumeCredentials = await assertCredentialDrain(tx, {
            sandboxId: sandbox.id,
            hostId: sandbox.sandboxHostId,
          });
          await requireRetainedStorage(tx, {
            hostId: sandbox.sandboxHostId,
            ownerId: owner.ownerId,
            sandboxId: sandbox.id,
            allowOffline: true,
          });
        }
        const advanceGeneration =
          typeof spec.advanceGeneration === "function"
            ? spec.advanceGeneration(sandbox.state)
            : spec.advanceGeneration === true;
        let boundGeneration = sandbox.generation;
        if (spec.skipStateUpdate !== true) {
          const nextState = spec.nextState;
          if (nextState == null) {
            throw sandboxStateConflict(
              "Lifecycle enqueue requires an explicit next sandbox state.",
            );
          }
          boundGeneration = await casExistingSandboxState(tx, sandbox, nextState, {
            advanceGeneration,
          });
        } else if (advanceGeneration) {
          // Only a cold reconnect advances here. Drain refused it while any lease
          // was RELEASING. The launch leases an UNKNOWN predecessor left behind
          // settle as superseded in their OWN transaction first
          // (`supersedeColdLaunch`), never here: this transaction claims next,
          // and holding settled instances while claiming others can cycle with
          // another settlement (§7.3). Roll back, settle, retry.
          if (resumeCredentials && (await hasSupersededLaunchLeases(tx, sandbox.id)))
            throw new SupersededLaunchPending(sandbox.generation);
          boundGeneration = await casExistingSandboxState(tx, sandbox, undefined, {
            advanceGeneration: true,
          });
          if (resumeCredentials) await dropSupersededSpecs(tx, sandbox.id, boundGeneration);
        } else {
          const admitted = await tx.sandbox.updateMany({
            where: {
              id: sandbox.id,
              userId: owner.ownerId,
              generation: sandbox.generation,
              state: sandbox.state,
            },
            data: { generation: sandbox.generation },
          });
          if (admitted.count !== 1) {
            throw sandboxStateConflict();
          }
        }

        // S is held by the CAS above: the stop's policy lands with the stop.
        // Managed sandboxes are never offloaded and refuse a policy.
        if (
          spec.offloadPolicy &&
          (
            await tx.sandbox.updateMany({
              where: { id: sandbox.id, userId: owner.ownerId, purpose: "WORKLOAD" },
              data: spec.offloadPolicy,
            })
          ).count !== 1
        )
          throw sandboxStateConflict("Managed sandboxes are never offloaded.");
        let acceptedLease: Partial<ReturnType<typeof acceptedLeaseFields>> = {};
        let rearmedAt: Date | null = null;
        if (spec.rearmLease) {
          // S is held by the preceding CAS. Every accepted connect gets its own
          // revision, including a no-op extension; replay never executes here.
          const now = await leaseTransactionNow(tx, spec.rearmLease.clock);
          rearmedAt = now;
          // G (lease path), H and S are held: the limit is stable until commit.
          // The origin path of an own-host row is unaffected by the usage clear.
          requireLeaseWithinPolicy(
            leaseRequestOf(spec.rearmLease.timeoutMs),
            await readLockedPathLimit(tx, sandbox),
          );
          const candidate = resolveLeaseTimeout(spec.rearmLease.timeoutMs, now.getTime());
          if (!advanceGeneration && isLeaseDeadlinePassed(sandbox.leaseExpiresAtEffective, now))
            throw sandboxStateConflict("Sandbox lease already expired on the host.");
          if (sandbox.leaseRevision >= 2_147_483_647)
            throw sandboxStateConflict("Lease revision exhausted.");
          const expiresAt = advanceGeneration
            ? candidate
            : new Date(
                Math.max(
                  candidate.getTime(),
                  sandbox.leaseExpiresAt?.getTime() ?? 0,
                  sandbox.leaseExpiresAtEffective?.getTime() ?? 0,
                ),
              );
          const revision = sandbox.leaseRevision + 1;
          const rearmed = await tx.sandbox.updateMany({
            where: { id: sandbox.id, userId: owner.ownerId, generation: boundGeneration },
            data: {
              leaseRevision: revision,
              leaseExpiresAt: expiresAt,
              leaseExpiresAtRequested: expiresAt,
              leaseExpireActionRequested: sandbox.leaseExpireAction,
              ...(advanceGeneration
                ? {
                    leaseRevisionEffective: null,
                    leaseExpiresAtEffective: null,
                    leaseExpireActionEffective: null,
                    startedAt: null,
                    readyAt: null,
                  }
                : {}),
            },
          });
          if (rearmed.count !== 1) throw sandboxStateConflict();
          acceptedLease = acceptedLeaseFields({
            now,
            timeoutMs: spec.rearmLease.timeoutMs,
            revision,
            expiresAt,
            action: sandbox.leaseExpireAction,
          });
        }

        // Cursor replay is bypassed by operationTransaction's durable lookup.
        // Fresh continuation acceptance uses the locked sandbox generation.
        // Commands and typed filesystem/process operations use the sole active codec.
        const typedCommand = spec.kind === "RUN_COMMAND";
        const typedResult = spec.fsProcess !== undefined || typedCommand;
        const cursor = typeof spec.payload.cursor === "string" ? spec.payload.cursor : undefined;
        const inherited =
          cursor && (spec.kind === "LIST_DIR" || spec.kind === "LIST_PROCESSES")
            ? await readResultContinuationInTransaction(tx, owner, {
                cursor,
                sandboxId: sandbox.id,
                generation: boundGeneration,
                kind: spec.kind,
                root: typeof spec.payload.path === "string" ? spec.payload.path : "/",
                depth: typeof spec.payload.depth === "number" ? spec.payload.depth : 1,
                limit:
                  typeof spec.payload.limit === "number"
                    ? spec.payload.limit
                    : RESULT_LIMITS.listDefaultLimit,
              })
            : null;
        const { cursor: _cursor, ...dispatchPayload } = spec.payload;
        // CLI logins (§7.2 resume rules): claims run after S and before O, so
        // the operation id is assigned here for the leases to name.
        const preassignedOperationId = resumeCredentials
          ? `op${randomUUID().replaceAll("-", "")}`
          : null;
        if (preassignedOperationId && sandbox.sandboxHostId) {
          // §6.1: the worst-case spec must fit before any claim.
          await preflightCredentialSpec(tx, {
            sandboxId: sandbox.id,
            credentialIds: (
              await tx.sandboxCredential.findMany({
                where: { sandboxId: sandbox.id, detachedAt: null },
                select: { credentialId: true },
                orderBy: { credentialId: "asc" },
                take: 8,
              })
            ).map((attachment) => attachment.credentialId),
          });
          // The claim gate inside covers every attachment it claims, pinned or not.
          await claimResumeLeases(tx, {
            principal: owner,
            ownerId: owner.ownerId,
            sandboxId: sandbox.id,
            operationId: preassignedOperationId,
            hostId: sandbox.sandboxHostId,
            generation: boundGeneration,
            pins: spec.credentialPins,
          });
        } else if ((spec.credentialPins?.length ?? 0) > 0)
          // A pin names a login this start would not claim (warm start, or a
          // sandbox without that attachment): refuse rather than ignore it.
          throw credentialError("credential.not_attached");
        const teardownPriorState =
          spec.kind === "STOP_SANDBOX" ? await resolveTeardownPriorState(tx, sandbox) : null;
        const row = await tx.sandboxOperation.create({
          data: {
            ...(preassignedOperationId ? { id: preassignedOperationId } : {}),
            ...(teardownPriorState ? { teardownPriorState } : {}),
            authorizingKeyId: recordedKeyIdOf(owner),
            userId: owner.ownerId,
            sandboxId: sandbox.id,
            kind: spec.kind,
            ...acceptedLease,
            state: "QUEUED",
            generation: boundGeneration,
            idempotencyKey: idempotencyKeyValue,
            requestBodyHash: bodyHash(),
            digestContext: operationDigestContext(tx),
            ...requestDigestMetadata(spec.kind),
            // §8.4: immutable launch semantics (STOPPED → COLD, READY → WARM).
            launchMode:
              spec.kind === "RECONNECT_SANDBOX"
                ? acceptedLaunchMode(spec.kind, sandbox.state)
                : null,
            // Initial stdin is at most one 32 KiB chunk: sequence 0 is consumed.
            nextStdinSequence:
              spec.kind === "RUN_COMMAND" && spec.payload.hasStdin === true ? 1 : 0,
            stdinClosed: spec.kind === "RUN_COMMAND" && spec.payload.hasStdin === true,
            ...initialResultFields(spec.kind, typedResult),
            ...initialProcessFields(spec.kind),
          },
        });

        if (advanceGeneration && spec.kind === "RECONNECT_SANDBOX") {
          const previous = await tx.sandboxPlacement.findFirst({
            where: {
              id: sandbox.currentPlacementId ?? "missing",
              sandboxId: sandbox.id,
              userId: owner.ownerId,
            },
          });
          if (!previous) throw sandboxStateConflict("Sandbox placement is missing.");
          const placement = await tx.sandboxPlacement.create({
            data: {
              userId: owner.ownerId,
              hostOwnerId: pinned?.hostOwnerId ?? previous.hostOwnerId,
              originShareId: previous.originShareId,
              acceptedGraceSeconds: Math.max(
                previous.acceptedGraceSeconds,
                coldPool?.pool.disconnectGraceSeconds ?? 0,
              ),
              sandboxId: sandbox.id,
              generation: boundGeneration,
              operationId: row.id,
              kind: previous.kind,
              originHostId: previous.originHostId,
              originPoolId: previous.originPoolId,
              originMemberId: previous.originMemberId,
              templateId: previous.templateId,
              templateRevisionId: previous.templateRevisionId,
              cpuCount: previous.cpuCount,
              memoryMiB: previous.memoryMiB,
              diskGiB: previous.diskGiB,
              storagePoolId: previous.storagePoolId,
              storagePoolName: previous.storagePoolName,
              storageMarker: previous.storageMarker,
              rootChargeGiB: previous.rootChargeGiB,
              chargedMemoryMiB: sandbox.liveResourcesHeld
                ? previous.chargedMemoryMiB
                : vmLiveMemoryChargeMiB(previous.memoryMiB),
              chargedVcpu: sandbox.liveResourcesHeld ? previous.chargedVcpu : previous.cpuCount,
              artifact: previous.artifact,
              architecture: previous.architecture,
              guestUid: previous.guestUid,
              guestGid: previous.guestGid,
              guestHome: previous.guestHome,
              guestShell: previous.guestShell,
              configId: previous.configId,
              acceptedAt: row.leaseAcceptedAt ?? row.createdAt,
            },
          });
          await tx.sandbox.update({
            where: { id: sandbox.id },
            data: { currentPlacementId: placement.id },
          });
          await reserveLiveResources(tx, {
            hostId: sandbox.sandboxHostId ?? previous.originHostId,
            ownerId: owner.ownerId,
            sandboxId: sandbox.id,
          });
        }
        if (advanceGeneration)
          await retireSupersededOperations(tx, owner.ownerId, sandbox.id, boundGeneration);
        // CLI logins (§7.5): a user stop settles login leases beside the
        // retirement. A cold reconnect (the other advancing kind here) settled
        // its superseded launch leases above, before its claims, and needs no
        // teardown settlement: drain refused it while any lease was RELEASING.
        if (advanceGeneration && spec.kind === "STOP_SANDBOX")
          await settleCredentialTeardown(tx, {
            sandboxId: sandbox.id,
            priorState: teardownPriorState ?? sandbox.state,
            generation: boundGeneration,
            teardownOperationId: row.id,
            skip: spec.payload.credentialCapture === "skip",
          });
        // CLI logins (§6.1): the cold start's spec (inject / recover leases and
        // residue to recover or scrub) is stored with the operation.
        const credentialSpec = resumeCredentials
          ? await writeLaunchSpec(tx, { sandboxId: sandbox.id, operationId: row.id })
          : null;

        await createSandboxOutboxEvent(tx, {
          authorizingPrincipal: attributionOf(owner),
          userId: owner.ownerId,
          aggregateId: sandbox.id,
          eventType: spec.eventType,
          payload: {
            sandboxId: sandbox.id,
            sandboxHostId: sandbox.sandboxHostId,
            generation: boundGeneration,
            dispatchAttempt: 0,
            operationId: row.id,
            idempotencyKey: idempotencyKeyValue,
            kind: OPERATION_DISPATCH_KIND[spec.kind],
            incusName: defaultIncusInstanceName(sandbox.id),
            // A cold reconnect relaunches the VM; the host re-enforces the
            // recorded policy, so the durable payload carries it verbatim.
            ...(spec.kind === "RECONNECT_SANDBOX"
              ? (() => {
                  const recorded = recordedEgressPolicy(sandbox);
                  return { egressPolicy: recorded.wire, egressPolicyHash: recorded.hash };
                })()
              : {}),
            ...dispatchPayload,
            ...(expectDisk ? { expectDisk } : {}),
            ...(credentialSpec ? { credentialSpec } : {}),
            ...(typedResult ? { resultVersion: 1 } : {}),
            ...(inherited ? { continuation: inherited.continuation } : {}),
          },
        });

        if (spec.fsProcess && isContentResultKind(spec.kind))
          await reserveOperationResult(tx, {
            ownerId: owner.ownerId,
            operationId: row.id,
            inheritedExpiresAt: inherited?.expiresAt,
          });
        // M2/N1: a warm re-arm keeps max(candidate, requested, effective), since
        // the host refuses a shortening reconnect. When that is over the lease
        // limit (a pull-in not yet acknowledged), shorten it here, at the END of
        // the closure: the reconnect's operation and outbox already carry
        // revision r+1, so this system renewal is r+2 and arrives after it.
        if (rearmedAt && !advanceGeneration)
          await pullInLeaseLocked(tx, { id: sandbox.id, userId: owner.ownerId }, rearmedAt);
        return { id: row.id, state: row.state };
      },
      async (_tx, prior) => prior,
    );
  let operation: Awaited<ReturnType<typeof accept>> | undefined;
  for (let attempt = 0; operation === undefined; attempt++) {
    try {
      operation = await accept();
    } catch (error: unknown) {
      // A cold reconnect found its predecessor's launch leases unsettled:
      // settle them in their own transaction, then accept again (bounded).
      if (error instanceof SupersededLaunchPending && attempt < 2) {
        await supersedeColdLaunch(owner, sandboxId, error.generation).catch((cause: unknown) =>
          rethrowSensitiveSandboxError(serviceAdmissionError(cause)),
        );
        continue;
      }
      // §5 order 3/4: the cached host may not take its copy back. Online:
      // a server-issued evict grant, then `sandbox.disk_evicting` (retry
      // restores elsewhere); a copy its host refused (`disk_stale`, or an
      // evict grant it let expire unused) cannot be evicted, so it goes to
      // the discard. Offline: the gated STALE detach. A detach accepts again
      // as a restore; every path refused: the copy stays cached.
      if (error instanceof CachedCopyIneligible && attempt < 2) {
        if (error.hostOnline && (await grantServerEviction(sandboxId))) throw diskEvicting();
        if (await detachStaleCachedCopy(owner.ownerId, sandboxId)) continue;
        cachedFallback = true;
        continue;
      }
      rethrowSensitiveSandboxError(
        serviceAdmissionError(
          error instanceof SupersededLaunchPending ? sandboxStateConflict() : error,
        ),
      );
    }
  }

  return { operationId: operation.id, state: operation.state };
}

/** A cold reconnect must first settle its predecessor's launch leases (§7.1). */
class SupersededLaunchPending extends Error {
  constructor(readonly generation: number) {
    super("superseded launch leases pending");
  }
}

/**
 * The first half of a cold reconnect with an UNKNOWN predecessor (§7.1
 * supersession, §7.3): its own committed transaction, User (admission) → H
 * → S, that supersedes the predecessor exactly as the reconnect's generation
 * advance would — generation + 1 on the STOPPED sandbox, earlier operations
 * retired — and settles the leases it left (`settleSupersededLaunchLeases`,
 * under the full settlement scope). The reconnect then claims in a separate
 * transaction holding no settled instance. Idempotent: a sandbox that moved
 * on (another generation, not STOPPED) or has nothing left to settle is left
 * alone, and a crash after this commit leaves a STOPPED sandbox whose next
 * reconnect simply proceeds. Instances freed here may be taken by others
 * before the claim; the resume rules then apply as usual.
 */
async function supersedeColdLaunch(owner: Principal, sandboxId: string, generation: number) {
  await prisma.$transaction(async (tx) => {
    await lockOwnerForAdmission(tx, owner.ownerId);
    const located = await tx.sandbox.findFirst({
      where: { id: sandboxId, userId: owner.ownerId },
      select: { sandboxHostId: true },
    });
    if (!located) return;
    await lockHostForSandboxOperation(tx, located.sandboxHostId, owner.ownerId, sandboxId);
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} AND "userId" = ${owner.ownerId} FOR NO KEY UPDATE`;
    const sandbox = await tx.sandbox.findFirst({
      where: { id: sandboxId, userId: owner.ownerId },
      select: { id: true, state: true, generation: true, sandboxHostId: true },
    });
    if (
      sandbox?.state !== "STOPPED" ||
      sandbox.generation !== generation ||
      sandbox.sandboxHostId !== located.sandboxHostId ||
      !(await hasSupersededLaunchLeases(tx, sandboxId))
    )
      return;
    const superseding = await casExistingSandboxState(tx, sandbox, undefined, {
      advanceGeneration: true,
    });
    await retireSupersededOperations(tx, owner.ownerId, sandboxId, superseding);
    await settleSupersededLaunchLeases(tx, { sandboxId, generation: superseding });
  });
}

async function rejectUnsupported(
  owner: Principal,
  sandboxId: string,
  capability: "snapshot" | "restore" | "fork",
): Promise<never> {
  await ownedSandbox(sandboxId, owner.ownerId);
  throw unsupportedCapability(capability);
}

export const listSandboxes = serviceProcedure(
  { action: "sandboxes.list" },
  async (owner: Principal, input: ListSandboxesInput) => {
    const query = await sandboxListReadQuery(owner, input);
    const rows = await prisma.sandbox.findMany({
      where: query.where,
      orderBy: query.orderBy,
      take: query.take,
      select: sandboxReadSelect,
    });
    await authorizeServiceAction(owner, "sandboxes.list");
    const waits = await capacityWaitViews(
      prisma,
      owner.ownerId,
      rows.filter((row) => row.state === "WAITING_FOR_CAPACITY").map((row) => row.id),
    );
    return sandboxListPage(
      rows.map((row) => redactSandbox({ ...row, capacityWait: waits.get(row.id) }, owner.ownerId)),
      query,
    );
  },
);

export const getSandbox = serviceProcedure(
  { action: "sandboxes.get", target: (input: SandboxIdInput) => ({ sandboxId: input.id }) },
  async (owner: Principal, input: SandboxIdInput) => {
    const sandbox = await findOwnedOrThrow({
      find: (args) => prisma.sandbox.findFirst(args),
      args: { where: { id: input.id }, select: sandboxReadSelect },
      owner: { field: "userId", id: owner.ownerId },
      notFound: NOT_FOUND,
    });
    const capacityWait =
      sandbox.state === "WAITING_FOR_CAPACITY"
        ? (await capacityWaitViews(prisma, owner.ownerId, [sandbox.id])).get(sandbox.id)
        : undefined;
    return redactSandbox({ ...sandbox, capacityWait }, owner.ownerId);
  },
);

export const getOperation = serviceProcedure(
  {
    action: "operations.get",
    target: (input: OperationIdInput) => ({ operationId: input.operationId }),
  },
  async (owner: Principal, input: OperationIdInput) => {
    const result = await ownedOperation(input.operationId, owner.ownerId, operationPublicSelect);
    await authorizeServiceAction(owner, "operations.get", { operationId: input.operationId });
    // The fixed readiness label recorded with a `guest_unavailable` failure.
    const readinessReason =
      result.errorCode === "guest_unavailable"
        ? readinessReasonOfFailure(result.failure)
        : undefined;
    return {
      ...result,
      ...(readinessReason ? { readinessReason } : {}),
      failure: failureSchema.safeParse(result.failure).data ?? null,
      errorCode: publicOperationErrorCode(result.errorCode),
    };
  },
);

export const createSandbox = serviceProcedure(
  {
    action: "sandboxes.createIntent",
  },
  async (
    owner: Principal,
    input: CreateSandboxInput,
    clock: LeaseClock = leaseNow,
    /** Internal: the orchestrator's build VM
     * create. Required exactly when the principal is a build, and must name
     * that build; the public input never carries it. */
    buildCreate?: { buildId: string; role?: BuildRole },
    /**
     * Server-internal only (never from a request): a managed sandbox (MS0)
     * with its own placement context and post-S rows — the CLI-login flow.
     */
    managed?: ManagedCreate & { credential: CredentialPlacementContext },
  ) => {
    const buildId = buildIdOf(owner);
    if ((buildCreate?.buildId ?? null) !== buildId) throw buildArgumentRefused();
    // A build VM is TEMPLATE_BUILD by its principal; it is never another managed create.
    if (managed && buildId !== null) throw buildArgumentRefused();
    // Community verify (community-base T4, D-O): a verify VM never waits for
    // capacity, and no build principal's VM ever carries guestSudo. The role
    // the orchestrator names is asserted against the one the in-transaction
    // authorization derived from durable facts (T1, review4 U1).
    const buildRole: BuildRole | null = buildCreate ? (buildCreate.role ?? "build") : null;
    if (buildRole === "verify" && input.waitForCapacityMs !== undefined)
      throw buildArgumentRefused();
    if (buildRole !== null && input.guestSudo === true) throw buildArgumentRefused();
    // A build is exempt; the helper stays kind-free.
    const budgetOwner = budgetSubjectOf(owner)?.ownerId;
    if (budgetOwner) await consumeCreateConnectBudget(budgetOwner);
    if (managed && (input.waitForCapacityMs !== undefined || (input.credentials?.length ?? 0) > 0))
      throw new ORPCError("BAD_REQUEST", { message: "Invalid managed create." });
    if (input.metadata !== undefined && !metadataSchema.safeParse(input.metadata).success)
      throw new ORPCError("BAD_REQUEST", { data: { code: "sandbox.metadata_invalid" } });
    if (input.lifecycle?.onTimeout === "pause" || input.lifecycle?.autoResume === true)
      throw unsupportedCapability("pause");
    if (input.network?.ingress !== undefined) throw unsupportedCapability("ingress");
    // Preview tunnels: declared ports are a WORKLOAD feature of a deployment
    // whose admin configured a tunnel server (refused before any write).
    // `tunnelPorts` (even `[]`) makes a tunnel sandbox: pinned on its host,
    // placed on tunnel hosts, and allowed to change its ports later.
    const tunnel = input.network?.tunnelPorts !== undefined;
    const tunnelPorts = input.network?.tunnelPorts
      ? normalizeTunnelPorts(input.network.tunnelPorts)
      : [];
    if (tunnel) {
      if (buildId !== null || managed !== undefined)
        throw new ORPCError("BAD_REQUEST", { message: "Invalid managed create." });
      if (!(await tunnelConfigured())) throw tunnelRefused("tunnel_off");
    }
    requireCreateCredentialsAllowed(owner, input.credentials);
    const credentialRequests = input.credentials ?? [];
    // Direct placement is the host owner's escape hatch: it never joins a
    // queue. Waits are disabled on a direct target: the typed refusal quotes
    // maxWaitMs 0 ("waits disabled") instead of a generic invalid request.
    if (input.waitForCapacityMs !== undefined && input.sandboxHostId !== undefined)
      throw capacityWaitExceedsPolicy(0);
    // The wait limit is checked inside resolveTarget, once the pool is
    // visible, so a refusal quotes the effective (deployment and pool) max.
    const overrides = executionEnvPairs(input.envs ?? {});
    let resolved: PlacedResult | undefined;
    let queued: CapacityEntryPlan | undefined;
    // Normalize before the transaction: an invalid policy never reaches
    // admission, so a rejected create records no sandbox, operation or outbox
    // row. The resolved policy/hash below are the only values ever persisted.
    const egress = resolveCreateEgressPolicy(input.egress);
    validateVmSizeOverrides(input);
    // guestSudo (DG-6, R13): only a WORKLOAD sandbox may have it, and it
    // defaults on there. A build VM or a CLI-login session resolves to false
    // first; an explicit true for one is then refused. Resolved after the
    // idempotency intent's input, which hashes the body as sent.
    if ((buildId !== null || managed !== undefined) && input.guestSudo === true)
      throw new ORPCError("BAD_REQUEST", { message: "Invalid managed create." });
    const guestSudoRequested =
      buildId === null && managed === undefined && (input.guestSudo ?? true);
    // Offload policy: WORKLOAD only (managed sandboxes are never offloaded).
    if ((buildId !== null || managed !== undefined) && input.offload !== undefined)
      throw new ORPCError("BAD_REQUEST", { message: "Invalid managed create." });
    const offloadPolicy = input.offload ? offloadPolicyColumns(input.offload) : undefined;
    const intent: CreateIntent = {
      originalSelector: input.template,
      overrides: Object.fromEntries(overrides),
      metadata: (input.metadata ?? {}) as Record<string, unknown>,
      egress: { request: egress },
      timeoutMs: input.timeoutMs ?? LEASE_DEFAULT_MS,
      onExpire: input.lifecycle?.onTimeout === "stop" ? "stop" : "destroy",
      guestSudo: guestSudoRequested,
      ...(tunnel ? { tunnelPorts } : {}),
    };
    const created = retryPlacement(() =>
      operationTransaction(
        owner,
        {
          key: input.idempotencyKey,
          intent: {
            ...input,
            envs: overrides.length > 0 ? Object.fromEntries(overrides) : undefined,
            timeoutMs: input.timeoutMs ?? LEASE_DEFAULT_MS,
            lifecycle: { onTimeout: input.lifecycle?.onTimeout ?? "kill", autoResume: false },
          },
          kind: "CREATE_SANDBOX",
          action: "sandboxes.create",
          target: { sandboxHostId: input.sandboxHostId },
          admissionPrincipals: input.poolId
            ? (tx) =>
                discoverPlacementPrincipals(tx, owner, {
                  poolId: input.poolId,
                  idempotencyKey: input.idempotencyKey,
                })
            : undefined,
          resolveTarget: async (tx) => {
            resolved = undefined;
            queued = undefined;
            const gate = input.poolId ? capacityGate(null) : undefined;
            // CLI logins (§8): the owner and capability stages for the
            // named logins, from rows read inside this transaction.
            const placementInput = {
              ...input,
              egressMode: egress.mode,
              tunnel,
              credential:
                managed?.credential ??
                (await credentialPlacementContextFor(
                  tx,
                  credentialRequests.map((request) => request.credentialId),
                )),
            };
            // E1-B-05: a login that cannot be claimed now is refused before
            // placement can answer with a (misleading) capacity refusal.
            // Visibility first, so an invisible login stays `credential.not_found`.
            // A create that may wait keeps the static and READY checks only:
            // its slot is decided at placement (a held one may free first).
            const mayWait = input.waitForCapacityMs !== undefined && input.poolId !== undefined;
            if (!managed && credentialRequests.length > 0) {
              await requireUsableLogins(
                tx,
                owner,
                credentialRequests.map((request) => request.credentialId),
              );
              for (const request of credentialRequests)
                await refuseUnclaimableLogin(tx, owner.ownerId, request, { slots: !mayWait });
            }
            if (input.waitForCapacityMs !== undefined && input.poolId) {
              const outcome = await resolvePlacement(tx, owner, placementInput, {
                gate,
                allowWait: true,
                buildId: buildRole === "build" ? buildId : null,
                rebuildOnMiss: true,
              });
              // Under the placement lock resolvePlacement took (pool path).
              await requireKeySandboxAllowance(tx, owner);
              if ("kind" in outcome) {
                queued = await admitCapacityWait(tx, owner, input.waitForCapacityMs, outcome);
                return queuedPoolContext({
                  sandboxHostId: null,
                  templateRevisionId: queued.revision.id,
                  originPoolId: queued.poolId,
                });
              }
              await requireEntryWaitWithinPolicy(tx, input.poolId, input.waitForCapacityMs);
              resolved = outcome;
            }
            // A verify VM uses ordinary placement: no BuildPlacement, no
            // builder requirement (community-base S9 "Placement").
            else {
              resolved = await resolvePlacement(tx, owner, placementInput, {
                gate,
                buildId: buildRole === "build" ? buildId : null,
              });
              // Under the placement lock resolvePlacement took (direct or pool path).
              await requireKeySandboxAllowance(tx, owner);
            }
            return {
              sandboxHostId: resolved.hostId,
              templateRevisionId: resolved.revision.id,
              originPoolId: resolved.poolId,
            };
          },
          queuedDigest: () => queued !== undefined,
        },
        async (tx, bodyHash, context) => {
          if (buildRole !== null && buildRoleOf(context) !== buildRole)
            throw buildArgumentRefused();
          if (queued) {
            const sandboxId = await enqueueCapacityWait(tx, owner, queued, intent, {
              idempotencyKey: input.idempotencyKey,
              bodyHash,
              name: input.name,
              expectedDisconnectGraceSeconds: input.expectedDisconnectGraceSeconds,
              credentials: credentialRequests,
              ...(offloadPolicy ? { offloadPolicy } : {}),
              ...(buildRole ? { buildRole } : {}),
            });
            const sandbox = await tx.sandbox.findFirstOrThrow({
              where: { id: sandboxId, userId: owner.ownerId },
              select: sandboxSelect,
            });
            return redactSandbox(sandbox, owner.ownerId);
          }
          const placementTarget = resolved;
          if (!placementTarget) throw templateNotFound();
          const sandboxId = await materializePlacement(
            tx,
            owner,
            placementTarget,
            intent,
            {
              idempotencyKey: input.idempotencyKey,
              fresh: {
                bodyHash,
                name: input.name,
                credentials: credentialRequests,
                ...(offloadPolicy ? { offloadPolicy } : {}),
                ...(buildRole ? { buildRole } : {}),
                ...(managed
                  ? { managed: { purpose: managed.purpose, afterSandbox: managed.afterSandbox } }
                  : {}),
              },
            },
            clock,
          );
          const sandbox = await tx.sandbox.findFirstOrThrow({
            where: { id: sandboxId, userId: owner.ownerId },
            select: sandboxSelect,
          });
          return redactSandbox(
            { ...sandbox, acceptedGraceSeconds: placementTarget.acceptedGraceSeconds },
            owner.ownerId,
          );
        },
        async (tx, prior) => {
          const sandbox = await tx.sandbox.findFirst({
            where: { id: prior.sandboxId, userId: owner.ownerId },
            select: sandboxSelect,
          });
          if (!sandbox) throw new ORPCError("NOT_FOUND");
          return redactSandbox(sandbox, owner.ownerId);
        },
      ),
    );
    return created.then(
      (sandbox) => {
        // A wait on a rebuild (template-builds §3.9): wake the orchestrator.
        if (queued?.blocker === "image_rebuilding") notifyTemplateBuildsChanged();
        return sandbox;
      },
      async (error: unknown) =>
        rethrowSensitiveSandboxError(
          serviceAdmissionError(await rebuildAfterRefusal(owner, input.template, error)),
        ),
    );
  },
);

export const killSandbox = serviceProcedure(
  {
    action: "sandboxes.kill",
    intentOnly: true,
    target: (input: KillSandboxInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: KillSandboxInput) => {
    return operationTransaction(
      owner,
      {
        key: input.idempotencyKey,
        // `skip` is part of the intent only when present, so existing keys keep their hash.
        intent: {
          sandboxId: input.id,
          ...(input.credentialCapture === "skip" ? { credentialCapture: "skip" } : {}),
        },
        kind: "KILL_SANDBOX",
        action: "sandboxes.kill",
        target: { sandboxId: input.id },
      },
      async (tx, bodyHash) => {
        // Destroying a create that is still waiting for capacity cancels it:
        // nothing exists on any host, so the KILL completes server-side.
        const cancelled = await cancelCapacityWaitIfWaiting(tx, owner.ownerId, input.id);
        if (cancelled) {
          await recordWaitingTeardown(tx, owner, input.id, input.idempotencyKey, bodyHash, {
            kind: "KILL_SANDBOX",
            generation: cancelled.generation,
          });
          return redactSandbox(await ownedSandbox(input.id, owner.ownerId, tx), owner.ownerId);
        }
        // §8.3c: destroy of an OFFLOADED sandbox whose restore waits ends the
        // wait CANCELLED and its operation `cancelled`, in this transaction.
        await cancelRestoreWaitIfWaiting(tx, owner.ownerId, { sandboxId: input.id });
        // Every read here shares the transaction's connection; a pooled read
        // would self-deadlock a single-connection pool while this tx holds it.
        const located = await ownedSandbox(input.id, owner.ownerId, tx);
        await lockHostForSandboxOperation(tx, located.sandboxHostId, owner.ownerId, input.id);
        const sandbox = await ownedSandbox(input.id, owner.ownerId, tx);
        // Destroy is idempotent: an already-DELETED sandbox (for example one
        // whose create a node daemon restart interrupted) completes at once,
        // with nothing sent to any host.
        if (sandbox.state === "DELETED") {
          await recordWaitingTeardown(tx, owner, sandbox.id, input.idempotencyKey, bodyHash, {
            kind: "KILL_SANDBOX",
            generation: sandbox.generation,
          });
          return redactSandbox(sandbox, owner.ownerId);
        }
        // Destroy of an OFFLOADED sandbox is
        // server-completed (nothing runs on any host). It ends the stored
        // offload through the choke point and goes straight to DELETED.
        // Before killNeedsRecovery: an offloaded disk holds no recoverable
        // login residue (`loginStateSettled` gated its offload).
        if (sandbox.state === OFFLOADED_STATE) {
          await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandbox.id} AND "userId" = ${owner.ownerId} FOR NO KEY UPDATE`;
          const now = await leaseTransactionNow(tx, leaseNow);
          const destroyed = await tx.sandboxOperation.create({
            data: {
              authorizingKeyId: recordedKeyIdOf(owner),
              userId: owner.ownerId,
              sandboxId: sandbox.id,
              kind: "KILL_SANDBOX",
              state: "SUCCEEDED",
              generation: sandbox.generation + 1,
              teardownPriorState: sandbox.state,
              teardownIntent: "OWNER_DESTROY",
              idempotencyKey: input.idempotencyKey,
              requestBodyHash: bodyHash(),
              digestContext: operationDigestContext(tx),
              ...requestDigestMetadata("KILL_SANDBOX"),
              completedAt: now,
              result: { state: "deleted" },
            },
            select: { id: true },
          });
          return finishOffloadedDestroy(tx, owner, sandbox, destroyed.id, now);
        }
        if (
          !KILLABLE_SANDBOX_STATES.has(sandbox.state) &&
          !(await hasSupersedableTeardown(tx, sandbox, owner.ownerId, undefined, true))
        ) {
          throw sandboxStateConflict();
        }
        if (!canTransitionSandboxState(sandbox.state, "STOPPING")) {
          throw invalidSandboxTransition(sandbox.state, "STOPPING");
        }

        // M8: a stopped disk that still holds a recoverable login value is
        // destroyed only with an explicit `credentialCapture: "skip"`.
        if (
          await killNeedsRecovery(tx, {
            sandboxId: sandbox.id,
            state: sandbox.state,
            skip: input.credentialCapture === "skip",
          })
        )
          throw credentialError("credential.recovery_required");

        const template = await pinnedLaunchSource(tx, sandbox.id, owner.ownerId, false);
        const teardownPriorState = await resolveTeardownPriorState(tx, sandbox);

        const boundGeneration = await casExistingSandboxState(tx, sandbox, "STOPPING", {
          advanceGeneration: true,
        });

        const operation = await tx.sandboxOperation.create({
          data: {
            authorizingKeyId: recordedKeyIdOf(owner),
            userId: owner.ownerId,
            sandboxId: sandbox.id,
            kind: "KILL_SANDBOX",
            state: "QUEUED",
            generation: boundGeneration,
            teardownPriorState,
            // S2: an owner destroy of a sandbox with an offloaded disk is
            // recorded as such, so its exit ends DELETED, never OFFLOADED.
            ...(sandbox.diskOffloadId ? { teardownIntent: "OWNER_DESTROY" as const } : {}),
            idempotencyKey: input.idempotencyKey,
            requestBodyHash: bodyHash(),
            digestContext: operationDigestContext(tx),
            ...requestDigestMetadata("KILL_SANDBOX"),
          },
        });

        await retireSupersededOperations(tx, owner.ownerId, sandbox.id, boundGeneration);
        // "Destroy during upload": the kill preempts the
        // daemon's upload; a live, not-yet-STORED offload ends SUPERSEDED
        // (session aborted, keys shredded; the disk sweeper reclaims objects).
        await supersedeLiveOffload(tx, sandbox.id);
        await settleCredentialTeardown(tx, {
          sandboxId: sandbox.id,
          priorState: teardownPriorState,
          generation: boundGeneration,
          teardownOperationId: operation.id,
          skip: input.credentialCapture === "skip",
        });

        await createSandboxOutboxEvent(tx, {
          authorizingPrincipal: attributionOf(owner),
          userId: owner.ownerId,
          aggregateId: sandbox.id,
          eventType: "sandbox.kill_requested",
          payload: {
            sandboxId: sandbox.id,
            sandboxHostId: sandbox.sandboxHostId,
            generation: boundGeneration,
            dispatchAttempt: 0,
            ...(template
              ? templateDispatchPayload(template)
              : { templateDigest: "", incusFingerprint: "" }),
            incusName: defaultIncusInstanceName(sandbox.id),
            operationId: operation.id,
            idempotencyKey: input.idempotencyKey,
            kind: OPERATION_DISPATCH_KIND.KILL_SANDBOX,
            ...(input.credentialCapture === "skip" ? { credentialCapture: "skip" } : {}),
          },
        });

        return redactSandbox(
          { ...sandbox, state: "STOPPING" as const, generation: boundGeneration },
          owner.ownerId,
        );
      },
      async (tx, prior) =>
        redactSandbox(await ownedSandbox(prior.sandboxId, owner.ownerId, tx), owner.ownerId),
    );
  },
);

const OFFLOADED_STATE = "OFFLOADED" satisfies SandboxState;

/** The rest of the server-completed owner destroy of an OFFLOADED sandbox
 * (§8.9), after its SUCCEEDED KILL row at generation + 1. */
async function finishOffloadedDestroy(
  tx: Prisma.TransactionClient,
  owner: Principal,
  sandbox: Awaited<ReturnType<typeof ownedSandbox>>,
  destroyOperationId: string,
  now: Date,
) {
  const generation = sandbox.generation + 1;
  await retireSupersededOperations(tx, owner.ownerId, sandbox.id, generation);
  await settleCredentialsOnDeleted(tx, sandbox.id);
  // The choke point writes DELETED itself here: an OFFLOADED row must hold
  // its disk pointer until the same statement leaves OFFLOADED.
  requireRelayFence(
    await endOffloadForDestroy(tx, {
      sandboxId: sandbox.id,
      userId: owner.ownerId,
      destroyOperationId,
      now,
      offloaded: { generation: sandbox.generation },
    }),
  );
  return redactSandbox(await ownedSandbox(sandbox.id, owner.ownerId, tx), owner.ownerId);
}

/** The command schema for a key: a `tb:` key parses with the build variant
 * (bound to the build principal by the caller), every other key strictly. */
function commandInputSchemaFor(input: { idempotencyKey?: unknown }) {
  return typeof input.idempotencyKey === "string" && input.idempotencyKey.startsWith("tb:")
    ? buildRunCommandInput
    : runCommandInput;
}

/** Internal trailing input of a build step. */
export type BuildCommandExtras = { runAs?: RunAsV11; buildCopy?: BuildCopyV11 };

function buildArgumentRefused() {
  return new ORPCError("FORBIDDEN", { message: "Build-only input is not allowed here." });
}

/**
 * Validate a build step's trailing fields against the principal and the
 * immutable sandbox row: only the build principal, only on ITS build VM
 * (`purpose = TEMPLATE_BUILD`, `buildId` equal), only its own context path.
 * The fields are persisted into the command outbox payload in the enqueue
 * transaction; the relay attaches frame fields from that payload alone.
 */
async function buildCommandFields(
  owner: Principal,
  input: RunCommandInput,
  extras: BuildCommandExtras,
): Promise<{ runAs?: RunAsV11; buildCopy?: BuildCopyV11 }> {
  const buildId = buildIdOf(owner);
  if (buildId === null) throw buildArgumentRefused();
  const vm = await prisma.sandbox.findFirst({
    where: { id: input.id, userId: owner.ownerId, purpose: "TEMPLATE_BUILD", buildId },
    select: { id: true },
  });
  if (!vm) throw buildArgumentRefused();
  const fields: { runAs?: RunAsV11; buildCopy?: BuildCopyV11 } = {};
  if (extras.runAs !== undefined) {
    if (!runAsV11Schema.safeParse(extras.runAs).success) throw buildArgumentRefused();
    fields.runAs = extras.runAs;
  }
  if (extras.buildCopy !== undefined) {
    const copy = buildCopyV11Schema.safeParse(extras.buildCopy);
    if (
      !copy.success ||
      fields.runAs !== undefined ||
      buildIdOfContextPath(copy.data.contextPath) !== buildId ||
      (input.envs != null && Object.keys(input.envs).length > 0) ||
      input.stdinBase64 != null
    )
      throw buildArgumentRefused();
    fields.buildCopy = copy.data;
  }
  return fields;
}

/** The default cwd of a workload sandbox's revision, or undefined. */
async function revisionDefaultCwd(owner: Principal, sandboxId: string) {
  const row = await prisma.sandbox.findFirst({
    where: { id: sandboxId, userId: owner.ownerId, purpose: "WORKLOAD" },
    select: { SandboxTemplateRevision: { select: { defaultCwd: true } } },
  });
  return row?.SandboxTemplateRevision.defaultCwd ?? undefined;
}

export const runCommand = serviceProcedure(
  {
    action: "commands.run",
    intentOnly: true,
    target: (input: RunCommandInput) => {
      // Validate before the authorization resolver performs resource IO. A
      // `tb:` key is bound to the build principal in the body below.
      const parsed = commandInputSchemaFor(input).safeParse(input);
      if (!parsed.success)
        throw new ORPCError("BAD_REQUEST", { message: "Invalid command payload." });
      return { sandboxId: parsed.data.id };
    },
  },
  async (owner: Principal, input: RunCommandInput, buildExtras?: BuildCommandExtras) => {
    // Native service callers share the router contract; types alone do not
    // enforce exclusivity or encoded byte budgets at runtime.
    const parsed = commandInputSchemaFor(input).safeParse(input);
    if (!parsed.success) {
      throw new ORPCError("BAD_REQUEST", { message: "Invalid command payload." });
    }
    input = parsed.data;
    // The reserved `tb:` namespace belongs to the orchestrator: only the build
    // principal, only under its own build id.
    if (isReservedInternalIdempotencyKey(input.idempotencyKey)) {
      const buildId = buildIdOf(owner);
      if (buildId === null || !input.idempotencyKey.startsWith(`tb:${buildId}:`))
        throw new ORPCError("BAD_REQUEST", { message: "Invalid command payload." });
    }
    const buildFields = buildExtras ? await buildCommandFields(owner, input, buildExtras) : {};
    // A command without a cwd runs in the revision's default cwd (a built
    // template's final WORKDIR), as the start command and terminal do. Build
    // VMs and login sandboxes keep the guest home: their steps name a cwd.
    const cwd = input.cwd ?? (buildExtras ? undefined : await revisionDefaultCwd(owner, input.id));
    if (input.stdinBase64 != null) stdinByteLength(input.stdinBase64);
    const envs = input.envs;
    // The only public-map → private-wire adapter; keys are unique and sorted.
    const env =
      envs == null
        ? undefined
        : Object.keys(envs)
            .sort()
            .map((key): [string, string] => [key, envs[key]!]);
    return enqueueOwnedOperation(owner, input.id, input.idempotencyKey, {
      kind: "RUN_COMMAND",
      fsProcess: { commandEnvironment: (env?.length ?? 0) > 0 },
      eventType: "sandbox.command_requested",
      body: input,
      payload: {
        // A COPY step runs the daemon's fixed helper: no argv/script/env.
        ...("buildCopy" in buildFields
          ? {}
          : input.script != null
            ? { script: input.script }
            : { argv: input.argv }),
        ...buildFields,
        cwd,
        ...(input.startEvidence ? { startEvidence: input.startEvidence } : {}),
        timeoutMs: encodeCommandTimeoutMs(effectiveCommandTimeoutMs(input.timeoutMs)),
        env,
        hasStdin: input.stdinBase64 != null,
        ...(input.stdinBase64 != null ? { stdinBase64: input.stdinBase64 } : {}),
      },
      allowedStates: HEALTHY_GUEST_STATES,
      conflictMessage: "Sandbox is not ready for commands.",
      skipStateUpdate: true,
    });
  },
);

export const readFile = serviceProcedure(
  {
    action: "files.read",
    intentOnly: true,
    target: (input: ReadFileInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: ReadFileInput) => {
    return enqueueOwnedOperation(owner, input.id, input.idempotencyKey, {
      kind: "GET_FILE",
      eventType: "sandbox.file_get_requested",
      body: input,
      payload: { path: input.path },
      allowedStates: HEALTHY_GUEST_STATES,
      conflictMessage: "Sandbox is not ready for file access.",
      skipStateUpdate: true,
    });
  },
);

export const reconnectSandbox = serviceProcedure(
  {
    action: "sandboxes.reconnect",
    intentOnly: true,
    target: (input: ReconnectSandboxInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: ReconnectSandboxInput, clock: LeaseClock = leaseNow) => {
    // A build is exempt; the helper stays kind-free.
    const budgetOwner = budgetSubjectOf(owner)?.ownerId;
    if (budgetOwner) await consumeCreateConnectBudget(budgetOwner);
    requireCreateCredentialsAllowed(owner, input.credentials);
    // §5a: the override of the creating key's allowlists is the owner's
    // dashboard choice only; any SDK principal (unrestricted keys included)
    // and any build is refused, whatever the sandbox's state.
    if (input.overrideCreatorAllowlist === true && !isBrowserSession(owner))
      throw insufficientScope();
    return enqueueOwnedOperation(owner, input.id, input.idempotencyKey, {
      kind: "RECONNECT_SANDBOX",
      eventType: "sandbox.reconnect_requested",
      body: {
        sandboxId: input.id,
        action: "reconnect",
        // The hash binds the requested mode: a warm receipt must never replay
        // for a cold request with the same key. "default" is the deliberate
        // representation of a browser's omitted mode (any of READY/STOPPED).
        mode: input.mode ?? "default",
        timeoutMs: input.timeoutMs ?? LEASE_DEFAULT_MS,
        // Resume pins are part of the intent only when present, so existing
        // keys keep their hash.
        ...(input.credentials?.length ? { credentials: input.credentials } : {}),
        // Restore intent (§8.3a), likewise only when present.
        ...(input.sandboxHostId ? { sandboxHostId: input.sandboxHostId } : {}),
        ...(input.poolId ? { poolId: input.poolId } : {}),
        ...(input.waitForCapacityMs !== undefined
          ? { waitForCapacityMs: input.waitForCapacityMs }
          : {}),
        ...(input.overrideCreatorAllowlist ? { overrideCreatorAllowlist: true } : {}),
      },
      ...(input.credentials?.length ? { credentialPins: input.credentials } : {}),
      restore: {
        request: restoreRequestOf({ ...input, timeoutMs: input.timeoutMs ?? LEASE_DEFAULT_MS }),
        clock,
      },
      payload: {},
      allowedStates:
        input.mode === "warm"
          ? new Set(["READY"])
          : input.mode === "cold"
            ? new Set(["STOPPED"])
            : RECONNECT_STATES,
      conflictMessage: "Sandbox cannot be reconnected from this state.",
      skipStateUpdate: true,
      advanceGeneration: (state) => state === "STOPPED",
      rearmLease: {
        timeoutMs: input.timeoutMs ?? LEASE_DEFAULT_MS,
        clock,
      },
    });
  },
);

export const stopSandbox = serviceProcedure(
  {
    action: "sandboxes.stop",
    intentOnly: true,
    target: (input: StopSandboxInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: StopSandboxInput) => {
    return enqueueOwnedOperation(owner, input.id, input.idempotencyKey, {
      kind: "STOP_SANDBOX",
      eventType: "sandbox.stop_requested",
      body: {
        sandboxId: input.id,
        action: "stop",
        ...(input.credentialCapture === "skip" ? { credentialCapture: "skip" } : {}),
        ...(input.offload ? { offload: input.offload } : {}),
      },
      payload: input.credentialCapture === "skip" ? { credentialCapture: "skip" } : {},
      ...(input.offload ? { offloadPolicy: offloadPolicyColumns(input.offload) } : {}),
      nextState: "STOPPING",
      allowedStates: STOPPABLE_SANDBOX_STATES,
      conflictMessage: "Sandbox cannot be stopped from this state.",
      advanceGeneration: true,
    });
  },
);

export const listDir = serviceProcedure(
  {
    action: "files.listDir",
    intentOnly: true,
    target: (input: ListDirInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: ListDirInput) => {
    return enqueueOwnedOperation(owner, input.id, input.idempotencyKey, {
      kind: "LIST_DIR",
      fsProcess: {},
      eventType: "sandbox.file_list_requested",
      body: input,
      payload: { path: input.path, depth: input.depth, limit: input.limit, cursor: input.cursor },
      allowedStates: HEALTHY_GUEST_STATES,
      conflictMessage: "Sandbox is not ready for this operation.",
      skipStateUpdate: true,
    });
  },
);

export const statPath = serviceProcedure(
  {
    action: "files.stat",
    intentOnly: true,
    target: (input: StatPathInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: StatPathInput) => {
    return enqueueOwnedOperation(owner, input.id, input.idempotencyKey, {
      kind: "STAT_PATH",
      fsProcess: {},
      eventType: "sandbox.file_stat_requested",
      body: input,
      payload: { path: input.path },
      allowedStates: HEALTHY_GUEST_STATES,
      conflictMessage: "Sandbox is not ready for this operation.",
      skipStateUpdate: true,
    });
  },
);

export const mkdir = serviceProcedure(
  {
    action: "files.mkdir",
    intentOnly: true,
    target: (input: MkdirInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: MkdirInput) => {
    return enqueueOwnedOperation(owner, input.id, input.idempotencyKey, {
      kind: "MKDIR",
      fsProcess: {},
      eventType: "sandbox.file_mkdir_requested",
      body: input,
      payload: { path: input.path },
      allowedStates: HEALTHY_GUEST_STATES,
      conflictMessage: "Sandbox is not ready for this operation.",
      skipStateUpdate: true,
    });
  },
);

export const removePath = serviceProcedure(
  {
    action: "files.remove",
    intentOnly: true,
    target: (input: RemovePathInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: RemovePathInput) => {
    return enqueueOwnedOperation(owner, input.id, input.idempotencyKey, {
      kind: "REMOVE_PATH",
      fsProcess: {},
      eventType: "sandbox.file_remove_requested",
      body: input,
      payload: { path: input.path, recursive: input.recursive === true },
      allowedStates: HEALTHY_GUEST_STATES,
      conflictMessage: "Sandbox is not ready for this operation.",
      skipStateUpdate: true,
    });
  },
);

export const movePath = serviceProcedure(
  {
    action: "files.move",
    intentOnly: true,
    target: (input: MovePathInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: MovePathInput) => {
    return enqueueOwnedOperation(owner, input.id, input.idempotencyKey, {
      kind: "MOVE_PATH",
      fsProcess: {},
      eventType: "sandbox.file_move_requested",
      body: input,
      payload: { path: input.path, destPath: input.destPath },
      allowedStates: HEALTHY_GUEST_STATES,
      conflictMessage: "Sandbox is not ready for this operation.",
      skipStateUpdate: true,
    });
  },
);

export const createSnapshot = serviceProcedure(
  { action: "sandboxes.get", target: (input: CreateSnapshotInput) => ({ sandboxId: input.id }) },
  async (owner: Principal, input: CreateSnapshotInput): Promise<never> =>
    rejectUnsupported(owner, input.id, "snapshot"),
);

export const restoreSnapshot = serviceProcedure(
  { action: "sandboxes.get", target: (input: RestoreSnapshotInput) => ({ sandboxId: input.id }) },
  async (owner: Principal, input: RestoreSnapshotInput): Promise<never> =>
    rejectUnsupported(owner, input.id, "restore"),
);

export const forkSandbox = serviceProcedure(
  { action: "sandboxes.get", target: (input: ForkSandboxInput) => ({ sandboxId: input.id }) },
  async (owner: Principal, input: ForkSandboxInput): Promise<never> =>
    rejectUnsupported(owner, input.id, "fork"),
);

export const listProcesses = serviceProcedure(
  {
    action: "processes.list",
    intentOnly: true,
    target: (input: ListProcessesInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: ListProcessesInput) => {
    return enqueueOwnedOperation(owner, input.id, input.idempotencyKey, {
      kind: "LIST_PROCESSES",
      fsProcess: {},
      eventType: "sandbox.process_list_requested",
      body: input,
      payload: { limit: input.limit, cursor: input.cursor },
      allowedStates: HEALTHY_GUEST_STATES,
      conflictMessage: "Sandbox is not ready for this operation.",
      skipStateUpdate: true,
    });
  },
);

export { signalProcessAction as signalProcess } from "../process-signals";

export const writeStdin = serviceProcedure(
  { action: "commands.writeStdin", intentOnly: true },
  async (owner: Principal, input: WriteStdinInput) => {
    await writeStdinAction(owner, {
      ...input,
      idempotencyKey: input.idempotencyKey ?? randomUUID(),
    });
    return { operationId: input.operationId, eof: input.eof === true };
  },
);

export const setSandboxTimeout = serviceProcedure(
  {
    action: "sandboxes.setTimeout",
    intentOnly: true,
    target: (input: SetSandboxTimeoutInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: SetSandboxTimeoutInput, clock: LeaseClock = leaseNow) => {
    const budgetOwner = budgetSubjectOf(owner)?.ownerId;
    if (budgetOwner) await consumeSandboxWriteBudget(budgetOwner, "lease");
    const located = await ownedSandbox(input.id, owner.ownerId);
    return operationTransaction(
      owner,
      {
        key: input.idempotencyKey,
        intent: {
          sandboxId: input.id,
          timeoutMs: input.timeoutMs,
        },
        kind: "RENEW_SANDBOX_LEASE",
        action: "sandboxes.setTimeout",
        target: { sandboxId: input.id },
      },
      async (tx, bodyHash) => {
        // Lease policy read: shared G on the lease path before H (pool and
        // membership writers hold it exclusively), H covers the host ceiling.
        await lockPoolGraphShared(tx, leasePathPools({ ...located, userId: owner.ownerId }));
        // Retained history has no placement to lock. S still serializes replay;
        // without a receipt the renewable-state check below rejects terminal rows.
        if (located.sandboxHostId !== null)
          await lockHostForSandboxOperation(tx, located.sandboxHostId, owner.ownerId, input.id);
        // Lock identity, not the preflight revision/state: matching retries must
        // replay even after another renewal or expiry has committed.
        const locked = await tx.sandbox.updateMany({
          where: { id: located.id, userId: owner.ownerId, sandboxHostId: located.sandboxHostId },
          data: { leaseRevision: { increment: 0 } },
        });
        requireRelayFence(locked.count === 1);
        const sandbox = await tx.sandbox.findFirst({
          where: { id: located.id, userId: owner.ownerId },
          select: sandboxSelect,
        });
        if (!sandbox) throw sandboxStateConflict();
        // The G taken above is only valid for the path it was taken for.
        if (
          !sameLeasePath(
            { ...located, userId: owner.ownerId },
            { ...sandbox, userId: owner.ownerId },
          )
        )
          throw sandboxStateConflict("Lease path changed. Retry.");
        requireState(
          sandbox,
          LEASE_RENEWABLE_STATES,
          "Sandbox lease cannot be renewed in this state.",
        );
        const now = await leaseTransactionNow(tx, clock);
        requireLeaseWithinPolicy(
          leaseRequestOf(input.timeoutMs),
          await readLockedPathLimit(tx, sandbox),
        );
        await commitSandboxLeaseRenewal(tx, {
          ownerId: owner.ownerId,
          attribution: attributionOf(owner),
          sandbox: { ...sandbox, userId: owner.ownerId },
          leaseExpiresAt: resolveLeaseTimeout(input.timeoutMs, now.getTime()),
          timeoutMs: input.timeoutMs,
          onExpire: sandbox.leaseExpireAction,
          idempotencyKey: input.idempotencyKey,
          bodyHash: bodyHash(),
          now,
        });
        const renewed = await tx.sandbox.findFirst({
          where: { id: sandbox.id, userId: owner.ownerId },
          select: sandboxSelect,
        });
        if (!renewed) throw sandboxStateConflict();
        return redactSandbox(renewed, owner.ownerId);
      },
      async (tx, prior) =>
        redactSandbox(await ownedSandbox(prior.sandboxId, owner.ownerId, tx), owner.ownerId),
    ).catch((error: unknown) => {
      if (error instanceof RelayFenceRejected) throw sandboxStateConflict();
      throw error;
    });
  },
);

/**
 * Update: rename and/or set the offload policy (`PUT /v1/sandboxes/{id}`,
 * oRPC `updateSandbox`). A policy change only steers later export decisions
 * (`offloadCandidates` and the `enqueueOffload` recheck under this row's
 * lock): an export already running finishes and a stored copy is kept. It
 * may be set in any live state, OFFLOADED included (it applies to the next
 * stop). Not an operation:
 * no idempotency key, outbox row or webhook (the webhook trigger fires on
 * state only). The shared gate (`sandboxes.update`) has already applied the
 * scope, the key's resource grants, the managed-purpose policy and the build
 * refusal, and runs again inside the transaction. Lock order: owner (FOR
 * SHARE) → SDK key (FOR SHARE, revalidated) → placement(31) → sandbox, the
 * same lock every create picks or checks its name under.
 */
export const updateSandbox = serviceProcedure(
  {
    action: "sandboxes.update",
    target: (input: UpdateSandboxInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: UpdateSandboxInput) => {
    const budgetOwner = budgetSubjectOf(owner)?.ownerId;
    if (budgetOwner) await consumeSandboxWriteBudget(budgetOwner, "ordinary");
    if (input.name !== undefined && !sandboxNameSchema.safeParse(input.name).success)
      throw sandboxNameInvalid();
    try {
      return await prisma.$transaction(async (tx) => {
        await lockOwnerForAdmission(tx, owner.ownerId);
        // Reauthorize in the transaction (as operationTransaction's work
        // does): an SDK key is locked FOR SHARE and revalidated here, before
        // lock 31, so a revocation either waits for this rename or refuses it.
        await authorizeServiceAction(owner, "sandboxes.update", { sandboxId: input.id }, tx);
        await lockOwnerPlacement(tx, owner.ownerId);
        const [row] = await tx.$queryRaw<{ id: string }[]>`
          SELECT id FROM sandbox_instance
          WHERE id = ${input.id} AND "userId" = ${owner.ownerId} AND state <> 'DELETED'::"SandboxState"
          FOR NO KEY UPDATE`;
        if (!row) throw new ORPCError("NOT_FOUND", { message: NOT_FOUND });
        if (input.name !== undefined)
          await assertSandboxNameFree(tx, owner.ownerId, input.name, row.id);
        const sandbox = await tx.sandbox.update({
          where: { id: row.id, userId: owner.ownerId },
          data: {
            ...(input.name !== undefined ? { name: input.name } : {}),
            ...(input.offload !== undefined ? offloadPolicyColumns(input.offload) : {}),
          },
          select: sandboxReadSelect,
        });
        return redactSandbox(sandbox, owner.ownerId);
      });
    } catch (error) {
      if (isSandboxNameViolation(error)) throw sandboxNameTaken();
      throw error;
    }
  },
);

/**
 * Retry cleanup: an owner session action. A sandbox
 * whose SYSTEM_DETACH cleanup outlived its automatic retries stays
 * `ERROR(restore_cleanup_pending)` holding its target; this re-queues the
 * same SYSTEM_DETACH kill (same attempt fields), whose proof detaches it to
 * OFFLOADED with its stored copy kept. Anything else is `state_conflict`.
 * Session only (the router builds it on `liveOwnerSessionProcedure`).
 */
export const retryRestoreCleanup = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: SandboxIdInput, clock: LeaseClock = leaseNow) => {
    await consumeSandboxWriteBudget(owner.ownerId, "ordinary");
    return sandboxOutboxTransaction(async (tx) => {
      await lockOwnerForAdmission(tx, owner.ownerId);
      const located = await ownedSandbox(input.id, owner.ownerId, tx);
      await lockHostForSandboxOperation(tx, located.sandboxHostId, owner.ownerId, input.id);
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${input.id} AND "userId" = ${owner.ownerId} FOR NO KEY UPDATE`;
      const now = await leaseTransactionNow(tx, clock);
      if (!(await requeueRestoreCleanup(tx, { sandboxId: input.id, userId: owner.ownerId }, now)))
        throw sandboxStateConflict("Only a sandbox whose restore cleanup is pending can retry it.");
      return redactSandbox(await ownedSandbox(input.id, owner.ownerId, tx), owner.ownerId);
    });
  },
);

export const cancelOperation = serviceProcedure(
  { action: "operations.cancel", intentOnly: true },
  async (owner: Principal, input: CancelOperationInput) => {
    const receipt = await cancelAction(owner, { ...input, idempotencyKey: randomUUID() });
    return { operationId: input.operationId, state: receipt.state };
  },
);

/** Fresh observation; never derives liveness from the stored lifecycle state. */
export const probeSandbox = serviceProcedure(
  { action: "sandboxes.probe", target: (input: SandboxIdInput) => ({ sandboxId: input.id }) },
  async (owner: Principal, input: SandboxIdInput, expectedGeneration?: number) => {
    const sandbox = await ownedSandbox(input.id, owner.ownerId);
    if (
      (expectedGeneration !== undefined && sandbox.generation !== expectedGeneration) ||
      !sandbox.sandboxHostId
    ) {
      return { state: "unreachable" as const };
    }
    const host = await prisma.sandboxHost.findFirst({
      where: { id: sandbox.sandboxHostId, userId: sandbox.hostOwnerId! },
      select: { status: true },
    });
    if (host?.status !== "CONNECTED") {
      return { state: "unreachable" as const };
    }
    const template = await pinnedLaunchSource(prisma, sandbox.id, owner.ownerId, false);
    if (!template) {
      return { state: "unreachable" as const };
    }
    const state = await probeHostSandbox({
      incusFingerprint: template.incusFingerprint,
      architecture: template.architecture,
      guestUid: template.guestUid,
      guestGid: template.guestGid,
      guestHome: template.guestHome,
      guestShell: template.guestShell,
      ownerId: owner.ownerId,
      hostId: sandbox.sandboxHostId,
      sandboxId: sandbox.id,
      generation: sandbox.generation,
    });
    const current = await prisma.sandbox.findFirst({
      where: {
        id: sandbox.id,
        userId: owner.ownerId,
        generation: sandbox.generation,
        sandboxHostId: sandbox.sandboxHostId,
      },
      select: { id: true },
    });
    await authorizeServiceAction(owner, "sandboxes.probe", { sandboxId: input.id });
    return { state: current ? state : ("unreachable" as const) };
  },
);

/**
 * One bounded page of a command's durable output (C26). Needs
 * `operations:read` + `commands:read`; bytes come back base64 per chunk, with
 * explicit gaps, the completion watermark and typed `OUTPUT_EXPIRED`.
 */
export const getCommandOutput = serviceProcedure(
  {
    action: "operations.getCommandOutput",
    target: (input: CommandOutputInput) => ({ operationId: input.operationId }),
  },
  async (owner: Principal, input: CommandOutputInput) => {
    const page = await readCommandOutputPage({
      ownerId: owner.ownerId,
      operationId: input.operationId,
      cursor: input.cursor,
      maxBytes: input.maxBytes,
      now: new Date(),
    });
    await authorizeServiceAction(owner, "operations.getCommandOutput", {
      operationId: input.operationId,
    });
    return page;
  },
);
