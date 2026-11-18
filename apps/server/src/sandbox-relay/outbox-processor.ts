import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import { settleOperationCredentials } from "@wssp/api/credentials/relay";
import { checkAcceptedDispatchAuthority } from "@wssp/api/lib/sdk-key-access";
import { CapacityQueueScheduler, runCapacityQueuePass } from "@wssp/api/sandbox/capacity-queue";
import { bindCapacityQueueWake } from "@wssp/api/sandbox/capacity-queue-wake";
import {
  type AuthorizingPrincipal,
  CommandTimeoutValidationError,
  effectiveCommandTimeoutMs,
  encodeCommandTimeoutMs,
  KEY_FREE_CLEANUP_KINDS,
  relayDispatchKind,
} from "@wssp/api/sandbox/contracts";
import { runRestoreWaitPass } from "@wssp/api/sandbox/disk-offload/restore-admit";
import {
  exitRestoreAttempt,
  type RestoreExitInput,
} from "@wssp/api/sandbox/disk-offload/restore-exit";
import { parseCommandRunDispatchEnvPairs } from "@wssp/api/sandbox/dispatch-control-envelope";
import {
  loadExecutionConfig,
  validateCommandEnvironmentUnion,
} from "@wssp/api/sandbox/execution-config";
import {
  noteHostBlockerReleased,
  releaseLiveResourcesIfHeld,
} from "@wssp/api/sandbox/host-admission";
import { fsProcessHostSupported } from "@wssp/api/sandbox/host-protocol";
import { hostJournalKey, hostJournalKeyAcknowledged } from "@wssp/api/sandbox/idempotency";
import { restoreOffloadOf } from "@wssp/api/sandbox/launch-mode";
import {
  isLeaseDeadlinePassed,
  type LeaseClock,
  leaseNow,
  leaseTransactionNow,
  reclaimExpiredSandboxLeases,
} from "@wssp/api/sandbox/lease";
import { scanLeasePolicy } from "@wssp/api/sandbox/lease-pull-in";
import { LEASE_DISPATCH_KINDS, leaseWireSchema } from "@wssp/api/sandbox/lease-wire";
import {
  bindSandboxDispatchWake,
  decodeOutboxPrincipal,
  systemDispatchAllowed,
} from "@wssp/api/sandbox/outbox";
import {
  dispatchClassOf,
  recordedKeyIdOf,
  systemAttribution,
} from "@wssp/api/sandbox/principal-kinds";
import {
  cancelQueuedOperation,
  casActiveOperation,
  casSandboxGeneration,
  lockCurrentHostEpoch,
  operationActiveFenceWhere,
  relayTransaction,
  requireRelayFence,
  requireRelayWorkload,
  sandboxStatesForOperation,
  settleSupersededOperations,
} from "@wssp/api/sandbox/relay-fence";
import { noteTerminalResultRelease } from "@wssp/api/sandbox/result-finalization";
import { assertBeforeResultQuota } from "@wssp/api/sandbox/result-locks";
import {
  rethrowSensitiveSandboxError,
  SandboxIntegrityError,
  safeOperationError,
} from "@wssp/api/sandbox/sensitive-errors";
import { bindSharingAccessWake, scanSandboxAccess } from "@wssp/api/sandbox/sharing-access";
import { SharingAccessScheduler } from "@wssp/api/sandbox/sharing-access-scheduler";
import {
  CANCELLABLE_OPERATION_KINDS,
  isLifecycleOperationKind,
} from "@wssp/api/sandbox/state-transitions";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import {
  CREDENTIAL_CAPTURE_DISPATCH_KINDS,
  type CredentialSpecRefV11,
  credentialSpecRefV11Schema,
  dispatchBuildV11Schema,
  dispatchCaptureV11Schema,
  dispatchHasDiskFields,
  dispatchImageV11Schema,
  type EgressPolicyWire,
  encodedJsonBytes,
  FS_PROCESS_LIMITS,
  isCanonicalEgressPolicyWire,
  pinnedAllocationV11Schema,
  processRefSchema,
  resultContinuationSchema,
} from "@wssp/sandbox-contracts";
import { transferStore } from "../sandbox-transfers/runtime.js";
import { type DispatchDiskFields, dispatchDiskFields } from "./disk-dispatch.js";
import {
  buildDispatchFieldsMatch,
  createEgressAdmissible,
  diskOffloadHostUnsupported,
  guestSudoHostUnsupported,
  launchEgressAdvertised,
  launchStartup,
  reclaimAuthorityVerdict,
  retainedStorageAdmits,
  sdkHostBindingHolds,
  templateStartupHostUnsupported,
  tunnelPortsHostUnsupported,
} from "./dispatch-gates.js";
import {
  classifyRelayDispatchKind,
  isDeterministicDispatchError,
  SandboxRelayDispatchValidationError,
  SandboxRelayVmSizeMismatchError,
} from "./protocol.js";
import { SandboxDispatchNotifier } from "./sandbox-dispatch-notifier.js";
import { sandboxRelaySessionManager } from "./session-manager.js";

/** Caller holds H. Only positive, current-epoch stored evidence proves refusal.
 * Disconnected carried snapshots and missing/stale admission prove no live downgrade. */
function fsProcessHostUnsupported(
  host: (NonNullable<Parameters<typeof fsProcessHostSupported>[0]> & { status: string }) | null,
) {
  return (
    host != null &&
    host.status === "CONNECTED" &&
    ((host.relayProtocolEpoch === host.connectionEpoch &&
      host.relayProtocolVersion != null &&
      !(host.relayProtocolVersion === "1.0")) ||
      (host.admissionEpoch === host.connectionEpoch && host.admissionRuntime === "UNSUPPORTED"))
  );
}

/** H/S/O are held. Keep the journal lineage only when EVERY dispatch attempt
 * used the same durable journal. Null is sticky after a reset/session move;
 * old dispatches without identity can never gain retroactive proof. This is
 * server-only outbox metadata, excluded from the explicit dispatch wire body. */
async function allocationJournalBinding(
  tx: Prisma.TransactionClient,
  event: Event,
  hostId: string | null,
  hostOwnerId: string,
  epoch: number,
  operation: { dispatchAttempt: number; dispatchedConnectionEpoch: number | null },
  attempt: number,
): Promise<Prisma.InputJsonObject> {
  if (!hostId) return {};
  const host = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: hostOwnerId, connectionEpoch: epoch },
    select: { admissionEpoch: true, daemonFeatures: true },
  });
  const features = host?.daemonFeatures;
  const id =
    features && typeof features === "object" && !Array.isArray(features)
      ? features.journalId
      : undefined;
  const current =
    host?.admissionEpoch === epoch && typeof id === "string" && /^[0-9a-f]{32}$/.test(id)
      ? id
      : null;
  const stored = await tx.outboxEvent.findFirst({
    where: { id: event.id, userId: event.userId },
    select: { payload: true },
  });
  const previous = stored?.payload;
  const metadata =
    previous && typeof previous === "object" && !Array.isArray(previous) ? previous : {};
  if (current === null && metadata.allocationJournalId === undefined) return {};
  const same =
    operation.dispatchAttempt === 0 ||
    (metadata.allocationJournalId === current &&
      metadata.allocationJournalAttempt === operation.dispatchAttempt &&
      metadata.allocationJournalEpoch === operation.dispatchedConnectionEpoch);
  return {
    allocationJournalId: same ? current : null,
    allocationJournalAttempt: attempt,
    allocationJournalEpoch: epoch,
    allocationDispatchSequence: null,
  };
}

/** §8.7 hand-off of a failed restore attempt: a no-effect proof only when
 * nothing was ever issued for it (attempt 0), else none (the kill path). */
function restoreExitInput(
  sandboxId: string,
  userId: string,
  operationId: string,
  generation: number,
  neverIssued: boolean,
  reason: "capability_refused" | "outbox_refused" | "dispatch_refused",
): RestoreExitInput {
  return {
    sandboxId,
    userId,
    attemptOperationId: operationId,
    attemptGeneration: generation,
    proof: neverIssued ? { kind: "no_effect", reason } : { kind: "none" },
  };
}

/** Private description of accepted intent, before env/wrapper rewriting. */
export function acceptedCommandDescription(payload: Record<string, unknown>) {
  const script = typeof payload.script === "string";
  const argv = Array.isArray(payload.argv)
    ? payload.argv.filter((v): v is string => typeof v === "string")
    : [];
  const cmd = script ? "/bin/bash" : argv[0];
  const cwd =
    typeof payload.cwd === "string"
      ? payload.cwd
      : typeof payload.guestHome === "string"
        ? payload.guestHome
        : "/";
  if (
    !cmd ||
    cmd.length > 512 ||
    cmd.includes("\0") ||
    !cwd.startsWith("/") ||
    Buffer.byteLength(cwd) > 4096 ||
    cwd.includes("\0")
  )
    return undefined;
  const args: string[] = [];
  let argsTruncated = script;
  // Match CommandDescription::from_request, including its conservative extra
  // comma byte. The ingress label check can then compare the stored prefix.
  let argsBytes = 2;
  for (const arg of script ? [] : argv.slice(1)) {
    const bytes = encodedJsonBytes(arg) + 1;
    if (args.length === 256 || arg.length > 512 || arg.includes("\0") || argsBytes + bytes > 4096) {
      argsTruncated = true;
      break;
    }
    argsBytes += bytes;
    args.push(arg);
  }
  const description = { cmd, args, argsTruncated, cwd };
  return encodedJsonBytes(description) <= 12288 ? description : undefined;
}

const OUTBOX_BATCH = 32;
// Claims reduce overlapping sends; expiry permits at-least-once delivery.
// Receiver sequence/order and cancel idempotency own the effect boundary.
const CLAIM_LEASE_MS = 30_000;
function claimable(now: Date): Prisma.OutboxEventWhereInput {
  return {
    processedAt: null,
    sentAt: null,
    OR: [{ claimToken: null }, { claimedAt: { lt: new Date(now.getTime() - CLAIM_LEASE_MS) } }],
  };
}
type Event = { id: string; userId: string; aggregateId: string; payload: Prisma.JsonValue };

/**
 * The recorded egress policy and hash ride every launch dispatch verbatim
 * from the durable payload. A launch whose payload predates C34 (or is
 * otherwise malformed) fails closed: the event is terminalized as a
 * protocol_error rather than dispatched without enforcement.
 */
function launchEgressFields(
  kind: string,
  payload: Record<string, unknown>,
): { egressPolicy?: EgressPolicyWire; egressPolicyHash?: string } {
  if (kind !== "sandbox.create" && kind !== "sandbox.reconnect") return {};
  const policy = payload.egressPolicy;
  const hash = payload.egressPolicyHash;
  if (
    !isCanonicalEgressPolicyWire(policy) ||
    typeof hash !== "string" ||
    !/^[0-9a-f]{64}$/.test(hash)
  ) {
    throw new SandboxRelayDispatchValidationError(
      "VM launch dispatch requires the recorded egress policy and hash.",
    );
  }
  return { egressPolicy: policy, egressPolicyHash: hash };
}

/** Kinds whose durable payload may carry a stored-spec reference (C10 adds attach/free). */
const CREDENTIAL_SPEC_LAUNCH_KINDS = new Set([
  "sandbox.create",
  "sandbox.reconnect",
  "sandbox.capture",
  "credential.attach",
  "credential.free",
]);

/**
 * CLI logins: a launch's (or a template capture's
 * scrub-list) stored-spec reference rides the dispatch verbatim from the
 * durable payload. A malformed one is a producer bug and fails closed
 * (protocol_error), never a launch without its logins or a capture without
 * its login scrub.
 */
export function launchCredentialSpec(
  kind: string,
  payload: Record<string, unknown>,
): { credentialSpec?: CredentialSpecRefV11 } {
  if (payload.credentialSpec === undefined) return {};
  const parsed = credentialSpecRefV11Schema.safeParse(payload.credentialSpec);
  if (!CREDENTIAL_SPEC_LAUNCH_KINDS.has(kind) || !parsed.success)
    throw new SandboxRelayDispatchValidationError("Invalid credential spec reference.");
  return { credentialSpec: parsed.data };
}

/**
 * CLI logins (§10.3, M8): a user stop/kill with `credentialCapture: "skip"`
 * and a system stop/kill's `credentialTeardown: "system"` ride the dispatch
 * verbatim; anything else on the payload is a producer bug.
 */
export function teardownCredentialCapture(
  kind: string,
  payload: Record<string, unknown>,
): { credentialCapture?: "skip"; credentialTeardown?: "system" } {
  if (payload.credentialCapture === undefined && payload.credentialTeardown === undefined)
    return {};
  if (!CREDENTIAL_CAPTURE_DISPATCH_KINDS.has(kind))
    throw new SandboxRelayDispatchValidationError("Invalid credential capture mode.");
  if (payload.credentialCapture !== undefined && payload.credentialCapture !== "skip")
    throw new SandboxRelayDispatchValidationError("Invalid credential capture mode.");
  if (payload.credentialTeardown !== undefined && payload.credentialTeardown !== "system")
    throw new SandboxRelayDispatchValidationError("Invalid credential teardown origin.");
  return {
    ...(payload.credentialCapture === "skip" ? { credentialCapture: "skip" as const } : {}),
    ...(payload.credentialTeardown === "system" ? { credentialTeardown: "system" as const } : {}),
  };
}

/** The outbox poller's projection: exactly what `dispatchEvent` reads. */
const outboxPollSelect = {
  id: true,
  userId: true,
  aggregateId: true,
  payload: true,
} satisfies Prisma.OutboxEventSelect;

/** A full pass (including offline hosts' events) at least this often. */
export const SANDBOX_OUTBOX_FULL_PASS_MS = 30_000;

/**
 * `skipOfflineHosts` (the frequent recovery scan): an event whose host has no
 * live registered socket in this process is passed over before any
 * transaction opens. The periodic full pass still evaluates it, so revoked
 * keys, superseded and queued-cancelled work settle within a bounded delay.
 * The in-transaction connection fence is unchanged either way.
 */
export async function processSandboxOutboxBatch(
  clock: LeaseClock = leaseNow,
  shouldStop: () => boolean = () => false,
  options: { skipOfflineHosts?: boolean } = {},
): Promise<number> {
  let dispatched = 0;
  let cursor: string | undefined;
  // Keyset pages also pass temporarily offline/ineligible rows in this scan.
  while (!shouldStop()) {
    const events = await prisma.outboxEvent.findMany({
      where: {
        ...claimable(clock()),
        aggregateType: "sandbox",
        ...(cursor ? { id: { gt: cursor } } : {}),
      },
      select: outboxPollSelect,
      orderBy: { id: "asc" },
      take: OUTBOX_BATCH,
    });
    for (const event of events) {
      if (shouldStop()) return dispatched;
      if (await dispatchEvent(event, clock, options.skipOfflineHosts === true)) dispatched += 1;
    }
    if (events.length < OUTBOX_BATCH) break;
    cursor = events[events.length - 1]!.id;
  }
  return dispatched + (await reclaimExpiredSandboxLeases(clock, OUTBOX_BATCH, shouldStop));
}

/**
 * WP7 (D9): kind-aware dispatchability, checked before the claim (the
 * pre-transaction filter and the in-transaction fence). A quiescing host takes
 * no new `command.run`: its event stays pending and unclaimed, the operation
 * stays QUEUED and no dispatch attempt is spent. Controls (cancel, stdin) and
 * every other kind still flow. Never re-checked after a claim: refusing then
 * would strand the claimed operation. The scan wakes at the next connection's
 * `reconcile.complete` (notifySandboxDispatchPending).
 */
function isHostDispatchable(hostId: string, kind: string, connectionEpoch?: number): boolean {
  return (
    sandboxRelaySessionManager.isHostConnected(hostId, connectionEpoch) &&
    !(kind === "command.run" && sandboxRelaySessionManager.isHostQuiescing?.(hostId) === true)
  );
}

async function dispatchEvent(
  event: Event,
  clock: LeaseClock,
  skipOfflineHosts: boolean,
): Promise<boolean> {
  const storedPayload = event.payload;
  if (storedPayload === null) return false;
  const payload = storedPayload as Record<string, unknown>;
  if (
    !payload ||
    typeof payload.operationId !== "string" ||
    typeof payload.kind !== "string" ||
    (payload.sandboxHostId !== null && typeof payload.sandboxHostId !== "string") ||
    payload.sandboxId !== event.aggregateId ||
    !Number.isSafeInteger(payload.generation) ||
    !Number.isSafeInteger(payload.dispatchAttempt)
  )
    return false;
  const operationId = payload.operationId;
  const sandboxId = event.aggregateId;
  const kind = payload.kind;
  const generation = payload.generation as number;
  const boundAttempt = payload.dispatchAttempt as number;
  const hostId =
    typeof payload.sandboxHostId === "string"
      ? payload.sandboxHostId
      : ((
          await prisma.sandbox.findFirst({
            where: { id: sandboxId, userId: event.userId },
            select: { sandboxHostId: true },
          })
        )?.sandboxHostId ?? null);
  if (hostId == null) return false;
  if (skipOfflineHosts && !isHostDispatchable(hostId, kind)) return false;

  // file.put only: reserve upload-stream capacity BEFORE the dispatch claim
  // commits (DISPATCHED + attempt + epoch). Refusing here leaves the event
  // pending for a later scan; refusing after the claim would strand the
  // operation, because no same-epoch scan may retry a DISPATCHED operation.
  const streamSlot =
    kind === "file.put" ? sandboxRelaySessionManager.reserveFileStreamSlot() : null;
  if (kind === "file.put" && !streamSlot) return false;
  try {
    return await dispatchClaimedEvent(
      event,
      clock,
      { payload, operationId, sandboxId, kind, generation, boundAttempt, hostId },
      streamSlot,
    );
  } catch (error) {
    // The transaction rolled back and logged its stable integrity code. Reuse
    // the existing 30 s claim lease as a bounded retry cooldown, retaining the
    // event for repair. Never overwrite a newer claim or a repaired payload.
    if (error instanceof SandboxIntegrityError) {
      const now = clock();
      await prisma.outboxEvent.updateMany({
        where: { id: event.id, ...claimable(now), payload: { equals: storedPayload } },
        data: { claimToken: `integrity-backoff:${error.code}`, claimedAt: now },
      });
      return false;
    }
    return rethrowSensitiveSandboxError(error);
  } finally {
    // dispatchOperation releases a slot it adopted; every other exit lands here.
    streamSlot?.release();
  }
}

async function dispatchClaimedEvent(
  event: Event,
  clock: LeaseClock,
  input: {
    payload: Record<string, unknown>;
    operationId: string;
    sandboxId: string;
    kind: string;
    generation: number;
    boundAttempt: number;
    hostId: string;
  },
  streamSlot: { release(): void } | null,
): Promise<boolean> {
  const { payload, operationId, sandboxId, kind, generation, boundAttempt, hostId } = input;
  const claimToken = randomUUID();
  const hostCredential = sandboxRelaySessionManager.captureHostDispatchCredential?.(hostId);
  let pendingConfig:
    | {
        principal: AuthorizingPrincipal;
        claimToken: string;
        attempt: number;
        dispatchedHostId: string | null;
        dispatchedConnectionEpoch: number | null;
        firstClaim: boolean;
        frame: Extract<
          import("./protocol.js").ServerControlMessage,
          { type: "private.config.install" }
        >;
      }
    | undefined;
  const prepared = await relayTransaction(async (tx) => {
    // Locate immutable principal without a lock, then K before H/S/O/outbox.
    // Dispatch never acquires owner admission, including refusal/retry paths.
    const binding = await tx.sandboxOperation.findFirst({
      where: { id: operationId },
      select: { userId: true, sandboxId: true, authorizingKeyId: true, resultVersion: true },
    });
    const principal = decodeOutboxPrincipal(payload);
    const dispatchKeyId = recordedKeyIdOf(principal);
    if (dispatchKeyId)
      await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${dispatchKeyId} FOR SHARE`;
    const locatedHost = hostId
      ? await tx.sandboxHost.findFirst({ where: { id: hostId }, select: { id: true } })
      : null;
    const host = locatedHost && hostId ? await lockCurrentHostEpoch(tx, hostId) : null;
    const requiresFsProcess =
      (kind === "command.run" && payload.timeoutMs === 0) ||
      binding?.resultVersion === 1 ||
      payload.startEvidence === "required" ||
      payload.process !== undefined ||
      payload.continuation !== undefined ||
      payload.limit !== undefined;
    const protocolHost =
      requiresFsProcess && hostId && host
        ? await tx.sandboxHost.findFirst({
            where: { id: hostId, userId: host!.userId },
            select: {
              connectionEpoch: true,
              status: true,
              relayProtocolVersion: true,
              relayProtocolEpoch: true,
              admissionRuntime: true,
              admissionEpoch: true,
            },
          })
        : null;
    // Hello may have committed while its socket publication is still pending.
    // Do not claim that epoch until the corresponding socket is registered.

    const located = await tx.sandboxOperation.findFirst({
      where: { id: operationId },
      select: { userId: true, sandboxId: true },
    });
    if (located == null) {
      const sandbox = await tx.sandbox.findFirst({
        where: { id: sandboxId, userId: event.userId },
      });
      if (sandbox)
        await casSandboxGeneration(tx, {
          sandboxId,
          userId: event.userId,
          generation: sandbox.generation,
          hostId: hostId ?? undefined,
          states: [sandbox.state],
        });
      // Cascaded operation deletion leaves no operation row to lock or mutate.
      const now = clock();
      await retireClaimableEvent(tx, event, now);
      return null;
    }
    requireRelayFence(located.userId === event.userId && located.sandboxId === sandboxId);
    let sandbox = await tx.sandbox.findFirst({ where: { id: sandboxId, userId: event.userId } });
    requireRelayFence(sandbox != null);
    if (host && hostId)
      await requireRelayWorkload(
        tx,
        { userId: host.userId, hostId },
        { operationId, sandboxId, sandboxOwnerId: event.userId },
      );
    // All eligibility and transition decisions below use O as observed under S.
    // An H lock alone cannot serialize against owner cancellation (S → O).
    await casSandboxGeneration(tx, {
      sandboxId,
      userId: event.userId,
      generation: sandbox.generation,
      hostId: hostId ?? undefined,
      states: [sandbox.state],
    });
    // Renewals can change the lease without changing generation. Read it again
    // under S, and sample time here rather than at the start of a batch/lock wait.
    sandbox = await tx.sandbox.findFirst({ where: { id: sandboxId, userId: event.userId } });
    requireRelayFence(sandbox != null);
    await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${operationId} AND "userId" = ${event.userId} FOR UPDATE`;
    const now = await leaseTransactionNow(tx, clock);
    const operation = await tx.sandboxOperation.findFirst({
      where: { id: operationId },
      select: {
        userId: true,
        sandboxId: true,
        kind: true,
        generation: true,
        dispatchAttempt: true,
        acceptedAttempt: true,
        resultVersion: true,
        processId: true,
        processPid: true,
        dispatchedHostId: true,
        dispatchedConnectionEpoch: true,
        state: true,
        nextStdinSequence: true,
        requestBodyHash: true,
        requestDigestScheme: true,
        requestDigestKeyId: true,
        authorizingKeyId: true,
        completedAt: true,
        launchMode: true,
        restoreOffloadId: true,
      },
    });
    requireRelayFence(
      operation != null &&
        operation.authorizingKeyId === binding?.authorizingKeyId &&
        operation.userId === event.userId &&
        operation.sandboxId === sandboxId &&
        operation.generation === generation &&
        (operation.dispatchedHostId === null || operation.dispatchedHostId === hostId),
    );
    // Offload plan U9.1: a restore is known from the operation row only.
    const restoreOffloadId = restoreOffloadOf(operation);
    const restore = restoreOffloadId !== null;
    const currentEvent = await tx.outboxEvent.findFirst({
      where: { id: event.id, userId: event.userId },
      select: { payload: true },
    });
    requireRelayFence(
      currentEvent != null &&
        JSON.stringify(currentEvent.payload) === JSON.stringify(event.payload),
    );
    const control = kind === "process.stdin" || kind === "operation.cancel";
    const malformedPrincipal =
      !principal || (!control && operation.authorizingKeyId !== recordedKeyIdOf(principal));
    const invalidSystem =
      principal !== null &&
      dispatchClassOf(principal, kind) === "system" &&
      !systemDispatchAllowed(kind, payload);
    if ((malformedPrincipal || invalidSystem) && control) {
      await refuseDispatchEvent(tx, event, payload, now, "protocol_error");
      return null;
    }
    if (kind === "operation.cancel" && !CANCELLABLE_OPERATION_KINDS.has(operation.kind)) {
      // Retire only this invalid control, preserving the lifecycle operation and
      // its dispatch intent and any accepted work.
      await retireClaimableEvent(tx, event, now);
      return null;
    }
    // The one live intent a DELETED sandbox can carry: the inventory-driven
    // destroy of a VM its node still reports, while that remnant holds its
    // live charge on exactly this host at this generation.
    const remnantDestroy =
      sandbox.state === "DELETED" &&
      operation.kind === "KILL_SANDBOX" &&
      sandbox.liveResourcesHeld &&
      sandbox.sandboxHostId === hostId &&
      sandbox.generation === generation;
    const obsolete =
      (hostId != null && host == null) ||
      sandbox.generation > generation ||
      (["DELETED", "ERROR", "HOST_LOST"].includes(sandbox.state) && !remnantDestroy);
    const terminal = !["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED"].includes(
      operation.state,
    );
    if (
      !obsolete &&
      !terminal &&
      (operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX") &&
      isLeaseDeadlinePassed(sandbox.leaseExpiresAt, now)
    ) {
      // Expiry may INSERT cleanup O/outbox (owner FK). The separate admitted
      // recovery transaction below owns that work, after K/H/S are released.
      return null;
    }
    const staleControl =
      (control || classifyRelayDispatchKind(kind) !== "allowed") &&
      boundAttempt !== operation.dispatchAttempt;
    if (obsolete || terminal || staleControl) {
      // Lock the CURRENT sandbox, then the old operation. Never rewrite its generation.
      await casSandboxGeneration(tx, {
        sandboxId,
        userId: event.userId,
        generation: sandbox.generation,
        hostId: hostId ?? undefined,
        states: [sandbox.state],
      });
      const retired = await tx.sandboxOperation.updateMany({
        where: {
          id: operationId,
          userId: event.userId,
          generation,
          dispatchAttempt: operation.dispatchAttempt,
          state: operation.state,
        },
        data:
          obsolete && !terminal
            ? {
                state: sandbox.generation > generation ? "CANCEL_REQUESTED" : "UNKNOWN_OUTCOME",
                // C26: retirement never moves the output-retention deadline. A
                // retired row can already carry its first completion; only a
                // never-completed row is stamped now.
                completedAt:
                  sandbox.generation > generation
                    ? (operation.completedAt ?? null)
                    : (operation.completedAt ?? now),
                errorCode: "superseded",
                errorDetail: "Sandbox authority superseded this operation.",
              }
            : { dispatchAttempt: operation.dispatchAttempt },
      });
      requireRelayFence(retired.count === 1);
      noteTerminalResultRelease(tx, event.userId, { operationId });
      if (obsolete && !terminal && sandbox.generation <= generation) {
        await settleSupersededOperations(tx, { ...operation, state: "UNKNOWN_OUTCOME" }, now);
      }
      await retireClaimableEvent(tx, event, now);
      return null;
    }
    const fence = {
      operationId,
      sandboxId,
      userId: event.userId,
      generation,
      attempt: operation.dispatchAttempt,
      hostId: operation.dispatchedHostId,
    };
    // Staged records must pass support before config/key prerequisites. A
    // downgrade can retire only a proven first unsent intent as FAILED. An
    // absent current-epoch proof proves no downgrade: keep accepted work pending
    // until reconnect. Naked signals are always refused, including offline.
    const nakedSignal =
      kind === "process.signal" &&
      (!processRefSchema.safeParse(payload.process).success ||
        typeof payload.targetOperationId !== "string");
    // §8.6: the disk fields from rows only (U9.1). A restore
    // whose offload is no longer the sandbox's STORED disk never dispatches.
    const diskFields = control
      ? {}
      : await dispatchDiskFields(tx, {
          kind,
          restoreOffloadId,
          payload,
          sandbox,
          diskCapable:
            hostId != null &&
            host != null &&
            (
              await tx.sandboxHost.findFirst({
                where: { id: hostId, userId: host.userId },
                select: { daemonDiskOffload: true },
              })
            )?.daemonDiskOffload === true,
        });
    const diskUnavailable = diskFields === "restore_unavailable";
    // Build frame fields on a sandbox they do not belong to (or a build VM
    // create without its binding) never dispatch: protocol_error (§3.1).
    const misplacedBuildFields =
      diskUnavailable ||
      (!control &&
        !buildDispatchFieldsMatch(kind, payload, {
          purpose: sandbox.purpose,
          buildId: sandbox.buildId,
          // I12: the revision's source decides whether this boot may happen.
          revisionSourceKind:
            (
              await tx.sandboxTemplateRevision.findFirst({
                where: { id: sandbox.templateRevisionId, userId: sandbox.userId },
                select: { sourceKind: true },
              })
            )?.sourceKind ?? null,
        }));
    // B9: a launch of a revision with a start command carries `startup`. The
    // session sends it only to a `templateStartup` daemon; any other daemon's
    // refusal settles the launch as unsupported (settleRefusedDispatch), so a
    // sandbox never boots without its start command.
    const startup = control ? undefined : await launchStartup(tx, kind, sandbox);
    if (
      !control &&
      (misplacedBuildFields ||
        (kind === "command.run" &&
          payload.timeoutMs === 0 &&
          !FS_PROCESS_LIMITS.commandTimeoutZero) ||
        nakedSignal ||
        (requiresFsProcess && fsProcessHostUnsupported(protocolHost)))
    ) {
      requireRelayFence(boundAttempt === 0 || boundAttempt === operation.dispatchAttempt);
      const neverIssued =
        operation.state === "QUEUED" &&
        operation.dispatchAttempt === 0 &&
        operation.acceptedAttempt === null &&
        operation.dispatchedHostId === null &&
        operation.dispatchedConnectionEpoch === null;
      await casActiveOperation(tx, fence, {
        state: neverIssued ? "FAILED" : "UNKNOWN_OUTCOME",
        completedAt: operation.completedAt ?? now,
        errorCode: misplacedBuildFields ? "protocol_error" : "unsupported_capability",
        errorDetail: safeOperationError(
          misplacedBuildFields ? "protocol_error" : "unsupported_capability",
        ).message,
      });
      await settleOperationCredentials(tx, {
        sandboxId,
        operation: {
          id: operationId,
          kind: operation.kind,
          dispatchAttempt: operation.dispatchAttempt,
        },
        opState: neverIssued ? "FAILED" : "UNKNOWN_OUTCOME",
      });
      // A restore retires its event first: the exit's SYSTEM_DETACH kill
      // retires every older generation's pending event, this one included.
      if (restore) await retireClaimableEvent(tx, event, now);
      // X1: an outbox refusal of a restore ends through the restore exit.
      if (restore)
        await exitRestoreAttempt(
          tx,
          restoreExitInput(
            sandboxId,
            event.userId,
            operationId,
            generation,
            neverIssued,
            "outbox_refused",
          ),
        );
      noteHostBlockerReleased(tx, hostId, host?.userId ?? sandbox.hostOwnerId!);
      noteTerminalResultRelease(tx, event.userId, { operationId });
      if (!restore) await retireClaimableEvent(tx, event, now);
      return null;
    }

    const authorizingKeyId = recordedKeyIdOf(principal);
    // Corrupt non-control attribution must settle its target with C-26, just
    // like an invalid system intent; consuming only the event strands capacity.
    const authority = await reclaimAuthorityVerdict(tx, {
      ownerId: event.userId,
      principal,
      malformed: malformedPrincipal || invalidSystem,
      kind,
      sandbox,
    });
    if (authority === "indeterminate") return null;
    if (control && authority === "inactive") {
      await refuseDispatchEvent(tx, event, payload, now, "credential_inactive");
      return null;
    }
    const envBearing =
      (Array.isArray(payload.env) && payload.env.length > 0) || payload.privateConfig != null;
    const keyed = operation.requestDigestScheme === "hmac-sha256-v1";
    if (
      authority === "active" &&
      (envBearing || (!control && keyed && !KEY_FREE_CLEANUP_KINDS.has(kind)))
    ) {
      const evidence = await tx.sandboxHost.findFirst({
        where: { id: hostId, userId: host!.userId },
        select: {
          connectionEpoch: true,
          journalKeyVersion: true,
          journalKeyId: true,
          journalKeyAcknowledgedEpoch: true,
        },
      });
      // Every keyed dispatch requires the key acknowledgement for this epoch.
      if (
        !evidence ||
        !hostJournalKeyAcknowledged(evidence) ||
        !keyed ||
        operation.requestDigestKeyId !== evidence.journalKeyId
      )
        return null;
    }
    let invalidConfig = false;
    if (
      authority === "active" &&
      ["sandbox.create", "sandbox.reconnect", "command.run"].includes(kind)
    ) {
      const config = await loadExecutionConfig(tx, sandboxId, event.userId).catch(
        (error: unknown) => {
          if (error instanceof ORPCError && error.code === "BAD_REQUEST") {
            invalidConfig = true;
            return null;
          }
          throw error;
        },
      );
      invalidConfig ||= (config == null) !== (payload.privateConfig == null);
      if (config) {
        invalidConfig ||= !(
          config.hostId === hostId &&
          payload.privateConfig != null &&
          typeof payload.privateConfig === "object" &&
          !Array.isArray(payload.privateConfig) &&
          Object.keys(payload.privateConfig).length === 4 &&
          Object.entries(config.reference).every(
            ([key, value]) => (payload.privateConfig as Record<string, unknown>)[key] === value,
          )
        );
        if (kind === "command.run") {
          try {
            validateCommandEnvironmentUnion(payload, config.env);
          } catch (error) {
            if (error instanceof ORPCError && error.code === "BAD_REQUEST") invalidConfig = true;
            else throw error;
          }
        }
        if (!invalidConfig && config.acknowledgedEpoch !== host?.connectionEpoch) {
          // Reuse the durable claim lease for install backoff. This write only
          // changes claim bookkeeping, so it cannot wake its own dispatch loop.
          const configClaimToken = `config:${claimToken}`;
          await claimEvent(tx, event, now, configClaimToken, undefined, host!.connectionEpoch);
          pendingConfig = {
            principal: principal!,
            claimToken: configClaimToken,
            attempt: operation.dispatchAttempt,
            dispatchedHostId: operation.dispatchedHostId,
            dispatchedConnectionEpoch: operation.dispatchedConnectionEpoch,
            firstClaim:
              operation.state === "QUEUED" &&
              operation.dispatchAttempt === 0 &&
              operation.acceptedAttempt === null &&
              operation.dispatchedHostId === null &&
              operation.dispatchedConnectionEpoch === null,
            frame: {
              type: "private.config.install",
              refusalToken: claimToken,
              connectionEpoch: host!.connectionEpoch,
              server: hostJournalKey(host!.userId, hostId).server,
              hostOwnerId: host!.userId,
              sandboxOwnerId: event.userId,
              hostId,
              sandboxId,
              generation: config.generation,
              config: config.reference,
              env: config.env,
            },
          };
          return null;
        }
      }
    }
    if (kind === "operation.cancel" && operation.state === "QUEUED") {
      await casSandboxGeneration(tx, {
        sandboxId,
        userId: event.userId,
        generation,
        hostId: hostId ?? undefined,
        states: sandboxStatesForOperation(operation),
      });
      await cancelQueuedOperation(
        tx,
        {
          operationId,
          sandboxId,
          kind: operation.kind,
          userId: event.userId,
          generation,
          attempt: boundAttempt,
          hostId: operation.dispatchedHostId,
        },
        now,
      );
      return null;
    }
    // Mirror authorizeOperation's SDK session-host binding before a send claim.
    // Queued cancellation above is local and does not require a socket send.
    if (!sdkHostBindingHolds(authority, principal, sandbox.sandboxHostId, hostId)) return null;
    // Pending controls must not acquire a send claim before receiver authority
    // exists. Returning keeps them pending while the outer keyset scan advances.
    if (kind === "operation.cancel") {
      if (
        operation.state !== "CANCEL_REQUESTED" ||
        operation.acceptedAttempt !== operation.dispatchAttempt
      )
        return null;
    } else if (control && !["ACCEPTED", "RUNNING"].includes(operation.state)) return null;
    // C21-9: an undispatched operation whose authorizing key is no longer valid is
    // terminalized here, even while its host is offline; it is never retried.
    requireRelayFence(
      hostId != null &&
        host != null &&
        (authority === "inactive" || isHostDispatchable(hostId, kind, host.connectionEpoch)),
    );
    await casSandboxGeneration(tx, {
      sandboxId,
      userId: event.userId,
      generation,
      hostId,
      states: sandboxStatesForOperation(operation),
    });
    const kindClass = classifyRelayDispatchKind(kind);
    if (
      invalidConfig ||
      kindClass === "unknown" ||
      kindClass === "unsupported_capability" ||
      (!control && relayDispatchKind(operation.kind) !== kind)
    ) {
      // Unsupported/invalid work is terminalized only for the event's exact attempt.
      requireRelayFence(boundAttempt === operation.dispatchAttempt);
      const rejectedState = operation.dispatchAttempt === 0 ? "FAILED" : "UNKNOWN_OUTCOME";
      noteHostBlockerReleased(tx, hostId, host?.userId ?? sandbox.hostOwnerId!);
      await casActiveOperation(tx, fence, {
        state: rejectedState,
        completedAt: now,
        errorCode:
          kindClass === "unsupported_capability" ? "unsupported_capability" : "protocol_error",
        errorDetail: safeOperationError("protocol_error").message,
      });
      await settleOperationCredentials(tx, {
        sandboxId,
        operation: {
          id: operationId,
          kind: operation.kind,
          dispatchAttempt: operation.dispatchAttempt,
        },
        opState: rejectedState,
      });
      // A restore retires its event first: the exit's SYSTEM_DETACH kill
      // retires every older generation's pending event, this one included.
      if (restore) await retireClaimableEvent(tx, event, now);
      // X1: an outbox protocol or unsupported refusal of a restore ends
      // through the restore exit (no-effect proof only at attempt 0).
      const exited =
        restore &&
        (await exitRestoreAttempt(
          tx,
          restoreExitInput(
            sandboxId,
            event.userId,
            operationId,
            generation,
            operation.dispatchAttempt === 0,
            "outbox_refused",
          ),
        ));
      if (!exited && isLifecycleOperationKind(operation.kind)) {
        await releaseLiveResourcesIfHeld(tx, {
          hostId,
          ownerId: event.userId,
          sandboxId,
          operationId,
          kind: operation.kind,
          opState: rejectedState,
          sandboxStateBeforeResult: sandbox.state,
          neverIssued: operation.dispatchAttempt === 0,
        });
      }
      noteTerminalResultRelease(tx, event.userId, { operationId });
      await settleSupersededOperations(tx, { ...operation, state: rejectedState }, now);
      if (!restore) await retireClaimableEvent(tx, event, now);
      return null;
    }
    if (kind === "sandbox.create" || kind === "sandbox.reconnect") {
      // C34: a launch is sent only to a host whose current hello still
      // advertises egress enforcement. This read runs in the transaction that
      // already write-locked the host row at its current connection epoch
      // (lockCurrentHostEpoch above). A replacement hello increments the epoch
      // unconditionally, so exactly one order holds:
      //  - the hello commits first: this transaction's epoch CAS matches zero
      //    rows and the prepare is rejected without a send; on the next
      //    attempt this read observes egressEnforcement=false and terminalizes;
      //  - this transaction commits first: the launch goes to the session
      //    that advertised enforcement, bound to the claimed epoch
      //    (sentConnectionEpoch), and the hello commits afterwards, replacing
      //    the session and fencing the replaced epoch's results.
      // (Proven against real PostgreSQL in egress-capability-race.pg.test.ts.)
      // §1.4 (M7): a CREATE additionally needs an active guard lease and, for
      // an open policy, the node owner's consent; checked right here, under
      // The same epoch lock. So does a restore (a new VM on
      // this host). An ordinary reconnect is never refused for those reasons.
      const advertised = await launchEgressAdvertised(tx, hostId, host!.userId);
      const egressRefusal =
        advertised && (kind === "sandbox.create" || restore)
          ? await createEgressAdmissible(tx, {
              hostId,
              hostOwnerId: host!.userId,
              sandboxOwnerId: event.userId,
              policy: payload.egressPolicy,
              now,
            })
          : null;
      if (!advertised || egressRefusal) {
        const refusalCode = egressRefusal ?? "unsupported_capability";
        const refusalDetail = egressRefusal
          ? safeOperationError(egressRefusal).message
          : "Host no longer advertises egress-policy enforcement.";
        // The durable event payload keeps dispatchAttempt 0 forever; the
        // operation row alone carries the incremented attempt, so the
        // FAILED/UNKNOWN_OUTCOME split reads the operation, not the payload.
        const rejectedState = operation.dispatchAttempt === 0 ? "FAILED" : "UNKNOWN_OUTCOME";
        noteHostBlockerReleased(tx, hostId, host?.userId ?? sandbox.hostOwnerId!);
        await casActiveOperation(tx, fence, {
          state: rejectedState,
          completedAt: now,
          errorCode: refusalCode,
          errorDetail: refusalDetail,
        });
        await settleOperationCredentials(tx, {
          sandboxId,
          operation: {
            id: operationId,
            kind: operation.kind,
            dispatchAttempt: operation.dispatchAttempt,
          },
          opState: rejectedState,
        });
        // A restore retires its event first: the exit's SYSTEM_DETACH kill
        // retires every older generation's pending event, this one included.
        if (restore) await retireClaimableEvent(tx, event, now);
        // X1: an egress refusal of a restore ends through the restore exit.
        const exited =
          restore &&
          (await exitRestoreAttempt(
            tx,
            restoreExitInput(
              sandboxId,
              event.userId,
              operationId,
              generation,
              operation.dispatchAttempt === 0,
              "outbox_refused",
            ),
          ));
        if (!exited && isLifecycleOperationKind(operation.kind)) {
          await releaseLiveResourcesIfHeld(tx, {
            hostId,
            ownerId: event.userId,
            sandboxId,
            operationId,
            kind: operation.kind,
            opState: rejectedState,
            sandboxStateBeforeResult: sandbox.state,
            neverIssued: operation.dispatchAttempt === 0,
            ...(rejectedState === "FAILED" && operation.kind === "CREATE_SANDBOX"
              ? {
                  sandboxFailure: {
                    lastErrorCode: refusalCode,
                    lastErrorDetail: refusalDetail,
                  },
                }
              : {}),
          });
        }
        noteTerminalResultRelease(tx, event.userId, { operationId });
        await settleSupersededOperations(tx, { ...operation, state: rejectedState }, now);
        if (!restore) await retireClaimableEvent(tx, event, now);
        return null;
      }
    }
    if (control) {
      // A replacement host session never adopts an old command's pipe or
      // cancellation authority. Refuse ONLY this event, preserving its target.
      if (
        operation.dispatchedConnectionEpoch !== host.connectionEpoch ||
        (payload.connectionEpoch !== undefined &&
          payload.connectionEpoch !== operation.dispatchedConnectionEpoch)
      ) {
        await refuseDispatchEvent(tx, event, payload, now, "unknown_outcome");
        return null;
      }
      // Cancellation retries retain the exact dispatch identity.
      requireRelayFence(boundAttempt > 0 && boundAttempt === operation.dispatchAttempt);
      requireRelayFence(operation.dispatchedHostId === hostId && operation.dispatchAttempt > 0);
      requireRelayFence(kind !== "process.stdin" || operation.kind === "RUN_COMMAND");
      const sequence = kind === "process.stdin" ? payload.stdinSequence : 0;
      requireRelayFence(Number.isSafeInteger(sequence) && (sequence as number) >= 0);
      if (kind === "operation.cancel") {
        const requested = await tx.sandboxOperation.updateMany({
          where: {
            ...operationActiveFenceWhere(fence),
            state: { in: ["ACCEPTED", "RUNNING", "CANCEL_REQUESTED"] },
          },
          data: { state: "CANCEL_REQUESTED" },
        });
        requireRelayFence(requested.count === 1);
      } else {
        await casActiveOperation(tx, fence, { dispatchAttempt: operation.dispatchAttempt });
      }
      await claimEvent(tx, event, now, claimToken, undefined, host.connectionEpoch);
      return {
        authorizingKeyId,
        principal: principal!,
        authority,
        firstClaim: false,
        generation,
        attempt: operation.dispatchAttempt,
        epoch: host.connectionEpoch,
        control: true,
        digestScheme: undefined,
        digestKeyId: undefined,
        sequence: sequence as number,
      };
    }
    // Only QUEUED or unacknowledged DISPATCHED from an older epoch may claim.
    // A proven first pre-frame refusal restores QUEUED for same-epoch retry;
    // possible prior effects still require a replacement connection.
    requireRelayFence(
      operation.state === "QUEUED" ||
        (operation.state === "DISPATCHED" &&
          operation.dispatchedConnectionEpoch != null &&
          operation.dispatchedConnectionEpoch < host.connectionEpoch),
    );
    requireRelayFence(operation.kind !== "RUN_COMMAND" || operation.processPid === null);
    if (
      authority === "active" &&
      !(await retainedStorageAdmits(tx, {
        hostId,
        ownerId: event.userId,
        sandboxId,
        kind,
        sandboxState: sandbox.state,
        restore,
      }))
    )
      return null;
    const attempt = operation.dispatchAttempt + 1;
    const claimed = await tx.sandboxOperation.updateMany({
      where: {
        ...operationActiveFenceWhere(fence),
        state: operation.state,
        dispatchAttempt: operation.dispatchAttempt,
        ...(operation.kind === "RUN_COMMAND" ? { processPid: null } : {}),
        dispatchedConnectionEpoch: operation.dispatchedConnectionEpoch,
      },
      data: {
        state: "DISPATCHED",
        ...(operation.kind === "RUN_COMMAND" && operation.resultVersion === 1
          ? { processDescription: acceptedCommandDescription(payload) }
          : {}),
        acceptedAttempt: null,
        dispatchedAt: now,
        dispatchAttempt: attempt,
        dispatchedHostId: hostId,
        dispatchedConnectionEpoch: host.connectionEpoch,
      },
    });
    requireRelayFence(claimed.count === 1);
    await claimEvent(
      tx,
      event,
      now,
      claimToken,
      {
        ...payload,
        sandboxHostId: hostId,
        ...(kind === "sandbox.create" || kind === "sandbox.reconnect"
          ? await allocationJournalBinding(
              tx,
              event,
              hostId,
              host.userId,
              host.connectionEpoch,
              operation,
              attempt,
            )
          : {}),
      } as Prisma.InputJsonObject,
      host.connectionEpoch,
    );
    return {
      authorizingKeyId,
      // R6 (coordinator ruling): an attribution that fails to decode NEVER
      // runs with session authority. Its authority is already `inactive`
      // (reclaimAuthorityVerdict refuses a missing principal without a
      // lookup), so it is settled under keyless system attribution with no
      // key lock and no user-scope check (settleRefusedDispatch).
      principal: principal ?? systemAttribution(),
      attributionUndecodable: principal === null,
      authority,
      requiresFsProcess,
      resultVersion: operation.resultVersion === 1 ? (1 as const) : undefined,
      processId:
        operation.resultVersion === 1 && operation.kind === "RUN_COMMAND"
          ? (operation.processId ?? undefined)
          : undefined,
      firstClaim:
        operation.state === "QUEUED" &&
        operation.dispatchAttempt === 0 &&
        operation.acceptedAttempt === null &&
        operation.dispatchedHostId === null &&
        operation.dispatchedConnectionEpoch === null,
      generation,
      attempt,
      epoch: host.connectionEpoch,
      control: false,
      bodyHash: operation.requestBodyHash,
      digestScheme: operation.requestDigestScheme,
      digestKeyId: operation.requestDigestKeyId,
      sequence: payload.hasStdin === true ? 0 : operation.nextStdinSequence,
      startup,
      // Guest privilege travels from the sandbox row on every launch (create,
      // create retry, reconnect, restore): the row is authoritative and only
      // `guestRoot` can rise there (backfill), never fall.
      guestSudo:
        (kind === "sandbox.create" || kind === "sandbox.reconnect") && sandbox.guestSudo
          ? (true as const)
          : undefined,
      guestRoot:
        (kind === "sandbox.create" || kind === "sandbox.reconnect") &&
        (sandbox.guestRoot || sandbox.guestSudo)
          ? (true as const)
          : undefined,
      // Preview tunnels: the declared ports compile into the launch's network
      // plan (create, and a restore's new root; a cold reconnect keeps its plan).
      tunnelPorts:
        (kind === "sandbox.create" || kind === "sandbox.reconnect") &&
        (sandbox.tunnelPorts ?? []).length > 0
          ? [...sandbox.tunnelPorts].sort((a, b) => a - b)
          : undefined,
      // §8.6 (rows only; `diskUnavailable` refused above).
      disk: typeof diskFields === "string" ? {} : diskFields,
      restore,
    };
  }, null);
  const now = clock();
  if (pendingConfig) {
    const outcome = await sandboxRelaySessionManager.installExecutionConfig(
      hostId,
      operationId,
      pendingConfig.principal,
      pendingConfig.frame,
    );
    if (outcome === "not_sent") {
      // The carrier never entered socket IO. Reconciliation's next wake may
      // retry immediately; an ambiguous send still keeps the backoff lease.
      await prisma.outboxEvent.updateMany({
        where: {
          id: event.id,
          userId: event.userId,
          aggregateId: sandboxId,
          processedAt: null,
          sentAt: null,
          claimToken: pendingConfig.claimToken,
          sentConnectionEpoch: pendingConfig.frame.connectionEpoch,
        },
        data: { claimToken: null, claimedAt: null },
      });
    }
    // Only a deterministic pre-frame refusal proves no new effect. Missing
    // ACKs and transport failures remain pending under the durable backoff.
    if (outcome === "invalid_config")
      await terminalizeDeterministicDispatchFailure({
        event,
        hostId,
        operationId,
        sandboxId,
        generation,
        prepared: {
          attempt: pendingConfig.attempt,
          epoch: pendingConfig.frame.connectionEpoch,
          firstClaim: pendingConfig.firstClaim,
          authorizingKeyId: recordedKeyIdOf(pendingConfig.principal),
        },
        pendingConfig: {
          hostId: pendingConfig.dispatchedHostId,
          epoch: pendingConfig.dispatchedConnectionEpoch,
        },
        neverSent: true,
        claimToken: pendingConfig.claimToken,
        clock,
        errorCode: "protocol_error",
        errorDetail: safeOperationError("protocol_error").message,
      });
    return false;
  }
  if (!prepared || !hostId) return false;

  let sent = false;
  let refusedBeforeFrame = false;
  let frameMayHaveBeenSent = false;
  const onPossibleDispatchFrame = () => {
    frameMayHaveBeenSent = true;
  };
  let confirmed = false;
  let deterministicFailure: Error | undefined;
  try {
    if (prepared.authority === "inactive") {
      refusedBeforeFrame = true;
    } else if (kind === "operation.cancel") {
      sent = await sandboxRelaySessionManager.cancelOperation(
        hostId,
        operationId,
        generation,
        prepared.attempt,
        prepared.epoch,
        prepared.principal,
      );
    } else if (kind === "process.stdin") {
      const raw = typeof payload.stdinBase64 === "string" ? payload.stdinBase64 : "";
      sent = await sandboxRelaySessionManager.sendStdin(
        hostId,
        operationId,
        generation,
        prepared.attempt,
        Uint8Array.from(Buffer.from(raw, "base64")),
        payload.eof === true,
        prepared.epoch,
        prepared.sequence,
        prepared.principal,
      );
    } else if (kind === "command.run") {
      // Preserve stored command/template data. Validate and numerically encode
      // duration on this live branch as well as in the shared wire builder.
      const outcome = await sandboxRelaySessionManager.dispatchOperation(hostId, {
        ...payload,
        timeoutMs: dispatchTimeoutMs(kind, payload.timeoutMs),
        ...("requiresFsProcess" in prepared && prepared.requiresFsProcess === true
          ? { requiresFsProcess: true }
          : {}),
        resultVersion: "resultVersion" in prepared ? prepared.resultVersion : undefined,
        processId: "processId" in prepared ? prepared.processId : undefined,
        authorizingPrincipal: prepared.principal,
        connectionEpoch: prepared.epoch,
        operationId,
        sandboxId,
        idempotencyKey: String(payload.idempotencyKey ?? ""),
        kind,
        generation,
        attempt: prepared.attempt,
        // Initial stdin rides in the durable outbox payload (bounded to one
        // 32 KiB chunk at enqueue); no operation row holds payload bytes.
        stdinBytes:
          typeof payload.stdinBase64 === "string"
            ? Uint8Array.from(Buffer.from(payload.stdinBase64, "base64"))
            : undefined,
        stdinSequence: prepared.sequence,
        stdinEof: payload.hasStdin === true,
        bodyHash: prepared.bodyHash,
        digestScheme: prepared.digestScheme,
        digestKeyId: prepared.digestKeyId,
        onPossibleDispatchFrame,
      });
      sent = outcome === "sent";
      refusedBeforeFrame = outcome === "refused_before_frame";
    } else {
      const outcome = await sandboxRelaySessionManager.dispatchOperation(hostId, {
        ...("requiresFsProcess" in prepared && prepared.requiresFsProcess === true
          ? { requiresFsProcess: true }
          : {}),
        resultVersion: "resultVersion" in prepared ? prepared.resultVersion : undefined,
        processId: "processId" in prepared ? prepared.processId : undefined,
        authorizingPrincipal: prepared.principal,
        connectionEpoch: prepared.epoch,
        operationId,
        sandboxId,
        idempotencyKey: String(payload.idempotencyKey ?? ""),
        kind,
        generation,
        attempt: prepared.attempt,
        allocation: pinnedAllocationV11Schema.safeParse(payload.allocation).data,
        cpuCount: typeof payload.cpuCount === "number" ? payload.cpuCount : undefined,
        memoryMiB: typeof payload.memoryMiB === "number" ? payload.memoryMiB : undefined,
        templateDigest:
          typeof payload.templateDigest === "string" ? payload.templateDigest : undefined,
        templateRevisionId:
          typeof payload.templateRevisionId === "string" ? payload.templateRevisionId : undefined,
        verificationConnectionEpoch: kind === "sandbox.create" ? prepared.epoch : undefined,
        incusFingerprint:
          typeof payload.incusFingerprint === "string" ? payload.incusFingerprint : undefined,
        architecture: typeof payload.architecture === "string" ? payload.architecture : undefined,
        guestUid: typeof payload.guestUid === "number" ? payload.guestUid : undefined,
        guestGid: typeof payload.guestGid === "number" ? payload.guestGid : undefined,
        guestHome: typeof payload.guestHome === "string" ? payload.guestHome : undefined,
        guestShell: typeof payload.guestShell === "string" ? payload.guestShell : undefined,
        incusName: typeof payload.incusName === "string" ? payload.incusName : undefined,
        argv: Array.isArray(payload.argv)
          ? payload.argv.filter((v): v is string => typeof v === "string")
          : undefined,
        script: typeof payload.script === "string" ? payload.script : undefined,
        cwd: typeof payload.cwd === "string" ? payload.cwd : undefined,
        timeoutMs: dispatchTimeoutMs(kind, payload.timeoutMs),
        path: typeof payload.path === "string" ? payload.path : undefined,
        destPath: typeof payload.destPath === "string" ? payload.destPath : undefined,
        recursive: payload.recursive === true,
        maxDepth: typeof payload.depth === "number" ? payload.depth : undefined,
        limit: typeof payload.limit === "number" ? payload.limit : undefined,
        continuation:
          payload.continuation === undefined
            ? undefined
            : resultContinuationSchema.parse(payload.continuation),
        process:
          payload.process === undefined ? undefined : processRefSchema.parse(payload.process),
        targetOperationId:
          typeof payload.targetOperationId === "string" ? payload.targetOperationId : undefined,
        env: parseCommandRunDispatchEnvPairs(payload.env),
        privateConfig: payload.privateConfig as
          | import("@wssp/api/sandbox/execution-config").PrivateConfigReference
          | undefined,
        // The recorded policy travels verbatim from the durable payload; a
        // missing or malformed one is a producer bug, not a retryable dispatch.
        ...launchEgressFields(kind, payload),
        ...launchCredentialSpec(kind, payload),
        ...teardownCredentialCapture(kind, payload),
        ...(kind === "sandbox.create" && payload.image !== undefined
          ? { image: dispatchImageV11Schema.parse(payload.image) }
          : {}),
        // §8.6: restore (with its disk image), expectDisk and
        // diskBaseFingerprint, built from rows in the dispatch transaction.
        ...("disk" in prepared ? prepared.disk : {}),
        ...(kind === "sandbox.capture"
          ? { capture: dispatchCaptureV11Schema.parse(payload.capture) }
          : {}),
        // Build binding: from the durable payload only (checked against the
        // sandbox row under S by buildDispatchFieldsMatch before the claim).
        ...(kind === "sandbox.create" && payload.build !== undefined
          ? { build: dispatchBuildV11Schema.parse(payload.build) }
          : {}),
        // Start/ready commands of the sandbox's immutable revision (B9).
        ...("startup" in prepared && prepared.startup ? { startup: prepared.startup } : {}),
        ...("guestSudo" in prepared && prepared.guestSudo ? { guestSudo: true as const } : {}),
        ...("guestRoot" in prepared && prepared.guestRoot ? { guestRoot: true as const } : {}),
        ...("tunnelPorts" in prepared && prepared.tunnelPorts
          ? { tunnelPorts: prepared.tunnelPorts }
          : {}),
        signal:
          payload.signal === "SIGTERM" ||
          payload.signal === "SIGINT" ||
          payload.signal === "SIGHUP" ||
          payload.signal === "SIGKILL"
            ? payload.signal
            : undefined,
        // The committed upload transfer is the ONLY file.put source (C29/C30).
        fileUpload:
          kind === "file.put"
            ? await (typeof payload.transferId === "string"
                ? transferStore().uploadSource(payload.transferId, operationId)
                : Promise.reject(new ORPCError("NOT_FOUND"))
              ).catch((error: unknown) => {
                if (error instanceof ORPCError && error.status < 500)
                  throw new SandboxRelayDispatchValidationError(
                    "Upload source is no longer available.",
                  );
                throw error;
              })
            : undefined,
        stdinSequence: kind === "command.run" ? prepared.sequence : undefined,
        stdinEof: kind === "command.run" ? payload.hasStdin === true : undefined,
        bodyHash: prepared.bodyHash,
        digestScheme: prepared.digestScheme,
        digestKeyId: prepared.digestKeyId,
        // Reserved before the claim committed; dispatch adopts it.
        fileStreamSlot: streamSlot ?? undefined,
        lease: LEASE_DISPATCH_KINDS.has(kind) ? leaseWireSchema.parse(payload.lease) : undefined,
        onPossibleDispatchFrame,
      });
      sent = outcome === "sent";
      refusedBeforeFrame = outcome === "refused_before_frame";
    }
  } catch (error) {
    if (error instanceof CommandTimeoutValidationError)
      deterministicFailure = new SandboxRelayDispatchValidationError(
        "Invalid stored command timeout.",
      );
    else if (isDeterministicDispatchError(error)) deterministicFailure = error;
    else throw error;
  } finally {
    if (!deterministicFailure && !refusedBeforeFrame) {
      // Confirm only our recorded target. Hello/reclaim may already own recovery.
      const written = await prisma.outboxEvent.updateMany({
        where: { id: event.id, claimToken, sentConnectionEpoch: prepared.epoch, processedAt: null },
        data:
          sent && kind === "operation.cancel"
            ? // Keep a leased delivery owner until a host result retires this event.
              // sentAt remains null so the scan reclaims it after the lease deadline.
              { sentAt: null }
            : sent
              ? {
                  sentAt: now,
                  ...(prepared.control ? { processedAt: now } : {}),
                  claimToken: null,
                  claimedAt: null,
                }
              : { claimToken: null, claimedAt: null },
      });
      confirmed = written.count === 1;
    }
  }
  if (deterministicFailure) {
    if (frameMayHaveBeenSent && !prepared.control) {
      // Encoding/transport failure after a possible frame cannot undo its effect.
      await prisma.outboxEvent.updateMany({
        where: { id: event.id, claimToken, sentConnectionEpoch: prepared.epoch, processedAt: null },
        data: { claimToken: null, claimedAt: null },
      });
      return false;
    }
    if (prepared.control) {
      await relayTransaction(async (tx) => {
        await refuseDispatchEvent(tx, event, payload, clock(), "protocol_error", claimToken);
        return true;
      }, false);
      return false;
    }
    await terminalizeDeterministicDispatchFailure({
      event,
      hostId,
      operationId,
      sandboxId,
      generation,
      prepared,
      claimToken,
      clock,
      neverSent: !frameMayHaveBeenSent,
      errorCode:
        deterministicFailure instanceof SandboxRelayVmSizeMismatchError
          ? "vm_size_mismatch"
          : deterministicFailure instanceof SandboxRelayDispatchValidationError
            ? "protocol_error"
            : "request_too_large",
      errorDetail: safeOperationError(
        deterministicFailure instanceof SandboxRelayVmSizeMismatchError
          ? "vm_size_mismatch"
          : deterministicFailure instanceof SandboxRelayDispatchValidationError
            ? "protocol_error"
            : "request_too_large",
      ).message,
    });
    return false;
  }
  if (!sent || !confirmed) {
    if (!sent && !frameMayHaveBeenSent && refusedBeforeFrame && !prepared.control) {
      await settleRefusedDispatch({
        event,
        hostId,
        operationId,
        sandboxId,
        generation,
        prepared,
        claimToken,
        clock,
        inactiveHost: hostCredential ? (tx) => hostCredential(prepared.epoch, tx) : undefined,
      });
    } else if (!sent && prepared.control) {
      // Controls re-read their own principal; no target-operation authorizer fallback.
      await relayTransaction(async (tx) => {
        const controlKeyId = recordedKeyIdOf(prepared.principal);
        if (controlKeyId !== null)
          await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${controlKeyId} FOR SHARE`;
        await lockCurrentHostEpoch(tx, hostId);
        const sandbox = await tx.sandbox.findFirst({
          where: { id: sandboxId, userId: event.userId },
        });
        if (!sandbox) return false;
        const status = await checkAcceptedDispatchAuthority(
          {
            ownerId: event.userId,
            principal: prepared.principal,
            context: {
              sandboxId: sandbox.id,
              sandboxHostId: sandbox.originHostId,
              templateRevisionId: sandbox.templateRevisionId,
              originPoolId: sandbox.originPoolId,
            },
          },
          tx,
        );
        if (status === "inactive")
          await refuseDispatchEvent(tx, event, payload, clock(), "credential_inactive");
        return true;
      }, false);
    }
    return false;
  }
  if (prepared.control && kind !== "operation.cancel") {
    // Stdin send is fenced; cancellation is terminal only after host acknowledgement.
    await relayTransaction(async (tx) => {
      const host = await lockCurrentHostEpoch(tx, hostId);
      requireRelayFence(host.connectionEpoch === prepared.epoch);
      await requireRelayWorkload(
        tx,
        { userId: host.userId, hostId },
        { operationId, sandboxId, sandboxOwnerId: event.userId },
      );
      const operation = await tx.sandboxOperation.findFirst({
        where: { id: operationId },
        select: { kind: true, launchMode: true },
      });
      requireRelayFence(operation != null);
      await casSandboxGeneration(tx, {
        sandboxId,
        userId: event.userId,
        generation,
        hostId,
        states: sandboxStatesForOperation(operation),
      });
      await casActiveOperation(
        tx,
        {
          operationId,
          sandboxId,
          userId: event.userId,
          generation,
          attempt: prepared.attempt,
          hostId,
        },
        { dispatchAttempt: prepared.attempt },
      );
      return true;
    }, false);
  }
  // Sent dispatches await results outside the pending-send scan.
  return true;
}

async function claimEvent(
  tx: Prisma.TransactionClient,
  event: Event,
  now: Date,
  claimToken: string,
  payload?: Prisma.InputJsonObject,
  targetEpoch?: number,
) {
  const claimedAt = now;
  const claimed = await tx.outboxEvent.updateMany({
    where: {
      id: event.id,
      userId: event.userId,
      aggregateId: event.aggregateId,
      ...claimable(claimedAt),
    },
    // Durable send intent precedes socket IO. claimedAt/token mark an in-flight send;
    // sentAt is confirmation only. Hello can reopen either phase by target epoch.
    data: {
      claimToken,
      claimedAt,
      ...(targetEpoch !== undefined ? { sentConnectionEpoch: targetEpoch } : {}),
      ...(payload ? { payload } : {}),
    },
  });
  requireRelayFence(claimed.count === 1);
}
/** Retire in one write: a second UPDATE would recheck the owner FK. */
async function retireClaimableEvent(tx: Prisma.TransactionClient, event: Event, now: Date) {
  const written = await tx.outboxEvent.updateMany({
    where: {
      id: event.id,
      userId: event.userId,
      aggregateId: event.aggregateId,
      ...claimable(now),
    },
    data: { processedAt: now, claimToken: null, claimedAt: null },
  });
  requireRelayFence(written.count === 1);
}

function dispatchTimeoutMs(kind: string, raw: unknown): number | undefined {
  const parsed = typeof raw === "number" && Number.isFinite(raw) ? raw : undefined;
  if (kind === "command.run") return encodeCommandTimeoutMs(effectiveCommandTimeoutMs(raw));
  return parsed;
}

/** A refusal is meaningful only for the exact outstanding install token, epoch
 * and config identity. Replays and ACK races fail the transactional event fence. */
export async function refuseExecutionConfig(
  sender: import("./operation-handlers.js").RelaySender,
  frame: Extract<import("./protocol.js").DaemonControlMessage, { type: "private.config.refused" }>,
): Promise<boolean> {
  if (sender.isCurrent?.() === false || sender.connectionEpoch !== frame.connectionEpoch)
    return false;
  const event = await prisma.outboxEvent.findFirst({
    where: {
      userId: frame.sandboxOwnerId,
      aggregateType: "sandbox",
      aggregateId: frame.sandboxId,
      claimToken: `config:${frame.refusalToken}`,
      sentConnectionEpoch: frame.connectionEpoch,
      processedAt: null,
      sentAt: null,
      payload: { path: ["privateConfig", "configId"], equals: frame.configId },
    },
  });
  if (!event?.payload || typeof event.payload !== "object" || Array.isArray(event.payload))
    return false;
  const operationId = event.payload.operationId;
  if (typeof operationId !== "string") return false;
  const operation = await prisma.sandboxOperation.findFirst({
    where: {
      id: operationId,
      userId: frame.sandboxOwnerId,
      sandboxId: frame.sandboxId,
      generation: frame.generation,
    },
  });
  if (!operation) return false;
  return terminalizeDeterministicDispatchFailure({
    event,
    hostId: sender.hostId,
    sandboxId: frame.sandboxId,
    operationId,
    generation: frame.generation,
    prepared: {
      attempt: operation.dispatchAttempt,
      epoch: frame.connectionEpoch,
      authorizingKeyId: operation.authorizingKeyId,
      firstClaim:
        operation.state === "QUEUED" &&
        operation.dispatchAttempt === 0 &&
        operation.dispatchedHostId === null &&
        operation.dispatchedConnectionEpoch === null &&
        operation.acceptedAttempt === null,
    },
    pendingConfig: {
      hostId: operation.dispatchedHostId,
      epoch: operation.dispatchedConnectionEpoch,
    },
    neverSent: true,
    claimToken: `config:${frame.refusalToken}`,
    clock: leaseNow,
    errorCode: "private_config_refused",
    errorDetail: safeOperationError("private_config_refused").message,
    refusal: { sender, frame },
  });
}

async function terminalizeDeterministicDispatchFailure(input: {
  event: Event;
  hostId: string;
  operationId: string;
  sandboxId: string;
  generation: number;
  prepared: {
    attempt: number;
    epoch: number;
    authorizingKeyId?: string | null;
    firstClaim: boolean;
  };
  neverSent: boolean;
  pendingConfig?: { hostId: string | null; epoch: number | null };
  claimToken: string;
  clock: LeaseClock;
  errorCode: "protocol_error" | "request_too_large" | "private_config_refused" | "vm_size_mismatch";
  errorDetail: string;
  refusal?: {
    sender: import("./operation-handlers.js").RelaySender;
    frame: Extract<
      import("./protocol.js").DaemonControlMessage,
      { type: "private.config.refused" }
    >;
  };
}): Promise<boolean> {
  return relayTransaction(async (tx) => {
    if (input.refusal) {
      await requireRelayWorkload(tx, input.refusal.sender, input.refusal.frame);
      await lockOwnerForAdmission(tx, input.event.userId);
      requireRelayFence(input.refusal.sender.isCurrent?.() !== false);
    }
    if (typeof input.prepared.authorizingKeyId === "string")
      await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${input.prepared.authorizingKeyId} FOR SHARE`;
    const host = await lockCurrentHostEpoch(tx, input.hostId);
    requireRelayFence(host.connectionEpoch === input.prepared.epoch);
    await requireRelayWorkload(
      tx,
      { userId: host.userId, hostId: input.hostId },
      {
        operationId: input.operationId,
        sandboxId: input.sandboxId,
        sandboxOwnerId: input.event.userId,
      },
    );
    const sandbox = await tx.sandbox.findFirst({
      where: { id: input.sandboxId, userId: input.event.userId },
    });
    requireRelayFence(sandbox != null);
    await casSandboxGeneration(tx, {
      sandboxId: input.sandboxId,
      userId: input.event.userId,
      generation: sandbox.generation,
      hostId: input.hostId,
      states: [sandbox.state],
    });
    await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${input.operationId} AND "userId" = ${input.event.userId} FOR UPDATE`;
    const now = await leaseTransactionNow(tx, input.clock);
    const operation = await tx.sandboxOperation.findFirst({
      where: { id: input.operationId },
    });
    requireRelayFence(
      operation != null &&
        operation.userId === input.event.userId &&
        operation.sandboxId === input.sandboxId &&
        operation.generation === input.generation,
    );
    if (input.refusal) {
      const frame = input.refusal.frame;
      const config = await loadExecutionConfig(tx, input.sandboxId, input.event.userId);
      const evidence = await tx.sandboxHost.findUnique({
        where: { id: input.hostId },
        select: {
          connectionEpoch: true,
          journalKeyVersion: true,
          journalKeyId: true,
          journalKeyAcknowledgedEpoch: true,
        },
      });
      requireRelayFence(
        sandbox.generation === input.generation &&
          config != null &&
          config.reference.configId === frame.configId &&
          config.hostId === input.hostId &&
          config.generation === frame.generation &&
          config.acknowledgedEpoch !== frame.connectionEpoch &&
          evidence != null &&
          hostJournalKeyAcknowledged(evidence) &&
          evidence.journalKeyId === config.reference.bindingKeyId,
      );
      // The first config refusal is promoted to the refused 0→1 operation
      // claim only while O still proves QUEUED@0 with no dispatch identity.
      // A prior dispatch or an accepted attempt cannot establish NOT_ISSUED.
      requireRelayFence(operation.acceptedAttempt === null || !input.prepared.firstClaim);
    }
    const fence = {
      operationId: input.operationId,
      sandboxId: input.sandboxId,
      userId: input.event.userId,
      generation: input.generation,
      attempt: input.prepared.attempt,
      hostId: input.pendingConfig ? input.pendingConfig.hostId : input.hostId,
    };
    const provenFirstClaim =
      input.prepared.firstClaim &&
      (!input.refusal ||
        (operation.state === "QUEUED" &&
          operation.dispatchAttempt === 0 &&
          operation.dispatchedHostId === null &&
          operation.dispatchedConnectionEpoch === null &&
          operation.acceptedAttempt === null));
    const failedState = provenFirstClaim && input.neverSent ? "FAILED" : "UNKNOWN_OUTCOME";
    const failed = await tx.sandboxOperation.updateMany({
      where: {
        ...operationActiveFenceWhere(fence),
        dispatchedConnectionEpoch: input.pendingConfig
          ? input.pendingConfig.epoch
          : input.prepared.epoch,
      },
      data: {
        state: failedState,
        ...(input.refusal && failedState === "FAILED" ? { dispatchAttempt: 1 } : {}),
        completedAt: now,
        errorCode: input.errorCode,
        errorDetail: input.errorDetail,
      },
    });
    requireRelayFence(failed.count === 1);
    await settleOperationCredentials(tx, {
      sandboxId: input.sandboxId,
      operation: {
        id: input.operationId,
        kind: operation.kind,
        dispatchAttempt: operation.dispatchAttempt,
      },
      opState: failedState,
    });
    noteHostBlockerReleased(tx, input.hostId, host.userId);
    const retireEvent = async () => {
      const processed = await tx.outboxEvent.updateMany({
        where: {
          id: input.event.id,
          userId: input.event.userId,
          aggregateId: input.sandboxId,
          processedAt: null,
          claimToken: input.claimToken,
          sentConnectionEpoch: input.prepared.epoch,
          ...(input.refusal ? { sentAt: null } : {}),
        },
        data: { processedAt: now, claimToken: null, claimedAt: null },
      });
      requireRelayFence(processed.count === 1);
    };
    const restore = restoreOffloadOf(operation) !== null;
    // A restore retires its event first: the exit's SYSTEM_DETACH kill
    // retires every older generation's pending event, this one included.
    if (restore) await retireEvent();
    // §8.7: a restore whose dispatch failed terminally ends through the
    // restore exit (no-effect proof only for a proven, never-sent first claim).
    const exited =
      restore &&
      (await exitRestoreAttempt(
        tx,
        restoreExitInput(
          input.sandboxId,
          input.event.userId,
          input.operationId,
          input.generation,
          failedState === "FAILED",
          "dispatch_refused",
        ),
      ));
    if (
      !exited &&
      failedState === "FAILED" &&
      input.errorCode !== "vm_size_mismatch" &&
      isLifecycleOperationKind(operation.kind)
    ) {
      await releaseLiveResourcesIfHeld(tx, {
        hostId: input.hostId,
        ownerId: input.event.userId,
        sandboxId: input.sandboxId,
        operationId: input.operationId,
        kind: operation.kind,
        opState: "FAILED",
        sandboxStateBeforeResult: sandbox.state,
        neverIssued: provenFirstClaim && input.neverSent,
        ...(operation.kind === "CREATE_SANDBOX"
          ? {
              sandboxFailure: {
                lastErrorCode: input.errorCode,
                lastErrorDetail: input.errorDetail,
              },
            }
          : {}),
      });
    }
    await settleSupersededOperations(tx, { ...operation, state: failedState }, now);
    if (!restore) await retireEvent();
    noteTerminalResultRelease(tx, input.event.userId, { operationId: input.operationId });
    requireRelayFence(input.refusal?.sender.isCurrent?.() !== false);
    return true;
  }, false);
}

/** The token and exact send identity fence BOTH rows in one transaction.
 * A moved ticket is retryable only when this first claim provably wrote no frame. */
async function settleRefusedDispatch(input: {
  event: Event;
  hostId: string;
  operationId: string;
  sandboxId: string;
  generation: number;
  prepared: {
    attempt: number;
    epoch: number;
    firstClaim: boolean;
    principal: AuthorizingPrincipal;
    /** R6: the event's attribution failed to decode; settle as `inactive`. */
    attributionUndecodable?: boolean;
    requiresFsProcess?: boolean;
    /** B9: the launch carried start/ready commands. */
    startup?: unknown;
    /** The launch carried guest privilege fields (DG-8). */
    guestRoot?: true;
    /** Preview tunnels: the launch's declared ports. */
    tunnelPorts?: number[];
    /** §8.6: the dispatch's disk fields. */
    disk?: DispatchDiskFields;
  };
  claimToken: string;
  clock: LeaseClock;
  inactiveHost?: (tx: Prisma.TransactionClient) => Promise<"active" | "inactive" | "indeterminate">;
}): Promise<void> {
  await relayTransaction(async (tx) => {
    const principal = input.prepared.principal;
    const principalKeyId = recordedKeyIdOf(principal);
    if (principalKeyId !== null)
      await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${principalKeyId} FOR SHARE`;
    const host = await lockCurrentHostEpoch(tx, input.hostId);
    await requireRelayWorkload(
      tx,
      { userId: host.userId, hostId: input.hostId },
      {
        operationId: input.operationId,
        sandboxId: input.sandboxId,
        sandboxOwnerId: input.event.userId,
      },
    );
    const sandbox = await tx.sandbox.findFirst({
      where: { id: input.sandboxId, userId: input.event.userId },
    });
    requireRelayFence(sandbox != null);
    await casSandboxGeneration(tx, {
      sandboxId: input.sandboxId,
      userId: input.event.userId,
      generation: input.generation,
      hostId: input.hostId,
      states: [sandbox.state],
    });
    await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${input.operationId} AND "userId" = ${input.event.userId} FOR UPDATE`;
    const now = await leaseTransactionNow(tx, input.clock);
    const operation = await tx.sandboxOperation.findFirst({
      where: { id: input.operationId, userId: input.event.userId },
    });
    requireRelayFence(
      operation != null &&
        operation.sandboxId === input.sandboxId &&
        operation.generation === input.generation &&
        operation.dispatchAttempt === input.prepared.attempt &&
        operation.dispatchedHostId === input.hostId &&
        operation.dispatchedConnectionEpoch === input.prepared.epoch &&
        operation.acceptedAttempt === null &&
        ["DISPATCHED", "CANCEL_REQUESTED", "UNKNOWN_OUTCOME"].includes(operation.state),
    );
    const launch = operation.kind === "CREATE_SANDBOX" || operation.kind === "RECONNECT_SANDBOX";
    // U9.1: a restore is known from the operation row only.
    const restore = restoreOffloadOf(operation) !== null;
    const diskFields =
      input.prepared.disk !== undefined && dispatchHasDiskFields(input.prepared.disk);
    const support =
      input.prepared.requiresFsProcess || launch || diskFields
        ? await tx.sandboxHost.findFirst({
            where: { id: input.hostId, userId: host.userId },
            select: {
              connectionEpoch: true,
              status: true,
              relayProtocolVersion: true,
              relayProtocolEpoch: true,
              admissionRuntime: true,
              admissionEpoch: true,
              daemonFeatures: true,
              daemonDiskOffload: true,
              daemonTunnelPorts: true,
            },
          })
        : null;
    const unsupported =
      // U9.2: the capability re-check at the current epoch. A restore (or a
      // cached cold reconnect's `expectDisk`) on an admitted daemon without
      // `diskOffload` is refused unsupported, never sent.
      ((diskFields || restore) && diskOffloadHostUnsupported(support)) ||
      (input.prepared.requiresFsProcess === true && fsProcessHostUnsupported(support)) ||
      // B9: a launch with start/ready commands on an admitted daemon without
      // `templateStartup` (typed refusal, never a silent start-less boot).
      (launch && input.prepared.startup !== undefined && templateStartupHostUnsupported(support)) ||
      // DG-8: a guest-privileged launch on an admitted daemon without
      // `guestSudo` (a taint-only `guestRoot` cannot degrade either).
      (launch && input.prepared.guestRoot === true && guestSudoHostUnsupported(support)) ||
      // Preview tunnels: a launch with declared ports on an admitted daemon
      // without the tunnel plan (typed refusal, never a frame it would reject).
      (launch && input.prepared.tunnelPorts !== undefined && tunnelPortsHostUnsupported(support)) ||
      (launch &&
        support != null &&
        support.status === "CONNECTED" &&
        support.relayProtocolEpoch === support.connectionEpoch &&
        support.relayProtocolVersion != null &&
        !(support.relayProtocolVersion === "1.0"));
    const first = input.prepared.firstClaim && input.prepared.attempt === 1;
    // Reconcile may win H first and conservatively retire this attempt UNKNOWN.
    // The caller's explicit no-frame refusal still proves this exact first claim
    // unsent. Only that proof plus a current persisted refusal may resolve it;
    // no earlier send, accepted attempt, birth, or changed epoch can pass here.
    // A rescan on another server may instead have retired it as unsupported.
    // PID/acceptance cannot arise for this single-owner no-frame claim; the
    // read guards are defense in depth. The CAS repeats them under the O lock,
    // so no writer can change them between the read and CAS.
    const reconciledUnknown =
      operation.state === "UNKNOWN_OUTCOME" &&
      ["unknown_outcome", "unsupported_capability"].includes(operation.errorCode ?? "") &&
      operation.processPid === null &&
      first &&
      unsupported &&
      host.connectionEpoch > input.prepared.epoch;
    requireRelayFence(operation.state !== "UNKNOWN_OUTCOME" || reconciledUnknown);
    // Hello reopens an old epoch's event by clearing its claim. While H
    // proves the new epoch cannot send this shape, the exact old attempt and
    // a proven no-frame refusal still own settlement. A successor claim misses.
    const eventWhere = {
      id: input.event.id,
      userId: input.event.userId,
      aggregateId: input.sandboxId,
      ...(reconciledUnknown ? {} : { processedAt: null }),
      sentAt: null,
      sentConnectionEpoch: input.prepared.epoch,
      ...(unsupported && host.connectionEpoch > input.prepared.epoch
        ? { OR: [{ claimToken: input.claimToken }, { claimToken: null }] }
        : { claimToken: input.claimToken }),
    };
    const event = await tx.outboxEvent.findFirst({
      where: eventWhere,
      select: { id: true, payload: true },
    });
    requireRelayFence(event != null);
    // R6: an undecodable attribution has no authority to look up. Settling
    // an already-refused outcome needs none: it is `inactive` outright and
    // never reaches a session, key or system authority check.
    let status: "active" | "inactive" | "indeterminate" = input.prepared.attributionUndecodable
      ? "inactive"
      : await checkAcceptedDispatchAuthority(
          {
            ownerId: input.event.userId,
            principal,
            operationKind: operation.kind,
            context: {
              sandboxId: sandbox.id,
              sandboxHostId: sandbox.originHostId,
              templateRevisionId: sandbox.templateRevisionId,
              originPoolId: sandbox.originPoolId,
            },
          },
          tx,
        );
    const eventPayload = event.payload as Record<string, unknown>;
    if (operation.authorizingKeyId !== recordedKeyIdOf(principal)) status = "inactive";
    if (
      !decodeOutboxPrincipal(eventPayload) ||
      JSON.stringify(decodeOutboxPrincipal(eventPayload)) !== JSON.stringify(principal) ||
      (dispatchClassOf(principal, String(eventPayload.kind)) === "system" &&
        !systemDispatchAllowed(String(eventPayload.kind), eventPayload))
    )
      status = "inactive";
    const hostStatus = await input.inactiveHost?.(tx).catch(() => "indeterminate" as const);
    // Only allocations have a known pre-effect failure on host credential
    // refusal. Cleanup and warm reconnect stay retryable so a replacement
    // epoch can finish them (3A R1-3).
    const allocation =
      operation.kind === "CREATE_SANDBOX" ||
      restore ||
      (operation.kind === "RECONNECT_SANDBOX" && sandbox.state === "STOPPED");
    if (hostStatus === "inactive" && allocation) status = "inactive";
    const cancelled = first && operation.state === "CANCEL_REQUESTED";
    const state = cancelled
      ? "CANCELLED"
      : unsupported
        ? first
          ? "FAILED"
          : "UNKNOWN_OUTCOME"
        : status === "inactive"
          ? first
            ? "FAILED"
            : "UNKNOWN_OUTCOME"
          : first
            ? "QUEUED"
            : operation.state;
    const fence = {
      operationId: input.operationId,
      sandboxId: input.sandboxId,
      userId: input.event.userId,
      generation: input.generation,
      attempt: input.prepared.attempt,
      hostId: input.hostId,
    };
    const failureCode = cancelled
      ? "cancelled"
      : unsupported
        ? "unsupported_capability"
        : "credential_inactive";
    const failureDetail = cancelled
      ? "Operation cancelled."
      : unsupported
        ? safeOperationError("unsupported_capability").message
        : "Accepted dispatch authority is inactive.";
    const data: Prisma.SandboxOperationUpdateManyMutationInput =
      state === "QUEUED"
        ? {
            state,
            dispatchAttempt: 0,
            dispatchedAt: null,
            dispatchedHostId: null,
            dispatchedConnectionEpoch: null,
          }
        : {
            state,
            ...(state !== operation.state
              ? {
                  completedAt: operation.completedAt ?? now,
                  errorCode: failureCode,
                  errorDetail: failureDetail,
                }
              : {}),
          };
    if (reconciledUnknown) {
      assertBeforeResultQuota(tx);
      const written = await tx.sandboxOperation.updateMany({
        where: {
          ...operationActiveFenceWhere(fence),
          state: "UNKNOWN_OUTCOME",
          errorCode: { in: ["unknown_outcome", "unsupported_capability"] },
          acceptedAttempt: null,
          processPid: null,
          dispatchedConnectionEpoch: input.prepared.epoch,
        },
        data,
      });
      requireRelayFence(written.count === 1);
    } else await casActiveOperation(tx, fence, data);
    await settleOperationCredentials(tx, {
      sandboxId: input.sandboxId,
      operation: {
        id: input.operationId,
        kind: operation.kind,
        dispatchAttempt: operation.dispatchAttempt,
      },
      opState: state,
    });
    const retireEvent = async () => {
      const processed = await tx.outboxEvent.updateMany({
        where: eventWhere,
        data: {
          claimToken: null,
          claimedAt: null,
          ...(["FAILED", "CANCELLED", "UNKNOWN_OUTCOME"].includes(state)
            ? { processedAt: now }
            : {}),
        },
      });
      requireRelayFence(processed.count === 1);
    };
    // A restore retires its event first: the exit's SYSTEM_DETACH kill
    // retires every older generation's pending event, this one included.
    if (restore) await retireEvent();
    // §8.7 / U9.2: a refused restore ends through the restore exit, with a
    // no-effect proof only for this exact first, never-sent claim.
    const exited =
      restore &&
      (state === "FAILED" || state === "UNKNOWN_OUTCOME") &&
      (await exitRestoreAttempt(
        tx,
        restoreExitInput(
          input.sandboxId,
          input.event.userId,
          input.operationId,
          input.generation,
          state === "FAILED",
          unsupported ? "capability_refused" : "dispatch_refused",
        ),
      ));
    if (state === "FAILED") {
      noteHostBlockerReleased(tx, input.hostId, host.userId);
      if (!exited && isLifecycleOperationKind(operation.kind))
        await releaseLiveResourcesIfHeld(tx, {
          hostId: input.hostId,
          ownerId: input.event.userId,
          sandboxId: input.sandboxId,
          operationId: input.operationId,
          kind: operation.kind,
          opState: "FAILED",
          sandboxStateBeforeResult: sandbox.state,
          neverIssued: operation.dispatchAttempt === 0,
          // A failed create must not leave the sandbox transitional (3A R1-4).
          ...(operation.kind === "CREATE_SANDBOX"
            ? {
                sandboxFailure: {
                  lastErrorCode: failureCode,
                  lastErrorDetail: failureDetail,
                },
              }
            : {}),
        });
      await settleSupersededOperations(tx, { ...operation, state: "FAILED" }, now);
    }
    if (!restore) await retireEvent();
    noteTerminalResultRelease(tx, input.event.userId, { operationId: input.operationId });
    return true;
  }, false);
}

async function refuseDispatchEvent(
  tx: Prisma.TransactionClient,
  event: Event,
  payload: Record<string, unknown>,
  now: Date,
  code: "protocol_error" | "credential_inactive" | "unknown_outcome",
  claimToken?: string,
) {
  const refused = await tx.outboxEvent.updateMany({
    where: {
      id: event.id,
      userId: event.userId,
      processedAt: null,
      sentAt: null,
      ...(claimToken ? { claimToken } : {}),
    },
    data: {
      processedAt: now,
      claimToken: null,
      claimedAt: null,
      payload: { ...payload, dispatchRefusal: code } as Prisma.InputJsonObject,
    },
  });
  requireRelayFence(refused.count === 1);
}

/**
 * The notifier's drain: fast passes skip offline hosts' events; one pass at
 * least every {@link SANDBOX_OUTBOX_FULL_PASS_MS} evaluates every event.
 */
export function createSandboxOutboxDrain(
  now: () => number = Date.now,
  clock: LeaseClock = leaseNow,
): (shouldStop: () => boolean) => Promise<number> {
  let lastFullPassAt: number | null = null;
  return (shouldStop) => {
    const at = now();
    const full = lastFullPassAt === null || at - lastFullPassAt >= SANDBOX_OUTBOX_FULL_PASS_MS;
    if (full) lastFullPassAt = at;
    return processSandboxOutboxBatch(clock, shouldStop, { skipOfflineHosts: !full });
  };
}

export function startSandboxOutboxProcessor(signal: AbortSignal): () => Promise<void> {
  const notifier = new SandboxDispatchNotifier({ drainBatch: createSandboxOutboxDrain() });
  // The lease pull-in sweep (M3) runs straight after the access scan on the
  // same timer and wake hints (pool, membership, hello and ceiling writes).
  const access = new SharingAccessScheduler(async (shouldStop, pools) => {
    await scanSandboxAccess(leaseNow, shouldStop, pools);
    if (!shouldStop()) await scanLeasePolicy(leaseNow, shouldStop, pools);
  });
  // Capacity queue (§4.5): placement, timeouts and access loss of waiting
  // pool creates, woken by post-commit capacity hints.
  // the restore-wait pass runs right after the
  // capacity pass on the same wake and timer.
  const queue = new CapacityQueueScheduler(async (shouldStop, hint) => {
    const create = await runCapacityQueuePass(leaseNow, shouldStop, hint);
    if (shouldStop()) return create;
    const restore = await runRestoreWaitPass(leaseNow, shouldStop, hint);
    if (create === null) return restore;
    return restore === null ? create : Math.min(create, restore);
  });
  let stopping: Promise<void> | null = null;
  const stop = () => {
    if (stopping) return stopping;
    bindSharingAccessWake(null);
    bindCapacityQueueWake(null);
    signal.removeEventListener("abort", stop);
    bindSandboxDispatchWake(null);
    stopping = Promise.all([notifier.stop(), access.stop(), queue.stop()]).then(() => {});
    return stopping;
  };
  if (signal.aborted) void stop();
  else {
    bindCapacityQueueWake((hint) => queue.wake(hint));
    bindSharingAccessWake((poolId) => access.wake(poolId));
    bindSandboxDispatchWake(() => notifier.wake());
    signal.addEventListener("abort", stop, { once: true });
    notifier.wake();
  }
  return stop;
}
