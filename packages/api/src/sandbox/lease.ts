import { ORPCError } from "@orpc/server";
import type {
  Prisma,
  SandboxLeaseExpireAction,
  SandboxOperation,
  SandboxState,
  SandboxTeardownIntent,
} from "@wssp/db";
import prisma from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import type { ReadinessFailureReason } from "@wssp/sandbox-contracts";
import {
  hasOpenCredentialLeases,
  settleCredentialTeardown,
  settleOperationCredentials,
} from "../credentials/teardown";
import { type AuthorizingPrincipal, OPERATION_DISPATCH_KIND } from "./contracts";
import {
  type DigestContextSnapshot,
  digestContextSnapshot,
  ENV_FREE_DIGEST_DOMAIN,
  operationDigestContext,
} from "./digest-context";
import { exitRestoreAttempt } from "./disk-offload/restore-exit";
import { supersedeLiveOffload } from "./disk-offload/store";
import { sandboxStateConflict } from "./errors";
import {
  hasPossiblyLiveSandboxAttempt,
  lockHostForSandboxOperation,
  noteHostBlockerReleased,
  releaseLiveResourcesIfHeld,
} from "./host-admission";
import { hashLegacyEnvFreeBody, requestDigestMetadata } from "./idempotency";
import {
  accessExpiryIdempotencyKey,
  leaseExpiryIdempotencyKey,
  readinessFailureIdempotencyKey,
  teardownRetryIdempotencyKey,
  teardownRetryIndex,
} from "./idempotency-key-reserved";
import { defaultIncusInstanceName } from "./incus-name";
import { isRestoreAttempt } from "./launch-mode";
import { LEASE_DEFAULT_MS, LEASE_FINITE_MAX_MS, LEASE_MAX_MS } from "./lease-limits";
import { leaseDeadline, leaseRequestOf } from "./lease-policy";
import { createSandboxOutboxEvent } from "./outbox";
import { outboxOperationWhere } from "./outbox-operation";
import { recordedKeyIdOf, systemAttribution } from "./principal-kinds";
import { readinessFailureDetail, readinessFailureRecord } from "./readiness-detail";
import {
  casSandboxGeneration,
  hostDatabaseNow,
  relayTransaction,
  requireRelayFence,
  retireSupersededOperations,
  settleSupersededOperations,
} from "./relay-fence";
import { SandboxIntegrityError } from "./sensitive-errors";
import { reconcileSandboxAccess, scanSandboxAccess } from "./sharing-access";
import {
  ACTIVE_OPERATION_STATES,
  KILLABLE_SANDBOX_STATES,
  STOPPABLE_SANDBOX_STATES,
} from "./state-transitions";
import {
  pinnedAllocationPayload,
  pinnedLaunchSource,
  templateDispatchPayload,
} from "./template-dispatch";

export { LEASE_DEFAULT_MS, LEASE_MAX_MS };

export const LEASE_RENEWABLE_STATES: ReadonlySet<SandboxState> = new Set(["READY"]);

export type SandboxLeaseExpireActionInput = "stop" | "destroy";

export function parseLeaseExpireAction(
  value: SandboxLeaseExpireActionInput | undefined,
): SandboxLeaseExpireAction {
  return value === "stop" ? "STOP" : "DESTROY";
}

/**
 * Deadline of an accepted relative lease (`0` → the far-future no-timer
 * deadline). Shape only: the layered policy is checked by the caller with
 * `requireLeaseWithinPolicy` inside NEW acceptance, never during replay.
 */
export function resolveLeaseTimeout(timeoutMs = LEASE_DEFAULT_MS, now = Date.now()): Date {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > LEASE_FINITE_MAX_MS)
    throw new ORPCError("BAD_REQUEST", { message: "Invalid sandbox timeout." });
  return leaseDeadline(leaseRequestOf(timeoutMs), now);
}

export function acceptedLeaseFields(input: {
  now: Date;
  timeoutMs: number;
  revision: number;
  expiresAt: Date;
  action: SandboxLeaseExpireAction;
}) {
  return {
    leaseAcceptedAt: input.now,
    leaseTimeoutMs: input.timeoutMs,
    leaseRevisionAccepted: input.revision,
    leaseExpiresAtAccepted: input.expiresAt,
    leaseExpireActionAccepted: input.action,
  };
}

export type LeaseClock = () => Date;
export const leaseNow: LeaseClock = () => new Date();

/** Sample once after H/S, including after lock waits. The injected clock is
 * an internal test seam; production acceptance/ACK time comes from PostgreSQL. */
export function leaseTransactionNow(
  tx: Prisma.TransactionClient,
  clock: LeaseClock,
): Promise<Date> {
  return clock === leaseNow ? hostDatabaseNow(tx) : Promise.resolve(clock());
}

export {
  inventoryObservationIdempotencyKey,
  leaseExpiryIdempotencyKey,
} from "./idempotency-key-reserved";

export function leaseExpiryRequestHash(input: {
  sandboxId: string;
  action: "expire-stop" | "expire-destroy";
  generation: number;
  leaseRevision: number;
}): string {
  return hashLegacyEnvFreeBody(input);
}

export function leaseExpiryDispatchAction(
  action: SandboxLeaseExpireAction,
): "expire-stop" | "expire-destroy" {
  return action === "DESTROY" ? "expire-destroy" : "expire-stop";
}

export function isLeaseDeadlinePassed(leaseExpiresAt: Date | null | undefined, now: Date): boolean {
  return leaseExpiresAt != null && leaseExpiresAt.getTime() <= now.getTime();
}

export function initialLeaseFields(input: {
  timeoutMs?: number;
  onExpire?: SandboxLeaseExpireActionInput;
  now?: number;
}): {
  leaseRevision: number;
  leaseExpiresAt: Date;
  leaseExpireAction: SandboxLeaseExpireAction;
  leaseExpiresAtRequested: Date;
  leaseExpireActionRequested: SandboxLeaseExpireAction;
  leaseRevisionEffective: null;
  leaseExpiresAtEffective: null;
  leaseExpireActionEffective: null;
} {
  const leaseExpiresAt = resolveLeaseTimeout(input.timeoutMs, input.now);
  const leaseExpireAction = parseLeaseExpireAction(input.onExpire);
  return {
    leaseRevision: 1,
    leaseExpiresAt,
    leaseExpireAction,
    leaseExpiresAtRequested: leaseExpiresAt,
    leaseExpireActionRequested: leaseExpireAction,
    leaseRevisionEffective: null,
    leaseExpiresAtEffective: null,
    leaseExpireActionEffective: null,
  };
}

export type SandboxLeaseRow = {
  id: string;
  userId: string;
  sandboxHostId: string | null;
  templateRevisionId?: string;
  generation: number;
  state: SandboxState;
  leaseRevision: number;
  leaseExpiresAt: Date | null;
  leaseExpireAction: SandboxLeaseExpireAction;
  leaseExpiresAtEffective?: Date | null;
  accessGraceUntil?: Date | null;
  liveResourcesHeld?: boolean;
  /** When the caller's row carries it, `systemTeardownKind` asserts it
   * equals the value it re-reads under S (U6/T11). */
  diskOffloadId?: string | null;
};

/** The failed restore attempt a `SYSTEM_DETACH` kill ends (U5.4): the
 * launch's own operation and placement generation, never the kill's. */
export type TeardownAttempt = { attemptOperationId: string; attemptGeneration: number };

/**
 * The kind and intent of a system
 * teardown. Re-reads `diskOffloadId` under the S lock the caller holds and
 * never trusts the caller's row (a `SandboxLeaseRow`, the reaper's raw SQL
 * row or `sharing-access`'s synthetic row); when that row carries the
 * column, the two must agree. A sandbox whose disk is offloaded is only ever
 * detached by the system: a forced KILL with `SYSTEM_DETACH`, whose success
 * maps to OFFLOADED (I17). Every other system teardown keeps its kind and
 * carries no intent.
 */
export async function systemTeardownKind(
  tx: Prisma.TransactionClient,
  sandbox: { id: string; userId: string; diskOffloadId?: string | null },
  kind: "STOP_SANDBOX" | "KILL_SANDBOX",
): Promise<{ kind: "STOP_SANDBOX" | "KILL_SANDBOX"; intent: SandboxTeardownIntent | null }> {
  const row = await tx.sandbox.findFirst({
    where: { id: sandbox.id, userId: sandbox.userId },
    select: { diskOffloadId: true },
  });
  requireRelayFence(row != null);
  if (sandbox.diskOffloadId !== undefined)
    requireRelayFence(sandbox.diskOffloadId === row.diskOffloadId);
  return row.diskOffloadId
    ? { kind: "KILL_SANDBOX", intent: "SYSTEM_DETACH" }
    : { kind, intent: null };
}

/**
 * Committed renewal: bumps lease revision, sets the requested deadline (which may shorten), and records
 * a queued host operation. Only a matching durable host ACK changes the effective lease.
 */
export async function commitSandboxLeaseRenewal(
  tx: Prisma.TransactionClient,
  input: {
    ownerId: string;
    /** The caller's accept attribution; the lease-policy pull-in passes the
     * system attribution (a renewal that can only shorten). */
    attribution: AuthorizingPrincipal;
    sandbox: SandboxLeaseRow;
    leaseExpiresAt: Date;
    onExpire: SandboxLeaseExpireAction;
    idempotencyKey: string;
    bodyHash: string;
    now: Date;
    timeoutMs: number;
    /** The system pull-in runs outside an operation admission and records an
     * env-free snapshot; every other caller uses its admission's context. */
    digestContext?: DigestContextSnapshot;
  },
): Promise<{ leaseRevision: number }> {
  if (input.sandbox.leaseRevision >= 2_147_483_647)
    throw sandboxStateConflict("Lease revision exhausted.");
  // The host enforces its acknowledged deadline without the server, so a lease
  // effective on the host and already past cannot be revived by a renewal.
  if (isLeaseDeadlinePassed(input.sandbox.leaseExpiresAtEffective, input.now))
    throw sandboxStateConflict("Sandbox lease already expired on the host.");
  const nextRevision = input.sandbox.leaseRevision + 1;
  const written = await tx.sandbox.updateMany({
    where: {
      id: input.sandbox.id,
      userId: input.ownerId,
      generation: input.sandbox.generation,
      state: { in: [...LEASE_RENEWABLE_STATES] },
      leaseRevision: input.sandbox.leaseRevision,
    },
    data: {
      leaseRevision: nextRevision,
      leaseExpiresAt: input.leaseExpiresAt,
      leaseExpireAction: input.onExpire,
      leaseExpiresAtRequested: input.leaseExpiresAt,
      leaseExpireActionRequested: input.onExpire,
    },
  });
  if (written.count !== 1) {
    throw sandboxStateConflict();
  }
  const operation = await tx.sandboxOperation.create({
    data: {
      authorizingKeyId: recordedKeyIdOf(input.attribution),
      userId: input.ownerId,
      sandboxId: input.sandbox.id,
      ...acceptedLeaseFields({
        now: input.now,
        timeoutMs: input.timeoutMs,
        revision: nextRevision,
        expiresAt: input.leaseExpiresAt,
        action: input.onExpire,
      }),
      kind: "RENEW_SANDBOX_LEASE",
      state: "QUEUED",
      generation: input.sandbox.generation,
      idempotencyKey: input.idempotencyKey,
      requestBodyHash: input.bodyHash,
      digestContext: input.digestContext ?? operationDigestContext(tx),
      ...requestDigestMetadata(),
    },
  });
  await createSandboxOutboxEvent(tx, {
    authorizingPrincipal: input.attribution,
    userId: input.ownerId,
    aggregateId: input.sandbox.id,
    eventType: "sandbox.lease_renew_requested",
    payload: {
      sandboxId: input.sandbox.id,
      sandboxHostId: input.sandbox.sandboxHostId,
      generation: input.sandbox.generation,
      dispatchAttempt: 0,
      operationId: operation.id,
      idempotencyKey: input.idempotencyKey,
      kind: OPERATION_DISPATCH_KIND.RENEW_SANDBOX_LEASE,
    },
  });
  return { leaseRevision: nextRevision };
}

/**
 * Readiness reasons that are their own public error code (option (a)): the
 * caller asked for, or refused, guest root, so `guest_unavailable` would
 * mislead. Mapped only after cleanup is classified (which keys on the
 * readiness failure itself, never on the code), so a create is still
 * destroyed and a reconnect still stopped with its disk kept.
 */
const READINESS_PUBLIC_CODES: Partial<Record<ReadinessFailureReason, string>> = {
  guest_sudo_unavailable: "guest_sudo_unavailable",
  guest_root_granted: "guest_root_granted",
};

/** Own H and S before calling; both rows and time must be sampled under S.
 * Supersession cannot revoke an already-issued host effect. Only a create with
 * no unresolved dispatch history proves no guest was launched. An undispatched
 * cold reconnect with no unresolved predecessor leaves its stopped disk alone.
 * Queued timeout, dispatch retry, results and reconciliation share this exit. */
export async function finalizeExpiredSandboxLifecycleOperation(
  tx: Prisma.TransactionClient,
  sandbox: SandboxLeaseRow,
  operation: Pick<
    SandboxOperation,
    | "id"
    | "userId"
    | "sandboxId"
    | "kind"
    | "state"
    | "generation"
    | "dispatchAttempt"
    | "dispatchedHostId"
    | "dispatchedConnectionEpoch"
    | "launchMode"
    | "restoreOffloadId"
  >,
  now: Date,
  guestConfirmed = false,
  /** `true`, or the failed check the daemon reported, for a readiness failure. */
  readinessFailure: boolean | ReadinessFailureReason = false,
  provisioningFailureCode?: string,
): Promise<boolean> {
  const failedProvisioning = readinessFailure !== false || provisioningFailureCode !== undefined;
  if (
    (operation.kind !== "CREATE_SANDBOX" && operation.kind !== "RECONNECT_SANDBOX") ||
    operation.generation !== sandbox.generation ||
    (!ACTIVE_OPERATION_STATES.has(operation.state) && operation.state !== "UNKNOWN_OUTCOME") ||
    (!failedProvisioning && !isLeaseDeadlinePassed(sandbox.leaseExpiresAt, now))
  )
    return false;
  requireRelayFence(operation.userId === sandbox.userId && operation.sandboxId === sandbox.id);
  // a restore attempt that ends without READY leaves
  // only through `exitRestoreAttempt` (its stored copy stays authoritative).
  const restore = isRestoreAttempt(operation) && operation.restoreOffloadId !== null;
  const errorCode =
    restore && readinessFailure !== false
      ? // §7 "Restore retries": a root guest can break its own boot chain.
        "restore_boot_failed"
      : (provisioningFailureCode ??
        (readinessFailure
          ? (readinessFailure !== true && READINESS_PUBLIC_CODES[readinessFailure]) ||
            "guest_unavailable"
          : "lease_expired"));
  const networkFailure = provisioningFailureCode === "guest_network_unavailable";
  const startupFailure =
    networkFailure ||
    provisioningFailureCode === "startup_failed" ||
    provisioningFailureCode === "startup_timeout";
  const errorDetail = networkFailure
    ? "Sandbox booted without an IPv4 network address (no DHCP lease); cleanup queued. The host firewall may drop sandbox bridge traffic: run `wssp guard status` on the host."
    : startupFailure
      ? "Sandbox template start command did not become ready; cleanup queued."
      : provisioningFailureCode === "unknown_outcome"
        ? "The node daemon could not confirm the create's outcome (it restarted or lost its connection mid-create); cleanup queued."
        : provisioningFailureCode
          ? "Sandbox provisioning outcome unconfirmed; cleanup queued."
          : readinessFailure
            ? readinessFailureDetail(readinessFailure)
            : "Sandbox lease expired before provisioning could complete.";
  // M4: a restore placement never dispatched is reverted server-side, like
  // a never-dispatched create (nothing was ever sent to its target).
  const neverDispatchedAllocation =
    (operation.kind === "CREATE_SANDBOX" || sandbox.state === "STOPPED" || restore) &&
    operation.state === "QUEUED" &&
    operation.dispatchAttempt === 0 &&
    operation.dispatchedHostId === null &&
    operation.dispatchedConnectionEpoch === null &&
    !guestConfirmed;
  const possiblyLiveGuest =
    !neverDispatchedAllocation ||
    (await hasPossiblyLiveSandboxAttempt(tx, sandbox.userId, sandbox.id, operation.id));

  const recorded = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: sandbox.userId,
      generation: sandbox.generation,
      state: sandbox.state,
      leaseRevision: sandbox.leaseRevision,
    },
    data: {
      ...(!possiblyLiveGuest && operation.kind === "CREATE_SANDBOX" ? { state: "ERROR" } : {}),
      ...(guestConfirmed ? { incusName: defaultIncusInstanceName(sandbox.id) } : {}),
      lastErrorCode: errorCode,
      lastErrorDetail: errorDetail,
    },
  });
  requireRelayFence(recorded.count === 1);
  // The failed readiness check, structured (the `/v1` `readinessReason`).
  const readinessRecord =
    errorCode === "guest_unavailable" && typeof readinessFailure === "string"
      ? { failure: readinessFailureRecord(readinessFailure) }
      : {};
  const finished = await tx.sandboxOperation.updateMany({
    where: {
      id: operation.id,
      userId: operation.userId,
      sandboxId: operation.sandboxId,
      kind: operation.kind,
      generation: operation.generation,
      state: operation.state,
      dispatchAttempt: operation.dispatchAttempt,
      dispatchedHostId: operation.dispatchedHostId,
      dispatchedConnectionEpoch: operation.dispatchedConnectionEpoch,
    },
    data: {
      state: "FAILED",
      completedAt: now,
      errorCode,
      errorDetail,
      result: {},
      ...readinessRecord,
    },
  });
  requireRelayFence(finished.count === 1);
  // CLI logins (§7.1): the launch ended without READY — settle the leases it
  // launched and drop its stored spec (UNKNOWN create, expiry, readiness).
  await settleOperationCredentials(tx, {
    sandboxId: sandbox.id,
    operation,
    opState: "FAILED",
  });
  noteHostBlockerReleased(tx, operation.dispatchedHostId, sandbox.userId);
  noteHostBlockerReleased(tx, sandbox.sandboxHostId, sandbox.userId);
  if (restore) {
    // §8.7: never dispatched (no-effect proof) → OFFLOADED at once;
    // otherwise the SYSTEM_DETACH kill, whose proof detaches it.
    requireRelayFence(
      await exitRestoreAttempt(tx, {
        sandboxId: sandbox.id,
        userId: sandbox.userId,
        attemptOperationId: operation.id,
        attemptGeneration: operation.generation,
        proof: possiblyLiveGuest
          ? { kind: "none" }
          : { kind: "no_effect", reason: "never_dispatched" },
        now,
      }),
    );
  } else if (possiblyLiveGuest) {
    // A reconnect whose start/ready failed keeps its disk: stop, never destroy.
    // So does a cold start whose READY evidence the server could not apply
    // (protocol_error, the WP0 receipt verdict): it may be running, so the
    // queued stop is what proves its state and releases its hold.
    const readiness =
      (startupFailure || provisioningFailureCode === "protocol_error") &&
      operation.kind === "RECONNECT_SANDBOX"
        ? "stop"
        : failedProvisioning;
    requireRelayFence(await commitLockedSandboxLeaseExpiry(tx, sandbox, now, readiness));
  } else {
    await releaseLiveResourcesIfHeld(tx, {
      hostId: sandbox.sandboxHostId,
      ownerId: sandbox.userId,
      sandboxId: sandbox.id,
      operationId: operation.id,
      kind: operation.kind,
      opState: "FAILED",
      sandboxStateBeforeResult: sandbox.state,
      neverIssued: operation.dispatchAttempt === 0,
    });
  }
  // Expiry retirement already locked every predecessor O before outbox. This
  // settlement revisits only that locked subset; it acquires no new O locks.
  const advanced = possiblyLiveGuest || restore ? 1 : 0;
  // credential-settlement: exempt — settles operation rows only; the generation
  // writer is commitLockedSandboxLeaseExpiry (settleCredentialTeardown).
  await settleSupersededOperations(
    tx,
    { ...operation, generation: sandbox.generation + advanced, state: "FAILED" },
    now,
  );
  await tx.outboxEvent.updateMany({
    where: {
      userId: sandbox.userId,
      aggregateType: "sandbox",
      aggregateId: sandbox.id,
      processedAt: null,
      ...outboxOperationWhere(operation.id),
    },
    data: { processedAt: now, claimToken: null, claimedAt: null },
  });
  return true;
}

/** Own H and S before calling. The row must be read under S. Used for READY
 * reclaim and possibly-live provisioning expiry, without publishing READY. */
export async function commitLockedSandboxLeaseExpiry(
  tx: Prisma.TransactionClient,
  sandbox: SandboxLeaseRow,
  now: Date,
  /** `true` destroys the failed guest; `"stop"` only stops it (B9 reconnect). */
  readinessFailure: boolean | "stop" = false,
  reason: "lease" | "access" = "lease",
  /** §8.7: the failed restore attempt a SYSTEM_DETACH kill ends. */
  attempt?: TeardownAttempt,
): Promise<boolean> {
  const access = reason === "access";
  const accessDestroy =
    access && sandbox.accessGraceUntil != null && sandbox.accessGraceUntil <= now;
  if (access) {
    if (!sandbox.sandboxHostId) return false;
    if (
      accessDestroy
        ? !KILLABLE_SANDBOX_STATES.has(sandbox.state)
        : !(
            STOPPABLE_SANDBOX_STATES.has(sandbox.state) ||
            sandbox.state === "UNREACHABLE" ||
            (sandbox.state === "ERROR" && sandbox.liveResourcesHeld)
          )
    )
      return false;
  } else {
    if (!["READY", "REQUESTED", "SCHEDULED", "PROVISIONING", "STOPPED"].includes(sandbox.state))
      return false;
    if (!readinessFailure && !isLeaseDeadlinePassed(sandbox.leaseExpiresAt, now)) return false;
  }
  const nextGeneration = sandbox.generation + 1;
  const dispatchAction = access
    ? accessDestroy
      ? "access-destroy"
      : "access-stop"
    : readinessFailure
      ? "readiness-failed"
      : leaseExpiryDispatchAction(sandbox.leaseExpireAction);
  const isDestroy = access
    ? accessDestroy
    : readinessFailure === true || (!readinessFailure && sandbox.leaseExpireAction === "DESTROY");
  // U6: before the dedupe, a sandbox whose disk is offloaded gets the
  // forced SYSTEM_DETACH kill (never a stop, never an owner destroy).
  const { kind, intent } = await systemTeardownKind(
    tx,
    sandbox,
    isDestroy ? "KILL_SANDBOX" : "STOP_SANDBOX",
  );

  const requestBodyHash = hashLegacyEnvFreeBody({
    sandboxId: sandbox.id,
    action: dispatchAction,
    generation: nextGeneration,
    leaseRevision: sandbox.leaseRevision,
    ...(access ? { reason, deadline: sandbox.accessGraceUntil?.toISOString() ?? null } : {}),
  });
  const idempotencyKey = access
    ? accessExpiryIdempotencyKey(
        sandbox.id,
        nextGeneration,
        isDestroy ? "DESTROY" : "STOP",
        sandbox.accessGraceUntil ?? null,
      )
    : readinessFailure
      ? readinessFailureIdempotencyKey(sandbox.id, nextGeneration)
      : leaseExpiryIdempotencyKey(
          sandbox.id,
          nextGeneration,
          sandbox.leaseRevision,
          sandbox.leaseExpireAction,
        );
  // Hash binds revision AND action; key existence alone is never evidence of expiry.
  const existing = await tx.sandboxOperation.findFirst({
    where: {
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      kind,
      generation: nextGeneration,
      requestBodyHash,
      ...requestDigestMetadata(kind),
      idempotencyKey,
    },
    select: { id: true },
  });
  if (existing != null) return false;

  const written = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: sandbox.userId,
      state: sandbox.state,
      generation: sandbox.generation,
      leaseRevision: sandbox.leaseRevision,
      ...(access
        ? {
            accessGraceUntil: sandbox.accessGraceUntil ?? null,
            ...(accessDestroy ? { AND: [{ accessGraceUntil: { lte: now } }] } : {}),
          }
        : !readinessFailure
          ? { leaseExpiresAt: { lte: now } }
          : {}),
    },
    data: { state: "STOPPING", generation: nextGeneration },
  });
  if (written.count !== 1) return false;
  await queueSystemTeardown(tx, sandbox, {
    kind,
    generation: nextGeneration,
    idempotencyKey,
    requestBodyHash,
    now,
    intent,
    attempt: intent === "SYSTEM_DETACH" ? attempt : undefined,
  });
  return true;
}

/**
 * The exported wrapper `exitRestoreAttempt` queues
 * its SYSTEM_DETACH kill through. The row moves to STOPPING and the kill
 * carries the failed attempt's operation id and generation; its SUCCEEDED
 * result re-enters the restore exit with the kill's root proof. Own H and S;
 * the row must be read under S.
 */
export async function queueSystemDetachKill(
  tx: Prisma.TransactionClient,
  sandbox: SandboxLeaseRow,
  now: Date,
  attempt: TeardownAttempt | undefined,
): Promise<boolean> {
  return commitLockedSandboxLeaseExpiry(tx, sandbox, now, true, "lease", attempt);
}

/** Stop/kill verdict resolver: system retries one failed teardown chain may
 * queue. Each is a fresh teardown at the next generation; only its proof
 * (stopped/absent/deleted) releases the hold. After the bound the sandbox
 * stays ERROR with its hold, for the reconnect census or a user kill. */
export const TEARDOWN_RETRY_MAX = 2;

/**
 * A stop/kill that FAILED (the host's own failure, or the server's verdict on
 * a receipt it could not apply) leaves the sandbox ERROR still holding its
 * live resources: the VM may be running, and neither lease reclaim (which
 * excludes ERROR) nor a connected session would ever resolve it. Queue the
 * same teardown again as a system operation, at most TEARDOWN_RETRY_MAX
 * times per chain (a user's new stop/kill starts a new chain), and never for
 * a sandbox with an unfinished login lease (its recovery is the owner's).
 * Call in the
 * failed result's transaction, after the sandbox row was moved to ERROR and
 * with H, S and the failed O already locked.
 */
export async function queueFailedTeardownRetry(
  tx: Prisma.TransactionClient,
  input: {
    sandboxId: string;
    userId: string;
    generation: number;
    failed: { kind: "STOP_SANDBOX" | "KILL_SANDBOX"; idempotencyKey: string };
  },
  now: Date,
): Promise<boolean> {
  // M1: a retry copies the failed teardown's intent and attempt fields.
  const failed = await tx.sandboxOperation.findFirst({
    where: {
      userId: input.userId,
      sandboxId: input.sandboxId,
      idempotencyKey: input.failed.idempotencyKey,
    },
    select: { teardownIntent: true, attemptOperationId: true, attemptGeneration: true },
  });
  const retry = teardownRetryIndex(input.failed.idempotencyKey) + 1;
  if (retry > TEARDOWN_RETRY_MAX) {
    // U10: a wedged SYSTEM_DETACH cleanup stays ERROR(restore_cleanup_pending)
    // with its hold, for the owner's Retry cleanup or destroy.
    if (failed?.teardownIntent === "SYSTEM_DETACH")
      await tx.sandbox.updateMany({
        where: {
          id: input.sandboxId,
          userId: input.userId,
          state: "ERROR",
          generation: input.generation,
        },
        data: {
          lastErrorCode: RESTORE_CLEANUP_PENDING,
          lastErrorDetail:
            "The host could not clean up a failed restore; retry the cleanup or destroy the sandbox.",
        },
      });
    return false;
  }
  const sandbox = await tx.sandbox.findFirst({
    where: { id: input.sandboxId, userId: input.userId },
  });
  if (
    sandbox == null ||
    sandbox.state !== "ERROR" ||
    !sandbox.liveResourcesHeld ||
    sandbox.generation !== input.generation ||
    sandbox.sandboxHostId == null ||
    (await hasOpenCredentialLeases(tx, sandbox.id))
  )
    return false;
  const { kind, intent } = await systemTeardownKind(tx, sandbox, input.failed.kind);
  const nextGeneration = sandbox.generation + 1;
  const idempotencyKey = teardownRetryIdempotencyKey(sandbox.id, nextGeneration, retry);
  const requestBodyHash = hashLegacyEnvFreeBody({
    sandboxId: sandbox.id,
    action: "teardown-retry",
    kind,
    generation: nextGeneration,
    retry,
  });
  const written = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: sandbox.userId,
      state: "ERROR",
      generation: sandbox.generation,
      liveResourcesHeld: true,
    },
    data: { state: "STOPPING", generation: nextGeneration },
  });
  if (written.count !== 1) return false;
  await queueSystemTeardown(tx, sandbox, {
    kind,
    generation: nextGeneration,
    idempotencyKey,
    requestBodyHash,
    now,
    intent,
    attempt: retainedAttempt(intent, failed),
  });
  return true;
}

/** `lastErrorCode` of a SYSTEM_DETACH cleanup past its retries (U10). */
export const RESTORE_CLEANUP_PENDING = "restore_cleanup_pending";

function retainedAttempt(
  intent: SandboxTeardownIntent | null,
  failed: { attemptOperationId: string | null; attemptGeneration: number | null } | null,
): TeardownAttempt | undefined {
  return intent === "SYSTEM_DETACH" &&
    failed?.attemptOperationId != null &&
    failed.attemptGeneration != null
    ? {
        attemptOperationId: failed.attemptOperationId,
        attemptGeneration: failed.attemptGeneration,
      }
    : undefined;
}

/**
 * Retry cleanup: the owner re-queues the
 * SYSTEM_DETACH kill of a sandbox left `ERROR(restore_cleanup_pending)`,
 * with the same attempt fields, as a fresh retry chain. Own H and S.
 * Returns false (nothing queued) when the sandbox is not in that state.
 */
export async function requeueRestoreCleanup(
  tx: Prisma.TransactionClient,
  input: { sandboxId: string; userId: string },
  now: Date,
): Promise<boolean> {
  const sandbox = await tx.sandbox.findFirst({
    where: { id: input.sandboxId, userId: input.userId },
  });
  if (
    sandbox == null ||
    sandbox.state !== "ERROR" ||
    sandbox.lastErrorCode !== RESTORE_CLEANUP_PENDING ||
    sandbox.diskOffloadId == null ||
    sandbox.sandboxHostId == null ||
    sandbox.generation >= 2_147_483_647
  )
    return false;
  const failed = await tx.sandboxOperation.findFirst({
    where: {
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      kind: "KILL_SANDBOX",
      teardownIntent: "SYSTEM_DETACH",
    },
    orderBy: { generation: "desc" },
    select: { attemptOperationId: true, attemptGeneration: true },
  });
  const { kind, intent } = await systemTeardownKind(tx, sandbox, "KILL_SANDBOX");
  const nextGeneration = sandbox.generation + 1;
  // Retry index 0: a new chain with its own TEARDOWN_RETRY_MAX retries.
  const idempotencyKey = teardownRetryIdempotencyKey(sandbox.id, nextGeneration, 0);
  const requestBodyHash = hashLegacyEnvFreeBody({
    sandboxId: sandbox.id,
    action: "cleanup-retry",
    kind,
    generation: nextGeneration,
  });
  const written = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: sandbox.userId,
      state: "ERROR",
      generation: sandbox.generation,
      lastErrorCode: RESTORE_CLEANUP_PENDING,
    },
    data: { state: "STOPPING", generation: nextGeneration },
  });
  if (written.count !== 1) return false;
  await queueSystemTeardown(tx, sandbox, {
    kind,
    generation: nextGeneration,
    idempotencyKey,
    requestBodyHash,
    now,
    intent,
    attempt: retainedAttempt(intent, failed),
  });
  return true;
}

/** The system teardown row, supersession, login settlement and dispatch
 * event for a sandbox already moved to STOPPING at `generation`. */
async function queueSystemTeardown(
  tx: Prisma.TransactionClient,
  sandbox: Pick<SandboxLeaseRow, "id" | "userId" | "state" | "sandboxHostId">,
  input: {
    kind: "STOP_SANDBOX" | "KILL_SANDBOX";
    generation: number;
    idempotencyKey: string;
    requestBodyHash: string;
    now: Date;
    /** From `systemTeardownKind` (S2): SYSTEM_DETACH iff `diskOffloadId` is set. */
    intent: SandboxTeardownIntent | null;
    attempt?: TeardownAttempt;
  },
): Promise<void> {
  const { kind, idempotencyKey, now } = input;
  requireRelayFence(input.intent === null || kind === "KILL_SANDBOX");
  const nextGeneration = input.generation;
  const eventType = kind === "KILL_SANDBOX" ? "sandbox.kill_requested" : "sandbox.stop_requested";
  const dispatchKind =
    kind === "KILL_SANDBOX"
      ? OPERATION_DISPATCH_KIND.KILL_SANDBOX
      : OPERATION_DISPATCH_KIND.STOP_SANDBOX;
  const operation = await tx.sandboxOperation.create({
    data: {
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      kind,
      state: "QUEUED",
      generation: nextGeneration,
      teardownPriorState: sandbox.state,
      idempotencyKey,
      requestBodyHash: input.requestBodyHash,
      digestContext: digestContextSnapshot(
        { domain: ENV_FREE_DIGEST_DOMAIN },
        { generation: nextGeneration },
      ),
      ...requestDigestMetadata(kind),
      ...(input.intent ? { teardownIntent: input.intent } : {}),
      ...(input.attempt ?? {}),
    },
  });

  await retireSupersededOperations(tx, sandbox.userId, sandbox.id, nextGeneration, now);
  // "Destroy during upload": a kill preempts the daemon's
  // upload; a live, not-yet-STORED offload ends SUPERSEDED here (session
  // aborted, keys shredded; the disk sweeper reclaims any object).
  if (kind === "KILL_SANDBOX") await supersedeLiveOffload(tx, sandbox.id);
  // CLI logins (§7.5, §10.3): the system expiry / access / readiness / retry writer
  // settles login leases like a user stop or kill; it never fails on capture.
  await settleCredentialTeardown(tx, {
    sandboxId: sandbox.id,
    priorState: sandbox.state,
    generation: nextGeneration,
    teardownOperationId: operation.id,
  });

  const template = await pinnedLaunchSource(tx, sandbox.id, sandbox.userId, false);
  await tx.outboxEvent.create({
    data: {
      userId: sandbox.userId,
      aggregateType: "sandbox",
      aggregateId: sandbox.id,
      eventType,
      operationId: operation.id,
      payload: {
        sandboxId: sandbox.id,
        sandboxHostId: sandbox.sandboxHostId,
        generation: nextGeneration,
        dispatchAttempt: 0,
        operationId: operation.id,
        idempotencyKey,
        kind: dispatchKind,
        incusName: defaultIncusInstanceName(sandbox.id),
        ...(template
          ? { ...templateDispatchPayload(template), ...pinnedAllocationPayload(template) }
          : {}),
        authorizingPrincipal: systemAttribution(),
        // CLI logins (§10.3): expiry, access, readiness and retry teardowns
        // never fail on a capture failure; the host stops/destroys regardless.
        credentialTeardown: "system",
      },
    },
  });
}

/** Owner admission → H → S before any cleanup INSERT; then re-read the lease and clock. A
 * stale scanner cannot expire a renewed revision, even if generation is equal. */
export async function tryCommitSandboxLeaseExpiry(
  tx: Prisma.TransactionClient,
  candidate: SandboxLeaseRow,
  clock: LeaseClock = leaseNow,
  reason: "lease" | "access" = "lease",
): Promise<boolean> {
  if (reason === "access") return reconcileSandboxAccess(tx, candidate.id, clock);
  await lockOwnerForAdmission(tx, candidate.userId);
  if (candidate.sandboxHostId) {
    await lockHostForSandboxOperation(tx, candidate.sandboxHostId, candidate.userId, candidate.id);
  }
  await casSandboxGeneration(tx, {
    sandboxId: candidate.id,
    userId: candidate.userId,
    generation: candidate.generation,
    states: ["READY", "REQUESTED", "SCHEDULED", "PROVISIONING", "STOPPED"],
    hostId: candidate.sandboxHostId ?? undefined,
  });
  const sandbox = await tx.sandbox.findFirst({
    where: { id: candidate.id, userId: candidate.userId },
  });
  requireRelayFence(sandbox != null);
  requireRelayFence(sandbox.sandboxHostId === candidate.sandboxHostId);
  if (sandbox.leaseRevision !== candidate.leaseRevision) return false;
  const now = await leaseTransactionNow(tx, clock);
  const provisioning = await tx.sandboxOperation.findFirst({
    where: {
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      generation: sandbox.generation,
      kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },
      state: { in: [...ACTIVE_OPERATION_STATES, "UNKNOWN_OUTCOME"] },
    },
    orderBy: { id: "asc" },
  });
  // Sent provisioning waits for host result/reconciliation, as before. Only
  // an unsent pending event needs the work deferred by the dispatch guard.
  const pending =
    provisioning &&
    (await tx.outboxEvent.findFirst({
      where: {
        userId: sandbox.userId,
        aggregateType: "sandbox",
        aggregateId: sandbox.id,
        processedAt: null,
        sentAt: null,
        ...outboxOperationWhere(provisioning.id),
      },
      select: { id: true },
    }));
  if (
    provisioning &&
    pending &&
    (await finalizeExpiredSandboxLifecycleOperation(tx, sandbox, provisioning, now))
  ) {
    // Count queued cleanup, rather than a proven unsent allocation's release.
    return (
      (await tx.sandbox.findFirst({
        where: {
          id: sandbox.id,
          userId: sandbox.userId,
          // credential-settlement: exempt — a read of the expiry this transaction queued.
          generation: sandbox.generation + 1,
          state: "STOPPING",
        },
        select: { id: true },
      })) !== null
    );
  }
  return sandbox.state === "READY" && (await commitLockedSandboxLeaseExpiry(tx, sandbox, now));
}

export async function reclaimExpiredSandboxLeases(
  clock: LeaseClock = leaseNow,
  batchSize = 32,
  shouldStop: () => boolean = () => false,
  reason: "lease" | "access" = "lease",
): Promise<number> {
  if (reason === "access") return scanSandboxAccess(clock, shouldStop);
  let queued = 0;
  let cursor: string | undefined;
  const scanDeadline = clock();
  // A stable ID keyset advances even over skipped/offline/stale candidates.
  // Each query is bounded; a skipped first page cannot starve another owner.
  while (!shouldStop()) {
    // Filter before LIMIT: historical stopped/failed allocations cannot expire
    // again. Match the same first current-generation provisioning operation and
    // unsent pending event that tryCommitSandboxLeaseExpiry rechecks under S.
    const expired = await prisma.$queryRaw<SandboxLeaseRow[]>`
      SELECT s.id, s."userId", s."sandboxHostId", s."templateRevisionId", s.generation,
             s.state, s."leaseRevision", s."leaseExpiresAt", s."leaseExpireAction"
      FROM sandbox_instance s
      WHERE s."leaseExpiresAt" <= ${scanDeadline}
        AND (${cursor ?? null}::text IS NULL OR s.id > ${cursor ?? null})
        AND (
          s.state = 'READY'
          OR (
            s.state IN ('REQUESTED', 'SCHEDULED', 'PROVISIONING', 'STOPPED')
            AND EXISTS (
              SELECT 1 FROM (
                  SELECT o.id FROM sandbox_mutation_operation o
                  WHERE o."userId" = s."userId" AND o."sandboxId" = s.id
                    AND o.generation = s.generation
                    AND o.kind IN ('CREATE_SANDBOX', 'RECONNECT_SANDBOX')
                    AND o.state::text = ANY(${[...ACTIVE_OPERATION_STATES, "UNKNOWN_OUTCOME"]}::text[])
                  ORDER BY o.id ASC LIMIT 1
                ) lead
              JOIN sandbox_dispatch_outbox e
                ON e."userId" = s."userId"
                AND e."aggregateType" = 'sandbox' AND e."aggregateId" = s.id
                AND e."processedAt" IS NULL AND e."sentAt" IS NULL
                AND (e."operationId" = lead.id
                  OR (e."operationId" IS NULL AND e.payload ->> 'operationId' = lead.id))
            )
          )
        )
      ORDER BY s.id ASC LIMIT ${batchSize}
    `;
    for (const sandbox of expired) {
      if (shouldStop()) return queued;
      try {
        const claimed = await relayTransaction(
          (tx) => tryCommitSandboxLeaseExpiry(tx, sandbox, clock),
          false,
        );
        if (claimed) queued += 1;
      } catch (error) {
        // Already logged at the invariant: rollback preserves the evidence.
        // Advance past this item so corrupt accounting cannot starve owners.
        if (!(error instanceof SandboxIntegrityError)) throw error;
      }
    }
    if (expired.length < batchSize) break;
    cursor = expired[expired.length - 1]!.id;
  }
  return queued;
}
