import type { Prisma } from "@wssp/db";
import { credentialError } from "./errors";

/**
 * Lease transition helpers shared by the relay fences . Every terminal transition decrements the instance's `activeLeases`
 * in the same transaction, closes the lease's open bindings and makes the
 * residue of those bindings non-recoverable (it is scrubbed, never
 * recaptured). Callers already hold S for a lease with a sandbox, so the
 * lease → instance decrement order cannot cycle (§7.3 P3-6).
 */

type Tx = Prisma.TransactionClient;

const TERMINAL_LEASE_STATES = ["RELEASED", "FORCE_RELEASED", "ABANDONED"] as const;
export type TerminalLeaseState = (typeof TERMINAL_LEASE_STATES)[number];

export function isTerminalLeaseState(state: string): state is TerminalLeaseState {
  return (TERMINAL_LEASE_STATES as readonly string[]).includes(state);
}

/** Closes every open binding of a lease and marks their residue non-recoverable. */
async function closeLeaseBindings(tx: Tx, leaseId: string, reason: string) {
  await tx.$executeRaw`UPDATE credential_residue SET recoverable = false
    WHERE "leaseId" = ${leaseId} AND "clearedAt" IS NULL AND recoverable`;
  await tx.$executeRaw`UPDATE credential_binding SET "closedAt" = (clock_timestamp() AT TIME ZONE 'UTC'),
      "closeReason" = ${reason}
    WHERE "leaseId" = ${leaseId} AND "closedAt" IS NULL`;
}

/**
 * Moves a non-terminal lease to a terminal state. Idempotent: a lease that is
 * already terminal is left alone and nothing is decremented twice. Returns
 * whether this call made the transition.
 */
export async function finishLease(
  tx: Tx,
  leaseId: string,
  state: TerminalLeaseState,
  reason: string,
): Promise<boolean> {
  const rows = await tx.$queryRaw<
    { instanceId: string; kind: string; loginSessionId: string | null }[]
  >`UPDATE credential_lease
    SET state = ${state}::"CredentialLeaseState", "endReason" = ${reason},
      "releasedAt" = (clock_timestamp() AT TIME ZONE 'UTC'), "teardownOperationId" = NULL,
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id = ${leaseId} AND state::text NOT IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED')
    RETURNING "instanceId", kind::text AS kind, "loginSessionId"`;
  const row = rows[0];
  if (!row) return false;
  await tx.$executeRaw`UPDATE credential_instance
    SET "activeLeases" = "activeLeases" - 1,
      "loginLeaseId" = CASE WHEN "loginLeaseId" = ${leaseId} THEN NULL ELSE "loginLeaseId" END,
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id = ${row.instanceId} AND "activeLeases" > 0`;
  await closeLeaseBindings(tx, leaseId, reason);
  if (row.kind === "LOGIN" && row.loginSessionId)
    await endLoginSession(tx, row.loginSessionId, reason === LOGIN_SAVED_REASON);
  return true;
}

/** The LOGIN lease's end reason when its login capture committed (§11 Save). */
export const LOGIN_SAVED_REASON = "login_saved";

/** Login session states that still hold (or are about to hold) a LOGIN lease. */
export const OPEN_LOGIN_SESSION_STATES = ["PROVISIONING", "READY", "SAVING", "FAILED"] as const;

/**
 * A LOGIN lease ended (§11): its session is SAVED when the login capture
 * committed — the value is durable whatever the session said before, even
 * after a cancel raced it — and otherwise EXPIRED unless the owner already
 * CANCELLED it. The instance's `loginLeaseId` was cleared by `finishLease`.
 */
async function endLoginSession(tx: Tx, sessionId: string, saved: boolean) {
  await tx.credentialLoginSession.updateMany({
    where: saved
      ? { id: sessionId, state: { not: "SAVED" } }
      : { id: sessionId, state: { in: [...OPEN_LOGIN_SESSION_STATES] } },
    data: { state: saved ? "SAVED" : "EXPIRED" },
  });
}

/**
 * Ends a sandbox's active attachment of a login (`detachedAt`): a free that
 * resolved (§10.1) or a free of a login with no live lease. Idempotent.
 */
export async function detachAttachment(tx: Tx, sandboxId: string, credentialId: string) {
  await tx.sandboxCredential.updateMany({
    where: { sandboxId, credentialId, detachedAt: null },
    data: { detachedAt: new Date() },
  });
}

/**
 * The ONLY writer of `RECOVERY_REQUIRED` (§7.1): the binding and its residue
 * stay recoverable, and the transition writes its `recovery_required`
 * credential_event in the same statement's transaction, which is what fires
 * the `credential.recovery_required` webhook (§12). No event is written when
 * the lease was not in a state that moves (the transition is idempotent).
 * `recovery-required-writers.test.ts` fails on any other writer.
 */
export async function requireLeaseRecovery(tx: Tx, leaseId: string, reason: string) {
  const moved = await tx.$queryRaw<
    {
      userId: string;
      credentialId: string;
      accountId: string;
      instanceId: string;
      sandboxId: string | null;
      hostId: string | null;
    }[]
  >`UPDATE credential_lease SET state = 'RECOVERY_REQUIRED', "endReason" = ${reason},
      "teardownOperationId" = NULL, "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id = ${leaseId} AND state::text IN ('ACTIVE', 'RELEASING', 'RECOVERING')
    RETURNING "userId", "credentialId", "accountId", "instanceId", "sandboxId", "hostId"`;
  const lease = moved[0];
  if (!lease) return false;
  await tx.credentialEvent.create({
    data: { ...lease, leaseId, type: "recovery_required", reason },
    select: { id: true },
  });
  return true;
}

/**
 * Template capture (§7.6): refused `credential.capture_in_progress` while any
 * lease of the sandbox is INSTALLING, RELEASING or RECOVERING — a login's
 * files are being written, captured or recovered, so the residue rows that
 * become the capture's scrub list are not settled yet. Runs under S.
 */
export async function requireNoCredentialWorkInFlight(tx: Tx, sandboxId: string) {
  const inFlight = await tx.credentialLease.count({
    where: { sandboxId, state: { in: ["INSTALLING", "RELEASING", "RECOVERING"] } },
  });
  if (inFlight > 0) throw credentialError("credential.capture_in_progress");
}

/** Locks S (the sandbox row) for a lease that has one. */
export async function lockLeaseSandbox(tx: Tx, sandboxId: string) {
  await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} FOR UPDATE`;
}

/** credential FOR SHARE → instance FOR UPDATE → lease FOR UPDATE (§7.3 capture/force-release). */
export async function lockLeaseChain(
  tx: Tx,
  lease: { id: string; credentialId: string; instanceId: string },
) {
  await tx.$queryRaw`SELECT id FROM credential WHERE id = ${lease.credentialId} FOR SHARE`;
  await tx.$queryRaw`SELECT id FROM credential_instance WHERE id = ${lease.instanceId} FOR UPDATE`;
  await tx.$queryRaw`SELECT id FROM credential_lease WHERE id = ${lease.id} FOR UPDATE`;
}

/**
 * The total credential → instance lock order (§7.3, N3) for a path that
 * decrements (or otherwise writes) several instances in one transaction:
 * every login FOR SHARE in sorted id order, then every instance FOR UPDATE
 * in (credentialId, instanceId) order — the order claims take (the claim
 * gate locks the sorted logins, then each claim one instance per login in
 * login order). Two transactions on different sandboxes sharing instances
 * then never wait on each other in a cycle, whatever their lease ids.
 * Call it before locking or finishing the leases themselves; a settling
 * transaction calls it through {@link lockSettlementScope}.
 */
export async function lockInstancesInClaimOrder(
  tx: Tx,
  rows: readonly { credentialId: string; instanceId: string }[],
) {
  const byKey = new Map(rows.map((row) => [`${row.credentialId}\u0000${row.instanceId}`, row]));
  const sorted = [...byKey.values()].sort((a, b) =>
    a.credentialId !== b.credentialId
      ? a.credentialId < b.credentialId
        ? -1
        : 1
      : a.instanceId < b.instanceId
        ? -1
        : a.instanceId > b.instanceId
          ? 1
          : 0,
  );
  for (const credentialId of [...new Set(sorted.map((row) => row.credentialId))])
    await tx.$queryRaw`SELECT id FROM credential WHERE id = ${credentialId} FOR SHARE`;
  for (const row of sorted)
    await tx.$queryRaw`SELECT id FROM credential_instance WHERE id = ${row.instanceId} FOR UPDATE`;
}

/**
 * The settlement scope (§7.3, N3): the COMPLETE instance set a settling
 * transaction can touch, locked once, in the claim order, before its first
 * settlement phase — the instances of every non-terminal lease of the named
 * sandboxes (S held for each), plus any extra lease the caller will lock.
 *
 * A transaction that settles in phases (a failed launch, then the expiry's
 * teardown; a capture fence, then the drained-teardown settlement; a census
 * over several sandboxes) must not lock a subset per phase: sorting each
 * subset does not order the transaction, and a later phase reaching back to
 * a smaller key closes a cycle with any other settlement holding it. Under S
 * no lease of the sandbox appears and a lease's instance never changes, so
 * every later phase only re-locks rows this call already holds.
 */
export async function lockSettlementScope(
  tx: Tx,
  input: {
    sandboxIds: readonly string[];
    leases?: readonly { credentialId: string; instanceId: string }[];
  },
) {
  const sandboxIds = [...new Set(input.sandboxIds)];
  const rows =
    sandboxIds.length === 0
      ? []
      : await tx.$queryRaw<{ credentialId: string; instanceId: string }[]>`
        SELECT DISTINCT l."credentialId", l."instanceId" FROM credential_lease l
        WHERE l."sandboxId" = ANY(${sandboxIds}::text[])
          AND l.state::text NOT IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED')`;
  // Mocked clients (unit tests of the relay) return nothing.
  await lockInstancesInClaimOrder(tx, [...(rows ?? []), ...(input.leases ?? [])]);
}

/** A host-submitted reference to one of its captures: the lease and binding it names. */
export type CaptureClaim = { leaseId: string; bindingId: string };

/**
 * Capture custody (§7.4.3): the ONE boundary every host-submitted capture
 * reference passes before anything is written on its behalf — the commit
 * fence, its rejection path and the census's pending rows. A claim is held
 * when its binding exists, names that lease and was issued to THIS host.
 * Binding identity (lease, host) is fixed at insert, so the check needs no
 * lock; a lease's bindings go only with the lease itself. A claim that is not
 * held never locks, transitions or attributes another lease: a host knowing
 * a foreign lease id gains nothing by naming it. Returns the held claims.
 */
export async function heldCaptureClaims<T extends CaptureClaim>(
  tx: Tx,
  hostId: string,
  claims: readonly T[],
): Promise<T[]> {
  if (claims.length === 0) return [];
  const bindingIds = [...new Set(claims.map((claim) => claim.bindingId))];
  const rows = await tx.credentialBinding.findMany({
    where: { id: { in: bindingIds }, hostId },
    select: { id: true, leaseId: true },
    take: bindingIds.length,
  });
  const leaseOf = new Map(rows.map((row) => [row.id, row.leaseId]));
  return claims.filter((claim) => leaseOf.get(claim.bindingId) === claim.leaseId);
}

export type QuarantineDiscard = { hostId: string; captureIds: string[] };

/**
 * Quarantine discard (§7.4.2, P3-1): marks the matching live rejection rows
 * discarded and returns, per host, the capture ids to name in
 * `credential.quarantine.discard` (≤ 64 per frame). A census that still lists
 * a discarded id gets the frame again, so delivery is eventually reliable.
 */
export async function discardQuarantined(
  tx: Tx,
  where: { leaseId: string } | { instanceId: string } | { hostId: string },
): Promise<QuarantineDiscard[]> {
  const rows =
    "leaseId" in where
      ? await tx.$queryRaw<
          { hostId: string; captureId: string }[]
        >`UPDATE credential_capture_rejection
          SET "discardedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
          WHERE "leaseId" = ${where.leaseId} AND "discardedAt" IS NULL RETURNING "hostId", "captureId"`
      : "instanceId" in where
        ? await tx.$queryRaw<
            { hostId: string; captureId: string }[]
          >`UPDATE credential_capture_rejection r
            SET "discardedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
            FROM credential_lease l
            WHERE l.id = r."leaseId" AND l."instanceId" = ${where.instanceId} AND r."discardedAt" IS NULL
            RETURNING r."hostId", r."captureId"`
        : await tx.$queryRaw<
            { hostId: string; captureId: string }[]
          >`UPDATE credential_capture_rejection
            SET "discardedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
            WHERE "hostId" = ${where.hostId} AND "discardedAt" IS NULL RETURNING "hostId", "captureId"`;
  return groupDiscards(rows);
}

export function groupDiscards(rows: { hostId: string; captureId: string }[]): QuarantineDiscard[] {
  const byHost = new Map<string, string[]>();
  for (const row of rows) {
    const ids = byHost.get(row.hostId) ?? [];
    if (!ids.includes(row.captureId)) ids.push(row.captureId);
    byHost.set(row.hostId, ids);
  }
  const out: QuarantineDiscard[] = [];
  for (const [hostId, ids] of byHost)
    for (let at = 0; at < ids.length; at += 64)
      out.push({ hostId, captureIds: ids.slice(at, at + 64) });
  return out;
}

export type ForceReleaseResult = {
  released: boolean;
  /** `credential.revoke` to the lease's host, if it has one. */
  revoke: { hostId: string; leaseId: string } | null;
  discards: QuarantineDiscard[];
};

/**
 * Force-release core (§7.1 non-terminal → FORCE_RELEASED): S → credential
 * FOR SHARE → instance FOR UPDATE → lease. All bindings close, residue becomes
 * non-recoverable, the lease's quarantined captures are discarded, and later
 * captures ack DISCARDED{force_released}. The owner action (gate, budget,
 * checkpoint promotion) is `forceRelease` in owner-actions.ts.
 */
export async function forceReleaseLease(
  tx: Tx,
  input: { ownerId: string; leaseId: string },
): Promise<ForceReleaseResult> {
  const lease = await tx.credentialLease.findFirst({
    where: { id: input.leaseId, userId: input.ownerId },
    select: { id: true, sandboxId: true, credentialId: true, instanceId: true, hostId: true },
  });
  if (!lease) return { released: false, revoke: null, discards: [] };
  if (lease.sandboxId) await lockLeaseSandbox(tx, lease.sandboxId);
  await lockLeaseChain(tx, lease);
  const released = await finishLease(tx, lease.id, "FORCE_RELEASED", "force_released");
  // Its unresolved envelopes are now authorized discards (a later upload
  // acks DISCARDED{force_released}); they no longer block delete or re-pin.
  if (released)
    await tx.$executeRaw`DELETE FROM credential_pending_capture WHERE "leaseId" = ${lease.id}`;
  const discards = await discardQuarantined(tx, { leaseId: lease.id });
  return {
    released,
    revoke: released && lease.hostId ? { hostId: lease.hostId, leaseId: lease.id } : null,
    discards,
  };
}
