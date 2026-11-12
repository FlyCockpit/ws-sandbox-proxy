import type { Prisma } from "@wssp/db";
import type { CredentialTeardownOutcomeV11 } from "@wssp/sandbox-contracts";
import { settleCredentialsOnOffloaded } from "../../credentials/teardown";
import { releaseLiveResourcesOnInventoryProof } from "../host-admission";
import { restoreOffloadOf } from "../launch-mode";
import { queueSystemDetachKill } from "../lease";
import { hostDatabaseNow, requireRelayFence } from "../relay-fence";
import { type DetachProof, detachToOffloaded, staleCopyIdentity } from "./detach";

/**
 * `disk-offload/restore-exit.ts::exitRestoreAttempt`: the
 * only place a restore attempt ends without READY.
 *
 * Every failed restore is handed here with the failed launch's own operation
 * id and placement generation (U5.4) and the proof its caller holds: the
 * outbox exits (X1), a refused or unsupported dispatch, the allocation
 * attestation's never-issued proof, and the lease finalizer (a failed,
 * unknown, readiness-failed or expired attempt, M1/M4/T3).
 *
 * - A no-effect proof (never dispatched; capability refused at dispatch; an
 *   outbox refusal at attempt 0; a root-absent `host_effect_not_issued` with
 *   first-attempt evidence) detaches straight to OFFLOADED in this
 *   transaction.
 * - Otherwise the attempt may have created a root: the `SYSTEM_DETACH` KILL
 *   goes out through `queueSystemDetachKill` (lease.ts) carrying
 *   `attemptOperationId` / `attemptGeneration`; the row moves to STOPPING.
 *   That kill's SUCCEEDED result (the result handler or the census) ends
 *   through `settleSystemDetachKill` below with its root proof.
 *
 * The detach transaction owns, in order: release of the live hold, release
 * of the target root on proof (inside `detachToOffloaded`), the credential
 * settlement `settleCredentialsOnOffloaded` with the attempt, and the one
 * `updateMany` to OFFLOADED (`detachToOffloaded`). The stored copy is never
 * touched: it stays authoritative until a READY (I20).
 *
 * Caller holds owner → H (the attempt's host) → S, as every relay and lease
 * writer does.
 */
export type RestoreExitProof =
  /** Nothing was ever issued for this attempt on its host. */
  | {
      kind: "no_effect";
      reason:
        | "capability_refused"
        | "outbox_refused"
        | "dispatch_refused"
        | "host_effect_not_issued"
        | "never_dispatched";
    }
  /** No proof: the attempt may have created a root (UNKNOWN). */
  | { kind: "none" };

export type RestoreExitInput = {
  sandboxId: string;
  userId: string;
  /** The failed launch's own operation and placement generation (U5.4). */
  attemptOperationId: string;
  attemptGeneration: number;
  proof: RestoreExitProof;
  now?: Date;
};

type Tx = Prisma.TransactionClient;

const exitSandboxSelect = {
  id: true,
  userId: true,
  state: true,
  generation: true,
  sandboxHostId: true,
  diskOffloadId: true,
  leaseRevision: true,
  leaseExpiresAt: true,
  leaseExpireAction: true,
  liveResourcesHeld: true,
} satisfies Prisma.SandboxSelect;

/**
 * End the failed restore attempt (see the module comment). Returns true when
 * this transaction owns its settlement (detached, or the SYSTEM_DETACH kill
 * queued); false when it is not a current restore attempt of this sandbox
 * (another generation, no stored disk, not a restore), and the caller keeps
 * its generic settlement.
 */
export async function exitRestoreAttempt(tx: Tx, input: RestoreExitInput): Promise<boolean> {
  await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${input.sandboxId} AND "userId" = ${input.userId} FOR NO KEY UPDATE`;
  const sandbox = await tx.sandbox.findFirst({
    where: { id: input.sandboxId, userId: input.userId },
    select: exitSandboxSelect,
  });
  if (!sandbox?.diskOffloadId || !sandbox.sandboxHostId) return false;
  if (sandbox.generation !== input.attemptGeneration) return false;
  const attempt = await tx.sandboxOperation.findFirst({
    where: { id: input.attemptOperationId, sandboxId: sandbox.id, userId: sandbox.userId },
    select: { kind: true, launchMode: true, restoreOffloadId: true, generation: true },
  });
  // Only the attempt that fetches this sandbox's current stored disk.
  if (
    !attempt ||
    attempt.generation !== input.attemptGeneration ||
    restoreOffloadOf(attempt) !== sandbox.diskOffloadId
  )
    return false;
  await closeRestoreFetch(tx, input.attemptOperationId, "restore_failed");
  const now = input.now ?? (await hostDatabaseNow(tx));
  const fields = {
    attemptOperationId: input.attemptOperationId,
    attemptGeneration: input.attemptGeneration,
  };
  if (input.proof.kind === "no_effect") {
    if (sandbox.state !== "PROVISIONING") return false;
    // The attempt holds a stored current disk at its own generation: the
    // detach cannot be refused once its preconditions held above.
    requireRelayFence(
      await detachWithProof(tx, sandbox, sandbox.sandboxHostId, fields, {
        kind: "restore_no_effect",
      }),
    );
    return true;
  }
  // The attempt is over either way: an UNKNOWN attempt (a later attempt's
  // outbox or dispatch refusal) is settled FAILED with its code before the
  // kill, as the lease finalizer settles a failed or unknown result, so
  // the kill's supersession of older generations never rewrites it
  // `superseded`. Only the kill's root proof ends the hold.
  await tx.sandboxOperation.updateMany({
    where: { id: input.attemptOperationId, userId: sandbox.userId, state: "UNKNOWN_OUTCOME" },
    data: { state: "FAILED" },
  });
  return queueSystemDetachKill(tx, sandbox, now, fields);
}

/**
 * The SUCCEEDED `SYSTEM_DETACH` kill (§8.7, §8.9 M2): its root/network
 * absence is the detach proof. Both mapping sites (the result handler and
 * the census) call this instead of every generic writer. A kill carrying a
 * failed restore attempt settles that attempt's credentials; one without
 * (expiry or access loss of a cached copy) clears nothing. Returns whether it
 * detached. Caller holds owner → H → S and the kill's row.
 */
export async function settleSystemDetachKill(
  tx: Tx,
  input: {
    sandboxId: string;
    userId: string;
    hostId: string;
    generation: number;
    killOperationId: string;
    outcomes?: readonly CredentialTeardownOutcomeV11[] | null;
  },
): Promise<boolean> {
  const kill = await tx.sandboxOperation.findFirst({
    where: {
      id: input.killOperationId,
      sandboxId: input.sandboxId,
      userId: input.userId,
      kind: "KILL_SANDBOX",
      teardownIntent: "SYSTEM_DETACH",
    },
    select: { attemptOperationId: true, attemptGeneration: true },
  });
  requireRelayFence(kill != null);
  const attempt =
    kill.attemptOperationId != null && kill.attemptGeneration != null
      ? { attemptOperationId: kill.attemptOperationId, attemptGeneration: kill.attemptGeneration }
      : null;
  if (attempt) await closeRestoreFetch(tx, attempt.attemptOperationId, "restore_failed");
  return detachWithProof(
    tx,
    { id: input.sandboxId, userId: input.userId, generation: input.generation },
    input.hostId,
    attempt,
    { kind: "system_detach_kill" },
    input.outcomes,
  );
}

/**
 * Census VM absence of a PROVISIONING or ERROR row that still holds its
 * stored disk (offload plan I3, §8.7 "census"): never ERROR or DELETED. VM
 * absence proves nothing runs on that host, so the live hold is released
 * and the sandbox detaches to OFFLOADED — with the census's exact root
 * proof the root is released, otherwise the hold moves to a
 * `SandboxDiskCopy(STALE)` for the discard. The credential settlement is
 * scoped to the newest failed restore attempt a SYSTEM_DETACH kill carried
 * (`restore_cleanup_pending`), or clears nothing. Caller holds owner → H →
 * S and already ruled out an uncertain launch. Returns whether it detached.
 */
export async function detachOnCensusAbsence(
  tx: Tx,
  input: {
    sandbox: {
      id: string;
      userId: string;
      generation: number;
      templateRevisionId: string;
      diskBaseFingerprint: string | null;
    };
    hostId: string;
    rootProof: boolean;
  },
): Promise<boolean> {
  const { sandbox } = input;
  const kill = await tx.sandboxOperation.findFirst({
    where: {
      sandboxId: sandbox.id,
      userId: sandbox.userId,
      kind: "KILL_SANDBOX",
      teardownIntent: "SYSTEM_DETACH",
      attemptOperationId: { not: null },
      attemptGeneration: { not: null, lte: sandbox.generation },
    },
    orderBy: { generation: "desc" },
    select: { attemptOperationId: true, attemptGeneration: true },
  });
  const attempt =
    kill?.attemptOperationId != null && kill.attemptGeneration != null
      ? { attemptOperationId: kill.attemptOperationId, attemptGeneration: kill.attemptGeneration }
      : null;
  if (attempt) await closeRestoreFetch(tx, attempt.attemptOperationId, "restore_failed");
  return detachWithProof(
    tx,
    sandbox,
    input.hostId,
    attempt,
    input.rootProof
      ? { kind: "root_absent" }
      : { kind: "stale_copy", ...(await staleCopyIdentity(tx, sandbox)) },
  );
}

/** The ordered detach steps (module comment). */
async function detachWithProof(
  tx: Tx,
  sandbox: { id: string; userId: string; generation: number },
  hostId: string,
  attempt: { attemptOperationId: string; attemptGeneration: number } | null,
  proof: DetachProof,
  outcomes?: readonly CredentialTeardownOutcomeV11[] | null,
): Promise<boolean> {
  // 1. The live hold (the proof: nothing runs there).
  await releaseLiveResourcesOnInventoryProof(tx, {
    hostId,
    ownerId: sandbox.userId,
    sandboxId: sandbox.id,
  });
  // 3. Credentials of the failed attempt (2, the root, is released inside
  //    the detach on its proof, before its state write).
  await settleCredentialsOnOffloaded(tx, {
    sandboxId: sandbox.id,
    attemptOperationId: attempt?.attemptOperationId ?? null,
    attemptGeneration: attempt?.attemptGeneration ?? null,
    outcomes,
  });
  // 4. The one write to OFFLOADED.
  return detachToOffloaded(tx, {
    sandboxId: sandbox.id,
    userId: sandbox.userId,
    hostId,
    generation: sandbox.generation,
    proof,
  });
}

/**
 * A restore's RESTORE_FETCH transfer ends with its attempt: the daemon sends
 * no `image.cached` for a restored disk, so the transfer would otherwise stay
 * OPEN until it expires. READY completes it; a failed attempt cancels it.
 */
export async function closeRestoreFetch(
  tx: Tx,
  attemptOperationId: string,
  reason: "restored" | "restore_failed",
): Promise<void> {
  await tx.sandboxImageTransfer.updateMany({
    where: { operationId: attemptOperationId, purpose: "RESTORE_FETCH", state: "OPEN" },
    data:
      reason === "restored"
        ? { state: "COMPLETE", endReason: reason }
        : { state: "CANCELLED", endReason: reason },
  });
}
