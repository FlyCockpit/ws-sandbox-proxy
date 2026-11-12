import { HOST_HEARTBEAT_STALE_AFTER_MS } from "@wssp/config/host-status";
import type { Prisma, SandboxState } from "@wssp/db";
import type { RootObservationV11 } from "@wssp/sandbox-contracts";
import { settleCredentialsOnOffloaded } from "../../credentials/teardown";
import {
  hasPossiblyLiveSandboxAttempt,
  noteHostBlockerReleased,
  releaseRootResources,
} from "../host-admission";
import { requireRelayFence, transactionHoldsHostLock } from "../relay-fence";
import { requireSandboxIntegrity } from "../sensitive-errors";
import { ACTIVE_OPERATION_STATES } from "../state-transitions";

/**
 * `disk-offload/detach.ts::detachToOffloaded`:
 * THE only writer of `SandboxState.OFFLOADED`. A sandbox whose disk is
 * STORED leaves its host only through here, and each caller carries exactly
 * one proof that no copy of it can still run there:
 *
 * | caller | proof |
 * | --- | --- |
 * | evict (§7) | grant-fenced `disk.evicted` root-absence proof (`root_absent`) |
 * | census (§7) | the census root-absence proof (`root_absent`), or else the hold moves to a `SandboxDiskCopy(STALE)` (`stale_copy`) |
 * | a `SYSTEM_DETACH` kill (§8.7, M2) | the settled kill's root/network absence (`system_detach_kill`) |
 * | the restore exit (§8.7) | a no-effect proof: nothing was ever issued for the attempt (`restore_no_effect`) |
 *
 * A root-absence proof releases the root reservation once (the
 * holder-generic `releaseRootResources`). A stale copy keeps it: the
 * reservation, its share attribution and the root identity move to the copy
 * row (counters unchanged) and discard settles it later.
 *
 * The detach clears host, host owner, placement, pool usage and member,
 * storage pool, lease and access-grace fields and the held flags, bumps the
 * generation (a fence for every dispatch of the old one), and returns the
 * offload to STORED with its evict marker cleared. Its credential
 * settlement is `settleCredentialsOnOffloaded`, once per transaction: the
 * restore exit runs it first with its attempt (residue and spec of that
 * attempt only); evict and census clear nothing (U5).
 *
 * The caller holds owner → host (`lockHostByEpoch`) → sandbox and passes the
 * generation it read under them.
 */

type Tx = Prisma.TransactionClient;

export type DetachProof =
  | { kind: "root_absent" }
  | { kind: "stale_copy"; createKey: string; baseFingerprint: string }
  | { kind: "system_detach_kill" }
  | { kind: "restore_no_effect" };

export type DetachInput = {
  sandboxId: string;
  userId: string;
  hostId: string;
  generation: number;
  proof: DetachProof;
};

/** States a detach leaves from, per proof. Evict and the offline/stale
 * start gate detach a cached STOPPED copy only (their own CAS requires it);
 * the census also detaches a PROVISIONING or ERROR row with a stored disk
 * whose VM is absent (I3); a settled SYSTEM_DETACH kill also ends a restore
 * attempt or a failed teardown (§8.7). */
function detachableStates(proof: DetachProof): SandboxState[] {
  if (proof.kind === "system_detach_kill") return ["STOPPED", "STOPPING", "PROVISIONING", "ERROR"];
  if (proof.kind === "restore_no_effect") return ["PROVISIONING"];
  return ["STOPPED", "PROVISIONING", "ERROR"];
}

const detachSelect = {
  id: true,
  userId: true,
  state: true,
  generation: true,
  sandboxHostId: true,
  hostOwnerId: true,
  diskOffloadId: true,
  liveResourcesHeld: true,
  diskReservationHeld: true,
  storagePoolId: true,
  storageMarker: true,
  storagePoolName: true,
  rootChargeGiB: true,
  usagePoolId: true,
  usageMemberId: true,
  cachedOffloadSeq: true,
} satisfies Prisma.SandboxSelect;

/**
 * Detach `sandboxId` from `hostId` to OFFLOADED (see the module comment).
 * Returns false (nothing written) when the sandbox is not detachable here:
 * another state, generation or host, no current offload, a live slot still
 * held, or an offload that is not STORED | EVICTING.
 */
export async function detachToOffloaded(tx: Tx, input: DetachInput): Promise<boolean> {
  requireRelayFence(transactionHoldsHostLock(tx, input.hostId));
  await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${input.sandboxId} AND "userId" = ${input.userId} FOR NO KEY UPDATE`;
  const sandbox = await tx.sandbox.findFirst({
    where: {
      id: input.sandboxId,
      userId: input.userId,
      generation: input.generation,
      sandboxHostId: input.hostId,
      state: { in: detachableStates(input.proof) },
      diskOffloadId: { not: null },
    },
    select: detachSelect,
  });
  if (!sandbox?.diskOffloadId || !sandbox.hostOwnerId) return false;
  // A detach never strands a live slot: the caller releases it first.
  if (sandbox.liveResourcesHeld) return false;
  const [offload] = await tx.$queryRaw<
    { state: string; seq: number }[]
  >`SELECT state::text AS state,
    seq FROM sandbox_disk_offload WHERE id = ${sandbox.diskOffloadId}
      AND "sandboxId" = ${sandbox.id} FOR UPDATE`;
  if (!offload || !["STORED", "EVICTING"].includes(offload.state)) return false;
  if (input.proof.kind === "stale_copy") {
    if (sandbox.storagePoolId && sandbox.storageMarker && sandbox.storagePoolName) {
      const existing = await tx.sandboxDiskCopy.findFirst({
        where: { sandboxId: sandbox.id, hostId: input.hostId },
        select: { id: true },
      });
      // Restore eligibility excludes a host with a copy row (R9).
      requireSandboxIntegrity(!existing, "sandbox_allocation_mismatch");
      requireSandboxIntegrity(
        !sandbox.diskReservationHeld || sandbox.rootChargeGiB != null,
        "sandbox_root_unbound",
      );
      // The hold moves (counters unchanged): the copy row now holds it.
      await tx.sandboxDiskCopy.create({
        data: {
          sandboxId: sandbox.id,
          userId: sandbox.userId,
          hostId: input.hostId,
          hostOwnerId: sandbox.hostOwnerId,
          usagePoolId: sandbox.usagePoolId,
          usageMemberId: sandbox.usageMemberId,
          storagePoolId: sandbox.storagePoolId,
          storageMarker: sandbox.storageMarker,
          storagePoolName: sandbox.storagePoolName,
          rootChargeGiB: sandbox.rootChargeGiB ?? 0,
          offloadSeq: sandbox.cachedOffloadSeq ?? offload.seq,
          createKey: input.proof.createKey,
          baseFingerprint: input.proof.baseFingerprint,
          diskReservationHeld: sandbox.diskReservationHeld,
        },
        select: { id: true },
      });
    }
  } else {
    await releaseRootResources(tx, {
      hostId: input.hostId,
      ownerId: sandbox.userId,
      sandboxId: sandbox.id,
    });
  }
  // U5: a no-op when the restore exit already settled this sandbox here.
  await settleCredentialsOnOffloaded(tx, {
    sandboxId: sandbox.id,
    attemptOperationId: null,
    attemptGeneration: null,
  });
  const detached = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: sandbox.userId,
      generation: input.generation,
      state: sandbox.state,
      sandboxHostId: input.hostId,
      diskOffloadId: sandbox.diskOffloadId,
      liveResourcesHeld: false,
    },
    data: {
      state: "OFFLOADED",
      generation: { increment: 1 },
      sandboxHostId: null,
      hostOwnerId: null,
      currentPlacementId: null,
      usagePoolId: null,
      usageMemberId: null,
      storagePoolId: null,
      liveResourcesHeld: false,
      diskReservationHeld: false,
      cachedOffloadSeq: null,
      leaseExpiresAt: null,
      leaseExpiresAtRequested: null,
      leaseExpireActionRequested: null,
      leaseExpiresAtEffective: null,
      leaseRevisionEffective: null,
      leaseExpireActionEffective: null,
      leasePendingReady: false,
      accessGraceUntil: null,
      accessGraceReason: null,
    },
  });
  requireRelayFence(detached.count === 1);
  await tx.sandboxDiskOffload.updateMany({
    where: { id: sandbox.diskOffloadId, state: { in: ["STORED", "EVICTING"] } },
    data: {
      state: "STORED",
      evictGrantId: null,
      evictHostId: null,
      evictGrantEpoch: null,
      evictGrantedAt: null,
      evictGrantExpiresAt: null,
    },
  });
  // The host lost a blocker; a waiting create may now place there.
  noteHostBlockerReleased(tx, input.hostId, sandbox.hostOwnerId);
  return true;
}

/**
 * The stale instance's identity for its `SandboxDiskCopy` (R9/U9.3, N1):
 * the create key of the operation that created the instance's root (the
 * latest succeeded create, or restore RECONNECT with `launchMode =
 * NEW_ROOT`; a cold reconnect reuses the root, so never its key), and its
 * base image (`diskBaseFingerprint` of a restored lineage, else the template
 * revision's fingerprint). An unknown key never binds a discard.
 */
export async function staleCopyIdentity(
  tx: Tx,
  sandbox: {
    id: string;
    userId: string;
    templateRevisionId: string;
    diskBaseFingerprint: string | null;
  },
): Promise<{ createKey: string; baseFingerprint: string }> {
  const created = await tx.sandboxOperation.findFirst({
    where: {
      sandboxId: sandbox.id,
      userId: sandbox.userId,
      state: "SUCCEEDED",
      OR: [{ kind: "CREATE_SANDBOX" }, { kind: "RECONNECT_SANDBOX", launchMode: "NEW_ROOT" }],
    },
    orderBy: { generation: "desc" },
    select: { idempotencyKey: true },
  });
  const revision = await tx.sandboxTemplateRevision.findFirst({
    where: { id: sandbox.templateRevisionId },
    select: { incusFingerprint: true },
  });
  return {
    createKey: created?.idempotencyKey ?? `unknown:${sandbox.id}`,
    baseFingerprint: sandbox.diskBaseFingerprint ?? revision?.incusFingerprint ?? "",
  };
}

/** Connected with a fresh heartbeat: a grant or discard can reach it. */
export async function hostOnline(tx: Tx, hostId: string, now: Date): Promise<boolean> {
  const host = await tx.sandboxHost.findUnique({
    where: { id: hostId },
    select: { status: true, lastHeartbeatAt: true },
  });
  return (
    host?.status === "CONNECTED" &&
    host.lastHeartbeatAt !== null &&
    now.getTime() - host.lastHeartbeatAt.getTime() <= HOST_HEARTBEAT_STALE_AFTER_MS
  );
}

/**
 * THE safe-detachment gate (§8.2, CN1/I21) for moving a STOPPED sandbox's
 * root hold off `hostId` to a `SandboxDiskCopy(STALE)` without a
 * root-absence proof: no possibly-live attempt exists
 * (`hasPossiblyLiveSandboxAttempt`) and no ACTIVE or UNKNOWN operation was
 * dispatched to that host. Shared by the restore path's offline cached
 * copy (`restore-admit.ts` `detachStaleCachedCopy`) and Forget unreachable
 * host (`forget.ts`). The caller has already required STOPPED with no live
 * slot under owner → host → sandbox locks.
 */
export async function staleDetachSafe(
  tx: Tx,
  input: { ownerId: string; sandboxId: string; hostId: string },
): Promise<boolean> {
  if (await hasPossiblyLiveSandboxAttempt(tx, input.ownerId, input.sandboxId, "")) return false;
  const dispatched = await tx.sandboxOperation.findFirst({
    where: {
      userId: input.ownerId,
      sandboxId: input.sandboxId,
      dispatchedHostId: input.hostId,
      state: { in: [...ACTIVE_OPERATION_STATES, "UNKNOWN_OUTCOME"] },
    },
    select: { id: true },
  });
  return dispatched === null;
}

/** The proof names the sandbox's own root, absent, network cleaned. */
export function rootProofMatches(
  proof: RootObservationV11,
  root: { storageMarker: string | null; storagePoolName: string | null; diskGiB?: number },
): boolean {
  return (
    proof.state === "absent" &&
    proof.networkCleanupComplete &&
    proof.storageMarker === root.storageMarker &&
    proof.storagePoolName === root.storagePoolName &&
    (root.diskGiB === undefined || proof.diskGiB === root.diskGiB)
  );
}

/** Clear an EVICTING marker back to STORED (the VM is known present, or
 * the granting session outlived the grant). Caller holds the sandbox lock. */
export async function clearEvictMarker(tx: Tx, offloadId: string): Promise<boolean> {
  const cleared = await tx.sandboxDiskOffload.updateMany({
    where: { id: offloadId, state: "EVICTING" },
    data: {
      state: "STORED",
      evictGrantId: null,
      evictHostId: null,
      evictGrantEpoch: null,
      evictGrantedAt: null,
      evictGrantExpiresAt: null,
    },
  });
  return cleared.count === 1;
}

/** Ask for a copy's discard soon (the census saw it on its host). */
export async function noteCopyReported(tx: Tx, copyId: string): Promise<void> {
  await tx.sandboxDiskCopy.updateMany({
    where: { id: copyId, state: "STALE" },
    data: { discardSentAt: null },
  });
}
