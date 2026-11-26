import {
  settleCredentialConvergence,
  settleCredentialsOnDeleted,
  settleCredentialsOnStopped,
  settleOperationCredentials,
} from "@wssp/api/credentials/relay";
import { noteCapacityChanged } from "@wssp/api/sandbox/capacity-queue-wake";
import { OPERATION_DISPATCH_KIND } from "@wssp/api/sandbox/contracts";
import { endOffloadForDestroy } from "@wssp/api/sandbox/disk-offload/destroy";
import {
  clearEvictMarker,
  detachToOffloaded,
  noteCopyReported,
  rootProofMatches,
  staleCopyIdentity,
} from "@wssp/api/sandbox/disk-offload/detach";
import {
  detachOnCensusAbsence,
  exitRestoreAttempt,
  settleSystemDetachKill,
} from "@wssp/api/sandbox/disk-offload/restore-exit";
import {
  clearRetiredReleaseQuarantine,
  type HostStorageObservation,
  initializeHostMemoryReservation,
  noteHostBlockerReleased,
  recordStorageObservation,
  releaseLiveResourcesOnInventoryProof,
  releaseRootResources,
  requireRetainedStorage,
  requireStaticCapacityMatch,
  STORAGE_HEALTH_STALE_MS,
} from "@wssp/api/sandbox/host-admission";
import { hashOperationRequestBody, requestDigestMetadata } from "@wssp/api/sandbox/idempotency";
import { defaultIncusInstanceName } from "@wssp/api/sandbox/incus-name";
import { restoreOffloadOf } from "@wssp/api/sandbox/launch-mode";
import {
  inventoryObservationIdempotencyKey,
  type LeaseClock,
  leaseExpiryDispatchAction,
  leaseExpiryIdempotencyKey,
  leaseNow,
} from "@wssp/api/sandbox/lease";
import { leaseWireSchema } from "@wssp/api/sandbox/lease-wire";
import { outboxOperationWhere } from "@wssp/api/sandbox/outbox-operation";
import { systemAttribution } from "@wssp/api/sandbox/principal-kinds";
import {
  casSandboxGeneration,
  hostDatabaseNow,
  lockHostByEpoch,
  relayTransaction,
  requireRelayFence,
  requireRelayWorkload,
  retireSupersededOperations,
  settleSupersededOperations,
} from "@wssp/api/sandbox/relay-fence";
import { safeOperationError } from "@wssp/api/sandbox/sensitive-errors";
import {
  ACTIVE_OPERATION_STATES,
  sandboxStateForLifecycleResult,
} from "@wssp/api/sandbox/state-transitions";
import type { Prisma, SandboxLeaseExpireAction, SandboxState } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import {
  type CredentialCapabilitiesV11,
  credentialCapabilitiesV11Schema,
  type ImageAdmissionV11,
  type ImageCapabilitiesV11,
  imageCapabilitiesV11Schema,
} from "@wssp/sandbox-contracts";
import {
  digestContextSnapshot,
  ENV_FREE_DIGEST_DOMAIN,
} from "../../../../packages/api/src/sandbox/digest-context";
import type { RelaySender } from "./operation-handlers.js";
import type { CensusEntryResult, DaemonControlMessage, InventoryEntry } from "./protocol.js";

/** Host-reported observations only: NEVER widen egress capability, grant
 * dispatch, clear quarantine, settle lifecycle, or infer packet isolation.
 * The server timestamp makes stale telemetry distinguishable from a pass. */
function policyReconcilerHealthMetadata(
  health: NonNullable<Extract<DaemonControlMessage, { type: "heartbeat" }>["policyReconciler"]>,
  now: Date,
): Prisma.InputJsonObject {
  return {
    ...health,
    reportedAt: now.toISOString(),
  };
}

/** Same authenticated owner/host/epoch CAS as the existing heartbeat. Health
 * is display-only; a stale writer changes neither heartbeat nor report. */
export async function recordHostHeartbeat(
  sender: RelaySender,
  health: Extract<DaemonControlMessage, { type: "heartbeat" }>["policyReconciler"],
  _now: Date,
): Promise<boolean> {
  return relayTransaction(async (tx) => {
    requireRelayFence(
      (await tx.sandboxHost.findFirst({
        where: {
          id: sender.hostId,
          userId: sender.userId,
          connectionEpoch: sender.connectionEpoch,
        },
        select: { id: true },
      })) != null,
    );
    await lockOwnerForAdmission(tx, sender.userId);
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    const receivedAt = await hostDatabaseNow(tx);
    const written = await tx.sandboxHost.updateMany({
      where: { id: sender.hostId, userId: sender.userId, connectionEpoch: sender.connectionEpoch },
      data: {
        lastHeartbeatAt: receivedAt,
        ...(health
          ? { policyReconcilerHealth: policyReconcilerHealthMetadata(health, receivedAt) }
          : {}),
      },
    });
    requireRelayFence(written.count === 1 && sender.isCurrent?.() !== false);
    return true;
  }, false);
}

/** Identity contradictions. Lifecycle disagreement is converged instead. */
export type QuarantineReason =
  | "unknown_sandbox"
  | "foreign_sandbox"
  | "deleted_instance_present"
  | "released_instance_present"
  | "generation_ahead"
  | "lease_ahead"
  | "lease_regressed"
  | "lease_mismatch";

/** `staleStorage`: the entry's root evidence was refused only because pool
 * health was not current (evidence older than the pool's observation, or the
 * observation aged out). The same evidence, re-collected under a current
 * observation, may converge; the census reports it so the host retries. */
type EntryOutcome =
  | { stale: true }
  | { conflict: QuarantineReason }
  | { converged: boolean; staleStorage?: true };

/** Server states whose silent absence can still change something. An ERROR
 * row that holds no slot is already converged: silence carries no lease, so it
 * cannot prove a destroy. Excluding it keeps converged rows from refilling the
 * pending bound on every census. */
const silenceWhere = {
  OR: [
    {
      state: {
        in: ["READY", "STOPPED", "STOPPING", "RECLAIMING"] as SandboxState[],
      },
    },
    { state: "ERROR" as const, liveResourcesHeld: true },
    // An ERROR row still holding its stored disk (offload I3): its silence
    // detaches it to OFFLOADED (`censusCachedCopy`).
    { state: "ERROR" as const, diskOffloadId: { not: null } },
    // A deleted sandbox's remnant VM charged to this node (`obligeRemnantDestroy`).
    // credential-settlement: exempt — read filter, not a write.
    { state: "DELETED" as const, liveResourcesHeld: true },
  ],
} satisfies Prisma.SandboxWhereInput;
const PENDING_ABSENT_MAX = 4096;
const SCAN_PAGE = 256;

export type InventoryCensusOptions = {
  /** Interior silence held until completion; the tail is never held. */
  pendingAbsentMax?: number;
  scanPage?: number;
};

type InventoryPage = Extract<DaemonControlMessage, { type: "sandbox.inventory" }>;

/**
 * One census per registered session. Pages arrive strictly in order; ids are
 * strictly ascending across pages. Explicit `absent` entries are not-found
 * evidence immediately. Silence is evidence only once the final page lands:
 * ids skipped inside a page range are held until then, and the tail after the
 * last id is scanned at completion. Nothing here is durable: a restart or
 * reconnect replays the whole census, and every write is an idempotent CAS.
 */
export class InventoryCensus {
  private nextPage = 0;
  private lastId: string | null = null;
  private pendingAbsent: string[] = [];
  private overflow = false;
  private releasedConflict = false;
  /** Per-sandbox disagreements this census contained (never a node quarantine). */
  readonly contained: { sandboxId: string; reason: QuarantineReason }[] = [];
  private readonly pendingAbsentMax: number;
  private readonly scanPage: number;
  complete = false;
  convergedCount = 0;
  /** Results of the last accepted page, one per entry in page order. */
  pageResults: CensusEntryResult[] = [];

  constructor(
    private readonly sender: RelaySender,
    private readonly clock: LeaseClock = leaseNow,
    options: InventoryCensusOptions = {},
  ) {
    this.pendingAbsentMax = options.pendingAbsentMax ?? PENDING_ABSENT_MAX;
    this.scanPage = options.scanPage ?? SCAN_PAGE;
  }

  /** Throws on a protocol violation. A per-sandbox conflict never aborts it. */
  async acceptPage(message: InventoryPage): Promise<{ ok: true } | { stale: true }> {
    if (this.complete) throw new Error("inventory after completion");
    if (message.page !== this.nextPage) throw new Error("inventory page out of order");
    const first = message.entries[0];
    if (first && this.lastId !== null && first.sandboxId <= this.lastId)
      throw new Error("inventory ids not ascending across pages");
    const results: CensusEntryResult[] = [];
    for (const entry of message.entries) {
      const outcome = await convergeInventoryEntry(this.sender, entry, this.clock, undefined, true);
      if ("stale" in outcome) return outcome;
      if ("conflict" in outcome) {
        if (await this.contain(entry.sandboxId, outcome.conflict)) return { stale: true };
        results.push({ sandboxId: entry.sandboxId, outcome: "not_converged" });
        continue;
      }
      if (outcome.converged) this.convergedCount += 1;
      results.push({
        sandboxId: entry.sandboxId,
        outcome: outcome.staleStorage
          ? "stale_storage"
          : outcome.converged
            ? "converged"
            : "not_converged",
      });
    }
    this.pageResults = results;
    const pageLast = message.entries.at(-1)?.sandboxId ?? this.lastId;
    const present = new Set(message.entries.map((entry) => entry.sandboxId));
    if (pageLast !== null) {
      const skipped = await this.scanSilent(this.lastId, pageLast, async (ids) => {
        for (const id of ids) {
          if (present.has(id)) continue;
          if (this.pendingAbsent.length >= this.pendingAbsentMax) {
            // Fail closed: unrecorded silence concludes nothing this census.
            // Converged rows leave the scan, so a replayed census reaches these.
            this.overflow = true;
            continue;
          }
          this.pendingAbsent.push(id);
        }
        return { ok: true };
      });
      if (!("ok" in skipped)) return skipped;
    }
    this.lastId = pageLast;
    this.nextPage += 1;
    if (!message.complete) return { ok: true };
    const held = await this.convergeAbsent(this.pendingAbsent);
    if (!("ok" in held)) return held;
    // The census is complete, so tail silence is evidence now: converge it in
    // bounded keyset chunks instead of holding it.
    const tail = await this.scanSilent(this.lastId, null, (ids) =>
      this.convergeAbsent(ids.filter((id) => !present.has(id))),
    );
    if (!("ok" in tail)) return tail;
    if (this.overflow)
      console.warn("[sandbox-relay] census silence exceeded the bound; remainder deferred");
    if (!(await recordCompleteCensus(this.sender, this.releasedConflict))) return { stale: true };
    this.complete = true;
    return { ok: true };
  }

  private async convergeAbsent(ids: readonly string[]): Promise<{ ok: true } | { stale: true }> {
    for (const sandboxId of ids) {
      const outcome = await convergeInventoryEntry(
        this.sender,
        { sandboxId, state: "absent" },
        this.clock,
        undefined,
        true,
      );
      if ("stale" in outcome) return outcome;
      if ("conflict" in outcome) {
        if (await this.contain(sandboxId, outcome.conflict)) return { stale: true };
        continue;
      }
      if (outcome.converged) this.convergedCount += 1;
    }
    return { ok: true };
  }

  /**
   * E3-A-01: one sandbox's disagreement is contained to that sandbox. The
   * entry concluded nothing about its lifecycle, its id still counts as
   * reported (never as silent absence), and the census goes on, so the node
   * reconnects and its queued teardown can reach the host. A deleted
   * sandbox's VM still present (`deleted_instance_present`) already carries
   * its durable remediation (`obligeRemnantDestroy`). A released allocation
   * still present keeps its own host-level remediation
   * (`released_instance_present`). Returns true when the session went stale
   * while recording.
   */
  private async contain(sandboxId: string, reason: QuarantineReason): Promise<boolean> {
    if (reason === "released_instance_present") {
      await quarantineHost(this.sender, reason, this.clock());
      this.releasedConflict = true;
      return this.sender.isCurrent?.() === false;
    }
    this.contained.push({ sandboxId, reason });
    logContainedConflict(this.sender, sandboxId, reason);
    return this.sender.isCurrent?.() === false;
  }

  /** Placed sandboxes in (after, through] whose silence matters, page by page. */
  private async scanSilent(
    after: string | null,
    through: string | null,
    onPage: (ids: string[]) => Promise<{ ok: true } | { stale: true }>,
  ): Promise<{ ok: true } | { stale: true }> {
    let cursor = after;
    for (;;) {
      const page = await relayTransaction(async (tx) => {
        await lockOwnerForAdmission(tx, this.sender.userId);
        await lockHostByEpoch(
          tx,
          this.sender.hostId,
          this.sender.connectionEpoch,
          this.sender.userId,
        );
        return tx.sandbox.findMany({
          where: {
            hostOwnerId: this.sender.userId,
            sandboxHostId: this.sender.hostId,
            ...silenceWhere,
            ...(cursor !== null || through !== null
              ? {
                  id: {
                    ...(cursor !== null ? { gt: cursor } : {}),
                    ...(through !== null ? { lte: through } : {}),
                  },
                }
              : {}),
          },
          orderBy: { id: "asc" },
          take: this.scanPage,
          select: { id: true },
        });
      }, null);
      if (page == null || this.sender.isCurrent?.() === false) return { stale: true };
      const handled = await onPage(page.map((row) => row.id));
      if (!("ok" in handled)) return handled;
      const last = page.at(-1);
      if (page.length < this.scanPage || !last) return { ok: true };
      cursor = last.id;
    }
  }
}

export type ObservedEntry = Pick<InventoryEntry, "sandboxId" | "state" | "lease"> & {
  sandboxOwnerId?: string | null;
  root?: {
    storagePoolName: string;
    storageMarker: string;
    diskGiB: number;
    state: "present" | "absent";
    networkCleanupComplete: boolean;
    observationSequence: number;
  } | null;
};

const sandboxConvergeSelect = {
  id: true,
  userId: true,
  hostOwnerId: true,
  sandboxHostId: true,
  state: true,
  generation: true,
  liveResourcesHeld: true,
  diskReservationHeld: true,
  storagePoolName: true,
  storageMarker: true,
  diskGiB: true,
  leaseRevision: true,
  leaseRevisionEffective: true,
  leaseExpiresAtEffective: true,
  leaseExpireActionEffective: true,
  lastErrorCode: true,
  lastErrorDetail: true,
  hostExpiryRevision: true,
  hostExpiryAction: true,
  currentPlacementId: true,
  diskOffloadId: true,
  diskBaseFingerprint: true,
  templateRevisionId: true,
} satisfies Prisma.SandboxSelect;
type ConvergeRow = Prisma.SandboxGetPayload<{ select: typeof sandboxConvergeSelect }>;

const wireAction = (action: "stop" | "destroy"): SandboxLeaseExpireAction =>
  action === "destroy" ? "DESTROY" : "STOP";

/**
 * The host of a sandbox's latest retained placement (by generation): the
 * host its VM last ran on (offload §8.10), or null when it never placed.
 */
async function lastPlacementHostId(
  tx: Prisma.TransactionClient,
  sandboxId: string,
  userId: string,
): Promise<string | null> {
  const placement = await tx.sandboxPlacement.findFirst({
    where: { sandboxId, userId },
    orderBy: [{ generation: "desc" }, { acceptedAt: "desc" }],
    select: { originHostId: true },
  });
  return placement?.originHostId ?? null;
}

/**
 * One entry under H → S → O → outbox. Convergence never infers more than the
 * host proved: a stopped or absent instance releases capacity; DELETED needs
 * a host-verified destroy expiry or a pending kill/stop that the absence
 * completes. An uncertain create/reconnect the host might still run blocks
 * every inference for that sandbox.
 */
export async function convergeInventoryEntry(
  sender: RelaySender,
  entry: ObservedEntry,
  clock: LeaseClock = leaseNow,
  proof?: AllocationProof,
  inCensus = false,
  /** VM absence without root evidence never converges a held reservation
   * (the census rule; also re-offered census evidence). */
  refuseRootlessAbsence = inCensus,
): Promise<EntryOutcome> {
  return relayTransaction<EntryOutcome>(
    async (tx) => {
      const located = await tx.sandbox.findFirst({
        where: { id: entry.sandboxId },
        select: sandboxConvergeSelect,
      });
      if (!located) return { conflict: "unknown_sandbox" };
      // A detached DELETED sandbox this node last ran: its absence is already
      // settled, and its presence is a remnant obligated below.
      // Offload §8.10 item 2: "this node last ran" is the host of its latest
      // retained placement (a restore moves it), never `Sandbox.originHostId`.
      const lastRanHere =
        located.state === "DELETED" &&
        (await lastPlacementHostId(tx, located.id, located.userId)) === sender.hostId;
      const detachedRemnant = lastRanHere && located.sandboxHostId === null;
      if (located.sandboxHostId !== sender.hostId) {
        // A detached stale copy on this host is
        // discard input, routed BEFORE remnant handling (never re-charged).
        const copy = await tx.sandboxDiskCopy.findFirst({
          where: { sandboxId: located.id, hostId: sender.hostId },
          select: { id: true },
        });
        if (copy) {
          await noteCopyReported(tx, copy.id);
          return { converged: false };
        }
        // An offloaded sandbox's former host proves nothing more by absence.
        if (located.state === "OFFLOADED" && entry.state === "absent") return { converged: false };
        if (detachedRemnant && entry.state === "absent") return { converged: false };
        if (!detachedRemnant)
          return lastRanHere
            ? { conflict: "deleted_instance_present" }
            : { conflict: "foreign_sandbox" };
      }
      if (entry.sandboxOwnerId === null) return { conflict: "foreign_sandbox" };
      const binding = await requireRelayWorkload(tx, sender, {
        sandboxId: entry.sandboxId,
        sandboxOwnerId: entry.sandboxOwnerId,
      });
      const creatorId = binding.sandboxOwnerId;
      for (const id of [...new Set([creatorId, sender.userId])].sort())
        await lockOwnerForAdmission(tx, id);
      await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
      await casSandboxGeneration(tx, {
        sandboxId: located.id,
        userId: creatorId,
        generation: located.generation,
        hostId: sender.hostId,
        states: [located.state],
      });
      const sandbox = await tx.sandbox.findFirst({
        where: {
          id: located.id,
          userId: creatorId,
          OR: [
            { sandboxHostId: sender.hostId },
            // credential-settlement: exempt — read filter, not a write.
            ...(detachedRemnant ? [{ sandboxHostId: null, state: "DELETED" as const }] : []),
          ],
        },
        select: sandboxConvergeSelect,
      });
      requireRelayFence(sandbox != null);
      await requireRelayWorkload(tx, sender, { sandboxId: sandbox.id, sandboxOwnerId: creatorId });
      if (sandbox.state === "DELETED") {
        if (entry.state !== "absent") {
          await obligeRemnantDestroy(tx, sender, sandbox, clock());
          requireRelayFence(sender.isCurrent?.() !== false);
          return { conflict: "deleted_instance_present" };
        }
        const settled = await settleRemnantAbsence(tx, sender, sandbox, entry, clock());
        requireRelayFence(sender.isCurrent?.() !== false);
        return { converged: settled };
      }
      if (
        sandbox.diskReservationHeld &&
        entry.root &&
        (entry.root.storageMarker !== sandbox.storageMarker ||
          entry.root.storagePoolName !== sandbox.storagePoolName ||
          entry.root.diskGiB !== sandbox.diskGiB)
      ) {
        await tx.sandboxHostStoragePool.updateMany({
          where: {
            sandboxHostId: sender.hostId,
            userId: sender.userId,
            marker: sandbox.storageMarker!,
          },
          data: { health: "unavailable", healthReason: "identity" },
        });
        return { converged: false };
      }
      if (sandbox.diskReservationHeld && entry.root) {
        // Exact root evidence can refresh omitted pools, but never overwrite a
        // newer negative health observation or rewrite frozen capacity/drain.
        const pool = await tx.sandboxHostStoragePool.findFirst({
          where: {
            sandboxHostId: sender.hostId,
            userId: sender.userId,
            marker: sandbox.storageMarker!,
            name: sandbox.storagePoolName!,
          },
        });
        const sequence = entry.root.observationSequence;
        if (!Number.isSafeInteger(sequence) || sequence < 0 || !pool) return { converged: false };
        // Evidence older than the pool's current observation on this epoch
        // never counts: that observation may be a newer negative one. It is
        // retried under a current observation.
        if (
          pool.connectionEpoch === sender.connectionEpoch &&
          BigInt(sequence) < pool.observationSequence
        )
          return { converged: false, staleStorage: true };
        if (
          pool.connectionEpoch !== sender.connectionEpoch ||
          BigInt(sequence) > pool.observationSequence
        )
          await tx.sandboxHostStoragePool.updateMany({
            where: { id: pool.id, sandboxHostId: sender.hostId, userId: sender.userId },
            data: {
              health: "healthy",
              healthReason: null,
              connectionEpoch: sender.connectionEpoch,
              observationSequence: BigInt(sequence),
              reportedAt: await hostDatabaseNow(tx),
            },
          });
      }
      // census rule (R2, N2): a cached STOPPED copy whose
      // disk is STORED (or EVICTING) is never ERROR or DELETED; nor is a
      // PROVISIONING or ERROR row that still holds its stored disk (I3).
      if (
        (sandbox.state === "STOPPED" ||
          sandbox.state === "PROVISIONING" ||
          sandbox.state === "ERROR") &&
        sandbox.diskOffloadId
      ) {
        const ruled = await censusCachedCopy(tx, sender, sandbox, entry);
        if (ruled) {
          requireRelayFence(sender.isCurrent?.() !== false);
          return ruled;
        }
      }
      // Census VM absence without root evidence never converges a held
      // reservation. It may still settle a pending stop/kill, the server's
      // own record (below), so a teardown state goes on to that check only.
      const censusRootless =
        refuseRootlessAbsence &&
        entry.state === "absent" &&
        sandbox.diskReservationHeld &&
        !entry.root;
      if (censusRootless && !["STOPPING", "RECLAIMING", "ERROR"].includes(sandbox.state))
        return { converged: false };
      if (proof) {
        if (entry.state !== "absent" || entry.lease) return { converged: false };
        if (
          sandbox.diskReservationHeld &&
          (!proof.root ||
            proof.root.storageMarker !== sandbox.storageMarker ||
            proof.root.storagePoolName !== sandbox.storagePoolName ||
            proof.root.diskGiB !== sandbox.diskGiB)
        )
          return { converged: false };
        const settled = await settleUnissuedAllocationAbsence(tx, sender, sandbox, proof);
        requireRelayFence(sender.isCurrent?.() !== false);
        return { converged: settled };
      }
      if (
        sandbox.state === "ERROR" &&
        !sandbox.liveResourcesHeld &&
        sandbox.lastErrorCode === "host_effect_not_issued" &&
        entry.state !== "absent"
      ) {
        // Persist the contradiction on the immutable failed allocation, so a
        // later teardown failure or generation cannot erase the witness. The
        // next complete census supersedes it without rewriting old results.
        const allocation = await tx.sandboxOperation.findFirst({
          where: {
            userId: creatorId,
            sandboxId: sandbox.id,
            state: "FAILED",
            kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },
            errorCode: "host_effect_not_issued",
          },
          orderBy: { generation: "desc" },
          select: { id: true, result: true },
        });
        if (allocation) {
          const host = await tx.sandboxHost.findFirst({
            where: { id: sender.hostId, userId: sender.userId },
            select: { inventorySeq: true },
          });
          requireRelayFence(host != null);
          await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${allocation.id} AND "userId" = ${creatorId} FOR UPDATE`;
          const result = allocation.result;
          await tx.sandboxOperation.updateMany({
            where: {
              id: allocation.id,
              userId: creatorId,
              state: "FAILED",
              kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },
              errorCode: "host_effect_not_issued",
            },
            data: {
              result: {
                ...(result && typeof result === "object" && !Array.isArray(result) ? result : {}),
                allocationPresenceCensus: host.inventorySeq + (inCensus ? 1 : 0),
                allocationPresenceEpoch: sender.connectionEpoch,
              },
            },
          });
          return { conflict: "released_instance_present" };
        }
      }
      const lease = await verifyHostLease(tx, sender, sandbox, entry);
      if ("conflict" in lease) return lease;
      const now = clock();
      const latched = entry.lease?.expired === true && entry.lease.expiryComplete;
      // The host refuses lifecycle work at or below a latched generation.
      const uncertain = await tx.sandboxOperation.findFirst({
        where: {
          userId: creatorId,
          sandboxId: sandbox.id,
          kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },
          generation: { gt: latched && entry.lease ? entry.lease.generation : 0 },
          OR: [
            { state: "UNKNOWN_OUTCOME" },
            { state: { in: [...ACTIVE_OPERATION_STATES] }, dispatchedHostId: { not: null } },
          ],
        },
        select: { id: true },
      });
      if (uncertain) return { converged: lease.adopted };
      // An entry naming an older lease arm proves nothing about the current
      // instance once a later create/reconnect succeeded: that allocation ran,
      // so the observation (typically a deferred expiry status captured before
      // it) describes a replaced generation. The uncertainty check above only
      // sees non-terminal allocations, so fence this case explicitly before
      // any lifecycle inference or teardown settlement.
      if (
        entry.lease != null &&
        entry.lease.generation < sandbox.generation &&
        (await laterAllocationMayHaveIssued(tx, sender, sandbox.id, entry.lease.generation))
      )
        return { converged: lease.adopted };
      if (sandbox.diskReservationHeld && (entry.state === "stopped" || entry.state === "absent")) {
        try {
          await requireRetainedStorage(tx, {
            hostId: sender.hostId,
            ownerId: creatorId,
            sandboxId: sandbox.id,
          });
        } catch {
          return (await retainedStorageStale(tx, sender, sandbox))
            ? { converged: lease.adopted, staleStorage: true }
            : { converged: lease.adopted };
        }
        const rootAbsent =
          entry.root?.state === "absent" &&
          entry.root.networkCleanupComplete &&
          entry.root.storagePoolName === sandbox.storagePoolName &&
          entry.root.storageMarker === sandbox.storageMarker &&
          entry.root.diskGiB === sandbox.diskGiB;
        if (entry.state === "absent" && !rootAbsent && !proof) {
          // VM absence proves no live effect. An orphan/unobserved root never
          // completes a destroy or permits detachment.
          if (
            ["READY", "STOPPED"].includes(sandbox.state) ||
            (sandbox.state === "ERROR" && sandbox.liveResourcesHeld)
          ) {
            // With no root evidence at all, nothing the host claims (its
            // `expired` flag included) moves a running record: only the
            // server's own due lease does. A pending teardown below is the
            // server's own record and keeps settling on VM absence.
            const serverExpiryDue =
              sandbox.leaseExpiresAtEffective != null &&
              sandbox.leaseExpiresAtEffective.getTime() <= now.getTime();
            if (!entry.root && (censusRootless || !serverExpiryDue)) {
              // A pending stop/kill of a held ERROR row is the server's own
              // record: VM absence settles it, as it does from STOPPING.
              if (
                sandbox.state === "ERROR" &&
                (await settlePendingTeardown(tx, sender, sandbox, entry, null, now))
              )
                return { converged: true };
              return { converged: lease.adopted };
            }
            // Without root evidence the disk reservation
            // stays held, so the host keeps its rootless retry until root
            // evidence settles the rest (partial convergence is not converged).
            const moved = await convergeStoppedOrMissing(tx, sender, sandbox, "absent", null, now);
            return { converged: moved && entry.root?.state === "present" };
          }
          // VM absence can settle a pending stop even when its retained root
          // is unobserved. Destroy still requires exact root/network proof.
          if (
            ["STOPPING", "RECLAIMING", "ERROR"].includes(sandbox.state) &&
            (await settlePendingTeardown(tx, sender, sandbox, entry, null, now))
          )
            return { converged: true };
          if (censusRootless) return { converged: lease.adopted };
          const released = await releaseLiveResourcesOnInventoryProof(tx, {
            hostId: sender.hostId,
            ownerId: creatorId,
            sandboxId: sandbox.id,
          });
          // As above: rootless absence leaves the disk held, not converged.
          return { converged: entry.root?.state === "present" && (released || lease.adopted) };
        }
      }
      // Only the host's own deadline timer is expiry evidence; an explicit
      // stop/kill latches too but proves nothing about the lease.
      const hostExpired =
        lease.verified &&
        lease.current &&
        latched &&
        entry.lease?.timerExpired &&
        entry.lease.lease.deadlineUnixMs <= now.getTime()
          ? entry.lease
          : null;
      const failure =
        lease.verified && lease.current && entry.lease?.expired && !entry.lease.expiryComplete
          ? (entry.lease.expiryFailure ?? null)
          : null;
      let converged = false;
      if (failure)
        converged = await recordExpiryFailure(
          tx,
          sender,
          sandbox,
          safeOperationError("expiry_failed").message,
        );
      else if (sandbox.state === "STOPPED" && entry.state === "stopped")
        converged = await recordSettledHostExpiry(tx, sender, sandbox, hostExpired, now);
      // ERROR included: a failed expiry moves a STOPPING/RECLAIMING sandbox to
      // ERROR while its stop/kill stays pending; recovery settles that operation.
      else if (
        (sandbox.state === "STOPPING" ||
          sandbox.state === "RECLAIMING" ||
          sandbox.state === "ERROR") &&
        (await settlePendingTeardown(tx, sender, sandbox, entry, hostExpired, now))
      )
        converged = true;
      else if (
        (sandbox.state === "READY" && (entry.state === "stopped" || entry.state === "absent")) ||
        (sandbox.state === "STOPPED" && entry.state === "absent") ||
        // A failed stop/kill keeps its FAILED operation; later host cleanup still
        // proves the end state. Absence without destroy proof only frees a held slot.
        (sandbox.state === "ERROR" &&
          (entry.state === "stopped" ||
            (entry.state === "absent" &&
              (sandbox.liveResourcesHeld || hostExpired?.lease.action === "destroy"))))
      )
        converged = await convergeStoppedOrMissing(
          tx,
          sender,
          sandbox,
          entry.state,
          hostExpired,
          now,
        );
      requireRelayFence(sender.isCurrent?.() !== false);
      return { converged: converged || lease.adopted };
    },
    { stale: true },
  );
}

export type AllocationProof = {
  connectionEpoch: number;
  barrier: number;
  journalId: string;
  root?: { storageMarker: string; storagePoolName: string; diskGiB: number };
};

/** Only called with an exact outstanding, session-bound targeted response.
 * H/S/O serialize result/teardown and the DB clock follows all locks. */
async function settleUnissuedAllocationAbsence(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandbox: ConvergeRow,
  proof: AllocationProof,
): Promise<boolean> {
  const { connectionEpoch: barrierEpoch, journalId } = proof;
  if (
    journalId === undefined ||
    barrierEpoch !== sender.connectionEpoch ||
    !sandbox.liveResourcesHeld ||
    !["REQUESTED", "SCHEDULED", "PROVISIONING", "READY", "STOPPED"].includes(sandbox.state) ||
    sandbox.generation >= 2_147_483_647
  )
    return false;
  const host = await tx.sandboxHost.findFirst({
    where: { id: sender.hostId, userId: sender.userId, connectionEpoch: barrierEpoch },
    select: {
      relayProtocolVersion: true,
      relayProtocolEpoch: true,
      admissionEpoch: true,
      daemonFeatures: true,
    },
  });
  if (
    host?.relayProtocolEpoch !== barrierEpoch ||
    host.relayProtocolVersion !== "1.0" ||
    host.admissionEpoch !== barrierEpoch ||
    !host.daemonFeatures ||
    typeof host.daemonFeatures !== "object" ||
    Array.isArray(host.daemonFeatures) ||
    host.daemonFeatures.journalId !== journalId
  )
    return false;
  const operation = await tx.sandboxOperation.findFirst({
    where: {
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      generation: sandbox.generation,
      kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },
      // Reconciliation first marks lost old-session results UNKNOWN; targeted
      // requests then run independently of general inventory convergence.
      state: "UNKNOWN_OUTCOME",
      dispatchedHostId: sender.hostId,
      dispatchedConnectionEpoch: { lte: barrierEpoch },
      dispatchAttempt: { gt: 0 },
    },
    select: {
      id: true,
      kind: true,
      state: true,
      dispatchAttempt: true,
      dispatchedConnectionEpoch: true,
      completedAt: true,
      generation: true,
      launchMode: true,
      restoreOffloadId: true,
    },
  });
  if (!operation) return false;
  await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${operation.id} AND "userId" = ${sandbox.userId} FOR UPDATE`;
  // A restore attempt is a new root with create
  // proofs. Its lineage's earlier launches ran on other hosts (or on this
  // one under an older placement whose cleanup the daemon's watermark
  // fences: its answer is never "never issued" then), so the journal
  // history is scoped to the attempts since this restore's placement.
  const restore = restoreOffloadOf(operation) !== null;
  if (
    !(await allocationJournalHistoryMatches(
      tx,
      sender,
      sandbox.id,
      proof,
      restore ? operation.generation : undefined,
    ))
  )
    return false;
  const now = await hostDatabaseNow(tx);
  const failed = await tx.sandboxOperation.updateMany({
    where: {
      id: operation.id,
      userId: sandbox.userId,
      generation: sandbox.generation,
      state: operation.state,
      dispatchAttempt: operation.dispatchAttempt,
      dispatchedHostId: sender.hostId,
      dispatchedConnectionEpoch: operation.dispatchedConnectionEpoch,
    },
    data: {
      state: "FAILED",
      // C26: UNKNOWN's first completion owns the retention deadline.
      completedAt: operation.completedAt ?? now,
      errorCode: "host_effect_not_issued",
      errorDetail: "Host proved this allocation was never issued.",
    },
  });
  requireRelayFence(failed.count === 1);
  // Never issued: the launch's leases settle now (no result will).
  await settleOperationCredentials(tx, {
    sandboxId: sandbox.id,
    operation,
    opState: "FAILED",
  });
  // §8.7: a restore proven never issued (root absence plus first-attempt
  // evidence, the daemon's answer) ends through the restore exit.
  if (
    restore &&
    (await exitRestoreAttempt(tx, {
      sandboxId: sandbox.id,
      userId: sandbox.userId,
      attemptOperationId: operation.id,
      attemptGeneration: operation.generation,
      proof: { kind: "no_effect", reason: "host_effect_not_issued" },
    }))
  )
    return true;
  if (sandbox.diskReservationHeld) {
    try {
      await requireRetainedStorage(tx, {
        hostId: sender.hostId,
        ownerId: sandbox.userId,
        sandboxId: sandbox.id,
      });
    } catch {
      return false;
    }
    const first = await tx.sandboxOperation.findFirst({
      where: { id: operation.id },
      select: { kind: true },
    });
    // A restore's new root is released on the same create proof (U3).
    if (first?.kind === "CREATE_SANDBOX" || restore)
      await releaseRootResources(tx, {
        hostId: sender.hostId,
        ownerId: sandbox.userId,
        sandboxId: sandbox.id,
      });
  }
  // Reuse generation advancement, lifecycle convergence, supersession and the
  // reservation release CAS. A late result can neither undo FAILED nor match S.
  return convergeStoppedOrMissing(tx, sender, sandbox, "absent", null, now, true);
}

/** Every attempt in the sandbox's allocation history must have targeted this
 * same durable journal. Missing/pruned pre-upgrade metadata proves nothing.
 * The dispatch writer records/invalidates each attempt binding under H/S/O.
 * H/S are held here; reads are bounded and do not acquire another sandbox. */
async function allocationJournalHistoryMatches(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandboxId: string,
  proof: AllocationProof,
  /** A restore attempt's generation: only its own and later attempts count. */
  sinceGeneration?: number,
): Promise<boolean> {
  const creatorId = (await requireRelayWorkload(tx, sender, { sandboxId })).sandboxOwnerId;
  const { journalId, barrier, connectionEpoch } = proof;
  let cursor: string | undefined;
  for (;;) {
    const operations = await tx.sandboxOperation.findMany({
      where: {
        userId: creatorId,
        sandboxId,
        kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },
        dispatchAttempt: { gt: 0 },
        ...(sinceGeneration !== undefined ? { generation: { gte: sinceGeneration } } : {}),
        ...(cursor ? { id: { gt: cursor } } : {}),
      },
      orderBy: { id: "asc" },
      take: 64,
      select: {
        id: true,
        generation: true,
        dispatchAttempt: true,
        dispatchedHostId: true,
        dispatchedConnectionEpoch: true,
      },
    });
    for (const operation of operations) {
      if (operation.dispatchedHostId !== sender.hostId) return false;
      const event = await tx.outboxEvent.findFirst({
        where: {
          userId: creatorId,
          aggregateType: "sandbox",
          aggregateId: sandboxId,
          eventType: { in: ["sandbox.create_requested", "sandbox.reconnect_requested"] },
          ...outboxOperationWhere(operation.id),
        },
        orderBy: { id: "asc" },
        select: { payload: true },
      });
      const payload = event?.payload;
      if (
        !payload ||
        typeof payload !== "object" ||
        Array.isArray(payload) ||
        payload.generation !== operation.generation ||
        payload.allocationJournalId !== journalId ||
        payload.allocationJournalAttempt !== operation.dispatchAttempt ||
        payload.allocationJournalEpoch !== operation.dispatchedConnectionEpoch ||
        operation.dispatchedConnectionEpoch === null ||
        operation.dispatchedConnectionEpoch > connectionEpoch ||
        (operation.dispatchedConnectionEpoch === connectionEpoch &&
          (typeof payload.allocationDispatchSequence !== "number" ||
            !Number.isSafeInteger(payload.allocationDispatchSequence) ||
            payload.allocationDispatchSequence <= 0 ||
            payload.allocationDispatchSequence >= barrier))
      )
        return false;
    }
    if (operations.length < 64) return true;
    cursor = operations.at(-1)?.id;
  }
}

/** The host may only hold a lease tuple this server sent it, never a newer
 * generation or revision. A lost ACK is recovered from the immutable dispatch
 * payload; a pruned payload leaves the tuple unverified (no inference). A tuple
 * from an earlier generation is still the instance's arm (`current`) when no
 * later create/reconnect was ever dispatched: stop and kill keep the timer. */
async function verifyHostLease(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandbox: ConvergeRow,
  entry: ObservedEntry,
): Promise<
  { conflict: QuarantineReason } | { verified: boolean; current: boolean; adopted: boolean }
> {
  const unverified = { verified: false, current: false, adopted: false };
  const reported = entry.lease;
  if (!reported) return unverified;
  if (reported.generation > sandbox.generation) return { conflict: "generation_ahead" };
  if (reported.lease.revision > sandbox.leaseRevision) return { conflict: "lease_ahead" };
  const effective = sandbox.leaseRevisionEffective;
  if (effective != null && reported.lease.revision < effective)
    return reported.generation === sandbox.generation
      ? { conflict: "lease_regressed" }
      : unverified;
  const current =
    reported.generation === sandbox.generation ||
    !(await laterAllocationMayHaveRun(tx, sender, sandbox.id, reported.generation));
  if (effective != null && reported.lease.revision === effective) {
    const same =
      sandbox.leaseExpiresAtEffective?.getTime() === reported.lease.deadlineUnixMs &&
      sandbox.leaseExpireActionEffective === wireAction(reported.lease.action);
    if (same) return { verified: true, current, adopted: false };
    // A shorten-only system renewal's ACK echoes the queued deadline; the
    // host stored it clamped to an earlier one. Adopt the host's truth (only
    // ever earlier, never later).
    const clampedEarlier =
      reported.lease.shortenOnly === true &&
      sandbox.leaseExpiresAtEffective != null &&
      reported.lease.deadlineUnixMs < sandbox.leaseExpiresAtEffective.getTime() &&
      sandbox.leaseExpireActionEffective === wireAction(reported.lease.action);
    if (!clampedEarlier) return { conflict: "lease_mismatch" };
    const corrected = await tx.sandbox.updateMany({
      where: {
        id: sandbox.id,
        userId: sandbox.userId,
        generation: sandbox.generation,
        leaseRevisionEffective: effective,
      },
      data: { leaseExpiresAtEffective: new Date(reported.lease.deadlineUnixMs) },
    });
    return { verified: true, current, adopted: corrected.count === 1 };
  }
  if (!current) return unverified;
  const event = await tx.outboxEvent.findFirst({
    where: {
      userId: sandbox.userId,
      aggregateType: "sandbox",
      aggregateId: sandbox.id,
      AND: [
        { payload: { path: ["generation"], equals: reported.generation } },
        { payload: { path: ["lease", "revision"], equals: reported.lease.revision } },
      ],
    },
    select: { payload: true },
  });
  const payload = event?.payload;
  const sent = leaseWireSchema.safeParse(
    payload && typeof payload === "object" && !Array.isArray(payload) ? payload.lease : undefined,
  );
  if (!sent.success) return unverified;
  // A shorten-only system renewal may be stored clamped to the earlier
  // deadline the host already held (never later than sent).
  const clamped =
    sent.data.shortenOnly === true &&
    reported.lease.shortenOnly === true &&
    reported.lease.deadlineUnixMs < sent.data.deadlineUnixMs;
  if (
    (sent.data.deadlineUnixMs !== reported.lease.deadlineUnixMs && !clamped) ||
    sent.data.action !== reported.lease.action
  )
    return { conflict: "lease_mismatch" };
  // A queued payload is an intent, never proof it reached this host. Census
  // can recover only a tuple from a dispatched operation on the original host
  // and a nonfuture epoch. It cannot acknowledge an operation: only the exact
  // result/receipt bodyHash+attempt fence can do that.
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    typeof payload.operationId !== "string" ||
    typeof payload.idempotencyKey !== "string"
  )
    return unverified;
  const operation = await tx.sandboxOperation.findFirst({
    where: {
      id: payload.operationId,
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      generation: reported.generation,
      idempotencyKey: payload.idempotencyKey,
      kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX", "RENEW_SANDBOX_LEASE"] },
      dispatchAttempt: { gt: 0 },
      dispatchedHostId: sender.hostId,
      dispatchedConnectionEpoch: { lte: sender.connectionEpoch },
    },
    select: {
      leaseRevisionAccepted: true,
      leaseExpiresAtAccepted: true,
      leaseExpireActionAccepted: true,
    },
  });
  if (!operation) return unverified;
  if (
    operation.leaseRevisionAccepted != null &&
    (operation.leaseRevisionAccepted !== reported.lease.revision ||
      (operation.leaseExpiresAtAccepted?.getTime() !== reported.lease.deadlineUnixMs && !clamped) ||
      operation.leaseExpireActionAccepted !== wireAction(reported.lease.action))
  )
    return { conflict: "lease_mismatch" };
  // Same monotonic adoption as a durable lease ACK (C31).
  const adopted = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: sandbox.userId,
      generation: sandbox.generation,
      OR: [
        { leaseRevisionEffective: null },
        { leaseRevisionEffective: { lt: reported.lease.revision } },
      ],
    },
    data: {
      leaseRevisionEffective: reported.lease.revision,
      leaseExpiresAtEffective: new Date(reported.lease.deadlineUnixMs),
      leaseExpireActionEffective: wireAction(reported.lease.action),
    },
  });
  return { verified: true, current, adopted: adopted.count === 1 };
}

/** A create/reconnect after `generation` that issued, or may have issued,
 * host effects: it succeeded, or it reached a host and ended any way other
 * than a host proof that nothing was issued. Such an allocation may have
 * replaced the instance and its lease arm (a failed reconnect can boot the VM
 * before failing), so an older arm's evidence proves nothing about it. */
async function laterAllocationMayHaveIssued(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandboxId: string,
  generation: number,
): Promise<boolean> {
  const creatorId = (await requireRelayWorkload(tx, sender, { sandboxId })).sandboxOwnerId;
  const reached = { dispatchedHostId: { not: null } };
  const later = await tx.sandboxOperation.findFirst({
    where: {
      userId: creatorId,
      sandboxId,
      kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },
      generation: { gt: generation },
      OR: [
        { state: "SUCCEEDED" },
        { ...reached, state: { not: "FAILED" } },
        { ...reached, state: "FAILED", errorCode: null },
        { ...reached, state: "FAILED", errorCode: { not: "host_effect_not_issued" } },
      ],
    },
    select: { id: true },
  });
  return later != null;
}

const retainedPoolSelect = {
  health: true,
  connectionEpoch: true,
  reportedAt: true,
} satisfies Prisma.SandboxHostStoragePoolSelect;

/** The retained-storage gate refused only because the pool's healthy
 * observation is not this epoch's or has aged out, so a current observation
 * may pass it. An unhealthy verdict is not staleness. */
async function retainedStorageStale(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandbox: ConvergeRow,
): Promise<boolean> {
  if (!sandbox.storageMarker || !sandbox.storagePoolName) return false;
  const pool = await tx.sandboxHostStoragePool.findFirst({
    where: {
      sandboxHostId: sender.hostId,
      userId: sender.userId,
      marker: sandbox.storageMarker,
      name: sandbox.storagePoolName,
    },
    select: retainedPoolSelect,
  });
  if (pool?.health !== "healthy") return false;
  const now = await hostDatabaseNow(tx);
  return (
    pool.connectionEpoch !== sender.connectionEpoch ||
    now.getTime() - pool.reportedAt.getTime() > STORAGE_HEALTH_STALE_MS
  );
}

/** A create/reconnect after `generation` that reached a host may have
 * replaced the instance and its lease arm. */
async function laterAllocationMayHaveRun(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandboxId: string,
  generation: number,
): Promise<boolean> {
  const creatorId = (await requireRelayWorkload(tx, sender, { sandboxId })).sandboxOwnerId;
  const later = await tx.sandboxOperation.findFirst({
    where: {
      userId: creatorId,
      sandboxId,
      kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },
      generation: { gt: generation },
      dispatchedHostId: { not: null },
    },
    select: { id: true },
  });
  return later != null;
}

/** A pending stop/kill is completed by its observed end state: one the host
 * never received, one still in flight, or one whose receipt reported an
 * uncertain outcome (including receipts adopted into this epoch). It is never
 * dispatched afterwards, so no destructive effect repeats. */
/**
 * The census rule for a STOPPED sandbox with `diskOffloadId` STORED or
 * EVICTING, and for a PROVISIONING or ERROR row
 * still holding it with no launch or teardown in flight (I3, through
 * `detachOnCensusAbsence`; one with work in flight is left to that work). VM absent: with the census's exact,
 * current root-absence proof, detach to OFFLOADED (the root reservation is
 * released); otherwise the hold moves to a `SandboxDiskCopy(STALE)` (create
 * key and base fingerprint recorded) and the sandbox detaches, the copy left
 * to discard. Never ERROR or DELETED. VM present: an expired grant's marker
 * is cleared ("Expired grant without proof"), and the ordinary convergence
 * continues. Null: not ruled here. Caller holds owners → H → S.
 */
async function censusCachedCopy(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandbox: ConvergeRow,
  entry: ObservedEntry,
): Promise<EntryOutcome | null> {
  if (!sandbox.diskOffloadId) return null;
  const [offload] = await tx.$queryRaw<
    { state: string; expiresAt: Date | null }[]
  >`SELECT state::text AS state, "evictGrantExpiresAt" AS "expiresAt" FROM sandbox_disk_offload
    WHERE id = ${sandbox.diskOffloadId} AND "sandboxId" = ${sandbox.id} FOR UPDATE`;
  if (!offload || !["STORED", "EVICTING"].includes(offload.state)) return null;
  const now = await hostDatabaseNow(tx);
  if (entry.state !== "absent") {
    if (offload.state === "EVICTING" && offload.expiresAt && offload.expiresAt <= now)
      await clearEvictMarker(tx, sandbox.diskOffloadId);
    return null;
  }
  // An uncertain create/reconnect the host might still run blocks inference.
  const uncertain = await tx.sandboxOperation.findFirst({
    where: {
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      OR: [{ state: "UNKNOWN_OUTCOME" }, { state: { in: [...ACTIVE_OPERATION_STATES] } }],
    },
    select: { id: true },
  });
  // A PROVISIONING/ERROR row with work in flight (a restore attempt, a
  // pending SYSTEM_DETACH kill) is left to its own settlement below.
  if (uncertain) return sandbox.state === "STOPPED" ? { converged: false } : null;
  let rootProof = false;
  if (entry.root && rootProofMatches(entry.root, sandbox)) {
    // Only current evidence proves absence (never older than the pool's
    // own observation on this epoch).
    const pool = await tx.sandboxHostStoragePool.findFirst({
      where: {
        sandboxHostId: sender.hostId,
        userId: sender.userId,
        marker: entry.root.storageMarker,
        name: entry.root.storagePoolName,
      },
      select: { connectionEpoch: true, observationSequence: true },
    });
    rootProof =
      pool != null &&
      pool.connectionEpoch === sender.connectionEpoch &&
      BigInt(entry.root.observationSequence) >= pool.observationSequence;
  }
  if (sandbox.state !== "STOPPED")
    return {
      converged: await detachOnCensusAbsence(tx, { sandbox, hostId: sender.hostId, rootProof }),
    };
  const detached = await detachToOffloaded(tx, {
    sandboxId: sandbox.id,
    userId: sandbox.userId,
    hostId: sender.hostId,
    generation: sandbox.generation,
    proof: rootProof
      ? { kind: "root_absent" }
      : { kind: "stale_copy", ...(await staleCopyIdentity(tx, sandbox)) },
  });
  return { converged: detached };
}

async function settlePendingTeardown(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandbox: ConvergeRow,
  entry: ObservedEntry,
  hostExpired: InventoryEntry["lease"] | null,
  now: Date,
): Promise<boolean> {
  const operation = await tx.sandboxOperation.findFirst({
    where: {
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      generation: sandbox.generation,
      kind: { in: ["STOP_SANDBOX", "KILL_SANDBOX"] },
      state: { in: [...ACTIVE_OPERATION_STATES, "UNKNOWN_OUTCOME"] },
    },
    select: {
      id: true,
      kind: true,
      state: true,
      idempotencyKey: true,
      dispatchAttempt: true,
      dispatchedConnectionEpoch: true,
      teardownIntent: true,
    },
  });
  if (!operation || (operation.kind !== "STOP_SANDBOX" && operation.kind !== "KILL_SANDBOX"))
    return false;
  const endState =
    operation.kind === "KILL_SANDBOX"
      ? entry.state === "absent"
        ? "deleted"
        : null
      : entry.state === "stopped" || entry.state === "absent"
        ? entry.state
        : null;
  if (!endState) return false;
  if (
    operation.kind === "KILL_SANDBOX" &&
    sandbox.diskReservationHeld &&
    !(entry.root?.state === "absent" && entry.root.networkCleanupComplete)
  )
    return false;
  const next =
    operation.kind === "STOP_SANDBOX" && sandbox.diskReservationHeld
      ? "STOPPED"
      : sandboxStateForLifecycleResult(
          operation.kind,
          "SUCCEEDED",
          endState,
          undefined,
          undefined,
          undefined,
          operation.teardownIntent,
        );
  // M2: the kill's `teardownIntent` decides; a SYSTEM_DETACH kill of a
  // sandbox whose disk is offloaded ends OFFLOADED (detach, below).
  requireRelayFence(next === "STOPPED" || next === "DELETED" || next === "OFFLOADED");
  const settled = await tx.sandboxOperation.updateMany({
    where: {
      id: operation.id,
      userId: sandbox.userId,
      state: operation.state,
      dispatchAttempt: operation.dispatchAttempt,
      dispatchedConnectionEpoch: operation.dispatchedConnectionEpoch,
    },
    data: {
      state: "SUCCEEDED",
      completedAt: now,
      dispatchedHostId: sender.hostId,
      dispatchedConnectionEpoch: sender.connectionEpoch,
      errorCode: null,
      errorDetail: null,
      result: { state: endState },
    },
  });
  requireRelayFence(settled.count === 1);
  if (next === "OFFLOADED") {
    // §8.7 (U5, U7): the kill's root/network absence is the detach proof
    // (§8.2); the census settles it through the restore exit's kill arm
    // (live release, the attempt's credentials, the only OFFLOADED writer)
    // instead of `finishConvergence`.
    requireRelayFence(
      await settleSystemDetachKill(tx, {
        sandboxId: sandbox.id,
        userId: sandbox.userId,
        hostId: sender.hostId,
        generation: sandbox.generation,
        killOperationId: operation.id,
      }),
    );
    await settleSupersededOperations(
      tx,
      {
        userId: sandbox.userId,
        sandboxId: sandbox.id,
        generation: sandbox.generation,
        kind: operation.kind,
        state: "SUCCEEDED",
      },
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
  // Whichever operation settles, a verified timer expiry whose action explains
  // the observed end state is recorded as host-enforced.
  const offlineExpiry = hostExpired != null && expiryExplains(hostExpired, entry.state);
  await finishConvergence(tx, sender, sandbox, {
    next,
    generation: sandbox.generation,
    kind: operation.kind,
    operationId: operation.id,
    offlineExpiry: offlineExpiry
      ? { revision: hostExpired.lease.revision, action: wireAction(hostExpired.lease.action) }
      : null,
    now,
  });
  return true;
}

/**
 * A DELETED sandbox whose VM this node still reports. The sandbox stays
 * DELETED and the node stays schedulable; the remnant alone is contained:
 *  - its boot charge (the current placement's pinned RAM/vCPU) is counted
 *    against this node again, so placement cannot oversubscribe it;
 *  - one system destroy at a fresh generation is queued to this node through
 *    the ordinary kill dispatch, owner/host/epoch/generation fenced.
 * Idempotent: a destroy still in flight for the current generation is the
 * obligation, so repeated (or concurrent, serialized on H → S) reports add
 * nothing. A failed or uncertain one is replaced by the next report. The
 * charge is released only by host proof: the destroy's success, or absence
 * in a later census (`settleRemnantAbsence`). Caller holds H and S.
 */
async function obligeRemnantDestroy(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandbox: ConvergeRow,
  now: Date,
): Promise<void> {
  if (sandbox.hostOwnerId !== sender.userId || sandbox.generation >= 2_147_483_647) return;
  const pending = await tx.sandboxOperation.findFirst({
    where: {
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      kind: "KILL_SANDBOX",
      generation: sandbox.generation,
      state: { in: [...ACTIVE_OPERATION_STATES] },
    },
    select: { id: true },
  });
  if (pending && sandbox.sandboxHostId === sender.hostId) return;
  const placement = sandbox.currentPlacementId
    ? await tx.sandboxPlacement.findFirst({
        where: { id: sandbox.currentPlacementId, sandboxId: sandbox.id, userId: sandbox.userId },
        select: { chargedMemoryMiB: true, chargedVcpu: true, storagePoolId: true },
      })
    : null;
  if (!placement) return;
  // Re-attaching restores the placement's pool pin (detach cleared it), so the
  // release path sees the allocation it pinned. A retired pool cannot be pinned.
  if (
    placement.storagePoolId != null &&
    !(await tx.sandboxHostStoragePool.findFirst({
      where: {
        id: placement.storagePoolId,
        sandboxHostId: sender.hostId,
        userId: sender.userId,
        marker: sandbox.storageMarker ?? undefined,
        name: sandbox.storagePoolName ?? undefined,
      },
      select: { id: true },
    }))
  )
    return;
  const hold = !sandbox.liveResourcesHeld;
  const generation = sandbox.generation + 1;
  const written = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: sandbox.userId,
      generation: sandbox.generation,
      state: "DELETED",
      hostOwnerId: sender.userId,
      liveResourcesHeld: sandbox.liveResourcesHeld,
      OR: [{ sandboxHostId: sender.hostId }, { sandboxHostId: null }],
    },
    data: {
      generation,
      sandboxHostId: sender.hostId,
      storagePoolId: placement.storagePoolId,
      ...(hold ? { liveResourcesHeld: true } : {}),
    },
  });
  requireRelayFence(written.count === 1);
  if (hold) {
    const charged = await tx.sandboxHost.updateMany({
      where: { id: sender.hostId, userId: sender.userId, connectionEpoch: sender.connectionEpoch },
      data: {
        liveCount: { increment: 1 },
        memoryReservedMiB: { increment: placement.chargedMemoryMiB },
        vcpuReserved: { increment: placement.chargedVcpu },
      },
    });
    requireRelayFence(charged.count === 1);
  }
  await retireSupersededOperations(tx, sandbox.userId, sandbox.id, generation, now);
  // Already DELETED: login leases were settled; re-settle under the new generation.
  await settleCredentialsOnDeleted(tx, sandbox.id);
  const idempotencyKey = inventoryObservationIdempotencyKey(sandbox.id, generation);
  const operation = await tx.sandboxOperation.create({
    data: {
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      kind: "KILL_SANDBOX",
      state: "QUEUED",
      generation,
      teardownPriorState: "DELETED",
      idempotencyKey,
      requestBodyHash: hashOperationRequestBody(
        { sandboxId: sandbox.id, action: "remnant-destroy", generation },
        "KILL_SANDBOX",
      ),
      ...requestDigestMetadata("KILL_SANDBOX"),
      digestContext: digestContextSnapshot({ domain: ENV_FREE_DIGEST_DOMAIN }, { generation }),
    },
    select: { id: true },
  });
  await tx.outboxEvent.create({
    data: {
      userId: sandbox.userId,
      aggregateType: "sandbox",
      aggregateId: sandbox.id,
      eventType: "sandbox.kill_requested",
      operationId: operation.id,
      payload: {
        sandboxId: sandbox.id,
        sandboxHostId: sender.hostId,
        generation,
        dispatchAttempt: 0,
        operationId: operation.id,
        idempotencyKey,
        kind: OPERATION_DISPATCH_KIND.KILL_SANDBOX,
        incusName: defaultIncusInstanceName(sandbox.id),
        authorizingPrincipal: systemAttribution(),
        credentialTeardown: "system",
      },
    },
  });
}

/** Absence of a remnant this node is charged for: settle its pending destroy
 * (or, without one, just the charge) and detach again. Caller holds H and S. */
async function settleRemnantAbsence(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandbox: ConvergeRow,
  entry: ObservedEntry,
  now: Date,
): Promise<boolean> {
  if (sandbox.sandboxHostId !== sender.hostId || !sandbox.liveResourcesHeld) return false;
  if (await settlePendingTeardown(tx, sender, sandbox, entry, null, now)) return true;
  await finishConvergence(tx, sender, sandbox, {
    next: "DELETED",
    generation: sandbox.generation,
    kind: "KILL_SANDBOX",
    operationId: null,
    offlineExpiry: null,
    now,
  });
  return true;
}

const FAILABLE_ON_EXPIRY: ReadonlySet<SandboxState> = new Set(["READY", "STOPPING", "RECLAIMING"]);

const expiryExplains = (expiry: NonNullable<InventoryEntry["lease"]>, observed: string) =>
  expiry.lease.action === "destroy" ? observed === "absent" : observed === "stopped";

/** The host is still trying to enforce an expiry. The sandbox is shown failed
 * with the host's reason and keeps its live slot: nothing is proven stopped.
 * A pending stop/kill (for example a server-queued expiry) is left unsettled,
 * so the host's later completion settles it like any other observation. */
async function recordExpiryFailure(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandbox: ConvergeRow,
  reason: string,
): Promise<boolean> {
  if (
    sandbox.lastErrorCode === "expiry_failed" &&
    sandbox.lastErrorDetail === reason &&
    !FAILABLE_ON_EXPIRY.has(sandbox.state)
  )
    return false;
  const written = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: sandbox.userId,
      sandboxHostId: sender.hostId,
      generation: sandbox.generation,
      state: sandbox.state,
    },
    data: {
      ...(FAILABLE_ON_EXPIRY.has(sandbox.state) ? { state: "ERROR" as const } : {}),
      lastErrorCode: "expiry_failed",
      lastErrorDetail: reason,
    },
  });
  requireRelayFence(written.count === 1);
  return true;
}

/** Some other operation (for example an uncertain user stop's receipt)
 * already settled the end state; a verified timer expiry still records the
 * host-enforced truth, once. A completed expiry of the CURRENT arm also
 * proves nothing running can still be claimed by it: a slot an uncertain
 * cold reconnect left held is freed, and that allocation is settled. An
 * older arm cannot fence a newer generation's queued start. */
async function recordSettledHostExpiry(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandbox: ConvergeRow,
  hostExpired: InventoryEntry["lease"] | null,
  now: Date,
): Promise<boolean> {
  const expiry = hostExpired && expiryExplains(hostExpired, "stopped") ? hostExpired : null;
  const action = expiry ? wireAction(expiry.lease.action) : null;
  const record =
    expiry != null &&
    (sandbox.hostExpiryRevision !== expiry.lease.revision || sandbox.hostExpiryAction !== action);
  // A failure reported earlier is cleared once the host stops reporting it.
  const clear = sandbox.lastErrorCode === "expiry_failed";
  const release =
    expiry != null && expiry.generation === sandbox.generation && sandbox.liveResourcesHeld;
  if (!record && !clear && !release) return false;
  const written = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: sandbox.userId,
      sandboxHostId: sender.hostId,
      generation: sandbox.generation,
      state: "STOPPED",
    },
    data: {
      ...(clear ? { lastErrorCode: null, lastErrorDetail: null } : {}),
      ...(record && expiry
        ? {
            hostExpiryConfirmedAt: now,
            hostExpiryRevision: expiry.lease.revision,
            hostExpiryAction: action,
          }
        : {}),
    },
  });
  requireRelayFence(written.count === 1);
  if (release && expiry) {
    // Cleanup is proven for every allocation at or below the expired arm; an
    // uncertain one can no longer produce a running instance. Same convention
    // as settleSupersededOperations: stop proof settles to CANCELLED.
    await tx.sandboxOperation.updateMany({
      where: {
        userId: sandbox.userId,
        sandboxId: sandbox.id,
        kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX"] },
        generation: { lte: expiry.generation },
        state: "UNKNOWN_OUTCOME",
      },
      data: { state: "CANCELLED", completedAt: now },
    });
    await releaseLiveResourcesOnInventoryProof(tx, {
      hostId: sender.hostId,
      ownerId: sandbox.userId,
      sandboxId: sandbox.id,
    });
  }
  return true;
}

/** Connected expiry status judged per entry,
 * like a census page, so the host re-offers whatever did not converge.
 * An expired lease supplies expiry evidence; any other entry is census
 * evidence the host re-offers (for
 * example one refused for stale storage), judged by the census rules, but
 * only when `predates` (the session's observation fence) proves the
 * observation began after every lifecycle result received for its sandbox.
 * Otherwise it is `superseded` untouched (the host re-observes it later): a reconnect's READY result can
 * overtake a stopped observation taken under its new lease, and the result
 * is the newer truth. The fence defaults closed. */
export async function judgeExpiryStatus(
  sender: RelaySender,
  entries: readonly InventoryEntry[],
  clock: LeaseClock = leaseNow,
  predates: (sandboxId: string) => boolean = () => true,
): Promise<{ results: CensusEntryResult[] } | { stale: true }> {
  const results: CensusEntryResult[] = [];
  for (const entry of entries) {
    const expired = entry.lease?.expired === true;
    if (!expired && predates(entry.sandboxId)) {
      // Not a verdict on the evidence: the host observes it again later.
      results.push({ sandboxId: entry.sandboxId, outcome: "superseded" });
      continue;
    }
    const outcome = await convergeInventoryEntry(sender, entry, clock, undefined, false, !expired);
    if ("stale" in outcome) return outcome;
    if ("conflict" in outcome) {
      if (outcome.conflict === "released_instance_present")
        await quarantineHost(sender, outcome.conflict, clock());
      else logContainedConflict(sender, entry.sandboxId, outcome.conflict);
      results.push({ sandboxId: entry.sandboxId, outcome: "not_converged" });
      continue;
    }
    results.push({
      sandboxId: entry.sandboxId,
      outcome: outcome.staleStorage
        ? "stale_storage"
        : outcome.converged
          ? "converged"
          : "not_converged",
    });
  }
  return { results };
}

/** Operator evidence for a contained disagreement: ids and the reason only. */
function logContainedConflict(sender: RelaySender, sandboxId: string, reason: QuarantineReason) {
  console.warn(
    `[sandbox-relay] inventory conflict contained to its sandbox host=${sender.hostId} sandbox=${sandboxId} reason=${reason}`,
  );
}

/** READY/STOPPED/ERROR disagreeing with the host. A new generation fences every
 * late create/renew/command result against the converged truth. */
async function convergeStoppedOrMissing(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandbox: ConvergeRow,
  observed: "stopped" | "absent",
  hostExpired: InventoryEntry["lease"] | null,
  now: Date,
  neverIssued = false,
): Promise<boolean> {
  if (sandbox.generation >= 2_147_483_647) return false;
  // Offload plan I3: a PROVISIONING or ERROR row that still holds its stored
  // disk is never written ERROR (or DELETED) on VM absence: it detaches to
  // OFFLOADED (a held root moves to a copy row; a released one is gone).
  if (
    observed === "absent" &&
    sandbox.diskOffloadId &&
    (sandbox.state === "PROVISIONING" || sandbox.state === "ERROR")
  )
    return detachOnCensusAbsence(tx, {
      sandbox,
      hostId: sender.hostId,
      rootProof: !sandbox.diskReservationHeld,
    });
  const generation = sandbox.generation + 1;
  const expiryAction = hostExpired ? wireAction(hostExpired.lease.action) : null;
  const evidence =
    observed === "stopped"
      ? { kind: "STOP_SANDBOX" as const, endState: "stopped", next: "STOPPED" as const }
      : // A host-reported expiry DESTROY is never a DELETED cause while the
        // sandbox's disk is offloaded.
        expiryAction === "DESTROY" && sandbox.diskOffloadId == null
        ? { kind: "KILL_SANDBOX" as const, endState: "deleted", next: "DELETED" as const }
        : null;
  // An expiry is attributed only when the host's action explains the observation.
  const offlineExpiry =
    hostExpired &&
    evidence &&
    expiryAction &&
    (evidence.kind === "KILL_SANDBOX" ? expiryAction === "DESTROY" : expiryAction === "STOP")
      ? { revision: hostExpired.lease.revision, action: expiryAction }
      : null;
  const written = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: sandbox.userId,
      sandboxHostId: sender.hostId,
      generation: sandbox.generation,
      state: sandbox.state,
    },
    data: {
      generation,
      ...(evidence
        ? { lastErrorCode: null, lastErrorDetail: null }
        : {
            lastErrorCode: neverIssued ? "host_effect_not_issued" : "instance_missing",
            lastErrorDetail: neverIssued
              ? "Host proved this allocation was never issued."
              : "Host inventory reports no instance for this sandbox.",
          }),
    },
  });
  requireRelayFence(written.count === 1);
  let operationId: string | null = null;
  if (evidence) {
    const action = offlineExpiry && hostExpired ? hostExpired.lease : null;
    const idempotencyKey = action
      ? leaseExpiryIdempotencyKey(
          sandbox.id,
          generation,
          action.revision,
          wireAction(action.action),
        )
      : inventoryObservationIdempotencyKey(sandbox.id, generation);
    const requestBodyHash = hashOperationRequestBody(
      action
        ? {
            sandboxId: sandbox.id,
            action: leaseExpiryDispatchAction(wireAction(action.action)),
            generation,
            leaseRevision: action.revision,
          }
        : { sandboxId: sandbox.id, action: "inventory-observed", generation },
      evidence.kind,
    );
    const operation = await tx.sandboxOperation.create({
      data: {
        userId: sandbox.userId,
        sandboxId: sandbox.id,
        kind: evidence.kind,
        state: "SUCCEEDED",
        generation,
        idempotencyKey,
        requestBodyHash,
        ...requestDigestMetadata(evidence.kind),
        digestContext: digestContextSnapshot({ domain: ENV_FREE_DIGEST_DOMAIN }, { generation }),
        completedAt: now,
        dispatchedHostId: sender.hostId,
        dispatchedConnectionEpoch: sender.connectionEpoch,
        result: { state: evidence.endState },
      },
      select: { id: true },
    });
    operationId = operation.id;
  }
  await retireSupersededOperations(tx, sandbox.userId, sandbox.id, generation, now);
  // CLI logins (§7.5 convergence settlement, P3-2).
  await settleCredentialConvergence(tx, {
    sandboxId: sandbox.id,
    generation,
    next: evidence?.next ?? "ERROR",
    operationId,
  });
  await finishConvergence(tx, sender, sandbox, {
    next: evidence?.next ?? "ERROR",
    generation,
    kind: evidence?.kind ?? "STOP_SANDBOX",
    operationId,
    offlineExpiry,
    now,
  });
  return true;
}

async function finishConvergence(
  tx: Prisma.TransactionClient,
  sender: RelaySender,
  sandbox: ConvergeRow,
  input: {
    next: SandboxState;
    generation: number;
    kind: "STOP_SANDBOX" | "KILL_SANDBOX";
    operationId: string | null;
    offlineExpiry: { revision: number; action: SandboxLeaseExpireAction } | null;
    now: Date;
  },
) {
  // U7/S17: OFFLOADED is written only by `detachToOffloaded`.
  requireRelayFence(input.next !== "OFFLOADED");
  // §8.9: a settled owner destroy ends the stored offload first (the only
  // clearer of `diskOffloadId`); no other census DELETED can pass the CHECK.
  if (input.next === "DELETED" && input.operationId && sandbox.diskOffloadId)
    await endOffloadForDestroy(tx, {
      sandboxId: sandbox.id,
      userId: sandbox.userId,
      destroyOperationId: input.operationId,
      now: input.now,
    });
  const changed = await tx.sandbox.updateMany({
    where: {
      id: sandbox.id,
      userId: sandbox.userId,
      generation: input.generation,
      sandboxHostId: sender.hostId,
    },
    data: {
      state: input.next,
      ...(input.next !== "ERROR" ? { lastErrorCode: null, lastErrorDetail: null } : {}),
      ...(input.offlineExpiry
        ? {
            hostExpiryConfirmedAt: input.now,
            hostExpiryRevision: input.offlineExpiry.revision,
            hostExpiryAction: input.offlineExpiry.action,
          }
        : {}),
    },
  });
  requireRelayFence(changed.count === 1);
  // A proven non-running instance holds no live slot; the CAS releases once.
  await releaseLiveResourcesOnInventoryProof(tx, {
    hostId: sender.hostId,
    ownerId: sandbox.userId,
    sandboxId: sandbox.id,
  });
  // CLI logins (§7.1): STOPPED releases resolved teardowns; DELETED settles
  // every lease and clears all residue, before the placement detach.
  if (input.next === "STOPPED") await settleCredentialsOnStopped(tx, sandbox.id);
  if (input.next === "DELETED") {
    await settleCredentialsOnDeleted(tx, sandbox.id);
    await releaseRootResources(tx, {
      hostId: sender.hostId,
      ownerId: sandbox.userId,
      sandboxId: sandbox.id,
    });
    const detached = await tx.sandbox.updateMany({
      where: {
        id: sandbox.id,
        userId: sandbox.userId,
        generation: input.generation,
        state: "DELETED",
        liveResourcesHeld: false,
        diskReservationHeld: false,
        sandboxHostId: sender.hostId,
      },
      data: { sandboxHostId: null, storagePoolId: null },
    });
    requireRelayFence(detached.count === 1);
  }
  await settleSupersededOperations(
    tx,
    {
      userId: sandbox.userId,
      sandboxId: sandbox.id,
      generation: input.generation,
      kind: input.kind,
      state: "SUCCEEDED",
    },
    input.now,
  );
  if (input.operationId)
    await tx.outboxEvent.updateMany({
      where: {
        userId: sandbox.userId,
        aggregateType: "sandbox",
        aggregateId: sandbox.id,
        processedAt: null,
        ...outboxOperationWhere(input.operationId),
      },
      data: { processedAt: input.now, claimToken: null, claimedAt: null },
    });
  noteHostBlockerReleased(tx, sender.hostId, sender.userId);
}

async function quarantineHost(sender: RelaySender, reason: QuarantineReason, now: Date) {
  await relayTransaction(async (tx) => {
    await lockOwnerForAdmission(tx, sender.userId);
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    await tx.sandboxHost.updateMany({
      where: {
        id: sender.hostId,
        userId: sender.userId,
        connectionEpoch: sender.connectionEpoch,
        // Remediation of a released placement cannot erase another identity
        // contradiction already observed in this census/session.
        ...(reason === "released_instance_present"
          ? {
              OR: [{ quarantineReason: null }, { quarantineReason: "released_instance_present" }],
            }
          : {}),
      },
      data: { quarantinedAt: now, quarantineReason: reason },
    });
    if (reason === "released_instance_present")
      await clearRetiredReleaseQuarantine(tx, sender.hostId, sender.userId);
  }, undefined);
}

/** Overflowed silence was not converged, but the census is still complete. */
async function recordCompleteCensus(
  sender: RelaySender,
  releasedConflict: boolean,
): Promise<boolean> {
  return relayTransaction(async (tx) => {
    await lockOwnerForAdmission(tx, sender.userId);
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    const receivedAt = await hostDatabaseNow(tx);
    const written = await tx.sandboxHost.updateMany({
      where: {
        id: sender.hostId,
        userId: sender.userId,
        connectionEpoch: sender.connectionEpoch,
      },
      data: {
        inventorySeq: { increment: 1 },
        inventoryAcknowledgedAt: receivedAt,
        inventoryAcknowledgedEpoch: sender.connectionEpoch,
      },
    });
    requireRelayFence(written.count === 1 && sender.isCurrent?.() !== false);
    // Census acknowledged: the host may now place (post-commit capacity wake).
    noteCapacityChanged(tx, { hostIds: [sender.hostId] });
    // Per-sandbox conflicts are contained and never quarantine the node, so a
    // completed census quarantines only for a released allocation still
    // present. Recompute the reason after each complete census.
    await tx.sandboxHost.updateMany({
      where: {
        id: sender.hostId,
        userId: sender.userId,
        connectionEpoch: sender.connectionEpoch,
      },
      data: {
        quarantinedAt: releasedConflict ? receivedAt : null,
        quarantineReason: releasedConflict ? "released_instance_present" : null,
      },
    });
    if (releasedConflict) await clearRetiredReleaseQuarantine(tx, sender.hostId, sender.userId);
    return true;
  }, false);
}

type HostAdmissionReport = Extract<DaemonControlMessage, { type: "host.admission" }>;
/** Owned by the registered session, independent of mutable census state. */
export type HostAdmissionState = { firstReport?: HostAdmissionReport };

function sameAdmission(a: HostAdmissionReport, b: HostAdmissionReport): boolean {
  return (
    a.connectionEpoch === b.connectionEpoch &&
    a.runtimeKind === b.runtimeKind &&
    a.schedulable === b.schedulable &&
    a.egressPolicy === b.egressPolicy &&
    (a.egressOpen === true) === (b.egressOpen === true) &&
    a.terminal === b.terminal &&
    a.journalId === b.journalId &&
    JSON.stringify(a.image ?? null) === JSON.stringify(b.image ?? null) &&
    a.vmCapacity?.memoryBudgetMiB === b.vmCapacity?.memoryBudgetMiB &&
    a.vmCapacity?.maxCpuCount === b.vmCapacity?.maxCpuCount &&
    a.vmCapacity?.vcpuBudget === b.vmCapacity?.vcpuBudget &&
    JSON.stringify(a.storagePools) === JSON.stringify(b.storagePools)
  );
}

/** Persist only the authenticated epoch's immutable first report. Census may
 * subsequently change schedulability without changing this session tuple. */
export async function recordHostAdmission(
  sender: RelaySender,
  message: HostAdmissionReport,
  _now: Date,
  state: HostAdmissionState,
): Promise<boolean> {
  if (message.connectionEpoch !== sender.connectionEpoch || sender.isCurrent?.() === false)
    return false;
  const runtime = { fake: "FAKE", incus_kvm: "INCUS_KVM", unsupported: "UNSUPPORTED" } as const;
  const accepted = await relayTransaction(async (tx) => {
    await lockOwnerForAdmission(tx, sender.userId);
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    // enqueueSocketWork serializes admission frames for this socket, including
    // publishing firstReport after commit. Dynamic census schedulability is
    // deliberately excluded from the stored static-tuple recheck under H.
    await requireStaticCapacityMatch(tx, sender.hostId, sender.userId, {
      vmCapacity: message.vmCapacity,
      storagePools: message.storagePools,
    });
    if (state.firstReport) {
      if (!sameAdmission(state.firstReport, message))
        throw new Error("Conflicting host admission report.");
      const stored = await tx.sandboxHost.findFirst({
        where: {
          id: sender.hostId,
          userId: sender.userId,
          connectionEpoch: sender.connectionEpoch,
          admissionEpoch: sender.connectionEpoch,
          admissionRuntime: runtime[message.runtimeKind],
          daemonMemoryBudgetMiB: message.vmCapacity?.memoryBudgetMiB ?? null,
          daemonMaxCpuCount: message.vmCapacity?.maxCpuCount ?? null,
          daemonVcpuBudget: message.vmCapacity?.vcpuBudget ?? null,
          AND: [
            { daemonFeatures: { path: ["egressPolicy"], equals: message.egressPolicy } },
            { daemonFeatures: { path: ["egressOpen"], equals: message.egressOpen === true } },
            { daemonFeatures: { path: ["terminal"], equals: message.terminal } },
            ...(message.journalId
              ? [{ daemonFeatures: { path: ["journalId"], equals: message.journalId } }]
              : []),
          ],
        },
        select: { id: true },
      });
      if (!stored) throw new Error("Stored host admission report conflicts.");
      return true;
    }
    await initializeHostMemoryReservation(tx, sender.hostId, sender.userId);
    const receivedAt = await hostDatabaseNow(tx);
    const helloFeatures =
      (
        await tx.sandboxHost.findFirst({
          where: {
            id: sender.hostId,
            userId: sender.userId,
            connectionEpoch: sender.connectionEpoch,
          },
          select: { daemonFeatures: true },
        })
      )?.daemonFeatures ?? null;
    const helloImage = admittedImageFeatures(helloFeatures, message.image);
    const helloCredentials = admittedCredentialFeatures(helloFeatures);
    const templateStartup =
      helloFeatures != null &&
      typeof helloFeatures === "object" &&
      !Array.isArray(helloFeatures) &&
      helloFeatures.helloTemplateStartup === true;
    const guestSudo =
      helloFeatures != null &&
      typeof helloFeatures === "object" &&
      !Array.isArray(helloFeatures) &&
      helloFeatures.helloGuestSudo === true;
    const written = await tx.sandboxHost.updateMany({
      where: {
        id: sender.hostId,
        userId: sender.userId,
        connectionEpoch: sender.connectionEpoch,
      },
      data: {
        daemonMemoryBudgetMiB: message.vmCapacity?.memoryBudgetMiB ?? null,
        daemonMaxCpuCount: message.vmCapacity?.maxCpuCount ?? null,
        daemonVcpuBudget: message.vmCapacity?.vcpuBudget ?? null,
        admissionRuntime: runtime[message.runtimeKind],
        admissionEpoch: sender.connectionEpoch,
        admissionReportedAt: receivedAt,
        daemonSchedulable: message.schedulable,
        daemonFeatures: {
          egressPolicy: message.egressPolicy,
          // Static open-egress capability (§2.5): open requests downgrade to
          // allowlist (HOST_UNSUPPORTED) on a host without it.
          egressOpen: message.egressOpen === true,
          terminal: message.terminal,
          ...(message.journalId ? { journalId: message.journalId } : {}),
          ...(helloImage ? { image: helloImage } : {}),
          // B9: the hello's start/ready capability, admitted for this epoch.
          ...(templateStartup ? { templateStartup: true } : {}),
          // guestSudo (grant and host-proof retirement), admitted for this epoch.
          ...(guestSudo ? { guestSudo: true } : {}),
          ...(helloCredentials ? { credentials: helloCredentials } : {}),
        },
        ...(helloImage && message.image
          ? {
              imageCacheCapBytes: BigInt(message.image.capBytes),
              imageCacheUsedBytes: BigInt(message.image.usedBytes),
              imageCacheForeignBytes: BigInt(message.image.foreignUsedBytes),
              imageCacheEpoch: sender.connectionEpoch,
            }
          : {}),
      },
    });
    requireRelayFence(written.count === 1 && sender.isCurrent?.() !== false);
    return true;
  }, false);
  if (accepted && !state.firstReport)
    state.firstReport = {
      ...message,
      ...(message.vmCapacity ? { vmCapacity: { ...message.vmCapacity } } : {}),
    };
  return accepted;
}

/**
 * The admitted image feature set: the hello capability plus the admission's
 * frozen cache facts. Both must be present (a daemon that advertised the
 * capability at hello reports its cache at admission); otherwise the host
 * never takes part in image distribution on this connection.
 */
function admittedImageFeatures(
  stored: Prisma.JsonValue | null,
  admission: ImageAdmissionV11 | undefined,
): (ImageCapabilitiesV11 & { captureStorageMarkers: string[] }) | null {
  if (!admission || !stored || typeof stored !== "object" || Array.isArray(stored)) return null;
  const parsed = imageCapabilitiesV11Schema.safeParse(stored.helloImage);
  if (!parsed.success) return null;
  return { ...parsed.data, captureStorageMarkers: admission.captureStorageMarkers };
}

/** The hello credential capability for this epoch (CLI logins §6), or null. */
function admittedCredentialFeatures(
  stored: Prisma.JsonValue | null,
): CredentialCapabilitiesV11 | null {
  if (!stored || typeof stored !== "object" || Array.isArray(stored)) return null;
  const parsed = credentialCapabilitiesV11Schema.safeParse(stored.helloCredentials);
  return parsed.success ? parsed.data : null;
}

/** Inventory updates cannot bypass owner admission or the current epoch. */
export async function recordHostInventory(
  sender: RelaySender,
  schedulable: boolean,
  report?: HostStorageObservation,
): Promise<boolean> {
  return relayTransaction(async (tx) => {
    await lockOwnerForAdmission(tx, sender.userId);
    await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
    requireRelayFence(sender.isCurrent?.() !== false);
    // Storage health or capacity may have come back (post-commit wake).
    noteCapacityChanged(tx, { hostIds: [sender.hostId] });
    if (report)
      await recordStorageObservation(tx, {
        hostId: sender.hostId,
        ownerId: sender.userId,
        epoch: sender.connectionEpoch,
        report,
      });
    const written = await tx.sandboxHost.updateMany({
      where: { id: sender.hostId, userId: sender.userId, connectionEpoch: sender.connectionEpoch },
      data: { daemonSchedulable: schedulable },
    });
    requireRelayFence(written.count === 1 && sender.isCurrent?.() !== false);
    return true;
  }, false);
}
