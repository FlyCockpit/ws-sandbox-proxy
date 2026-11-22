import type {
  OperationState,
  Prisma,
  SandboxLaunchMode,
  SandboxOperationKind,
  SandboxState,
} from "@wssp/db";
import { AccountDeletionConflictError } from "@wssp/db/account-deletion";
import { noteHostBlockerReleased } from "./host-admission";
import { sandboxOutboxTransaction } from "./outbox";
import { outboxOperationWhere } from "./outbox-operation";
import { RelayFenceRejected, requireRelayFence } from "./relay-fence-rejected";
import { noteTerminalResultRelease } from "./result-finalization";
import { assertBeforeResultQuota } from "./result-locks";
import { rethrowSensitiveSandboxError, SandboxIntegrityError } from "./sensitive-errors";
import {
  ACTIVE_OPERATION_STATES,
  CANCELLABLE_OPERATION_KINDS,
  isLifecycleOperationKind,
} from "./state-transitions";

/**
 * Application acquisition order: host admission row → sandbox row → operation rows → outbox.
 * The host row combines connectionEpoch CAS (`lockHostByEpoch`) with live capacity
 * (pinned live/root resource counters in host-admission.ts). Both mutate only after
 * the same epoch lock, so capacity cannot invert ahead of relay fencing.
 * Reads locate rows; epoch/generation SELECT FOR UPDATE locks last until commit.
 * Owner admission precedes host work, except dispatch, which uses K before H
 * and never takes the owner lock. New-row FKs and finalizer children follow
 * their documented ranks; real PostgreSQL barriers prove each writer path.
 * All predicate misses throw so even earlier no-op writes roll back. Never
 * hold database locks across socket/Incus IO: commit intent, send to that epoch.
 * Admission without a placed host starts at the sandbox row and never acquires
 * a host lock later. First dispatch pins the chosen host under this same order.
 */
export { RelayFenceRejected, requireRelayFence };
/** A rejected fence that is permanent for this evidence: what the host
 * reported can never apply to its own row or request (codec, request binding,
 * bound identity, immutable stored evidence). Authority, epoch and race fences
 * stay plain `requireRelayFence`; only these let an exact receipt take the
 * server's terminal verdict instead of replaying unconfirmed. */
export class ResultIncompatible extends RelayFenceRejected {}
export function requireResultCompatible(ok: boolean): asserts ok {
  if (!ok) throw new ResultIncompatible();
}
/** A refusal that only waits for a server-side observation still to come (a
 * birth the server has not recorded yet, a result expiry or lease window the
 * server clock has not reached). An exact receipt refused this way is retried
 * on a later session; it never takes the terminal verdict. */
export class RelayFencePending extends RelayFenceRejected {}
export function requireObserved(ok: boolean): asserts ok {
  if (!ok) throw new RelayFencePending();
}
export async function relayTransaction<T>(
  work: (tx: Prisma.TransactionClient) => Promise<T>,
  rejected: T,
  /** Sees the fence that rolled the transaction back (e.g. to tell a
   * permanent `ResultIncompatible` from an authority or race fence). */
  onRejected?: (error: RelayFenceRejected) => void,
): Promise<T> {
  try {
    return await sandboxOutboxTransaction(work);
  } catch (error) {
    if (error instanceof SandboxIntegrityError) throw error;
    if (error instanceof RelayFenceRejected) {
      onRejected?.(error);
      return rejected;
    }
    if (error instanceof AccountDeletionConflictError) return rejected;
    rethrowSensitiveSandboxError(error);
  }
}

/** Database wall clock, never BEGIN time. Verdict writers sample after
 * owner/H; external verification samples before IO to fence stale responses.
 * Read as UTC wall time: DateTime columns are UTC `timestamp`s, and the pg
 * adapter reads a `timestamptz` by replacing (not converting) the session
 * offset, so a bare clock_timestamp() is hours off under a non-UTC TimeZone. */
export async function hostDatabaseNow(tx: Prisma.TransactionClient): Promise<Date> {
  const [row] = await tx.$queryRaw<
    { now: Date }[]
  >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
  requireRelayFence(row != null);
  return row.now;
}

const lockedHosts = new WeakMap<object, Set<string>>();

/** A finalizer may run after S/O and must never acquire a new H then. */
export function transactionHoldsHostLock(tx: Prisma.TransactionClient, hostId: string): boolean {
  return lockedHosts.get(tx)?.has(hostId) ?? false;
}

export async function lockHostByEpoch(
  tx: Prisma.TransactionClient,
  hostId: string,
  connectionEpoch: number,
  userId?: string,
): Promise<void> {
  assertBeforeResultQuota(tx);
  const rows = userId
    ? await tx.$queryRaw<
        { id: string }[]
      >`SELECT id FROM sandbox_host WHERE id = ${hostId} AND "connectionEpoch" = ${connectionEpoch} AND "userId" = ${userId} FOR UPDATE`
    : await tx.$queryRaw<
        { id: string }[]
      >`SELECT id FROM sandbox_host WHERE id = ${hostId} AND "connectionEpoch" = ${connectionEpoch} FOR UPDATE`;
  requireRelayFence(rows.length === 1);
  let hosts = lockedHosts.get(tx);
  if (!hosts) {
    hosts = new Set();
    lockedHosts.set(tx, hosts);
  }
  hosts.add(hostId);
}

/** Hello creates a new epoch, so lock the owner-bound row without a stale
 * pre-lock epoch read. Subsequent writers use the ordinary epoch CAS. */
export async function lockHostForHello(
  tx: Prisma.TransactionClient,
  hostId: string,
  ownerId: string,
) {
  assertBeforeResultQuota(tx);
  const rows = await tx.$queryRaw<
    { id: string }[]
  >`SELECT id FROM sandbox_host WHERE id = ${hostId} AND "userId" = ${ownerId} FOR UPDATE`;
  requireRelayFence(rows.length === 1);
  let hosts = lockedHosts.get(tx);
  if (!hosts) {
    hosts = new Set();
    lockedHosts.set(tx, hosts);
  }
  hosts.add(hostId);
}

export async function lockCurrentHostEpoch(tx: Prisma.TransactionClient, hostId: string) {
  const host = await tx.sandboxHost.findFirst({
    where: { id: hostId },
    select: { connectionEpoch: true, userId: true },
  });
  requireRelayFence(host != null);
  await lockHostByEpoch(tx, hostId, host.connectionEpoch, host.userId);
  return host;
}

/**
 * The sandbox states an operation's fence admits. Mode-aware (offload plan
 * U9): a restore attempt (`RECONNECT_SANDBOX` accepted with `launchMode =
 * NEW_ROOT`, written only by restore admission) runs while the sandbox is
 * `PROVISIONING` on its new host; every other reconnect keeps `READY |
 * STOPPED`, so a non-restore reconnect is still refused in `PROVISIONING`.
 * Every caller passes the operation row's own immutable `launchMode`.
 */
export function sandboxStatesForOperation(op: {
  kind: string;
  launchMode: SandboxLaunchMode | null;
}): readonly SandboxState[] {
  const kind = op.kind;
  if (kind === "RECONNECT_SANDBOX" && op.launchMode === "NEW_ROOT") return ["PROVISIONING"];
  switch (kind) {
    case "CREATE_SANDBOX":
      return ["REQUESTED", "SCHEDULED", "PROVISIONING"];
    case "STOP_SANDBOX":
      return ["STOPPING"];
    // DELETED: the inventory-driven destroy of a deleted sandbox's VM that its
    // node still reports (see `obligeRemnantDestroy` in the relay).
    case "KILL_SANDBOX":
      return ["STOPPING", "RECLAIMING", "DELETED"];
    case "RECONNECT_SANDBOX":
    // A capture works on a READY (frozen snapshot) or STOPPED (direct copy) root.
    case "CAPTURE_TEMPLATE":
      return ["READY", "STOPPED"];
    default:
      return ["READY"];
  }
}

export async function casSandboxGeneration(
  tx: Prisma.TransactionClient,
  input: {
    sandboxId: string;
    userId: string;
    generation: number;
    hostId?: string;
    states: readonly SandboxState[];
    pinHost?: boolean;
  },
): Promise<void> {
  assertBeforeResultQuota(tx);
  if (!input.pinHost) {
    // A row lock avoids the owner FK recheck caused by updating this tuple
    // repeatedly in one transaction (dispatch must stay owner-lock-free).
    const rows = await tx.$queryRaw<
      { id: string }[]
    >`SELECT id FROM sandbox_instance WHERE id = ${input.sandboxId} AND "userId" = ${input.userId} AND generation = ${input.generation} FOR UPDATE`;
    requireRelayFence(rows.length === 1);
    const current = await tx.sandbox.findFirst({
      where: {
        id: input.sandboxId,
        userId: input.userId,
        generation: input.generation,
        state: { in: [...input.states] },
        ...(input.hostId ? { OR: [{ sandboxHostId: input.hostId }, { sandboxHostId: null }] } : {}),
      },
      select: { id: true },
    });
    requireRelayFence(current !== null);
    await lockCurrentPlacement(tx, input.sandboxId, input.userId);
    return;
  }
  const written = await tx.sandbox.updateMany({
    where: {
      id: input.sandboxId,
      userId: input.userId,
      generation: input.generation,
      state: { in: [...input.states] },
      ...(input.hostId ? { OR: [{ sandboxHostId: input.hostId }, { sandboxHostId: null }] } : {}),
    },
    data: {
      generation: input.generation,
      ...(input.pinHost ? { sandboxHostId: input.hostId } : {}),
    },
  });
  requireRelayFence(written.count === 1);
  await lockCurrentPlacement(tx, input.sandboxId, input.userId);
}

/** S is already held; acquire its current boot before O/outbox. Every later
 * placement observation revisits this row, never seeks an earlier lock. */
async function lockCurrentPlacement(
  tx: Prisma.TransactionClient,
  sandboxId: string,
  userId: string,
) {
  await tx.$queryRaw`SELECT p.id FROM sandbox_placement p JOIN sandbox_instance s ON s."currentPlacementId" = p.id AND s.id = p."sandboxId" AND s."userId" = p."userId" WHERE s.id = ${sandboxId} AND s."userId" = ${userId} FOR UPDATE OF p`;
}

export function operationActiveFenceWhere(input: {
  operationId: string;
  sandboxId?: string;
  userId: string;
  generation: number;
  attempt: number;
  hostId: string | null;
}): Prisma.SandboxOperationWhereInput {
  return {
    id: input.operationId,
    ...(input.sandboxId ? { sandboxId: input.sandboxId } : {}),
    userId: input.userId,
    generation: input.generation,
    dispatchAttempt: input.attempt,
    dispatchedHostId: input.hostId,
    state: { in: [...ACTIVE_OPERATION_STATES] },
  };
}

export async function casActiveOperation(
  tx: Prisma.TransactionClient,
  input: Parameters<typeof operationActiveFenceWhere>[0],
  data: Prisma.SandboxOperationUpdateManyMutationInput,
): Promise<void> {
  assertBeforeResultQuota(tx);
  const written = await tx.sandboxOperation.updateMany({
    where: operationActiveFenceWhere(input),
    data,
  });
  requireRelayFence(written.count === 1);
  const state = typeof data.state === "string" ? data.state : data.state?.set;
  if (state === "SUCCEEDED" || state === "FAILED" || state === "CANCELLED")
    noteTerminalResultRelease(tx, input.userId, { operationId: input.operationId });
}

/** Caller owns S. QUEUED has no committed dispatch claim, so cancellation can
 * retire its intent atomically without host IO. DISPATCHED may already be in
 * flight even when sentAt is null; only host acceptance permits a control send.
 */
export async function cancelQueuedOperation(
  tx: Prisma.TransactionClient,
  input: Parameters<typeof operationActiveFenceWhere>[0] & {
    sandboxId: string;
    kind: SandboxOperationKind;
  },
  now: Date,
) {
  requireRelayFence(CANCELLABLE_OPERATION_KINDS.has(input.kind));
  const written = await tx.sandboxOperation.updateMany({
    where: { ...operationActiveFenceWhere(input), kind: input.kind, state: "QUEUED" },
    data: { state: "CANCELLED", completedAt: now },
  });
  requireRelayFence(written.count === 1);
  noteHostBlockerReleased(tx, input.hostId, input.userId);
  noteTerminalResultRelease(tx, input.userId, { operationId: input.operationId });
  await tx.outboxEvent.updateMany({
    where: {
      userId: input.userId,
      aggregateType: "sandbox",
      aggregateId: input.sandboxId,
      processedAt: null,
      ...outboxOperationWhere(input.operationId),
    },
    data: { processedAt: now, claimToken: null, claimedAt: null },
  });
}

/** A capture whose result the host already delivered and the server recorded
 * (CAPTURED/STORING/FINALIZED). Its outcome exists and its finalizer
 * (image-store/captures.ts finalizeCapture) owns the one terminal write, so
 * whatever the operation row says (RUNNING, or CANCEL_REQUESTED after a
 * supersession), no other path may retire or settle it: reconnect
 * reconciliation, supersession retire/settle, lease expiry (which goes
 * through both), and result/receipt ingress all exclude it.
 *
 * One exception moves such an operation, never settles it: the
 * recorded-capture adoption of an image upload resume
 * (apps/server/src/sandbox-relay/image-handlers.ts adoptRecordedCapture).
 * After a relay reconnect of the capture's own host it writes only
 * `dispatchedConnectionEpoch` (old epoch → the new connection's), for the
 * exact dispatch (host, epoch, attempt, ACCEPTED/RUNNING, capture
 * CAPTURED/STORING on that host) that was authorized on the old epoch, so
 * the upload goes on there. State, result and terminal write stay the
 * finalizer's, so the invariant above holds. */
export const RECORDED_CAPTURE_WHERE = {
  kind: "CAPTURE_TEMPLATE",
  Capture: { is: { state: { in: ["CAPTURED", "STORING", "FINALIZED"] } } },
} satisfies Prisma.SandboxOperationWhereInput;

/** Every lifecycle terminal writer calls this in its transaction, after H → S
 * and the lifecycle O write, before outbox. Generation is the durable supersession
 * link, including work that never acquired a dispatched host/epoch. A newer
 * lifecycle can itself settle an older lifecycle and all its predecessors in
 * this one update; no recursive locking or host IO is needed.
 */
export async function settleSupersededOperations(
  tx: Prisma.TransactionClient,
  input: {
    userId: string;
    sandboxId: string;
    generation: number;
    kind: SandboxOperationKind;
    state: OperationState;
  },
  now: Date,
) {
  if (!isLifecycleOperationKind(input.kind)) return;
  noteTerminalResultRelease(tx, input.userId, { sandboxId: input.sandboxId });
  requireRelayFence(!ACTIVE_OPERATION_STATES.has(input.state));
  // Only a successful stop/kill receipt proves Stopped/absent. Failure,
  // cancellation, missing receipts and create/reconnect cannot prove it.
  const stopped =
    input.state === "SUCCEEDED" && (input.kind === "STOP_SANDBOX" || input.kind === "KILL_SANDBOX");
  const where: Prisma.SandboxOperationWhereInput = {
    userId: input.userId,
    sandboxId: input.sandboxId,
    generation: { lt: input.generation },
    state: { in: ["CANCEL_REQUESTED", "UNKNOWN_OUTCOME"] },
    errorCode: "superseded",
    NOT: RECORDED_CAPTURE_WHERE,
  };
  // A first completion owns the output-retention deadline (C26): settling a
  // predecessor again must never push it out.
  await tx.sandboxOperation.updateMany({
    where: { ...where, completedAt: { not: null } },
    data: { state: stopped ? "CANCELLED" : "UNKNOWN_OUTCOME" },
  });
  await tx.sandboxOperation.updateMany({
    where: { ...where, completedAt: null },
    data: { state: stopped ? "CANCELLED" : "UNKNOWN_OUTCOME", completedAt: now },
  });
}

/** Caller already owns host and sandbox. Acquire operation rows before outbox.
 * Retire previous generations including sent/acknowledged work, which is absent
 * from the pending-send scan. New lifecycle intent is inserted by the caller.
 */
export async function retireSupersededOperations(
  tx: Prisma.TransactionClient,
  userId: string,
  sandboxId: string,
  generation: number,
  now = new Date(),
) {
  await tx.sandboxOperation.updateMany({
    where: {
      userId,
      sandboxId,
      generation: { lt: generation },
      state: { in: [...ACTIVE_OPERATION_STATES, "UNKNOWN_OUTCOME"] },
      NOT: RECORDED_CAPTURE_WHERE,
    },
    data: {
      state: "CANCEL_REQUESTED",
      // completedAt is never touched here (C26): an UNKNOWN_OUTCOME row already
      // completed, and its first completion owns the output-retention deadline.
      // Clearing it would let a later settle restart retention at each repeated
      // supersession. Active rows have no completion to preserve.
      errorCode: "superseded",
      errorDetail: "Sandbox authority superseded this operation.",
    },
  });
  await tx.outboxEvent.updateMany({
    where: {
      userId,
      aggregateType: "sandbox",
      aggregateId: sandboxId,
      processedAt: null,
      payload: { path: ["generation"], lt: generation },
    },
    data: { processedAt: now, claimToken: null, claimedAt: null },
  });
}

/** Resolve the creator from durable custody, never from a host assertion.
 * Discovery may precede the lock prefix; callers repeat it after H/S before
 * writing results. Historical operation generations still belong to this host.
 */
export async function requireRelayWorkload(
  tx: Prisma.TransactionClient,
  transport: { hostId: string; userId: string },
  target: { sandboxId?: string; operationId?: string; sandboxOwnerId?: string },
) {
  const operation = target.operationId
    ? await tx.sandboxOperation.findFirst({
        where: { id: target.operationId },
        select: { sandboxId: true, userId: true, dispatchedHostId: true },
      })
    : null;
  if (
    target.operationId &&
    (!operation ||
      (operation.dispatchedHostId !== null && operation.dispatchedHostId !== transport.hostId))
  )
    requireRelayFence(false);
  const id = target.sandboxId ?? operation?.sandboxId;
  requireRelayFence(Boolean(id) && (!operation || operation.sandboxId === id));
  const row = await tx.sandbox.findFirst({
    where: { id },
    select: {
      id: true,
      userId: true,
      hostOwnerId: true,
      sandboxHostId: true,
      state: true,
      generation: true,
      CurrentPlacement: {
        select: {
          sandboxId: true,
          userId: true,
          hostOwnerId: true,
          originHostId: true,
          generation: true,
        },
      },
    },
  });
  const p = row?.CurrentPlacement;
  requireRelayFence(
    !(
      !row ||
      !p ||
      (operation && operation.userId !== row.userId) ||
      (target.sandboxOwnerId !== undefined && target.sandboxOwnerId !== row.userId) ||
      row.hostOwnerId !== transport.userId ||
      p.hostOwnerId !== row.hostOwnerId ||
      p.sandboxId !== row.id ||
      p.userId !== row.userId ||
      p.generation > row.generation ||
      p.originHostId !== transport.hostId ||
      // Offload §8.10: a DELETED remnant is reported by the host it last ran
      // on, its current (latest) placement's host checked above — never
      // `Sandbox.originHostId`, which a restore leaves on the first host.
      (row.sandboxHostId !== transport.hostId && row.state !== "DELETED")
    ),
  );
  requireRelayFence(row != null);
  return {
    sandboxId: row.id,
    sandboxOwnerId: row.userId,
    hostOwnerId: transport.userId,
    hostId: transport.hostId,
  };
}

/** Receipt confirmation of terminal work (offload §8.10, retained placement
 * evidence). A hostless sandbox (OFFLOADED after a restore attempt's
 * SYSTEM_DETACH kill or an eviction, or a DELETED one with no current
 * placement) has no current host, so `requireRelayWorkload` refuses every
 * host — and the host that ran the kill could never confirm it, leaving its
 * cleanup watermark unsettled and a later restore back onto it refused.
 *
 * Only then, and only for an operation already terminal on the server that
 * was dispatched to this exact transport host: the sandbox owner matches the
 * operation's, and the placement the operation ran under (the latest
 * placement at or below its generation, never the latest host) was on this
 * host under this host owner. A sandbox with a current host or placement
 * takes the ordinary current-host fence. Epoch fences stay with the caller.
 */
export async function requireRelayReceiptWorkload(
  tx: Prisma.TransactionClient,
  transport: { hostId: string; userId: string },
  target: { sandboxId?: string; operationId: string; sandboxOwnerId?: string },
) {
  if (target.sandboxId === undefined) return requireRelayWorkload(tx, transport, target);
  const row = await tx.sandbox.findFirst({
    where: { id: target.sandboxId },
    select: { id: true, userId: true, sandboxHostId: true, currentPlacementId: true },
  });
  if (!row || row.sandboxHostId !== null || row.currentPlacementId !== null)
    return requireRelayWorkload(tx, transport, target);
  requireRelayFence(target.sandboxOwnerId === undefined || target.sandboxOwnerId === row.userId);
  const operation = await tx.sandboxOperation.findFirst({
    where: {
      id: target.operationId,
      sandboxId: row.id,
      userId: row.userId,
      dispatchedHostId: transport.hostId,
      state: { in: ["SUCCEEDED", "FAILED", "CANCELLED"] },
    },
    select: { generation: true },
  });
  requireRelayFence(operation != null);
  const placement = await tx.sandboxPlacement.findFirst({
    where: { sandboxId: row.id, userId: row.userId, generation: { lte: operation.generation } },
    orderBy: { generation: "desc" },
    select: { originHostId: true, hostOwnerId: true },
  });
  requireRelayFence(
    placement != null &&
      placement.originHostId === transport.hostId &&
      placement.hostOwnerId === transport.userId,
  );
  return {
    sandboxId: row.id,
    sandboxOwnerId: row.userId,
    hostOwnerId: transport.userId,
    hostId: transport.hostId,
  };
}
