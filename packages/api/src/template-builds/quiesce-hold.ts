/**
 * WP7 (D9): a quiescing host holds new `command.run` work in the outbox,
 * before its claim. A template build whose step is held there must not
 * spend its build deadline on the hold. The relay records when the host
 * started quiescing (`SandboxHost.quiescingSince`); while it is set the
 * orchestrator extends the step's effective deadline by the running hold
 * (`quiesceHeldMs` in `decide.ts`, capped), and when a later hello arrives
 * without `quiescing` the hold is settled: in ONE transaction, under the
 * locks the orchestrator takes (owner admission and placement, then the
 * build row), each held build's `deadlineAt` moves out by its hold and the
 * marker is cleared (compare-and-set: at most once). An orchestrator tick
 * therefore sees either the marker or the extended deadline, never neither.
 *
 * Both writes are fenced by the connection epoch that caused them, so a
 * delayed write from an older connection never lands after a newer hello.
 */
import prisma, { type Prisma } from "@wssp/db";
import { AccountDeletionConflictError, lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { lockOwnerPlacement } from "../sandbox/direct-placement";
import { quiesceHeldMs } from "./decide";

/** Builds settled per hello (a host runs at most a few build VMs). */
const SETTLE_BATCH = 256;

/** The connection whose report or hello the write follows. */
export type QuiesceHost = { hostId: string; ownerId: string; connectionEpoch: number };

/** The host started quiescing (a `host.quiesce` or a quiescing hello) on
 * connection `connectionEpoch`, still the host's current one. Keeps the
 * earliest start across reconnects. */
export async function markHostQuiescing(host: QuiesceHost, now: Date): Promise<void> {
  await prisma.sandboxHost.updateMany({
    where: {
      id: host.hostId,
      userId: host.ownerId,
      connectionEpoch: host.connectionEpoch,
      quiescingSince: null,
    },
    data: { quiescingSince: now },
  });
}

class SettlementRaced extends Error {}

/**
 * The host's current connection (`connectionEpoch`) said hello without
 * `quiescing`: end the hold. Returns the number of builds whose deadline
 * moved.
 */
export async function settleHostQuiesce(host: QuiesceHost, now: Date): Promise<number> {
  try {
    return await prisma.$transaction((tx) => settle(tx, host, now), { timeout: 15_000 });
  } catch (error) {
    // A newer hello settled or re-marked meanwhile: nothing of ours applies.
    if (error instanceof SettlementRaced) return 0;
    throw error;
  }
}

async function settle(tx: Prisma.TransactionClient, host: QuiesceHost, now: Date) {
  const row = await tx.sandboxHost.findFirst({
    where: { id: host.hostId, userId: host.ownerId, connectionEpoch: host.connectionEpoch },
    select: { quiescingSince: true },
  });
  const since = row?.quiescingSince;
  if (!since) return 0;
  const candidates = await tx.sandboxTemplateBuild.findMany({
    where: {
      hostOwnerId: host.ownerId,
      hostId: host.hostId,
      state: "RUNNING",
      deadlineAt: { not: null },
      currentOperationId: { not: null },
    },
    select: { id: true, userId: true },
    orderBy: { id: "asc" },
    take: SETTLE_BATCH,
  });
  // The orchestrator's lock order: owner admission, owner placement, then
  // the build row (owners in one fixed order).
  const owners = [...new Set(candidates.map((build) => build.userId))].sort();
  const locked = new Set<string>();
  for (const owner of owners) {
    try {
      await lockOwnerForAdmission(tx, owner);
    } catch (error) {
      // An account being deleted: its builds end anyway.
      if (error instanceof AccountDeletionConflictError) continue;
      throw error;
    }
    await lockOwnerPlacement(tx, owner);
    locked.add(owner);
  }
  let extended = 0;
  for (const candidate of candidates) {
    if (!locked.has(candidate.userId)) continue;
    await tx.$queryRaw`SELECT id FROM sandbox_template_build WHERE id = ${candidate.id} AND "userId" = ${candidate.userId} FOR UPDATE`;
    const build = await tx.sandboxTemplateBuild.findFirst({
      where: { id: candidate.id, userId: candidate.userId, state: "RUNNING" },
      select: { deadlineAt: true, currentOperationId: true },
    });
    if (!build?.deadlineAt || !build.currentOperationId) continue;
    const op = await tx.sandboxOperation.findFirst({
      where: { id: build.currentOperationId, userId: candidate.userId },
      select: { kind: true, state: true, createdAt: true, dispatchedAt: true },
    });
    const held = quiesceHeldMs(since, op, now);
    if (held <= 0) continue;
    await tx.sandboxTemplateBuild.update({
      where: { id: candidate.id },
      data: { deadlineAt: new Date(build.deadlineAt.getTime() + held) },
    });
    extended++;
  }
  const cleared = await tx.sandboxHost.updateMany({
    where: {
      id: host.hostId,
      connectionEpoch: host.connectionEpoch,
      quiescingSince: since,
    },
    data: { quiescingSince: null },
  });
  // Roll back every extension: the marker changed under us.
  if (cleared.count !== 1) throw new SettlementRaced();
  return extended;
}
