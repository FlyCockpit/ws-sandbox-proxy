import type { Prisma } from "@wssp/db";
import { hostDeleteConflict, hostForgetUnsafe } from "../errors";
import { releaseRootResources } from "../host-admission";
import { RelayFenceRejected, requireRelayFence, transactionHoldsHostLock } from "../relay-fence";
import { detachToOffloaded, hostOnline, staleCopyIdentity, staleDetachSafe } from "./detach";

/**
 * Forget unreachable host: the owner's
 * explicit, type-to-confirm abandonment of a host that cannot come back.
 *
 * Each sandbox on the host with a stored disk (`diskOffloadId` set) detaches
 * to OFFLOADED only through the safe-detachment gate, the same gate as an
 * offline cached host at restore request (`detach.ts` `staleDetachSafe`,
 * also used by `restore-admit.ts` `detachStaleCachedCopy`): STOPPED, no
 * live slot, `hasPossiblyLiveSandboxAttempt` false and no ACTIVE or UNKNOWN
 * operation dispatched there. Its root hold moves to a `SandboxDiskCopy(STALE)` row,
 * which the forget then drops with every other copy row on the host: the
 * host is being deleted, so no discard can ever reach it.
 *
 * A sandbox that may still run there (disconnected lifecycle work keeps
 * running; a stopped daemon enforces nothing) refuses the whole forget with
 * `sandbox.host_forget_unsafe`, listing it, before anything is written.
 * Forget never writes DELETED, and sandboxes without a stored disk are not
 * touched: they keep blocking the host's deletion.
 */

type Tx = Prisma.TransactionClient;

const PAGE = 100;

/** Distinct owners of sandboxes with a stored disk on `hostId` (bounded),
 * to lock in id order before the host lock. */
export async function forgetSandboxOwners(tx: Tx, hostId: string): Promise<string[]> {
  const rows = await tx.$queryRaw<{ userId: string }[]>`
    SELECT DISTINCT "userId" FROM sandbox_instance
    WHERE "sandboxHostId" = ${hostId} AND "diskOffloadId" IS NOT NULL
    ORDER BY "userId" LIMIT ${PAGE}`;
  return rows.map((row) => row.userId);
}

const forgetSandboxSelect = {
  id: true,
  userId: true,
  state: true,
  generation: true,
  liveResourcesHeld: true,
  templateRevisionId: true,
  diskBaseFingerprint: true,
} satisfies Prisma.SandboxSelect;

/** The safe-detachment gate (§8.2) for one sandbox on the forgotten host. */
async function safeToDetach(
  tx: Tx,
  hostId: string,
  sandbox: Prisma.SandboxGetPayload<{ select: typeof forgetSandboxSelect }>,
): Promise<boolean> {
  if (sandbox.state !== "STOPPED" || sandbox.liveResourcesHeld) return false;
  return staleDetachSafe(tx, { ownerId: sandbox.userId, sandboxId: sandbox.id, hostId });
}

/**
 * Detach every stored-disk sandbox on `hostId` and drop the host's copy
 * rows. Caller holds the involved owners (id order), then the host lock,
 * and has checked the host unreachable. All or nothing: any unsafe
 * sandbox throws `sandbox.host_forget_unsafe` before a write.
 */
export async function forgetOffloadedDisks(
  tx: Tx,
  hostId: string,
  lockedOwners: ReadonlySet<string>,
): Promise<{ detached: number; copiesForgotten: number }> {
  requireRelayFence(transactionHoldsHostLock(tx, hostId));
  const now = new Date();
  if (await hostOnline(tx, hostId, now))
    throw hostDeleteConflict("A connected host cannot be forgotten; delete it instead.");

  const safe: Prisma.SandboxGetPayload<{ select: typeof forgetSandboxSelect }>[] = [];
  const unsafe: string[] = [];
  let cursor = "";
  for (;;) {
    const page = await tx.$queryRaw<{ id: string; userId: string }[]>`
      SELECT id, "userId" FROM sandbox_instance
      WHERE "sandboxHostId" = ${hostId} AND "diskOffloadId" IS NOT NULL AND id > ${cursor}
      ORDER BY id LIMIT ${PAGE} FOR NO KEY UPDATE`;
    for (const row of page) {
      // An owner that appeared after the lock pass: retry the request.
      requireRelayFence(lockedOwners.has(row.userId));
      const sandbox = await tx.sandbox.findFirst({
        where: { id: row.id, userId: row.userId, sandboxHostId: hostId },
        select: forgetSandboxSelect,
      });
      if (!sandbox) throw new RelayFenceRejected();
      if (await safeToDetach(tx, hostId, sandbox)) safe.push(sandbox);
      else unsafe.push(sandbox.id);
    }
    if (page.length < PAGE) break;
    cursor = page[page.length - 1]?.id ?? cursor;
  }
  if (unsafe.length > 0) throw hostForgetUnsafe(unsafe);

  let detached = 0;
  for (const sandbox of safe) {
    const identity = await staleCopyIdentity(tx, sandbox);
    const ok = await detachToOffloaded(tx, {
      sandboxId: sandbox.id,
      userId: sandbox.userId,
      hostId,
      generation: sandbox.generation,
      proof: { kind: "stale_copy", ...identity },
    });
    requireRelayFence(ok);
    detached++;
  }

  // The host goes away: its copies (stale or just detached) can never be
  // discarded there. Each releases its root hold once, then the row goes.
  let copiesForgotten = 0;
  for (;;) {
    const copies = await tx.sandboxDiskCopy.findMany({
      where: { hostId },
      select: { id: true },
      orderBy: { id: "asc" },
      take: PAGE,
    });
    for (const copy of copies) {
      await releaseRootResources(tx, { hostId, copyId: copy.id });
      const removed = await tx.sandboxDiskCopy.deleteMany({
        where: { id: copy.id, hostId, diskReservationHeld: false },
      });
      requireRelayFence(removed.count === 1);
      copiesForgotten++;
    }
    if (copies.length < PAGE) break;
  }
  return { detached, copiesForgotten };
}
