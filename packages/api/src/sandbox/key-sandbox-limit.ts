import type { Prisma } from "@wssp/db";
import type { Principal } from "./contracts";
import { keySandboxLimitReached } from "./errors";
import { callingKeyOf } from "./principal-kinds";

/**
 * The live WORKLOAD sandboxes one key created: the owner's sandboxes, not
 * DELETED, whose CREATE operation this key authorized (the same creator
 * predicate as `serviceResourceFilter` for an own-sandboxes-only key). A
 * waiting-for-capacity create has its sandbox and CREATE operation already, so
 * it counts; a destroy (DELETED) frees its slot. HOST_LOST frees it too: that
 * state only ever leads to RECLAIMING or DELETED (`state-transitions.ts`), and
 * a lost host would otherwise hold the slot until it reconciles.
 */
function keyLiveSandboxesWhere(ownerId: string, keyId: string) {
  return {
    userId: ownerId,
    purpose: "WORKLOAD",
    state: { notIn: ["DELETED", "HOST_LOST"] },
    Operations: { some: { kind: "CREATE_SANDBOX", authorizingKeyId: keyId, userId: ownerId } },
  } satisfies Prisma.SandboxWhereInput;
}

export async function countKeyLiveSandboxes(
  tx: Prisma.TransactionClient,
  ownerId: string,
  keyId: string,
): Promise<number> {
  return tx.sandbox.count({ where: keyLiveSandboxesWhere(ownerId, keyId) });
}

/**
 * Refuse a new create when the calling key is at its `maxLiveSandboxes`.
 *
 * Callers hold the owner's placement lock (`lockOwnerPlacement`, taken by
 * `resolvePlacement` on the direct and the pool path) so concurrent creates of
 * one owner serialize here: each counts the creates committed before it. The
 * limit is immutable after mint, so the column read here is the minted value.
 * An idempotent replay resolves before target resolution and never gets here.
 */
export async function requireKeySandboxAllowance(
  tx: Prisma.TransactionClient,
  principal: Principal,
): Promise<void> {
  const key = callingKeyOf(principal);
  if (!key) return;
  const row = await tx.sdkKey.findFirst({
    where: { id: key.keyId, userId: principal.ownerId },
    select: { maxLiveSandboxes: true },
  });
  const max = row?.maxLiveSandboxes ?? null;
  if (max === null) return;
  const live = await countKeyLiveSandboxes(tx, principal.ownerId, key.keyId);
  if (live >= max) throw keySandboxLimitReached(max, live);
}
