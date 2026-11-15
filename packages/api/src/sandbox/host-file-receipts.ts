import { setTimeout as delay } from "node:timers/promises";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { isPrismaUniqueViolation } from "../lib/prisma-errors";
import type { Principal } from "./contracts";
import { idempotencyConflict } from "./errors";
import {
  hostCredentialId,
  hostFileOutcomeUnknown,
  isHostDispatchOutcomeUnknown,
} from "./host-access";
import { hostSubjectHmac } from "./host-audit";

/** Receipts live 7 days, the same post-decision window as queued host commands. */
const HOST_FILE_RECEIPT_TTL_MS = 7 * 86_400_000;
/** Longer than the relay's 30 s host file request timeout plus pre-dispatch
 * IO: a receipt still PENDING after this lost its process mid-flight. */
const HOST_FILE_RECEIPT_SETTLE_MS = 45_000;
const DUPLICATE_POLL_MS = 200;

const receiptSelect = {
  id: true,
  createdAt: true,
  expiresAt: true,
  requestHmac: true,
  state: true,
  result: true,
} satisfies Prisma.HostFileReceiptSelect;

/** Request identity: a keyed HMAC of the canonical arguments, never raw content. */
export function hostFileRequestHmac(hostId: string, request: readonly unknown[]): string {
  return hostSubjectHmac(JSON.stringify(["host-file-receipt-v1", hostId, ...request]));
}

/** May the effect have happened? Only proven pre-dispatch refusals and
 * definitive daemon refusals release the key; everything else is unknown. */
function outcomeMayHaveApplied(error: unknown): boolean {
  if (isHostDispatchOutcomeUnknown(error)) return true;
  if (!(error instanceof ORPCError)) return true;
  if (error.code === "INTERNAL_SERVER_ERROR") return true;
  const data = error.data as { code?: unknown; reason?: unknown } | undefined;
  // These reasons can follow an applied change, so they do not prove nothing
  // happened: the daemon renames atomically, but a failed directory fsync
  // after the rename reports io_error; and it rewrites a successful result to
  // policy_changed when the host policy changed before delivery
  // (apps/cli/src/sandbox_relay/host_files.rs `replies`).
  return (
    data?.code === "host.file_error" &&
    (data.reason === "io_error" || data.reason === "policy_changed")
  );
}

/**
 * Credential-scoped idempotency for one host file write/edit. The first request
 * reserves `(sdkKeyId, key)` with a unique PENDING row before any effect.
 * Same key and request replays the stored result without dispatching; another
 * request is `sandbox.idempotency_conflict`. A concurrent duplicate waits for
 * the first to settle, then replays it (or claims a released key). A request
 * refused before dispatch, or definitively by the node, releases the key; an
 * uncertain outcome is kept and answered `host.file_outcome_unknown`.
 */
export async function withHostFileReceipt<R>(
  principal: Principal,
  input: { hostId: string; idempotencyKey?: string },
  requestHmac: string,
  replay: (stored: unknown) => R,
  work: { prepare(): Promise<void>; dispatch(): Promise<R> },
): Promise<R> {
  const sdkKeyId = hostCredentialId(principal);
  const idempotencyKey = input.idempotencyKey;
  if (!idempotencyKey) throw new ORPCError("BAD_REQUEST");
  const where = { sdkKeyId_idempotencyKey: { sdkKeyId, idempotencyKey } };
  for (;;) {
    const now = new Date();
    const claimed = await prisma.hostFileReceipt
      .create({
        data: {
          userId: principal.ownerId,
          sandboxHostId: input.hostId,
          sdkKeyId,
          idempotencyKey,
          requestHmac,
          expiresAt: new Date(now.getTime() + HOST_FILE_RECEIPT_TTL_MS),
        },
        select: { id: true },
      })
      .catch((error: unknown) => {
        if (isPrismaUniqueViolation(error)) return null;
        throw error;
      });
    if (claimed) return apply(claimed.id, work);
    const prior = await prisma.hostFileReceipt.findUnique({ where, select: receiptSelect });
    if (!prior) continue; // Released or swept between the insert and the read.
    if (prior.expiresAt <= now) {
      // Expired keys may be reused before the sweep reaches them.
      await prisma.hostFileReceipt.deleteMany({
        where: { id: prior.id, expiresAt: { lte: now } },
      });
      continue;
    }
    if (prior.requestHmac !== requestHmac) throw idempotencyConflict();
    if (prior.state === "SUCCEEDED") return replay(prior.result);
    if (prior.state === "UNKNOWN") throw hostFileOutcomeUnknown();
    if (now.getTime() - prior.createdAt.getTime() >= HOST_FILE_RECEIPT_SETTLE_MS) {
      await prisma.hostFileReceipt.updateMany({
        where: { id: prior.id, state: "PENDING" },
        data: { state: "UNKNOWN" },
      });
      continue;
    }
    await delay(DUPLICATE_POLL_MS);
  }
}

async function apply<R>(
  id: string,
  work: { prepare(): Promise<void>; dispatch(): Promise<R> },
): Promise<R> {
  const release = () => prisma.hostFileReceipt.deleteMany({ where: { id, state: "PENDING" } });
  try {
    await work.prepare();
  } catch (error) {
    await release();
    throw error;
  }
  let result: R;
  try {
    result = await work.dispatch();
  } catch (error) {
    if (!outcomeMayHaveApplied(error)) {
      await release();
      throw error;
    }
    await prisma.hostFileReceipt.updateMany({
      where: { id, state: "PENDING" },
      data: { state: "UNKNOWN" },
    });
    throw hostFileOutcomeUnknown();
  }
  // A late success still records the truth over a settle-timeout UNKNOWN.
  await prisma.hostFileReceipt.updateMany({
    where: { id, state: { in: ["PENDING", "UNKNOWN"] } },
    data: { state: "SUCCEEDED", result: result as Prisma.InputJsonValue },
  });
  return result;
}
