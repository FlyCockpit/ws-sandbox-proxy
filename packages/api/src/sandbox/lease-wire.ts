import { LEASE_UNLIMITED_DEADLINE_MS } from "@wssp/sandbox-contracts";
import { z } from "zod";

/** Fixed policy, versioned with the relay. C32 owns timer/retry execution. */
export const leaseWireSchema = z
  .object({
    revision: z.number().int().min(1).max(2_147_483_647),
    // The far-future deadline means "no lease timer" (timeoutMs 0).
    deadlineUnixMs: z.number().int().positive().max(LEASE_UNLIMITED_DEADLINE_MS),
    action: z.enum(["stop", "destroy"]),
    expiryPolicy: z.literal("retry-force-60s"),
    /**
     * Only on lease-policy system renewals: the host stores it only as a
     * shortening of its current deadline (never an extension). Omitted otherwise.
     */
    shortenOnly: z.literal(true).optional(),
    /**
     * Lease from READY (creates on `leaseFromReady` hosts): the relative
     * timeout. `deadlineUnixMs` is then the provisional backstop only.
     */
    fromReadyMs: z.number().int().min(1).max(2_073_600_000).optional(),
  })
  .strict();
export type HostLease = z.infer<typeof leaseWireSchema>;
export const LEASE_DISPATCH_KINDS = new Set([
  "sandbox.create",
  "sandbox.reconnect",
  "sandbox.lease.renew",
]);
export function leaseDispatchPayload(
  row: {
    leaseRevision: number;
    leaseExpiresAt: Date | null;
    leaseExpireAction: "STOP" | "DESTROY";
  },
  shortenOnly = false,
  fromReadyMs?: number,
): HostLease {
  return leaseWireSchema.parse({
    revision: row.leaseRevision,
    deadlineUnixMs: row.leaseExpiresAt?.getTime(),
    action: row.leaseExpireAction === "DESTROY" ? "destroy" : "stop",
    expiryPolicy: "retry-force-60s",
    ...(shortenOnly ? { shortenOnly: true } : {}),
    ...(fromReadyMs !== undefined ? { fromReadyMs } : {}),
  });
}

/** Clock skew tolerated on both bounds of a READY-based lease ACK (matches the host). */
export const LEASE_FROM_READY_SKEW_MS = 60_000;

/**
 * Lease-from-READY ACK window (M7): the host's deadline is readyAt + timeout
 * on its own clock. It must lie within [acceptedAt + timeout, min(provisional,
 * dbNow + timeout)], widened by the skew on both ends.
 */
export function fromReadyDeadlineAcceptable(input: {
  deadlineMs: number;
  acceptedAtMs: number;
  timeoutMs: number;
  provisionalMs: number;
  nowMs: number;
}): boolean {
  const lower = input.acceptedAtMs + input.timeoutMs - LEASE_FROM_READY_SKEW_MS;
  const upper =
    Math.min(input.provisionalMs, input.nowMs + input.timeoutMs) + LEASE_FROM_READY_SKEW_MS;
  return input.deadlineMs >= lower && input.deadlineMs <= upper;
}
