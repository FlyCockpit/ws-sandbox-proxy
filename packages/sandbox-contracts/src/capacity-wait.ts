import { z } from "zod";

/** Longest finite capacity wait (24 days, the same 32-bit bound as leases). */
export const CAPACITY_WAIT_MAX_MS = 2_073_600_000;
/** Shortest finite capacity wait a create may request. */
export const CAPACITY_WAIT_MIN_MS = 1_000;

/**
 * `waitForCapacityMs` on a POOL create: how long it may wait in the pool's
 * FIFO queue when no host fits now, or `"unlimited"` (allowed only when no
 * layer sets a limit). Absent means no wait (today's immediate refusal). The
 * lease starts when the create is placed, not while it waits. Direct
 * (`sandboxHostId`) creates refuse it.
 */
export const capacityWaitRequestSchema = z
  .union([
    z.number().int().min(CAPACITY_WAIT_MIN_MS).max(CAPACITY_WAIT_MAX_MS),
    z.literal("unlimited"),
  ])
  .describe(
    'Pool creates only: wait up to this many milliseconds (1000..2073600000) for capacity, or "unlimited". The lease starts at placement.',
  );
export type CapacityWaitRequest = z.infer<typeof capacityWaitRequestSchema>;
