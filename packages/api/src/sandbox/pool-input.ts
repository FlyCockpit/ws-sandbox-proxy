import {
  CAPACITY_WAIT_MAX_MS,
  LEASE_FINITE_MAX_MS,
  LEASE_LIMIT_MIN_MS,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { cursorPageInput } from "../lib/pagination";
import { entityId, resourceSlugSchema, shortText } from "../lib/schemas";

export const poolIdInput = z.object({ id: entityId }).strict();
/** Capacity view: optional template and size overrides (revision defaults fill the rest). */
export const poolCapacityInput = z
  .object({
    id: entityId,
    template: z.string().min(1).max(200).optional(),
    cpuCount: z.number().int().min(1).max(32).optional(),
    memoryMiB: z.number().int().min(512).max(65536).optional(),
    diskGiB: z.number().int().min(1).max(2048).optional(),
  })
  .strict();
/**
 * A finite lease maximum (5 min .. 24 days) or null for "no limit from this
 * layer". Every input that carries it treats omission as "unchanged".
 */
export const leaseMaxInput = z
  .number()
  .int()
  .min(LEASE_LIMIT_MIN_MS)
  .max(LEASE_FINITE_MAX_MS)
  .nullable();
export const listPoolsInput = cursorPageInput.extend({}).strict();
export const createPoolInput = z
  .object({
    slug: resourceSlugSchema,
    label: shortText.max(120),
    maxLeaseMs: leaseMaxInput.optional(),
    unlimitedLeaseForShares: z.boolean().optional(),
  })
  .strict();
export const updatePoolInput = createPoolInput
  .extend({
    id: entityId,
    ownHostsOnly: z.boolean().optional(),
    /** Rank the requester's own member hosts first (sort tier, not a filter). */
    preferOwnHosts: z.boolean().optional(),
    /** Capacity-wait limits; null inherits the operator ceiling (omitted: unchanged). */
    capacityWaitMaxMs: z.number().int().min(0).max(CAPACITY_WAIT_MAX_MS).nullable().optional(),
    capacityQueuePerKeyMax: z.number().int().min(0).max(100_000).nullable().optional(),
    capacityQueuePerOwnerMax: z.number().int().min(0).max(100_000).nullable().optional(),
    disconnectGraceSeconds: z.number().int().min(0).max(2592000).optional(),
    /** GiB of other accounts' images per contributed member; null = no pool limit. */
    memberImageCacheMaxGiB: z.number().int().min(0).max(1048576).nullable().optional(),
  })
  .strict();
export const listPoolMembersInput = cursorPageInput.extend({ poolId: entityId }).strict();
/** Pool owner's view of its capacity queue (bounded, oldest first). */
export const listPoolQueueInput = cursorPageInput.extend({ poolId: entityId }).strict();
export const poolMemberInput = z
  .object({
    poolId: entityId,
    sandboxHostId: entityId,
  })
  .strict();
export const addPoolMemberInput = poolMemberInput
  .extend({ enabled: z.boolean().default(true), maxLeaseMs: leaseMaxInput.optional() })
  .strict();
/** Omitted fields are unchanged; `maxLeaseMs` is the host owner's alone. */
export const updatePoolMemberInput = poolMemberInput
  .extend({ enabled: z.boolean().optional(), maxLeaseMs: leaseMaxInput.optional() })
  .strict();

export const shareCapsInput = z
  .object({
    maxMemoryMiB: z.number().int().min(1).max(16777216).nullable().default(null),
    maxVcpu: z.number().int().min(1).max(8192).nullable().default(null),
    maxDiskGiB: z.number().int().min(1).max(268435456).nullable().default(null),
  })
  .strict();
export const sharePermissionsInput = shareCapsInput
  .extend({
    canUse: z.boolean().default(true),
    canContribute: z.boolean().default(true),
  })
  .strict()
  .refine((value) => value.canUse || value.canContribute);
export const disconnectGraceSecondsInput = z.number().int().min(0).max(2592000);
export const memberPercentInput = z.number().int().min(1).max(100).nullable();

/** Preview of a lease-limit lowering: pool maximum, or one membership's. */
export const previewLeaseLoweringInput = z
  .object({
    scope: z.enum(["pool", "member"]),
    poolId: entityId,
    sandboxHostId: entityId.optional(),
    maxLeaseMs: z.number().int().min(LEASE_LIMIT_MIN_MS).max(LEASE_FINITE_MAX_MS),
  })
  .strict()
  .refine((input) => (input.scope === "member") === (input.sandboxHostId !== undefined));
