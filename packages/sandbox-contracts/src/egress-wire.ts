import { z } from "zod";

/**
 * Relay 1.0 egress wire (additive): the hello capability, the static
 * `egressOpen` admission bit (in `hostAdmissionV11Schema`), and the live
 * `host.egress-state` report. Mirrors `crates/sandbox-protocol/src/egress.rs`;
 * both read `crates/sandbox-protocol/fixtures/control_host_egress_state.json`.
 * The launch policy itself is `egressPolicyWireSchema` (`./egress`).
 */

/** Required hello evidence for open egress and guard support. */
export const egressCapabilitiesV11Schema = z.strictObject({
  /** Static per daemon run: open-mode policies are enforceable on this host. */
  open: z.boolean(),
  /** Egress guard health at hello time (live value: `host.egress-state`). */
  guard: z.boolean(),
});
export type EgressCapabilitiesV11 = z.infer<typeof egressCapabilitiesV11Schema>;

const SAFE_INTEGER_MAX = Number.MAX_SAFE_INTEGER;

/** Guard reasons are bounded machine codes, never free text. */
export const egressGuardReasonSchema = z.string().regex(/^[a-z0-9_]{1,64}$/);
/** Opaque guard process instance id. */
export const egressGuardInstanceIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);

/**
 * Current-link egress report, sent every 5 s and on change: a guard-lease
 * renewal, fenced like `host.lease-policy` (epoch, monotonic sequence) plus
 * the guard instance and generation. `guardOk` ⇔ no `guardReason`; a healthy
 * guard names its instance and generation; instance and generation travel
 * together.
 */
export const hostEgressStateV11Schema = z
  .strictObject({
    type: z.literal("host.egress-state"),
    connectionEpoch: z.number().int().min(1).max(2_147_483_647),
    sequence: z.number().int().min(1).max(SAFE_INTEGER_MAX),
    allowOpenForOthers: z.boolean(),
    /** Required live consent for guest privilege elevation on other users' sandboxes. */
    allowGuestSudoForOthers: z.boolean(),
    guardOk: z.boolean(),
    guardReason: egressGuardReasonSchema.optional(),
    guardInstanceId: egressGuardInstanceIdSchema.optional(),
    guardGeneration: z.number().int().min(1).max(SAFE_INTEGER_MAX).optional(),
  })
  .refine((report) => report.guardOk === (report.guardReason === undefined))
  .refine(
    (report) => (report.guardInstanceId === undefined) === (report.guardGeneration === undefined),
  )
  .refine((report) => !report.guardOk || report.guardInstanceId !== undefined);
export type HostEgressStateV11 = z.infer<typeof hostEgressStateV11Schema>;

/** Guard limits for one deployment list: 4096 CIDRs plus 2048 domains. */
export const EGRESS_BLOCKLIST_MAX_ENTRIES = 4096 + 2048;
const blocklistEntrySchema = z.string().regex(/^[0-9a-z./-]{1,253}$/);

/**
 * Deployment-wide egress blocklist (`egress.blocklist`, default-open egress
 * E6), server → daemon after `hello.ok`, only to daemons advertising the
 * egress capability. Mirrors `EgressBlocklistV11` in
 * `crates/sandbox-protocol/src/egress.rs`; both read
 * `crates/sandbox-protocol/fixtures/egress_blocklist_cases.json`.
 *
 * `configured:false` (no entries) clears the deployment source explicitly;
 * `configured:true` carries the relay-normalized entries, sorted and unique.
 * `invalid:true` (configured, no entries; omitted otherwise) reports a
 * configured list that failed validation: daemons keep their last list and
 * a daemon without one refuses new sandboxes, never an empty list (M13).
 * `digest` is `sha256:<hex>` of `JSON.stringify(entries)`.
 */
export const egressBlocklistV11Schema = z
  .strictObject({
    type: z.literal("egress.blocklist"),
    configured: z.boolean(),
    entries: z.array(blocklistEntrySchema).max(EGRESS_BLOCKLIST_MAX_ENTRIES),
    digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    invalid: z.literal(true).optional(),
  })
  .refine((list) =>
    list.invalid
      ? list.configured && list.entries.length === 0
      : list.configured === list.entries.length > 0,
  )
  .refine((list) =>
    list.entries.every((entry, i) => i === 0 || (list.entries[i - 1] as string) < entry),
  );
export type EgressBlocklistV11 = z.infer<typeof egressBlocklistV11Schema>;
