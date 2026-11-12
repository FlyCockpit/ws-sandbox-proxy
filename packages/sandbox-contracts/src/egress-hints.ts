import { z } from "zod";

/**
 * Relay 1.0 additive blocked-name hints (template-builds , §6.3).
 * Mirrors `crates/sandbox-protocol/src/egress_hints.rs`; the shared fixture
 * is `crates/sandbox-protocol/fixtures/egress_refused.json`.
 *
 * Names are operator-reported text: only lowercase DNS names cross the wire
 * (and are re-checked before display), at most 16 per frame and unique.
 */
export const EGRESS_REFUSED_NAMES_MAX = 16;
export const HINT_DNS_NAME_MAX_BYTES = 253;
export const HINT_DNS_LABEL_MAX_BYTES = 63;
/** Per-sandbox frame budget (≤ 1 frame / 2 s / sandbox). */
export const EGRESS_REFUSED_MIN_INTERVAL_MS = 2_000;

const LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

/** Lowercase DNS name grammar (no trailing dot, `_` allowed for service labels). */
export function validHintDnsName(name: string): boolean {
  return (
    name.length > 0 &&
    name.length <= HINT_DNS_NAME_MAX_BYTES &&
    name.split(".").every((label) => LABEL.test(label))
  );
}

const sandboxIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/);

export const egressRefusedV11Schema = z.strictObject({
  type: z.literal("egress.refused"),
  sandboxId: sandboxIdSchema,
  names: z
    .array(z.string().refine(validHintDnsName))
    .min(1)
    .max(EGRESS_REFUSED_NAMES_MAX)
    .refine((names) => new Set(names).size === names.length),
});
export type EgressRefusedV11 = z.infer<typeof egressRefusedV11Schema>;
