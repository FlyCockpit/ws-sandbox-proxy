import { type EgressRefusalReason, egressRefusalReasonSchema } from "@wssp/sandbox-contracts";
import { z } from "zod";

/**
 * The ONE mapping from a daemon result error to a typed egress refusal
 * (default-open egress §1.5), applied to every operation result. A refused
 * cold start leaves the sandbox STOPPED (`sandboxStateForLifecycleResult`):
 * `egress_guard_unavailable` is retryable once the node's guard runs again;
 * `open_egress_not_permitted` means the node owner withdrew consent, so it
 * cannot restart there (the user recreates it); `guest_sudo_not_permitted`
 * is its guestSudo twin (OD-2). A refused create fails it.
 *
 * Egress refusals carry a typed reason. Other unsupported features retain
 * their generic capability error.
 */
export function daemonEgressRefusal(error: {
  code: string;
  reason?: string;
}): EgressRefusalReason | undefined {
  if (error.code !== "unsupported_capability") return undefined;
  return egressRefusalReasonSchema.safeParse(error.reason).data;
}

/** Same bound as the `sandbox_instance_egress_denied` column check. */
const MAX_DENIED_GRANTS = 128;
const deniedGrantsSchema = z
  .array(
    z
      .string()
      .min(1)
      .max(253)
      .regex(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/),
  )
  .max(MAX_DENIED_GRANTS);

/**
 * `egressDeniedGrants` of a successful create result (M19): the allowlist
 * grants the node's domain blocklist denied at materialization, reported by
 * the daemon (bounded, sorted, unique). Display data: a malformed list is
 * ignored, never a failed result.
 */
export function createResultDeniedGrants(
  result: Record<string, unknown> | null | undefined,
): string[] | undefined {
  if (result?.egressDeniedGrants === undefined) return undefined;
  const parsed = deniedGrantsSchema.safeParse(result.egressDeniedGrants);
  return parsed.success ? [...new Set(parsed.data)].sort() : undefined;
}
