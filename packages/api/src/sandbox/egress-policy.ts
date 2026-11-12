import { createHash } from "node:crypto";

import {
  canonicalEgressPolicyJson,
  DENY_ALL_EGRESS_POLICY,
  type EgressPolicyInput,
  EgressPolicyValidationError,
  type EgressPolicyWire,
  egressPolicyFromWire,
  isNormalizedEgressPolicy,
  type NormalizedEgressPolicy,
  normalizeEgressPolicy,
  OPEN_EGRESS_POLICY,
  toEgressPolicyWire,
} from "@wssp/sandbox-contracts";

import { egressPolicyInvalid } from "./errors";

export type RecordedEgressPolicy = {
  /** Normalized form with an explicit mode (DTOs and views). */
  policy: NormalizedEgressPolicy;
  /**
   * Stored and dispatched form (`mode` only when open), so an allowlist row
   * and its relay payload stay byte-identical to the pre-mode wire.
   */
  wire: EgressPolicyWire;
  /** SHA-256 of the canonical normalized policy JSON text (lowercase hex). */
  hash: string;
};

function recorded(policy: NormalizedEgressPolicy, hash?: string): RecordedEgressPolicy {
  return { policy, wire: toEgressPolicyWire(policy), hash: hash ?? hashPolicy(policy) };
}

function hashPolicy(policy: NormalizedEgressPolicy): string {
  // The digest covers the canonical JSON text itself — never a re-serialized,
  // quoted wrapper — so independent implementations can verify it byte-for-byte.
  return createHash("sha256").update(canonicalEgressPolicyJson(policy), "utf8").digest("hex");
}

/**
 * The one normalization step for create admission: the normalized REQUEST
 * (explicit mode). A missing `egress` field requests open internet (§1.1
 * inference); any present field must normalize or the create fails with the
 * typed catalog error before any row or dispatch exists. The effective policy
 * is resolved later, once, by `resolveEffectiveEgress` at materialization.
 */
export function resolveCreateEgressPolicy(
  input: EgressPolicyInput | undefined,
): NormalizedEgressPolicy {
  try {
    return normalizeEgressPolicy(input);
  } catch (error) {
    if (error instanceof EgressPolicyValidationError) throw egressPolicyInvalid();
    throw error;
  }
}

/** Why the effective mode is allowlist although open was requested. */
export type EgressModeReason = "NODE_POLICY" | "HOST_UNSUPPORTED";

/** Host facts read under the host lock (H) at materialization. */
export type EgressHostFacts = {
  ownerId: string;
  /** `daemonFeatures.egressOpen` on the current admission. */
  egressOpen: boolean;
  /** `daemonOpenEgressForOthers` from the current connection's report. */
  openEgressForOthers: boolean;
};

/**
 * The ONLY producer of an effective egress policy (§1.2). Called once per
 * sandbox, by `materializePlacement`, inside the materialization transaction
 * and before the CREATE is enqueued. Never called on reconnect, cold boot,
 * adopt, inventory reconcile or rendering: those read the stored policy, so
 * a sandbox is never narrowed or widened after placement.
 *
 * Precondition (never a downgrade, M11): the host holds an active egress
 * guard lease; placement filters on it in both modes.
 *
 * - allowlist request              → the request itself, no reason
 * - open, host cannot serve open   → allowlist with the request's (fallback) grants, HOST_UNSUPPORTED
 * - open, foreign node, no consent → allowlist with the request's grants, NODE_POLICY
 * - open otherwise                 → open with no grants (fallback grants are inert)
 */
export function resolveEffectiveEgress(
  request: NormalizedEgressPolicy,
  host: EgressHostFacts,
  sandboxOwnerId: string,
): { effective: RecordedEgressPolicy; reason: EgressModeReason | null } {
  const fallback = (reason: EgressModeReason) => ({
    effective: recorded({
      mode: "allowlist",
      domains: [...request.domains],
      cidrs: [...request.cidrs],
    }),
    reason,
  });
  if (request.mode === "allowlist") return { effective: recorded(request), reason: null };
  if (!host.egressOpen) return fallback("HOST_UNSUPPORTED");
  if (host.ownerId !== sandboxOwnerId && !host.openEgressForOthers) return fallback("NODE_POLICY");
  return { effective: recorded(OPEN_EGRESS_POLICY), reason: null };
}

/** Stored request read-back; null for pre-mode rows or a non-canonical value. */
export function recordedEgressRequest(value: unknown): NormalizedEgressPolicy | null {
  return isNormalizedEgressPolicy(value) ? value : null;
}

/**
 * Read-back for stored rows: the recorded policy is authoritative and never
 * re-derivable from metadata, env or a host report. Pre-policy rows (null)
 * read as deny-all with the matching hash; so does a create still waiting
 * for capacity (its effective policy is resolved only at placement), which
 * is fail-safe.
 */
export function recordedEgressPolicy(row: {
  egressPolicy: unknown;
  egressPolicyHash: string | null;
}): RecordedEgressPolicy {
  if (row.egressPolicy == null || row.egressPolicyHash == null) {
    return recorded(DENY_ALL_EGRESS_POLICY);
  }
  const policy = egressPolicyFromWire(row.egressPolicy);
  if (!policy) throw egressPolicyInvalid();
  return recorded(policy, row.egressPolicyHash);
}
