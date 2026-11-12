import type { SandboxGuestSudoReason } from "@wssp/db";

/** Host facts read under the host lock (H) at materialization. */
export type GuestSudoHostFacts = {
  ownerId: string;
  /** `daemonFeatures.guestSudo` on the current admission. */
  guestSudo: boolean;
  /** `daemonGuestSudoForOthers` from the current connection's report. */
  guestSudoForOthers: boolean;
};

/**
 * The ONLY producer of an effective `guestSudo` (OD-2). Called once per
 * sandbox, by `materializePlacement`, inside the materialization transaction
 * and before the CREATE is enqueued, next to the egress resolver. Never
 * called on reconnect, cold boot, adopt, inventory reconcile, restore or
 * rendering: those read the stored row, so a grant is never widened or
 * narrowed after placement.
 *
 * - not requested                           → false, no reason
 * - host does not advertise `guestSudo`      → false, HOST_UNSUPPORTED
 * - foreign node whose owner does not allow  → false, NODE_POLICY
 * - otherwise                                → true, no reason
 *
 * Placement never filters on consent: the degrade is silent and visible as
 * the reason, as for egress.
 */
export function resolveEffectiveGuestSudo(
  requested: boolean,
  host: GuestSudoHostFacts,
  sandboxOwnerId: string,
): { effective: boolean; reason: SandboxGuestSudoReason | null } {
  if (!requested) return { effective: false, reason: null };
  if (!host.guestSudo) return { effective: false, reason: "HOST_UNSUPPORTED" };
  if (host.ownerId !== sandboxOwnerId && !host.guestSudoForOthers)
    return { effective: false, reason: "NODE_POLICY" };
  return { effective: true, reason: null };
}

/** The revision facts the root taint is computed from. */
export type RevisionRootFacts = {
  builtWithRoot: boolean;
  capturedWithGuestRoot: boolean;
  builtWithWsspRecipe: boolean;
};

/**
 * THE root-taint definition (I15): a sandbox from this revision may reach
 * guest root even with `guestSudo` off. `builtWithWsspRecipe` waives only the
 * `builtWithRoot` term (wssp's own verified base recipe). Never redefine it elsewhere.
 */
export function revisionRootTaint(revision: RevisionRootFacts): boolean {
  return (
    revision.capturedWithGuestRoot || (revision.builtWithRoot && !revision.builtWithWsspRecipe)
  );
}

/** Public spelling of the stored guestSudo reason. */
export function guestSudoReasonDto(
  reason: SandboxGuestSudoReason | null,
): "node_policy" | "host_unsupported" | null {
  return reason === "NODE_POLICY"
    ? "node_policy"
    : reason === "HOST_UNSUPPORTED"
      ? "host_unsupported"
      : null;
}
