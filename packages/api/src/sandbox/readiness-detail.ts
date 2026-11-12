import { type ReadinessFailureReason, readinessFailureReasonSchema } from "@wssp/sandbox-contracts";
import { z } from "zod";

/**
 * Operator-facing readiness failure text: fixed per reason, never host text.
 * Pure (no env, queue or Prisma-client imports), shared with `public-dto.ts`.
 */
const READINESS_FAILURE_DETAIL: Record<ReadinessFailureReason, string> = {
  agent_timeout: "the guest agent did not answer within the readiness budget",
  vm_not_running: "the VM stopped, or entered an error state, during readiness",
  guest_restarts: "the guest kept restarting during readiness",
  architecture: "the VM architecture differs from the template's",
  guest_user: "the template's guest user, uid or gid does not match",
  guest_home: "the guest user's HOME is missing, not writable or wrongly owned",
  guest_shell: "the guest user's login shell is missing or differs",
  guest_repo: "$HOME/repo is missing, not writable or wrongly owned",
  guest_tooling: "a required guest tool (setsid, python3, coreutils) is missing",
  guest_check: "a guest readiness check failed",
  guest_sudo_unavailable:
    "guestSudo was requested but the image has no usable `sudo` or the grant did not take effect",
  guest_root_granted:
    "guestSudo is off but the image grants the guest user root (a sudoers rule, a privileged group or doas)",
};

const DETAIL_PREFIX = "Sandbox guest readiness failed (";

/** The stored error detail of a readiness failure (`true`: no reason reported). */
export function readinessFailureDetail(reason: true | ReadinessFailureReason): string {
  return reason === true
    ? "Sandbox guest readiness failed; cleanup queued."
    : `${DETAIL_PREFIX}${reason}: ${READINESS_FAILURE_DETAIL[reason]}); cleanup queued.`;
}

/**
 * The operation `failure` record of a readiness failure: only the fixed
 * label, never the detail text. It is not a public `failure` (that schema is
 * strict), so the `/v1` operation exposes it as `readinessReason` alone.
 */
export function readinessFailureRecord(reason: ReadinessFailureReason) {
  return { readinessReason: reason };
}

const readinessFailureRecordSchema = z
  .object({ readinessReason: readinessFailureReasonSchema })
  .strict();

/** The label of a stored readiness failure record, if it is exactly one. */
export function readinessReasonOfFailure(failure: unknown): ReadinessFailureReason | undefined {
  return readinessFailureRecordSchema.safeParse(failure).data?.readinessReason;
}
