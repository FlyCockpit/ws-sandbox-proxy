import type { OperationErrorCode } from "@wssp/sandbox-contracts";

/*
 * The restore wait's login-refusal classes (§8.3c), in a module with no IO so
 * the dashboard reads the same lists (`apps/web/src/lib/sandbox-rules.ts`).
 */

/**
 * Login refusals at placement that waiting cannot cure (§8.3c, §4
 * safeguard 2): the restore ends at once with that login code, never later
 * as `restore_no_allowed_host`. The transient ones
 * (`TRANSIENT_RESTORE_LOGIN_CODES`) can clear while the restore waits, so
 * the row keeps waiting until its deadline.
 */
export const PERMANENT_RESTORE_LOGIN_CODES = [
  "credential.not_attached",
  "credential.not_found",
  "credential.account_not_found",
  "credential.instance_not_found",
  "credential.definition_corrupt",
  "credential.spec_too_large",
  "credential.env_conflict",
  // The set's file paths overlap (`requireDisjointAttachmentSet`): only a
  // detach or re-pin changes it, never waiting.
  "credential.path_conflict",
  // The deployment has CLI logins off or no data key (`requireCredentials`
  // in the claim gate): only an operator restart changes it.
  "credential.unavailable",
] as const satisfies readonly OperationErrorCode[];

/**
 * Login refusals at placement that can clear while the restore waits
 * (§8.3c): the row keeps waiting and records the code in
 * `lastLoginRefusal`. Every evaluation runs under the wait-row lock, so
 * the latest evaluation that reaches a verdict decides it, in its own
 * transaction: a refusal (at target selection, or at the bind's claims,
 * undone to a savepoint) sets it, an evaluation that finds no host with
 * room clears it, a lost race or any other refusal is no verdict and
 * leaves it. At the deadline a set value is the failure code instead of
 * `restore_no_allowed_host`, so the owner sees the login that kept the
 * restore waiting.
 */
export const TRANSIENT_RESTORE_LOGIN_CODES = [
  "credential.in_use",
  "credential.busy",
  "credential.pending_drain",
  "credential.needs_login",
  "credential.account_paused",
  "credential.limit_reached",
  "credential.host_forbidden",
  "credential.recovery_required",
] as const satisfies readonly OperationErrorCode[];
