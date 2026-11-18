/**
 * `data.code` values on the typed errors the administrator procedures throw.
 * The admin UI keys its explanations on these codes, never on message text
 * (messages are English and may change). Pure constants: imported by the web
 * app as well as the routers.
 */
import type { AccountDeletionBlockerKind } from "@wssp/db/account-deletion";

export const ADMIN_ERROR_CODES = {
  /** FORBIDDEN: an admin tried to remove their own admin role. */
  selfDemotion: "admin.self_demotion",
  /** FORBIDDEN: an admin tried to archive their own account. */
  selfArchive: "admin.self_archive",
  /** FORBIDDEN: an admin tried to delete their own account. */
  selfDelete: "admin.self_delete",
  /** CONFLICT: the change would leave no active, verified administrator. */
  lastAdmin: "admin.last_admin",
  /** CONFLICT: live resources block account deletion; `data.blockers` names them. */
  accountDeletionBlocked: "admin.account_deletion_blocked",
  /** NOT_FOUND: the target user does not exist (or is being deleted). */
  userNotFound: "admin.user_not_found",
  /** CONFLICT: an invite named an email that already has an account. */
  emailTaken: "admin.email_taken",
  /** BAD_REQUEST: the auth configuration refused to create the invited account. */
  inviteRefused: "admin.invite_refused",
  /** FORBIDDEN: requiring 2FA for others needs 2FA on the acting admin's account. */
  ownTwoFactorRequired: "admin.own_two_factor_required",
  /** PRECONDITION_FAILED: signup needs verification email, and no mail transport is configured. */
  signupEmailRequired: "admin.signup_email_required",
  /** CONFLICT: a data-key or return-key action was refused; `data.reason` is a {@link DataKeyRefusal}. */
  dataKeyRefused: "admin.data_key_refused",
  /** CONFLICT: the tunnel server setting was refused; `data.reason` is a {@link TunnelConfigRefusal}. */
  tunnelConfigRefused: "admin.tunnel_config_refused",
} as const;

/** `data.reason` of {@link ADMIN_ERROR_CODES.tunnelConfigRefused}; the tunnel card translates each. */
export const TUNNEL_CONFIG_REFUSALS = [
  "url_invalid",
  "key_missing",
  "credential_invalid",
  "credential_required",
  "credential_rejected",
  "server_unreachable",
  "turning_off",
  "turn_off_first",
] as const;
export type TunnelConfigRefusal = (typeof TUNNEL_CONFIG_REFUSALS)[number];

/** `data.reason` of {@link ADMIN_ERROR_CODES.dataKeyRefused}; the admin card translates each. */
export const DATA_KEY_REFUSALS = [
  "not_configured",
  "kid_malformed",
  "key_not_held",
  "not_initialized",
  "not_found",
  "current",
  "already_destroyed",
  "host_not_drained",
  "quarantined_envelopes",
  "already_declared",
  "confirmation_mismatch",
] as const;

export type DataKeyRefusal = (typeof DATA_KEY_REFUSALS)[number];

export type AdminErrorCode = (typeof ADMIN_ERROR_CODES)[keyof typeof ADMIN_ERROR_CODES];

/** Live-state kinds that refuse account deletion (mirrors `@wssp/db/account-deletion`). */
export const ACCOUNT_DELETION_BLOCKER_KINDS = [
  "hosts",
  "sandboxes",
  "operations",
  "outbox",
  "transfers",
  "image_jobs",
  "shared_pool_workloads",
] as const satisfies readonly AccountDeletionBlockerKind[];

export type AccountDeletionBlocker = (typeof ACCOUNT_DELETION_BLOCKER_KINDS)[number];
