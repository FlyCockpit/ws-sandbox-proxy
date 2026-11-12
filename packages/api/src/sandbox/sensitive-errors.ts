import { ORPCError } from "@orpc/server";
import {
  CAPACITY_QUEUE_SCOPES,
  capacityReasonSchema,
  capacityWaitMaxSchema,
  egressRefusalReasonSchema,
  isRetryableRefusalCode,
  isSdkErrorCode,
  leaseMaxTimeoutMsSchema,
  type OperationErrorCode,
  poolFullReasonSchema,
  SDK_ERRORS,
  skippedHostReasonsSchema,
} from "@wssp/sandbox-contracts";
import resultErrors from "../../../config/src/sandbox-result-errors.json";

/** Corrupt accounting is a server fault, never an ordinary relay fence miss. */
export class SandboxIntegrityError extends Error {
  constructor(
    readonly code:
      | "sandbox_reservation_underflow"
      | "sandbox_allocation_mismatch"
      | "sandbox_reservation_nonzero_memory"
      | "sandbox_reservation_nonzero_resources"
      | "sandbox_reservation_unbound"
      | "sandbox_root_unbound"
      | "sandbox_root_underflow",
  ) {
    super(code);
  }
}

export function requireSandboxIntegrity(
  ok: boolean,
  code: SandboxIntegrityError["code"],
): asserts ok {
  if (ok) return;
  const error = new SandboxIntegrityError(code);
  console.error("[sandbox] integrity failure:", safeErrorLog(error, code));
  throw error;
}

function safeCapability(value: unknown) {
  switch (value) {
    case "snapshot":
    case "restore":
    case "fork":
    case "egress":
    case "pause":
    case "ingress":
    case "credentials":
      return value;
    default:
      return undefined;
  }
}

/** Never retain an error's text, stack, cause, invocation, DETAIL or input.
 * Reconstruct known domain failures from a closed values-free catalog. */
export function rethrowSensitiveSandboxError(error: unknown): never {
  if (error && typeof error === "object" && "code" in error && error.code === "P2003")
    throw new ORPCError("CONFLICT", { message: "A referenced resource was removed concurrently." });
  if (error instanceof ORPCError) {
    const data: unknown = error.data;
    const domain = data && typeof data === "object" && "code" in data ? data.code : undefined;
    const code = isSdkErrorCode(domain)
      ? domain
      : isSdkErrorCode(error.code)
        ? error.code
        : "INTERNAL_SERVER_ERROR";
    const statusCode = isSdkErrorCode(error.code) ? error.code : "INTERNAL_SERVER_ERROR";
    const capability =
      domain === "UNSUPPORTED_CAPABILITY" &&
      data &&
      typeof data === "object" &&
      "capability" in data
        ? safeCapability(data.capability)
        : undefined;
    const egressReason =
      domain === "UNSUPPORTED_CAPABILITY" && data && typeof data === "object" && "reason" in data
        ? egressRefusalReasonSchema.safeParse(data.reason)
        : null;
    const reason =
      (code === "sandbox.host_capacity" || code === "sandbox.pool_full") &&
      data &&
      typeof data === "object" &&
      "reason" in data
        ? (code === "sandbox.pool_full" ? poolFullReasonSchema : capacityReasonSchema).safeParse(
            data.reason,
          )
        : null;
    const skipped =
      (code === "sandbox.pool_full" ||
        code === "sandbox.pool_unavailable" ||
        code === "sandbox.share_quota" ||
        code === "sandbox.member_quota") &&
      data &&
      typeof data === "object" &&
      "skipped" in data
        ? skippedHostReasonsSchema.safeParse(data.skipped)
        : null;
    const resource =
      data &&
      typeof data === "object" &&
      "resource" in data &&
      ((code === "sandbox.share_quota" &&
        ["memory", "vcpu", "disk"].includes(String(data.resource))) ||
        (code === "sandbox.member_quota" && ["memory", "vcpu"].includes(String(data.resource))))
        ? data.resource
        : undefined;
    const maxTimeoutMs =
      code === "lease_exceeds_policy" && data && typeof data === "object" && "maxTimeoutMs" in data
        ? leaseMaxTimeoutMsSchema.safeParse(data.maxTimeoutMs)
        : null;
    const maxWaitMs =
      code === "capacity_wait_exceeds_policy" &&
      data &&
      typeof data === "object" &&
      "maxWaitMs" in data
        ? capacityWaitMaxSchema.safeParse(data.maxWaitMs)
        : null;
    const scope =
      code === "sandbox.capacity_queue_full" && data && typeof data === "object" && "scope" in data
        ? CAPACITY_QUEUE_SCOPES.find((value) => value === data.scope)
        : undefined;
    const retryable =
      isRetryableRefusalCode(code) &&
      data &&
      typeof data === "object" &&
      "retryable" in data &&
      typeof data.retryable === "boolean"
        ? data.retryable
        : undefined;
    // Rebuild on miss (template-builds §3.9): closed values only.
    const image =
      code === "sandbox.template_image_unavailable" && data && typeof data === "object"
        ? {
            ...("reason" in data &&
            (data.reason === "rebuilding" || data.reason === "rebuild_quota")
              ? { reason: data.reason }
              : {}),
            ...("hint" in data && data.hint === "rebuild_required"
              ? { hint: "rebuild_required" }
              : {}),
          }
        : {};
    throw new ORPCError(statusCode, {
      status: SDK_ERRORS[code][0],
      message: SDK_ERRORS[code][1],
      ...(isSdkErrorCode(domain)
        ? {
            data: {
              code: domain,
              ...(capability ? { capability } : {}),
              ...(reason?.success ? { reason: reason.data } : {}),
              ...(egressReason?.success ? { reason: egressReason.data } : {}),
              ...(resource ? { resource } : {}),
              ...(maxTimeoutMs?.success ? { maxTimeoutMs: maxTimeoutMs.data } : {}),
              ...(skipped?.success ? { skipped: skipped.data } : {}),
              ...(maxWaitMs?.success ? { maxWaitMs: maxWaitMs.data } : {}),
              ...(scope ? { scope } : {}),
              ...(retryable === undefined ? {} : { retryable }),
              ...image,
            },
          }
        : {}),
    });
  }
  throw new ORPCError("INTERNAL_SERVER_ERROR", { message: SDK_ERRORS.INTERNAL_SERVER_ERROR[1] });
}

// Constructor names come from a closed set: Error.name, overridden constructors
// and dynamically named classes can themselves carry private values.
const ERROR_CLASSES = new Set([
  "Error",
  "TypeError",
  "RangeError",
  "SyntaxError",
  "URIError",
  "EvalError",
  "AggregateError",
  "ORPCError",
  "PrismaClientKnownRequestError",
  "PrismaClientUnknownRequestError",
  "PrismaClientValidationError",
  "PrismaClientInitializationError",
  "PrismaClientRustPanicError",
  "DatabaseError",
  "ReplyError",
  "WorkerDrainError",
  "AbortError",
  "TimeoutError",
]);

/** Values-free diagnostics only; never retain text, stack, cause, DETAIL or input. */
export function safeErrorLog(
  error: unknown,
  fallbackCode = "unhandled_error",
): { code: string; errorClass: string } {
  let code = fallbackCode;
  let errorClass = "UnknownError";
  try {
    if (error instanceof Error) errorClass = "Error";
    if (error && typeof error === "object") {
      const prototype: unknown = Object.getPrototypeOf(error);
      const errorConstructor: unknown =
        prototype && typeof prototype === "object" && "constructor" in prototype
          ? prototype.constructor
          : undefined;
      if (typeof errorConstructor === "function" && ERROR_CLASSES.has(errorConstructor.name))
        errorClass = errorConstructor.name;
      if (
        "code" in error &&
        typeof error.code === "string" &&
        ((error instanceof ORPCError && isSdkErrorCode(error.code)) ||
          /^(?:P\d{4}|\d{5})$/.test(error.code))
      )
        code = error.code;
    }
  } catch {
    // Even malformed getters/proxies cannot turn this backstop into a raw log.
  }
  return { code, errorClass };
}

/**
 * A Node system error code (`EACCES`, `ENOENT`, `EROFS`, ...) or null. The
 * code is a fixed errno token, never text, a path or a value; anything else
 * (including a code that merely starts with `E`) is dropped.
 */
export function safeErrnoCode(error: unknown): string | null {
  try {
    if (error && typeof error === "object" && "code" in error) {
      const code: unknown = error.code;
      if (typeof code === "string" && /^E[A-Z0-9]{2,15}$/.test(code)) return code;
    }
  } catch {
    // A throwing getter yields no diagnostic, never a raw value.
  }
  return null;
}

/** Host error codes are a closed protocol catalog; messages are never authority. */
const OPERATION_ERRORS = {
  fs_not_found: resultErrors.fs_not_found.message,
  fs_is_directory: resultErrors.fs_is_directory.message,
  fs_not_directory: resultErrors.fs_not_directory.message,
  fs_not_regular: resultErrors.fs_not_regular.message,
  fs_permission_denied: resultErrors.fs_permission_denied.message,
  fs_read_only: resultErrors.fs_read_only.message,
  fs_already_exists: resultErrors.fs_already_exists.message,
  fs_not_empty: resultErrors.fs_not_empty.message,
  fs_cross_device: resultErrors.fs_cross_device.message,
  fs_no_space: resultErrors.fs_no_space.message,
  fs_symlink_refused: resultErrors.fs_symlink_refused.message,
  fs_entry_too_large: resultErrors.fs_entry_too_large.message,
  fs_listing_limit: resultErrors.fs_listing_limit.message,
  fs_invalid_encoding: resultErrors.fs_invalid_encoding.message,
  fs_metadata_unrepresentable: resultErrors.fs_metadata_unrepresentable.message,
  process_not_found: resultErrors.process_not_found.message,
  process_exited: resultErrors.process_exited.message,
  process_stale: resultErrors.process_stale.message,
  process_not_started: resultErrors.process_not_started.message,
  process_stdin_closed: resultErrors.process_stdin_closed.message,
  process_cancel_pending: resultErrors.process_cancel_pending.message,
  process_permission_denied: resultErrors.process_permission_denied.message,
  signal_unsupported_on_guest: resultErrors.signal_unsupported_on_guest.message,
  access_denied: "Access denied.",
  cancelled: "Operation cancelled.",
  capacity_wait_timeout: "Timed out waiting for capacity.",
  placement_infeasible: "The request can no longer be placed in this pool.",
  credential_inactive: "Authorizing SDK key is no longer valid.",
  digest_key_changed: "Digest key changed.",
  digest_key_unavailable: "Digest key unavailable.",
  disconnected: "Host disconnected.",
  guest_operation_failed: "Guest operation failed.",
  guest_permission_denied: "Guest permission denied.",
  guest_unavailable: "Guest is unavailable.",
  host_capacity: "Host capacity is full.",
  vm_size_mismatch: SDK_ERRORS["sandbox.vm_size_mismatch"][1],
  host_effect_not_issued: "Host effect was not issued.",
  host_disconnect_expired:
    "The host stayed disconnected past its carry limit and stopped the work.",
  host_runtime_unsupported: "Host runtime is unsupported.",
  idempotency_conflict: "Idempotency key conflicts with existing work.",
  internal: "Operation failed.",
  egress_resolution_failed: "Egress domain could not be resolved to an allowed IPv4 destination.",
  egress_guard_unavailable: "This host's network guard is not running; the sandbox did not start.",
  open_egress_not_permitted:
    "The host owner does not allow open internet for other users' sandboxes; the sandbox did not start.",
  guest_sudo_not_permitted:
    "The host owner does not allow root for the guest user (guestSudo) in other users' sandboxes; the sandbox did not start.",
  guest_sudo_unavailable:
    "Root for the guest user (guestSudo) is unavailable in this image; the sandbox did not start.",
  guest_root_granted:
    "The image grants the guest user root although guestSudo is off; the sandbox did not start.",
  lease_expired: "Sandbox lease expired.",
  lease_exceeds_policy: "Requested lease exceeds the allowed maximum.",
  not_found: "Resource not found.",
  operation_not_found: "Operation not found.",
  path_refused: "Guest path refused.",
  private_config_refused: "Private configuration refused before installation.",
  protocol_error: "Invalid dispatch or host report.",
  protocol_version_unsupported: "Protocol version unsupported.",
  rate_limited: "Request budget exceeded.",
  receipt_digest_pruned: "Receipt digest pruned.",
  request_too_large: "Request exceeds the allowed size.",
  "sandbox.template_image_missing": "Sandbox template image is missing.",
  sandbox_not_found: "Sandbox not found.",
  sandbox_not_running: "Sandbox is not running.",
  snapshot_failed: "Snapshot failed.",
  state_conflict: "Operation conflicts with current state.",
  superseded: "Operation superseded.",
  timeout: "Operation timed out.",
  transfer_expired: "Transfer expired.",
  transfer_quota: "Transfer capacity is full.",
  transport: "Host transport failed.",
  unknown_outcome: "Operation outcome is unknown.",
  unsupported_capability: "Capability is unsupported.",
  expiry_failed: "Host could not enforce sandbox expiry.",
  image_unavailable: "No eligible host could provide the template image.",
  image_cache_full: "The host image cache has no room for this image.",
  image_corrupt: "The downloaded template image failed verification.",
  image_rejected: "The host rejected the downloaded template image.",
  image_fetch_timeout: "The template image download timed out.",
  provision_timeout: "The sandbox did not become ready in time.",
  capture_failed: "The template capture failed.",
  capture_freeze_failed: "The guest filesystem could not be frozen for capture.",
  capture_store_failed: "The captured image could not be stored.",
  startup_failed: "The template start command could not be launched.",
  startup_timeout: "The template ready command did not succeed in time.",
  guest_network_unavailable:
    "The sandbox booted without a network address (no DHCP lease). The host's firewall may drop sandbox bridge traffic; run `wssp guard status` on the host.",
  credential_install_failed: "A login could not be installed in the sandbox.",
  credential_spec_invalid: "The sandbox login specification could not be verified.",
  credential_env_pending: "Login environment is still being restored; retry shortly.",
  credential_capture_failed: "A login could not be captured; the sandbox kept running.",
  disk_stale:
    "The host's cached disk no longer matches the stored copy; the next start restores the stored copy.",
  restore_boot_failed: "The restored disk did not boot; its stored copy is kept.",
  restore_cleanup_pending:
    "Cleanup of a failed restore is pending; retry the cleanup or destroy the sandbox.",
  restore_no_allowed_host: "No host this restore may use had room for the sandbox.",
  "credential.not_attached": SDK_ERRORS["credential.not_attached"][1],
  "credential.not_found": SDK_ERRORS["credential.not_found"][1],
  "credential.account_not_found": SDK_ERRORS["credential.account_not_found"][1],
  "credential.instance_not_found": SDK_ERRORS["credential.instance_not_found"][1],
  "credential.definition_corrupt": SDK_ERRORS["credential.definition_corrupt"][1],
  "credential.spec_too_large": SDK_ERRORS["credential.spec_too_large"][1],
  "credential.env_conflict": SDK_ERRORS["credential.env_conflict"][1],
  "credential.in_use": SDK_ERRORS["credential.in_use"][1],
  "credential.busy": SDK_ERRORS["credential.busy"][1],
  "credential.pending_drain": SDK_ERRORS["credential.pending_drain"][1],
  "credential.needs_login": SDK_ERRORS["credential.needs_login"][1],
  "credential.account_paused": SDK_ERRORS["credential.account_paused"][1],
  "credential.limit_reached": SDK_ERRORS["credential.limit_reached"][1],
  "credential.host_forbidden": SDK_ERRORS["credential.host_forbidden"][1],
  "credential.recovery_required": SDK_ERRORS["credential.recovery_required"][1],
  "credential.path_conflict": SDK_ERRORS["credential.path_conflict"][1],
  "credential.unavailable": SDK_ERRORS["credential.unavailable"][1],
} as const satisfies Record<OperationErrorCode, string> & Record<string, string>;

export function safeOperationError(
  code: OperationErrorCode | null,
  reason?: unknown,
): {
  code: OperationErrorCode;
  message: string;
  reason?: import("@wssp/sandbox-contracts").CapacityReason;
};
export function safeOperationError(
  code: unknown,
  reason?: unknown,
): { code: string; message: string; reason?: import("@wssp/sandbox-contracts").CapacityReason };
export function safeOperationError(
  code: unknown,
  reason?: unknown,
): { code: string; message: string; reason?: import("@wssp/sandbox-contracts").CapacityReason } {
  if (typeof code === "string" && Object.hasOwn(OPERATION_ERRORS, code)) {
    const known = code as keyof typeof OPERATION_ERRORS;
    const capacity =
      known === "host_capacity" ? capacityReasonSchema.safeParse(reason).data : undefined;
    return {
      code: known,
      message: OPERATION_ERRORS[known],
      ...(capacity ? { reason: capacity } : {}),
    };
  }
  return { code: "internal", message: OPERATION_ERRORS.internal };
}
