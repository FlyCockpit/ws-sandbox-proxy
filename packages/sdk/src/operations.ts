import {
  isSdkErrorCode,
  type OperationErrorCode,
  type SdkErrorCode,
} from "@wssp/sandbox-contracts";
import {
  classifyCatalogError,
  FileSystemError,
  type FileSystemOperationCode,
  ProcessError,
  WsspError,
  type WsspErrorKind,
} from "./errors";
import {
  longPollRead,
  longPollWaitMs,
  type PollContext,
  type PollingOptions,
  poll,
  resolvePolling,
  type WaitOptions,
  waitTimeout,
} from "./polling";
import type { RouteResponse, WsspTransport } from "./transport";

/** Terminal read of `/v1/operations/{id}`: a status record or an action receipt. */
export type OperationRead = RouteResponse<"getOperation">;

/**
 * Kind of a FAILED operation, from its stable operation error code. Exhaustive
 * on purpose (`satisfies`): a new catalog code fails to compile until it is
 * classified here. Action receipts carry SDK error codes instead; those fall
 * back to `classifyCatalogError`.
 */
const FAILED_KIND_BY_OPERATION_CODE = {
  fs_not_found: "not_found",
  fs_is_directory: "conflict",
  fs_not_directory: "conflict",
  fs_not_regular: "conflict",
  fs_permission_denied: "conflict",
  fs_read_only: "conflict",
  fs_already_exists: "conflict",
  fs_not_empty: "conflict",
  fs_cross_device: "conflict",
  fs_no_space: "capacity",
  fs_symlink_refused: "invalid_request",
  fs_entry_too_large: "invalid_request",
  fs_listing_limit: "capacity",
  fs_invalid_encoding: "invalid_request",
  fs_metadata_unrepresentable: "invalid_request",
  process_not_found: "not_found",
  process_exited: "conflict",
  process_stale: "conflict",
  process_not_started: "conflict",
  process_stdin_closed: "conflict",
  process_cancel_pending: "conflict",
  process_permission_denied: "conflict",
  signal_unsupported_on_guest: "unsupported",

  access_denied: "authorization",
  cancelled: "aborted",
  capacity_wait_timeout: "timeout",
  placement_infeasible: "conflict",
  credential_inactive: "authorization",
  disconnected: "unavailable",
  egress_resolution_failed: "invalid_request",
  egress_guard_unavailable: "unavailable",
  open_egress_not_permitted: "unsupported",
  guest_sudo_not_permitted: "unsupported",
  guest_sudo_unavailable: "unsupported",
  guest_root_granted: "conflict",
  digest_key_changed: "conflict",
  digest_key_unavailable: "conflict",
  receipt_digest_pruned: "conflict",
  guest_operation_failed: "unavailable",
  guest_permission_denied: "authorization",
  guest_unavailable: "unavailable",
  host_capacity: "capacity",
  host_effect_not_issued: "unavailable",
  host_disconnect_expired: "unavailable",
  host_runtime_unsupported: "unsupported",
  idempotency_conflict: "conflict",
  internal: "unavailable",
  lease_expired: "conflict",
  lease_exceeds_policy: "invalid_request",
  not_found: "not_found",
  "sandbox.template_image_missing": "conflict",
  operation_not_found: "not_found",
  path_refused: "invalid_request",
  protocol_error: "protocol",
  protocol_version_unsupported: "unsupported",
  rate_limited: "capacity",
  request_too_large: "invalid_request",
  sandbox_not_found: "not_found",
  sandbox_not_running: "conflict",
  snapshot_failed: "unavailable",
  state_conflict: "conflict",
  vm_size_mismatch: "conflict",
  superseded: "conflict",
  timeout: "timeout",
  transport: "unavailable",
  unknown_outcome: "unknown",
  unsupported_capability: "unsupported",
  image_unavailable: "unavailable",
  image_cache_full: "capacity",
  image_corrupt: "unavailable",
  image_rejected: "invalid_request",
  image_fetch_timeout: "timeout",
  provision_timeout: "timeout",
  capture_failed: "unavailable",
  capture_freeze_failed: "unavailable",
  capture_store_failed: "unavailable",
  startup_failed: "unavailable",
  startup_timeout: "timeout",
  guest_network_unavailable: "unavailable",
  credential_install_failed: "unavailable",
  credential_spec_invalid: "unavailable",
  credential_env_pending: "unavailable",
  credential_capture_failed: "unavailable",
  disk_stale: "conflict",
  restore_boot_failed: "unavailable",
  restore_cleanup_pending: "conflict",
  restore_no_allowed_host: "conflict",
  // A queued restore's permanent login refusal: the catalog code's kind.
  "credential.not_attached": "not_found",
  "credential.not_found": "not_found",
  "credential.account_not_found": "not_found",
  "credential.instance_not_found": "not_found",
  "credential.definition_corrupt": "conflict",
  "credential.spec_too_large": "invalid_request",
  "credential.env_conflict": "conflict",
  // A queued restore whose last pass a transient login refusal stopped.
  "credential.in_use": "conflict",
  "credential.busy": "conflict",
  "credential.pending_drain": "conflict",
  "credential.needs_login": "conflict",
  "credential.account_paused": "conflict",
  "credential.limit_reached": "capacity",
  "credential.host_forbidden": "conflict",
  "credential.recovery_required": "conflict",
  // A queued restore that a permanent login refusal ended at once.
  "credential.path_conflict": "conflict",
  "credential.unavailable": "unsupported",
} as const satisfies Record<OperationErrorCode, WsspErrorKind>;

function failedKind(code: OperationErrorCode | SdkErrorCode | null): WsspErrorKind {
  if (code !== null && code in FAILED_KIND_BY_OPERATION_CODE) {
    return FAILED_KIND_BY_OPERATION_CODE[code as OperationErrorCode];
  }
  if (isSdkErrorCode(code)) return classifyCatalogError(code, false);
  return "unavailable";
}

/**
 * Throw for every non-success terminal outcome. `unknown` stays `unknown` and
 * is never retried by the SDK; `failed` maps the stable error code to a kind;
 * `cancelled` reports as `aborted`.
 */
export function ensureSucceeded(operation: OperationRead, context: PollContext): void {
  if (operation.outcome === "succeeded") return;
  const base = {
    phase: context.phase,
    process: context.process,
    operationId: operation.id,
    operationErrorCode: operation.errorCode,
    code: operation.errorCode,
    ...((operation.errorCode === "host_capacity" ||
      operation.errorCode === "capacity_wait_timeout") &&
    "failure" in operation &&
    operation.failure?.reason
      ? { reason: operation.failure.reason }
      : {}),
    idempotencyKey: context.idempotencyKey ?? null,
  };
  if (operation.outcome === "failed") {
    const init = {
      kind: failedKind(operation.errorCode),
      message:
        operation.errorCode === "unknown_outcome"
          ? // A FAILED unknown_outcome is settled: the node daemon never
            // reported a result (most often because it restarted).
            `${context.label}: the operation failed (unknown_outcome): the node daemon could not confirm a result (it restarted or lost its connection mid-operation). Nothing is retried; submit it again with a new idempotency key.`
          : operation.errorCode === "host_disconnect_expired"
            ? // The host proved it stopped the work at its `max_carry` cap.
              `${context.label}: the operation failed (host_disconnect_expired): the node stayed disconnected from the server past its carry limit, so it stopped the work. Nothing is retried; submit it again with a new idempotency key.`
            : operation.errorCode === "guest_unavailable" &&
                "readinessReason" in operation &&
                operation.readinessReason
              ? // The guest readiness check that failed (a fixed label).
                `${context.label}: the operation failed (guest_unavailable: readiness check ${operation.readinessReason} failed).`
              : `${context.label}: the operation failed (${operation.errorCode ?? "internal"}).`,
      failure: "failure" in operation ? operation.failure : null,
      ...base,
    };
    const code = operation.errorCode;
    if (code?.startsWith("fs_"))
      throw new FileSystemError({
        ...init,
        operationErrorCode: code as FileSystemOperationCode,
      });
    if (code?.startsWith("process_") || code === "signal_unsupported_on_guest")
      throw new ProcessError(init);
    throw new WsspError(init);
  }
  if (operation.outcome === "cancelled") {
    throw new WsspError({
      kind: "aborted",
      message: `${context.label}: the operation was cancelled.`,
      ...base,
    });
  }
  throw new WsspError({
    kind: "unknown",
    reason: "server_error",
    message: `${context.label}: the operation outcome is unknown; ${context.idempotencyKey ? "retry only with the same idempotency key." : "recover using this operation ID; do not submit replacement work."}`,
    ...base,
  });
}

/**
 * Poll one operation until it reaches a terminal outcome. Each read asks the
 * server to hold it until the outcome changes (`polling.longPollMs`), so a
 * completion is seen within one round trip instead of the next poll interval.
 */
export async function waitOperation(
  transport: WsspTransport,
  defaults: PollingOptions | undefined,
  id: string,
  options: WaitOptions = {},
  context: PollContext = { label: `operation ${id}`, operationId: id },
): Promise<OperationRead> {
  const polling = resolvePolling(defaults, options);
  const ctx: PollContext = { ...context, operationId: id };
  return poll<OperationRead>(
    async (attempt, { remainingMs }) => {
      const { value: operation, waited } = await longPollRead(
        transport,
        longPollWaitMs(polling, remainingMs),
        (query, timeoutMs) =>
          transport.request("getOperation", {
            params: { id },
            query,
            signal: attempt,
            ...(timeoutMs !== undefined ? { timeoutMs } : {}),
          }),
      );
      if (operation.id !== id)
        throw new WsspError({
          kind: "protocol",
          reason: "invalid_response",
          message: "Operation status identity does not match the request.",
          operationId: id,
        });
      return operation.outcome === "pending"
        ? { done: false, waited }
        : { done: true, value: operation };
    },
    polling,
    options.signal,
    ctx,
  );
}

export type OperationsApi = {
  /** One kind-scoped, versioned result read; legacy and expired results refuse. */
  getResult(id: string, options?: WaitOptions): Promise<RouteResponse<"getOperationResult">>;
  /** One read of an operation's status metadata. */
  get(id: string, options?: WaitOptions): Promise<OperationRead>;
  /** Poll until a terminal outcome; the result may still be failed/unknown. */
  wait(id: string, options?: WaitOptions): Promise<OperationRead>;
};

export function createOperationsApi(
  transport: WsspTransport,
  defaults: PollingOptions | undefined,
): OperationsApi {
  return {
    getResult: async (id, options = {}) => {
      const result = await transport.request("getOperationResult", {
        params: { id },
        signal: options.signal,
        timeoutMs: waitTimeout(options),
      });
      if (result.operationId !== id)
        throw new WsspError({
          kind: "protocol",
          reason: "invalid_response",
          message: "Operation result identity does not match the request.",
          operationId: id,
        });
      return result;
    },
    get: (id, options = {}) =>
      transport.request("getOperation", {
        params: { id },
        signal: options.signal,
        timeoutMs: waitTimeout(options),
      }),
    wait: (id, options) => waitOperation(transport, defaults, id, options),
  };
}
