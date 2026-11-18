import { inspect } from "node:util";
import {
  type CapacityReason,
  type HostFileErrorReason,
  type OperationErrorCode,
  type OperationFailure,
  type ProcessRef,
  SDK_ERRORS,
  type SdkErrorCode,
  type SkippedHostReason,
  TEMPLATE_BUILD_ERROR_EXTRAS,
  type TemplateBuildErrorExtrasCode,
} from "@wssp/sandbox-contracts";
import type { z } from "zod";

/**
 * Discriminant of every error the SDK throws.
 *
 * - `unknown`: a mutation was (or may have been) sent and no definitive
 *   answer arrived. The effect may or may not have happened. Poll, or retry
 *   with the same idempotency key; never retry under a new key.
 * - `gone`: content that existed has expired (410). The resource or receipt
 *   is still readable; this is not `not_found`.
 * - `timeout` / `aborted`: a read did not complete in time / was cancelled by
 *   the caller. Mutations report these as `unknown` with that `reason`.
 * - `protocol`: the server answered outside the documented contract (schema
 *   mismatch, unexpected status, refused redirect) on a read.
 * - `invalid_request`: rejected input, either locally before any network IO
 *   or by the server (400/413/415/416).
 */
export const WSSP_ERROR_KINDS = [
  "command_exit",
  "authorization",
  "not_found",
  "gone",
  "unavailable",
  "timeout",
  "capacity",
  "unsupported",
  "unknown",
  "conflict",
  "invalid_request",
  "aborted",
  "protocol",
] as const;
export type WsspErrorKind = (typeof WSSP_ERROR_KINDS)[number];

/** Bounded capacity dimension or transport failure cause; otherwise null. */
export type WsspErrorReason =
  | CapacityReason
  | HostFileErrorReason
  /** `sandbox.capture_unsupported`: what makes the sandbox uncapturable. */
  | "runtime"
  | "state"
  /** `sandbox.image_quota_exceeded`: which image quota is exhausted. */
  | "stored"
  | "downloads"
  /** `sandbox.pool_full` only: capacity is held for an older waiting create. */
  | "reserved"
  /** `sandbox.template_image_unavailable`: the build revision is being rebuilt / the rebuild was refused by quota. */
  | "rebuilding"
  | "rebuild_quota"
  /** `UNSUPPORTED_CAPABILITY` (egress): the host's network guard is not running. */
  | "egress_guard_unavailable"
  /** `UNSUPPORTED_CAPABILITY` (egress): the host owner does not allow open internet for others. */
  | "open_egress_not_permitted"
  /** The node owner does not allow root (`guestSudo`) in other users' sandboxes. */
  | "guest_sudo_not_permitted"
  /** `UNSUPPORTED_CAPABILITY` (tunnel): no tunnel server is configured on this deployment. */
  | "tunnel_off"
  /** `UNSUPPORTED_CAPABILITY` (tunnel): no eligible host runs the tunnel client for you. */
  | "tunnel_no_host"
  /** `UNSUPPORTED_CAPABILITY` (tunnel): this sandbox's host does not run the tunnel client. */
  | "tunnel_host_unsupported"
  /** `UNSUPPORTED_CAPABILITY` (tunnel): the host owner does not allow tunnels for others. */
  | "tunnel_not_shared"
  /** `UNSUPPORTED_CAPABILITY` (tunnel): the sandbox was created without `network.tunnelPorts`. */
  | "tunnel_not_enabled"
  /** `packContext` (local): no descriptor-anchored traversal on this platform. */
  | "unanchored_context"
  | "network"
  | "timeout"
  | "aborted"
  | "server_error"
  | "invalid_response"
  | "redirect_refused"
  /** A fenced 403/404 AFTER a possibly-durable commit (store.ts: the
   * authorize-before-commit window leaves this ambiguous by design). */
  | "maybe_after_commit";

/**
 * Kind of each catalog code on a read. A mutation maps ambiguous 5xx errors
 * to `unknown` (see `classifyCatalogError` for definitive refusals). `satisfies` makes a new catalog code a
 * type error until it is classified here.
 */
const KIND_BY_CODE = {
  "host.not_owned": "authorization",
  "host.agent_access_off": "conflict",
  "host.node_offline": "unavailable",
  "host.command_not_found": "not_found",
  "host_queue.limit": "capacity",
  "host.file_error": "invalid_request",
  "host.file_outcome_unknown": "unknown",
  OPERATION_RESULT_EXPIRED: "gone",
  OPERATION_RESULT_NOT_READY: "conflict",
  OPERATION_RESULT_QUOTA: "capacity",
  OPERATION_RESULT_UNSUPPORTED: "unsupported",
  RESULT_CURSOR_INVALID: "invalid_request",
  RESULT_CURSOR_STALE: "conflict",
  "sandbox.process_not_found": "not_found",
  "sandbox.process_exited": "conflict",
  "sandbox.process_stale": "conflict",
  "sandbox.process_not_started": "conflict",
  "sandbox.process_stdin_closed": "conflict",
  "sandbox.process_cancel_pending": "conflict",
  "sandbox.process_permission_denied": "conflict",
  "sandbox.process_unknown_outcome": "unknown",
  "sandbox.process_unavailable": "unavailable",

  "sandbox.vm_size_invalid": "invalid_request",
  "sandbox.vm_size_unsupported": "unsupported",
  "sandbox.vm_size_mismatch": "conflict",
  "sandbox.disk_below_image": "invalid_request",
  "sandbox.metadata_invalid": "invalid_request",
  "sandbox.name_invalid": "invalid_request",
  "sandbox.name_taken": "conflict",
  digest_key_changed: "conflict",
  digest_key_unavailable: "conflict",
  "sandbox.host_reconnecting": "unavailable",
  receipt_digest_pruned: "conflict",
  BAD_REQUEST: "invalid_request",
  UNAUTHORIZED: "authorization",
  FORBIDDEN: "authorization",
  NOT_FOUND: "not_found",
  METHOD_NOT_SUPPORTED: "unsupported",
  CONFLICT: "conflict",
  PAYLOAD_TOO_LARGE: "invalid_request",
  UNSUPPORTED_MEDIA_TYPE: "invalid_request",
  TOO_MANY_REQUESTS: "capacity",
  INTERNAL_SERVER_ERROR: "unavailable",
  SERVICE_UNAVAILABLE: "unavailable",
  GATEWAY_TIMEOUT: "timeout",
  "sandbox.egress_policy_invalid": "invalid_request",
  lease_exceeds_policy: "invalid_request",
  "sandbox.idempotency_conflict": "conflict",
  "sandbox.state_conflict": "conflict",
  "sandbox.managed": "conflict",
  "sandbox.template_not_found": "not_found",
  "sandbox.template_in_use": "conflict",
  "sandbox.template_image_missing": "conflict",
  "sandbox.template_unavailable": "conflict",
  capacity_wait_exceeds_policy: "invalid_request",
  "sandbox.capacity_queue_full": "capacity",
  "sandbox.key_limit_reached": "capacity",
  "key.self_revoke_forbidden": "authorization",
  "sandbox.template_image_rejected": "invalid_request",
  "sandbox.template_revision_exists": "conflict",
  "sandbox.template_image_unavailable": "unavailable",
  "sandbox.template_store_unavailable": "unavailable",
  "sandbox.capture_unsupported": "unsupported",
  "sandbox.capture_policy_forbidden": "conflict",
  "sandbox.capture_busy": "conflict",
  "sandbox.disk_evicting": "conflict",
  "sandbox.restoring": "conflict",
  restore_no_allowed_host: "conflict",
  "sandbox.disk_offloaded": "conflict",
  "sandbox.disk_unavailable": "unavailable",
  "sandbox.host_forget_unsafe": "conflict",
  "sandbox.capture_invalid": "invalid_request",
  "sandbox.image_quota_exceeded": "capacity",
  "sandbox.host_not_found": "not_found",
  "sandbox.pool_not_found": "not_found",
  "sandbox.pool_no_compatible_host": "conflict",
  "sandbox.pool_unavailable": "unavailable",
  "sandbox.share_quota": "conflict",
  "sandbox.member_quota": "conflict",
  "sandbox.pool_policy_changed": "conflict",
  "sandbox.pool_full": "capacity",
  "sandbox.host_capacity": "capacity",
  "sandbox.host_draining": "conflict",
  "sandbox.host_delete_conflict": "conflict",
  "sandbox.host_unavailable": "unavailable",
  host_runtime_unsupported: "unsupported",
  "sandbox.not_found": "not_found",
  "sandbox.operation_not_found": "not_found",
  "sandbox.invalid_transition": "conflict",
  UNSUPPORTED_CAPABILITY: "unsupported",
  "sandbox.tunnel_not_found": "not_found",
  "sandbox.tunnel_port_undeclared": "invalid_request",
  "sandbox.tunnel_ports_limit": "invalid_request",
  "sandbox.tunnel_not_ready": "conflict",
  "sandbox.tunnel_quota": "capacity",
  "sandbox.tunnel_unavailable": "unavailable",
  TRANSFER_EXPIRED: "gone",
  TRANSFER_QUOTA: "capacity",
  TRANSFER_IO: "unavailable",
  TRANSFER_NOT_READY: "conflict",
  RANGE_NOT_SATISFIABLE: "invalid_request",
  OUTPUT_EXPIRED: "gone",
  "webhook.endpoint_not_found": "not_found",
  "webhook.delivery_not_found": "not_found",
  "webhook.destination_invalid": "invalid_request",
  "webhook.destination_blocked": "invalid_request",
  "webhook.endpoint_limit": "capacity",
  "webhook.endpoint_disabled": "conflict",
  "webhook.event_expired": "gone",
  "template.build_disabled": "unsupported",
  "template.build_recipe_invalid": "invalid_request",
  "template.build_no_builder": "capacity",
  "template.build_concurrency": "capacity",
  "template.build_minutes_exhausted": "capacity",
  "template.build_context_required": "invalid_request",
  "template.build_context_too_large": "invalid_request",
  "template.build_context_busy": "capacity",
  "template.build_context_mismatch": "invalid_request",
  "template.build_not_cancellable": "conflict",
  "template.build_egress_mode_unavailable": "unsupported",
  "template.community_key_scope": "authorization",
  "template.community_unavailable": "unavailable",
  "template.community_managed": "conflict",
  "credential.not_found": "not_found",
  "credential.account_not_found": "not_found",
  "credential.instance_not_found": "not_found",
  "credential.lease_not_found": "not_found",
  "credential.definition_not_found": "not_found",
  "credential.in_use": "conflict",
  "credential.account_paused": "conflict",
  "credential.needs_login": "conflict",
  "credential.limit_reached": "capacity",
  "credential.unavailable": "unsupported",
  "credential.repin_blocked": "conflict",
  "credential.repin_confirm_erase": "invalid_request",
  "credential.value_invalid": "invalid_request",
  "credential.definition_corrupt": "conflict",
  "credential.name_taken": "conflict",
  "credential.busy": "conflict",
  "credential.spec_too_large": "invalid_request",
  "credential.pending_drain": "conflict",
  "credential.recovery_required": "conflict",
  "credential.capture_in_progress": "conflict",
  "credential.host_forbidden": "conflict",
  "credential.env_conflict": "conflict",
  "credential.path_conflict": "conflict",
  "credential.proxy_not_enabled": "conflict",
  "credential.not_attached": "not_found",
  "credential.already_attached": "conflict",
  "credential.login_needs_consent": "conflict",
  "credential.login_requires_upload": "conflict",
  "credential.login_session_not_found": "not_found",
  "credential.login_state": "conflict",
  "definition.invalid": "invalid_request",
  "definition.spec_too_large": "invalid_request",
  "definition.schema_version_unsupported": "invalid_request",
} as const satisfies Record<SdkErrorCode, WsspErrorKind>;

/**
 * 5xx catalog codes the server emits only as a refusal BEFORE any durable
 * write (no receipt, reservation or outbox row), so a mutation answered with
 * one definitely did not happen and is not `unknown`.
 */
const PRE_COMMIT_REFUSALS: ReadonlySet<SdkErrorCode> = new Set(["sandbox.host_reconnecting"]);

/** A transient pre-commit refusal the mutation submit loop waits out. */
export function isTransientRefusal(error: { code: string | null }): boolean {
  return error.code !== null && (PRE_COMMIT_REFUSALS as ReadonlySet<string>).has(error.code);
}

export function classifyCatalogError(code: SdkErrorCode, mutation: boolean): WsspErrorKind {
  if (mutation && SDK_ERRORS[code][0] >= 500 && !PRE_COMMIT_REFUSALS.has(code)) return "unknown";
  return KIND_BY_CODE[code];
}

/**
 * The typed fields of a `template.build_*` refusal, e.g. `recipeCode`, `line`
 * and `column` of `template.build_recipe_invalid`, `skipped` of
 * `template.build_no_builder`, `scope` of `template.build_context_busy`.
 */
export type TemplateBuildErrorDetail = {
  [C in TemplateBuildErrorExtrasCode]: z.output<(typeof TEMPLATE_BUILD_ERROR_EXTRAS)[C]>;
}[TemplateBuildErrorExtrasCode];

/**
 * `credential.value_invalid` detail: `entry` names what failed (for example
 * `env.TOOL_API_KEY`, `bundle.undeclared_path` or `files.missing_required`)
 * and `path` the file entry, when there is one. Neither carries a value.
 */
export type CredentialValueInvalidDetail = {
  readonly entry: string | null;
  readonly path: string | null;
};

/** `sandbox.key_limit_reached` detail. */
export type KeySandboxLimitDetail = {
  readonly maxLiveSandboxes: number;
  readonly liveSandboxes: number;
};
export type WsspErrorPhase = "submit" | "start" | "follow" | "result" | "command" | "lease";
export type WsspErrorInit = {
  phase?: WsspErrorPhase | null;
  process?: ProcessRef | null;
  failure?: OperationFailure | null;
  kind: WsspErrorKind;
  message: string;
  code?: SdkErrorCode | OperationErrorCode | null;
  status?: number | null;
  requestId?: string | null;
  retryAfterSeconds?: number | null;
  route?: string | null;
  reason?: WsspErrorReason | null;
  resource?: "memory" | "vcpu" | "disk" | null;
  /** Finite allowed maximum carried by `lease_exceeds_policy`. */
  maxTimeoutMs?: number | null;
  /** Static host exclusions on pool capacity refusals (never counts). */
  skipped?: readonly SkippedHostReason[] | null;
  /** `capacity_wait_exceeds_policy`: the largest wait allowed (0 = waits disabled). */
  maxWaitMs?: number | null;
  /** `sandbox.capacity_queue_full`: which limit was reached. */
  /** Queue scope (`sandbox.capacity_queue_full`) or image quota (`sandbox.image_quota_exceeded`). */
  scope?: "key" | "owner" | "pool" | "stored" | "downloads" | null;
  /** Capacity, quota and pool refusals (`RETRYABLE_REFUSAL_CODES`): see `WsspError.retryable`. */
  retryable?: boolean | null;
  /** Sandbox of a create whose local wait ended while the server entry remains. */
  sandboxId?: string | null;
  idempotencyKey?: string | null;
  /** Operation whose wait timed out, was aborted or ended failed/unknown. */
  operationId?: string | null;
  /** Stable error code reported by a failed operation. */
  operationErrorCode?: OperationErrorCode | SdkErrorCode | null;
  /**
   * Derived commit key of an interrupted upload, when the error escaped the
   * commit phase: the reservation key rides `idempotencyKey` (retry
   * `files.upload` with it) while this identifies the commit itself.
   */
  commitKey?: string | null;
  /** Fields of a `template.build_*` refusal (see `TemplateBuildErrorDetail`). */
  build?: TemplateBuildErrorDetail | null;
  /** `sandbox.template_image_unavailable`: build again (a COPY build cannot be rebuilt). */
  hint?: "rebuild_required" | null;
  /** `credential.value_invalid`: what failed and, for a file, its path (never a value). */
  valueInvalid?: CredentialValueInvalidDetail | null;
  /** `sandbox.key_limit_reached`: the key's live-sandbox limit and its live creates. */
  keyLimit?: KeySandboxLimitDetail | null;
  cause?: unknown;
};

/**
 * The only error type the transport throws. It never holds the API key, the
 * Authorization header, a response body or an original error object: `cause`
 * is a redacted copy built by `redactCause`.
 */
export class WsspError extends Error {
  override readonly name: string = "WsspError";
  readonly phase: WsspErrorPhase | null;
  readonly process: ProcessRef | null;
  readonly failure: OperationFailure | null;
  readonly kind: WsspErrorKind;
  readonly code: SdkErrorCode | OperationErrorCode | null;
  readonly status: number | null;
  readonly requestId: string | null;
  readonly retryAfterSeconds: number | null;
  /** Registry route ID of the failed call, e.g. `getSandbox`. */
  readonly route: string | null;
  readonly reason: WsspErrorReason | null;
  readonly resource: "memory" | "vcpu" | "disk" | null;
  /** For `lease_exceeds_policy`: the largest finite timeoutMs the target allows. */
  readonly maxTimeoutMs: number | null;
  /** Pool capacity refusals: some visible hosts were excluded for these static reasons. */
  readonly skipped: readonly SkippedHostReason[] | null;
  readonly maxWaitMs: number | null;
  readonly scope: "key" | "owner" | "pool" | "stored" | "downloads" | null;
  /**
   * Capacity, quota and pool refusals (`sandbox.host_capacity`,
   * `sandbox.pool_full`, `sandbox.pool_unavailable`,
   * `sandbox.pool_no_compatible_host`, `sandbox.share_quota`,
   * `sandbox.member_quota`, `sandbox.capacity_queue_full`): `true` when
   * current usage, queue depth or online state blocks the request (back off,
   * honoring `retryAfterSeconds`); `false` when the request alone can never
   * be admitted as configured (fall back or change the request). Always set
   * on those codes. Also true for host.node_offline and false for
   * host.agent_access_off; null on other errors.
   */
  readonly retryable: boolean | null;
  /** A create whose local wait ended: the server entry (and sandbox) remain. */
  readonly sandboxId: string | null;
  /** Key to reuse when retrying a mutation whose outcome is `unknown`. */
  readonly idempotencyKey: string | null;
  readonly operationId: string | null;
  readonly operationErrorCode: OperationErrorCode | SdkErrorCode | null;
  readonly commitKey: string | null;
  /** Fields of a `template.build_*` refusal; null otherwise. */
  readonly build: TemplateBuildErrorDetail | null;
  /** `rebuild_required` on `sandbox.template_image_unavailable`; null otherwise. */
  readonly hint: "rebuild_required" | null;
  /** `credential.value_invalid`: the refused entry and path; null otherwise. */
  readonly valueInvalid: CredentialValueInvalidDetail | null;
  /** `sandbox.key_limit_reached`: destroy one of this key's sandboxes to free a slot; null otherwise. */
  readonly keyLimit: KeySandboxLimitDetail | null;

  constructor(init: WsspErrorInit) {
    super(init.message, init.cause === undefined ? undefined : { cause: init.cause });
    this.kind = init.kind;
    this.phase = init.phase ?? null;
    this.process = init.process ? Object.freeze({ ...init.process }) : null;
    this.failure = init.failure ? Object.freeze({ ...init.failure }) : null;
    this.code = init.code ?? null;
    this.status = init.status ?? null;
    this.requestId = init.requestId ?? null;
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
    this.route = init.route ?? null;
    this.reason = init.reason ?? null;
    this.resource = init.resource ?? null;
    this.maxTimeoutMs = init.maxTimeoutMs ?? null;
    this.skipped = init.skipped ? Object.freeze([...init.skipped]) : null;
    this.maxWaitMs = init.maxWaitMs ?? null;
    this.scope = init.scope ?? null;
    this.retryable = init.retryable ?? null;
    this.sandboxId = init.sandboxId ?? null;
    this.idempotencyKey = init.idempotencyKey ?? null;
    this.operationId = init.operationId ?? null;
    this.operationErrorCode = init.operationErrorCode ?? null;
    this.commitKey = init.commitKey ?? null;
    this.build = init.build ? Object.freeze({ ...init.build }) : null;
    this.hint = init.hint ?? null;
    this.valueInvalid = init.valueInvalid ? Object.freeze({ ...init.valueInvalid }) : null;
    this.keyLimit = init.keyLimit ? Object.freeze({ ...init.keyLimit }) : null;
  }

  [inspect.custom]() {
    return this.toJSON();
  }

  toJSON() {
    return {
      name: this.name,
      phase: this.phase,
      process: this.process,
      failure: this.failure,
      kind: this.kind,
      message: this.message,
      code: this.code,
      status: this.status,
      requestId: this.requestId,
      retryAfterSeconds: this.retryAfterSeconds,
      route: this.route,
      reason: this.reason,
      ...(this.resource ? { resource: this.resource } : {}),
      ...(this.maxTimeoutMs === null ? {} : { maxTimeoutMs: this.maxTimeoutMs }),
      ...(this.skipped ? { skipped: this.skipped } : {}),
      ...(this.maxWaitMs === null ? {} : { maxWaitMs: this.maxWaitMs }),
      ...(this.scope ? { scope: this.scope } : {}),
      ...(this.retryable === null ? {} : { retryable: this.retryable }),
      ...(this.sandboxId ? { sandboxId: this.sandboxId } : {}),
      idempotencyKey: this.idempotencyKey,
      operationId: this.operationId,
      operationErrorCode: this.operationErrorCode,
      commitKey: this.commitKey,
      ...(this.build ? { build: this.build } : {}),
      ...(this.hint ? { hint: this.hint } : {}),
      ...(this.valueInvalid ? { valueInvalid: this.valueInvalid } : {}),
      ...(this.keyLimit ? { keyLimit: this.keyLimit } : {}),
    };
  }
}

export function isWsspError<K extends WsspErrorKind>(
  error: unknown,
  kind?: K,
): error is WsspError & { kind: K } {
  return error instanceof WsspError && (kind === undefined || error.kind === kind);
}

const CREDENTIAL_PATTERN = /\bwssp_(?:sdk|host|device)_[A-Za-z0-9_-]*/gi;
const BEARER_PATTERN = /\bBearer\s+\S+/gi;

/** Remove the client's key and anything credential-shaped from `text`. */
export function redact(text: string, secret: string): string {
  const withoutSecret = secret ? text.split(secret).join("[REDACTED]") : text;
  return withoutSecret
    .replace(BEARER_PATTERN, "Bearer [REDACTED]")
    .replace(CREDENTIAL_PATTERN, "[REDACTED]");
}

const CAUSE_DEPTH = 3;
const CAUSE_TEXT_MAX = 512;
/** Fixed, input-free placeholder used when a thrown value resists inspection. */
const UNINSPECTABLE_CAUSE = "uninspectable thrown value";

function uninspectableCause(): Error {
  const fallback = new Error(UNINSPECTABLE_CAUSE);
  fallback.stack = `Error: ${UNINSPECTABLE_CAUSE}`;
  return fallback;
}

/**
 * A fresh Error chain carrying only the redacted name, message and string
 * `code` of `error` and its causes. The original objects (which an injected
 * fetch could have decorated with request headers) are dropped.
 *
 * NEVER throws: an arbitrary value can be a Proxy or carry throwing
 * accessors (`message`, `cause`, `code`, even `instanceof` traps), and a
 * redaction failure must not escape with the raw value attached or lose the
 * operation context of the error being built. Any inspection failure yields
 * a fixed safe placeholder instead.
 */
export function redactCause(error: unknown, secret: string, depth = 0): Error | undefined {
  if (depth >= CAUSE_DEPTH || error === undefined || error === null) return undefined;
  try {
    return redactCauseCopy(error, secret, depth);
  } catch {
    return uninspectableCause();
  }
}

/**
 * Read-once, primitive-only text: an object-valued `message`/`name` could
 * supply its own `slice`/`split` methods and CAPTURE the secret passed to
 * them by `redact`. Non-strings degrade to a fixed placeholder before any
 * string method runs. The FULL string is returned: truncation happens only
 * after redaction.
 */
function asSafeText(value: unknown, fallback = UNINSPECTABLE_CAUSE): string {
  return typeof value === "string" ? value : fallback;
}

function redactCauseCopy(error: unknown, secret: string, depth: number): Error {
  const source = error instanceof Error ? error : null;
  const rawMessage = source ? source.message : typeof error === "string" ? error : typeof error;
  // Redact the COMPLETE contents first, THEN truncate: slicing first could
  // cut through a credential so exact-key replacement fails and the
  // credential regex finds no word boundary on the surviving fragment.
  const message = redact(asSafeText(rawMessage), secret).slice(0, CAUSE_TEXT_MAX);
  // Reading `.cause` can itself throw; a hostile nested value degrades to the
  // placeholder while the outer (already redacted) message survives.
  let nested: Error | undefined;
  if (source) {
    try {
      nested = redactCause(source.cause, secret, depth + 1);
    } catch {
      nested = uninspectableCause();
    }
  }
  const copy = new Error(message, nested ? { cause: nested } : undefined);
  copy.name = redact(asSafeText(source?.name, "Error"), secret).slice(0, 64);
  // The stack embeds the message; rebuild it from redacted parts only.
  copy.stack = `${copy.name}: ${message}`;
  const code = source && "code" in source ? source.code : undefined;
  if (typeof code === "string") {
    Object.defineProperty(copy, "code", { value: redact(code, secret).slice(0, 64) });
  }
  return copy;
}

/** Add recovery metadata without replacing a precise subclass or retaining a request. */
export function attachErrorContext(
  error: unknown,
  context: Pick<
    WsspErrorInit,
    "operationId" | "idempotencyKey" | "commitKey" | "phase" | "process" | "failure"
  >,
): unknown {
  if (!(error instanceof WsspError)) return error;
  for (const [key, value] of Object.entries(context)) {
    if (value !== undefined && Reflect.get(error, key) == null)
      Object.defineProperty(error, key, {
        value: key === "process" && value ? Object.freeze({ ...context.process }) : value,
        enumerable: true,
        configurable: true,
        writable: false,
      });
  }
  return error;
}
type WithoutPrefix<S extends string, P extends string> = S extends `${P}${infer T}` ? T : S;
export type FileSystemOperationCode = Extract<OperationErrorCode, `fs_${string}`>;
export type FileSystemErrorKind = WithoutPrefix<FileSystemOperationCode, "fs_">;
export class FileSystemError extends WsspError {
  override readonly name = "FileSystemError";
  readonly filesystemKind: FileSystemErrorKind;
  constructor(init: WsspErrorInit & { operationErrorCode: FileSystemOperationCode }) {
    super(init);
    this.filesystemKind = init.operationErrorCode.slice(3) as FileSystemErrorKind;
  }
  override toJSON() {
    return { ...super.toJSON(), filesystemKind: this.filesystemKind };
  }
}
type ProcessOperationCode = Extract<
  OperationErrorCode,
  `process_${string}` | "signal_unsupported_on_guest"
>;
export type ProcessErrorKind =
  | WithoutPrefix<ProcessOperationCode, "process_">
  | WithoutPrefix<Extract<SdkErrorCode, `sandbox.process_${string}`>, "sandbox.process_">;
export class ProcessError extends WsspError {
  override readonly name = "ProcessError";
  readonly processKind: ProcessErrorKind;
  constructor(init: WsspErrorInit) {
    super(init);
    const source = init.operationErrorCode ?? init.code ?? "process_unknown_outcome";
    this.processKind = source.replace(/^sandbox[.]process_|^process_/, "") as ProcessErrorKind;
  }
  override toJSON() {
    return { ...super.toJSON(), processKind: this.processKind };
  }
}
/** A UTF-8 tail never starts inside a code point and never exceeds its byte bound. */
function exceptionTail(text: string, maxBytes = 65536): string {
  const bytes = new TextEncoder().encode(text);
  let start = Math.max(0, bytes.length - maxBytes);
  while (start < bytes.length && (bytes[start]! & 0xc0) === 0x80) start++;
  return new TextDecoder().decode(bytes.subarray(start));
}
export type OutputAvailability = "available" | "expired" | "unavailable";
export type CommandExitErrorInit = {
  operationId: string;
  process: ProcessRef | null;
  exitCode: number;
  stdout: string;
  stderr: string;
  startOffset: number;
  totalBytes: number | null;
  receivedBytes: number;
  retainedBytes: number;
  truncated: boolean;
  discarded: { stdout: number; stderr: number };
  outputAvailability: OutputAvailability;
  idempotencyKey?: string | null;
};
/** Natural nonzero completion only. Output is explicit-access data, absent from automatic inspection. */
export class CommandExitError extends WsspError {
  override readonly name = "CommandExitError";
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly startOffset: number;
  readonly totalBytes: number | null;
  readonly receivedBytes: number;
  readonly retainedBytes: number;
  readonly truncated: boolean;
  readonly discarded: { stdout: number; stderr: number };
  readonly outputAvailability: OutputAvailability;
  constructor(init: CommandExitErrorInit) {
    super({
      kind: "command_exit",
      message: `Command exited with code ${init.exitCode}.`,
      operationId: init.operationId,
      idempotencyKey: init.idempotencyKey,
      process: init.process,
      phase: "command",
    });
    this.exitCode = init.exitCode;
    this.stdout = exceptionTail(init.stdout);
    this.stderr = exceptionTail(init.stderr);
    this.startOffset = init.startOffset;
    this.totalBytes = init.totalBytes;
    this.receivedBytes = init.receivedBytes;
    this.retainedBytes = init.retainedBytes;
    this.truncated = init.truncated || this.stdout !== init.stdout || this.stderr !== init.stderr;
    this.discarded = { ...init.discarded };
    this.outputAvailability = init.outputAvailability;
    Object.defineProperty(this, "stdout", { enumerable: false });
    Object.defineProperty(this, "stderr", { enumerable: false });
  }
  override toJSON() {
    return {
      ...super.toJSON(),
      exitCode: this.exitCode,
      startOffset: this.startOffset,
      totalBytes: this.totalBytes,
      receivedBytes: this.receivedBytes,
      retainedBytes: this.retainedBytes,
      truncated: this.truncated,
      discarded: this.discarded,
      outputAvailability: this.outputAvailability,
    };
  }
}

/** A create that waited for capacity and timed out on the server. */
export function isCapacityWaitTimeout(error: unknown): error is WsspError {
  return (
    error instanceof WsspError &&
    (error.operationErrorCode === "capacity_wait_timeout" || error.code === "capacity_wait_timeout")
  );
}
