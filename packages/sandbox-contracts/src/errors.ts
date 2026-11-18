import { z } from "zod";
import { CAPACITY_WAIT_MAX_MS } from "./capacity-wait";
import { LEASE_FINITE_MAX_MS, LEASE_LIMIT_MIN_MS } from "./lease-limits";
import { tunnelRefusalReasonSchema } from "./tunnels";

/**
 * The public `/v1` error catalog: stable code → [HTTP status, constant message].
 * Messages never reflect internal error text. Servers, the OpenAPI document and
 * SDK typed errors all consume this one table.
 */
export const SDK_ERRORS = {
  "host.not_owned": [403, "Host is not owned by this credential's owner."],
  "host.agent_access_off": [409, "Agent access is disabled on this host."],
  "host.node_offline": [409, "Host node is offline; retry shortly."],
  "host.command_not_found": [404, "Host command not found."],
  "host_queue.limit": [409, "Queued host command limit reached."],
  "host.file_error": [422, "Host file operation failed."],
  "host.file_outcome_unknown": [
    409,
    "The host file change was sent but its outcome is unknown; read the file before changing it again.",
  ],
  OPERATION_RESULT_NOT_READY: [409, "Operation result is not ready."],
  OPERATION_RESULT_UNSUPPORTED: [400, "Operation has no supported typed result."],
  OPERATION_RESULT_EXPIRED: [410, "Operation result has expired; status remains available."],
  OPERATION_RESULT_QUOTA: [429, "Operation result capacity is full."],
  RESULT_CURSOR_INVALID: [400, "Result cursor does not match this request."],
  RESULT_CURSOR_STALE: [409, "Result cursor generation is stale."],
  "sandbox.process_not_found": [404, "Process not found."],
  "sandbox.process_exited": [409, "Process has exited."],
  "sandbox.process_stale": [409, "Process reference is stale."],
  "sandbox.process_not_started": [409, "Process has not started."],
  "sandbox.process_stdin_closed": [409, "Process stdin is closed."],
  "sandbox.process_cancel_pending": [409, "Process cancellation is pending."],
  "sandbox.process_permission_denied": [409, "Guest process permission denied."],
  "sandbox.process_unknown_outcome": [409, "Process outcome is unknown."],
  "sandbox.process_unavailable": [409, "Process host is unavailable."],

  "sandbox.vm_size_invalid": [400, "VM size is invalid."],
  "sandbox.vm_size_unsupported": [409, "VM size exceeds the target capacity."],
  "sandbox.vm_size_mismatch": [409, "VM size conflicts with the accepted allocation."],
  "sandbox.disk_below_image": [
    400,
    "The requested disk is smaller than the template image's root disk; request at least the revision's minDiskGiB.",
  ],
  "sandbox.metadata_invalid": [400, "Metadata exceeds the allowed shape or size."],
  "sandbox.name_invalid": [
    400,
    "Sandbox name must be 1-63 lowercase letters, digits and inner hyphens, not UUID-shaped and not starting with wssp-.",
  ],
  "sandbox.name_taken": [409, "Another live sandbox already uses this name."],
  "sandbox.egress_policy_invalid": [400, "Egress policy exceeds the allowed shape or size."],
  lease_exceeds_policy: [400, "Requested lease exceeds the allowed maximum."],
  capacity_wait_exceeds_policy: [400, "Requested capacity wait exceeds the allowed maximum."],
  "sandbox.capacity_queue_full": [409, "The capacity queue is full."],
  digest_key_changed: [409, "Digest key changed."],
  digest_key_unavailable: [409, "Digest key unavailable."],
  "sandbox.host_reconnecting": [503, "Host is reconnecting; retry shortly."],
  receipt_digest_pruned: [409, "Receipt digest pruned."],
  BAD_REQUEST: [400, "Invalid request."],
  UNAUTHORIZED: [401, "A valid SDK bearer key is required."],
  FORBIDDEN: [403, "This key cannot perform this action."],
  NOT_FOUND: [404, "Resource not found."],
  METHOD_NOT_SUPPORTED: [405, "Method not supported."],
  CONFLICT: [409, "The request conflicts with current state."],
  PAYLOAD_TOO_LARGE: [413, "Request body exceeds the allowed size."],
  UNSUPPORTED_MEDIA_TYPE: [415, "An uncompressed JSON body is required."],
  TOO_MANY_REQUESTS: [429, "Request budget exceeded."],
  INTERNAL_SERVER_ERROR: [500, "An internal error occurred."],
  SERVICE_UNAVAILABLE: [503, "Service temporarily unavailable."],
  GATEWAY_TIMEOUT: [504, "The upstream request timed out."],
  "sandbox.idempotency_conflict": [409, "Idempotency key was used for different input."],
  "sandbox.state_conflict": [409, "Sandbox state conflicts with this action."],
  "sandbox.managed": [409, "This sandbox is managed by wssp and cannot be used for this action."],
  "sandbox.template_not_found": [404, "Template not found."],
  "sandbox.template_in_use": [409, "Template is still used by sandboxes that are not deleted."],
  "sandbox.template_image_missing": [409, "The exact template image is missing on this host."],
  "sandbox.template_unavailable": [
    409,
    "The template revision is not available on any eligible host in this pool.",
  ],
  "sandbox.template_image_rejected": [400, "The host rejected the template image."],
  "sandbox.template_revision_exists": [409, "This template revision already exists."],
  "sandbox.template_image_unavailable": [
    409,
    "No eligible host has or can fetch this template image.",
  ],
  "sandbox.template_store_unavailable": [
    409,
    "The image store cannot keep a capture taken on this host.",
  ],
  "sandbox.capture_unsupported": [409, "This sandbox cannot be captured."],
  "sandbox.capture_policy_forbidden": [409, "The template's image placement forbids this capture."],
  "sandbox.capture_busy": [409, "A capture is already running for this sandbox or host."],
  "sandbox.disk_evicting": [
    409,
    "The sandbox's cached disk is being evicted; retry the start shortly.",
  ],
  "sandbox.restoring": [409, "The sandbox is being restored; retry once the restore settles."],
  restore_no_allowed_host: [409, "No host this restore may use has room for the sandbox."],
  "sandbox.disk_offloaded": [
    409,
    "The sandbox's disk is offloaded to the image store; start the sandbox first.",
  ],
  "sandbox.disk_unavailable": [
    409,
    "The sandbox's stored disk cannot be used on this deployment right now.",
  ],
  "sandbox.host_forget_unsafe": [
    409,
    "The host still holds sandboxes whose cleanup cannot be proven; forget is refused.",
  ],
  "sandbox.capture_invalid": [400, "Capture request is invalid."],
  "sandbox.image_quota_exceeded": [409, "The account's image quota is exhausted."],
  "sandbox.host_not_found": [404, "Host not found."],
  "sandbox.pool_not_found": [404, "Pool not found."],
  "sandbox.pool_no_compatible_host": [409, "Pool has no compatible host."],
  "sandbox.pool_unavailable": [409, "Pool is unavailable."],
  "sandbox.share_quota": [409, "Share resource quota exceeded."],
  "sandbox.member_quota": [409, "Member resource quota exceeded."],
  "sandbox.pool_policy_changed": [409, "Pool grace decreased. Review the policy before retrying."],
  "sandbox.pool_full": [409, "Pool capacity is full."],
  "sandbox.host_capacity": [409, "Host capacity is full."],
  "sandbox.host_draining": [409, "Host is draining."],
  "sandbox.host_delete_conflict": [409, "Host cannot be deleted in its current state."],
  "sandbox.host_unavailable": [409, "Host is unavailable."],
  host_runtime_unsupported: [400, "Host runtime is unsupported."],
  "sandbox.not_found": [404, "Sandbox not found."],
  "sandbox.operation_not_found": [404, "Operation not found."],
  "sandbox.invalid_transition": [409, "Sandbox transition is invalid."],
  UNSUPPORTED_CAPABILITY: [400, "Capability is unsupported."],
  "sandbox.tunnel_not_found": [404, "This sandbox has no tunnel."],
  "sandbox.tunnel_port_undeclared": [
    400,
    "The port was not declared for tunnels when the sandbox was created.",
  ],
  "sandbox.tunnel_not_ready": [409, "The tunnel is not connected yet; retry shortly."],
  "sandbox.tunnel_quota": [409, "The account's tunnel limit is reached."],
  "sandbox.tunnel_unavailable": [503, "The tunnel server is unavailable."],
  TRANSFER_EXPIRED: [410, "Transfer content has expired; the receipt is still available."],
  TRANSFER_QUOTA: [429, "Transfer capacity is full."],
  TRANSFER_IO: [503, "Transfer storage is unavailable."],
  TRANSFER_NOT_READY: [409, "The file capture is not complete; poll the operation."],
  RANGE_NOT_SATISFIABLE: [416, "The requested byte range cannot be satisfied."],
  OUTPUT_EXPIRED: [410, "Command output has expired; the operation status is still available."],
  "webhook.endpoint_not_found": [404, "Webhook endpoint not found."],
  "webhook.delivery_not_found": [404, "Webhook delivery not found."],
  "webhook.destination_invalid": [400, "Webhook destination URL is invalid."],
  "webhook.destination_blocked": [400, "Webhook destination is not allowed."],
  "webhook.endpoint_limit": [409, "Webhook endpoint limit reached."],
  "webhook.endpoint_disabled": [409, "Webhook endpoint is disabled."],
  "webhook.event_expired": [410, "Webhook event is too old to redeliver."],
  "template.build_disabled": [409, "Template builds are unavailable on this server."],
  "template.build_recipe_invalid": [400, "The build recipe is invalid."],
  "template.build_no_builder": [409, "No builder host can run this build."],
  "template.build_concurrency": [409, "The account is running its maximum number of builds."],
  "template.build_minutes_exhausted": [409, "The account's build minutes for this month are used."],
  "template.build_context_required": [
    400,
    "A recipe with COPY needs contextSha256 and contextBytes.",
  ],
  "template.build_context_too_large": [400, "The build context exceeds the allowed size."],
  "template.build_context_busy": [429, "Staged build-context capacity is full."],
  "template.build_context_mismatch": [
    400,
    "The uploaded build context does not match its SHA-256.",
  ],
  "template.build_not_cancellable": [409, "The build has already finished."],
  "template.build_egress_mode_unavailable": [
    400,
    "This egress mode is not available for template builds yet.",
  ],
  "template.community_key_scope": [
    403,
    "Community templates need a key that can see every template and revision.",
  ],
  "template.community_unavailable": [409, "No tested community image is available right now."],
  "template.community_managed": [409, "This community template is managed by wssp."],
  "credential.not_found": [404, "Login not found."],
  "credential.account_not_found": [404, "Login account not found."],
  "credential.instance_not_found": [404, "Login instance not found."],
  "credential.lease_not_found": [404, "Login lease not found."],
  "credential.definition_not_found": [404, "Login definition not found."],
  "credential.in_use": [409, "Every matching login instance is in use."],
  "credential.account_paused": [409, "The login account is paused."],
  "credential.needs_login": [409, "No matching login instance is ready; log in or upload a value."],
  "credential.limit_reached": [409, "A login limit was reached."],
  "credential.unavailable": [400, "CLI logins are not available on this server."],
  "credential.repin_blocked": [
    409,
    "The login has live leases, recoverable residue or pending captures; it cannot be re-pinned now.",
  ],
  "credential.repin_confirm_erase": [
    400,
    "Re-pinning erases proxy values; confirm with the login's name.",
  ],
  "credential.value_invalid": [400, "The login value does not match its definition."],
  "credential.definition_corrupt": [409, "The stored login definition does not match its digest."],
  "credential.name_taken": [409, "That name is already used."],
  "credential.busy": [409, "The login instance is held by a running sandbox or a login session."],
  "credential.spec_too_large": [400, "The sandbox's login specification is too large."],
  "credential.pending_drain": [
    409,
    "The sandbox's host has not yet settled its login captures; retry shortly.",
  ],
  "credential.recovery_required": [
    409,
    "The sandbox's disk holds a login value that must be recovered first; start the sandbox or force-release the login.",
  ],
  "credential.capture_in_progress": [
    409,
    "A login is being installed, captured or recovered on this sandbox; capture it once that settles.",
  ],
  "credential.host_forbidden": [
    409,
    "A login attached to this sandbox is not allowed on that host.",
  ],
  "credential.env_conflict": [
    409,
    "The login's environment variables collide with the sandbox's environment or another attached login.",
  ],
  "credential.path_conflict": [
    409,
    "The login's files overlap the files of another login attached to this sandbox.",
  ],
  "credential.proxy_not_enabled": [
    409,
    "Proxy-mode logins can only be attached to a sandbox created with one.",
  ],
  "credential.not_attached": [404, "That login is not attached to this sandbox."],
  "credential.already_attached": [409, "That login is already attached to this sandbox."],
  "credential.login_needs_consent": [
    409,
    "None of your own hosts can run this login; allow a foreign host for this login session to continue.",
  ],
  "credential.login_requires_upload": [
    409,
    "This login is initialized by uploading a value, not by a login sandbox.",
  ],
  "credential.login_session_not_found": [404, "Login session not found."],
  "credential.login_state": [409, "The login session cannot do that in its current state."],
  "definition.invalid": [400, "The login definition is invalid."],
  "definition.spec_too_large": [
    400,
    "The login definition's paths or proxy settings are too large to dispatch.",
  ],
  "definition.schema_version_unsupported": [
    400,
    "The login definition schema version is not supported.",
  ],
} as const satisfies Record<string, readonly [number, string]>;

export type SdkErrorCode = keyof typeof SDK_ERRORS;

export const SDK_ERROR_CODES = Object.keys(SDK_ERRORS) as [SdkErrorCode, ...SdkErrorCode[]];

export function isSdkErrorCode(value: unknown): value is SdkErrorCode {
  return typeof value === "string" && Object.hasOwn(SDK_ERRORS, value);
}

/** Codes whose HTTP status equals `status`, in catalog order. */
export function sdkErrorCodesForStatus(status: number): SdkErrorCode[] {
  return SDK_ERROR_CODES.filter((code) => SDK_ERRORS[code][0] === status);
}

export const CAPACITY_REASONS = [
  "ram",
  "vcpu",
  "disk",
  "storage",
  "ceiling",
  /** One sandbox holds the most non-terminal command receipts a host keeps for it. */
  "sandbox_receipts",
] as const;
export const capacityReasonSchema = z.enum(CAPACITY_REASONS);
export type CapacityReason = z.infer<typeof capacityReasonSchema>;
/** `pool_full` only: `reserved` means capacity exists but is held for an
 * older waiting request (head protection). Never valid for `host_capacity`. */
export const POOL_FULL_REASONS = ["ram", "vcpu", "disk", "storage", "ceiling", "reserved"] as const;
export const poolFullReasonSchema = z.enum(POOL_FULL_REASONS);
export type PoolFullReason = z.infer<typeof poolFullReasonSchema>;

/**
 * Static exclusions among the hosts the caller can see: "full among hosts
 * that have your template; some other hosts lack it". Never counts and never
 * a foreign member's online status. `template_startup`: the revision has a
 * start command and some hosts' daemons do not run start/ready commands.
 */
export const SKIPPED_HOST_REASONS = [
  "template_startup",
  "template_unavailable",
  "lease_policy",
  "vm_size",
  /** CLI logins: an attached login is not opted in to foreign hosts. */
  "credential_policy",
] as const;
export const skippedHostReasonsSchema = z
  .array(z.enum(SKIPPED_HOST_REASONS))
  .min(1)
  .max(SKIPPED_HOST_REASONS.length);
export type SkippedHostReason = (typeof SKIPPED_HOST_REASONS)[number];

/** `sandbox.template_image_unavailable{reason}` (template builds, rebuild on miss). */
export const TEMPLATE_IMAGE_UNAVAILABLE_REASONS = ["rebuilding", "rebuild_quota"] as const;

/** Why a sandbox cannot be captured: its storage, its host runtime, or its state. */
export const CAPTURE_UNSUPPORTED_REASONS = ["storage", "runtime", "state"] as const;
export const IMAGE_QUOTA_SCOPES = ["stored", "downloads"] as const;

/**
 * Why `UNSUPPORTED_CAPABILITY` refused a sandbox launch for egress reasons
 * (default-open egress §1.4, §1.5). `egress_guard_unavailable`: the host's
 * root-owned egress guard is missing, unhealthy or its lease expired (a host
 * without it is never schedulable, in either mode); retryable.
 * `open_egress_not_permitted`: an open-mode sandbox on another user's host
 * whose owner does not (or no longer) allow open internet for other users'
 * sandboxes; create a new sandbox. `guest_sudo_not_permitted`: a sandbox
 * with guestSudo on another user's node whose owner no longer allows it;
 * terminal for that node.
 */
export const EGRESS_REFUSAL_REASONS = [
  "open_egress_not_permitted",
  "egress_guard_unavailable",
  "guest_sudo_not_permitted",
] as const;
export const egressRefusalReasonSchema = z.enum(EGRESS_REFUSAL_REASONS);
export type EgressRefusalReason = z.infer<typeof egressRefusalReasonSchema>;

/**
 * Which guest readiness check failed: the relay `details.reason` of a
 * `guest_unavailable` create or cold reconnect. Constant labels chosen by the
 * daemon, never guest output. Mirrors `ReadinessFailureReason` in
 * `crates/sandbox-protocol/src/control.rs`.
 */
export const READINESS_FAILURE_REASONS = [
  "agent_timeout",
  "vm_not_running",
  "guest_restarts",
  "architecture",
  "guest_user",
  "guest_home",
  "guest_shell",
  "guest_repo",
  "guest_tooling",
  "guest_check",
  /** guestSudo was requested but the grant failed or is not effective. */
  "guest_sudo_unavailable",
  /** guestSudo is off but the image grants the guest user root (hygiene audit). */
  "guest_root_granted",
  /** The create's disk exceeds the image's root and the guest root did not grow to it. */
  "root_disk_not_grown",
] as const;
export const readinessFailureReasonSchema = z.enum(READINESS_FAILURE_REASONS);
export type ReadinessFailureReason = z.infer<typeof readinessFailureReasonSchema>;

/** Finite allowed maximum carried by `lease_exceeds_policy`. */
export const leaseMaxTimeoutMsSchema = z
  .number()
  .int()
  .min(LEASE_LIMIT_MIN_MS)
  .max(LEASE_FINITE_MAX_MS);

/**
 * Typed fields of the `template.build_*` refusals that carry any. Every one is
 * required: the server answers INTERNAL_SERVER_ERROR rather than a code
 * without its documented fields.
 */
export const TEMPLATE_BUILD_ERROR_EXTRAS = {
  "template.build_disabled": z.strictObject({
    reason: z.enum([
      "off",
      "image_distribution_off",
      "no_builder",
      "lease_ceiling",
      "storage_unavailable",
      "community_timeout_exceeds_max",
    ]),
  }),
  "template.build_recipe_invalid": z.strictObject({
    /** Stable recipe/Dockerfile error code (e.g. `dockerfile_unsupported_instruction`). */
    recipeCode: z.string().regex(/^[a-z0-9_]{1,64}$/),
    /** Dockerfile position, when the error has one. */
    line: z.number().int().min(0).optional(),
    column: z.number().int().min(0).optional(),
    /** Recipe step index, when the error has one. */
    stepIndex: z.number().int().min(0).optional(),
  }),
  "template.build_no_builder": z.strictObject({
    /** Static reasons some visible hosts were excluded (true/false hints, never counts). */
    skipped: z.strictObject({
      builder: z.boolean(),
      capture_policy: z.boolean(),
      lease: z.boolean(),
    }),
  }),
  "template.build_concurrency": z.strictObject({ maxConcurrent: z.number().int().min(0) }),
  "template.build_minutes_exhausted": z.strictObject({ minutesPerMonth: z.number().int().min(0) }),
  "template.build_context_too_large": z.strictObject({ maxBytes: z.number().int().min(1) }),
  "template.build_context_busy": z.strictObject({ scope: z.enum(["account", "global"]) }),
  "template.build_not_cancellable": z.strictObject({ state: z.enum(["SUCCEEDED", "FAILED"]) }),
  "template.community_unavailable": z.strictObject({
    reason: z.enum(["index_unreachable", "no_tested_version"]),
  }),
} as const satisfies Partial<Record<SdkErrorCode, z.ZodObject>>;
export type TemplateBuildErrorExtrasCode = keyof typeof TEMPLATE_BUILD_ERROR_EXTRAS;
export function isTemplateBuildErrorExtrasCode(code: string): code is TemplateBuildErrorExtrasCode {
  return Object.hasOwn(TEMPLATE_BUILD_ERROR_EXTRAS, code);
}

export const HOST_FILE_ERROR_REASONS = [
  "host_files_off",
  "policy_changed",
  "owner_mismatch",
  "no_roots",
  "path_denied",
  "not_found",
  "not_a_file",
  "not_a_dir",
  "too_large",
  "binary_file",
  "conflict",
  "no_match",
  "match_count",
  "redacted_span",
  "exists",
  "invalid_input",
  "io_error",
  "limit",
] as const;
export const hostFileErrorReasonSchema = z.enum(HOST_FILE_ERROR_REASONS);
export type HostFileErrorReason = z.infer<typeof hostFileErrorReasonSchema>;

const errorFields = {
  message: z.string(),
  requestId: z.uuid(),
  retryAfterSeconds: z.number().int().min(1).max(86_400).optional(),
};
/**
 * Capacity, quota and pool admission refusals (all 409). Each carries the
 * REQUIRED `retryable` flag: `false` when the request alone can never be
 * admitted without changing the request, grants or configuration (it
 * exceeds a cap or every eligible member is disabled), `true` when current
 * usage, queue depth or online state blocks it. Only `retryable: true`
 * refusals carry `retryAfterSeconds` / `Retry-After`. The flag is computed
 * from the same static feasibility the capacity queue uses; it is a
 * classification, not a promise that capacity frees within that time.
 */
export const RETRYABLE_REFUSAL_CODES = [
  "sandbox.host_capacity",
  "sandbox.pool_full",
  "sandbox.pool_unavailable",
  "sandbox.pool_no_compatible_host",
  "sandbox.share_quota",
  "sandbox.member_quota",
  "sandbox.capacity_queue_full",
] as const satisfies readonly SdkErrorCode[];
export type RetryableRefusalCode = (typeof RETRYABLE_REFUSAL_CODES)[number];
export function isRetryableRefusalCode(code: string): code is RetryableRefusalCode {
  return (RETRYABLE_REFUSAL_CODES as readonly string[]).includes(code);
}
const refusalFields = { ...errorFields, retryable: z.boolean() };
const nonCapacityCodes = SDK_ERROR_CODES.filter(
  (code) =>
    !isRetryableRefusalCode(code) &&
    code !== "host.agent_access_off" &&
    code !== "host.node_offline" &&
    code !== "host.file_error" &&
    code !== "lease_exceeds_policy" &&
    code !== "sandbox.capture_unsupported" &&
    code !== "sandbox.image_quota_exceeded" &&
    code !== "capacity_wait_exceeds_policy" &&
    code !== "sandbox.template_image_unavailable" &&
    code !== "UNSUPPORTED_CAPABILITY" &&
    code !== "credential.value_invalid" &&
    !isTemplateBuildErrorExtrasCode(code),
);
function buildVariant<C extends TemplateBuildErrorExtrasCode>(code: C) {
  return z.strictObject({
    code: z.literal(code),
    ...errorFields,
    ...TEMPLATE_BUILD_ERROR_EXTRAS[code].shape,
  });
}
/**
 * `credential.value_invalid` detail text: which entry failed (`env.TOOL_API_KEY`,
 * `bundle.undeclared_path`, `files.missing_required`) and, for a file, its
 * path. Non-secret and printable (no control characters); never a value.
 */
export const credentialValueInvalidTextSchema = z
  .string()
  .min(1)
  .max(512)
  .refine((value) => [...value].every((ch) => ch >= " " && ch !== "\u007f"));
/** Which limit a full capacity queue hit. */
export const CAPACITY_QUEUE_SCOPES = ["key", "owner", "pool"] as const;
/** `capacity_wait_exceeds_policy`: the largest finite wait allowed (0 = waits disabled). */
export const capacityWaitMaxSchema = z.number().int().min(0).max(CAPACITY_WAIT_MAX_MS);
export const sdkErrorEnvelopeSchema = z.strictObject({
  error: z.discriminatedUnion("code", [
    z.strictObject({
      code: z.literal("host.agent_access_off"),
      ...errorFields,
      retryable: z.literal(false),
    }),
    z.strictObject({
      code: z.literal("host.node_offline"),
      ...errorFields,
      retryable: z.literal(true),
      retryAfterSeconds: z.number().int().min(1).max(86_400),
    }),
    z.strictObject({
      code: z.literal("host.file_error"),
      ...errorFields,
      data: z.strictObject({ reason: hostFileErrorReasonSchema }),
    }),
    z.strictObject({ code: z.enum(nonCapacityCodes), ...errorFields }),
    z.strictObject({
      code: z.literal("sandbox.share_quota"),
      ...refusalFields,
      resource: z.enum(["memory", "vcpu", "disk"]),
      skipped: skippedHostReasonsSchema.optional(),
    }),
    z.strictObject({
      code: z.literal("sandbox.member_quota"),
      ...refusalFields,
      resource: z.enum(["memory", "vcpu"]),
      skipped: skippedHostReasonsSchema.optional(),
    }),
    z.strictObject({
      code: z.literal("sandbox.host_capacity"),
      ...refusalFields,
      reason: capacityReasonSchema,
    }),
    z.strictObject({
      code: z.literal("sandbox.capture_unsupported"),
      ...errorFields,
      reason: z.enum(CAPTURE_UNSUPPORTED_REASONS),
    }),
    z.strictObject({
      code: z.literal("sandbox.image_quota_exceeded"),
      ...errorFields,
      scope: z.enum(IMAGE_QUOTA_SCOPES),
    }),
    z.strictObject({
      code: z.literal("sandbox.pool_full"),
      ...refusalFields,
      reason: poolFullReasonSchema,
      skipped: skippedHostReasonsSchema.optional(),
    }),
    z.strictObject({
      code: z.literal("sandbox.pool_unavailable"),
      ...refusalFields,
      skipped: skippedHostReasonsSchema.optional(),
    }),
    z.strictObject({ code: z.literal("sandbox.pool_no_compatible_host"), ...refusalFields }),
    z.strictObject({
      code: z.literal("capacity_wait_exceeds_policy"),
      ...errorFields,
      maxWaitMs: capacityWaitMaxSchema,
    }),
    z.strictObject({
      code: z.literal("sandbox.capacity_queue_full"),
      ...refusalFields,
      scope: z.enum(CAPACITY_QUEUE_SCOPES),
    }),
    z.strictObject({
      code: z.literal("sandbox.template_image_unavailable"),
      ...errorFields,
      /**
       * Rebuild on miss: `rebuilding` (a rebuild of the template's build
       * revision is running; retry later), `rebuild_quota` (the template owner's
       * build quota refused the rebuild).
       */
      reason: z.enum(TEMPLATE_IMAGE_UNAVAILABLE_REASONS).optional(),
      /** `rebuild_required`: a COPY build cannot be rebuilt without its context; build again. */
      hint: z.literal("rebuild_required").optional(),
    }),
    buildVariant("template.build_disabled"),
    buildVariant("template.build_recipe_invalid"),
    buildVariant("template.build_no_builder"),
    buildVariant("template.build_concurrency"),
    buildVariant("template.build_minutes_exhausted"),
    buildVariant("template.build_context_too_large"),
    buildVariant("template.build_context_busy"),
    buildVariant("template.build_not_cancellable"),
    buildVariant("template.community_unavailable"),
    z.strictObject({
      code: z.literal("UNSUPPORTED_CAPABILITY"),
      ...errorFields,
      /** Present only for an egress or tunnel refusal. */
      reason: z.union([egressRefusalReasonSchema, tunnelRefusalReasonSchema]).optional(),
    }),
    z.strictObject({
      code: z.literal("credential.value_invalid"),
      ...errorFields,
      /** What failed, e.g. `env.TOOL_API_KEY` or `bundle.undeclared_path`. */
      entry: credentialValueInvalidTextSchema.optional(),
      /** The offending file path, for a file entry. */
      path: credentialValueInvalidTextSchema.optional(),
    }),
    z.strictObject({
      code: z.literal("lease_exceeds_policy"),
      ...errorFields,
      /** The largest finite timeoutMs the caller may request on this target. */
      maxTimeoutMs: leaseMaxTimeoutMsSchema,
    }),
  ]),
});

export type SdkErrorEnvelope = z.infer<typeof sdkErrorEnvelopeSchema>;
