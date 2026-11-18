import { ORPCError } from "@orpc/server";
import {
  type EgressRefusalReason,
  SDK_ERRORS,
  type TunnelRefusalReason,
} from "@wssp/sandbox-contracts";

/**
 * Stable sandbox control-plane error codes. Node daemons, adapters, and clients
 * should key off these strings — not message text.
 */
const SandboxErrorCode = {
  vmSizeInvalid: "sandbox.vm_size_invalid",
  vmSizeUnsupported: "sandbox.vm_size_unsupported",
  vmSizeMismatch: "sandbox.vm_size_mismatch",
  diskBelowImage: "sandbox.disk_below_image",
  egressPolicyInvalid: "sandbox.egress_policy_invalid",
  digestKeyUnavailable: "digest_key_unavailable",
  digestKeyChanged: "digest_key_changed",
  idempotencyConflict: "sandbox.idempotency_conflict",
  stateConflict: "sandbox.state_conflict",
  templateNotFound: "sandbox.template_not_found",
  templateInUse: "sandbox.template_in_use",
  templateImageRejected: "sandbox.template_image_rejected",
  templateImageMissing: "sandbox.template_image_missing",
  templateImageUnavailable: "sandbox.template_image_unavailable",
  templateStoreUnavailable: "sandbox.template_store_unavailable",
  captureUnsupported: "sandbox.capture_unsupported",
  capturePolicyForbidden: "sandbox.capture_policy_forbidden",
  captureBusy: "sandbox.capture_busy",
  diskEvicting: "sandbox.disk_evicting",
  sandboxRestoring: "sandbox.restoring",
  restoreNoAllowedHost: "restore_no_allowed_host",
  diskUnavailable: "sandbox.disk_unavailable",
  diskOffloaded: "sandbox.disk_offloaded",
  hostForgetUnsafe: "sandbox.host_forget_unsafe",
  imageQuotaExceeded: "sandbox.image_quota_exceeded",
  templateUnavailable: "sandbox.template_unavailable",
  templateRevisionExists: "sandbox.template_revision_exists",
  hostNotFound: "sandbox.host_not_found",
  poolNotFound: "sandbox.pool_not_found",
  poolNoCompatibleHost: "sandbox.pool_no_compatible_host",
  poolUnavailable: "sandbox.pool_unavailable",
  poolFull: "sandbox.pool_full",
  hostCapacity: "sandbox.host_capacity",
  hostDraining: "sandbox.host_draining",
  hostDeleteConflict: "sandbox.host_delete_conflict",
  hostUnavailable: "sandbox.host_unavailable",
  hostReconnecting: "sandbox.host_reconnecting",
  hostRuntimeUnsupported: "host_runtime_unsupported",
  sandboxNotFound: "sandbox.not_found",
  operationNotFound: "sandbox.operation_not_found",
  invalidTransition: "sandbox.invalid_transition",
  unsupportedCapability: "UNSUPPORTED_CAPABILITY",
  leaseExceedsPolicy: "lease_exceeds_policy",
  tunnelNotFound: "sandbox.tunnel_not_found",
  tunnelPortUndeclared: "sandbox.tunnel_port_undeclared",
  tunnelNotReady: "sandbox.tunnel_not_ready",
  tunnelQuota: "sandbox.tunnel_quota",
  tunnelPortsLimit: "sandbox.tunnel_ports_limit",
  tunnelUnavailable: "sandbox.tunnel_unavailable",
} as const;

type SandboxErrorCode = (typeof SandboxErrorCode)[keyof typeof SandboxErrorCode];

type OrpcStatusCode =
  | "BAD_REQUEST"
  | "CONFLICT"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "UNAUTHORIZED"
  | "SERVICE_UNAVAILABLE";

function sandboxOrpcError(
  code: SandboxErrorCode,
  message: string,
  orpcCode: OrpcStatusCode = "BAD_REQUEST",
  extra: Record<string, string> = {},
) {
  return new ORPCError(orpcCode, {
    message,
    data: { ...extra, code },
  });
}

export function idempotencyConflict() {
  return sandboxOrpcError(
    SandboxErrorCode.idempotencyConflict,
    "Idempotency key was reused with a different request body.",
    "CONFLICT",
  );
}

export function sandboxStateConflict(message = "Sandbox is not in a valid state for this action.") {
  return sandboxOrpcError(SandboxErrorCode.stateConflict, message, "CONFLICT");
}

export function templateNotFound() {
  return sandboxOrpcError(SandboxErrorCode.templateNotFound, "Template not found.", "NOT_FOUND");
}

/** Archive refused: sandboxes that are not DELETED still reference the template. */
export function templateInUse() {
  return sandboxOrpcError(
    SandboxErrorCode.templateInUse,
    "Template still has sandboxes that are not deleted.",
    "CONFLICT",
  );
}

/** No eligible host has the image or can fetch it now (pool reselection code). */
export function templateImageUnavailable() {
  return sandboxOrpcError(
    SandboxErrorCode.templateImageUnavailable,
    "No eligible host has or can fetch this template image.",
    "CONFLICT",
  );
}

export function templateStoreUnavailable() {
  return sandboxOrpcError(
    SandboxErrorCode.templateStoreUnavailable,
    "The image store cannot keep a capture taken on this host.",
    "CONFLICT",
  );
}

export function captureUnsupported(reason: "storage" | "runtime" | "state") {
  return sandboxOrpcError(
    SandboxErrorCode.captureUnsupported,
    "This sandbox cannot be captured.",
    "CONFLICT",
    { reason },
  );
}

export function capturePolicyForbidden() {
  return sandboxOrpcError(
    SandboxErrorCode.capturePolicyForbidden,
    "The template's image placement forbids this capture.",
    "CONFLICT",
  );
}

export function captureBusy() {
  return sandboxOrpcError(
    SandboxErrorCode.captureBusy,
    "A capture is already running for this sandbox or host.",
    "CONFLICT",
  );
}

/** item 3 / §7 step 4: a reconnect while an eviction of
 * the cached copy is granted (EVICTING). Retryable: the restore follows. */
export function diskEvicting() {
  return sandboxOrpcError(
    SandboxErrorCode.diskEvicting,
    "The sandbox's cached disk is being evicted; retry the start shortly.",
    "CONFLICT",
  );
}

/** an owner stop while a restore attempt is active. */
export function sandboxRestoring() {
  return sandboxOrpcError(
    SandboxErrorCode.sandboxRestoring,
    "The sandbox is being restored; retry once the restore settles.",
    "CONFLICT",
  );
}

/** no host the restore may use (the creating key's
 * allowlists included) had capacity before the wait ended. */
export function restoreNoAllowedHost() {
  return sandboxOrpcError(
    SandboxErrorCode.restoreNoAllowedHost,
    "No host this restore may use has room for the sandbox.",
    "CONFLICT",
  );
}

/** a restore while the image store or the data key
 * is not configured; the stored disk is kept and nothing is accepted. */
export function diskUnavailable() {
  return sandboxOrpcError(
    SandboxErrorCode.diskUnavailable,
    "The sandbox's stored disk cannot be used on this deployment right now.",
    "CONFLICT",
  );
}

/** C7: an action that needs the host copy of the disk
 * (template capture) on an OFFLOADED sandbox. Start it first. */
export function diskOffloaded() {
  return sandboxOrpcError(
    SandboxErrorCode.diskOffloaded,
    "The sandbox's disk is offloaded to the image store; start the sandbox first.",
    "CONFLICT",
  );
}

/** At most this many refused sandboxes are listed in a forget refusal. */
export const HOST_FORGET_UNSAFE_LIST_MAX = 50;

/**
 * Forget unreachable host refused because these
 * sandboxes may still run there (a possibly-live attempt or unsettled work).
 * Lists their ids (bounded); nothing was detached.
 */
export function hostForgetUnsafe(sandboxIds: readonly string[]) {
  return new ORPCError("CONFLICT", {
    message: "The host still holds sandboxes whose cleanup cannot be proven; forget is refused.",
    data: {
      code: SandboxErrorCode.hostForgetUnsafe,
      sandboxIds: sandboxIds.slice(0, HOST_FORGET_UNSAFE_LIST_MAX),
    },
  });
}

export function imageQuotaExceeded(scope: "stored" | "downloads") {
  return sandboxOrpcError(
    SandboxErrorCode.imageQuotaExceeded,
    "The account's image quota is exhausted.",
    "CONFLICT",
    { scope },
  );
}

export function templateImageMissing() {
  return sandboxOrpcError(
    SandboxErrorCode.templateImageMissing,
    "The exact template image is missing on this host.",
    "CONFLICT",
  );
}

/**
 * The host looked the image up and refused it (not a VM image,
 * wrong architecture). `detail` is the node daemon's bounded message.
 */
export function templateImageRejected(detail: string) {
  return sandboxOrpcError(
    SandboxErrorCode.templateImageRejected,
    detail || "Host rejected the image.",
  );
}

export function templateRevisionExists() {
  return sandboxOrpcError(
    SandboxErrorCode.templateRevisionExists,
    "This template revision already exists.",
    "CONFLICT",
  );
}

/** The host cannot answer now (not connected, credential inactive, busy, timed out). */
export function hostUnavailable(message = "Host is unavailable.") {
  return sandboxOrpcError(SandboxErrorCode.hostUnavailable, message, "CONFLICT");
}

/**
 * Transient: the host's current connection has not yet acknowledged its
 * journal key (the seconds after every relay hello). Refused before any
 * receipt, reservation or outbox row, so a retry under the same key is safe.
 */
export function hostReconnecting() {
  return sandboxOrpcError(
    SandboxErrorCode.hostReconnecting,
    "Host is reconnecting; retry shortly.",
    "SERVICE_UNAVAILABLE",
  );
}

export function hostNotFound() {
  return sandboxOrpcError(SandboxErrorCode.hostNotFound, "Host not found.", "NOT_FOUND");
}

export type CapacityReason = "ram" | "vcpu" | "disk" | "storage" | "ceiling";
/**
 * `retryable` (required on every capacity/quota/pool refusal, see
 * `RETRYABLE_REFUSAL_CODES`): false when the request alone can never fit this
 * host; true when current reservations or storage state block it.
 */
export function hostCapacityConflict(reason: CapacityReason, retryable: boolean) {
  return new ORPCError("CONFLICT", {
    message: "Host capacity is full.",
    data: { code: SandboxErrorCode.hostCapacity, reason, retryable },
  });
}

/**
 * The same refusal with its `retryable` classification replaced: pool
 * placement reclassifies against static feasibility (`placePool`'s refuse).
 */
export function withRetryable(error: ORPCError<string, unknown>, retryable: boolean) {
  const data = error.data;
  if (!data || typeof data !== "object") return error;
  return new ORPCError(error.code, {
    status: error.status,
    message: error.message,
    data: { ...data, retryable },
  });
}

export function hostDrainingConflict() {
  return sandboxOrpcError(SandboxErrorCode.hostDraining, "Host is draining.", "CONFLICT");
}

export function hostDeleteConflict(message: string) {
  return sandboxOrpcError(SandboxErrorCode.hostDeleteConflict, message, "CONFLICT");
}

export function sandboxNotFound() {
  return sandboxOrpcError(SandboxErrorCode.sandboxNotFound, "Sandbox not found.", "NOT_FOUND");
}

export function operationNotFound() {
  return sandboxOrpcError(SandboxErrorCode.operationNotFound, "Operation not found.", "NOT_FOUND");
}

/**
 * The missing capability is also machine-readable (`data.capability`) so the
 * dashboard can explain it; `/v1` maps by `data.code` only and keeps the
 * catalog's constant message.
 */
export function unsupportedCapability(
  capability:
    | "snapshot"
    | "restore"
    | "fork"
    | "egress"
    | "pause"
    | "ingress"
    | "template_startup"
    | "credentials",
) {
  return sandboxOrpcError(
    SandboxErrorCode.unsupportedCapability,
    `Unsupported capability: ${capability}.`,
    "BAD_REQUEST",
    { capability },
  );
}

/** A preview-tunnel refusal: `UNSUPPORTED_CAPABILITY` for capability `tunnel`. */
export function tunnelRefused(reason: TunnelRefusalReason) {
  const messages: Record<TunnelRefusalReason, string> = {
    tunnel_off: "Preview tunnels are not configured on this deployment.",
    tunnel_no_host: "No eligible host runs preview tunnels for you.",
    tunnel_host_unsupported: "This sandbox's host does not run preview tunnels.",
    tunnel_not_shared: "The host owner does not allow preview tunnels for other users' sandboxes.",
    tunnel_not_enabled:
      "This sandbox was created without network.tunnelPorts; only tunnel sandboxes change their ports.",
  };
  return sandboxOrpcError(SandboxErrorCode.unsupportedCapability, messages[reason], "BAD_REQUEST", {
    capability: "tunnel",
    reason,
  });
}

export function tunnelNotFound() {
  return sandboxOrpcError(
    SandboxErrorCode.tunnelNotFound,
    "This sandbox has no tunnel.",
    "NOT_FOUND",
  );
}
export function tunnelPortUndeclared() {
  return sandboxOrpcError(
    SandboxErrorCode.tunnelPortUndeclared,
    "The port is not declared for tunnels on this sandbox.",
  );
}
export function tunnelPortsLimit() {
  return sandboxOrpcError(
    SandboxErrorCode.tunnelPortsLimit,
    "A sandbox declares at most 8 tunnel ports.",
  );
}
export function tunnelNotReady() {
  return sandboxOrpcError(
    SandboxErrorCode.tunnelNotReady,
    "The tunnel is not connected yet; retry shortly.",
    "CONFLICT",
  );
}
export function tunnelQuota() {
  return sandboxOrpcError(
    SandboxErrorCode.tunnelQuota,
    "The account's tunnel limit is reached.",
    "CONFLICT",
  );
}
export function tunnelUnavailable() {
  return sandboxOrpcError(
    SandboxErrorCode.tunnelUnavailable,
    "The tunnel server is unavailable.",
    "SERVICE_UNAVAILABLE",
  );
}

/**
 * An egress refusal of a sandbox launch (default-open egress §1.3, §1.4):
 * `UNSUPPORTED_CAPABILITY` for capability `egress` with a typed reason. Pool
 * reselection (`poolHostRecheck`) treats it like any egress capability race.
 */
export function egressRefused(reason: EgressRefusalReason) {
  return sandboxOrpcError(
    SandboxErrorCode.unsupportedCapability,
    reason === "egress_guard_unavailable"
      ? "This host's network guard is not running. Try another host or ask the host owner."
      : "The host owner does not allow open internet for other users' sandboxes.",
    "BAD_REQUEST",
    { capability: "egress", reason },
  );
}

/** Malformed, ambiguous or protected-range-intersecting egress policy (C34). */
export function egressPolicyInvalid() {
  return sandboxOrpcError(
    SandboxErrorCode.egressPolicyInvalid,
    "Egress policy exceeds the allowed shape or size.",
  );
}

export function invalidSandboxTransition(from: string, to: string) {
  return sandboxOrpcError(
    SandboxErrorCode.invalidTransition,
    `Sandbox cannot transition from ${from} to ${to}.`,
    "CONFLICT",
  );
}

export function digestKeyChanged() {
  return sandboxOrpcError(SandboxErrorCode.digestKeyChanged, "Digest key changed.", "CONFLICT");
}

export function digestKeyUnavailable() {
  return sandboxOrpcError(
    SandboxErrorCode.digestKeyUnavailable,
    "Digest key unavailable.",
    "CONFLICT",
  );
}

export function poolNotFound() {
  return sandboxOrpcError(SandboxErrorCode.poolNotFound, "Pool not found.", "NOT_FOUND");
}
/** Static: no visible member can ever run this template/revision as configured. */
export function poolNoCompatibleHost() {
  return new ORPCError("CONFLICT", {
    message: "Pool has no compatible host.",
    data: { code: SandboxErrorCode.poolNoCompatibleHost, retryable: false },
  });
}
/** Static host exclusions among visible hosts (booleans only, never counts). */
type SkippedHint =
  | "template_startup"
  | "template_unavailable"
  | "lease_policy"
  | "vm_size"
  | "credential_policy";
const skippedData = (skipped: readonly SkippedHint[]) =>
  skipped.length > 0 ? { skipped: [...skipped] } : {};

/** `retryable: false`: every member is disabled (or the request is statically
 * infeasible); true: members are offline or lack a capability right now. */
export function poolUnavailable(retryable: boolean, skipped: readonly SkippedHint[] = []) {
  return new ORPCError("CONFLICT", {
    message: "Pool is unavailable.",
    data: { code: SandboxErrorCode.poolUnavailable, retryable, ...skippedData(skipped) },
  });
}
/** `reserved`: capacity exists but is held for an older waiting request. */
export function poolFull(
  reason: CapacityReason | "reserved",
  retryable: boolean,
  skipped: readonly SkippedHint[] = [],
) {
  return new ORPCError("CONFLICT", {
    message: "Pool capacity is full.",
    data: { code: SandboxErrorCode.poolFull, reason, retryable, ...skippedData(skipped) },
  });
}
export function memberQuota(
  resource: "memory" | "vcpu",
  retryable: boolean,
  skipped: readonly SkippedHint[] = [],
) {
  return new ORPCError("CONFLICT", {
    message: "Member resource quota exceeded.",
    data: { code: "sandbox.member_quota", resource, retryable, ...skippedData(skipped) },
  });
}
/**
 * Template builds (plan template-builds §3.3, §4): visible, enabled,
 * compatible hosts excluded from a build, by reason. `builder`: the node
 * offers no builds to this requester (no `image.build`, or a foreign node
 * without `acceptForeignBuilds`); `capture_policy`: a foreign builder ruled
 * out by the requester opt-in, the S3 requirement, the target template's
 * image placement or the node's foreign-image acceptance; `lease`: a builder
 * whose lease ceiling cannot hold the build lease. Like every `skipped` hint,
 * these are true/false hints, never counts and never host ids, so a pool
 * reveals nothing about other owners' members.
 */
export type BuildSkipped = { builder: boolean; capture_policy: boolean; lease: boolean };
export function buildNoBuilder(skipped: BuildSkipped) {
  return new ORPCError("CONFLICT", {
    message: "No builder host can run this build.",
    data: { code: "template.build_no_builder", skipped: { ...skipped } },
  });
}
/** The template revision is on no eligible host in the pool (any epoch). */
export function templateUnavailable() {
  return sandboxOrpcError(
    SandboxErrorCode.templateUnavailable,
    SDK_ERRORS[SandboxErrorCode.templateUnavailable][1],
    "CONFLICT",
  );
}

/** Values-free size failures: never accept request, runtime or database text. */
export function vmSizeInvalid() {
  return sandboxOrpcError(
    SandboxErrorCode.vmSizeInvalid,
    SDK_ERRORS[SandboxErrorCode.vmSizeInvalid][1],
  );
}
/** A captured or built image's root disk is the source VM's disk: a smaller
 * root cannot hold it, and Incus would refuse the instance after dispatch. */
export function diskBelowImage() {
  return sandboxOrpcError(
    SandboxErrorCode.diskBelowImage,
    SDK_ERRORS[SandboxErrorCode.diskBelowImage][1],
  );
}
export function vmSizeUnsupported() {
  return sandboxOrpcError(
    SandboxErrorCode.vmSizeUnsupported,
    SDK_ERRORS[SandboxErrorCode.vmSizeUnsupported][1],
    "CONFLICT",
  );
}
export function vmSizeMismatch() {
  return sandboxOrpcError(
    SandboxErrorCode.vmSizeMismatch,
    SDK_ERRORS[SandboxErrorCode.vmSizeMismatch][1],
    "CONFLICT",
  );
}

/**
 * Requested lease exceeds the effective policy (deployment, host ceiling, pool
 * and membership maximums). `maxTimeoutMs` is the finite allowed maximum the
 * caller may request on the same target; it is numeric, so it bypasses the
 * string-only `extra` of `sandboxOrpcError`.
 */
export function leaseExceedsPolicy(maxTimeoutMs: number) {
  return new ORPCError("BAD_REQUEST", {
    message: SDK_ERRORS[SandboxErrorCode.leaseExceedsPolicy][1],
    data: { code: SandboxErrorCode.leaseExceedsPolicy, maxTimeoutMs },
  });
}

/** Requested `waitForCapacityMs` is over the effective limit; never clamped.
 * `maxWaitMs` is the largest finite wait allowed (0: waits are disabled). */
/** The creating key's live-sandbox limit (`SdkKey.maxLiveSandboxes`) is reached. */
export function keySandboxLimitReached(maxLiveSandboxes: number, liveSandboxes: number) {
  return new ORPCError("CONFLICT", {
    message: SDK_ERRORS["sandbox.key_limit_reached"][1],
    data: { code: "sandbox.key_limit_reached", maxLiveSandboxes, liveSandboxes },
  });
}

export function capacityWaitExceedsPolicy(maxWaitMs: number) {
  return new ORPCError("BAD_REQUEST", {
    message: SDK_ERRORS.capacity_wait_exceeds_policy[1],
    data: { code: "capacity_wait_exceeds_policy", maxWaitMs },
  });
}
/** A waiting-create limit (per key, per owner or per pool) is reached.
 * `retryable: false` only when that limit is 0 (waits disabled at that layer). */
export function capacityQueueFull(scope: "key" | "owner" | "pool", retryable: boolean) {
  return new ORPCError("CONFLICT", {
    message: SDK_ERRORS["sandbox.capacity_queue_full"][1],
    data: { code: "sandbox.capacity_queue_full", scope, retryable },
  });
}
/** Another live workload sandbox of this owner already has the name. */
export function sandboxNameTaken() {
  return new ORPCError("CONFLICT", {
    message: SDK_ERRORS["sandbox.name_taken"][1],
    data: { code: "sandbox.name_taken" },
  });
}
/** The name is not a valid sandbox name (never transformed). */
export function sandboxNameInvalid() {
  return new ORPCError("BAD_REQUEST", {
    message: SDK_ERRORS["sandbox.name_invalid"][1],
    data: { code: "sandbox.name_invalid" },
  });
}
