import { z } from "zod";
import resultLimits from "../../config/src/sandbox-result-limits.json";
import { CAPACITY_WAIT_MAX_MS } from "./capacity-wait";
import { commandTimeoutZeroEnabled } from "./command-timeout-policy";
import { EGRESS_MODES, normalizedEgressPolicySchema } from "./egress";
import { assertUniqueMetadataKeys } from "./env-json";
import { capacityReasonSchema, readinessFailureReasonSchema } from "./errors";
import { LEASE_FINITE_MAX_MS, LEASE_LIMIT_MIN_MS } from "./lease-limits";
import { METADATA_MAX_BYTES, metadataSchema } from "./metadata";
import { sandboxNameSchema } from "./sandbox-name";
import {
  hostVcpuBudgetSchema,
  storageIdentityV11Schema,
  storagePoolV11Schema,
  VM_SIZE_LIMITS,
  vmCapacitySchema,
  vmSizeSchema,
} from "./vm-size";
/**
 * Public `/v1` data transfer objects. Every object is strict: a projection that
 * adds a field (for example command output or a credential digest) fails
 * response validation instead of reaching a client. Dates are ISO-8601 UTC
 * strings and IDs are opaque strings. This module must not import Prisma,
 * server, oRPC or auth code; the boundary test enforces that.
 */

export const API_VERSION = "v1" as const;

/** Opaque resource ID (cuid2 on this server; clients must not parse it). */
export const resourceIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);

/** Opaque pagination cursor. Its content is not a contract. */
export const cursorSchema = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/);

export const isoDateTimeSchema = z.iso.datetime();

/** Default cap for a JSON request body on `/v1`; binary transfers use separate limits. */
export const JSON_BODY_MAX_BYTES = 1024 * 1024;

export const PAGE_SIZE_DEFAULT = 20;
export const PAGE_SIZE_MAX = 100;

/** Decimal page size string, 1–100. Query values are strings on the wire. */
export const pageLimitQuerySchema = z
  .string()
  .regex(/^[1-9][0-9]{0,2}$/)
  .transform(Number)
  .pipe(z.number().int().min(1).max(PAGE_SIZE_MAX));

export const pageQuerySchema = z
  .object({
    limit: pageLimitQuerySchema.optional(),
    cursor: cursorSchema.optional(),
  })
  .strict();

export const SDK_SCOPES = [
  "hosts:read",
  "pools:read",
  "templates:read",
  "templates:write",
  "templates:build",
  "sandboxes:read",
  "sandboxes:write",
  "commands:read",
  "commands:execute",
  "files:read",
  "files:write",
  "operations:read",
  "operations:cancel",
  "webhooks:write",
  "credentials:read",
  "credentials:write",
  "credentials:use",
] as const;
export type SdkScope = (typeof SDK_SCOPES)[number];

export const HOST_STATUSES = ["DISCONNECTED", "CONNECTED", "STALE", "REVOKED"] as const;

export const SANDBOX_STATES = [
  "REQUESTED",
  "SCHEDULED",
  "PROVISIONING",
  "READY",
  "STOPPING",
  "STOPPED",
  "RECLAIMING",
  "DELETED",
  "UNREACHABLE",
  "RECOVERED",
  "HOST_LOST",
  "ERROR",
  "WAITING_FOR_CAPACITY",
  "OFFLOADED",
] as const;
export type SandboxStateDto = (typeof SANDBOX_STATES)[number];

/** Sandbox cursors bind owner, normalized filters and order. Other lists retain cursorSchema. */
export const sandboxCursorSchema = z.string().regex(/^[A-Za-z0-9_-]{1,256}$/);

export const sandboxListFiltersSchema = z.object({
  metadata: metadataSchema.optional(),
  states: z.array(z.enum(SANDBOX_STATES)).min(1).max(SANDBOX_STATES.length).optional(),
  templateId: resourceIdSchema.optional(),
  templateRevisionId: resourceIdSchema.optional(),
  poolId: resourceIdSchema.optional(),
  startedAfter: isoDateTimeSchema.optional(),
  /** Total order is (createdAt, id); default newest first. */
  order: z.enum(["asc", "desc"]).optional(),
});

const metadataQuerySchema = z
  .string()
  .max(METADATA_MAX_BYTES)
  .transform((source, ctx) => {
    try {
      assertUniqueMetadataKeys(source, METADATA_MAX_BYTES, true);
      return metadataSchema.parse(JSON.parse(source));
    } catch {
      ctx.addIssue({ code: "custom", message: "sandbox.metadata_invalid" });
      return z.NEVER;
    }
  })
  .meta({
    description:
      "One JSON object of string metadata filters, exact-match AND. Duplicate keys are refused; at most 8192 UTF-8 bytes.",
  });

/** HTTP query values are strings; states is one comma-separated list. */
export const sandboxListQuerySchema = pageQuerySchema
  .extend({
    cursor: sandboxCursorSchema.optional(),
    metadata: metadataQuerySchema.optional(),
    states: z
      .string()
      .max(256)
      .transform((value) => value.split(","))
      .pipe(sandboxListFiltersSchema.shape.states.unwrap())
      .optional(),
    templateId: sandboxListFiltersSchema.shape.templateId,
    templateRevisionId: sandboxListFiltersSchema.shape.templateRevisionId,
    poolId: sandboxListFiltersSchema.shape.poolId,
    startedAfter: sandboxListFiltersSchema.shape.startedAfter,
    order: sandboxListFiltersSchema.shape.order,
  })
  .strict();

export const OPERATION_STATES = [
  "QUEUED",
  "DISPATCHED",
  "ACCEPTED",
  "RUNNING",
  "CANCEL_REQUESTED",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
  "UNKNOWN_OUTCOME",
] as const;
export type OperationStateDto = (typeof OPERATION_STATES)[number];

export const OPERATION_KINDS = [
  "CREATE_SANDBOX",
  "KILL_SANDBOX",
  "RUN_COMMAND",
  "GET_FILE",
  "PUT_FILE",
  "RECONNECT_SANDBOX",
  "STOP_SANDBOX",
  "RENEW_SANDBOX_LEASE",
  "LIST_DIR",
  "STAT_PATH",
  "MKDIR",
  "REMOVE_PATH",
  "MOVE_PATH",
  "LIST_PROCESSES",
  "SIGNAL_PROCESS",
  "CAPTURE_TEMPLATE",
  "CREDENTIAL_ATTACH",
  "CREDENTIAL_FREE",
] as const;

/**
 * Client-facing outcome of an operation. `unknown` (UNKNOWN_OUTCOME) means the
 * server cannot tell whether the host applied the effect: it is neither failure
 * nor absence, and it must never be retried as a fresh request.
 */
export const OPERATION_OUTCOMES = [
  "pending",
  "succeeded",
  "failed",
  "cancelled",
  "unknown",
] as const;
export type OperationOutcome = (typeof OPERATION_OUTCOMES)[number];

const OUTCOME_BY_STATE: Record<OperationStateDto, OperationOutcome> = {
  QUEUED: "pending",
  DISPATCHED: "pending",
  ACCEPTED: "pending",
  RUNNING: "pending",
  CANCEL_REQUESTED: "pending",
  SUCCEEDED: "succeeded",
  FAILED: "failed",
  CANCELLED: "cancelled",
  UNKNOWN_OUTCOME: "unknown",
};

export function operationOutcome(state: OperationStateDto): OperationOutcome {
  return OUTCOME_BY_STATE[state];
}

/**
 * Stable operation error codes: the host relay catalog plus codes the control
 * plane records itself. Any other stored value is reported as `internal`.
 */
export const OPERATION_ERROR_CODES = [
  "fs_not_found",
  "fs_is_directory",
  "fs_not_directory",
  "fs_not_regular",
  "fs_permission_denied",
  "fs_read_only",
  "fs_already_exists",
  "fs_not_empty",
  "fs_cross_device",
  "fs_no_space",
  "fs_symlink_refused",
  "fs_entry_too_large",
  "fs_listing_limit",
  "fs_invalid_encoding",
  "fs_metadata_unrepresentable",
  "process_not_found",
  "process_exited",
  "process_stale",
  "process_not_started",
  "process_stdin_closed",
  "process_cancel_pending",
  "process_permission_denied",
  "signal_unsupported_on_guest",

  "access_denied",
  "cancelled",
  "capacity_wait_timeout",
  "placement_infeasible",
  "credential_inactive",
  "disconnected",
  "egress_resolution_failed",
  "egress_guard_unavailable",
  "open_egress_not_permitted",
  // guestSudo (docs/guide/sandboxes.md#root-in-the-guest).
  "guest_sudo_not_permitted",
  "guest_sudo_unavailable",
  "guest_root_granted",
  "guest_operation_failed",
  "guest_permission_denied",
  "guest_unavailable",
  "host_capacity",
  "vm_size_mismatch",
  "host_effect_not_issued",
  // The host stayed disconnected past its `max_carry` cap and stopped the work.
  "host_disconnect_expired",
  "host_runtime_unsupported",
  "idempotency_conflict",
  "digest_key_changed",
  "digest_key_unavailable",
  "receipt_digest_pruned",
  "internal",
  "lease_expired",
  "lease_exceeds_policy",
  "not_found",
  "sandbox.template_image_missing",
  "operation_not_found",
  "path_refused",
  "protocol_error",
  "protocol_version_unsupported",
  "rate_limited",
  "request_too_large",
  "sandbox_not_found",
  "sandbox_not_running",
  "snapshot_failed",
  "state_conflict",
  "superseded",
  "timeout",
  "transport",
  "unknown_outcome",
  "unsupported_capability",
  // Template image distribution and capture (docs/operations/templates.md).
  "image_unavailable",
  "image_cache_full",
  "image_corrupt",
  "image_rejected",
  "image_fetch_timeout",
  "provision_timeout",
  "capture_failed",
  "capture_freeze_failed",
  "capture_store_failed",
  // Template start/ready commands (template builds B9).
  "startup_failed",
  "startup_timeout",
  // The guest booted without an IPv4 default route (no DHCP lease).
  "guest_network_unavailable",
  // CLI logins (docs/guide/cli-logins.md).
  "credential_install_failed",
  "credential_spec_invalid",
  "credential_env_pending",
  "credential_capture_failed",
  // Disk offload: a cached copy no longer matches.
  "disk_stale",
  // Disk offload (§8.7): a restore did not boot; its cleanup is pending.
  "restore_boot_failed",
  "restore_cleanup_pending",
  // Disk offload restore (docs/guide/sandboxes.md#disk-offload).
  "restore_no_allowed_host",
  // A queued restore ended by a login refusal waiting cannot cure (§8.3c).
  "credential.not_attached",
  "credential.not_found",
  "credential.account_not_found",
  "credential.instance_not_found",
  "credential.definition_corrupt",
  "credential.spec_too_large",
  "credential.env_conflict",
  // A queued restore whose wait ended at its deadline while the latest
  // placement pass was refused by a login (§8.3c), not for capacity.
  "credential.in_use",
  "credential.busy",
  "credential.pending_drain",
  "credential.needs_login",
  "credential.account_paused",
  "credential.limit_reached",
  "credential.host_forbidden",
  "credential.recovery_required",
  // A queued restore that a permanent login refusal ended at once.
  "credential.path_conflict",
  "credential.unavailable",
] as const;
export type OperationErrorCode = (typeof OPERATION_ERROR_CODES)[number];

const OPERATION_ERROR_CODE_SET: ReadonlySet<string> = new Set(OPERATION_ERROR_CODES);

export function publicOperationErrorCode(code: string | null): OperationErrorCode | null {
  if (code === null) return null;
  return OPERATION_ERROR_CODE_SET.has(code) ? (code as OperationErrorCode) : "internal";
}

export const LEASE_EXPIRE_ACTIONS = ["stop", "destroy"] as const;

const leaseTermSchema = z
  .object({
    expiresAt: isoDateTimeSchema.nullable(),
    onExpire: z.enum(LEASE_EXPIRE_ACTIONS),
  })
  .strict();

/** Polling observations only; never dispatch authority or packet evidence. */
export const policyReconcilerObservationSchema = z
  .object({
    enabled: z.boolean(),
    lastPassUnixMs: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    verified: z.number().int().nonnegative().max(2_147_483_647),
    drift: z.number().int().nonnegative().max(2_147_483_647),
    inconclusive: z.number().int().nonnegative().max(2_147_483_647),
    foreign: z.number().int().nonnegative().max(2_147_483_647),
    absent: z.number().int().nonnegative().max(2_147_483_647),
    pending: z.number().int().nonnegative().max(2_147_483_647),
  })
  .strict();
export const policyReconcilerHealthSchema = policyReconcilerObservationSchema
  .extend({
    reportedAt: isoDateTimeSchema,
  })
  .strict();

export const hostCapacitySchema = z.strictObject({
  memoryBudgetMiB: vmCapacitySchema.shape.memoryBudgetMiB.nullable(),
  maxCpuCount: vmCapacitySchema.shape.maxCpuCount.nullable(),
  maxMemoryMiB: z.number().int().min(0).max(VM_SIZE_LIMITS.memoryMiBMax).nullable(),
  memoryReservedMiB: z.number().int().min(0),
  memoryAvailableMiB: z.number().int().min(0).nullable(),
  memoryOvercommittedMiB: z.number().int().min(0).nullable(),
  vcpuBudget: hostVcpuBudgetSchema.nullable(),
  vcpuReserved: z.number().int().min(0),
  vcpuAvailable: z.number().int().min(0).nullable(),
  vcpuOvercommitted: z.number().int().min(0).nullable(),
  retainedRootCount: z.number().int().min(0),
  current: z.boolean(),
  reportedAt: isoDateTimeSchema.nullable(),
});

export const VM_SIZE_PUBLIC_LIMITS = {
  vmCpuCountMin: VM_SIZE_LIMITS.cpuCountMin,
  vmCpuCountMax: VM_SIZE_LIMITS.cpuCountMax,
  vmCpuCountDefault: VM_SIZE_LIMITS.cpuCountDefault,
  vmMemoryMiBMin: VM_SIZE_LIMITS.memoryMiBMin,
  vmMemoryMiBMax: VM_SIZE_LIMITS.memoryMiBMax,
  vmMemoryMiBDefault: VM_SIZE_LIMITS.memoryMiBDefault,
  vmMemoryMiBStep: VM_SIZE_LIMITS.memoryMiBStep,
  vmDiskGiBMin: VM_SIZE_LIMITS.diskGiBMin,
  vmDiskGiBMax: VM_SIZE_LIMITS.diskGiBMax,
  vmDiskGiBDefault: VM_SIZE_LIMITS.diskGiBDefault,
  vmHostOverheadMiB: VM_SIZE_LIMITS.vmHostOverheadMiB,
  hostManagedSandboxCeiling: VM_SIZE_LIMITS.hostManagedSandboxCeiling,
} as const;
const vmSizeLimitsSchema = z.object({
  vmDiskGiBMin: z.literal(VM_SIZE_PUBLIC_LIMITS.vmDiskGiBMin),
  vmDiskGiBMax: z.literal(VM_SIZE_PUBLIC_LIMITS.vmDiskGiBMax),
  vmDiskGiBDefault: z.literal(VM_SIZE_PUBLIC_LIMITS.vmDiskGiBDefault),
  vmHostOverheadMiB: z.literal(VM_SIZE_PUBLIC_LIMITS.vmHostOverheadMiB),
  hostManagedSandboxCeiling: z.literal(VM_SIZE_PUBLIC_LIMITS.hostManagedSandboxCeiling),
  vmCpuCountMin: z.literal(VM_SIZE_PUBLIC_LIMITS.vmCpuCountMin),
  vmCpuCountMax: z.literal(VM_SIZE_PUBLIC_LIMITS.vmCpuCountMax),
  vmCpuCountDefault: z.literal(VM_SIZE_PUBLIC_LIMITS.vmCpuCountDefault),
  vmMemoryMiBMin: z.literal(VM_SIZE_PUBLIC_LIMITS.vmMemoryMiBMin),
  vmMemoryMiBMax: z.literal(VM_SIZE_PUBLIC_LIMITS.vmMemoryMiBMax),
  vmMemoryMiBDefault: z.literal(VM_SIZE_PUBLIC_LIMITS.vmMemoryMiBDefault),
  vmMemoryMiBStep: z.literal(VM_SIZE_PUBLIC_LIMITS.vmMemoryMiBStep),
});

export const hostStoragePoolSchema = storagePoolV11Schema.safeExtend({
  id: resourceIdSchema,
  diskReservedGiB: z.number().int().min(0).max(2147483647),
  reportedAt: isoDateTimeSchema,
});

export const SANDBOX_EGRESS_MODE_REASONS = ["node_policy", "host_unsupported"] as const;
export type SandboxEgressModeReason = (typeof SANDBOX_EGRESS_MODE_REASONS)[number];
/** Why requested guestSudo is not effective (public spelling of `SandboxGuestSudoReason`). */
export const SANDBOX_GUEST_SUDO_REASONS = ["node_policy", "host_unsupported"] as const;
export type SandboxGuestSudoReason = (typeof SANDBOX_GUEST_SUDO_REASONS)[number];

/**
 * Where a stopped sandbox's root disk lives (docs/guide/sandboxes.md#disk-offload):
 * `host` (on its host only), `host_and_store` (on its host and a verified
 * encrypted copy in the image store), `store` (in the store only; OFFLOADED,
 * or a restore still fetching it onto its new host).
 */
export const SANDBOX_DISK_LOCATIONS = ["host", "host_and_store", "store"] as const;
export type SandboxDiskLocation = (typeof SANDBOX_DISK_LOCATIONS)[number];
/** The sandbox's current offload attempt or stored copy; `none` when it has neither. */
export const SANDBOX_DISK_OFFLOAD_STATES = [
  "none",
  "pending",
  "exporting",
  "uploading",
  "verifying",
  "stored",
  "evicting",
  "failed",
] as const;
export type SandboxDiskOffloadStateDto = (typeof SANDBOX_DISK_OFFLOAD_STATES)[number];
/**
 * Why the last offload of the current stopped disk failed (`offloadState:
 * "failed"`); the disk stays on its host. `other` covers transient upload,
 * verification and host failures.
 */
export const SANDBOX_DISK_OFFLOAD_FAILURES = [
  "quota_exceeded",
  "size_exceeded",
  "staging_full",
  "other",
] as const;
export type SandboxDiskOffloadFailure = (typeof SANDBOX_DISK_OFFLOAD_FAILURES)[number];
/**
 * Which hosts may restore the disk: `any_host` (your hosts and other users'
 * hosts that accept foreign images), `own_hosts` (pinned, login history or an
 * owned-nodes-only template), `never` (a managed sandbox, never offloaded).
 * Per-host checks (capacity, guard, allowlists) still apply at restore.
 */
export const SANDBOX_DISK_ELIGIBILITY = ["any_host", "own_hosts", "never"] as const;
export type SandboxDiskEligibility = (typeof SANDBOX_DISK_ELIGIBILITY)[number];
/** Owner restore pin: `OWN_HOSTS` keeps the disk off other users' hosts. */
export const SANDBOX_OFFLOAD_PINS = ["ANY", "OWN_HOSTS"] as const;
export type SandboxOffloadPinDto = (typeof SANDBOX_OFFLOAD_PINS)[number];

/** Owner-scoped disk facts; never an object key, key material or host of a stored copy. */
export const sandboxDiskSchema = z
  .object({
    location: z.enum(SANDBOX_DISK_LOCATIONS),
    offloadState: z.enum(SANDBOX_DISK_OFFLOAD_STATES),
    /** Present only when `offloadState` is `failed`. */
    offloadFailure: z.enum(SANDBOX_DISK_OFFLOAD_FAILURES).nullable(),
    /** When the current stored copy was verified; null without one. */
    offloadedAt: isoDateTimeSchema.nullable(),
    /** Plaintext size of the current stored copy; null without one. */
    sizeBytes: z.number().int().nonnegative().nullable(),
    eligibility: z.enum(SANDBOX_DISK_ELIGIBILITY),
    offloadPin: z.enum(SANDBOX_OFFLOAD_PINS),
  })
  .strict();
export type SandboxDiskDto = z.infer<typeof sandboxDiskSchema>;

export const hostSchema = z
  .object({
    id: resourceIdSchema,
    slug: z.string(),
    label: z.string(),
    status: z.enum(HOST_STATUSES),
    lastConnectedAt: isoDateTimeSchema.nullable(),
    lastHeartbeatAt: isoDateTimeSchema.nullable(),
    retainedRootCount: z.number().int().min(0),
    capacity: hostCapacitySchema,
    storagePools: z.array(hostStoragePoolSchema).max(VM_SIZE_LIMITS.storagePoolMax),
    draining: z.boolean(),
    /** Host advertised egress-policy enforcement in its last registered hello (M5, C34). */
    egressEnforcement: z.boolean(),
    /** The daemon can serve open-mode egress on this connection (static per daemon run). */
    egressOpen: z.boolean(),
    /** The host owner allows open internet for other users' sandboxes (set on the host). */
    openEgressForOthers: z.boolean(),
    /** The node owner allows guestSudo in other users' sandboxes (daemon default: allow). */
    guestSudoForOthers: z.boolean(),
    /**
     * The host's root-owned egress guard. A host without an active lease is
     * not schedulable in either mode. `reason` is a bounded machine code.
     */
    egressGuard: z
      .object({
        ok: z.boolean(),
        reason: z.string().max(64).nullable(),
        leaseActive: z.boolean(),
      })
      .strict(),
    policyReconciler: policyReconcilerHealthSchema.optional(),
    liveSandboxCount: z.number().int().min(0),
    drained: z.boolean(),
    deletionRequested: z.boolean(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
  })
  .strict();
export type HostDto = z.infer<typeof hostSchema>;

/** Image placement and capture retention settings. */
const templateImageSettingsShape = {
  imagePlacement: z.enum(["INHERIT", "ANY_NODE", "OWNED_NODES_ONLY"]),
  captureKeep: z.number().int().min(1).max(50),
  pruneAfterDays: z.number().int().min(1).max(3650).nullable(),
};
export const IMAGE_ARTIFACT_STATES = [
  "LOCAL",
  "UPLOADING",
  "VERIFYING",
  "STORED",
  "CORRUPT",
  "FAILED",
  "DELETING",
  "DELETED",
] as const;
/** Why a revision retired (CHECK `sandbox_revision_retired_reason`). */
export const RETIRED_REASONS = [
  "manual",
  "retention",
  "auto_prune",
  "verify_failed",
  "superseded",
] as const;
export type RetiredReason = (typeof RETIRED_REASONS)[number];
/** Where a revision came from. UPSTREAM is a community base's pinned image. */
export const REVISION_SOURCE_KINDS = ["MANUAL", "CAPTURE", "BUILD", "UPSTREAM"] as const;
const revisionImageShape = {
  source: z
    .object({
      kind: z.enum(REVISION_SOURCE_KINDS),
      parentRevisionId: resourceIdSchema.nullable(),
      captureTag: z.string().nullable(),
    })
    .strict()
    .optional(),
  image: z
    .object({
      state: z.enum(IMAGE_ARTIFACT_STATES),
      store: z.enum(["S3", "PEER"]),
      /** Decimal string: image sizes can exceed 2^53 bytes in principle. */
      sizeBytes: z.string().regex(/^[0-9]{1,16}$/),
    })
    .strict()
    .nullable()
    .optional(),
  retiredReason: z.enum(RETIRED_REASONS).nullable().optional(),
  /** A community build's output awaiting its verify VM: not launchable yet. */
  pendingVerify: z.boolean().optional(),
};
export const templateSchema = z
  .object({
    id: resourceIdSchema,
    slug: z.string(),
    label: z.string(),
    archivedAt: isoDateTimeSchema.nullable(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    ...templateImageSettingsShape,
    /** A wssp-managed community base: its catalog id and daily refresh switch. */
    community: z
      .object({ source: z.string(), refresh: z.boolean() })
      .strict()
      .nullable()
      .optional(),
  })
  .strict();
export type TemplateDto = z.infer<typeof templateSchema>;
export const templateRevisionSchema = z
  .object({
    id: resourceIdSchema,
    templateId: resourceIdSchema,
    revision: z.number().int().positive(),
    ...vmSizeSchema.shape,
    incusFingerprint: z.string(),
    architecture: z.string(),
    guest: z
      .object({
        uid: z.number().int().positive(),
        gid: z.number().int().positive(),
        home: z.string(),
        shell: z.string(),
      })
      .strict(),
    guestVersion: z.string().nullable(),
    manifestDigest: z.string(),
    retiredAt: isoDateTimeSchema.nullable(),
    createdAt: isoDateTimeSchema,
    /**
     * Captured from (or built on) a sandbox whose guest could reach root.
     * Sandboxes from this revision are `guestRoot` even with `guestSudo` off.
     */
    capturedWithGuestRoot: z.boolean(),
    /** Built by wssp's own verified base recipe (its root steps are not a taint). */
    builtWithWsspRecipe: z.boolean(),
    ...revisionImageShape,
  })
  .strict();
export type TemplateRevisionDto = z.infer<typeof templateRevisionSchema>;
export const templateAvailabilitySchema = z
  .object({
    id: resourceIdSchema,
    revisionId: resourceIdSchema,
    hostId: resourceIdSchema,
    status: z.enum(["PENDING", "AVAILABLE", "MISSING", "REJECTED"]),
    verifiedConnectionEpoch: z.number().int().nonnegative().nullable(),
    observedAt: isoDateTimeSchema.nullable(),
  })
  .strict();
export const templateRevisionPageSchema = z
  .object({ items: z.array(templateRevisionSchema), nextCursor: cursorSchema.nullable() })
  .strict();
export const templateAvailabilityPageSchema = z
  .object({ items: z.array(templateAvailabilitySchema), nextCursor: cursorSchema.nullable() })
  .strict();

/** Why a waiting create could not place on its last evaluation. */
export const CAPACITY_BLOCKERS = [
  "ram",
  "vcpu",
  "disk",
  "storage",
  "ceiling",
  "reserved",
  "member_quota",
  "share_quota",
  "unavailable",
  /** The template's build revision is being rebuilt (template builds, rebuild on miss). */
  "image_rebuilding",
] as const;
export type CapacityBlocker = (typeof CAPACITY_BLOCKERS)[number];
export const capacityWaitViewSchema = z
  .object({
    state: z.literal("waiting"),
    poolId: resourceIdSchema,
    enqueuedAt: isoDateTimeSchema,
    deadlineAt: isoDateTimeSchema.nullable().describe("null waits without limit."),
    position: z.number().int().min(1),
    blocker: z.enum(CAPACITY_BLOCKERS).nullable(),
  })
  .strict();
export type CapacityWaitView = z.infer<typeof capacityWaitViewSchema>;

export const sandboxSchema = z
  .object({
    acceptedGraceSeconds: z.number().int().min(0).max(2592000).default(0),
    accessGraceUntil: isoDateTimeSchema.nullable().default(null),
    id: resourceIdSchema,
    /** Owner-chosen or generated name, unique among the owner's live sandboxes. */
    name: sandboxNameSchema,
    hostId: resourceIdSchema.nullable(),
    storageId: resourceIdSchema.nullable(),
    storagePoolName: storageIdentityV11Schema.shape.name.nullable(),
    storageMarker: storageIdentityV11Schema.shape.marker.nullable(),
    ...vmSizeSchema.shape,
    templateId: resourceIdSchema,
    templateRevisionId: resourceIdSchema,
    originPoolId: resourceIdSchema.nullable(),
    state: z.enum(SANDBOX_STATES),
    generation: z.number().int().min(0),
    lease: z
      .object({
        revision: z.number().int().min(0),
        expiresAt: isoDateTimeSchema
          .nullable()
          .describe(
            "Requested lease end. 9999-12-31T23:59:59.999Z means no time limit (timeoutMs: 0).",
          ),
        onExpire: z.enum(LEASE_EXPIRE_ACTIONS),
        /** Most recent lease the caller requested (create or renewal); null if none is recorded. */
        requested: leaseTermSchema.nullable(),
        /** Lease the host acknowledged; null until the host confirms one. */
        effective: leaseTermSchema.nullable(),
      })
      .strict(),
    endAt: isoDateTimeSchema
      .nullable()
      .describe(
        "Lease end the host enforces. 9999-12-31T23:59:59.999Z means no time limit; see isUnlimitedLeaseEnd.",
      ),
    startedAt: isoDateTimeSchema.nullable(),
    readyAt: isoDateTimeSchema.nullable(),
    lifecycle: z
      .object({ onTimeout: z.enum(["kill", "stop"]), autoResume: z.literal(false) })
      .strict(),
    sandboxDomain: z.null(),
    portExposure: z.null(),
    metadata: metadataSchema,
    /**
     * The EFFECTIVE egress policy the host enforces, fixed when the sandbox
     * was placed and never re-derived. `open`: public IPv4 internet;
     * `allowlist` with no grants is deny-all (also the read-back while a
     * create waits for capacity and for pre-policy rows).
     */
    egress: normalizedEgressPolicySchema,
    /** The normalized request (explicit mode; grants are fallback grants when open). Null on pre-mode rows. */
    egressRequest: normalizedEgressPolicySchema.nullable(),
    /**
     * Why open was requested but the effective mode is allowlist:
     * `node_policy` (another user's host that allows only listed destinations
     * for other users' sandboxes) or `host_unsupported` (the host cannot serve
     * open mode). Null otherwise.
     */
    egressModeReason: z.enum(SANDBOX_EGRESS_MODE_REASONS).nullable(),
    /** Grants the host's domain blocklist refused (allowlist mode). */
    egressDeniedGrants: z.array(z.string().max(253)).max(128),
    /** EFFECTIVE guest sudo, resolved once at placement and never changed. */
    guestSudo: z.boolean(),
    /** Whether the create asked for guestSudo (after the default). */
    guestSudoRequested: z.boolean(),
    /**
     * Why requested guestSudo is off: `node_policy` (another user's node that does
     * not allow guestSudo for others) or `host_unsupported` (the node's
     * daemon cannot grant it). Null otherwise.
     */
    guestSudoReason: z.enum(SANDBOX_GUEST_SUDO_REASONS).nullable(),
    /**
     * The guest may reach root (guest sudo, or a revision built with root or
     * captured with guest root). Every command result is then guest-attested,
     * and UNKNOWN commands retire only on host proof.
     */
    guestRoot: z.boolean(),
    /**
     * Root disk location and offload facts (disk offload). Null while the
     * sandbox has no disk: waiting for capacity, or deleted.
     */
    disk: sandboxDiskSchema.nullable(),
    /**
     * Present only while a pool create waits for capacity (state
     * WAITING_FOR_CAPACITY). `position` counts this pool's waiting creates
     * ahead of it plus one; `blocker` is the last reason it could not place.
     */
    capacityWait: capacityWaitViewSchema.optional(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
  })
  .strict();
export type SandboxDto = z.infer<typeof sandboxSchema>;

/** Safe accepted lifetime evidence; no request/config digest or workload values. */
export const acceptedLeaseIntentSchema = z
  .object({
    acceptedAt: isoDateTimeSchema,
    timeoutMs: z
      .number()
      .int()
      .nonnegative()
      .describe(
        "Accepted relative lease. 0 means no lease timer; endAt is then 9999-12-31T23:59:59.999Z.",
      ),
    revision: z.number().int().positive(),
    endAt: isoDateTimeSchema,
    onTimeout: z.enum(["kill", "stop"]),
    acknowledgedAt: isoDateTimeSchema.nullable(),
    acknowledgedAttempt: z.number().int().positive().nullable(),
    acknowledgedEpoch: z.number().int().nonnegative().nullable(),
  })
  .strict();

export const failureSchema = z
  .object({
    resource: z.enum(["filesystem", "process", "command", "sandbox", "operation"]),
    effect: z.enum(["none", "partial", "unknown"]),
    reason: capacityReasonSchema.optional(),
  })
  .strict();
export type OperationFailure = z.infer<typeof failureSchema>;

export const OPERATION_PROGRESS_PHASES = [
  "fetching_image",
  "importing_image",
  "freezing",
  "snapshotting",
  "copying",
  "scrubbing",
  "publishing",
  "uploading",
  "finalizing",
  // Disk offload and restore (§8).
  "exporting_disk",
  "uploading_disk",
  "fetching_disk",
  "importing_disk",
] as const;
export const operationProgressSchema = z
  .object({
    phase: z.enum(OPERATION_PROGRESS_PHASES),
    bytesDone: z.number().int().nonnegative().nullable(),
    bytesTotal: z.number().int().nonnegative().nullable(),
    updatedAt: isoDateTimeSchema,
  })
  .strict();
export type OperationProgressDto = z.infer<typeof operationProgressSchema>;

/** Status metadata only: never result, output, error detail, payload or idempotency key. */
export const operationSchema = z
  .object({
    id: resourceIdSchema,
    sandboxId: resourceIdSchema,
    kind: z.enum(OPERATION_KINDS),
    state: z.enum(OPERATION_STATES),
    outcome: z.enum(OPERATION_OUTCOMES),
    generation: z.number().int().min(0),
    leaseIntent: acceptedLeaseIntentSchema.nullable(),
    failure: failureSchema.nullable(),
    errorCode: z.enum(OPERATION_ERROR_CODES).nullable(),
    /** `guest_unavailable` only: which guest readiness check failed (a fixed label). */
    readinessReason: readinessFailureReasonSchema.optional(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    dispatchedAt: isoDateTimeSchema.nullable(),
    completedAt: isoDateTimeSchema.nullable(),
    /** Host-reported progress (image download, capture phases); omitted when none. */
    progress: operationProgressSchema.optional(),
    /** CAPTURE_TEMPLATE only: the revision the capture produced. */
    capturedRevisionId: resourceIdSchema.optional(),
  })
  .strict()
  .refine(
    (operation) =>
      operation.failure?.reason === undefined ||
      operation.errorCode === "host_capacity" ||
      operation.errorCode === "capacity_wait_timeout",
    { message: "Capacity reasons require a capacity error", path: ["failure", "reason"] },
  )
  .refine(
    (operation) =>
      operation.readinessReason === undefined || operation.errorCode === "guest_unavailable",
    { message: "Readiness reasons require guest_unavailable", path: ["readinessReason"] },
  )
  .refine((operation) => operation.outcome === operationOutcome(operation.state), {
    message: "outcome must be derived from state",
    path: ["outcome"],
  });
export type OperationDto = z.infer<typeof operationSchema>;

function pageSchema<T extends z.ZodType>(item: T) {
  return z
    .object({ items: z.array(item).max(PAGE_SIZE_MAX), nextCursor: cursorSchema.nullable() })
    .strict();
}

export const hostPageSchema = pageSchema(hostSchema);
export const templatePageSchema = pageSchema(templateSchema);
export const sandboxPageSchema = pageSchema(sandboxSchema).extend({
  nextCursor: sandboxCursorSchema.nullable(),
});
export type HostPage = z.infer<typeof hostPageSchema>;
export type TemplatePage = z.infer<typeof templatePageSchema>;
export type SandboxPage = z.infer<typeof sandboxPageSchema>;

/**
 * Public feature names. A feature appears in `/v1/capabilities` only when every
 * route that provides it is registered by the running server.
 */
export const SDK_FEATURES = [
  "sandboxes.write",
  "sandboxes.vmSize",
  "sandboxes.probe",
  "commands.execute",
  "commands.read",
  "operations.cancel",
  "files.metadata",
  "files.upload",
  "files.download",
  "templates.write",
  "hosts.read",
  "pools.read",
  "templates.read",
  "sandboxes.read",
  "operations.read",
  "operations.result",
  "files.list",
  "commands.background",
  "processes.list",
  "processes.connect",
  "processes.kill",
  "processes.signal",
  "templates.capture",
  "sandboxes.imageFetch",
  "webhooks.write",
  "sandboxes.capacityWait",
  "pools.capacity",
  "templates.build",
  "credentials.read",
  "credentials.write",
  "credentials.use",
  "sandboxes.guestSudo",
] as const;
export type SdkFeature = (typeof SDK_FEATURES)[number];

/** Fixed interface bounds and the staged command-duration capability. */
export const FS_PROCESS_LIMITS = {
  resultPageMaxBytes: resultLimits.hostResultMaxBytes,
  responseMaxBytes: resultLimits.responseMaxBytes,
  observationRetentionMs: resultLimits.observationRetentionMs,
  mutationContentRetentionMs: resultLimits.mutationContentRetentionMs,
  resultOwnerReservedMaxBytes: resultLimits.ownerReservedMaxBytes,
  resultPendingReservationBytes: resultLimits.hostResultMaxBytes,
  listDefaultLimit: resultLimits.listDefaultLimit,
  listMaxLimit: resultLimits.listMaxLimit,
  directoryDepthMax: resultLimits.directoryDepthMax,
  listVisitMax: resultLimits.listVisitMax,
  observationTimeoutMs: resultLimits.observationTimeoutMs,
  commandTimeoutDefaultMs: 120000,
  commandTimeoutPositiveMaxMs: 1800000,
  get commandTimeoutZero(): boolean {
    return commandTimeoutZeroEnabled;
  },
} as const;
export const fsProcessLimitsSchema = z
  .object({
    resultPageMaxBytes: z.literal(FS_PROCESS_LIMITS.resultPageMaxBytes),
    responseMaxBytes: z.literal(FS_PROCESS_LIMITS.responseMaxBytes),
    observationRetentionMs: z.literal(FS_PROCESS_LIMITS.observationRetentionMs),
    mutationContentRetentionMs: z.literal(FS_PROCESS_LIMITS.mutationContentRetentionMs),
    resultOwnerReservedMaxBytes: z.literal(FS_PROCESS_LIMITS.resultOwnerReservedMaxBytes),
    resultPendingReservationBytes: z.literal(FS_PROCESS_LIMITS.resultPendingReservationBytes),
    listDefaultLimit: z.literal(FS_PROCESS_LIMITS.listDefaultLimit),
    listMaxLimit: z.literal(FS_PROCESS_LIMITS.listMaxLimit),
    directoryDepthMax: z.literal(FS_PROCESS_LIMITS.directoryDepthMax),
    listVisitMax: z.literal(FS_PROCESS_LIMITS.listVisitMax),
    observationTimeoutMs: z.literal(FS_PROCESS_LIMITS.observationTimeoutMs),
    commandTimeoutDefaultMs: z.literal(FS_PROCESS_LIMITS.commandTimeoutDefaultMs),
    commandTimeoutPositiveMaxMs: z.literal(FS_PROCESS_LIMITS.commandTimeoutPositiveMaxMs),
    commandTimeoutZero: z
      .boolean()
      .describe(
        "Whether command timeoutMs: 0 is accepted: no separate command timer, bounded by the sandbox lease and execution authority. Clients must check this capability before sending zero.",
      ),
  })
  .strict();
export const guestApiSchema = z
  .object({
    resultVersion: z.literal(1),
    processModel: z.literal("tracked-commands"),
    supportedSignals: z
      .array(z.enum(["SIGTERM", "SIGINT", "SIGHUP", "SIGKILL"]))
      .min(1)
      .max(4),
    signalSupport: z.literal("checked-at-call"),
    symlinkMetadata: z.literal(true),
    symlinkTraversal: z.literal(false),
    allGuestProcesses: z.literal(false),
    filesWatch: z.literal(false),
    sdkPty: z.literal(false),
    ingress: z.literal(false),
    getHost: z.literal(false),
    pause: z.literal(false),
    snapshot: z.literal(false),
    restore: z.literal(false),
    fork: z.literal(false),
    /** Sandboxes may grant the guest user `sudo` (`guestSudo`, default on). */
    guestSudo: z.literal(true),
  })
  .strict();
/**
 * `processSignalsAvailable`: the `processes.signal` feature is advertised for
 * this target and, for a sandbox, its host has not observed a guest without
 * group signals (kernel < 6.9). Calls are still checked at call time.
 */
export function guestApiCapabilities(
  processSignalsAvailable: boolean,
): z.infer<typeof guestApiSchema> {
  return {
    resultVersion: 1,
    processModel: "tracked-commands",
    supportedSignals: processSignalsAvailable
      ? ["SIGTERM", "SIGINT", "SIGHUP", "SIGKILL"]
      : ["SIGKILL"],
    signalSupport: "checked-at-call",
    symlinkMetadata: true,
    symlinkTraversal: false,
    allGuestProcesses: false,
    filesWatch: false,
    sdkPty: false,
    ingress: false,
    getHost: false,
    pause: false,
    snapshot: false,
    restore: false,
    fork: false,
    guestSudo: true,
  };
}
export const sandboxCapabilitiesSchema = z
  .object({
    sandboxId: resourceIdSchema,
    generation: z.number().int().positive(),
    features: z.array(z.enum(SDK_FEATURES)),
    unavailableReason: z.enum(["host_unavailable", "unsupported_runtime"]).nullable(),
    limits: fsProcessLimitsSchema,
    guestApi: guestApiSchema,
  })
  .strict();
export type SandboxCapabilities = z.infer<typeof sandboxCapabilitiesSchema>;

/**
 * Template-build availability and limits for the caller's owner. `reason` is a
 * deployment-level cause (`no_builder` is reported per build request instead).
 */
export const templateBuildLimitsSchema = z
  .object({
    enabled: z.boolean(),
    reason: z
      .enum(["off", "image_distribution_off", "no_builder", "lease_ceiling", "storage_unavailable"])
      .nullable()
      .describe("Why builds are unavailable; null when enabled."),
    maxMinutes: z
      .number()
      .int()
      .min(0)
      .max(1440)
      .describe(
        "Largest timeoutMinutes one build may request, after the deployment lease clamp (0 when disabled by it).",
      ),
    maxConcurrent: z
      .number()
      .int()
      .min(0)
      .nullable()
      .describe(
        "Builds this account may run at once (awaiting context included); null is unlimited.",
      ),
    minutesPerMonth: z
      .number()
      .int()
      .min(0)
      .nullable()
      .describe("Build minutes per UTC month for this account; null is unlimited."),
    contextMaxBytes: z.number().int().min(1).describe("Largest COPY context of one build."),
    contextWaitMaxMs: z
      .number()
      .int()
      .min(0)
      .describe("A COPY build's waitForCapacityMs is clamped to this."),
    openEgress: z.boolean().describe("Whether builds may request open egress (mode: open)."),
  })
  .strict();
export type TemplateBuildLimits = z.infer<typeof templateBuildLimitsSchema>;

export const capabilitiesSchema = z
  .object({
    apiVersion: z.literal(API_VERSION),
    features: z.array(z.enum(SDK_FEATURES)),
    limits: z
      .object({
        ...fsProcessLimitsSchema.shape,
        ...vmSizeLimitsSchema.shape,
        sandboxTimeoutMinMs: z
          .literal(1)
          .describe(
            "Smallest finite sandbox timeoutMs. 0 is a separate no-timer sentinel gated by sandboxTimeoutZero.",
          ),
        sandboxTimeoutDefaultMs: z.literal(300000),
        sandboxTimeoutMaxMs: z
          .number()
          .int()
          .min(LEASE_LIMIT_MIN_MS)
          .max(LEASE_FINITE_MAX_MS)
          .describe(
            "Largest finite sandbox timeoutMs this deployment allows. Hosts, pools and memberships may allow less; see a pool's lease field.",
          ),
        sandboxTimeoutZero: z
          .boolean()
          .describe(
            "Whether this deployment allows sandbox timeoutMs: 0 (no lease timer). A target must also allow it; the far-future endAt 9999-12-31T23:59:59.999Z marks such a sandbox.",
          ),
        pageSizeDefault: z.number().int().min(1),
        pageSizeMax: z.number().int().min(1),
        jsonBodyMaxBytes: z.number().int().min(1),
        /** The server's configured per-transfer cap (at most TRANSFER_MAX_BYTES). */
        transferMaxBytes: z.number().int().min(1),
        /** Template image distribution mode and this key owner's quotas. */
        imageStore: z
          .object({
            mode: z.enum(["off", "peer", "s3"]),
            maxStoredGiB: z.number().int().nonnegative().nullable(),
            downloadsPerHour: z.number().int().nonnegative().nullable(),
          })
          .strict()
          .optional(),
        /** Template builds for this key's owner (absent on servers without builds). */
        templateBuilds: templateBuildLimitsSchema.optional(),
        capacityWaitMaxMs: z
          .number()
          .int()
          .min(0)
          .max(CAPACITY_WAIT_MAX_MS)
          .nullable()
          .describe(
            "Deployment maximum waitForCapacityMs; null allows waits without limit, 0 disables waits. Pools may allow less.",
          ),
        capacityQueuePerKey: z
          .number()
          .int()
          .min(0)
          .nullable()
          .describe("Waiting creates one SDK key may hold across pools; null is unlimited."),
        capacityQueuePerOwner: z
          .number()
          .int()
          .min(0)
          .nullable()
          .describe("Waiting creates one account may hold across pools; null is unlimited."),
      })
      .strict(),
    guestApi: guestApiSchema,
    ports: z.object({ ingress: z.literal(false), proxy: z.literal(false) }).strict(),
    network: z
      .object({
        egressModes: z.array(z.enum(EGRESS_MODES)),
        defaultEgressMode: z.enum(EGRESS_MODES),
      })
      .strict()
      .describe(
        "Egress modes. Omitting `egress` requests open internet; on another user's host that allows only listed destinations the sandbox is placed in allowlist mode with the request's grants (egressModeReason).",
      ),
    key: z
      .object({
        scopes: z.array(z.enum(SDK_SCOPES)),
        resourceMode: z.enum(["allOwned", "allowlist"]),
        poolMode: z.enum(["allUsable", "selected"]),
      })
      .strict(),
  })
  .strict();
export type CapabilitiesDto = z.infer<typeof capabilitiesSchema>;

export const resourceIdParamsSchema = z.object({ id: resourceIdSchema }).strict();
export const emptyQuerySchema = z.object({}).strict();

/**
 * Longest time one operation read may be held open by `waitMs` (long-poll).
 * Well under common proxy idle limits (Cloudflare: 100 s).
 */
export const OPERATION_WAIT_MAX_MS = 25_000;

/**
 * Streamed-output pacing of a held output read (`waitMs`): a page with new
 * bytes of a still-running command is held this long (from the moment the
 * bytes are first seen) for more bytes or the completion, then answered. A
 * completion ends the hold at once, so a quick command still answers in one
 * held read. 2 s caps a continuously printing command at 60 / (2 s + RTT) ≤ 30
 * answers a minute even at zero round-trip time (≈ 28/min at 150 ms), the
 * same as the earlier interval polling (back-off capped at 2 s), so several
 * concurrent commands fit one key's 100/min `/v1` budget as before.
 */
export const OPERATION_WAIT_PROGRESS_HOLD_MS = 2_000;

/**
 * `waitMs`: decimal milliseconds string, 0–25000. The server may answer
 * earlier (a change, its own waiter capacity, shutdown); 0 or absent reads
 * immediately. Query values are strings on the wire.
 */
export const operationWaitMsQuerySchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]{0,4})$/)
  .transform(Number)
  .pipe(z.number().int().min(0).max(OPERATION_WAIT_MAX_MS));

/** Query of the operation status and result reads: an optional long-poll hold. */
export const operationWaitQuerySchema = z
  .object({ waitMs: operationWaitMsQuerySchema.optional() })
  .strict();

/** Effective queue limits: null is unlimited; maxWaitMs 0 disables waits. */
export const poolCapacityLimitsSchema = z
  .object({
    maxWaitMs: z.number().int().min(0).max(CAPACITY_WAIT_MAX_MS).nullable(),
    perKey: z.number().int().min(0).nullable(),
    perOwner: z.number().int().min(0).nullable(),
  })
  .strict();

export const poolSchema = z
  .object({
    id: resourceIdSchema,
    slug: z.string(),
    label: z.string(),
    owner: z.object({ id: resourceIdSchema, name: z.string() }).strict().optional(),
    share: z
      .object({
        canUse: z.boolean(),
        canContribute: z.boolean(),
        maxMemoryMiB: z.number().int().min(1).max(16777216).nullable(),
        maxVcpu: z.number().int().min(1).max(8192).nullable(),
        maxDiskGiB: z.number().int().min(1).max(268435456).nullable(),
        usage: z
          .object({
            memoryMiB: z.string().max(20).regex(/^\d+$/),
            vcpu: z.string().max(20).regex(/^\d+$/),
            diskGiB: z.string().max(20).regex(/^\d+$/),
          })
          .strict(),
      })
      .strict()
      .optional(),
    disconnectGraceSeconds: z.number().int().min(0).max(2592000).optional(),
    lease: z
      .strictObject({
        maxTimeoutMs: z
          .number()
          .int()
          .min(LEASE_LIMIT_MIN_MS)
          .max(LEASE_FINITE_MAX_MS)
          .describe(
            "Largest finite timeoutMs on this pool's best available path for this key (deployment, host ceilings, pool and membership maximums). Placement may offer less if hosts are offline.",
          ),
        timeoutZero: z
          .boolean()
          .describe(
            "Whether some path in this pool allows timeoutMs: 0 (no lease timer) for this caller.",
          ),
      })
      .describe(
        "Lease limits for this caller. With a single contributed member, maxTimeoutMs reveals that host's effective ceiling.",
      ),
    preferOwnHosts: z
      .boolean()
      .describe("Placement ranks the requester's own member hosts first (a tier, not a filter)."),
    capacityWait: poolCapacityLimitsSchema.describe(
      "Effective capacity-wait limits for this caller (deployment and pool layers).",
    ),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
  })
  .strict();
export const poolDetailSchema = poolSchema
  .extend({ memberCount: z.number().int().min(0) })
  .strict();
const ownedPoolMemberSchema = z
  .object({
    id: resourceIdSchema,
    poolId: resourceIdSchema,
    hostId: resourceIdSchema,
    enabled: z.boolean(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    host: z
      .object({
        id: resourceIdSchema,
        slug: z.string(),
        label: z.string(),
        draining: z.boolean(),
        status: z.enum(HOST_STATUSES),
      })
      .strict(),
  })
  .strict();
/** Use grantees get an opaque member ID; no foreign host identity/status. */
export const poolMemberSchema = z.union([
  ownedPoolMemberSchema,
  z.object({ id: resourceIdSchema, poolId: resourceIdSchema }).strict(),
]);
export const poolPageSchema = z
  .object({ items: z.array(poolSchema).max(PAGE_SIZE_MAX), nextCursor: cursorSchema.nullable() })
  .strict();
export const poolMemberPageSchema = z
  .object({
    items: z.array(poolMemberSchema).max(PAGE_SIZE_MAX),
    nextCursor: cursorSchema.nullable(),
  })
  .strict();
const resourceTriple = z
  .object({
    memoryMiB: z.number().int().min(0),
    vcpu: z.number().int().min(0),
    diskGiB: z.number().int().min(0),
  })
  .strict();
export const CAPACITY_HOST_EXCLUSIONS = [
  /** The revision has a start command; this host's daemon cannot run it. */
  "template_startup",
  "template_unavailable",
  "lease_policy",
  "vm_size",
  "offline",
  "draining",
  /** Held for an older waiting create in the pool queue (strict head). */
  "reserved",
] as const;
/**
 * `GET /v1/pools/{id}/capacity`: what the caller could place now. Aggregates
 * sum pool-usable free capacity (host free, capped by member caps) over
 * currently schedulable visible hosts. `fits` leaves out hosts reserved for
 * an older waiting create, exactly as a create would (`pool_full` with reason
 * `reserved`). `hosts` lists only the caller's OWN
 * member hosts (and only with hosts:read); foreign hosts never appear.
 */
export const poolCapacitySchema = z
  .object({
    poolId: resourceIdSchema,
    templateRevisionId: resourceIdSchema.nullable(),
    size: vmSizeSchema.nullable(),
    aggregate: z.object({ free: resourceTriple, budget: resourceTriple }).strict(),
    /** Request-size sandboxes that fit now (capped by your share caps); null without a size. */
    fits: z.number().int().min(0).nullable(),
    lease: z.strictObject({
      maxTimeoutMs: z.number().int().min(LEASE_LIMIT_MIN_MS).max(LEASE_FINITE_MAX_MS),
      timeoutZero: z.boolean(),
    }),
    queue: z
      .object({
        waiting: z.number().int().min(0),
        mine: z.number().int().min(0),
        myOldestPosition: z.number().int().min(1).nullable(),
        limits: poolCapacityLimitsSchema,
        preferOwnHosts: z.boolean(),
      })
      .strict(),
    hosts: z
      .array(
        z
          .object({
            id: resourceIdSchema,
            slug: z.string(),
            label: z.string(),
            status: z.enum(HOST_STATUSES),
            draining: z.boolean(),
            schedulable: z.boolean(),
            memory: z
              .object({ budgetMiB: z.number().int().min(0), reservedMiB: z.number().int().min(0) })
              .strict(),
            vcpu: z
              .object({ budget: z.number().int().min(0), reserved: z.number().int().min(0) })
              .strict(),
            storagePools: z
              .array(
                z
                  .object({
                    name: z.string(),
                    capacityGiB: z.number().int().min(0),
                    reservedGiB: z.number().int().min(0),
                    healthy: z.boolean(),
                  })
                  .strict(),
              )
              .max(64),
            liveCount: z.number().int().min(0),
            member: z
              .object({
                memoryCapPercent: z.number().int().min(1).max(100).nullable(),
                vcpuCapPercent: z.number().int().min(1).max(100).nullable(),
                maxLeaseMs: z.number().int().nullable(),
              })
              .strict(),
            fits: z.number().int().min(0).nullable(),
            dominantShareAfter: z.number().min(0).nullable(),
            excludedBy: z.enum(CAPACITY_HOST_EXCLUSIONS).nullable(),
          })
          .strict(),
      )
      .max(250),
  })
  .strict();
export type PoolCapacityDto = z.infer<typeof poolCapacitySchema>;
export const poolCapacityQuerySchema = z
  .object({
    template: z.string().min(1).max(200).optional(),
    cpuCount: z
      .string()
      .regex(/^[1-9][0-9]{0,1}$/)
      .transform(Number)
      .optional(),
    memoryMiB: z
      .string()
      .regex(/^[1-9][0-9]{2,5}$/)
      .transform(Number)
      .optional(),
    diskGiB: z
      .string()
      .regex(/^[1-9][0-9]{0,3}$/)
      .transform(Number)
      .optional(),
  })
  .strict();

export type PoolDto = z.infer<typeof poolSchema>;
export type PoolDetailDto = z.infer<typeof poolDetailSchema>;
export type PoolMemberDto = z.infer<typeof poolMemberSchema>;
export type PoolPage = z.infer<typeof poolPageSchema>;
export type PoolMemberPage = z.infer<typeof poolMemberPageSchema>;
