import { KEY_FREE_CLEANUP_KINDS } from "@wssp/api/sandbox/contracts";
import { type HostLease, leaseWireSchema } from "@wssp/api/sandbox/lease-wire";
import {
  type BuildCopyV11,
  hostHelloV11Schema as baseHostHelloV11Schema,
  CHANNEL_KINDS,
  CREDENTIAL_CAPTURE_DISPATCH_KINDS,
  CREDENTIAL_SPEC_DISPATCH_KINDS,
  type CredentialSpecRefV11,
  capacityReasonSchema,
  channelsCapabilitySchema,
  credentialSpecRefV11Schema,
  credentialTeardownOriginSchema,
  type DispatchBuildV11,
  type DispatchCaptureV11,
  type DispatchExpectDiskV11,
  type DispatchImageV11,
  type DispatchRestoreV11,
  type DispatchStartupV11,
  daemonCredentialMessageSchemas,
  daemonDiskMessageSchemas,
  daemonImageMessageSchemas,
  defaultEnvSchema,
  dispatchCaptureV11Schema,
  dispatchStartupV11Schema,
  type EgressBlocklistV11,
  type EgressPolicyWire,
  egressBlocklistV11Schema,
  egressRefusalReasonSchema,
  egressRefusedV11Schema,
  encodedJsonBytes,
  failureSchema,
  hostAdmissionV11Schema,
  hostEgressStateV11Schema,
  hostInventoryUpdateV11Schema,
  hostLeaseCeilingSchema,
  isCanonicalEgressPolicyWire,
  isoDateTimeSchema,
  knownRelayProtocolVersion,
  type LaunchMode,
  launchModeSchema,
  operationProgressV11Schema,
  outputChunkBytesSchema,
  pinnedAllocationV11Schema,
  policyReconcilerObservationSchema,
  processRefSchema,
  RESULT_LIMITS,
  type RelayProtocolVersion,
  type RunAsV11,
  readinessFailureReasonSchema,
  resourceIdSchema,
  resultBodySchema,
  resultContinuationSchema,
  rootObservationV11Schema,
  SANDBOX_RELAY_PROTOCOL_VERSION,
  SERVER_CREDENTIAL_MESSAGE_TYPES,
  SERVER_DISK_MESSAGE_TYPES,
  SERVER_IMAGE_MESSAGE_TYPES,
  type ServerCredentialMessage,
  type ServerDiskMessage,
  type ServerImageMessage,
  serverCredentialMessageSchema,
  serverDiskMessageSchema,
  serverImageMessageSchema,
  type TunnelApplyV11,
  type TunnelClearV11,
  type TunnelPortsV11,
  tunnelApplyV11Schema,
  tunnelClearV11Schema,
  tunnelPortsStatusV11Schema,
  tunnelPortsV11Schema,
  tunnelStatusV11Schema,
  tunnelWireDeclaredPortsSchema,
  type VmSize,
  validDispatchBuildFields,
  validDispatchDiskFields,
  validDispatchImageFields,
  validDispatchStartup,
  vmSizeSchema,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import {
  agentPolicyFields,
  HOST_CONTROL_MAX_BYTES,
  type HostServerMessage,
  hostDaemonSchemas,
  hostServerMessageSchema,
  validAgentPolicy,
} from "./host-access-protocol.js";

const hostHelloV11Schema = baseHostHelloV11Schema.safeExtend({
  daemon: baseHostHelloV11Schema.shape.daemon.extend({
    capabilities: baseHostHelloV11Schema.shape.daemon.shape.capabilities
      .extend(agentPolicyFields)
      .refine(validAgentPolicy),
  }),
});

import channelLimits from "../../../../packages/config/src/sandbox-channel-limits.json";
import commandLimits from "../../../../packages/config/src/sandbox-command-limits.json";
import receiptLimits from "../../../../packages/config/src/sandbox-receipt-limits.json";
import terminalLimits from "../../../../packages/config/src/sandbox-terminal-limits.json";
export const RECEIPT_LIMITS = receiptLimits;
/** C52 terminal channel bounds, shared with Rust (`sandbox_protocol::terminal`). */
export const TERMINAL_LIMITS = terminalLimits;
/** Interactive channel bounds, shared with Rust (`sandbox_protocol::channel`). */
export const CHANNEL_LIMITS = channelLimits;
const COMMAND_LIMITS = commandLimits;
/** Stateless (non-streaming) codecs, shared by every frame. */
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const canonicalBodyHashSchema = z
  .string()
  .length(RECEIPT_LIMITS.bodyHashBytes)
  .regex(/^[0-9a-f]+$/);

export const SANDBOX_RELAY_SUBPROTOCOL = "ws-sandbox-proxy.relay.v1";
export { SANDBOX_RELAY_PROTOCOL_VERSION } from "@wssp/sandbox-contracts";

type NegotiatedVersion = RelayProtocolVersion;

export const SANDBOX_JSON_CONTROL_MAX_BYTES = COMMAND_LIMITS.jsonControlMaxBytes;
export const SANDBOX_BINARY_CHUNK_MAX_BYTES = 1024 * 1024;
export const SANDBOX_FRAME_MAX_BYTES = Math.max(
  HOST_CONTROL_MAX_BYTES,
  4 + SANDBOX_JSON_CONTROL_MAX_BYTES + SANDBOX_BINARY_CHUNK_MAX_BYTES,
);
const SANDBOX_STREAM_WINDOW_CHUNKS = 4;

const messageIdSchema = z.string().trim().min(1).max(128);

export const sandboxErrorCodeSchema = z.enum([
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

  "host_runtime_unsupported",
  "host_effect_not_issued",
  "host_disconnect_expired",
  "host_capacity",
  "vm_size_mismatch",
  "protocol_version_unsupported",
  "protocol_error",
  "transport",
  "timeout",
  "disconnected",
  "egress_resolution_failed",
  "cancelled",
  "access_denied",
  "guest_permission_denied",
  "guest_operation_failed",
  "path_refused",
  "not_found",
  "sandbox_not_found",
  "operation_not_found",
  "idempotency_conflict",
  "digest_key_changed",
  "digest_key_unavailable",
  "receipt_digest_pruned",
  "state_conflict",
  "lease_exceeds_policy",
  "request_too_large",
  "rate_limited",
  "internal",
  "unknown_outcome",
  "guest_unavailable",
  "sandbox_not_running",
  "snapshot_failed",
  "unsupported_capability",
  "image_unavailable",
  "image_cache_full",
  "image_corrupt",
  "image_rejected",
  "image_fetch_timeout",
  "capture_failed",
  "capture_freeze_failed",
  "capture_store_failed",
  "startup_failed",
  "startup_timeout",
  "guest_network_unavailable",
  "credential_install_failed",
  "credential_spec_invalid",
  "credential_env_pending",
  "credential_capture_failed",
  "disk_stale",
  "connection_refused",
]);
export type SandboxErrorCode = z.infer<typeof sandboxErrorCodeSchema>;

export const ALLOWED_HOST_DISPATCH_KINDS = [
  "sandbox.create",
  "sandbox.lease.renew",
  "sandbox.kill",
  "sandbox.reconnect",
  "sandbox.stop",
  "command.run",
  "file.get",
  "file.put",
  "file.list",
  "file.stat",
  "file.mkdir",
  "file.remove",
  "file.move",
  "process.list",
  "process.signal",
  "sandbox.probe",
  "sandbox.capture",
  "credential.attach",
  "credential.free",
] as const;

const RELAY_CONTROL_DISPATCH_KINDS = ["process.stdin", "operation.cancel"] as const;

const UNSUPPORTED_HOST_DISPATCH_KINDS = [
  "snapshot.create",
  "snapshot.restore",
  "sandbox.fork",
] as const;

export type DispatchKindClass = "allowed" | "control" | "unsupported_capability" | "unknown";

export function classifyRelayDispatchKind(kind: string): DispatchKindClass {
  if ((UNSUPPORTED_HOST_DISPATCH_KINDS as readonly string[]).includes(kind)) {
    return "unsupported_capability";
  }
  if ((RELAY_CONTROL_DISPATCH_KINDS as readonly string[]).includes(kind)) {
    return "control";
  }
  if ((ALLOWED_HOST_DISPATCH_KINDS as readonly string[]).includes(kind)) {
    return "allowed";
  }
  return "unknown";
}

const operationStateSchema = z.enum([
  "queued",
  "dispatched",
  "accepted",
  "running",
  "cancel_requested",
  "succeeded",
  "failed",
  "cancelled",
  "unknown_outcome",
]);

const generationSchema = z.number().int().min(1);
const attemptSchema = z.number().int().min(0);

export const sandboxLifecycleStateSchema = z.enum([
  "requested",
  "scheduled",
  "provisioning",
  "ready",
  "stopping",
  "stopped",
  "absent",
  "reclaiming",
  "deleted",
  "unreachable",
  "recovered",
  "host_lost",
  "error",
]);
type SandboxLifecycleState = z.infer<typeof sandboxLifecycleStateSchema>;

const runtimeKindSchema = z.enum(["fake", "incus_kvm", "unsupported"]);
export type DaemonRuntimeKind = z.infer<typeof runtimeKindSchema>;

/**
 * Open wire error code. A newer daemon may send (or replay from its journal)
 * a well-formed code outside this catalog; it parses as `internal`, a
 * fail-safe terminal failure, instead of failing the whole frame. Anything
 * not `[a-z_]{1,64}` is still a protocol error.
 */
const wireErrorCodeSchema = z
  .string()
  .regex(/^[a-z_]{1,64}$/)
  .transform((code): SandboxErrorCode => {
    const known = sandboxErrorCodeSchema.safeParse(code);
    return known.success ? known.data : "internal";
  });

const protocolErrorDetailSchema = z
  .object({
    code: wireErrorCodeSchema,
    /** A capacity reason with `host_capacity`; an egress refusal reason
     * (default-open egress §1.5) with `unsupported_capability`; the failed
     * readiness check with `guest_unavailable`. */
    reason: z
      .union([capacityReasonSchema, egressRefusalReasonSchema, readinessFailureReasonSchema])
      .optional(),
    message: z.string().refine((value) => Buffer.byteLength(value) <= RECEIPT_LIMITS.errorBytes),
    operationId: z.string().trim().min(1).max(128).optional(),
    sandboxId: z.string().trim().min(1).max(128).optional(),
  })
  .strict()
  .refine(
    (error) =>
      error.reason === undefined ||
      (error.code === "host_capacity" && capacityReasonSchema.safeParse(error.reason).success) ||
      (error.code === "unsupported_capability" &&
        egressRefusalReasonSchema.safeParse(error.reason).success) ||
      (error.code === "guest_unavailable" &&
        readinessFailureReasonSchema.safeParse(error.reason).success),
  );

const INVENTORY_PAGE_MAX_ENTRIES = 64;
const INVENTORY_MAX_PAGES = 1024;

const EXPIRY_FAILURE_REASON_MAX_BYTES = 160;

const inventoryEntrySchema = z
  .object({
    sandboxOwnerId: messageIdSchema.nullable(),
    // Shared with the disk root-absence proofs (`disk.evicted`).
    root: rootObservationV11Schema.nullable(),
    sandboxId: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[A-Za-z0-9_-]+$/),
    state: sandboxLifecycleStateSchema,
    lease: z
      .object({
        generation: generationSchema,
        lease: leaseWireSchema,
        expired: z.boolean(),
        expiryComplete: z.boolean(),
        timerExpired: z.boolean(),
        expiryFailure: z
          .object({
            reason: z
              .string()
              .min(1)
              .max(EXPIRY_FAILURE_REASON_MAX_BYTES)
              .regex(/^[\x20-\x7e]+$/),
            attempts: z.number().int().min(1).max(4_294_967_295),
            sinceUnixMs: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
          })
          .strict()
          .optional(),
      })
      .strict()
      .refine((lease) => !lease.timerExpired || lease.expired, "timer latch requires expiry")
      .refine(
        (lease) => !lease.expiryFailure || (lease.expired && !lease.expiryComplete),
        "expiry failure requires a pending expiry",
      )
      .optional(),
  })
  .strict();
const allocationIdsSchema = z
  .array(
    z
      .string()
      .min(1)
      .max(128)
      .regex(/^[A-Za-z0-9_-]+$/),
  )
  .min(1)
  .max(256)
  .refine((ids) => ids.every((id, i) => i === 0 || id > ids[i - 1]!));
const allocationBarrierSchema = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const allocationRequestSchema = z
  .object({
    type: z.literal("allocation.attest.request"),
    connectionEpoch: generationSchema.max(2_147_483_647),
    barrier: allocationBarrierSchema,
    sandboxIds: allocationIdsSchema,
    allocations: z
      .array(
        z.strictObject({
          sandboxId: z.string().min(1).max(128),
          sandboxOwnerId: messageIdSchema,
          allocation: pinnedAllocationV11Schema,
        }),
      )
      .max(256),
  })
  .strict();

export type InventoryEntry = z.infer<typeof inventoryEntrySchema>;

const inventoryEntriesSchema = z
  .array(inventoryEntrySchema)
  .max(INVENTORY_PAGE_MAX_ENTRIES)
  .refine(
    (entries) =>
      entries.every((entry, i) => i === 0 || (entries[i - 1]?.sandboxId ?? "") < entry.sandboxId),
    "inventory entries must be strictly ascending",
  );

const terminalIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/);
const admissionEpochSchema = z.number().int().min(1).max(2_147_483_647);
const terminalTargetV11Schema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("host") }),
  z.strictObject({
    kind: z.literal("sandbox"),
    sandboxId: terminalIdSchema,
    generation: admissionEpochSchema,
  }),
]);
export const terminalFenceV11Schema = z.strictObject({
  sessionId: terminalIdSchema,
  operationId: terminalIdSchema,
  hostId: terminalIdSchema,
  epoch: admissionEpochSchema,
  target: terminalTargetV11Schema,
});
const policyRevisionV11Schema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
export const hostTerminalPolicyControlV11Schema = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("host.terminal-policy"),
    connectionEpoch: admissionEpochSchema,
    sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    hostTerminal: z.boolean(),
    requireHostTerminalTotp: z.boolean(),
    policyRevision: policyRevisionV11Schema,
  }),
  z.strictObject({
    type: z.literal("host.terminal-policy.raise"),
    connectionEpoch: admissionEpochSchema,
    requestId: terminalIdSchema,
  }),
]);
/** Current-link host lease ceiling report; fenced like the terminal policy. */
const hostLeasePolicyControlV11Schema = z.strictObject({
  type: z.literal("host.lease-policy"),
  connectionEpoch: admissionEpochSchema,
  sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  maxLeaseMs: hostLeaseCeilingSchema,
});
/** WP7 (D9): the daemon is quiescing for a restart; negotiated (`quiesce`). */
const hostQuiesceV11Schema = z.strictObject({
  type: z.literal("host.quiesce"),
  connectionEpoch: admissionEpochSchema,
  sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
});
/** The server's answer to `host.quiesce`, echoing its sequence. */
const hostQuiesceAckV11Schema = z.strictObject({
  type: z.literal("host.quiesce.ack"),
  sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
});
const terminalFenceSchema = terminalFenceV11Schema;
export type TerminalFence = z.infer<typeof terminalFenceSchema>;
const terminalRowsSchema = z.number().int().min(1).max(TERMINAL_LIMITS.maxRows);
const terminalColsSchema = z.number().int().min(1).max(TERMINAL_LIMITS.maxCols);
const terminalSequenceSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const terminalCloseIntentSchema = z.enum([
  "client",
  "detached",
  "replaced",
  "backpressure",
  "revoked",
  "superseded",
  "protocol_violation",
  "host_disconnected",
  "expired",
  "sandbox_stopped",
  "sandbox_destroyed",
  "lifecycle_unconfirmed",
  "shutdown",
]);
export type TerminalCloseIntent = z.infer<typeof terminalCloseIntentSchema>;

/** Guest terminal cwd: the daemon's `valid_cwd`, shared with `startup.cwd`. */
const terminalCwdSchema = dispatchStartupV11Schema.shape.cwd.unwrap();

const serverTerminalMessageSchema = z.discriminatedUnion("type", [
  hostTerminalPolicyControlV11Schema.options[1],
  z
    .object({
      type: z.literal("terminal.open"),
      hostPolicy: z
        .strictObject({ policyRevision: policyRevisionV11Schema, proofRequired: z.boolean() })
        .optional(),
      requestId: terminalIdSchema,
      fence: terminalFenceSchema,
      rows: terminalRowsSchema,
      cols: terminalColsSchema,
      /** Guest opens only: the revision's default cwd (else the guest home). */
      cwd: terminalCwdSchema.optional(),
    })
    .strict()
    .refine((v) => (v.fence.target.kind === "host") === (v.hostPolicy !== undefined))
    .refine((v) => v.fence.target.kind === "sandbox" || v.cwd === undefined),
  z
    .object({
      type: z.literal("terminal.resize"),
      requestId: terminalIdSchema,
      fence: terminalFenceSchema,
      rows: terminalRowsSchema,
      cols: terminalColsSchema,
    })
    .strict(),
  /**
   * WP8: reattach the detached sandbox PTY `fence.sessionId` under this
   * connection's fence. Sent only to a node that negotiated `terminalResume`,
   * after its `reconcile.complete`; never for a host target.
   */
  z
    .object({
      type: z.literal("terminal.resume"),
      requestId: terminalIdSchema,
      fence: terminalFenceSchema,
      nextOutputSeq: terminalSequenceSchema,
      rows: terminalRowsSchema,
      cols: terminalColsSchema,
    })
    .strict()
    .refine((v) => v.fence.target.kind === "sandbox"),
  z
    .object({
      type: z.literal("terminal.close"),
      requestId: terminalIdSchema,
      fence: terminalFenceSchema,
      intent: terminalCloseIntentSchema,
    })
    .strict(),
  z
    .object({
      type: z.literal("terminal.ack"),
      fence: terminalFenceSchema,
      sequence: terminalSequenceSchema,
    })
    .strict(),
]);
type ServerTerminalMessage = z.infer<typeof serverTerminalMessageSchema>;

/** Channel and connection ids: shorter than terminal ids so the guest unit
 * `wssp-chan-<connectionId>.<channelId>.scope` stays short. */
const channelIdSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/);
const channelFenceSchema = z.strictObject({
  channelId: channelIdSchema,
  connectionId: channelIdSchema,
  hostId: terminalIdSchema,
  epoch: admissionEpochSchema,
  target: z.strictObject({
    kind: z.literal("sandbox"),
    sandboxId: terminalIdSchema,
    generation: admissionEpochSchema,
  }),
});
export type ChannelFence = z.infer<typeof channelFenceSchema>;
const utf8Bytes = (value: string) => Buffer.byteLength(value, "utf8");
const noNul = (value: string) => !value.includes("\0");
const channelArgvSchema = z
  .array(z.string().refine(noNul))
  .min(1)
  .max(CHANNEL_LIMITS.argvMaxItems)
  .refine(
    (argv) => argv.reduce((total, arg) => total + utf8Bytes(arg), 0) <= CHANNEL_LIMITS.argvMaxBytes,
  );
const channelCwdSchema = z
  .string()
  .refine(
    (cwd) => cwd.startsWith("/") && noNul(cwd) && utf8Bytes(cwd) <= CHANNEL_LIMITS.cwdMaxBytes,
  );
/** Only locale and colour hints; `TERM` travels in `pty.term`. */
const channelEnvSchema = z
  .record(
    z.string().regex(/^(COLORTERM|LANG|LC_[A-Z0-9_]+)$/),
    z
      .string()
      .refine((value) => noNul(value) && utf8Bytes(value) <= CHANNEL_LIMITS.envValueMaxBytes),
  )
  .refine((env) => Object.keys(env).length <= CHANNEL_LIMITS.envMaxEntries);
const channelPtyParamsSchema = z.strictObject({
  rows: terminalRowsSchema,
  cols: terminalColsSchema,
  term: z
    .string()
    .min(1)
    .max(CHANNEL_LIMITS.termMaxBytes)
    .regex(/^[A-Za-z0-9._+-]+$/),
});
/** A guest loopback TCP port (`tcp` channels); never a host. */
const channelPortSchema = z.number().int().min(1).max(65_535);
/** An absolute guest Unix socket path (`unix` channels), never abstract. */
const channelUnixPathSchema = z
  .string()
  .refine(
    (path) =>
      path.startsWith("/") && noNul(path) && utf8Bytes(path) <= CHANNEL_LIMITS.unixPathMaxBytes,
  );
const channelOutputStreamSchema = z.enum(["stdout", "stderr"]);
const channelStreamSchema = z.enum(["stdin", "stdout", "stderr"]);

const serverChannelMessageSchema = z.discriminatedUnion("type", [
  z
    .strictObject({
      type: z.literal("channel.open"),
      fence: channelFenceSchema,
      kind: z.enum(CHANNEL_KINDS),
      argv: channelArgvSchema.optional(),
      login: z.boolean(),
      cwd: channelCwdSchema.optional(),
      env: channelEnvSchema.optional(),
      pty: channelPtyParamsSchema.optional(),
      port: channelPortSchema.optional(),
      path: channelUnixPathSchema.optional(),
    })
    .refine((v) => (v.kind === "pty") === (v.pty !== undefined))
    // A relay (tcp/unix) carries exactly its target and nothing of a
    // process; a process channel never carries a target.
    .refine((v) =>
      v.kind === "tcp" || v.kind === "unix"
        ? !v.login &&
          v.argv === undefined &&
          v.cwd === undefined &&
          v.env === undefined &&
          (v.kind === "tcp"
            ? v.port !== undefined && v.path === undefined
            : v.path !== undefined && v.port === undefined)
        : v.port === undefined && v.path === undefined,
    ),
  /** Cumulative credit: the highest delivered output `seq` of `stream`. */
  z.strictObject({
    type: z.literal("channel.ack"),
    fence: channelFenceSchema,
    stream: channelOutputStreamSchema,
    seq: terminalSequenceSchema,
  }),
  z.strictObject({
    type: z.literal("channel.eof"),
    fence: channelFenceSchema,
    stream: z.literal("stdin"),
    frames: terminalSequenceSchema,
  }),
  z.strictObject({
    type: z.literal("channel.resize"),
    fence: channelFenceSchema,
    rows: terminalRowsSchema,
    cols: terminalColsSchema,
  }),
  z.strictObject({
    type: z.literal("channel.signal"),
    fence: channelFenceSchema,
    signal: z.enum(["TERM", "INT", "HUP", "KILL"]),
  }),
  /** `client` is a normal close; any other intent kill-closes the channel. */
  z.strictObject({
    type: z.literal("channel.close"),
    fence: channelFenceSchema,
    intent: terminalCloseIntentSchema,
  }),
]);
type ServerChannelMessage = z.infer<typeof serverChannelMessageSchema>;

export const availabilityBindingSchema = z
  .object({
    revisionId: messageIdSchema,
    artifact: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    manifestHash: z.string().regex(/^[0-9a-f]{64}$/),
    architecture: z.enum(["x86_64", "aarch64"]),
  })
  .strict();
export type AvailabilityBinding = z.infer<typeof availabilityBindingSchema>;
const availabilityPageSchema = z.number().int().min(0).max(99);

const journalKeyIdSchema = z.string().regex(/^[0-9a-f]{32}$/);
const journalKeyInstallSchema = z
  .object({
    type: z.literal("journal.key.install"),
    connectionEpoch: admissionEpochSchema,
    keyVersion: z.literal(1),
    keyId: journalKeyIdSchema,
    server: z.string().min(1).max(2048),
    hostOwnerId: messageIdSchema,
    hostId: messageIdSchema,
    keyHex: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();

const privateConfigIdSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/);
const privateConfigRefSchema = z
  .object({
    configId: privateConfigIdSchema,
    bindingScheme: z.literal("hmac-sha256-v1"),
    bindingKeyId: journalKeyIdSchema,
    bindingMac: canonicalBodyHashSchema,
  })
  .strict();
const privateConfigAckSchema = z
  .object({
    type: z.literal("private.config.ack"),
    sandboxOwnerId: privateConfigIdSchema,
    connectionEpoch: admissionEpochSchema,
    sandboxId: privateConfigIdSchema,
    generation: admissionEpochSchema,
    config: privateConfigRefSchema,
  })
  .strict();
const privateConfigInstallSchema = z
  .object({
    type: z.literal("private.config.install"),
    refusalToken: privateConfigIdSchema,
    connectionEpoch: admissionEpochSchema,
    server: z.string().min(1).max(2048),
    hostOwnerId: privateConfigIdSchema,
    sandboxOwnerId: privateConfigIdSchema,
    hostId: privateConfigIdSchema,
    sandboxId: privateConfigIdSchema,
    generation: admissionEpochSchema,
    config: privateConfigRefSchema,
    env: z
      .array(z.tuple([z.string(), z.string()]))
      .max(64)
      .refine(
        (env) =>
          new Set(env.map(([key]) => key)).size === env.length &&
          defaultEnvSchema.safeParse(Object.fromEntries(env)).success,
      ),
  })
  .strict();

const U64_MAX = 18_446_744_073_709_551_615n;
/** Birth codec; session ingress still requires explicit negotiation.
 * Field rules match Rust `ProcessStarted::validate` exactly (shared cases in
 * `process_started_cases.json`): opaque operation id, canonical lowercase
 * 8-4-4-4-12 boot id (Linux boot_id; no RFC version rule), 1..=u64::MAX ticks. */
export const processStartedSchema = processRefSchema
  .extend({
    type: z.literal("process.started"),
    operationId: resourceIdSchema,
    bootId: z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/),
    startTicks: z
      .string()
      .regex(/^[1-9][0-9]{0,19}$/)
      .refine((ticks) => BigInt(ticks) <= U64_MAX),
    startedAt: isoDateTimeSchema,
    observedAt: isoDateTimeSchema,
  })
  .strict();

/** One strict, byte-bounded codec for both live and recovered host results. */
export const hostOperationResultSchema = z
  .object({
    version: z.literal(1),
    observedAt: isoDateTimeSchema,
    payload: resultBodySchema.nullable(),
    continuation: resultContinuationSchema.nullable(),
    birth: processStartedSchema.nullable(),
    failure: failureSchema.nullable(),
    outputBytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
    resultExpired: z.boolean().optional(),
  })
  .strict()
  .refine((value) => encodedJsonBytes(value) <= RESULT_LIMITS.hostResultMaxBytes)
  .refine(
    (value) => !value.resultExpired || (value.payload === null && value.continuation === null),
  )
  .refine((value) => {
    if (value.payload?.type === "command") {
      const b = value.birth,
        p = value.payload.process;
      return (
        b !== null &&
        p.sandboxId === b.sandboxId &&
        p.generation === b.generation &&
        p.attempt === b.attempt &&
        p.processId === b.processId &&
        p.pid === b.pid &&
        value.payload.startedAt === b.startedAt
      );
    }
    return value.payload === null || value.birth === null;
  });

/** Bound on one reconnect dispatch-audit page (Rust DISPATCH_AUDIT_PAGE_MAX). */
export const DISPATCH_AUDIT_PAGE_MAX = 64;
/** WP2 (D11): most receipts one `reconcile.complete` names as still resolving
 * (the host's in-flight resolution bound; Rust `PENDING_RECEIPTS_MAX`). */
export const PENDING_RECEIPTS_MAX = 4;
const dispatchAuditPageSchema = z.number().int().min(0).max(1024);

const coreDaemonControlMessageSchema = z.discriminatedUnion("type", [
  hostTerminalPolicyControlV11Schema.options[0],
  hostLeasePolicyControlV11Schema,
  hostQuiesceV11Schema,
  hostEgressStateV11Schema,
  tunnelStatusV11Schema,
  tunnelPortsStatusV11Schema,
  processStartedSchema,
  z
    .object({
      type: z.literal("operation.receipt.pruned"),
      sandboxOwnerId: messageIdSchema,
      operationId: privateConfigIdSchema,
      sandboxId: privateConfigIdSchema,
      generation: admissionEpochSchema,
      attempt: admissionEpochSchema,
      idempotencyKey: z.string().min(1).max(RECEIPT_LIMITS.idempotencyKeyBytes),
      kind: z.enum(receiptLimits.kinds as [string, ...string[]]),
    })
    .strict(),
  z
    .object({
      type: z.literal("private.config.refused"),
      sandboxOwnerId: privateConfigIdSchema,
      connectionEpoch: admissionEpochSchema,
      sandboxId: privateConfigIdSchema,
      generation: admissionEpochSchema,
      configId: privateConfigIdSchema,
      refusalToken: privateConfigIdSchema,
      reason: z.enum(["cleanup_watermark", "config_count_bound", "journal_io_before_persistence"]),
    })
    .strict(),
  privateConfigAckSchema,
  z
    .object({
      type: z.literal("journal.key.ack"),
      connectionEpoch: admissionEpochSchema,
      keyVersion: z.literal(1),
      keyId: journalKeyIdSchema,
    })
    .strict(),
  hostAdmissionV11Schema,
  z
    .object({
      type: z.literal("availability.result"),
      requestId: messageIdSchema,
      connectionEpoch: admissionEpochSchema,
      page: availabilityPageSchema,
      entries: z
        .array(
          z
            .object({
              binding: availabilityBindingSchema,
              status: z.enum(["present", "missing", "rejected"]),
              sizeBytes: z.number().int().min(1).optional(),
              format: z.enum(["unified", "split"]).optional(),
            })
            .strict(),
        )
        .max(100)
        .refine(
          (entries) => new Set(entries.map((e) => e.binding.revisionId)).size === entries.length,
        ),
    })
    .strict(),
  z
    .object({
      type: z.literal("terminal.ready"),
      requestId: terminalIdSchema,
      fence: terminalFenceSchema,
      rows: terminalRowsSchema,
      cols: terminalColsSchema,
      /** WP8: only on the answer to `terminal.resume` (the next output sequence). */
      outputSeq: terminalSequenceSchema.optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("terminal.ack"),
      fence: terminalFenceSchema,
      sequence: terminalSequenceSchema,
    })
    .strict(),
  z
    .object({
      type: z.literal("terminal.exit"),
      requestId: terminalIdSchema.optional(),
      fence: terminalFenceSchema,
      exitCode: z.number().int().min(-2147483648).max(2147483647).optional(),
      intent: terminalCloseIntentSchema.optional(),
      reaped: z.boolean(),
      error: protocolErrorDetailSchema.optional(),
    })
    .strict(),
  z.strictObject({
    type: z.literal("channel.ready"),
    fence: channelFenceSchema,
    pty: z.strictObject({ rows: terminalRowsSchema, cols: terminalColsSchema }).optional(),
  }),
  z.strictObject({
    type: z.literal("channel.ack"),
    fence: channelFenceSchema,
    stream: z.literal("stdin"),
    seq: terminalSequenceSchema,
  }),
  z.strictObject({
    type: z.literal("channel.eof"),
    fence: channelFenceSchema,
    stream: channelOutputStreamSchema,
    frames: terminalSequenceSchema,
  }),
  z.strictObject({
    type: z.literal("channel.error"),
    fence: channelFenceSchema,
    code: z.enum(["unsupported_signal", "state_conflict"]),
  }),
  /** The channel's last frame; at most one of `exitCode` and `signal`. */
  z
    .strictObject({
      type: z.literal("channel.exit"),
      fence: channelFenceSchema,
      exitCode: z.number().int().min(-2147483648).max(2147483647).optional(),
      signal: z.number().int().min(1).max(64).optional(),
      intent: terminalCloseIntentSchema.optional(),
      error: protocolErrorDetailSchema.optional(),
      reaped: z.boolean(),
      frames: z.strictObject({ stdout: terminalSequenceSchema, stderr: terminalSequenceSchema }),
    })
    .refine((v) => v.exitCode === undefined || v.signal === undefined),
  z
    .object({
      type: z.literal("allocation.attest.result"),
      connectionEpoch: generationSchema.max(2_147_483_647),
      barrier: allocationBarrierSchema,
      journalId: z.string().regex(/^[0-9a-f]{32}$/),
      entries: z
        .array(
          z
            .object({
              sandboxId: z.string(),
              sandboxOwnerId: messageIdSchema,
              settledNeverIssued: z.boolean(),
            })
            .strict(),
        )
        .refine(
          (entries) => allocationIdsSchema.safeParse(entries.map((e) => e.sandboxId)).success,
        ),
    })
    .strict(),
  z
    .object({
      type: z.literal("sandbox.inventory"),
      page: z
        .number()
        .int()
        .min(0)
        .max(INVENTORY_MAX_PAGES - 1),
      complete: z.boolean(),
      entries: inventoryEntriesSchema,
    })
    .strict(),
  z
    .object({
      type: z.literal("sandbox.expiry_status"),
      entries: inventoryEntriesSchema.refine((entries) => entries.length > 0),
      /** Only with `expiryStatusResults`: strictly increasing per session. */
      batch: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
      /** Only with `observationFence`, on every batch: the observation its
       * entries come from (from 1 per session, shared by its batches). */
      observation: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
    })
    .strict()
    // An observation numbers batches; it never stands alone.
    .refine((frame) => frame.observation === undefined || frame.batch !== undefined),
  hostHelloV11Schema,
  hostInventoryUpdateV11Schema,
  z
    .object({
      type: z.literal("heartbeat"),
      id: messageIdSchema,
      sentAt: z.string().datetime().optional(),
      policyReconciler: policyReconcilerObservationSchema.optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("operation.progress"),
      id: messageIdSchema,
      operationId: messageIdSchema,
      sandboxId: messageIdSchema,
      generation: generationSchema,
      attempt: attemptSchema,
      state: operationStateSchema,
      progress: operationProgressV11Schema.optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("operation.result"),
      id: messageIdSchema,
      operationId: messageIdSchema,
      sandboxId: messageIdSchema,
      generation: generationSchema,
      attempt: attemptSchema,
      state: operationStateSchema,
      error: protocolErrorDetailSchema.optional(),
      result: z.record(z.string(), z.unknown()).optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("operation.receipt"),
      sandboxOwnerId: messageIdSchema,
      operationId: messageIdSchema,
      sandboxId: messageIdSchema,
      generation: generationSchema,
      attempt: attemptSchema,
      bodyHash: canonicalBodyHashSchema,
      idempotencyKey: z
        .string()
        .min(1)
        .refine((value) => Buffer.byteLength(value) <= RECEIPT_LIMITS.idempotencyKeyBytes),
      kind: z.string().refine((value) => RECEIPT_LIMITS.kinds.includes(value)),
      state: z.enum(["succeeded", "failed", "cancelled", "unknown_outcome"]),
      result: z
        .record(z.string(), z.unknown())
        .refine((value) => Buffer.byteLength(JSON.stringify(value)) <= RECEIPT_LIMITS.resultBytes)
        .nullable(),
      error: protocolErrorDetailSchema.nullable(),
      /** the launch mode the host journaled (launches only). */
      launchMode: launchModeSchema.optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("operation.adopt"),
      sandboxOwnerId: terminalIdSchema,
      operationId: messageIdSchema,
      sandboxId: messageIdSchema,
      generation: generationSchema.max(2_147_483_647),
      attempt: attemptSchema,
      bodyHash: canonicalBodyHashSchema,
      idempotencyKey: z
        .string()
        .min(1)
        .refine((value) => Buffer.byteLength(value) <= RECEIPT_LIMITS.idempotencyKeyBytes),
      kind: z.string().refine((value) => RECEIPT_LIMITS.kinds.includes(value)),
      phase: z.enum(["intent", "effect"]),
      stdinNextSequence: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).nullable(),
    })
    .strict(),
  z.object({ type: z.literal("dispatch.audit.request"), page: dispatchAuditPageSchema }).strict(),
  z
    .object({
      type: z.literal("dispatch.audit.result"),
      page: dispatchAuditPageSchema,
      entries: z
        .array(
          z
            .object({
              operationId: terminalIdSchema,
              generation: generationSchema.max(2_147_483_647),
              attempt: attemptSchema.max(2_147_483_647),
              received: z.boolean(),
            })
            .strict(),
        )
        .max(DISPATCH_AUDIT_PAGE_MAX),
    })
    .strict(),
  z
    .object({
      type: z.literal("reconcile.complete"),
      /** WP2 (D11), only with `pendingReceipts`: operations whose receipt the
       * host is still resolving; left unsettled until it arrives or the
       * session ends. */
      pendingReceipts: z
        .array(terminalIdSchema)
        .max(PENDING_RECEIPTS_MAX)
        .refine((ids) => new Set(ids).size === ids.length)
        .optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("sandbox.probe.result"),
      requestId: messageIdSchema,
      state: z.enum(["guest_ready", "stopped", "confirmed_absent", "unreachable"]),
    })
    .strict(),
  z
    .object({
      type: z.literal("file.chunk.ack"),
      operationId: messageIdSchema,
      generation: generationSchema,
      attempt: attemptSchema,
      sequence: z.number().int().nonnegative(),
      offset: z.number().int().nonnegative(),
    })
    .strict(),
  z
    .object({
      type: z.literal("image.verify.result"),
      requestId: messageIdSchema,
      incusFingerprint: z.string().trim().min(1).max(128).optional(),
      architecture: z.string().trim().min(1).max(64).optional(),
      error: protocolErrorDetailSchema.optional(),
      sizeBytes: z.number().int().min(1).optional(),
      format: z.enum(["unified", "split"]).optional(),
    })
    .strict(),
  ...daemonImageMessageSchemas,
  ...daemonDiskMessageSchemas,
  egressRefusedV11Schema,
  ...daemonCredentialMessageSchemas,
]);
const daemonControlMessageSchema = z.union([coreDaemonControlMessageSchema, ...hostDaemonSchemas]);
export type DaemonControlMessage = z.infer<typeof daemonControlMessageSchema>;

const negotiatedCapabilitiesSchema = z
  .object({
    protocolVersion: z.custom<RelayProtocolVersion>(knownRelayProtocolVersion),
    binaryFrames: z.literal(true),
    cancellation: z.literal(true),
    maxBinaryChunkBytes: z.literal(SANDBOX_BINARY_CHUNK_MAX_BYTES),
    streamWindowChunks: z.literal(SANDBOX_STREAM_WINDOW_CHUNKS),
    /** D3b: command-output chunk ceiling; sent only to daemons that offered
     * `maxOutputChunkBytes` (absent: 8 KiB). */
    outputChunkBytes: outputChunkBytesSchema,
    /** WP7: sent (true) only to daemons that offered `quiesce`. */
    quiesce: z.literal(true).optional(),
    /** Sent only to daemons that offered `censusEntryResults`: every
     * `inventory.ack` then carries `entryResults`. */
    censusEntryResults: z.literal(true),
    /** WP8: echoed only to a daemon that offered `terminalResume`. */
    terminalResume: z.literal(true).optional(),
    /** WP2 (D11): sent only to daemons that offered `pendingReceipts`:
     * `reconcile.complete` may then carry `pendingReceipts`. */
    pendingReceipts: z.literal(true),
    /** WP2: sent only to daemons that offered `expiryStatusResults`: every
     * `sandbox.expiry_status` then carries a `batch`, answered by one
     * `sandbox.expiry_status.ack` judging each entry. */
    expiryStatusResults: z.literal(true),
    /** WP2 follow-up: sent only together with `expiryStatusResults`, to a
     * daemon that offered both: every batch then carries `observation`. */
    observationFence: z.literal(true),
    /** Plan §10: sent only to daemons that offered `commandRetire`:
     * `receipt.confirmed` may then carry `retireCommand`. */
    commandRetire: z.literal(true),
    /** Echoed only to a daemon that offered `channels`. */
    channels: channelsCapabilitySchema.optional(),
  })
  .strict();

export type NegotiatedCapabilities = z.infer<typeof negotiatedCapabilitiesSchema>;

/** Per-entry census result, in page order (`inventory.ack` `entryResults`,
 * sent to daemons that negotiated `censusEntryResults`). `stale_storage`:
 * the root evidence was refused only because pool health was not current;
 * the host retries it under a current observation. */
export type CensusEntryResult = {
  sandboxId: string;
  /** Exact offered root retirement; convergence alone may only adopt a lease. */
  rootRetired?: boolean;
  /** `superseded`: only in `sandbox.expiry_status.ack` (`observationFence`):
   * the observation may predate a lifecycle result the server received, so
   * it was not judged; the host offers a newer observation (bounded). */
  outcome: "converged" | "not_converged" | "stale_storage" | "superseded";
};

export type ServerControlMessage =
  | HostServerMessage
  | EgressBlocklistV11
  | TunnelApplyV11
  | TunnelClearV11
  | TunnelPortsV11
  | z.infer<typeof allocationRequestSchema>
  | z.infer<typeof journalKeyInstallSchema>
  | z.infer<typeof hostQuiesceAckV11Schema>
  | z.infer<typeof privateConfigInstallSchema>
  | {
      type: "availability.request";
      requestId: string;
      connectionEpoch: number;
      page: number;
      bindings: AvailabilityBinding[];
    }
  | ServerTerminalMessage
  | ServerChannelMessage
  | {
      type: "command.output.ack" | "file.chunk.ack";
      operationId: string;
      generation: number;
      attempt: number;
      sequence: number;
      offset: number;
    }
  | ({
      type: "sandbox.probe.request";
      requestId: string;
    } & Omit<import("@wssp/api/sandbox/host-image-verifier").HostSandboxProbeInput, "ownerId"> & {
        hostOwnerId: string;
        sandboxOwnerId: string;
      })
  | {
      type: "hello.ok";
      id: string;
      protocolVersion: NegotiatedVersion;
      capabilities: NegotiatedCapabilities;
      supportedProtocolVersions: string[];
      hostOwnerId: string;
      /** Every terminal/admission fence carries this exact epoch. */
      connectionEpoch: number;
    }
  | {
      type: "receipt.confirmed";
      sandboxOwnerId: string;
      operationId: string;
      sandboxId: string;
      generation: number;
      attempt: number;
      bodyHash: string;
      idempotencyKey: string;
      kind: string;
      cleanupGeneration?: number;
      /** Plan §10, only with `commandRetire`: this exact `command.run`
       * receipt is recorded UNKNOWN; the host retires it once it proves the
       * command can no longer run. Never with `cleanupGeneration`. */
      retireCommand?: true;
    }
  | {
      type: "receipt.pruned.ack";
      sandboxOwnerId: string;
      connectionEpoch: number;
      operationId: string;
      sandboxId: string;
      generation: number;
      attempt: number;
      idempotencyKey: string;
      kind: string;
    }
  | { type: "receipt.ack"; operationId: string }
  | {
      type: "dispatch.audit.page";
      page: number;
      complete: boolean;
      entries: Array<{
        sandboxOwnerId: string;
        operationId: string;
        sandboxId: string;
        generation: number;
        attempt: number;
        connectionEpoch: number;
        idempotencyKey: string;
        kind: string;
      }>;
    }
  | {
      type: "operation.adopt.result";
      operationId: string;
      generation: number;
      attempt: number;
      adopted: boolean;
    }
  | {
      /** WP2, only with `expiryStatusResults`: one result per entry of the
       * `sandbox.expiry_status` with the same batch, in order. */
      type: "sandbox.expiry_status.ack";
      batch: number;
      entryResults: CensusEntryResult[];
    }
  | {
      type: "inventory.ack";
      page: number;
      /** One per page entry, in order; only with `censusEntryResults`. */
      entryResults?: CensusEntryResult[];
    }
  | { type: "heartbeat.pong"; id: string; receivedAt: string }
  | {
      type: "operation.dispatch";
      sandboxOwnerId: string;
      operationId: string;
      sandboxId: string;
      idempotencyKey: string;
      kind: string;
      generation: number;
      attempt: number;
      allocation?: z.infer<typeof pinnedAllocationV11Schema>;
      cpuCount?: number;
      memoryMiB?: number;
      templateDigest?: string;
      templateRevisionId?: string;
      verificationConnectionEpoch?: number;
      incusFingerprint?: string;
      architecture?: string;
      guestUid?: number;
      guestGid?: number;
      guestHome?: string;
      guestShell?: string;
      incusName?: string;
      argv?: string[];
      script?: string;
      cwd?: string;
      timeoutMs?: number;
      stdinSequence?: number;
      path?: string;
      destPath?: string;
      recursive?: boolean;
      maxDepth?: number;
      env?: Array<[string, string]>;
      pid?: number;
      signal?: "SIGTERM" | "SIGINT" | "SIGHUP" | "SIGKILL";
      bodyHash?: string;
      digestScheme?: string;
      digestKeyId?: string | null;
      privateConfig?: z.infer<typeof privateConfigRefSchema>;
      lease?: HostLease;
      /** Recorded immutable egress policy, wire form (M5, C34); required on VM launches. */
      egressPolicy?: EgressPolicyWire;
      egressPolicyHash?: string;
      fileSize?: number;
      fileSha256?: string;
      /** Planned image fetch; only to hosts advertising `image.fetch`. */
      image?: DispatchImageV11;
      /** `sandbox.capture` body. */
      capture?: DispatchCaptureV11;
      /** Template build binding; `sandbox.create` only. */
      build?: DispatchBuildV11;
      /** Guest root for a build step; `command.run` on build sandboxes only. */
      runAs?: RunAsV11;
      /** Recipe COPY through the daemon's fixed helper; implies root. */
      buildCopy?: BuildCopyV11;
      /** Template start/ready commands; launches only (B9). */
      startup?: DispatchStartupV11;
      /** guestSudo grant; `sandbox.create`/`sandbox.reconnect` only, only
       * `true` (absent means false), only with `guestRoot`. */
      guestSudo?: true;
      /** The guest may reach root: host-proof-only retirement. Launches only. */
      guestRoot?: true;
      /** Preview tunnels: a tunnel sandbox's declared ports (ascending,
       * possibly none); launches only, always with their revision. */
      tunnelPorts?: number[];
      tunnelPortsRevision?: number;
      /** §8.6 (only to `diskOffload` daemons): a reconnect
       * that boots a new root from the stored disk, with `launchMode:
       * "new_root"` and a `fetch` image of the same fingerprint. */
      restore?: DispatchRestoreV11;
      /** The operation's immutable launch mode; launches only. */
      launchMode?: LaunchMode;
      /** §8.1: cold reconnect of a cached offloaded copy. */
      expectDisk?: DispatchExpectDiskV11;
      /** N1: the restored lineage's base image, for binding. */
      diskBaseFingerprint?: string;
      /** Credential spec reference; never inline. */
      credentialSpec?: CredentialSpecRefV11;
      /** `skip` on a stop/kill; absent means capture. */
      credentialCapture?: "skip";
      /** `system` on a stop/kill by the expiry/access/readiness writers; absent = user. */
      credentialTeardown?: "system";
      /** Qualified `process.signal` target; `pid` must repeat its pid (E4-01). */
      process?: import("@wssp/sandbox-contracts").ProcessRef;
      targetOperationId?: string;
    }
  | {
      type: "operation.cancel";
      operationId: string;
      generation: number;
      attempt: number;
      reason: SandboxErrorCode;
    }
  | {
      type: "sandbox.state";
      sandboxId: string;
      generation: number;
      state: SandboxLifecycleState;
    }
  | {
      type: "protocol.error";
      failure: SandboxErrorCode;
      message: string;
      operationId?: string;
    }
  | {
      type: "image.verify.request";
      requestId: string;
      imageRef: string;
      expectedArchitecture: string;
    }
  | ServerImageMessage
  | ServerDiskMessage
  | ServerCredentialMessage;

const streamKindSchema = z.enum(["stream.chunk", "stream.end"]);

const streamChunkFlagsSchema = z
  .object({
    stdout: z.boolean().optional(),
    stderr: z.boolean().optional(),
    fileUpload: z.boolean().optional(),
    fileDownload: z.boolean().optional(),
    stdin: z.boolean().optional(),
  })
  .strict();

const streamBinaryMetadataSchema = z
  .object({
    type: streamKindSchema,
    streamId: messageIdSchema,
    operationId: messageIdSchema,
    generation: generationSchema,
    attempt: attemptSchema,
    sequence: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
    offset: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
    gapStart: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
    flags: streamChunkFlagsSchema.optional(),
    final: z.boolean().optional(),
  })
  .strict();

export type StreamBinaryMetadata = z.infer<typeof streamBinaryMetadataSchema>;

export function negotiatedCapabilities(
  protocolVersion: NegotiatedVersion = SANDBOX_RELAY_PROTOCOL_VERSION,
  /** The daemon's hello offer: optional features echoed only when offered. */
  offered?: { channels?: NegotiatedCapabilities["channels"] },
): NegotiatedCapabilities {
  return {
    protocolVersion,
    binaryFrames: true,
    cancellation: true,
    maxBinaryChunkBytes: SANDBOX_BINARY_CHUNK_MAX_BYTES,
    streamWindowChunks: SANDBOX_STREAM_WINDOW_CHUNKS,
    outputChunkBytes: 65536,
    censusEntryResults: true,
    pendingReceipts: true,
    expiryStatusResults: true,
    observationFence: true,
    commandRetire: true,
    ...(offered?.channels === undefined ? {} : { channels: offered.channels }),
  };
}

export function parseSandboxRelaySubprotocolHeader(header: string | undefined): {
  ok: boolean;
  supported: boolean;
  requestedMajorVersions: number[];
} {
  const requested = (header ?? "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  const requestedMajorVersions = requested
    .map((part) => /^ws-sandbox-proxy\.relay\.v(\d+)$/.exec(part)?.[1])
    .filter((part): part is string => Boolean(part))
    .map((part) => Number.parseInt(part, 10));
  return {
    ok: requested.length > 0,
    supported: requested.includes(SANDBOX_RELAY_SUBPROTOCOL),
    requestedMajorVersions,
  };
}

class SandboxRelayProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SandboxRelayProtocolError";
  }
}

/** A payload validation failure proven to occur before any socket send. */
export class SandboxRelayDispatchValidationError extends Error {}
export class SandboxRelayVmSizeMismatchError extends SandboxRelayDispatchValidationError {}

/** Deterministic validation/encode failures in the dispatch send path. */
export function isDeterministicDispatchError(error: unknown): error is Error {
  if (error instanceof SandboxRelayDispatchValidationError) return true;
  if (error instanceof SandboxRelayProtocolError) return true;
  return false;
}

/** Decode only the launch pair; wire omission is distinct from persisted defaults. */
export function launchVmSizeForVersion(size: unknown, version: string): VmSize {
  if (!knownRelayProtocolVersion(version))
    throw new SandboxRelayDispatchValidationError("VM size was not negotiated.");
  const parsed = vmSizeSchema.safeParse(size);
  if (!parsed.success) throw new SandboxRelayDispatchValidationError("Invalid VM size.");
  return parsed.data;
}

export function encodeServerControlMessage(
  message: ServerControlMessage,
  protocolVersion: string,
): string {
  if (message.type.startsWith("host.policy.") && message.type !== "host.policy.lower")
    throw new SandboxRelayDispatchValidationError("Unsupported host policy request.");
  if (
    message.type.startsWith("host.exec.") ||
    message.type === "host.policy.lower" ||
    message.type === "host.file.request"
  ) {
    const encoded = JSON.stringify(hostServerMessageSchema.parse(message));
    if (
      Buffer.byteLength(encoded) >
      (["host.exec.start", "host.exec.stdin", "host.file.request"].includes(message.type)
        ? HOST_CONTROL_MAX_BYTES
        : SANDBOX_JSON_CONTROL_MAX_BYTES)
    )
      throw new SandboxRelayDispatchValidationError("Host control frame exceeds bound.");
    if (!knownRelayProtocolVersion(protocolVersion))
      throw new SandboxRelayDispatchValidationError("Unknown negotiated protocol version.");
    return encoded;
  }
  if (!knownRelayProtocolVersion(protocolVersion))
    throw new SandboxRelayDispatchValidationError("Unknown negotiated protocol version.");
  if (message.type === "inventory.ack" || message.type === "sandbox.expiry_status.ack") {
    const resultSchema = z
      .strictObject({
        sandboxId: z
          .string()
          .min(1)
          .max(128)
          .regex(/^[A-Za-z0-9_-]+$/),
        outcome: z.enum(["converged", "not_converged", "stale_storage", "superseded"]),
        rootRetired: z.boolean().optional(),
      })
      .refine((r) => !r.rootRetired || r.outcome === "converged");
    if (
      message.entryResults &&
      (!z.array(resultSchema).max(INVENTORY_PAGE_MAX_ENTRIES).safeParse(message.entryResults)
        .success ||
        (message.type === "inventory.ack" &&
          message.entryResults.some((r) => r.outcome === "superseded")))
    )
      throw new SandboxRelayDispatchValidationError("Invalid inventory acknowledgement.");
  }
  if (
    message.type === "allocation.attest.request" &&
    (!allocationRequestSchema.safeParse(message).success ||
      message.allocations.length !== message.sandboxIds.length ||
      message.allocations.map((p) => p.sandboxId).join("\0") !== message.sandboxIds.join("\0"))
  )
    throw new SandboxRelayDispatchValidationError("Invalid or unnegotiated allocation request.");
  if (
    message.type === "hello.ok" &&
    !admissionEpochSchema.safeParse(message.connectionEpoch).success
  )
    throw new SandboxRelayDispatchValidationError("Invalid hello epoch.");
  // D3b: daemons parse `hello.ok` strictly; never send an invalid ceiling.
  if (
    message.type === "hello.ok" &&
    !negotiatedCapabilitiesSchema.safeParse(message.capabilities).success
  )
    throw new SandboxRelayDispatchValidationError("Invalid hello capabilities.");
  if (message.type === "operation.dispatch") {
    const launch = message.kind === "sandbox.create" || message.kind === "sandbox.reconnect";
    const hasSize = message.cpuCount !== undefined || message.memoryMiB !== undefined;
    const bound = launch || KEY_FREE_CLEANUP_KINDS.has(message.kind);
    if (bound && !pinnedAllocationV11Schema.safeParse(message.allocation).success)
      throw new SandboxRelayDispatchValidationError("Pinned allocation is required.");
    if (
      launch &&
      (message.cpuCount !== message.allocation?.cpuCount ||
        message.memoryMiB !== message.allocation?.memoryMiB)
    )
      throw new SandboxRelayDispatchValidationError("Pinned allocation mismatch.");
    if (!bound && message.allocation !== undefined)
      throw new SandboxRelayDispatchValidationError("Unexpected allocation.");
    if (!launch && hasSize)
      throw new SandboxRelayDispatchValidationError("VM size is launch-only.");
    if (launch) {
      const size = {
        ...(message.cpuCount !== undefined ? { cpuCount: message.cpuCount } : {}),
        ...(message.memoryMiB !== undefined ? { memoryMiB: message.memoryMiB } : {}),
        diskGiB: message.allocation?.diskGiB,
      };
      if (hasSize && !vmSizeSchema.safeParse(size).success)
        throw new SandboxRelayDispatchValidationError("Invalid VM size.");
      launchVmSizeForVersion(size, protocolVersion);
    }
  }
  if (
    SERVER_IMAGE_MESSAGE_TYPES.has(message.type) &&
    !serverImageMessageSchema.safeParse(message).success
  )
    throw new SandboxRelayDispatchValidationError("Invalid image frame.");
  if (
    SERVER_DISK_MESSAGE_TYPES.has(message.type) &&
    !serverDiskMessageSchema.safeParse(message).success
  )
    throw new SandboxRelayDispatchValidationError("Invalid disk offload frame.");
  if (
    SERVER_CREDENTIAL_MESSAGE_TYPES.has(message.type) &&
    !serverCredentialMessageSchema.safeParse(message).success
  )
    throw new SandboxRelayDispatchValidationError("Invalid credential frame.");
  if (message.type === "operation.dispatch") {
    if (
      message.credentialSpec !== undefined &&
      (!CREDENTIAL_SPEC_DISPATCH_KINDS.has(message.kind) ||
        !credentialSpecRefV11Schema.safeParse(message.credentialSpec).success)
    )
      throw new SandboxRelayDispatchValidationError("Invalid credential spec reference.");
    if (
      message.credentialCapture !== undefined &&
      (message.credentialCapture !== "skip" || !CREDENTIAL_CAPTURE_DISPATCH_KINDS.has(message.kind))
    )
      throw new SandboxRelayDispatchValidationError("Invalid credential capture mode.");
    if (
      message.credentialTeardown !== undefined &&
      (!credentialTeardownOriginSchema.safeParse(message.credentialTeardown).success ||
        !CREDENTIAL_CAPTURE_DISPATCH_KINDS.has(message.kind))
    )
      throw new SandboxRelayDispatchValidationError("Invalid credential teardown origin.");
    if (!validDispatchImageFields(message))
      throw new SandboxRelayDispatchValidationError("Invalid image fetch plan.");
    if (!validDispatchDiskFields(message))
      throw new SandboxRelayDispatchValidationError("Invalid disk offload fields.");
    if (
      (message.kind === "sandbox.capture") !== (message.capture !== undefined) ||
      (message.capture !== undefined &&
        !dispatchCaptureV11Schema.safeParse(message.capture).success)
    )
      throw new SandboxRelayDispatchValidationError("Invalid capture body.");
    if (!validDispatchBuildFields(message))
      throw new SandboxRelayDispatchValidationError("Invalid build fields.");
    if (!validDispatchStartup(message))
      throw new SandboxRelayDispatchValidationError("Invalid startup field.");
    // One encoding per meaning (the daemon refuses `false`), launches only,
    // and guestSudo implies guestRoot (I1).
    if (
      ((message.guestSudo !== undefined || message.guestRoot !== undefined) &&
        message.kind !== "sandbox.create" &&
        message.kind !== "sandbox.reconnect") ||
      (message.guestSudo !== undefined && message.guestSudo !== true) ||
      (message.guestRoot !== undefined && message.guestRoot !== true) ||
      (message.guestSudo === true && message.guestRoot !== true) ||
      (message.guestSudo === true && message.build !== undefined)
    )
      throw new SandboxRelayDispatchValidationError("Invalid guest privilege fields.");
    if (
      (message.tunnelPorts === undefined) !== (message.tunnelPortsRevision === undefined) ||
      (message.tunnelPorts !== undefined &&
        ((message.kind !== "sandbox.create" && message.kind !== "sandbox.reconnect") ||
          !tunnelWireDeclaredPortsSchema.safeParse(message.tunnelPorts).success ||
          !Number.isSafeInteger(message.tunnelPortsRevision) ||
          (message.tunnelPortsRevision ?? -1) < 0))
    )
      throw new SandboxRelayDispatchValidationError("Invalid tunnel ports.");
    // E4-01: the daemon refuses a signal whose wire pid is not its qualified
    // target's pid; never send one (a deterministic, settled producer bug).
    if (
      message.kind === "process.signal"
        ? message.process !== undefined && message.pid !== message.process.pid
        : message.pid !== undefined
    )
      throw new SandboxRelayDispatchValidationError("Invalid process identity field.");
  }
  if (
    message.type === "private.config.install" &&
    !privateConfigInstallSchema.safeParse(message).success
  )
    throw new SandboxRelayDispatchValidationError("Invalid private config frame.");
  if (message.type === "tunnel.apply" && !tunnelApplyV11Schema.safeParse(message).success)
    throw new SandboxRelayDispatchValidationError("Invalid tunnel apply frame.");
  if (message.type === "tunnel.clear" && !tunnelClearV11Schema.safeParse(message).success)
    throw new SandboxRelayDispatchValidationError("Invalid tunnel clear frame.");
  if (message.type === "tunnel.ports" && !tunnelPortsV11Schema.safeParse(message).success)
    throw new SandboxRelayDispatchValidationError("Invalid tunnel ports frame.");
  if (message.type === "egress.blocklist" && !egressBlocklistV11Schema.safeParse(message).success)
    throw new SandboxRelayDispatchValidationError("Invalid egress blocklist frame.");
  if (message.type === "journal.key.install" && !journalKeyInstallSchema.safeParse(message).success)
    throw new SandboxRelayDispatchValidationError("Invalid journal key frame.");
  if (message.type === "host.quiesce.ack" && !hostQuiesceAckV11Schema.safeParse(message).success)
    throw new SandboxRelayDispatchValidationError("Invalid quiesce ACK frame.");
  if (
    (message.type.startsWith("terminal.") || message.type === "host.terminal-policy.raise") &&
    !serverTerminalMessageSchema.safeParse(message).success
  )
    throw new SandboxRelayDispatchValidationError("refusing terminal frame: invalid fence or size");
  if (message.type.startsWith("channel.") && !serverChannelMessageSchema.safeParse(message).success)
    throw new SandboxRelayDispatchValidationError("Invalid channel frame.");
  if (
    message.type === "operation.dispatch" &&
    !terminalIdSchema.safeParse(message.sandboxOwnerId).success
  )
    throw new SandboxRelayDispatchValidationError("Invalid workload identity.");
  if (
    message.type === "operation.dispatch" &&
    !canonicalBodyHashSchema.safeParse(message.bodyHash).success
  )
    throw new SandboxRelayDispatchValidationError(
      "refusing operation.dispatch: bodyHash must be a canonical lowercase SHA-256 hash",
    );
  if (
    message.type === "operation.dispatch" &&
    (message.kind === "sandbox.create" || message.kind === "sandbox.reconnect")
  ) {
    // VM launches always carry the recorded policy: a missing or malformed one
    // is a deterministic producer bug, never a retryable send.
    if (
      !isCanonicalEgressPolicyWire(message.egressPolicy) ||
      !canonicalBodyHashSchema.safeParse(message.egressPolicyHash).success
    ) {
      throw new SandboxRelayDispatchValidationError(
        "refusing operation.dispatch: VM launch requires the recorded egress policy and hash",
      );
    }
  }
  if (message.type === "operation.dispatch" && KEY_FREE_CLEANUP_KINDS.has(message.kind)) {
    if (
      message.privateConfig !== undefined ||
      message.env !== undefined ||
      message.argv !== undefined ||
      message.script !== undefined ||
      message.cwd !== undefined ||
      message.path !== undefined ||
      message.destPath !== undefined ||
      message.stdinSequence !== undefined ||
      message.timeoutMs !== undefined ||
      message.pid !== undefined ||
      message.signal !== undefined ||
      message.fileSize !== undefined ||
      message.fileSha256 !== undefined ||
      message.egressPolicy !== undefined ||
      message.egressPolicyHash !== undefined ||
      message.digestScheme === "hmac-sha256-v1" ||
      message.digestKeyId != null
    )
      throw new SandboxRelayDispatchValidationError("Invalid key-free cleanup frame.");
    // Only safe identity/lease fields cross the key-free boundary.
    message = {
      type: message.type,
      sandboxOwnerId: message.sandboxOwnerId,
      operationId: message.operationId,
      sandboxId: message.sandboxId,
      idempotencyKey: message.idempotencyKey,
      kind: message.kind,
      generation: message.generation,
      attempt: message.attempt,
      incusName: message.incusName,
      templateDigest: message.templateDigest,
      incusFingerprint: message.incusFingerprint,
      recursive: message.recursive,
      bodyHash: message.bodyHash,
      lease: message.lease,
      allocation: message.allocation,
      digestScheme: message.digestScheme,
      // Non-secret references: a stop/kill must keep its capture contract.
      ...(message.credentialSpec !== undefined ? { credentialSpec: message.credentialSpec } : {}),
      ...(message.credentialCapture !== undefined
        ? { credentialCapture: message.credentialCapture }
        : {}),
      ...(message.credentialTeardown !== undefined
        ? { credentialTeardown: message.credentialTeardown }
        : {}),
    };
  }
  if (
    message.type === "operation.dispatch" &&
    message.privateConfig !== undefined &&
    !privateConfigRefSchema.safeParse(message.privateConfig).success
  )
    throw new SandboxRelayDispatchValidationError("Invalid private config reference.");
  const encoded = JSON.stringify(message);
  if (Buffer.byteLength(encoded, "utf8") > SANDBOX_JSON_CONTROL_MAX_BYTES) {
    throw new SandboxRelayProtocolError("JSON control frame exceeds 64 KiB.");
  }
  return encoded;
}

export function parseDaemonControlFrame(
  frame: string,
  protocolVersion?: string,
): DaemonControlMessage {
  const bytes = checkDaemonControlFrameSize(Buffer.byteLength(frame, "utf8"), protocolVersion);
  let parsed: unknown;
  try {
    parsed = JSON.parse(frame);
  } catch (error) {
    if (bytes > SANDBOX_JSON_CONTROL_MAX_BYTES)
      throw new SandboxRelayProtocolError("JSON control frame exceeds 64 KiB.");
    throw error;
  }
  return validateDaemonControlMessage(parsed, bytes);
}

/**
 * {@link parseDaemonControlFrame} for a frame the caller already `JSON.parse`d
 * and sized (`Buffer.byteLength(frame, "utf8")`): the same checks in the same
 * order, without a second parse.
 */
export function parseParsedDaemonControlFrame(
  parsed: unknown,
  bytes: number,
  protocolVersion?: string,
): DaemonControlMessage {
  return validateDaemonControlMessage(parsed, checkDaemonControlFrameSize(bytes, protocolVersion));
}

function checkDaemonControlFrameSize(bytes: number, protocolVersion: string | undefined): number {
  if (protocolVersion !== undefined && !knownRelayProtocolVersion(protocolVersion))
    throw new SandboxRelayProtocolError("Unknown negotiated protocol version.");
  if (bytes > HOST_CONTROL_MAX_BYTES) {
    throw new SandboxRelayProtocolError("JSON control frame exceeds host bound.");
  }
  return bytes;
}

function validateDaemonControlMessage(parsed: unknown, bytes: number): DaemonControlMessage {
  const type = parsed && typeof parsed === "object" && "type" in parsed ? parsed.type : undefined;
  const hostAccess =
    typeof type === "string" && (type === "host.exec.status" || type === "host.file.result");
  if (bytes > SANDBOX_JSON_CONTROL_MAX_BYTES && !hostAccess)
    throw new SandboxRelayProtocolError("JSON control frame exceeds 64 KiB.");
  const message = daemonControlMessageSchema.parse(parsed);
  if (
    (message.type === "operation.result" || message.type === "operation.receipt") &&
    message.result?.version !== undefined &&
    !hostOperationResultSchema.safeParse(message.result).success
  )
    throw new SandboxRelayProtocolError("Invalid typed host result.");
  if (message.type === "operation.receipt" && bytes > RECEIPT_LIMITS.receiptBytes) {
    throw new SandboxRelayProtocolError("Receipt exceeds storage/replay bound.");
  }
  return message;
}

export function encodeBinaryFrame(metadata: StreamBinaryMetadata, body: Uint8Array): ArrayBuffer {
  if (body.byteLength > SANDBOX_BINARY_CHUNK_MAX_BYTES) {
    throw new SandboxRelayProtocolError("Binary body chunk exceeds 1 MiB.");
  }
  const metadataBytes = textEncoder.encode(JSON.stringify(metadata));
  if (metadataBytes.byteLength > SANDBOX_JSON_CONTROL_MAX_BYTES) {
    throw new SandboxRelayProtocolError("Binary frame metadata exceeds 64 KiB.");
  }
  const frame = new Uint8Array(4 + metadataBytes.byteLength + body.byteLength);
  new DataView(frame.buffer).setUint32(0, metadataBytes.byteLength, false);
  frame.set(metadataBytes, 4);
  frame.set(body, 4 + metadataBytes.byteLength);
  return frame.buffer;
}

export function parseBinaryFrame(frame: ArrayBuffer): {
  metadata: StreamBinaryMetadata;
  body: Uint8Array;
} {
  if (frame.byteLength < 4) {
    throw new SandboxRelayProtocolError("Binary frame is missing metadata length.");
  }
  const metadataLength = new DataView(frame).getUint32(0, false);
  if (metadataLength > SANDBOX_JSON_CONTROL_MAX_BYTES) {
    throw new SandboxRelayProtocolError("Binary frame metadata exceeds 64 KiB.");
  }
  const bodyLength = frame.byteLength - 4 - metadataLength;
  if (bodyLength < 0) {
    throw new SandboxRelayProtocolError("Binary frame metadata length is invalid.");
  }
  if (bodyLength > SANDBOX_BINARY_CHUNK_MAX_BYTES) {
    throw new SandboxRelayProtocolError("Binary body chunk exceeds 1 MiB.");
  }
  const metadataBytes = new Uint8Array(frame, 4, metadataLength);
  const metadataText = textDecoder.decode(metadataBytes);
  const metadata = streamBinaryMetadataSchema.parse(JSON.parse(metadataText));
  const body = new Uint8Array(frame, 4 + metadataLength, bodyLength);
  return { metadata, body };
}

const terminalDataMetadataSchema = z
  .object({
    type: z.literal("terminal.data"),
    fence: terminalFenceSchema,
    sequence: terminalSequenceSchema,
  })
  .strict();
export type TerminalDataMetadata = z.infer<typeof terminalDataMetadataSchema>;

export function encodeTerminalDataFrame(
  metadata: TerminalDataMetadata,
  body: Uint8Array,
): ArrayBuffer {
  if (body.byteLength === 0 || body.byteLength > TERMINAL_LIMITS.dataMaxBytes) {
    throw new SandboxRelayDispatchValidationError("Terminal data body is empty or oversized.");
  }
  const checked = terminalDataMetadataSchema.parse(metadata);
  const metadataBytes = textEncoder.encode(JSON.stringify(checked));
  const frame = new Uint8Array(4 + metadataBytes.byteLength + body.byteLength);
  new DataView(frame.buffer).setUint32(0, metadataBytes.byteLength, false);
  frame.set(metadataBytes, 4);
  frame.set(body, 4 + metadataBytes.byteLength);
  return frame.buffer;
}

/**
 * `null` when the binary frame is not a terminal frame (a command/file stream
 * frame). Otherwise the strictly parsed terminal frame; an empty or oversized
 * body, unknown field or invalid fence throws.
 */
export function parseTerminalDataFrame(
  frame: ArrayBuffer,
): { metadata: TerminalDataMetadata; body: Uint8Array } | null {
  if (frame.byteLength < 4) return null;
  const metadataLength = new DataView(frame).getUint32(0, false);
  if (metadataLength > SANDBOX_JSON_CONTROL_MAX_BYTES || 4 + metadataLength > frame.byteLength)
    return null;
  let raw: unknown;
  try {
    raw = JSON.parse(textDecoder.decode(new Uint8Array(frame, 4, metadataLength)));
  } catch {
    return null;
  }
  if (!raw || typeof raw !== "object" || (raw as { type?: unknown }).type !== "terminal.data")
    return null;
  const bodyLength = frame.byteLength - 4 - metadataLength;
  if (bodyLength === 0 || bodyLength > TERMINAL_LIMITS.dataMaxBytes) {
    throw new SandboxRelayProtocolError("Terminal data body is empty or oversized.");
  }
  return {
    metadata: terminalDataMetadataSchema.parse(raw),
    body: new Uint8Array(frame, 4 + metadataLength, bodyLength),
  };
}

const channelDataMetadataSchema = z.strictObject({
  type: z.literal("channel.data"),
  fence: channelFenceSchema,
  stream: channelStreamSchema,
  seq: terminalSequenceSchema,
});
export type ChannelDataMetadata = z.infer<typeof channelDataMetadataSchema>;

/** Body 1..=`bulkDataMaxBytes`; the 16 KiB PTY bound is the endpoints'. */
export function encodeChannelDataFrame(
  metadata: ChannelDataMetadata,
  body: Uint8Array,
): ArrayBuffer {
  if (body.byteLength === 0 || body.byteLength > CHANNEL_LIMITS.bulkDataMaxBytes) {
    throw new SandboxRelayDispatchValidationError("Channel data body is empty or oversized.");
  }
  const checked = channelDataMetadataSchema.parse(metadata);
  const metadataBytes = textEncoder.encode(JSON.stringify(checked));
  const frame = new Uint8Array(4 + metadataBytes.byteLength + body.byteLength);
  new DataView(frame.buffer).setUint32(0, metadataBytes.byteLength, false);
  frame.set(metadataBytes, 4);
  frame.set(body, 4 + metadataBytes.byteLength);
  return frame.buffer;
}

/**
 * `null` when the binary frame is not a channel frame (a command/file stream
 * or terminal frame). Otherwise the strictly parsed channel frame; an empty or
 * oversized body, unknown field or invalid fence throws.
 */
export function parseChannelDataFrame(
  frame: ArrayBuffer,
): { metadata: ChannelDataMetadata; body: Uint8Array } | null {
  if (frame.byteLength < 4) return null;
  const metadataLength = new DataView(frame).getUint32(0, false);
  if (metadataLength > SANDBOX_JSON_CONTROL_MAX_BYTES || 4 + metadataLength > frame.byteLength)
    return null;
  let raw: unknown;
  try {
    raw = JSON.parse(textDecoder.decode(new Uint8Array(frame, 4, metadataLength)));
  } catch {
    return null;
  }
  if (!raw || typeof raw !== "object" || (raw as { type?: unknown }).type !== "channel.data")
    return null;
  const bodyLength = frame.byteLength - 4 - metadataLength;
  if (bodyLength === 0 || bodyLength > CHANNEL_LIMITS.bulkDataMaxBytes) {
    throw new SandboxRelayProtocolError("Channel data body is empty or oversized.");
  }
  return {
    metadata: channelDataMetadataSchema.parse(raw),
    body: new Uint8Array(frame, 4 + metadataLength, bodyLength),
  };
}

/** Final command controls contain only bounded scalar metadata. */
export const commandResultMetadataSchema = z
  .object({
    exitCode: z.number().int().min(-2147483648).max(2147483647).nullable().optional(),
    pid: z.number().int().min(1).max(4294967295).nullable().optional(),
    outputBytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
  })
  .strict();

/** Integrated 1.0 transport and workload identities. Terminal target consumers
 * switch to the typed target fence in T1. */
export const transportBindingV11Schema = z.strictObject({
  server: z
    .string()
    .min(1)
    .refine((value) => Buffer.byteLength(value) <= 2048),
  hostOwnerId: terminalIdSchema,
  hostId: terminalIdSchema,
});
export const workloadBindingV11Schema = transportBindingV11Schema.extend({
  sandboxOwnerId: terminalIdSchema,
  sandboxId: terminalIdSchema,
  generation: admissionEpochSchema,
});
const terminalSizedV11 = {
  requestId: terminalIdSchema,
  fence: terminalFenceV11Schema,
  rows: terminalRowsSchema,
  cols: terminalColsSchema,
};
/** Strict integrated 1.0 terminal controls. */
export const terminalControlV11Schema = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("terminal.exit"),
    fence: terminalFenceV11Schema,
    reaped: z.boolean(),
    requestId: terminalIdSchema.optional(),
    exitCode: z.number().int().min(-2147483648).max(2147483647).optional(),
    intent: terminalCloseIntentSchema.optional(),
    error: protocolErrorDetailSchema.optional(),
  }),
  z
    .strictObject({
      type: z.literal("terminal.open"),
      ...terminalSizedV11,
      hostPolicy: z
        .strictObject({ policyRevision: policyRevisionV11Schema, proofRequired: z.boolean() })
        .optional(),
      cwd: terminalCwdSchema.optional(),
    })
    .refine((frame) => (frame.fence.target.kind === "host") === (frame.hostPolicy !== undefined))
    .refine((frame) => frame.fence.target.kind === "sandbox" || frame.cwd === undefined),
  z.strictObject({ type: z.literal("terminal.ready"), ...terminalSizedV11 }),
  z.strictObject({ type: z.literal("terminal.resize"), ...terminalSizedV11 }),
  z.strictObject({
    type: z.literal("terminal.ack"),
    fence: terminalFenceV11Schema,
    sequence: terminalSequenceSchema,
  }),
  z.strictObject({
    type: z.literal("terminal.data"),
    fence: terminalFenceV11Schema,
    sequence: terminalSequenceSchema,
  }),
  z.strictObject({
    type: z.literal("terminal.close"),
    requestId: terminalIdSchema,
    fence: terminalFenceV11Schema,
    intent: terminalCloseIntentSchema,
  }),
]);

const terminalDataMetadataV11Schema = z.strictObject({
  type: z.literal("terminal.data"),
  fence: terminalFenceV11Schema,
  sequence: terminalSequenceSchema,
});
export type TerminalDataMetadataV11 = z.infer<typeof terminalDataMetadataV11Schema>;
export function encodeTerminalDataFrameV11(
  metadata: TerminalDataMetadataV11,
  body: Uint8Array,
): Buffer {
  if (body.byteLength === 0 || body.byteLength > TERMINAL_LIMITS.dataMaxBytes)
    throw new Error("invalid terminal body");
  const bytes = Buffer.from(JSON.stringify(terminalDataMetadataV11Schema.parse(metadata)));
  if (bytes.byteLength > SANDBOX_JSON_CONTROL_MAX_BYTES)
    throw new Error("invalid terminal metadata");
  const frame = Buffer.alloc(4 + bytes.byteLength + body.byteLength);
  frame.writeUInt32BE(bytes.byteLength);
  bytes.copy(frame, 4);
  frame.set(body, 4 + bytes.byteLength);
  return frame;
}
export function parseTerminalDataFrameV11(frame: Uint8Array): {
  metadata: TerminalDataMetadataV11;
  body: Buffer;
} {
  const bytes = Buffer.from(frame);
  if (bytes.byteLength < 4) throw new Error("invalid terminal frame");
  const length = bytes.readUInt32BE();
  if (length > SANDBOX_JSON_CONTROL_MAX_BYTES || length + 4 >= bytes.byteLength)
    throw new Error("invalid terminal metadata");
  const metadata = terminalDataMetadataV11Schema.parse(
    JSON.parse(bytes.subarray(4, 4 + length).toString("utf8")),
  );
  const body = bytes.subarray(4 + length);
  encodeTerminalDataFrameV11(metadata, body);
  return { metadata, body };
}
