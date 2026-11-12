import type { SandboxOperationKind } from "@wssp/db";
import {
  capacityWaitRequestSchema,
  commandPayloadBytes,
  commandTimeoutSchema,
  cursorSchema,
  defaultEnvSchema,
  egressPolicyInputSchema,
  envSchema,
  guestEntryPathSchema,
  guestFilePathSchema,
  guestPathSchema,
  lifecycleInputSchema,
  metadataSchema,
  networkInputSchema,
  OPERATION_KINDS,
  OPERATION_STATES,
  OUTPUT_PAGE_MAX_BYTES,
  processRefSchema,
  processSignalSchema,
  resultListOptionsSchema,
  SANDBOX_OFFLOAD_PINS,
  sandboxCursorSchema,
  sandboxListFiltersSchema,
  sandboxNameSchema,
  sandboxTimeoutSchema,
  stdinBase64Schema,
  templateSelectorSchema,
  vmSizeOverridesSchema,
} from "@wssp/sandbox-contracts";

/** Sandbox name rules, for the dashboard's create and rename forms (R11). */
export { SANDBOX_NAME_MAX, sandboxNameSchema, VM_SIZE_LIMITS } from "@wssp/sandbox-contracts";
/** Recipe checks and egress presets (template builds), for the dashboard's build editor. */
export {
  compileDockerfile,
  EGRESS_PRESET_NAMES,
  parseRecipe,
  RECIPE_ERROR_CODES,
  RecipeError,
} from "@wssp/template-recipe";

import { z } from "zod";
import cleanupKinds from "../../../config/src/sandbox-key-free-cleanup.json";
import receiptLimits from "../../../config/src/sandbox-receipt-limits.json";
import { cursorPageInput } from "../lib/pagination";
import { entityId, resourceSlugSchema, shortText } from "../lib/schemas";
import {
  commandRunMode,
  SANDBOX_COMMAND_ARGV_MAX_COUNT,
  SANDBOX_COMMAND_ARGV_MAX_UTF16_UNITS,
  SANDBOX_COMMAND_PAYLOAD_MAX_BYTES,
} from "./command-payload";
import { isReservedInternalIdempotencyKey } from "./idempotency-key-reserved";

/** Adapters preserve the authenticated credential identity through every service call. */
export type SessionPrincipal = {
  readonly kind: "session";
  readonly ownerId: string;
  /**
   * Set only by wssp's own managed flows (never from a request): the CLI-login
   * flow acts on its CREDENTIAL_LOGIN sandbox through the shared services, and
   * the managed-sandbox policy admits that flow's lifecycle actions.
   */
  readonly flow?: "credentialLogin";
};
export type Principal =
  | SessionPrincipal
  | import("../lib/sdk-key-access").ServicePrincipal
  | import("../template-builds/principal").BuildPrincipal;

export {
  classifyKillOutcome,
  type EntryInfo,
  FS_PROCESS_LIMITS,
  OPERATION_ERROR_CODES,
  OPERATION_KINDS,
  OPERATION_STATES,
  type OperationErrorCode,
  OUTPUT_HEAD_BYTES,
  OUTPUT_PAGE_MAX_BYTES,
  OUTPUT_RETENTION_MS,
  OUTPUT_TAIL_BYTES,
  type ProcessInfo,
  type ProcessRef,
  processRefSchema,
  processSignalSchema,
  resultListOptionsSchema,
  TEMPLATE_BUILD_ERROR_CODES,
  TEMPLATE_BUILD_STATES,
  TEMPLATE_BUILD_TERMINAL_STATES,
  type TemplateBuildErrorCode,
  type TemplateBuildStateDto,
  TRANSFER_CHUNK_BYTES,
  TRANSFER_MAX_BYTES,
} from "@wssp/sandbox-contracts";

export function sessionPrincipal(ownerId: string): SessionPrincipal {
  return { kind: "session", ownerId };
}

export const listPageInput = cursorPageInput;
export type ListPageInput = z.infer<typeof listPageInput>;
export const listHostsInput = listPageInput.extend({ excludePoolId: entityId.optional() }).strict();
export type ListHostsInput = z.infer<typeof listHostsInput>;

/** `active`: every sandbox that is not DELETED (including stopped and failed ones). */
export const SANDBOX_LIST_STATUSES = ["active", "deleted", "all"] as const;
export const listSandboxesInput = cursorPageInput
  .extend({
    ...sandboxListFiltersSchema.shape,
    cursor: sandboxCursorSchema.optional(),
    status: z.enum(SANDBOX_LIST_STATUSES).optional(),
  })
  .strict();
export type ListSandboxesInput = z.infer<typeof listSandboxesInput>;

/**
 * Dashboard operation list filter (C48). `state` is either one exact
 * operation state or a group: `active` (still in flight, including
 * CANCEL_REQUESTED) or `settled` (every other state, UNKNOWN_OUTCOME included).
 */
export const OPERATION_LIST_STATE_GROUPS = ["active", "settled"] as const;
export const listOperationsInput = cursorPageInput.extend({
  sandboxId: entityId.optional(),
  kind: z.enum(OPERATION_KINDS).optional(),
  state: z.enum([...OPERATION_LIST_STATE_GROUPS, ...OPERATION_STATES]).optional(),
});
export type ListOperationsInput = z.infer<typeof listOperationsInput>;

const idempotencyKeyShape = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._:-]+$/)
  .refine((key) => new TextEncoder().encode(key).byteLength <= receiptLimits.idempotencyKeyBytes);
export const idempotencyKey = idempotencyKeyShape.refine(
  (key) => !isReservedInternalIdempotencyKey(key),
  "Reserved idempotency key namespace.",
);
/**
 * Template-build orchestrator keys (`tb:<buildId>:…`): never
 * accepted from a client. A service that parses its own input admits this
 * shape only for a build principal and only with its own build id prefix.
 */
export const buildIdempotencyKey = idempotencyKeyShape.refine(
  (key) => key.startsWith("tb:"),
  "Build orchestrator key required.",
);
export const sandboxIdInput = z.object({ id: entityId });
export type SandboxIdInput = z.infer<typeof sandboxIdInput>;

export const createSandboxInput = z
  .object({
    template: templateSelectorSchema,
    /** Omitted: a free adjective-noun name is generated. */
    name: sandboxNameSchema.optional(),
    ...vmSizeOverridesSchema.shape,
    sandboxHostId: entityId.optional(),
    poolId: entityId.optional(),
    expectedDisconnectGraceSeconds: z.number().int().min(0).max(2592000).optional(),
    envs: defaultEnvSchema.optional(),
    idempotencyKey,
    metadata: metadataSchema.optional(),
    /**
     * Immutable egress request (M5, C34); omitted requests open internet.
     * While a create waits for placement the recorded effective policy is
     * null, which reads as deny-all (fail-safe).
     */
    egress: egressPolicyInputSchema.optional(),
    timeoutMs: sandboxTimeoutSchema.optional().meta({ default: 300000 }),
    lifecycle: lifecycleInputSchema.optional(),
    network: networkInputSchema.optional(),
    /** Pool creates only: wait for capacity (FIFO); the lease starts at placement. */
    waitForCapacityMs: capacityWaitRequestSchema.optional(),
    /** CLI logins (≤ 8); account/instance are one-shot hints for this create. */
    credentials: z
      .array(
        z
          .object({
            credentialId: entityId,
            accountId: entityId.optional(),
            instanceId: entityId.optional(),
          })
          .strict(),
      )
      .max(8)
      .refine(
        (rows) => new Set(rows.map((row) => row.credentialId)).size === rows.length,
        "Each login may be named once.",
      )
      .optional(),
    /**
     * guestSudo (immutable). No schema default: the idempotency intent hashes
     * the input as sent, and the service resolves omitted to on for WORKLOAD.
     */
    guestSudo: z.boolean().optional(),
  })
  .strict()
  .refine(
    (input) => (input.poolId === undefined) !== (input.sandboxHostId === undefined),
    "Choose exactly one placement target.",
  )
  .meta({
    oneOf: [
      { required: ["poolId"], not: { required: ["sandboxHostId"] } },
      { required: ["sandboxHostId"], not: { required: ["poolId"] } },
    ],
  });
export type CreateSandboxInput = z.infer<typeof createSandboxInput>;

/** CLI logins (§10.3, M8): stop/kill without capturing login values. */
const credentialCaptureMode = z.literal("skip").optional();

export const killSandboxInput = sandboxIdInput.extend({
  idempotencyKey,
  credentialCapture: credentialCaptureMode,
});
export type KillSandboxInput = z.infer<typeof killSandboxInput>;

/** PLAN shared command timeout: default 120s, maximum 1800s. */
export const SANDBOX_COMMAND_TIMEOUT_DEFAULT_MS = 120_000;
export const SANDBOX_COMMAND_TIMEOUT_MAX_MS = 1_800_000;

/** Stored values must retain their meaning, including explicit zero. */
export class CommandTimeoutValidationError extends Error {
  constructor() {
    super("Invalid stored command timeout.");
  }
}
export type CommandTimeout = { kind: "deadline"; ms: number } | { kind: "none" };
export function effectiveCommandTimeoutMs(timeoutMs: unknown): CommandTimeout {
  if (timeoutMs === undefined) return { kind: "deadline", ms: SANDBOX_COMMAND_TIMEOUT_DEFAULT_MS };
  if (
    typeof timeoutMs !== "number" ||
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 0 ||
    timeoutMs > SANDBOX_COMMAND_TIMEOUT_MAX_MS
  )
    throw new CommandTimeoutValidationError();
  return timeoutMs === 0 ? { kind: "none" } : { kind: "deadline", ms: timeoutMs };
}
export function encodeCommandTimeoutMs(timeout: CommandTimeout): number {
  return timeout.kind === "none" ? 0 : timeout.ms;
}

const hostString = (label: string) =>
  z
    .string()
    .refine((value) => !value.includes("\0"), { message: `${label} must not contain NUL.` })
    // A Unicode iterator combines valid pairs; a remaining surrogate is lone.
    .refine(
      (value) =>
        Array.from(value).every((char) => {
          const point = char.codePointAt(0)!;
          return point < 0xd800 || point > 0xdfff;
        }),
      { message: `${label} must not contain unpaired UTF-16 surrogates.` },
    );

// One guest-path rule for the server and the SDK (TQ-N2, E-28).
const guestPathInput = guestPathSchema;

const runCommandInputFor = <K extends z.ZodType<string>>(key: K) =>
  sandboxIdInput
    .extend({
      idempotencyKey: key,
      argv: z
        .array(
          hostString("Argv element")
            .max(SANDBOX_COMMAND_ARGV_MAX_UTF16_UNITS)
            // Zod 4.6 counts code points; the relay contract counts UTF-16 units.
            .refine((value) => value.length <= SANDBOX_COMMAND_ARGV_MAX_UTF16_UNITS, {
              message: "sandbox.command_invalid",
            }),
        )
        .min(1)
        .max(SANDBOX_COMMAND_ARGV_MAX_COUNT)
        .optional(),
      script: hostString("Script").min(1).max(SANDBOX_COMMAND_PAYLOAD_MAX_BYTES).optional(),
      cwd: guestPathInput.optional(),
      timeoutMs: commandTimeoutSchema.default(SANDBOX_COMMAND_TIMEOUT_DEFAULT_MS),
      startEvidence: z.literal("required").optional(),
      envs: envSchema.optional(),
      stdinBase64: stdinBase64Schema.optional(),
    })
    .strict()
    .superRefine((input, ctx) => {
      const mode = commandRunMode({
        argv: input.argv,
        script: input.script,
        cwd: input.cwd,
      });
      if (mode === "invalid") {
        ctx.addIssue({
          code: "custom",
          message: "Provide exactly one of argv or script.",
          path: ["argv"],
        });
        return;
      }
      if (commandPayloadBytes(input) > SANDBOX_COMMAND_PAYLOAD_MAX_BYTES) {
        ctx.addIssue({
          code: "custom",
          message: `Serialized command payload exceeds ${SANDBOX_COMMAND_PAYLOAD_MAX_BYTES} bytes.`,
          path: [mode === "script" ? "script" : "argv"],
        });
      }
    });
export const runCommandInput = runCommandInputFor(idempotencyKey);
/** The orchestrator's build step input: a `tb:` key, the rest unchanged. */
export const buildRunCommandInput = runCommandInputFor(buildIdempotencyKey);
export type RunCommandInput = z.infer<typeof runCommandInput>;

export const readFileInput = sandboxIdInput.extend({
  idempotencyKey,
  // A download moves bytes through the guest file helper: its rules apply.
  path: guestFilePathSchema,
});
export type ReadFileInput = z.infer<typeof readFileInput>;

export const operationIdInput = z.object({ operationId: entityId });
export type OperationIdInput = z.infer<typeof operationIdInput>;

/** Incremental command-output page request; `cursor` comes from `nextCursor`. */
export const commandOutputInput = operationIdInput.extend({
  cursor: cursorSchema.optional(),
  maxBytes: z.number().int().min(1).max(OUTPUT_PAGE_MAX_BYTES).optional(),
});
export type CommandOutputInput = z.infer<typeof commandOutputInput>;

/** One login of a create, a resume pin or a live attach (one-shot account/instance hint). */
const credentialRequest = z
  .object({
    credentialId: entityId,
    accountId: entityId.optional(),
    instanceId: entityId.optional(),
  })
  .strict();

export const reconnectSandboxInput = sandboxIdInput
  .extend({
    mode: z.enum(["warm", "cold"]).optional(),
    idempotencyKey,
    timeoutMs: sandboxTimeoutSchema.optional().meta({ default: 300000 }),
    /** CLI logins: resume pins for a cold start (§7.2 rule 4; no fallback). */
    credentials: z
      .array(credentialRequest)
      .max(8)
      .refine(
        (rows) => new Set(rows.map((row) => row.credentialId)).size === rows.length,
        "Each login may be named once.",
      )
      .optional(),
    /** Restore of an OFFLOADED sandbox (§8.3a): the target hint and wait. */
    sandboxHostId: entityId.optional(),
    poolId: entityId.optional(),
    waitForCapacityMs: capacityWaitRequestSchema.optional(),
    /**
     * Dashboard only (§5a): restore outside the creating SDK key's
     * allowlists; that key then loses use of the sandbox. The /v1 body
     * schema has no such field, and the service refuses it for any SDK
     * principal (`forbidden`).
     */
    overrideCreatorAllowlist: z.boolean().optional(),
  })
  .strict()
  .refine(
    (input) => input.poolId === undefined || input.sandboxHostId === undefined,
    "Choose at most one restore target.",
  );

/** CLI logins (§10.1): live attach on READY, record-only attach on STOPPED. */
export const attachSandboxCredentialInput = sandboxIdInput
  .extend({ idempotencyKey })
  .extend(credentialRequest.shape)
  .strict();
export type AttachSandboxCredentialInput = z.infer<typeof attachSandboxCredentialInput>;

/** CLI logins (§10.1, §10.3): free one login; `skip` frees without copy-back. */
export const freeSandboxCredentialInput = sandboxIdInput
  .extend({ idempotencyKey, credentialId: entityId, credentialCapture: credentialCaptureMode })
  .strict();
export type FreeSandboxCredentialInput = z.infer<typeof freeSandboxCredentialInput>;

export type ReconnectSandboxInput = z.infer<typeof reconnectSandboxInput>;

export const stopSandboxInput = sandboxIdInput.extend({
  idempotencyKey,
  credentialCapture: credentialCaptureMode,
});
export type StopSandboxInput = z.infer<typeof stopSandboxInput>;

export const listDirInput = sandboxIdInput.extend({
  idempotencyKey,
  path: guestPathInput,
  depth: z.number().int().min(1).max(8).default(1),
  ...resultListOptionsSchema.shape,
});
export type ListDirInput = z.infer<typeof listDirInput>;

export const statPathInput = sandboxIdInput.extend({ idempotencyKey, path: guestPathInput });
export type StatPathInput = z.infer<typeof statPathInput>;

// The host refuses `/` as a mutation target (G4R1-2).
export const mkdirInput = sandboxIdInput.extend({ idempotencyKey, path: guestEntryPathSchema });
export type MkdirInput = z.infer<typeof mkdirInput>;

export const removePathInput = sandboxIdInput.extend({
  idempotencyKey,
  path: guestEntryPathSchema,
  recursive: z.boolean().optional(),
});
export type RemovePathInput = z.infer<typeof removePathInput>;

export const movePathInput = sandboxIdInput.extend({
  idempotencyKey,
  path: guestEntryPathSchema,
  destPath: guestEntryPathSchema,
});
export type MovePathInput = z.infer<typeof movePathInput>;

const snapshotNameInput = z
  .string()
  .trim()
  .min(1)
  .max(63)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/);

export const createSnapshotInput = sandboxIdInput.extend({
  idempotencyKey,
  snapshotName: snapshotNameInput,
});
export type CreateSnapshotInput = z.infer<typeof createSnapshotInput>;

export const restoreSnapshotInput = sandboxIdInput.extend({
  idempotencyKey,
  snapshotName: snapshotNameInput,
});
export type RestoreSnapshotInput = z.infer<typeof restoreSnapshotInput>;

export const forkSandboxInput = sandboxIdInput.extend({ idempotencyKey });
export type ForkSandboxInput = z.infer<typeof forkSandboxInput>;

export const listProcessesInput = sandboxIdInput.extend({
  idempotencyKey,
  ...resultListOptionsSchema.shape,
});
export type ListProcessesInput = z.infer<typeof listProcessesInput>;

export const connectProcessInput = z.object({ process: processRefSchema }).strict();
export const killProcessInput = connectProcessInput.extend({ idempotencyKey });
export const sendProcessStdinInput = killProcessInput
  .extend({
    contentBase64: stdinBase64Schema,
    eof: z.boolean().optional(),
  })
  .strict();
export const signalProcessInput = killProcessInput.extend({ signal: processSignalSchema }).strict();
export type SignalProcessInput = z.infer<typeof signalProcessInput>;

export const writeStdinInput = z
  .object({
    operationId: entityId,
    idempotencyKey: idempotencyKey.optional(),
    contentBase64: stdinBase64Schema,
    eof: z.boolean().optional(),
  })
  .refine((input) => input.contentBase64 !== "" || input.eof === true, {
    path: ["contentBase64"],
    message: "Empty stdin requires EOF.",
  });
export type WriteStdinInput = z.infer<typeof writeStdinInput>;

export const setSandboxTimeoutInput = sandboxIdInput
  .extend({
    idempotencyKey,
    timeoutMs: sandboxTimeoutSchema,
  })
  .strict();
export type SetSandboxTimeoutInput = z.infer<typeof setSandboxTimeoutInput>;

/** Rename: not an operation, so no idempotency key. */
/** `name` is checked by the service (`sandbox.name_invalid`), not the input schema. */
export const renameSandboxInput = sandboxIdInput.extend({ name: z.string().max(256) }).strict();
export type RenameSandboxInput = z.infer<typeof renameSandboxInput>;

/** Dashboard only: keep a stored disk off other users' hosts. */
export const setSandboxOffloadPinInput = sandboxIdInput
  .extend({ offloadPin: z.enum(SANDBOX_OFFLOAD_PINS) })
  .strict();
export type SetSandboxOffloadPinInput = z.infer<typeof setSandboxOffloadPinInput>;

export type CancelOperationInput = OperationIdInput;

export const createHostInput = z.object({
  slug: resourceSlugSchema,
  label: shortText.max(160),
});
export type CreateHostInput = z.infer<typeof createHostInput>;

export const hostIdInput = z.object({ id: entityId });
export type HostIdInput = z.infer<typeof hostIdInput>;

export const setHostDrainingInput = hostIdInput
  .extend({
    id: entityId.regex(/^[A-Za-z0-9_-]+$/),
    draining: z.boolean(),
    /** C7 (`wssp drain --offload`): while draining, offload
     * stopped sandboxes here and evict their cached copies when an eligible
     * restore host exists. Ignored (cleared) by undrain. */
    offload: z.boolean().optional(),
  })
  .strict();
export type SetHostDrainingInput = z.infer<typeof setHostDrainingInput>;

export const updateHostInput = hostIdInput.extend({
  label: shortText.max(160).optional(),
});
export type UpdateHostInput = z.infer<typeof updateHostInput>;

/** Cursor-paged, newest first; revoked credentials only on request. */
export const listHostTokensInput = cursorPageInput.extend({
  hostId: entityId.optional(),
  includeRevoked: z.boolean().default(false),
});
export type ListHostTokensInput = z.infer<typeof listHostTokensInput>;

export type ListDeviceCredentialsInput = z.infer<typeof listHostTokensInput>;

export const revokeDeviceCredentialInput = z.object({ id: entityId });
export type RevokeDeviceCredentialInput = z.infer<typeof revokeDeviceCredentialInput>;

export const createHostTokenInput = z.object({
  hostId: entityId,
  name: shortText.max(120),
  expiresAt: z.coerce.date().nullable().optional(),
});
export type CreateHostTokenInput = z.infer<typeof createHostTokenInput>;

export const revokeHostTokenInput = z.object({ id: entityId });
export type RevokeHostTokenInput = z.infer<typeof revokeHostTokenInput>;

export {
  type CreateTemplateInput,
  createTemplateInput,
  type ListTemplatesInput,
  listTemplatesInput,
  type TemplateIdInput,
  templateIdInput,
} from "./template-input";

export type DispatchableOperationKind =
  | "CREATE_SANDBOX"
  | "RENEW_SANDBOX_LEASE"
  | "KILL_SANDBOX"
  | "RUN_COMMAND"
  | "GET_FILE"
  | "PUT_FILE"
  | "RECONNECT_SANDBOX"
  | "STOP_SANDBOX"
  | "LIST_DIR"
  | "STAT_PATH"
  | "MKDIR"
  | "REMOVE_PATH"
  | "MOVE_PATH"
  | "LIST_PROCESSES"
  | "SIGNAL_PROCESS"
  | "CAPTURE_TEMPLATE"
  | "CREDENTIAL_ATTACH"
  | "CREDENTIAL_FREE";

export const OPERATION_DISPATCH_KIND = {
  CREATE_SANDBOX: "sandbox.create",
  RENEW_SANDBOX_LEASE: "sandbox.lease.renew",
  KILL_SANDBOX: "sandbox.kill",
  RUN_COMMAND: "command.run",
  GET_FILE: "file.get",
  PUT_FILE: "file.put",
  RECONNECT_SANDBOX: "sandbox.reconnect",
  STOP_SANDBOX: "sandbox.stop",
  LIST_DIR: "file.list",
  STAT_PATH: "file.stat",
  MKDIR: "file.mkdir",
  REMOVE_PATH: "file.remove",
  MOVE_PATH: "file.move",
  LIST_PROCESSES: "process.list",
  SIGNAL_PROCESS: "process.signal",
  CAPTURE_TEMPLATE: "sandbox.capture",
  CREDENTIAL_ATTACH: "credential.attach",
  CREDENTIAL_FREE: "credential.free",
} as const satisfies Record<DispatchableOperationKind, string>;

export function relayDispatchKind(
  kind: SandboxOperationKind,
): (typeof OPERATION_DISPATCH_KIND)[DispatchableOperationKind] | undefined {
  return OPERATION_DISPATCH_KIND[kind as DispatchableOperationKind];
}

/** Relay kinds that may be sent to a host. Snapshot/restore/fork are not in this set. */
export const ALLOWED_RELAY_DISPATCH_KINDS: ReadonlySet<string> = new Set([
  ...Object.values(OPERATION_DISPATCH_KIND),
  "process.stdin",
  "operation.cancel",
]);

export const UNSUPPORTED_RELAY_DISPATCH_KINDS: ReadonlySet<string> = new Set([
  "snapshot.create",
  "snapshot.restore",
  "sandbox.fork",
]);

/** Exact system/key-free cleanup kinds, shared with the host protocol. */
export const KEY_FREE_CLEANUP_KINDS: ReadonlySet<string> = new Set(cleanupKinds);

/** Private immutable accept attribution, never part of a host wire DTO. */
export type AuthorizingPrincipal =
  | { kind: "sdkKey"; keyId: string }
  | { kind: "session" }
  | { kind: "system" }
  /** Template-build work: the build fact, plus the real accepting key (null
   * for session/system builds). Decoded strictly (exactly these keys). */
  | { kind: "build"; buildId: string; keyId: string | null };
