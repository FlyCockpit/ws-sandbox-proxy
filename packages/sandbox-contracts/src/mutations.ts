import { z } from "zod";
import { capacityWaitRequestSchema } from "./capacity-wait";
import { commandTimeoutZeroEnabled } from "./command-timeout-policy";
import {
  isoDateTimeSchema,
  OPERATION_OUTCOMES,
  OPERATION_STATES,
  resourceIdSchema,
  sandboxOffloadPolicySchema,
} from "./dto";
import { egressPolicyInputSchema } from "./egress";
import { commandPayloadBytes, defaultEnvSchema, envSchema } from "./env";
import { SDK_ERROR_CODES } from "./errors";
import { guestEntryPathSchema, guestFilePathSchema, guestPathSchema } from "./guest-path";
import { validScrubPath } from "./image-wire";
import { LEASE_FINITE_MAX_MS } from "./lease-limits";
import { isSafeMapText } from "./map-primitives";
import { metadataSchema } from "./metadata";
import { sandboxNameSchema } from "./sandbox-name";
import { templateSelectorSchema } from "./template-selector";
import { tunnelPortsSchema } from "./tunnels";
import { revisionSizeOverridesSchema, vmDiskGiBSchema, vmSizeOverridesSchema } from "./vm-size";

export const idempotencyKeySchema = z
  .string()
  .min(1)
  .max(128)
  // Every internal namespace (packages/api INTERNAL_IDEMPOTENCY_KEY_PREFIXES;
  // a parity test keeps them equal), so an SDK key never collides with one.
  .regex(
    /^(?!(?:lease-expire:|readiness-failed:|inventory-observed:|access-expire:|lease-policy:|tb:|teardown-retry:))[A-Za-z0-9._:-]+$/,
  );
const path = z.string().min(1).max(4096).regex(/^\//);
/**
 * Relative lease in milliseconds. `0` means no lease timer and is accepted only
 * where the effective policy allows it (`limits.sandboxTimeoutZero`, a pool's
 * `lease.timeoutZero`); positive values above the effective policy maximum
 * fail with `lease_exceeds_policy`, including any value above the finite
 * ceiling (`LEASE_FINITE_MAX_MS`, which no policy layer can exceed). The
 * schema therefore accepts every safe non-negative integer and leaves the
 * maximum to the typed policy check; non-integers and negatives stay
 * BAD_REQUEST.
 */
export const sandboxTimeoutSchema = z
  .number()
  .int()
  .min(0)
  .meta({
    description: `Relative lease in milliseconds; 0 means no lease timer where policy allows it. Finite leases are capped at 24 days (${LEASE_FINITE_MAX_MS} ms) by policy, or lower by the deployment, host or pool: a larger value fails with 400 \`lease_exceeds_policy\` carrying \`maxTimeoutMs\`.`,
  });

/** A well-formed lease timeout no policy can admit (`lease_exceeds_policy`). */
export function leaseTimeoutBeyondFiniteMax(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > LEASE_FINITE_MAX_MS;
}
export const lifecycleInputSchema = z
  .object({
    onTimeout: z.enum(["kill", "stop", "pause"]).optional().meta({ default: "kill" }),
    autoResume: z.boolean().optional().meta({ default: false }),
  })
  .strict();
// Reserved, deliberately unsupported until an ingress contract is implemented.
export const networkInputSchema = z
  .object({
    ingress: z.object({}).strict().optional(),
    /**
     * Preview tunnels: the guest ports that may ever be exposed (≤ 8, fixed
     * for the sandbox's life). Needs a configured tunnel server and a host
     * that runs the tunnel client; otherwise `UNSUPPORTED_CAPABILITY`.
     */
    tunnelPorts: tunnelPortsSchema.optional(),
  })
  .strict();
/**
 * UTF-8 budget of the serialized `{argv, script, cwd, env}` command payload,
 * enforced server-side (packages/config sandbox-command-limits.json).
 */
export const COMMAND_PAYLOAD_MAX_BYTES = 32768;
export const emptyBodySchema = z.object({}).strict();
/**
 * CLI logins to use (≤ 8, one per login). Naming an account or instance is a
 * one-shot placement hint for this create only; resume never re-applies it.
 */
export const sandboxCredentialRequestsSchema = z
  .array(
    z
      .object({
        credentialId: resourceIdSchema,
        accountId: resourceIdSchema.optional(),
        instanceId: resourceIdSchema.optional(),
      })
      .strict(),
  )
  .max(8)
  .refine(
    (rows) => new Set(rows.map((row) => row.credentialId)).size === rows.length,
    "Each login may be named once.",
  );
export const createSandboxBodySchema = z
  .object({
    template: templateSelectorSchema,
    /** Omitted: the server picks a free adjective-noun name. */
    name: sandboxNameSchema.optional(),
    ...vmSizeOverridesSchema.shape,
    sandboxHostId: resourceIdSchema.optional(),
    poolId: resourceIdSchema.optional(),
    expectedDisconnectGraceSeconds: z.number().int().min(0).max(2592000).optional(),
    envs: defaultEnvSchema.optional(),
    metadata: metadataSchema.optional(),
    /**
     * Immutable egress request (M5, C34). Omitting it requests open internet;
     * grants without `mode` are an allowlist (`inferEgressMode`). Unknown
     * fields, wildcards, URLs and IP literals in `domains` are rejected.
     */
    egress: egressPolicyInputSchema.optional(),
    timeoutMs: sandboxTimeoutSchema.optional().meta({ default: 300000 }),
    lifecycle: lifecycleInputSchema.optional(),
    network: networkInputSchema.optional(),
    waitForCapacityMs: capacityWaitRequestSchema.optional(),
    credentials: sandboxCredentialRequestsSchema.optional(),
    /**
     * Grant the guest user passwordless `sudo` inside the VM. Omitted means on.
     * On another user's node that does not allow it, the sandbox starts with
     * guestSudo off (`guestSudoReason`). Immutable after create.
     */
    guestSudo: z.boolean().optional(),
    /**
     * When this sandbox's disk is exported to the image store after a stop.
     * Omitted: `{mode: "on_stop"}`. Changeable later (`PUT /v1/sandboxes/{id}`
     * or the stop body).
     */
    offload: sandboxOffloadPolicySchema.optional(),
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
/**
 * Update (`PUT /v1/sandboxes/{id}`): rename and/or change the offload policy.
 * At least one field. Neither touches the VM.
 */
export const updateSandboxBodySchema = z
  .object({
    name: sandboxNameSchema.optional(),
    offload: sandboxOffloadPolicySchema.optional(),
  })
  .strict()
  .refine(
    (input) => input.name !== undefined || input.offload !== undefined,
    "Set name, offload or both.",
  )
  .meta({ anyOf: [{ required: ["name"] }, { required: ["offload"] }] });
export const reconnectBodySchema = z
  .object({
    mode: z.enum(["warm", "cold"]).optional(),
    timeoutMs: sandboxTimeoutSchema.optional().meta({ default: 300000 }),
    /**
     * CLI logins: resume pins for a cold start. A named account or instance
     * applies to this start only and disables fallback (`credential.in_use`,
     * `credential.account_paused`); omitted logins resume by the recorded
     * account and instance with fallback.
     */
    credentials: sandboxCredentialRequestsSchema.optional(),
    /**
     * Restore of an offloaded sandbox only (`OFFLOADED`): restore onto this
     * host, or through this pool, instead of the default order (the owner's
     * own hosts, then the sandbox's origin pool). At most one.
     */
    sandboxHostId: resourceIdSchema.optional(),
    poolId: resourceIdSchema.optional(),
    /**
     * Restore of an offloaded sandbox only: wait up to this long (bounded by
     * the deployment's capacity-wait maximum) for a host it may use to have
     * room, else fail `restore_no_allowed_host`. Omitted: fail at once.
     */
    waitForCapacityMs: capacityWaitRequestSchema.optional(),
  })
  .strict()
  .refine(
    (input) => input.poolId === undefined || input.sandboxHostId === undefined,
    "Choose at most one restore target.",
  );
/**
 * Stop and destroy: `credentialCapture: "skip"` tears down without copying the
 * guest's login files back (the vault keeps its previous value).
 */
export const teardownBodySchema = z
  .object({ credentialCapture: z.literal("skip").optional() })
  .strict();
/**
 * Stop: the teardown body plus `offload`, which sets the sandbox's offload
 * policy in the same transaction as the accepted stop (a replay of the same
 * key does not set it again). Use it to park a sandbox without exporting its
 * disk, for example `{offload: {mode: "on_pressure"}}`.
 */
export const stopBodySchema = z
  .object({
    credentialCapture: z.literal("skip").optional(),
    offload: sandboxOffloadPolicySchema.optional(),
  })
  .strict();
/** Live attach (READY) or record-only attach (STOPPED) of one login. */
export const attachCredentialBodySchema = z
  .object({
    credentialId: resourceIdSchema,
    accountId: resourceIdSchema.optional(),
    instanceId: resourceIdSchema.optional(),
  })
  .strict();
/**
 * Free one login: its env leaves new commands at once, every terminal opened
 * with it closes, and its files are copied back (unless `skip`) and scrubbed.
 */
export const freeCredentialBodySchema = z
  .object({ credentialCapture: z.literal("skip").optional() })
  .strict();
export const sandboxCredentialParamsSchema = z
  .object({ id: resourceIdSchema, credentialId: resourceIdSchema })
  .strict();
export const renewBodySchema = z.object({ timeoutMs: sandboxTimeoutSchema }).strict();
/** Most extra scrub paths one capture (or template recipe) may name. */
export const CAPTURE_EXTRA_SCRUB_PATHS_MAX = 16;
/**
 * Save a sandbox as a template revision. Over the SDK the capture may only
 * move `latest`; other tags need a browser session. `templateId` defaults to
 * the sandbox's own template. Extra scrub paths are absolute guest paths.
 */
export const captureBodySchema = z
  .object({
    templateId: resourceIdSchema.optional(),
    tag: z.literal("latest").optional(),
    scrubPaths: z
      .array(
        z
          .string()
          .refine(validScrubPath, "sandbox.capture_invalid")
          .describe("Absolute guest path; `*` matches within the last segment only."),
      )
      .max(CAPTURE_EXTRA_SCRUB_PATHS_MAX)
      .optional(),
    /**
     * The new revision's `defaultDiskGiB`. Its `minDiskGiB` is always the
     * sandbox's own disk (a root never shrinks), so capture a sandbox created
     * small to keep the template small. Omitted: the source revision's
     * default, at least the sandbox's disk.
     */
    defaultDiskGiB: vmDiskGiBSchema.optional(),
  })
  .strict();
/** Command duration only; observation and lease budgets stay strictly positive. */
export const commandTimeoutSchema = z
  .number()
  .int()
  .min(0)
  .max(1_800_000)
  .refine((value) => value !== 0 || commandTimeoutZeroEnabled, "sandbox.command_invalid")
  .describe(
    "Command timeout in milliseconds. 0 means no separate command timer, bounded by the sandbox lease and execution authority; accepted only when limits.commandTimeoutZero is true. Omission defaults to 120000; positive values are at most 1800000.",
  );
export const commandBodySchema = z
  .object({
    argv: z
      .array(
        z
          .string()
          .max(512)
          // Match the host's UTF-16 limit despite Zod 4.6's code-point bounds.
          .refine(
            (value) => value.length <= 512 && isSafeMapText(value),
            "sandbox.command_invalid",
          ),
      )
      .min(1)
      .max(256)
      .refine((argv) => argv[0] !== "", "sandbox.command_invalid")
      .meta({
        prefixItems: [{ type: "string", minLength: 1, maxLength: 512 }],
      })
      .optional(),
    script: z
      .string()
      .min(1)
      .max(32768)
      .refine(isSafeMapText, "sandbox.command_invalid")
      .optional(),
    startEvidence: z.literal("required").optional(),
    cwd: guestPathSchema.optional(),
    envs: envSchema.optional(),
    timeoutMs: commandTimeoutSchema.optional(),
  })
  .strict()
  .refine(
    (input) => (input.argv === undefined) !== (input.script === undefined),
    "Provide exactly one of argv or script.",
  )
  .refine(
    (input) => commandPayloadBytes(input) <= COMMAND_PAYLOAD_MAX_BYTES,
    "sandbox.command_too_large",
  )
  .meta({
    oneOf: [
      { required: ["argv"], not: { required: ["script"] } },
      { required: ["script"], not: { required: ["argv"] } },
    ],
    "x-wssp-maxCommandBytes": COMMAND_PAYLOAD_MAX_BYTES,
  });
/**
 * One stdin write, decoded at most 32 KiB. The same bound applies to the
 * browser `runCommand` initial stdin: stdin travels in the durable outbox
 * payload, never in an SQL byte column (C30).
 */
export const STDIN_CHUNK_MAX_BYTES = 32 * 1024;
export const stdinBase64Schema = z
  .string()
  .max(Math.ceil(STDIN_CHUNK_MAX_BYTES / 3) * 4)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
export const stdinBodySchema = z
  .object({
    contentBase64: stdinBase64Schema,
    eof: z.boolean().optional(),
  })
  .strict();
// File operations share the server's guest-path rule (TQ-N2, G4R1-1, G4R1-2).
export const statBodySchema = z.object({ path: guestPathSchema }).strict();
export const mkdirBodySchema = z.object({ path: guestEntryPathSchema }).strict();
/** A download captures file bytes through the guest file helper: its rules apply (E-28). */
export const downloadBodySchema = z.object({ path: guestFilePathSchema }).strict();
export const listBodySchema = statBodySchema.extend({
  depth: z.number().int().min(1).max(8).default(1),
  limit: z.number().int().min(1).max(100).default(100),
  cursor: resourceIdSchema.optional(),
});
export const removeBodySchema = mkdirBodySchema.extend({ recursive: z.boolean().optional() });
export const moveBodySchema = mkdirBodySchema.extend({ destPath: guestEntryPathSchema });
const templateDefinitionBodySchema = z
  .object({
    hostId: resourceIdSchema.optional(),
    poolId: resourceIdSchema.optional(),
    memberId: resourceIdSchema.optional(),
    /** `minDiskGiB` defaults to `defaultDiskGiB`; set it to the image's real root to allow smaller creates. */
    ...revisionSizeOverridesSchema.shape,
    slug: z
      .string()
      .min(1)
      .max(63)
      .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
    label: z.string().min(1).max(160),
    imageRef: z.string().min(2).max(128),
    envs: defaultEnvSchema.optional(),
    architecture: z.string().min(1).max(32).optional(),
    guestUid: z.number().int().min(1).max(65534).optional(),
    guestGid: z.number().int().min(1).max(65534).optional(),
    guestHome: path.optional(),
    guestShell: path.optional(),
    guestVersion: z.string().max(64).optional(),
  })
  .strict();
function validImageTarget(input: { hostId?: string; poolId?: string; memberId?: string }) {
  return input.hostId ? !input.poolId && !input.memberId : Boolean(input.poolId && input.memberId);
}
export const templateBodySchema = templateDefinitionBodySchema.refine(
  validImageTarget,
  "Choose one image verification target.",
);
export const appendTemplateRevisionBodySchema = templateDefinitionBodySchema
  .omit({
    slug: true,
    label: true,
  })
  .refine(validImageTarget, "Choose one image verification target.");
export const associateTemplateAvailabilityBodySchema = z
  .object({
    revisionId: resourceIdSchema,
    hostId: resourceIdSchema.optional(),
    poolId: resourceIdSchema.optional(),
    memberId: resourceIdSchema.optional(),
  })
  .strict()
  .refine(validImageTarget, "Choose one image verification target.");
export const mutationReceiptSchema = z
  .object({
    operationId: resourceIdSchema,
    state: z.enum(OPERATION_STATES),
    location: z.string().regex(/^\/v1\/operations\/[A-Za-z0-9_-]{1,64}$/),
  })
  .strict();
export const actionReceiptSchema = z
  .object({
    id: resourceIdSchema,
    kind: z.enum([
      "templates.create",
      "templates.append",
      "templates.associate",
      "sandboxes.probe",
      "commands.writeStdin",
      "operations.cancel",
    ]),
    state: z.enum(OPERATION_STATES),
    sandboxId: resourceIdSchema.nullable(),
    generation: z.number().int().nullable(),
    outcome: z.enum(OPERATION_OUTCOMES),
    errorCode: z.enum(SDK_ERROR_CODES).nullable(),
    targetOperationId: resourceIdSchema.nullable(),
    resourceId: resourceIdSchema.nullable(),
    observation: z.enum(["guest_ready", "stopped", "confirmed_absent", "unreachable"]).nullable(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
  })
  .strict();
