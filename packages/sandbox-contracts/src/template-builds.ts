import { z } from "zod";
import { capacityWaitRequestSchema } from "./capacity-wait";
import {
  cursorSchema,
  isoDateTimeSchema,
  OPERATION_WAIT_MAX_MS,
  operationWaitMsQuerySchema,
  PAGE_SIZE_MAX,
  pageLimitQuerySchema,
  resourceIdSchema,
  SANDBOX_EGRESS_MODE_REASONS,
  templateSchema,
} from "./dto";
import { emptyBodySchema } from "./mutations";
import { commandOutputPageSchema, outputMaxBytesQuerySchema } from "./output";
import type { SdkRoute } from "./routes";
import { TRANSFER_CHUNK_BYTES, TRANSFER_MAX_BYTES } from "./transfers";
import { vmDiskGiBSchema, vmSizeOverridesSchema } from "./vm-size";

/**
 * Template builds (`/v1/template-builds`): a recipe (canonical JSON or a
 * Dockerfile subset) is run in a managed build VM and captured as a new
 * revision of the target template. Scope `templates:build`; creating the
 * target template by slug also needs `templates:write`.
 */

export const TEMPLATE_BUILD_STATES = [
  "AWAITING_CONTEXT",
  "QUEUED",
  "PLACING",
  "RUNNING",
  "STOPPING",
  "CAPTURING",
  "CANCELLING",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
] as const;
export type TemplateBuildStateDto = (typeof TEMPLATE_BUILD_STATES)[number];
/** States after which a build never changes again (cleanup may still run). */
export const TEMPLATE_BUILD_TERMINAL_STATES = ["SUCCEEDED", "FAILED", "CANCELLED"] as const;

/** Why a build failed (`errorCode`); `errorDetail` carries the typed cause. */
export const TEMPLATE_BUILD_ERROR_CODES = [
  "build_step_failed",
  "build_step_unknown",
  "build_step_timeout",
  "build_step_host_disconnected",
  "build_timeout",
  "build_context_timeout",
  "build_context_mismatch",
  "build_context_expired",
  "build_context_failed",
  "build_placement_failed",
  "build_capture_failed",
  "build_capture_lease_expired",
  "build_store_failed",
  "build_authority_lost",
  "build_host_lost",
  "build_internal",
  "build_cancelled",
  /** Community base: the verify VM's smoke failed, timed out or could not run. */
  "build_verify_failed",
  /** Community base: the pinned upstream image is gone from the index host. */
  "build_upstream_unavailable",
] as const;
export type TemplateBuildErrorCode = (typeof TEMPLATE_BUILD_ERROR_CODES)[number];

const buildIdSchema = resourceIdSchema;
const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);

/** One executed step: a WORKDIR prelude, a RUN or a COPY (ENV/ARG/USER fold into state). */
export const templateBuildStepSchema = z
  .object({
    /** Position in the executed step list (the `step` logs parameter). */
    n: z.number().int().min(0).max(255),
    /** Index of the recipe step this executes. */
    stepIndex: z.number().int().min(0),
    kind: z.enum(["prelude", "run", "copy"]),
    state: z.enum(["pending", "running", "succeeded", "failed"]),
    /** The step's command operation once issued. */
    operationId: resourceIdSchema.nullable(),
    exitCode: z.number().int().nullable(),
  })
  .strict();
export type TemplateBuildStepDto = z.infer<typeof templateBuildStepSchema>;

export const templateBuildSchema = z
  .object({
    id: buildIdSchema,
    templateId: resourceIdSchema,
    tag: z.string(),
    /** Who accepted the build: a browser session, an SDK key, or wssp itself (rebuild). */
    acceptedBy: z.enum(["session", "sdkKey", "system"]),
    state: z.enum(TEMPLATE_BUILD_STATES),
    /**
     * Fine-grained progress; null when terminal. One of awaiting_context,
     * queued, placing, waiting_for_capacity (a pool create queued for
     * capacity), context_import, context_commit, step (running
     * `steps[stepIndex]`), lease (re-anchoring the VM lease before stop),
     * stopping, capturing, capture_waiting_capacity (the capture waits for
     * disk or memory on the builder), storing.
     */
    phase: z.string().max(64).nullable(),
    /** Current executed step (`steps[n]`), -1 before the first. */
    stepIndex: z.number().int().min(-1),
    steps: z.array(templateBuildStepSchema).max(256),
    recipeDigest: sha256Schema,
    buildDigest: sha256Schema,
    contextSha256: sha256Schema.nullable(),
    contextBytes: z.number().int().positive().nullable(),
    timeoutMinutes: z.number().int().min(1),
    reservedMinutes: z.number().int().min(0),
    chargedMinutes: z.number().int().min(0).nullable(),
    /** The revision this build captured. */
    revisionId: resourceIdSchema.nullable(),
    /** An earlier identical build's revision (no VM ran). */
    cacheHitRevisionId: resourceIdSchema.nullable(),
    errorCode: z.enum(TEMPLATE_BUILD_ERROR_CODES).nullable(),
    /** Typed cause behind `errorCode` (code-shaped, never message text). */
    errorDetail: z.string().max(64).nullable(),
    failureStepIndex: z.number().int().min(0).nullable(),
    failureExitCode: z.number().int().nullable(),
    cancelRequestedAt: isoDateTimeSchema.nullable(),
    /** DONE once the build VM is gone and no staged context remains. */
    cleanupState: z.enum(["PENDING", "DONE"]),
    /**
     * Why the build VM ran with the allowlist although open egress was
     * requested (`node_policy`: a foreign builder that does not allow open
     * internet for others; `host_unsupported`). Projected from the build VM's
     * sandbox row, the only store of effective egress; null otherwise.
     */
    egressModeReason: z.enum(SANDBOX_EGRESS_MODE_REASONS).nullable(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    completedAt: isoDateTimeSchema.nullable(),
  })
  .strict();
export type TemplateBuildDto = z.infer<typeof templateBuildSchema>;

export const templateBuildPageSchema = z
  .object({
    items: z.array(templateBuildSchema).max(PAGE_SIZE_MAX),
    nextCursor: cursorSchema.nullable(),
  })
  .strict();

/** The staged build-context upload of a COPY build (before any VM exists). */
export const templateBuildContextSchema = z
  .object({
    buildId: buildIdSchema,
    state: z.enum(["OPEN", "SEALED", "ADOPTED", "ABORTED", "EXPIRED"]),
    totalBytes: z.number().int().positive().max(TRANSFER_MAX_BYTES),
    receivedBytes: z.number().int().min(0),
    chunkBytes: z.literal(TRANSFER_CHUNK_BYTES),
    /** OPEN only: the next chunk must arrive before this. */
    idleExpiresAt: isoDateTimeSchema.nullable(),
    expiresAt: isoDateTimeSchema,
    errorCode: z.enum(TEMPLATE_BUILD_ERROR_CODES).nullable(),
  })
  .strict();
export type TemplateBuildContextDto = z.infer<typeof templateBuildContextSchema>;

const BUILD_ARGS_MAX = 64;
/** The create fields without the cross-field rules (the browser plane extends them). */
export const templateBuildCreateFieldsSchema = z
  .object({
    /** Target template: an existing id, or a slug (created when missing; needs `templates:write`). */
    template: z.union([
      z.object({ id: resourceIdSchema }).strict(),
      z
        .object({
          slug: z
            .string()
            .min(1)
            .max(63)
            .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
        })
        .strict(),
    ]),
    /** SDK keys may move only `latest`. */
    tag: z.literal("latest").optional(),
    /** Canonical recipe (`version: 1`); exactly one of `recipe` and `dockerfile`. */
    recipe: z.record(z.string(), z.unknown()).optional(),
    /** Dockerfile subset (65536 bytes at most). */
    dockerfile: z.string().min(1).max(65536).optional(),
    buildArgs: z
      .record(z.string().min(1).max(128), z.string().max(4096))
      .refine((args) => Object.keys(args).length <= BUILD_ARGS_MAX, "Too many build args.")
      .optional(),
    poolId: resourceIdSchema.optional(),
    sandboxHostId: resourceIdSchema.optional(),
    /**
     * Build VM size; overrides the recipe's resources, which override the
     * base. The build VM's `diskGiB` becomes the revision's `minDiskGiB`
     * (default: the base's `minDiskGiB` + 2 GiB).
     */
    ...vmSizeOverridesSchema.shape,
    /** The revision's `defaultDiskGiB` (default: the base's default, at least the build disk). */
    defaultDiskGiB: vmDiskGiBSchema.optional(),
    /** Step time budget; capture time is not counted. Default min(30, maxMinutes). */
    timeoutMinutes: z.number().int().min(1).max(1440).optional(),
    waitForCapacityMs: capacityWaitRequestSchema.optional(),
    /** Required exactly when the recipe has a COPY step: the context tar's SHA-256 and size. */
    contextSha256: sha256Schema.optional(),
    contextBytes: z.number().int().min(1).max(TRANSFER_MAX_BYTES).optional(),
    /** Never reuse or join an identical build. */
    noCache: z.boolean().optional(),
  })
  .strict();
/** Exactly one recipe source and exactly one placement target. */
export function validTemplateBuildCreate(input: {
  recipe?: unknown;
  dockerfile?: unknown;
  poolId?: unknown;
  sandboxHostId?: unknown;
}): boolean {
  return (
    (input.recipe === undefined) !== (input.dockerfile === undefined) &&
    (input.poolId === undefined) !== (input.sandboxHostId === undefined)
  );
}
export const templateBuildCreateBodySchema = templateBuildCreateFieldsSchema
  .refine(
    (input) => (input.recipe === undefined) !== (input.dockerfile === undefined),
    "Send exactly one of recipe and dockerfile.",
  )
  .refine(
    (input) => (input.poolId === undefined) !== (input.sandboxHostId === undefined),
    "Choose exactly one placement target.",
  );
export type TemplateBuildCreateBody = z.input<typeof templateBuildCreateBodySchema>;

export const templateBuildCreatedSchema = z
  .object({
    build: templateBuildSchema,
    /** An identical active build was joined; a join never gets the upload handle. */
    joined: z.boolean(),
    /** An earlier identical build's revision was reused; nothing runs. */
    cacheHit: z.boolean(),
    /** The context upload of a COPY build this request accepted; else null. */
    contextUpload: templateBuildContextSchema.nullable(),
  })
  .strict();
export type TemplateBuildCreatedDto = z.infer<typeof templateBuildCreatedSchema>;

/**
 * `POST /v1/templates/community` (community-base S11): create the owner's
 * wssp-managed template for one tested catalog entry and its first prep
 * build. Scopes `templates:write` + `templates:build`; allowlist keys are
 * refused (403 `template.community_key_scope`). Idempotent.
 */
export const communityTemplateCreateBodySchema = z
  .object({
    /** A tested community catalog id, for example `ubuntu-26.04`. */
    source: z.string().min(1).max(64),
    poolId: resourceIdSchema.optional(),
    sandboxHostId: resourceIdSchema.optional(),
    /** Display label; defaults to the catalog label. */
    label: z.string().trim().min(1).max(100).optional(),
  })
  .strict()
  .refine(
    (input) => (input.poolId === undefined) !== (input.sandboxHostId === undefined),
    "Choose exactly one placement target.",
  );
export type CommunityTemplateCreateBody = z.input<typeof communityTemplateCreateBodySchema>;

export const communityTemplateCreatedSchema = z
  .object({
    template: templateSchema,
    /** The prep build this request accepted, or the template's active build; null when none runs. */
    build: templateBuildSchema.nullable(),
    /** The owner already had this community template (or this key replayed); nothing new was created. */
    existing: z.boolean(),
  })
  .strict();
export type CommunityTemplateCreatedDto = z.infer<typeof communityTemplateCreatedSchema>;

export const templateBuildGetQuerySchema = z
  .object({
    /** Long-poll: hold until the build changes (or is terminal), at most this many ms. */
    waitMs: operationWaitMsQuerySchema.optional(),
  })
  .strict();

export const templateBuildListQuerySchema = z
  .object({
    limit: pageLimitQuerySchema.optional(),
    cursor: cursorSchema.optional(),
    templateId: resourceIdSchema.optional(),
    state: z.enum(TEMPLATE_BUILD_STATES).optional(),
  })
  .strict();

export const templateBuildLogsQuerySchema = z
  .object({
    /** The executed step (`steps[n].n`). */
    step: z
      .string()
      .regex(/^(?:0|[1-9][0-9]{0,2})$/)
      .transform(Number)
      .pipe(z.number().int().min(0).max(255)),
    cursor: cursorSchema.optional(),
    maxBytes: outputMaxBytesQuerySchema.optional(),
    /** Long-poll an empty page of a running step (at most 25000 ms). */
    waitMs: operationWaitMsQuerySchema.optional(),
  })
  .strict();

/**
 * A blocked-name hint (B12, §6.3): a DNS name the build VM's allowlist
 * resolver refused during this step. `source: "foreign_node"` means another
 * user's host reported it: untrusted operator input, shown under a
 * "reported by the host" label, never with a grant suggestion or preset.
 */
export const templateBuildHintSchema = z
  .object({
    type: z.literal("blocked_name"),
    step: z.number().int().min(0).max(255),
    /** A lowercase DNS name (≤ 253 bytes), validated before storage and display. */
    name: z.string().min(1).max(253),
    /** Foreign hosts stay anonymous (no foreign host identity to grantees). */
    source: z.enum(["own_node", "foreign_node"]),
    /** An egress preset that grants this name (own-node hints only). */
    preset: z.string().max(64).nullable(),
    /** The synthetic log line. */
    message: z.string().max(512),
    at: z.string(),
  })
  .strict();
export type TemplateBuildHintDto = z.infer<typeof templateBuildHintSchema>;
export const TEMPLATE_BUILD_HINTS_MAX = 64;

export const templateBuildLogsSchema = z
  .object({
    buildId: buildIdSchema,
    step: templateBuildStepSchema,
    /** One page of the step's output; null before the step's command exists. */
    output: commandOutputPageSchema.nullable(),
    /** Blocked-name hints of this step, oldest first (at most 64 per build). */
    hints: z.array(templateBuildHintSchema).max(TEMPLATE_BUILD_HINTS_MAX),
  })
  .strict();
export type TemplateBuildLogsDto = z.infer<typeof templateBuildLogsSchema>;

/** `waitMs` ceiling of the build reads (same as operations). */
export const TEMPLATE_BUILD_WAIT_MAX_MS = OPERATION_WAIT_MAX_MS;

const contextParams = z.object({ id: buildIdSchema }).strict();
const contextBase = {
  transport: "upload",
  feature: "templates.build",
  scopes: ["templates:build"],
  query: z.object({}).strict(),
  params: contextParams,
  response: { name: "TemplateBuildContext", schema: templateBuildContextSchema },
  notFound: "NOT_FOUND",
  paginated: false,
  errors: ["TRANSFER_EXPIRED", "TRANSFER_QUOTA", "TRANSFER_IO", "template.build_context_busy"],
  successStatus: 200,
} as const;

/**
 * The staged context of a COPY build, uploaded BEFORE any VM exists. Only the
 * accepting principal (the session or the key that created the build) may use
 * these routes; anything else is 404. Chunks sit on the fixed 1 MiB grid at
 * `offset` in the path (no Content-Range), in order; seal checks SHA-256.
 */
export const BUILD_CONTEXT_ROUTES = {
  openBuildContext: {
    ...contextBase,
    method: "post",
    path: "/v1/template-builds/{id}/context",
    body: emptyBodySchema,
    idempotency: false,
    summary:
      "Open (or re-open, idempotently) the context upload of a COPY build this key accepted.",
  },
  putBuildContextChunk: {
    ...contextBase,
    method: "put",
    path: "/v1/template-builds/{id}/context/chunks/{offset}",
    params: contextParams.extend({ offset: z.string().regex(/^\d{1,16}$/) }).strict(),
    binary: true,
    chunkOffsetInPath: true,
    summary: "Write or replay one fixed 1 MiB chunk at `offset` (the final chunk may be shorter).",
  },
  sealBuildContext: {
    ...contextBase,
    method: "post",
    path: "/v1/template-builds/{id}/context/seal",
    body: emptyBodySchema,
    idempotency: false,
    errors: [...contextBase.errors, "template.build_context_mismatch"],
    summary:
      "Hash the received context and seal it; a SHA-256 mismatch fails the build. Then the build queues.",
  },
} as const satisfies Record<string, SdkRoute>;
