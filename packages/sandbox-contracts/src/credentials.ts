import { z } from "zod";
import { cursorSchema, isoDateTimeSchema, PAGE_SIZE_MAX, resourceIdSchema } from "./dto";

/**
 * CLI logins public contract: login definitions,
 * logins, accounts and instances. Values are write-only: no DTO ever carries
 * one, and value writes return metadata only.
 *
 * Vocabulary: a login pins one definition version; an account is a provider
 * account (pause lives here); an instance is one independent token set.
 */

export const CREDENTIAL_MODES = ["EXCLUSIVE", "SHAREABLE"] as const;
export const CREDENTIAL_DELIVERIES = ["GUEST", "PROXY"] as const;
export const CREDENTIAL_INSTANCE_STATES = ["EMPTY", "READY", "NEEDS_LOGIN"] as const;
export const CREDENTIAL_NAME_MAX_LENGTH = 80;
/** Upper bound on a pasted definition (UTF-8 bytes); the definition parser enforces the exact bound. */
export const CREDENTIAL_DEFINITION_TEXT_MAX_BYTES = 1_048_576;
export const CREDENTIAL_CHECKPOINT_MIN = 5;
export const CREDENTIAL_CHECKPOINT_MAX = 240;
export const CREDENTIAL_MAX_CONCURRENT_MAX = 100_000;
export const CREDENTIAL_VALUE_FILES_MAX = 4096;
export const CREDENTIAL_VALUE_ENV_MAX = 16;

const nameSchema = z.string().trim().min(1).max(CREDENTIAL_NAME_MAX_LENGTH);
const pageInput = {
  limit: z.number().int().min(1).max(PAGE_SIZE_MAX).optional(),
  cursor: cursorSchema.optional(),
};

// --- Inputs -----------------------------------------------------------------

export const credentialPageInputSchema = z.strictObject(pageInput);
export const credentialIdInputSchema = z.strictObject({ id: resourceIdSchema });

export const createCredentialDefinitionBodySchema = z.union([
  z.strictObject({ text: z.string().min(1).max(CREDENTIAL_DEFINITION_TEXT_MAX_BYTES) }),
  z.strictObject({ document: z.record(z.string(), z.unknown()) }),
]);

export const createCredentialBodySchema = z.strictObject({
  name: nameSchema,
  definitionId: resourceIdSchema,
  delivery: z.enum(CREDENTIAL_DELIVERIES).optional(),
  copyBack: z.boolean().optional(),
  checkpointIntervalMin: z
    .number()
    .int()
    .min(CREDENTIAL_CHECKPOINT_MIN)
    .max(CREDENTIAL_CHECKPOINT_MAX)
    .nullable()
    .optional(),
  foreignAllowed: z.boolean().optional(),
});

/** SDK-editable login settings. */
export const updateCredentialBodySchema = z
  .strictObject({
    name: nameSchema.optional(),
    checkpointIntervalMin: z
      .number()
      .int()
      .min(CREDENTIAL_CHECKPOINT_MIN)
      .max(CREDENTIAL_CHECKPOINT_MAX)
      .nullable()
      .optional(),
  })
  .refine((body) => Object.keys(body).length > 0, "Nothing to update.");

export const createCredentialAccountBodySchema = z.strictObject({ name: nameSchema.optional() });
export const updateCredentialAccountBodySchema = z
  .strictObject({ name: nameSchema.nullable().optional(), paused: z.boolean().optional() })
  .refine((body) => Object.keys(body).length > 0, "Nothing to update.");

export const createCredentialInstanceBodySchema = z.strictObject({
  name: nameSchema.optional(),
  /** SHAREABLE logins only; omitted or null = unlimited. */
  maxConcurrent: z.number().int().min(1).max(CREDENTIAL_MAX_CONCURRENT_MAX).nullable().optional(),
});
export const updateCredentialInstanceBodySchema = z
  .strictObject({
    name: nameSchema.nullable().optional(),
    maxConcurrent: z.number().int().min(1).max(CREDENTIAL_MAX_CONCURRENT_MAX).nullable().optional(),
  })
  .refine((body) => Object.keys(body).length > 0, "Nothing to update.");

/** Base64 (standard alphabet) file content; size is bounded by the definition's maxBytes. */
const base64Schema = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/);
export const writeCredentialValueBodySchema = z
  .strictObject({
    files: z
      .array(
        z.strictObject({
          path: z.string().min(1).max(1024),
          kind: z.enum(["file", "dir"]).optional(),
          mode: z.union([z.literal(0o600), z.literal(0o700)]).optional(),
          contentBase64: base64Schema.optional(),
        }),
      )
      .max(CREDENTIAL_VALUE_FILES_MAX)
      .optional(),
    env: z.record(z.string().min(1).max(128), z.string().max(4096)).optional(),
  })
  .refine((body) => (body.files?.length ?? 0) + Object.keys(body.env ?? {}).length > 0, {
    message: "A value needs at least one file or env entry.",
  })
  .refine((body) => Object.keys(body.env ?? {}).length <= CREDENTIAL_VALUE_ENV_MAX, {
    message: "Too many env entries.",
  });

// --- DTOs -------------------------------------------------------------------

export const credentialDefinitionDtoSchema = z.strictObject({
  id: resourceIdSchema,
  slug: z.string(),
  version: z.number().int().min(1),
  digest: z.string(),
  displayName: z.string(),
  archivedAt: isoDateTimeSchema.nullable(),
  createdAt: isoDateTimeSchema,
});
export type CredentialDefinitionDto = z.infer<typeof credentialDefinitionDtoSchema>;
export const credentialDefinitionDetailDtoSchema = credentialDefinitionDtoSchema.extend({
  document: z.record(z.string(), z.unknown()),
  warnings: z.array(z.string()),
});
export type CredentialDefinitionDetailDto = z.infer<typeof credentialDefinitionDetailDtoSchema>;

export const credentialDtoSchema = z.strictObject({
  id: resourceIdSchema,
  name: z.string(),
  definition: z.strictObject({
    id: resourceIdSchema,
    slug: z.string(),
    version: z.number().int(),
    displayName: z.string(),
  }),
  definitionDigest: z.string(),
  mode: z.enum(CREDENTIAL_MODES),
  delivery: z.enum(CREDENTIAL_DELIVERIES),
  copyBack: z.boolean(),
  checkpointIntervalMin: z.number().int().nullable(),
  foreignAllowed: z.boolean(),
  createdAt: isoDateTimeSchema,
  updatedAt: isoDateTimeSchema,
});
export type CredentialDto = z.infer<typeof credentialDtoSchema>;

export const credentialAccountDtoSchema = z.strictObject({
  id: resourceIdSchema,
  credentialId: resourceIdSchema,
  ordinal: z.number().int(),
  name: z.string().nullable(),
  paused: z.boolean(),
  pausedAt: isoDateTimeSchema.nullable(),
  createdAt: isoDateTimeSchema,
});
export type CredentialAccountDto = z.infer<typeof credentialAccountDtoSchema>;

export const credentialInstanceDtoSchema = z.strictObject({
  id: resourceIdSchema,
  credentialId: resourceIdSchema,
  accountId: resourceIdSchema,
  ordinal: z.number().int(),
  name: z.string().nullable(),
  state: z.enum(CREDENTIAL_INSTANCE_STATES),
  needsLoginReason: z.string().nullable(),
  /** SHAREABLE: maxConcurrent (null = unlimited). EXCLUSIVE: 1. */
  maxConcurrent: z.number().int().nullable(),
  activeLeases: z.number().int(),
  loginInProgress: z.boolean(),
  lastCapturedAt: isoDateTimeSchema.nullable(),
  /** The newest upload of a value (dashboard or API), if one is still stored. */
  lastUploadedAt: isoDateTimeSchema.nullable(),
  createdAt: isoDateTimeSchema,
});
export type CredentialInstanceDto = z.infer<typeof credentialInstanceDtoSchema>;

export const credentialEventDtoSchema = z.strictObject({
  id: resourceIdSchema,
  type: z.string(),
  accountId: resourceIdSchema.nullable(),
  instanceId: resourceIdSchema.nullable(),
  leaseId: resourceIdSchema.nullable(),
  sandboxId: resourceIdSchema.nullable(),
  storageSeq: z.number().int().nullable(),
  sizeBytes: z.number().int().nullable(),
  reason: z.string().nullable(),
  at: isoDateTimeSchema,
});
export type CredentialEventDto = z.infer<typeof credentialEventDtoSchema>;

export const credentialValueWriteResultSchema = z.strictObject({
  instanceId: resourceIdSchema,
  storageSeq: z.number().int(),
  sizeBytes: z.number().int(),
  state: z.enum(CREDENTIAL_INSTANCE_STATES),
});
export type CredentialValueWriteResult = z.infer<typeof credentialValueWriteResultSchema>;

// --- /v1 route schemas ---------------------------------------------------------

export const credentialDefinitionCreatedDtoSchema = credentialDefinitionDtoSchema.extend({
  warnings: z.array(z.string()),
});
export const credentialDeletedSchema = z.strictObject({ deleted: z.literal(true) });
/** Force-release of one lease (`released` false when it was already terminal). */
export const forceReleaseCredentialLeaseBodySchema = z
  .strictObject({ promoteCheckpoint: z.boolean().optional() })
  .meta({
    description:
      "`promoteCheckpoint`: make the lease's newest checkpoint newer than the current value current.",
  });
export const credentialLeaseReleasedSchema = z.strictObject({
  leaseId: resourceIdSchema,
  released: z.boolean(),
  promoted: z.strictObject({ storageSeq: z.number().int(), fromSeq: z.number().int() }).nullable(),
});
/** Lease states a holder can be in (terminal leases are not listed). */
export const CREDENTIAL_LEASE_LIVE_STATES = [
  "RESERVED",
  "INSTALLING",
  "ACTIVE",
  "RELEASING",
  "RECOVERY_REQUIRED",
  "RECOVERING",
] as const;
/**
 * One live lease (holder) of an instance: what force-release needs. A
 * WORKLOAD lease is a sandbox's; a LOGIN lease is a login session's.
 * `checkpoint` is the newest checkpoint this lease captured that is newer
 * than the instance's current value (what `promoteCheckpoint` would make
 * current), or null.
 */
export const credentialLeaseDtoSchema = z.strictObject({
  id: resourceIdSchema,
  kind: z.enum(["WORKLOAD", "LOGIN"]),
  state: z.enum(CREDENTIAL_LEASE_LIVE_STATES),
  sandboxId: resourceIdSchema.nullable(),
  createdAt: isoDateTimeSchema,
  checkpoint: z.strictObject({ storageSeq: z.number().int(), at: isoDateTimeSchema }).nullable(),
});
export type CredentialLeaseDto = z.infer<typeof credentialLeaseDtoSchema>;
export const credentialLeaseParamsSchema = z
  .object({ id: resourceIdSchema, instanceId: resourceIdSchema, leaseId: resourceIdSchema })
  .strict();
export const credentialAccountParamsSchema = z
  .object({ id: resourceIdSchema, accountId: resourceIdSchema })
  .strict();
export const credentialInstanceParamsSchema = z
  .object({ id: resourceIdSchema, instanceId: resourceIdSchema })
  .strict();
const page = <T extends z.ZodType>(item: T) =>
  z.strictObject({ items: z.array(item).max(PAGE_SIZE_MAX), nextCursor: cursorSchema.nullable() });
export const credentialDefinitionPageSchema = page(credentialDefinitionDtoSchema);
export const credentialPageSchema = page(credentialDtoSchema);
export const credentialAccountPageSchema = page(credentialAccountDtoSchema);
export const credentialInstancePageSchema = page(credentialInstanceDtoSchema);
export const credentialEventPageSchema = page(credentialEventDtoSchema);
export const credentialLeasePageSchema = page(credentialLeaseDtoSchema);
