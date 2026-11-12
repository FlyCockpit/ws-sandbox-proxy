import { z } from "zod";
import {
  cursorSchema,
  failureSchema,
  isoDateTimeSchema,
  OPERATION_ERROR_CODES,
  OPERATION_KINDS,
  OPERATION_OUTCOMES,
  OPERATION_STATES,
  PAGE_SIZE_MAX,
  pageQuerySchema,
  resourceIdSchema,
  SANDBOX_STATES,
} from "./dto";
import { metadataSchema } from "./metadata";
import { sandboxNameSchema } from "./sandbox-name";

/**
 * Public webhook contract (payload v1). Endpoints, deliveries and the event
 * payload a receiver verifies. Signing lives server-side
 * (`packages/api/src/webhooks/signing.ts`) and in the SDK verifier; this
 * module carries only shapes, so the browser bundle never sees key material.
 */

/**
 * Event types an endpoint can subscribe to. `webhook.test` is never
 * subscribable. `credential.*` events come from CLI-login lease transitions
 * (capture failed on a user stop/kill, capture lost, recovery required,
 * instance needs a new login); they carry ids and a reason code only.
 */
export const WEBHOOK_EVENT_TYPES = [
  "sandbox.ready",
  "sandbox.stopped",
  "sandbox.create_failed",
  "sandbox.destroyed",
  "sandbox.offloaded",
  "operation.completed",
  "credential.capture_failed",
  "credential.capture_lost",
  "credential.recovery_required",
  "credential.needs_login",
] as const;
export type WebhookSubscribableEventType = (typeof WEBHOOK_EVENT_TYPES)[number];
export const WEBHOOK_TEST_EVENT_TYPE = "webhook.test" as const;
export type WebhookEventType = WebhookSubscribableEventType | typeof WEBHOOK_TEST_EVENT_TYPE;

/**
 * Default `operation.completed` filter: lifecycle kinds plus commands. File and
 * process inspection kinds are high volume; owners opt into them explicitly
 * (or pass `"all"`).
 */
export const WEBHOOK_DEFAULT_OPERATION_KINDS = [
  "CREATE_SANDBOX",
  "STOP_SANDBOX",
  "KILL_SANDBOX",
  "RECONNECT_SANDBOX",
  "RENEW_SANDBOX_LEASE",
  "RUN_COMMAND",
] as const satisfies readonly (typeof OPERATION_KINDS)[number][];

export const WEBHOOK_PAYLOAD_VERSION = 1 as const;
export const WEBHOOK_URL_MAX_LENGTH = 2048;
export const WEBHOOK_DESCRIPTION_MAX_LENGTH = 200;
export const WEBHOOK_MAX_ENDPOINTS_PER_OWNER = 10;
/** Signing secrets are `whsec_` + base64 of 32 random bytes (Standard Webhooks). */
export const WEBHOOK_SECRET_PREFIX = "whsec_";
export const WEBHOOK_ROTATION_OVERLAP_DEFAULT_SECONDS = 86_400;
export const WEBHOOK_ROTATION_OVERLAP_MAX_SECONDS = 7 * 86_400;
/** Receivers should reject timestamps further than this from their clock. */
export const WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS = 300;
/** Retry window: a delivery that has not succeeded within this time fails. */
export const WEBHOOK_DELIVERY_WINDOW_HOURS = 24;

export const WEBHOOK_DELIVERY_STATES = [
  "PENDING",
  "IN_FLIGHT",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
] as const;
export const WEBHOOK_DELIVERY_KINDS = ["event", "test", "redeliver"] as const;

/** Closed set of attempt failure classes. Nothing else is ever recorded. */
export const WEBHOOK_ERROR_CLASSES = [
  "dns_failed",
  "destination_blocked",
  "connect_failed",
  "connect_timeout",
  "tls_error",
  "timeout",
  "http_status",
  "redirect_not_followed",
  "response_too_large",
  "protocol_error",
  "worker_lost",
  "not_configured",
  "backlog_overflow",
  "expired",
  "endpoint_disabled",
] as const;
export type WebhookErrorClass = (typeof WEBHOOK_ERROR_CLASSES)[number];

export const WEBHOOK_DISABLED_REASONS = ["owner", "sustained_failures"] as const;

const operationKindsFilterSchema = z.union([
  z.literal("all"),
  z
    .array(z.enum(OPERATION_KINDS))
    .min(1)
    .max(OPERATION_KINDS.length)
    .refine((kinds) => new Set(kinds).size === kinds.length, { message: "Duplicate kinds." }),
]);

const eventsSchema = z
  .array(z.enum(WEBHOOK_EVENT_TYPES))
  .min(1)
  .max(WEBHOOK_EVENT_TYPES.length)
  .refine((events) => new Set(events).size === events.length, { message: "Duplicate events." });

const urlSchema = z.string().min(1).max(WEBHOOK_URL_MAX_LENGTH);
const descriptionSchema = z.string().max(WEBHOOK_DESCRIPTION_MAX_LENGTH);

export const webhookEndpointSchema = z
  .object({
    id: resourceIdSchema,
    url: urlSchema,
    description: descriptionSchema.nullable(),
    events: z.array(z.enum(WEBHOOK_EVENT_TYPES)),
    operationKinds: operationKindsFilterSchema,
    payloadVersion: z.literal(WEBHOOK_PAYLOAD_VERSION),
    enabled: z.boolean(),
    disabledAt: isoDateTimeSchema.nullable(),
    disabledReason: z.enum(WEBHOOK_DISABLED_REASONS).nullable(),
    secretVersion: z.number().int().min(1),
    previousSecretExpiresAt: isoDateTimeSchema.nullable(),
    health: z
      .object({
        consecutiveFailures: z.number().int().min(0),
        failingSince: isoDateTimeSchema.nullable(),
        lastSuccessAt: isoDateTimeSchema.nullable(),
        lastFailureAt: isoDateTimeSchema.nullable(),
        lastFailureClass: z.enum(WEBHOOK_ERROR_CLASSES).nullable(),
      })
      .strict(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
  })
  .strict();
export type WebhookEndpointDto = z.infer<typeof webhookEndpointSchema>;

export const webhookEndpointPageSchema = z
  .object({
    items: z.array(webhookEndpointSchema).max(PAGE_SIZE_MAX),
    nextCursor: cursorSchema.nullable(),
  })
  .strict();

/** Create and rotate return the plaintext signing secret exactly once. */
export const webhookEndpointWithSecretSchema = z
  .object({
    endpoint: webhookEndpointSchema,
    secret: z.string().regex(/^whsec_[A-Za-z0-9+/]{43}=$/),
  })
  .strict();

export const createWebhookEndpointBodySchema = z
  .object({
    url: urlSchema,
    description: descriptionSchema.optional(),
    events: eventsSchema,
    operationKinds: operationKindsFilterSchema.optional(),
  })
  .strict();
export type CreateWebhookEndpointBody = z.infer<typeof createWebhookEndpointBodySchema>;

/** PUT: full replacement of every mutable field. */
export const updateWebhookEndpointBodySchema = z
  .object({
    url: urlSchema,
    description: descriptionSchema.nullable(),
    events: eventsSchema,
    operationKinds: operationKindsFilterSchema,
    enabled: z.boolean(),
  })
  .strict();
export type UpdateWebhookEndpointBody = z.infer<typeof updateWebhookEndpointBodySchema>;

export const rotateWebhookSecretBodySchema = z
  .object({
    overlapSeconds: z.number().int().min(0).max(WEBHOOK_ROTATION_OVERLAP_MAX_SECONDS).optional(),
  })
  .strict();

export const webhookEmptyBodySchema = z.object({}).strict();

export const webhookDeletedSchema = z
  .object({ id: resourceIdSchema, deleted: z.literal(true) })
  .strict();

export const webhookDeliveryAcceptedSchema = z
  .object({ deliveryId: resourceIdSchema, eventId: z.string().regex(/^evt_[0-9a-f]{32}$/) })
  .strict();

export const webhookDeliverySchema = z
  .object({
    id: resourceIdSchema,
    eventId: z.string().regex(/^evt_[0-9a-f]{32}$/),
    eventType: z.string().min(1).max(64),
    endpointId: resourceIdSchema,
    kind: z.enum(WEBHOOK_DELIVERY_KINDS),
    state: z.enum(WEBHOOK_DELIVERY_STATES),
    attemptCount: z.number().int().min(0),
    maxAttempts: z.number().int().min(1),
    nextAttemptAt: isoDateTimeSchema.nullable(),
    lastStatusCode: z.number().int().min(100).max(599).nullable(),
    lastErrorClass: z.enum(WEBHOOK_ERROR_CLASSES).nullable(),
    createdAt: isoDateTimeSchema,
    expiresAt: isoDateTimeSchema,
    completedAt: isoDateTimeSchema.nullable(),
  })
  .strict();
export type WebhookDeliveryDto = z.infer<typeof webhookDeliverySchema>;

export const webhookDeliveryAttemptSchema = z
  .object({
    attempt: z.number().int().min(1),
    startedAt: isoDateTimeSchema,
    durationMs: z.number().int().min(0),
    statusCode: z.number().int().min(100).max(599).nullable(),
    errorClass: z.enum(WEBHOOK_ERROR_CLASSES).nullable(),
    /** Owner-only: the address the attempt connected to. */
    resolvedAddress: z.string().max(64).nullable(),
    /** Owner-only: at most 512 bytes of the receiver's reply, lossy UTF-8. */
    responseExcerpt: z.string().max(1024).nullable(),
  })
  .strict();

export const webhookDeliveryDetailSchema = webhookDeliverySchema
  .extend({ attempts: z.array(webhookDeliveryAttemptSchema).max(32) })
  .strict();
export type WebhookDeliveryDetailDto = z.infer<typeof webhookDeliveryDetailSchema>;

export const webhookDeliveryPageSchema = z
  .object({
    items: z.array(webhookDeliverySchema).max(PAGE_SIZE_MAX),
    nextCursor: cursorSchema.nullable(),
  })
  .strict();

export const webhookDeliveryListQuerySchema = pageQuerySchema
  .extend({ state: z.enum(WEBHOOK_DELIVERY_STATES).optional() })
  .strict();

// --- Event payloads (v1) ------------------------------------------------------

const eventIdSchema = z.string().regex(/^evt_[0-9a-f]{32}$/);

export const webhookSandboxDataSchema = z
  .object({
    sandbox: z
      .object({
        id: resourceIdSchema,
        /** The sandbox's name when the event is delivered (a later rename shows on retries). */
        name: sandboxNameSchema,
        state: z.enum(SANDBOX_STATES),
        previousState: z.enum(SANDBOX_STATES).nullable(),
        generation: z.number().int().min(0),
        hostId: resourceIdSchema.nullable(),
        templateId: resourceIdSchema,
        templateRevisionId: resourceIdSchema,
        originPoolId: resourceIdSchema.nullable(),
        metadata: metadataSchema,
      })
      .strict(),
  })
  .strict();

export const webhookCreateFailedDataSchema = webhookSandboxDataSchema
  .extend({
    error: z.object({ code: z.enum(OPERATION_ERROR_CODES).nullable() }).strict(),
  })
  .strict();

/** Strict subset of `operationSchema`: no result, output, error detail, payload or key. */
export const webhookOperationDataSchema = z
  .object({
    operation: z
      .object({
        id: resourceIdSchema,
        sandboxId: resourceIdSchema,
        kind: z.enum(OPERATION_KINDS),
        state: z.enum(OPERATION_STATES),
        outcome: z.enum(OPERATION_OUTCOMES),
        errorCode: z.enum(OPERATION_ERROR_CODES).nullable(),
        failure: failureSchema.nullable(),
        completedAt: isoDateTimeSchema.nullable(),
      })
      .strict(),
  })
  .strict();

/** Reason codes are fixed server tokens (`capture_lost`, `census_settlement`, …), never text. */
export const WEBHOOK_CREDENTIAL_REASON_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;

/**
 * `credential.*` events: identifiers and a reason code only, the same fields
 * the owner's `GET /v1/credentials/{id}/events` returns. Never a value, path,
 * host or envelope byte.
 */
export const webhookCredentialDataSchema = z
  .object({
    credential: z
      .object({
        id: resourceIdSchema,
        accountId: resourceIdSchema.nullable(),
        instanceId: resourceIdSchema.nullable(),
      })
      .strict(),
    leaseId: resourceIdSchema.nullable(),
    sandboxId: resourceIdSchema.nullable(),
    reason: z.string().regex(WEBHOOK_CREDENTIAL_REASON_PATTERN).nullable(),
  })
  .strict();

const envelope = <T extends string, D extends z.ZodType>(type: T, data: D) =>
  z
    .object({
      id: eventIdSchema,
      type: z.literal(type),
      schemaVersion: z.literal(WEBHOOK_PAYLOAD_VERSION),
      occurredAt: isoDateTimeSchema,
      data,
    })
    .strict();

export const webhookEventSchemas = {
  "sandbox.ready": envelope("sandbox.ready", webhookSandboxDataSchema),
  "sandbox.stopped": envelope("sandbox.stopped", webhookSandboxDataSchema),
  "sandbox.create_failed": envelope("sandbox.create_failed", webhookCreateFailedDataSchema),
  "sandbox.destroyed": envelope("sandbox.destroyed", webhookSandboxDataSchema),
  "sandbox.offloaded": envelope("sandbox.offloaded", webhookSandboxDataSchema),
  "operation.completed": envelope("operation.completed", webhookOperationDataSchema),
  "credential.capture_failed": envelope("credential.capture_failed", webhookCredentialDataSchema),
  "credential.capture_lost": envelope("credential.capture_lost", webhookCredentialDataSchema),
  "credential.recovery_required": envelope(
    "credential.recovery_required",
    webhookCredentialDataSchema,
  ),
  "credential.needs_login": envelope("credential.needs_login", webhookCredentialDataSchema),
  "webhook.test": envelope(
    WEBHOOK_TEST_EVENT_TYPE,
    z.object({ endpointId: resourceIdSchema }).strict(),
  ),
} as const satisfies Record<WebhookEventType, z.ZodType>;

export const webhookEventPayloadSchema = z.discriminatedUnion("type", [
  webhookEventSchemas["sandbox.ready"],
  webhookEventSchemas["sandbox.stopped"],
  webhookEventSchemas["sandbox.create_failed"],
  webhookEventSchemas["sandbox.destroyed"],
  webhookEventSchemas["sandbox.offloaded"],
  webhookEventSchemas["operation.completed"],
  webhookEventSchemas["credential.capture_failed"],
  webhookEventSchemas["credential.capture_lost"],
  webhookEventSchemas["credential.recovery_required"],
  webhookEventSchemas["credential.needs_login"],
  webhookEventSchemas["webhook.test"],
]);
export type WebhookEventPayload = z.infer<typeof webhookEventPayloadSchema>;

/** Rendered payloads never exceed this many bytes (UTF-8). */
export const WEBHOOK_BODY_MAX_BYTES = 64 * 1024;
