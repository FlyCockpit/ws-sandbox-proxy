import type { Prisma } from "@wssp/db";
import {
  OPERATION_STATES,
  operationOutcome,
  publicOperationErrorCode,
  SANDBOX_STATES,
  WEBHOOK_BODY_MAX_BYTES,
  WEBHOOK_CREDENTIAL_REASON_PATTERN,
  WEBHOOK_PAYLOAD_VERSION,
  type WebhookEventType,
  webhookEventSchemas,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { sandboxDiskSelect } from "../sandbox/disk-offload/disk-view";
import { redactSandbox, toOperationDto, toSandboxDto } from "../sandbox/public-dto";

/**
 * Renders a webhook event body ONCE, at fan-out; retries and redeliveries send
 * the identical bytes. The payload is built by picking fields from the same
 * public `/v1` projections `GET /v1/sandboxes/{id}` and `GET /v1/operations/{id}`
 * use (`../sandbox/public-dto.ts`, with host redaction for shared hosts), so a
 * webhook never discloses more than those reads. The transition itself (state,
 * previous state, generation, error code) comes from the trigger's frozen
 * `facts`, not the live row: two `operation.completed` events for one
 * operation (UNKNOWN_OUTCOME, then resolved) render their own states.
 * `credential.*` events re-read their credential_event row through a fixed
 * projection: ids and a reason code, the owner's own event-list fields.
 */

const sandboxFactsSchema = z.object({
  from: z.enum(SANDBOX_STATES).nullable(),
  to: z.enum(SANDBOX_STATES),
  generation: z.number().int().min(0),
  errorCode: z.string().nullable(),
});
const operationFactsSchema = z.object({
  from: z.enum(OPERATION_STATES).nullable(),
  to: z.enum(OPERATION_STATES),
  generation: z.number().int().min(0),
  errorCode: z.string().nullable(),
});

/** Exactly the columns the public projections read; a disclosure boundary. */
export const webhookSandboxRenderSelect = {
  ...sandboxDiskSelect,
  id: true,
  userId: true,
  cpuCount: true,
  memoryMiB: true,
  diskGiB: true,
  storagePoolId: true,
  storagePoolName: true,
  storageMarker: true,
  sandboxHostId: true,
  hostOwnerId: true,
  usagePoolId: true,
  usageMemberId: true,
  accessGraceUntil: true,
  name: true,
  templateId: true,
  templateRevisionId: true,
  originPoolId: true,
  state: true,
  generation: true,
  startedAt: true,
  readyAt: true,
  leaseRevision: true,
  leaseExpiresAt: true,
  leaseExpireAction: true,
  leaseExpiresAtRequested: true,
  leaseExpireActionRequested: true,
  leaseExpiresAtEffective: true,
  leaseExpireActionEffective: true,
  metadata: true,
  egressPolicy: true,
  egressPolicyHash: true,
  egressRequest: true,
  egressModeReason: true,
  egressDeniedGrants: true,
  guestSudo: true,
  guestSudoRequested: true,
  guestSudoReason: true,
  tunnelEnabled: true,
  tunnelPorts: true,
  guestRoot: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.SandboxSelect;

export const webhookOperationRenderSelect = {
  id: true,
  userId: true,
  sandboxId: true,
  kind: true,
  state: true,
  generation: true,
  errorCode: true,
  failure: true,
  createdAt: true,
  updatedAt: true,
  dispatchedAt: true,
  completedAt: true,
} satisfies Prisma.SandboxOperationSelect;

export type RenderableEvent = {
  id: string;
  userId: string;
  type: string;
  sandboxId: string | null;
  operationId: string | null;
  occurredAt: Date;
  facts: unknown;
};

/** Exactly the credential_event columns a `credential.*` payload may carry. */
export const webhookCredentialEventRenderSelect = {
  id: true,
  userId: true,
  type: true,
  credentialId: true,
  accountId: true,
  instanceId: true,
  leaseId: true,
  sandboxId: true,
  reason: true,
} satisfies Prisma.CredentialEventSelect;

const credentialFactsSchema = z.object({ credentialEventId: z.string().min(1).max(64) });

/** Webhook type ↔ the `credential_event.type` the trigger emits it for. */
const CREDENTIAL_EVENT_TYPES = {
  "credential.capture_failed": "capture_failed",
  "credential.capture_lost": "capture_lost",
  "credential.recovery_required": "recovery_required",
  "credential.needs_login": "needs_login",
} as const satisfies Partial<Record<WebhookEventType, string>>;
type CredentialWebhookType = keyof typeof CREDENTIAL_EVENT_TYPES;

function isCredentialWebhookType(type: string): type is CredentialWebhookType {
  return Object.hasOwn(CREDENTIAL_EVENT_TYPES, type);
}

type RenderClient = Pick<
  Prisma.TransactionClient,
  "sandbox" | "sandboxOperation" | "credentialEvent"
>;

/**
 * `credential.*`: re-read the owner's credential_event row named by the
 * frozen facts through {@link webhookCredentialEventRenderSelect}. A reason
 * that is not a fixed token renders as null rather than leaking text.
 */
async function renderCredentialEvent(
  client: RenderClient,
  event: RenderableEvent,
  type: CredentialWebhookType,
  envelope: { id: string; schemaVersion: number; occurredAt: string },
): Promise<string | null> {
  const facts = credentialFactsSchema.safeParse(event.facts);
  if (!facts.success) return null;
  const row = await client.credentialEvent.findFirst({
    where: { id: facts.data.credentialEventId, userId: event.userId },
    select: webhookCredentialEventRenderSelect,
  });
  if (!row || row.type !== CREDENTIAL_EVENT_TYPES[type]) return null;
  return serializeWebhookPayload(type, {
    ...envelope,
    type,
    data: {
      credential: {
        id: row.credentialId,
        accountId: row.accountId,
        instanceId: row.instanceId,
      },
      leaseId: row.leaseId,
      sandboxId: row.sandboxId,
      reason:
        row.reason !== null && WEBHOOK_CREDENTIAL_REASON_PATTERN.test(row.reason)
          ? row.reason
          : null,
    },
  });
}

/** Serialize and enforce the frozen contract: strict schema and the 64 KiB cap. */
export function serializeWebhookPayload(type: WebhookEventType, payload: unknown): string | null {
  const checked = webhookEventSchemas[type].safeParse(payload);
  if (!checked.success) return null;
  const body = JSON.stringify(checked.data);
  return Buffer.byteLength(body, "utf8") <= WEBHOOK_BODY_MAX_BYTES ? body : null;
}

/**
 * The frozen body for one event, or null when it cannot be rendered (the
 * resource is gone or the facts are malformed). Null events are fanned out
 * with no deliveries.
 */
export async function renderWebhookEvent(
  client: RenderClient,
  event: RenderableEvent,
): Promise<string | null> {
  const envelope = {
    id: event.id,
    schemaVersion: WEBHOOK_PAYLOAD_VERSION,
    occurredAt: event.occurredAt.toISOString(),
  };
  if (isCredentialWebhookType(event.type))
    return renderCredentialEvent(client, event, event.type, envelope);
  if (event.type === "operation.completed") {
    const facts = operationFactsSchema.safeParse(event.facts);
    if (!facts.success || !event.operationId) return null;
    const row = await client.sandboxOperation.findFirst({
      where: { id: event.operationId, userId: event.userId },
      select: webhookOperationRenderSelect,
    });
    if (!row) return null;
    const dto = toOperationDto({ ...row, state: facts.data.to, errorCode: facts.data.errorCode });
    return serializeWebhookPayload("operation.completed", {
      ...envelope,
      type: "operation.completed",
      data: {
        operation: {
          id: dto.id,
          sandboxId: dto.sandboxId,
          kind: dto.kind,
          state: dto.state,
          outcome: operationOutcome(dto.state),
          errorCode: dto.errorCode,
          failure: dto.failure,
          completedAt: dto.completedAt,
        },
      },
    });
  }
  if (
    event.type !== "sandbox.ready" &&
    event.type !== "sandbox.stopped" &&
    event.type !== "sandbox.create_failed" &&
    event.type !== "sandbox.destroyed" &&
    event.type !== "sandbox.offloaded"
  )
    return null;
  const facts = sandboxFactsSchema.safeParse(event.facts);
  if (!facts.success || !event.sandboxId) return null;
  const row = await client.sandbox.findFirst({
    where: { id: event.sandboxId, userId: event.userId },
    select: webhookSandboxRenderSelect,
  });
  if (!row) return null;
  let dto: ReturnType<typeof toSandboxDto>;
  try {
    dto = toSandboxDto(redactSandbox(row, event.userId));
  } catch {
    return null;
  }
  const sandbox = {
    id: dto.id,
    // The name as of delivery (a rename between event and delivery shows).
    name: dto.name,
    state: facts.data.to,
    previousState: facts.data.from,
    generation: facts.data.generation,
    hostId: dto.hostId,
    templateId: dto.templateId,
    templateRevisionId: dto.templateRevisionId,
    originPoolId: dto.originPoolId,
    metadata: dto.metadata,
  };
  if (event.type === "sandbox.create_failed")
    return serializeWebhookPayload(event.type, {
      ...envelope,
      type: event.type,
      data: { sandbox, error: { code: publicOperationErrorCode(facts.data.errorCode) } },
    });
  return serializeWebhookPayload(event.type, { ...envelope, type: event.type, data: { sandbox } });
}

/** `webhook.test` body; rendered at test-send time. */
export function renderTestEvent(input: { eventId: string; endpointId: string; occurredAt: Date }) {
  return serializeWebhookPayload("webhook.test", {
    id: input.eventId,
    type: "webhook.test",
    schemaVersion: WEBHOOK_PAYLOAD_VERSION,
    occurredAt: input.occurredAt.toISOString(),
    data: { endpointId: input.endpointId },
  });
}
