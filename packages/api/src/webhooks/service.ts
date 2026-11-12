import { randomBytes } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import {
  createWebhookEndpointBodySchema,
  OPERATION_KINDS,
  PAGE_SIZE_DEFAULT,
  type ParsedCidr,
  rotateWebhookSecretBodySchema,
  updateWebhookEndpointBodySchema,
  WEBHOOK_DEFAULT_OPERATION_KINDS,
  WEBHOOK_DELIVERY_STATES,
  WEBHOOK_DISABLED_REASONS,
  WEBHOOK_ERROR_CLASSES,
  WEBHOOK_EVENT_TYPES,
  WEBHOOK_MAX_ENDPOINTS_PER_OWNER,
  WEBHOOK_ROTATION_OVERLAP_DEFAULT_SECONDS,
  type WebhookDeliveryDetailDto,
  type WebhookDeliveryDto,
  type WebhookEndpointDto,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { DataKeyStaleWriter, fenceWriteKey, staleWriterError } from "../crypto/data-key-epoch";
import { cursorPage, cursorTokenSchema, pageTake, withCursor } from "../lib/pagination";
import { authorizeServiceAction, serviceProcedure } from "../lib/sdk-key-access";
import { isAdminAccountAuthorized } from "../lib/sensitive-session-two-factor-gate";
import type { Principal } from "../sandbox/contracts";
import { recordedKeyIdOf, viewerOf } from "../sandbox/principal-kinds";
import { consumeWebhookRedeliver, consumeWebhookTest, consumeWebhookWrite } from "./budgets";
import { loadWebhookConfig, type WebhookConfig } from "./config";
import { generateSigningSecret, sealSecret } from "./crypto";
import { checkAddresses, parseDestination } from "./destination-policy";
import { parseResolvedAddresses, type ResolveAddresses, resolveWithCares } from "./http-client";
import { renderTestEvent } from "./render";
import {
  REDELIVER_MAX_EVENT_AGE_MS,
  WEBHOOK_DELIVERY_WINDOW_MS,
  WEBHOOK_MAX_ATTEMPTS,
  WEBHOOK_TEST_MAX_ATTEMPTS,
} from "./schedule";

function rethrowStaleWriter(error: unknown): never {
  if (error instanceof DataKeyStaleWriter) throw staleWriterError();
  throw error;
}

/**
 * Webhook endpoint services: the one implementation behind the browser oRPC
 * router and the `/v1` handlers. Every function is a `serviceProcedure`
 * (scope `webhooks:write`), consumes its budget here (so both planes share one
 * count), and is owner-scoped: a foreign id is indistinguishable from a
 * missing one. Secrets are returned only by create and rotate.
 *
 * The server only writes ledger rows. The worker's dispatcher releases due
 * PENDING deliveries into each endpoint's free in-flight slots, so the server
 * never touches the webhook queues.
 */

const endpointNotFound = () =>
  new ORPCError("NOT_FOUND", {
    message: "Webhook endpoint not found.",
    data: { code: "webhook.endpoint_not_found" },
  });
const deliveryNotFound = () =>
  new ORPCError("NOT_FOUND", {
    message: "Webhook delivery not found.",
    data: { code: "webhook.delivery_not_found" },
  });
const notConfigured = () =>
  new ORPCError("BAD_REQUEST", {
    message: "Webhooks are not configured on this server.",
    data: { code: "UNSUPPORTED_CAPABILITY" },
  });

function requireConfig(): WebhookConfig {
  const config = loadWebhookConfig();
  if (!config) throw notConfigured();
  return config;
}

/**
 * An endpoint receives events for every sandbox on the account, so an SDK key
 * restricted to some hosts, templates or pools cannot manage one (the mint
 * rule refuses such keys; this re-checks at use).
 */
function requireAccountWideKey(principal: Principal): void {
  const viewer = viewerOf(principal);
  if (viewer.resourceMode !== "ALL_OWNED" || viewer.allowedPoolIds !== "allUsable")
    throw new ORPCError("FORBIDDEN", {
      message: "webhooks:write needs a key over all owned resources and all usable pools.",
    });
}

/** Whether the owner may use the operator's private-destination allowlist. */
export async function ownerMayUsePrivateDestinations(
  db: Pick<Prisma.TransactionClient, "user" | "appSetting">,
  userId: string,
  config: Pick<WebhookConfig, "privateScope">,
): Promise<boolean> {
  return config.privateScope === "all" || isAdminAccountAuthorized(userId, { db });
}

const refuseDestination = (code: "invalid" | "blocked") =>
  new ORPCError("BAD_REQUEST", {
    message:
      code === "invalid"
        ? "Webhook destination URL is invalid."
        : "Webhook destination is not allowed.",
    data: {
      code: code === "invalid" ? "webhook.destination_invalid" : "webhook.destination_blocked",
    },
  });

/** Bound on create/update name resolution (the resolver also times out per query). */
export const CREATE_RESOLVE_DEADLINE_MS = 5_000;
let destinationResolver: ResolveAddresses = resolveWithCares;
/** Test seam: unit and pg tests never resolve real names. */
export function setWebhookDestinationResolverForTests(resolve: ResolveAddresses | null): void {
  destinationResolver = resolve ?? resolveWithCares;
}

type PreparedDestination = {
  destination: Extract<ReturnType<typeof parseDestination>, { ok: true }>;
  addresses: ParsedCidr[];
};

/**
 * Create/update destination check, part 1 (outside any transaction, so no lock
 * is held across DNS): URL rules, then resolve a hostname with the delivery
 * resolver and parse EVERY answer. A name that does not resolve is refused.
 * Every delivery attempt re-resolves and re-validates independently.
 */
async function prepareDestination(
  url: string,
  config: WebhookConfig,
): Promise<PreparedDestination> {
  const destination = parseDestination(url, config.allowlist);
  if (!destination.ok) throw refuseDestination(destination.code);
  if (destination.literal) return { destination, addresses: [destination.literal] };
  let names: string[];
  try {
    names = await Promise.race([
      destinationResolver(destination.hostname),
      new Promise<never>((_, reject) => {
        setTimeout(
          () => reject(new Error("resolve timeout")),
          CREATE_RESOLVE_DEADLINE_MS,
        ).unref?.();
      }),
    ]);
  } catch {
    throw refuseDestination("invalid");
  }
  const parsed = parseResolvedAddresses(names);
  if (!parsed.ok)
    throw refuseDestination(parsed.errorClass === "dns_failed" ? "invalid" : "blocked");
  return { destination, addresses: parsed.addresses };
}

/**
 * Part 2 (inside the owner-locked transaction): the same address decision a
 * delivery attempt makes, with the owner's CURRENT private-allowlist
 * eligibility. A non-admin cannot register a name that resolves privately.
 */
async function checkPreparedDestination(
  tx: Prisma.TransactionClient,
  userId: string,
  prepared: PreparedDestination,
  config: WebhookConfig,
): Promise<string> {
  const eligible = await ownerMayUsePrivateDestinations(tx, userId, config);
  const verdict = checkAddresses({
    destination: prepared.destination,
    addresses: prepared.addresses,
    allowlist: config.allowlist,
    ownerMayUsePrivate: eligible,
  });
  if (!verdict.ok) throw refuseDestination("blocked");
  return prepared.destination.url.href;
}

/** Disclosure boundary: never a secret column. */
export const webhookEndpointPublicSelect = {
  id: true,
  url: true,
  description: true,
  events: true,
  operationKinds: true,
  payloadVersion: true,
  disabledAt: true,
  disabledReason: true,
  secretVersion: true,
  previousSecretExpiresAt: true,
  consecutiveFailures: true,
  failingSince: true,
  lastSuccessAt: true,
  lastFailureAt: true,
  lastFailureClass: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.WebhookEndpointSelect;
type EndpointRow = Prisma.WebhookEndpointGetPayload<{ select: typeof webhookEndpointPublicSelect }>;

const iso = (value: Date) => value.toISOString();
const isoOrNull = (value: Date | null) => (value ? value.toISOString() : null);
const eventTypes = new Set<string>(WEBHOOK_EVENT_TYPES);
const errorClasses = new Set<string>(WEBHOOK_ERROR_CLASSES);
const operationKinds = new Set<string>(OPERATION_KINDS);
const knownErrorClass = (value: string | null) =>
  value && errorClasses.has(value)
    ? (value as WebhookEndpointDto["health"]["lastFailureClass"])
    : null;

/**
 * `now` hides an expired rotation overlap: its previous secret no longer signs
 * (see `claimDelivery`), so the DTO must not imply an active overlap even
 * before the maintenance tick clears the stored columns.
 */
export function toWebhookEndpointDto(row: EndpointRow, now: Date = new Date()): WebhookEndpointDto {
  const disabledReason = (WEBHOOK_DISABLED_REASONS as readonly string[]).includes(
    row.disabledReason ?? "",
  )
    ? (row.disabledReason as WebhookEndpointDto["disabledReason"])
    : row.disabledAt
      ? "owner"
      : null;
  const kinds = row.operationKinds.filter((kind) => operationKinds.has(kind));
  return {
    id: row.id,
    url: row.url,
    description: row.description,
    events: row.events.filter((event) => eventTypes.has(event)) as WebhookEndpointDto["events"],
    operationKinds:
      kinds.length === 0 ? "all" : (kinds as Exclude<WebhookEndpointDto["operationKinds"], "all">),
    payloadVersion: 1,
    enabled: row.disabledAt === null,
    disabledAt: isoOrNull(row.disabledAt),
    disabledReason,
    secretVersion: row.secretVersion,
    previousSecretExpiresAt:
      row.previousSecretExpiresAt && row.previousSecretExpiresAt.getTime() > now.getTime()
        ? iso(row.previousSecretExpiresAt)
        : null,
    health: {
      consecutiveFailures: row.consecutiveFailures,
      failingSince: isoOrNull(row.failingSince),
      lastSuccessAt: isoOrNull(row.lastSuccessAt),
      lastFailureAt: isoOrNull(row.lastFailureAt),
      lastFailureClass: knownErrorClass(row.lastFailureClass),
    },
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

function storedKinds(input: "all" | readonly string[] | undefined): string[] {
  if (input === "all") return [];
  return [...(input ?? WEBHOOK_DEFAULT_OPERATION_KINDS)];
}

export function newEventId(): string {
  return `evt_${randomBytes(16).toString("hex")}`;
}
function newEndpointId(): string {
  return `whe_${randomBytes(16).toString("base64url")}`;
}

function parse<T extends z.ZodType>(schema: T, input: unknown): z.output<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new ORPCError("BAD_REQUEST", { message: "Invalid webhook input." });
  return parsed.data;
}

// --- Inputs (oRPC and /v1 share them) ---------------------------------------

export const webhookPageInput = z.object({
  cursor: cursorTokenSchema.optional(),
  limit: z.number().int().min(1).max(100).default(PAGE_SIZE_DEFAULT),
});
export const webhookIdInput = z.object({ id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/) });
export const createWebhookEndpointInput = createWebhookEndpointBodySchema;
export const updateWebhookEndpointInput = updateWebhookEndpointBodySchema.extend(
  webhookIdInput.shape,
);
export const rotateWebhookSecretInput = rotateWebhookSecretBodySchema.extend(webhookIdInput.shape);
export const listWebhookDeliveriesInput = webhookPageInput.extend({
  id: webhookIdInput.shape.id,
  state: z.enum(WEBHOOK_DELIVERY_STATES).optional(),
});

// --- Endpoints ----------------------------------------------------------------

export const listWebhookEndpoints = serviceProcedure(
  { action: "webhooks.list" },
  async (principal: Principal, input: z.input<typeof webhookPageInput>) => {
    requireConfig();
    requireAccountWideKey(principal);
    const page = parse(webhookPageInput, input);
    const rows = await prisma.webhookEndpoint.findMany({
      where: withCursor({ userId: principal.ownerId }, "createdAt", page.cursor, "desc"),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(page.limit),
      select: webhookEndpointPublicSelect,
    });
    const result = cursorPage(rows, page.limit, "createdAt");
    return {
      items: result.items.map((row) => toWebhookEndpointDto(row)),
      nextCursor: result.nextCursor,
    };
  },
);

export const getWebhookEndpoint = serviceProcedure(
  { action: "webhooks.get" },
  async (principal: Principal, input: z.input<typeof webhookIdInput>) => {
    requireConfig();
    requireAccountWideKey(principal);
    const { id } = parse(webhookIdInput, input);
    const row = await prisma.webhookEndpoint.findFirst({
      where: { id, userId: principal.ownerId },
      select: webhookEndpointPublicSelect,
    });
    if (!row) throw endpointNotFound();
    return toWebhookEndpointDto(row);
  },
);

export const createWebhookEndpoint = serviceProcedure(
  { action: "webhooks.create" },
  async (principal: Principal, input: z.input<typeof createWebhookEndpointInput>) => {
    const config = requireConfig();
    requireAccountWideKey(principal);
    const body = parse(createWebhookEndpointInput, input);
    await consumeWebhookWrite(principal.ownerId);
    const prepared = await prepareDestination(body.url, config);
    const secret = generateSigningSecret();
    const id = newEndpointId();
    const row = await prisma
      .$transaction(async (tx) => {
        // Owner lock (refuses accounts in deletion) and fresh key authority.
        await authorizeServiceAction(principal, "webhooks.create", {}, tx);
        await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtext(${`wssp:webhook-endpoints:${principal.ownerId}`}))`;
        const url = await checkPreparedDestination(tx, principal.ownerId, prepared, config);
        const count = await tx.webhookEndpoint.count({ where: { userId: principal.ownerId } });
        if (count >= WEBHOOK_MAX_ENDPOINTS_PER_OWNER)
          throw new ORPCError("CONFLICT", {
            message: "Webhook endpoint limit reached.",
            data: { code: "webhook.endpoint_limit" },
          });
        // The data-key epoch fence: seal under the kid the DB names.
        const sealed = sealSecret(
          secret.raw,
          { endpointId: id, userId: principal.ownerId, version: 1 },
          await fenceWriteKey(tx, config.keys),
        );
        return tx.webhookEndpoint.create({
          data: {
            id,
            userId: principal.ownerId,
            createdByKeyId: recordedKeyIdOf(principal),
            url,
            description: body.description ?? null,
            events: [...body.events],
            operationKinds: storedKinds(body.operationKinds),
            secretCiphertext: new Uint8Array(sealed.ciphertext),
            secretNonce: new Uint8Array(sealed.nonce),
            secretKeyId: sealed.keyId,
            secretVersion: 1,
          },
          select: webhookEndpointPublicSelect,
        });
      })
      .catch(rethrowStaleWriter);
    return { endpoint: toWebhookEndpointDto(row), secret: secret.text };
  },
);

export const updateWebhookEndpoint = serviceProcedure(
  { action: "webhooks.update" },
  async (principal: Principal, input: z.input<typeof updateWebhookEndpointInput>) => {
    const config = requireConfig();
    requireAccountWideKey(principal);
    const body = parse(updateWebhookEndpointInput, input);
    await consumeWebhookWrite(principal.ownerId);
    const destination = parseDestination(body.url, config.allowlist);
    if (!destination.ok) throw refuseDestination(destination.code);
    // An update that leaves the endpoint DISABLED with an unchanged destination
    // sends nothing, so it needs no DNS: an owner can always switch off an
    // endpoint whose name no longer resolves. A destination change or an
    // endpoint that stays or becomes enabled is fully re-validated.
    const existing = body.enabled
      ? null
      : await prisma.webhookEndpoint.findFirst({
          where: { id: body.id, userId: principal.ownerId },
          select: { url: true },
        });
    const unchangedWhileDisabled = existing?.url === destination.url.href;
    const prepared = unchangedWhileDisabled ? null : await prepareDestination(body.url, config);
    const row = await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "webhooks.update", {}, tx);
      const [current] = await tx.$queryRaw<{ disabledAt: Date | null; url: string }[]>`
        SELECT "disabledAt", url FROM webhook_endpoint WHERE id = ${body.id} AND "userId" = ${principal.ownerId} FOR NO KEY UPDATE`;
      if (!current) throw endpointNotFound();
      let url: string;
      if (prepared) url = await checkPreparedDestination(tx, principal.ownerId, prepared, config);
      else if (current.url === destination.url.href) url = current.url;
      else
        throw new ORPCError("CONFLICT", {
          message: "The endpoint changed during the update; retry.",
        });
      const now = new Date();
      const enabling = body.enabled && current.disabledAt !== null;
      const disabling = !body.enabled && current.disabledAt === null;
      if (disabling)
        await tx.webhookDelivery.updateMany({
          where: { endpointId: body.id, state: "PENDING" },
          data: { state: "CANCELLED", lastErrorClass: "endpoint_disabled", completedAt: now },
        });
      return tx.webhookEndpoint.update({
        where: { id: body.id },
        data: {
          url,
          description: body.description,
          events: [...body.events],
          operationKinds: storedKinds(body.operationKinds),
          ...(enabling
            ? {
                disabledAt: null,
                disabledReason: null,
                disabledNotifiedAt: null,
                consecutiveFailures: 0,
                failingSince: null,
              }
            : {}),
          ...(disabling ? { disabledAt: now, disabledReason: "owner" } : {}),
        },
        select: webhookEndpointPublicSelect,
      });
    });
    return toWebhookEndpointDto(row);
  },
);

export const deleteWebhookEndpoint = serviceProcedure(
  { action: "webhooks.delete" },
  async (principal: Principal, input: z.input<typeof webhookIdInput>) => {
    requireConfig();
    requireAccountWideKey(principal);
    const { id } = parse(webhookIdInput, input);
    await consumeWebhookWrite(principal.ownerId);
    const deleted = await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "webhooks.delete", {}, tx);
      return tx.webhookEndpoint.deleteMany({ where: { id, userId: principal.ownerId } });
    });
    if (deleted.count !== 1) throw endpointNotFound();
    return { id, deleted: true as const };
  },
);

export const rotateWebhookSecret = serviceProcedure(
  { action: "webhooks.rotateSecret" },
  async (principal: Principal, input: z.input<typeof rotateWebhookSecretInput>) => {
    const config = requireConfig();
    requireAccountWideKey(principal);
    const body = parse(rotateWebhookSecretInput, input);
    const overlapSeconds = body.overlapSeconds ?? WEBHOOK_ROTATION_OVERLAP_DEFAULT_SECONDS;
    await consumeWebhookWrite(principal.ownerId);
    const secret = generateSigningSecret();
    const row = await prisma
      .$transaction(async (tx) => {
        await authorizeServiceAction(principal, "webhooks.rotateSecret", {}, tx);
        const [current] = await tx.$queryRaw<
          {
            secretCiphertext: Uint8Array;
            secretNonce: Uint8Array;
            secretKeyId: string;
            secretVersion: number;
          }[]
        >`SELECT "secretCiphertext", "secretNonce", "secretKeyId", "secretVersion" FROM webhook_endpoint
        WHERE id = ${body.id} AND "userId" = ${principal.ownerId} FOR NO KEY UPDATE`;
        if (!current) throw endpointNotFound();
        const version = current.secretVersion + 1;
        // The data-key epoch fence: seal under the kid the DB names.
        const sealed = sealSecret(
          secret.raw,
          { endpointId: body.id, userId: principal.ownerId, version },
          await fenceWriteKey(tx, config.keys),
        );
        // Rotating during an overlap discards the older previous secret.
        const overlap =
          overlapSeconds > 0
            ? {
                previousSecretCiphertext: new Uint8Array(current.secretCiphertext),
                previousSecretNonce: new Uint8Array(current.secretNonce),
                previousSecretKeyId: current.secretKeyId,
                previousSecretVersion: current.secretVersion,
                previousSecretExpiresAt: new Date(Date.now() + overlapSeconds * 1000),
              }
            : {
                previousSecretCiphertext: null,
                previousSecretNonce: null,
                previousSecretKeyId: null,
                previousSecretVersion: null,
                previousSecretExpiresAt: null,
              };
        return tx.webhookEndpoint.update({
          where: { id: body.id },
          data: {
            secretCiphertext: new Uint8Array(sealed.ciphertext),
            secretNonce: new Uint8Array(sealed.nonce),
            secretKeyId: sealed.keyId,
            secretVersion: version,
            ...overlap,
          },
          select: webhookEndpointPublicSelect,
        });
      })
      .catch(rethrowStaleWriter);
    return { endpoint: toWebhookEndpointDto(row), secret: secret.text };
  },
);

export const testWebhookEndpoint = serviceProcedure(
  { action: "webhooks.test" },
  async (principal: Principal, input: z.input<typeof webhookIdInput>) => {
    requireConfig();
    requireAccountWideKey(principal);
    const { id } = parse(webhookIdInput, input);
    await consumeWebhookTest(principal.ownerId, id);
    const now = new Date();
    const eventId = newEventId();
    return prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "webhooks.test", {}, tx);
      const endpoint = await tx.webhookEndpoint.findFirst({
        where: { id, userId: principal.ownerId },
        select: { id: true, disabledAt: true },
      });
      if (!endpoint) throw endpointNotFound();
      if (endpoint.disabledAt)
        throw new ORPCError("CONFLICT", {
          message: "Webhook endpoint is disabled.",
          data: { code: "webhook.endpoint_disabled" },
        });
      const body = renderTestEvent({ eventId, endpointId: id, occurredAt: now });
      if (!body) throw new ORPCError("INTERNAL_SERVER_ERROR");
      // Rendered and fanned out at birth: the dispatcher never fans test events.
      await tx.webhookEvent.create({
        data: {
          id: eventId,
          userId: principal.ownerId,
          type: "webhook.test",
          occurredAt: now,
          facts: {},
          body,
          fannedOutAt: now,
        },
      });
      const delivery = await tx.webhookDelivery.create({
        data: {
          eventId,
          endpointId: id,
          userId: principal.ownerId,
          kind: "test",
          maxAttempts: WEBHOOK_TEST_MAX_ATTEMPTS,
          nextAttemptAt: now,
          expiresAt: new Date(now.getTime() + WEBHOOK_DELIVERY_WINDOW_MS),
        },
        select: { id: true },
      });
      return { deliveryId: delivery.id, eventId };
    });
  },
);

// --- Deliveries ----------------------------------------------------------------

const deliverySelect = {
  id: true,
  eventId: true,
  endpointId: true,
  kind: true,
  state: true,
  attemptCount: true,
  maxAttempts: true,
  nextAttemptAt: true,
  lastStatusCode: true,
  lastErrorClass: true,
  createdAt: true,
  expiresAt: true,
  completedAt: true,
  Event: { select: { type: true } },
} satisfies Prisma.WebhookDeliverySelect;
type DeliveryRow = Prisma.WebhookDeliveryGetPayload<{ select: typeof deliverySelect }>;

const deliveryKinds = new Set(["event", "test", "redeliver"]);
const statusOrNull = (value: number | null) =>
  value !== null && value >= 100 && value <= 599 ? value : null;

export function toWebhookDeliveryDto(row: DeliveryRow): WebhookDeliveryDto {
  return {
    id: row.id,
    eventId: row.eventId,
    eventType: row.Event.type,
    endpointId: row.endpointId,
    kind: (deliveryKinds.has(row.kind) ? row.kind : "event") as WebhookDeliveryDto["kind"],
    state: row.state,
    attemptCount: row.attemptCount,
    maxAttempts: row.maxAttempts,
    nextAttemptAt: row.state === "PENDING" ? isoOrNull(row.nextAttemptAt) : null,
    lastStatusCode: statusOrNull(row.lastStatusCode),
    lastErrorClass: knownErrorClass(row.lastErrorClass),
    createdAt: iso(row.createdAt),
    expiresAt: iso(row.expiresAt),
    completedAt: isoOrNull(row.completedAt),
  };
}

export const listWebhookDeliveries = serviceProcedure(
  { action: "webhooks.listDeliveries" },
  async (principal: Principal, input: z.input<typeof listWebhookDeliveriesInput>) => {
    requireConfig();
    requireAccountWideKey(principal);
    const page = parse(listWebhookDeliveriesInput, input);
    const endpoint = await prisma.webhookEndpoint.findFirst({
      where: { id: page.id, userId: principal.ownerId },
      select: { id: true },
    });
    if (!endpoint) throw endpointNotFound();
    const rows = await prisma.webhookDelivery.findMany({
      where: withCursor(
        {
          endpointId: page.id,
          userId: principal.ownerId,
          ...(page.state ? { state: page.state } : {}),
        },
        "createdAt",
        page.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(page.limit),
      select: deliverySelect,
    });
    const result = cursorPage(rows, page.limit, "createdAt");
    return { items: result.items.map(toWebhookDeliveryDto), nextCursor: result.nextCursor };
  },
);

export const getWebhookDelivery = serviceProcedure(
  { action: "webhooks.getDelivery" },
  async (
    principal: Principal,
    input: z.input<typeof webhookIdInput>,
  ): Promise<WebhookDeliveryDetailDto> => {
    requireConfig();
    requireAccountWideKey(principal);
    const { id } = parse(webhookIdInput, input);
    const row = await prisma.webhookDelivery.findFirst({
      where: { id, userId: principal.ownerId },
      select: {
        ...deliverySelect,
        Attempts: {
          orderBy: { attempt: "asc" },
          take: 32,
          select: {
            attempt: true,
            startedAt: true,
            durationMs: true,
            statusCode: true,
            errorClass: true,
            resolvedAddress: true,
            responseExcerpt: true,
          },
        },
      },
    });
    if (!row) throw deliveryNotFound();
    return {
      ...toWebhookDeliveryDto(row),
      attempts: row.Attempts.map((attempt) => ({
        attempt: attempt.attempt,
        startedAt: iso(attempt.startedAt),
        durationMs: Math.max(0, attempt.durationMs),
        statusCode: statusOrNull(attempt.statusCode),
        errorClass: knownErrorClass(attempt.errorClass),
        resolvedAddress: attempt.resolvedAddress?.slice(0, 64) ?? null,
        responseExcerpt: attempt.responseExcerpt?.slice(0, 1024) ?? null,
      })),
    };
  },
);

export const redeliverWebhook = serviceProcedure(
  { action: "webhooks.redeliver" },
  async (principal: Principal, input: z.input<typeof webhookIdInput>) => {
    requireConfig();
    requireAccountWideKey(principal);
    const { id } = parse(webhookIdInput, input);
    await consumeWebhookRedeliver(principal.ownerId);
    return prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "webhooks.redeliver", {}, tx);
      const source = await tx.webhookDelivery.findFirst({
        where: { id, userId: principal.ownerId },
        select: {
          endpointId: true,
          eventId: true,
          Endpoint: { select: { disabledAt: true } },
          Event: { select: { occurredAt: true, body: true } },
        },
      });
      if (!source) throw deliveryNotFound();
      if (source.Endpoint.disabledAt)
        throw new ORPCError("CONFLICT", {
          message: "Webhook endpoint is disabled.",
          data: { code: "webhook.endpoint_disabled" },
        });
      const now = new Date();
      if (
        !source.Event.body ||
        now.getTime() - source.Event.occurredAt.getTime() > REDELIVER_MAX_EVENT_AGE_MS
      )
        throw new ORPCError("GONE", {
          message: "Webhook event is too old to redeliver.",
          data: { code: "webhook.event_expired" },
        });
      const delivery = await tx.webhookDelivery.create({
        data: {
          eventId: source.eventId,
          endpointId: source.endpointId,
          userId: principal.ownerId,
          kind: "redeliver",
          maxAttempts: WEBHOOK_MAX_ATTEMPTS,
          nextAttemptAt: now,
          expiresAt: new Date(now.getTime() + WEBHOOK_DELIVERY_WINDOW_MS),
        },
        select: { id: true },
      });
      return { deliveryId: delivery.id, eventId: source.eventId };
    });
  },
);
