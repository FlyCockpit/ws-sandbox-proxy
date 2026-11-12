import {
  type createWebhookEndpointBodySchema,
  cursorSchema,
  PAGE_SIZE_MAX,
  type rotateWebhookSecretBodySchema,
  type updateWebhookEndpointBodySchema,
  WEBHOOK_DELIVERY_STATES,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { WsspError } from "./errors";
import { type WaitOptions, waitTimeout } from "./polling";
import type { RouteResponse, WsspTransport } from "./transport";

const page = z
  .object({
    limit: z.number().int().min(1).max(PAGE_SIZE_MAX).optional(),
    cursor: cursorSchema.optional(),
  })
  .strict();
const deliveryPage = page.extend({ state: z.enum(WEBHOOK_DELIVERY_STATES).optional() }).strict();
export type WebhookPageOptions = z.input<typeof page>;
export type WebhookDeliveryPageOptions = z.input<typeof deliveryPage>;
export type CreateWebhookEndpointInput = z.input<typeof createWebhookEndpointBodySchema>;
export type UpdateWebhookEndpointInput = z.input<typeof updateWebhookEndpointBodySchema>;
export type RotateWebhookSecretInput = z.input<typeof rotateWebhookSecretBodySchema>;

function wire<T extends z.ZodType>(schema: T, input: unknown) {
  const parsed = schema.safeParse(input ?? {});
  if (!parsed.success)
    throw new WsspError({ kind: "invalid_request", message: "Invalid webhook page options." });
  const data = parsed.data as { limit?: number } & Record<string, unknown>;
  return { ...data, limit: data.limit?.toString() };
}

export type WebhookEndpointsApi = {
  list(
    query?: WebhookPageOptions,
    options?: WaitOptions,
  ): Promise<RouteResponse<"listWebhookEndpoints">>;
  get(id: string, options?: WaitOptions): Promise<RouteResponse<"getWebhookEndpoint">>;
  /** Not idempotent: retrying after an unknown outcome may create a second endpoint. */
  create(
    input: CreateWebhookEndpointInput,
    options?: WaitOptions,
  ): Promise<RouteResponse<"createWebhookEndpoint">>;
  /** Full replacement of every mutable field, including `enabled`. */
  update(
    id: string,
    input: UpdateWebhookEndpointInput,
    options?: WaitOptions,
  ): Promise<RouteResponse<"updateWebhookEndpoint">>;
  delete(id: string, options?: WaitOptions): Promise<RouteResponse<"deleteWebhookEndpoint">>;
  rotateSecret(
    id: string,
    input?: RotateWebhookSecretInput,
    options?: WaitOptions,
  ): Promise<RouteResponse<"rotateWebhookSecret">>;
  test(id: string, options?: WaitOptions): Promise<RouteResponse<"testWebhookEndpoint">>;
};
export type WebhookDeliveriesApi = {
  list(
    endpointId: string,
    query?: WebhookDeliveryPageOptions,
    options?: WaitOptions,
  ): Promise<RouteResponse<"listWebhookDeliveries">>;
  get(id: string, options?: WaitOptions): Promise<RouteResponse<"getWebhookDelivery">>;
  redeliver(id: string, options?: WaitOptions): Promise<RouteResponse<"redeliverWebhook">>;
};
export type WebhooksApi = { endpoints: WebhookEndpointsApi; deliveries: WebhookDeliveriesApi };

export function createWebhooksApi(transport: WsspTransport): WebhooksApi {
  const opts = (options?: WaitOptions) => ({
    signal: options?.signal,
    timeoutMs: waitTimeout(options),
  });
  return {
    endpoints: {
      list: (query, options) =>
        transport.request("listWebhookEndpoints", { query: wire(page, query), ...opts(options) }),
      get: (id, options) =>
        transport.request("getWebhookEndpoint", { params: { id }, ...opts(options) }),
      create: (input, options) =>
        transport.request("createWebhookEndpoint", { body: input, ...opts(options) }),
      update: (id, input, options) =>
        transport.request("updateWebhookEndpoint", {
          params: { id },
          body: input,
          ...opts(options),
        }),
      delete: (id, options) =>
        transport.request("deleteWebhookEndpoint", { params: { id }, ...opts(options) }),
      rotateSecret: (id, input, options) =>
        transport.request("rotateWebhookSecret", {
          params: { id },
          body: input ?? {},
          ...opts(options),
        }),
      test: (id, options) =>
        transport.request("testWebhookEndpoint", { params: { id }, body: {}, ...opts(options) }),
    },
    deliveries: {
      list: (endpointId, query, options) =>
        transport.request("listWebhookDeliveries", {
          params: { id: endpointId },
          query: wire(deliveryPage, query),
          ...opts(options),
        }),
      get: (id, options) =>
        transport.request("getWebhookDelivery", { params: { id }, ...opts(options) }),
      redeliver: (id, options) =>
        transport.request("redeliverWebhook", { params: { id }, body: {}, ...opts(options) }),
    },
  };
}
