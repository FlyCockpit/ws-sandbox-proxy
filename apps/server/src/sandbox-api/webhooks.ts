import {
  createWebhookEndpoint,
  deleteWebhookEndpoint,
  getWebhookDelivery,
  getWebhookEndpoint,
  listWebhookDeliveries,
  listWebhookEndpoints,
  redeliverWebhook,
  rotateWebhookSecret,
  testWebhookEndpoint,
  updateWebhookEndpoint,
} from "@wssp/api/webhooks/service";
import { PAGE_SIZE_DEFAULT } from "@wssp/sandbox-contracts";
import type { RouteHandlers } from "./reads.js";

/**
 * `/v1` webhook adapters: each calls the shared `serviceProcedure` with the
 * SDK principal (scope `webhooks:write`; budgets and owner scoping live in the
 * service). Never a cookie session.
 */
export const webhookHandlers = {
  listWebhookEndpoints: (principal, { query }) =>
    listWebhookEndpoints(principal, {
      cursor: query.cursor,
      limit: query.limit ?? PAGE_SIZE_DEFAULT,
    }),
  createWebhookEndpoint: (principal, { body }) => createWebhookEndpoint(principal, body),
  getWebhookEndpoint: (principal, { params }) => getWebhookEndpoint(principal, { id: params.id }),
  updateWebhookEndpoint: (principal, { params, body }) =>
    updateWebhookEndpoint(principal, { ...body, id: params.id }),
  deleteWebhookEndpoint: (principal, { params }) =>
    deleteWebhookEndpoint(principal, { id: params.id }),
  rotateWebhookSecret: (principal, { params, body }) =>
    rotateWebhookSecret(principal, { ...body, id: params.id }),
  testWebhookEndpoint: (principal, { params }) => testWebhookEndpoint(principal, { id: params.id }),
  listWebhookDeliveries: (principal, { params, query }) =>
    listWebhookDeliveries(principal, {
      id: params.id,
      cursor: query.cursor,
      limit: query.limit ?? PAGE_SIZE_DEFAULT,
      state: query.state,
    }),
  getWebhookDelivery: (principal, { params }) => getWebhookDelivery(principal, { id: params.id }),
  redeliverWebhook: (principal, { params }) => redeliverWebhook(principal, { id: params.id }),
} satisfies Pick<
  RouteHandlers,
  | "listWebhookEndpoints"
  | "createWebhookEndpoint"
  | "getWebhookEndpoint"
  | "updateWebhookEndpoint"
  | "deleteWebhookEndpoint"
  | "rotateWebhookSecret"
  | "testWebhookEndpoint"
  | "listWebhookDeliveries"
  | "getWebhookDelivery"
  | "redeliverWebhook"
>;
