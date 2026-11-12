import { liveOwnerSessionProcedure, protectedProcedure } from "../index";
import { sessionPrincipal } from "../sandbox";
import { webhooksConfigured } from "../webhooks/config";
import {
  createWebhookEndpoint,
  createWebhookEndpointInput,
  deleteWebhookEndpoint,
  getWebhookDelivery,
  getWebhookEndpoint,
  listWebhookDeliveries,
  listWebhookDeliveriesInput,
  listWebhookEndpoints,
  redeliverWebhook,
  rotateWebhookSecret,
  rotateWebhookSecretInput,
  testWebhookEndpoint,
  updateWebhookEndpoint,
  updateWebhookEndpointInput,
  webhookIdInput,
  webhookPageInput,
} from "../webhooks/service";

/**
 * Browser plane for webhooks. Reads are `protectedProcedure`; every write
 * (create, update, delete, rotate, test, redeliver) is
 * `liveOwnerSessionProcedure`: it opens an outbound data channel or reveals a
 * signing secret, so it needs the durable, non-impersonated owner session.
 * Budgets are consumed inside the shared services.
 */
export const webhooksRouter = {
  status: protectedProcedure.handler(async () => ({ configured: webhooksConfigured() })),
  list: protectedProcedure
    .input(webhookPageInput)
    .handler(({ input, context }) =>
      listWebhookEndpoints(sessionPrincipal(context.session.user.id), input),
    ),
  get: protectedProcedure
    .input(webhookIdInput)
    .handler(({ input, context }) =>
      getWebhookEndpoint(sessionPrincipal(context.session.user.id), input),
    ),
  create: liveOwnerSessionProcedure
    .input(createWebhookEndpointInput)
    .handler(({ input, context }) =>
      createWebhookEndpoint(sessionPrincipal(context.session.user.id), input),
    ),
  update: liveOwnerSessionProcedure
    .input(updateWebhookEndpointInput)
    .handler(({ input, context }) =>
      updateWebhookEndpoint(sessionPrincipal(context.session.user.id), input),
    ),
  delete: liveOwnerSessionProcedure
    .input(webhookIdInput)
    .handler(({ input, context }) =>
      deleteWebhookEndpoint(sessionPrincipal(context.session.user.id), input),
    ),
  rotateSecret: liveOwnerSessionProcedure
    .input(rotateWebhookSecretInput)
    .handler(({ input, context }) =>
      rotateWebhookSecret(sessionPrincipal(context.session.user.id), input),
    ),
  test: liveOwnerSessionProcedure
    .input(webhookIdInput)
    .handler(({ input, context }) =>
      testWebhookEndpoint(sessionPrincipal(context.session.user.id), input),
    ),
  listDeliveries: protectedProcedure
    .input(listWebhookDeliveriesInput)
    .handler(({ input, context }) =>
      listWebhookDeliveries(sessionPrincipal(context.session.user.id), input),
    ),
  getDelivery: protectedProcedure
    .input(webhookIdInput)
    .handler(({ input, context }) =>
      getWebhookDelivery(sessionPrincipal(context.session.user.id), input),
    ),
  redeliver: liveOwnerSessionProcedure
    .input(webhookIdInput)
    .handler(({ input, context }) =>
      redeliverWebhook(sessionPrincipal(context.session.user.id), input),
    ),
};
