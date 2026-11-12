/**
 * Browser-safe webhook constants for the dashboard (re-exported from the public
 * contract so apps/web needs no extra workspace dependency). Pure: no Node,
 * env, Prisma or crypto imports.
 */
export {
  WEBHOOK_DEFAULT_OPERATION_KINDS,
  WEBHOOK_DESCRIPTION_MAX_LENGTH,
  WEBHOOK_EVENT_TYPES,
  WEBHOOK_URL_MAX_LENGTH,
  type WebhookSubscribableEventType,
} from "@wssp/sandbox-contracts";
