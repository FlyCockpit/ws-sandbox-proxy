import {
  WEBHOOK_DEFAULT_OPERATION_KINDS,
  WEBHOOK_DESCRIPTION_MAX_LENGTH,
  WEBHOOK_EVENT_TYPES,
  WEBHOOK_URL_MAX_LENGTH,
  type WebhookSubscribableEventType,
} from "@wssp/api/webhooks/constants";

/**
 * Pure rules for the Webhooks pages. The server re-checks every URL (and
 * re-checks the resolved addresses on every delivery attempt); the browser
 * only explains problems early and maps server refusals to text.
 */
export { WEBHOOK_DEFAULT_OPERATION_KINDS, WEBHOOK_EVENT_TYPES };

export type WebhookDraft = {
  url: string;
  description: string;
  events: readonly WebhookSubscribableEventType[];
  /** `default` = lifecycle + commands; `all`; `custom` keeps an API-set list unchanged. */
  kinds: "default" | "all" | "custom";
};
export type WebhookDraftProblem =
  | "urlRequired"
  | "urlTooLong"
  | "eventsRequired"
  | "descriptionTooLong"
  | "destinationInvalid";

export function webhookDraftProblems(draft: WebhookDraft): WebhookDraftProblem[] {
  const problems: WebhookDraftProblem[] = [];
  const url = draft.url.trim();
  if (!url) problems.push("urlRequired");
  else if (url.length > WEBHOOK_URL_MAX_LENGTH) problems.push("urlTooLong");
  else if (!/^https:\/\//i.test(url) && !/^http:\/\//i.test(url))
    problems.push("destinationInvalid");
  if (draft.events.length === 0) problems.push("eventsRequired");
  if (draft.description.trim().length > WEBHOOK_DESCRIPTION_MAX_LENGTH)
    problems.push("descriptionTooLong");
  return problems;
}

/** The host shown (and typed to confirm a delete); never the path or query. */
export function webhookHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export type WebhookProblem =
  | "destinationInvalid"
  | "destinationBlocked"
  | "limit"
  | "disabled"
  | "expired"
  | "notConfigured"
  | "notFound"
  | "rateLimited"
  | "generic";

const BY_CODE: Record<string, WebhookProblem> = {
  "webhook.destination_invalid": "destinationInvalid",
  "webhook.destination_blocked": "destinationBlocked",
  "webhook.endpoint_limit": "limit",
  "webhook.endpoint_disabled": "disabled",
  "webhook.event_expired": "expired",
  "webhook.endpoint_not_found": "notFound",
  "webhook.delivery_not_found": "notFound",
  UNSUPPORTED_CAPABILITY: "notConfigured",
};

/** Map a failed webhook call to the explanation shown next to it. */
export function webhookProblem(error: unknown): WebhookProblem {
  const shape = (error && typeof error === "object" ? error : {}) as {
    code?: unknown;
    status?: unknown;
    data?: unknown;
  };
  const code =
    shape.data != null && typeof shape.data === "object"
      ? (shape.data as { code?: unknown }).code
      : undefined;
  if (typeof code === "string" && BY_CODE[code]) return BY_CODE[code];
  if (shape.code === "NOT_FOUND" || shape.status === 404) return "notFound";
  if (shape.code === "TOO_MANY_REQUESTS" || shape.status === 429) return "rateLimited";
  return "generic";
}

/** Rotation overlap choices, in seconds. */
export const ROTATION_OVERLAPS = [
  { id: "none", seconds: 0 },
  { id: "hour", seconds: 3_600 },
  { id: "day", seconds: 86_400 },
  { id: "week", seconds: 604_800 },
] as const;
