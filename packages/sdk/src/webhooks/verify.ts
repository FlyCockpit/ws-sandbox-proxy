import { createHmac, timingSafeEqual } from "node:crypto";
import {
  WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS,
  type WebhookEventPayload,
  webhookEventPayloadSchema,
} from "@wssp/sandbox-contracts";

/**
 * Verify a wssp webhook delivery (Standard Webhooks). Pass the RAW request body
 * (exactly the bytes received, before any JSON parsing), the request headers
 * and your `whsec_` secret. During a secret rotation pass both secrets.
 *
 * Checks, in order: the three `webhook-*` headers are present; the timestamp
 * is within `toleranceSeconds` (default 300) of `now`; at least one `v1,`
 * signature matches `HMAC-SHA256(secret, "${id}.${timestamp}.${body}")`
 * (constant-time comparison of every candidate); the body is a JSON object.
 * Then dedupe on the returned `id`: deliveries are at-least-once.
 */

export type WebhookVerificationErrorCode =
  | "missing_header"
  | "timestamp_out_of_tolerance"
  | "invalid_signature"
  | "malformed_payload";

export class WebhookVerificationError extends Error {
  readonly code: WebhookVerificationErrorCode;
  constructor(code: WebhookVerificationErrorCode) {
    super(`Webhook verification failed: ${code}.`);
    this.name = "WebhookVerificationError";
    this.code = code;
  }
}

/** A known event, or a future type this SDK does not know yet (never thrown on). */
export type WebhookEvent =
  | WebhookEventPayload
  | { id: string; type: string; schemaVersion: number; occurredAt: string; data: unknown };

export type VerifyWebhookInput = {
  body: string | Uint8Array;
  headers: Headers | Record<string, string | string[] | undefined>;
  secret: string | readonly string[];
  toleranceSeconds?: number;
  /** Clock seam, milliseconds since the epoch. */
  now?: () => number;
};

function header(headers: VerifyWebhookInput["headers"], name: string): string | undefined {
  if (typeof Headers !== "undefined" && headers instanceof Headers)
    return headers.get(name) ?? undefined;
  const record = headers as Record<string, string | string[] | undefined>;
  for (const [key, value] of Object.entries(record))
    if (key.toLowerCase() === name) return Array.isArray(value) ? value[0] : value;
  return undefined;
}

function secretKey(secret: string): Buffer {
  const encoded = secret.startsWith("whsec_") ? secret.slice("whsec_".length) : secret;
  const key = Buffer.from(encoded, "base64");
  if (key.byteLength === 0) throw new WebhookVerificationError("invalid_signature");
  return key;
}

export function verifyWebhook(input: VerifyWebhookInput): WebhookEvent {
  const id = header(input.headers, "webhook-id");
  const timestamp = header(input.headers, "webhook-timestamp");
  const signature = header(input.headers, "webhook-signature");
  if (!id || !timestamp || !signature) throw new WebhookVerificationError("missing_header");
  if (!/^\d{1,12}$/.test(timestamp))
    throw new WebhookVerificationError("timestamp_out_of_tolerance");
  const tolerance = input.toleranceSeconds ?? WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS;
  const nowSeconds = Math.floor((input.now ?? Date.now)() / 1000);
  if (Math.abs(nowSeconds - Number(timestamp)) > tolerance)
    throw new WebhookVerificationError("timestamp_out_of_tolerance");
  const body =
    typeof input.body === "string" ? Buffer.from(input.body, "utf8") : Buffer.from(input.body);
  const signed = Buffer.concat([Buffer.from(`${id}.${timestamp}.`, "utf8"), body]);
  const candidates = signature
    .split(" ")
    .map((part) => part.trim())
    .filter((part) => part.startsWith("v1,"))
    .map((part) => Buffer.from(part.slice(3), "base64"));
  const secrets = typeof input.secret === "string" ? [input.secret] : input.secret;
  let valid = false;
  for (const secret of secrets) {
    const expected = createHmac("sha256", secretKey(secret)).update(signed).digest();
    // Compare against every candidate; never short-circuit on the first match.
    for (const candidate of candidates)
      if (candidate.byteLength === expected.byteLength && timingSafeEqual(candidate, expected))
        valid = true;
  }
  if (!valid) throw new WebhookVerificationError("invalid_signature");
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {
    throw new WebhookVerificationError("malformed_payload");
  }
  const known = webhookEventPayloadSchema.safeParse(parsed);
  if (known.success) return known.data;
  const value = parsed as Record<string, unknown> | null;
  if (
    value &&
    typeof value === "object" &&
    typeof value.id === "string" &&
    typeof value.type === "string" &&
    typeof value.schemaVersion === "number" &&
    typeof value.occurredAt === "string" &&
    "data" in value
  ) {
    // A future or newer payload: return it untyped rather than failing.
    return {
      id: value.id,
      type: value.type,
      schemaVersion: value.schemaVersion,
      occurredAt: value.occurredAt,
      data: value.data,
    };
  }
  throw new WebhookVerificationError("malformed_payload");
}
