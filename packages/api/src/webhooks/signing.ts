import { createHmac } from "node:crypto";

/**
 * Standard Webhooks signing (https://www.standardwebhooks.com/). The signed
 * bytes are `${id}.${timestamp}.${body}` with the raw UTF-8 body; the key is
 * the raw secret bytes (the base64 part after `whsec_`). Binding the event id
 * stops a valid signature being replayed under a swapped dedupe id.
 *
 * Server-side only: the browser bundle never imports signing code.
 */
export function signatureValue(key: Uint8Array, id: string, timestamp: number, body: string) {
  const mac = createHmac("sha256", key)
    .update(`${id}.${timestamp}.${body}`, "utf8")
    .digest("base64");
  return `v1,${mac}`;
}

/** `webhook-signature`: one `v1,…` value per key, newest first, space-separated. */
export function signatureHeader(
  keys: readonly Uint8Array[],
  id: string,
  timestamp: number,
  body: string,
): string {
  if (keys.length === 0) throw new Error("At least one signing key is required.");
  return keys.map((key) => signatureValue(key, id, timestamp, body)).join(" ");
}

export function webhookSignedHeaders(input: {
  keys: readonly Uint8Array[];
  eventId: string;
  eventType: string;
  deliveryId: string;
  attempt: number;
  timestamp: number;
  body: string;
}): Record<string, string> {
  return {
    "content-type": "application/json",
    "user-agent": "wssp-webhooks/1",
    "webhook-id": input.eventId,
    "webhook-timestamp": String(input.timestamp),
    "webhook-signature": signatureHeader(input.keys, input.eventId, input.timestamp, input.body),
    "wssp-event-type": input.eventType,
    "wssp-delivery-id": input.deliveryId,
    "wssp-delivery-attempt": String(input.attempt),
  };
}
