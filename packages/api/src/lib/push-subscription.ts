import { ORPCError } from "@orpc/server";
import prisma from "@wssp/db";
import { z } from "zod";
import { isPrismaUniqueViolation } from "./prisma-errors";

/**
 * Shared Zod schema for a push-subscription payload.
 *
 * Used by both the `push.subscribe` oRPC procedure and the dedicated
 * `POST /sw/push-renew` HTTP endpoint that the service worker calls when the
 * browser rotates VAPID keys (`pushsubscriptionchange`). Keeping the shape in
 * one place prevents the two call sites from drifting.
 */
const allowedPushServiceHostSuffixes = [
  "fcm.googleapis.com",
  "android.googleapis.com",
  "updates.push.services.mozilla.com",
  "web.push.apple.com",
  "push.apple.com",
  "notify.windows.com",
];

export const pushEndpointSchema = z
  .string()
  .url()
  .refine((value) => isAllowedPushEndpoint(value), {
    message: "Push endpoint must be an HTTPS browser push service URL.",
  });

/** Stored-size bounds for a subscribe/renew body. A P-256 public key is 65
 * bytes (87 base64url chars) and the auth secret 16 bytes (22 chars); the caps
 * leave room for padding without letting a client store arbitrary text. The
 * alphabet admits standard base64 too: the service worker's renewal path
 * (`apps/web/src/sw.ts`) encodes the keys with `btoa`. */
export const PUSH_ENDPOINT_MAX_LENGTH = 2048;
const base64Key = (max: number) =>
  z
    .string()
    .max(max)
    .regex(/^[A-Za-z0-9+/_-]*={0,2}$/, { message: "Must be base64url." });

/** Endpoints one user may keep. A new endpoint past it evicts the user's
 * oldest subscriptions: browsers rotate endpoints without unregistering the
 * old one, and users cannot list or delete stale rows, so refusing would lock
 * them out of push for good. Soft under concurrency: parallel registrations
 * can briefly exceed it by the number racing. */
export const MAX_PUSH_SUBSCRIPTIONS_PER_USER = 20;

export const pushSubscriptionInputSchema = z.object({
  endpoint: z.string().max(PUSH_ENDPOINT_MAX_LENGTH).pipe(pushEndpointSchema),
  keys: z.object({
    p256dh: base64Key(128),
    auth: base64Key(64),
  }),
});

export type PushSubscriptionInput = z.infer<typeof pushSubscriptionInputSchema>;

function endpointTaken() {
  return new ORPCError("CONFLICT", {
    message: "Push subscription endpoint is already registered to another user.",
  });
}

/**
 * Upsert a web-push subscription for the given user.
 *
 * Endpoint is the natural primary key. The same user can refresh keys for an
 * existing endpoint, but another user cannot claim it by submitting the same
 * endpoint. A concurrent create of the same endpoint (P2002) is re-read and
 * resolved the same way; a row deleted between the read and the key refresh
 * retries once, as a create. Refreshes are scoped to the same owner even if
 * another user registers a replacement between the read and the write.
 */
export async function upsertPushSubscription(userId: string, input: PushSubscriptionInput) {
  const keys = { p256dh: input.keys.p256dh, auth: input.keys.auth };
  for (let attempt = 0; ; attempt++) {
    const existing = await prisma.pushSubscription.findUnique({
      where: { endpoint: input.endpoint },
      select: { userId: true },
    });

    if (existing && existing.userId !== userId) throw endpointTaken();

    if (existing) {
      const refreshed = await prisma.pushSubscription.updateMany({
        where: { endpoint: input.endpoint, userId },
        data: keys,
      });
      if (refreshed.count === 1) return;
      if (attempt === 0) continue;
      throw subscriptionChanged();
    }

    const count = await prisma.pushSubscription.count({ where: { userId } });
    if (count >= MAX_PUSH_SUBSCRIPTIONS_PER_USER) {
      const oldest = await prisma.pushSubscription.findMany({
        where: { userId },
        orderBy: [{ createdAt: "asc" }, { id: "asc" }],
        take: count - MAX_PUSH_SUBSCRIPTIONS_PER_USER + 1,
        select: { id: true },
      });
      await prisma.pushSubscription.deleteMany({
        where: { userId, id: { in: oldest.map((row) => row.id) } },
      });
    }

    try {
      await prisma.pushSubscription.create({
        data: { endpoint: input.endpoint, ...keys, userId },
      });
      return;
    } catch (error) {
      if (!isPrismaUniqueViolation(error)) throw error;
    }
    // Lost a concurrent create of the same endpoint: the winner decides.
    const winner = await prisma.pushSubscription.findUnique({
      where: { endpoint: input.endpoint },
      select: { userId: true },
    });
    if (winner && winner.userId !== userId) throw endpointTaken();
    if (winner) {
      const refreshed = await prisma.pushSubscription.updateMany({
        where: { endpoint: input.endpoint, userId },
        data: keys,
      });
      if (refreshed.count === 1) return;
    }
    // The winning row vanished again before it could be refreshed.
    if (attempt > 0) throw subscriptionChanged();
  }
}

function subscriptionChanged() {
  return new ORPCError("CONFLICT", {
    message: "Push subscription changed. Retry the request.",
  });
}

function isAllowedPushEndpoint(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }

  if (url.protocol !== "https:") return false;
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (isBlockedEndpointHost(hostname)) return false;
  return allowedPushServiceHostSuffixes.some(
    (suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`),
  );
}

function isBlockedEndpointHost(hostname: string): boolean {
  if (hostname === "localhost" || hostname.endsWith(".localhost")) return true;
  if (hostname.startsWith("[") || hostname.endsWith("]")) return true;
  return isPrivateIpv4(hostname);
}

function isPrivateIpv4(hostname: string): boolean {
  const parts = hostname.split(".").map((part) => Number.parseInt(part, 10));
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return false;
  }
  const a = parts[0];
  const b = parts[1];
  if (a === undefined || b === undefined) return true;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224
  );
}
