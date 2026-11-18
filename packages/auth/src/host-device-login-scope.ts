import { hostSlugFromDeviceLoginScope } from "@wssp/config/host-device-login";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { admin } from "better-auth/plugins";

/**
 * `onDeviceAuthRequest` for the deviceAuthorization plugin. `wssp host enroll` is the
 * only device-flow client and every request must name exactly one host slug
 * (`scope = "host-slug:<slug>"`), so the approval page can show what approving
 * authorizes and the exchange can mint for that slug only.
 */
export function requireHostDeviceLoginScope(clientId: string, scope: string | undefined): void {
  if (clientId.length > 64 || clientId !== "wssp") {
    throw new APIError("BAD_REQUEST", {
      error: "invalid_client",
      error_description: "Invalid client ID",
    });
  }
  if (hostSlugFromDeviceLoginScope(scope) !== null) return;
  throw new APIError("BAD_REQUEST", {
    error: "invalid_scope",
    error_description:
      "Device authorization must name one host slug as `host-slug:<slug>`; upgrade wssp.",
  });
}

/**
 * Better Auth paths turned off with `disabledPaths` (404 before any handler
 * runs). `/device/token` would redeem an approved `wssp host enroll` code for a full
 * browser session (Better Auth's RFC 8628 token endpoint), which is not what
 * the approval page describes. The only redemption is
 * `hostCredentials.exchangeDeviceCode`, which mints the one device credential
 * the approver saw.
 */
export const DISABLED_DEVICE_AUTHORIZATION_PATHS: readonly string[] = [
  "/device/token",
  "/device",
  "/device/approve",
  "/device/deny",
];

/** Every user-deleting endpoint in Better Auth 1.7.1 (C21-12): oRPC `users.remove`
 * (`requestAccountDeletion`) is the only deletion path. The anonymous plugin's
 * `/delete-anonymous-user` is not mounted. */
const DISABLED_USER_DELETION_PATHS: readonly string[] = [
  "/delete-user",
  "/delete-user/callback",
  "/admin/remove-user",
];

// Derive the inventory from the pinned plugin so new endpoints fail closed too.
const DISABLED_ADMIN_HTTP_PATHS = Object.values(admin().endpoints).map((endpoint) => endpoint.path);

export const DISABLED_BETTER_AUTH_PATHS: readonly string[] = [
  ...DISABLED_DEVICE_AUTHORIZATION_PATHS,
  ...DISABLED_USER_DELETION_PATHS,
  ...DISABLED_ADMIN_HTTP_PATHS,
];

/** Reject even an empty/pre-bound user_id before Better Auth persists issuance. */
export const deviceIssuanceGuard = createAuthMiddleware(async (ctx) => {
  if (ctx.path === "/device/code" && ctx.body && Object.hasOwn(ctx.body, "user_id")) {
    throw new APIError("BAD_REQUEST", {
      error: "invalid_request",
      error_description: "user_id is not allowed",
    });
  }
});

export function deviceVerificationUri(apiOrigin: string, webOrigin?: string): string {
  return new URL("/device", webOrigin || apiOrigin).href;
}
