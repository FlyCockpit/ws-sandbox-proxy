import { createEnv } from "@t3-oss/env-core";
import { isWeakSecret } from "./secret-strength.js";
import { env as sharedEnv } from "./shared.js";
import { serverVars } from "./vars/server.js";
import { webVars } from "./vars/web.js";

// ---------------------------------------------------------------------------
// Full server environment.
//
// `extends: [sharedEnv]` merges in everything ./shared.ts already validated
// (database, redis, S3, translation) so server-side code keeps seeing a
// single `env` with every field. This module adds only the server-only
// variables and the startup guards that depend on them. The worker never
// imports this file, so a worker-only deployment is not required to set
// BETTER_AUTH_URL, BETTER_AUTH_SECRET, the rate-limit knobs, etc.
//
// The variable declarations themselves live in ./vars/server.ts — a
// side-effect-free module, so `pnpm env:check` can read the key set without
// running the startup guards below. Declare new variables there, never inline
// in the `createEnv` call.
//
// Disjointness contract: no key declared in ./vars/server.ts may also appear in
// ./vars/shared.ts — `extends` merges, it does not allow overriding.
// ---------------------------------------------------------------------------

export const env = createEnv({
  extends: [sharedEnv],
  server: serverVars,
  runtimeEnv: process.env,
  emptyStringAsUndefined: true,
});

// ---------------------------------------------------------------------------
// Admin emails — parsed once at startup into a Set for O(1) lookups.
// ---------------------------------------------------------------------------
export const ADMIN_EMAILS: Set<string> = new Set(
  (env.ADMIN_EMAILS ?? "")
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean),
);

export const SIGNUP_ENABLED: boolean = env.SIGNUP_ENABLED;

// Server-side display name (defaults to WS Sandbox Proxy). VITE_APP_NAME is
// declared exactly once — in ./vars/web.ts (the one-surface rule in scripts/lib/env-schema.ts forbids
// re-declaring it here) — but the server needs it too (seo.ts renders it into
// /llms.txt, and the Docker image carries it as a runtime ENV). This helper
// validates the raw runtime value against that same canonical schema instead
// of reading process.env inline, so an overlong/mistyped value fails fast at
// boot like every other env var instead of shipping into public SEO files.
// Empty string counts as unset: the Dockerfile defaults the build arg to ""
// and always exports the ENV, so "" is the common "not configured" shape.
export function resolveAppName(raw: string | undefined = process.env.VITE_APP_NAME): string {
  return webVars.VITE_APP_NAME.parse(raw || undefined) ?? "WS Sandbox Proxy";
}

// ---------------------------------------------------------------------------
// BETTER_AUTH_SECRET entropy check — catch weak/placeholder secrets early.
// ---------------------------------------------------------------------------
const weakReason = isWeakSecret(env.BETTER_AUTH_SECRET);
if (weakReason) {
  const msg =
    `[env] BETTER_AUTH_SECRET is weak: ${weakReason}. ` +
    "Generate a strong secret with: pnpm generate:secret";
  if (env.NODE_ENV === "production") {
    throw new Error(msg);
  }
  console.warn(msg);
}

if (env.BETTER_AUTH_SECRET_PREVIOUS) {
  if (env.BETTER_AUTH_SECRET_PREVIOUS === env.BETTER_AUTH_SECRET) {
    throw new Error(
      "[env] BETTER_AUTH_SECRET_PREVIOUS must differ from BETTER_AUTH_SECRET; unset it or set the old secret",
    );
  }
  const previousWeakReason = isWeakSecret(env.BETTER_AUTH_SECRET_PREVIOUS);
  if (previousWeakReason) {
    // docs/operations/production-hardening.md § Password pepper.
    const msg = `[env] BETTER_AUTH_SECRET_PREVIOUS is weak: ${previousWeakReason}. Use the old secret only while rotating; see Password pepper in the production hardening guide.`;
    if (env.NODE_ENV === "production") throw new Error(msg);
    console.warn(msg);
  }
}

// Admin lockout guard. The only in-app path to a NEW admin account is the
// email/password bootstrap signup for addresses in ADMIN_EMAILS, and
// SIGNUP_ENABLED=false blocks every user creation. Signup-disabled + empty
// ADMIN_EMAILS is therefore a lockout risk on a FRESH deploy, but a healthy
// shape for a provisioned one whose admins already persist in the database
// (clearing the bootstrap allowlist after provisioning is expected). This
// module cannot see the database at import time, so it must not refuse the
// boot here — that would brick every provisioned install that drops the
// allowlist. Warn in every environment so a fresh deploy still notices; the
// deploy stays up so existing admins can sign in. Fresh install with no
// admin yet: set SETUP_KEY and run `pnpm deploy:generate-admin` (no email
// needed), set ADMIN_EMAILS to a comma-separated list of operator emails, or
// set SIGNUP_ENABLED=true (requires SMTP). A set SETUP_KEY is a bootstrap
// path, so it silences this.
if (ADMIN_EMAILS.size === 0 && !SIGNUP_ENABLED && !env.SETUP_KEY) {
  console.warn(
    "[env] SIGNUP_ENABLED=false and ADMIN_EMAILS is empty — no NEW admin can " +
      "be bootstrapped: with signup disabled no account can be created, and " +
      "the admin-bootstrap signup path requires an address in ADMIN_EMAILS. " +
      "If this is a fresh install with no admin yet, set SETUP_KEY and run " +
      "`pnpm deploy:generate-admin` (no email needed), set ADMIN_EMAILS to a " +
      "comma-separated list of operator emails, or set SIGNUP_ENABLED=true " +
      "(requires SMTP) to allow public registration. If admins already exist " +
      "in the database, this warning is expected and safe to ignore.",
  );
} else if (ADMIN_EMAILS.size === 0 && !env.SETUP_KEY && env.NODE_ENV === "production") {
  console.warn(
    "[env] ADMIN_EMAILS is empty — no users will have admin privileges. " +
      "Set ADMIN_EMAILS in your environment to grant admin access.",
  );
}

// SETUP_KEY opens POST /api/setup/admin, the email-free first-admin bootstrap
// (apps/server/src/setup-routes.ts). It is a credential: the same entropy bar
// as the other secrets, and a standing reminder to remove it — the route
// refuses once an administrator exists, but an unused key is still one more
// secret lying around.
if (env.SETUP_KEY) {
  const setupKeyWeakReason = isWeakSecret(env.SETUP_KEY);
  if (setupKeyWeakReason) {
    const msg =
      `[env] SETUP_KEY is weak: ${setupKeyWeakReason}. ` +
      "Generate a strong key with: pnpm generate:secret";
    if (env.NODE_ENV === "production") {
      throw new Error(msg);
    }
    console.warn(msg);
  }
  console.warn(
    "[env] SETUP_KEY is set: the first-admin setup route is open until an administrator " +
      "exists. Remove SETUP_KEY once the first admin has signed in.",
  );
}

const vapidMissing: string[] = [];
if (!env.VAPID_PUBLIC_KEY) vapidMissing.push("VAPID_PUBLIC_KEY");
if (!env.VAPID_PRIVATE_KEY) vapidMissing.push("VAPID_PRIVATE_KEY");
if (!env.VAPID_SUBJECT) vapidMissing.push("VAPID_SUBJECT");
if (vapidMissing.length > 0 && vapidMissing.length < 3) {
  const msg =
    `[env] Web push is partially configured — missing ${vapidMissing.join(", ")}. ` +
    "Set all three of VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, and VAPID_SUBJECT " +
    "(generate a keypair with: pnpm generate:vapid), or unset them all to ship push inert.";
  if (env.NODE_ENV === "production") {
    throw new Error(msg);
  }
  console.warn(msg);
}

if (env.SMTP_HOST && !env.SMTP_FROM) {
  const msg =
    "[env] SMTP_HOST is set but SMTP_FROM is not. Outgoing email needs an explicit " +
    'From: address — set SMTP_FROM (e.g. "App Name <no-reply@yourdomain.com>").';
  if (env.NODE_ENV === "production") {
    throw new Error(msg);
  }
  console.warn(msg);
}

if (env.NODE_ENV === "production") {
  if (env.BETTER_AUTH_URL.startsWith("http:")) {
    throw new Error(
      "[env] BETTER_AUTH_URL must use https in production (it drives secure cookies and the canonical SEO origin).",
    );
  }
  if (env.CORS_ORIGIN?.startsWith("http:")) {
    throw new Error("[env] CORS_ORIGIN must use https in production.");
  }
  if (env.PUBLIC_APP_URL?.startsWith("http:")) {
    throw new Error("[env] PUBLIC_APP_URL must use https in production.");
  }
}

if (SIGNUP_ENABLED && !env.SMTP_HOST) {
  const msg =
    "[env] SIGNUP_ENABLED=true but SMTP_HOST is not configured. " +
    "Better-Auth enforces email verification on signup, so the first user to " +
    "register will hit a runtime error when the verification email tries to send. " +
    "Set SMTP_HOST/SMTP_PORT/SMTP_FROM (and SMTP_USER/SMTP_PASS if your provider " +
    "requires auth), or set SIGNUP_ENABLED=false until SMTP is wired up.";
  if (env.NODE_ENV === "production") {
    throw new Error(msg);
  }
  console.warn(msg);
}
