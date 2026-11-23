import { isAdminRole } from "@wssp/auth/roles";

import {
  type ForcedTwoFactorSettings,
  type TwoFactorPolicySessionUser,
  twoFactorEnrollmentState,
} from "../utils/two-factor-policy";

type RouteSessionUser = {
  id: string;
  name: string;
  email: string;
  emailVerified: boolean;
  role?: string | null;
  twoFactorEnabled?: boolean | null;
  /**
   * `User.createdAt` as epoch milliseconds (`null` when unreadable). Carried
   * as a number, not a `Date`, because this projection crosses the
   * `createServerFn` serialization boundary. The forced-2FA enrollment grace
   * window is measured from it — see `apps/web/src/utils/two-factor-policy.ts`.
   */
  createdAt: number | null;
};

export type RouteSession = {
  user: RouteSessionUser;
};

export type RouteSessionResolution =
  | { status: "resolved"; session: RouteSession | null }
  | { status: "error" };

/**
 * What the `_auth` guard's single server round trip resolves: the route-safe
 * session and, only for a signed-in visitor, the client-readable force-2FA
 * settings (the keys `settings.getAll` serves an authenticated caller).
 * Carrying both lets the layout decide its forced-2FA takeover before any
 * protected page renders, without a second request.
 */
export type ProtectedRouteSessionResolution =
  | { status: "resolved"; session: null }
  | {
      status: "resolved";
      session: RouteSession;
      forcedTwoFactorSettings: ForcedTwoFactorSettings;
      /**
       * The account still has an admin-set temporary password. Read from the
       * user row, not the cookie-cached session, so the takeover ends as soon
       * as the password is replaced.
       */
      passwordChangeRequired: boolean;
    }
  | { status: "error" };

export type ProtectedRouteDecision =
  | {
      kind: "allow";
      session: RouteSession;
      forcedTwoFactorSettings: ForcedTwoFactorSettings;
      passwordChangeRequired: boolean;
    }
  | { kind: "redirect-to-login" }
  | { kind: "error" };

export type AnonymousOnlyRouteDecision =
  | { kind: "allow" }
  | { kind: "redirect-authenticated"; session: RouteSession }
  | { kind: "error" };

export type AdminRouteDecision =
  | { kind: "allow"; session: RouteSession }
  | { kind: "not-found" }
  | { kind: "error" };

export type RootLandingDecision = { kind: "dashboard" } | { kind: "landing" };

export type DeviceRouteDecision =
  | { kind: "allow"; session: RouteSession }
  | { kind: "redirect-to-login" }
  | { kind: "redirect-to-security" }
  | { kind: "error" };

export function resolvedRouteSession(session: RouteSession | null): RouteSessionResolution {
  return { status: "resolved", session };
}

export function failedRouteSessionResolution(): RouteSessionResolution {
  return { status: "error" };
}

/**
 * Gate for the ordinary authenticated app (`_auth`: dashboard, settings).
 *
 * Deliberately checks only "is there a session" — NOT `emailVerified`, which
 * the admin gate (server-side, see `decideAdminRouteAccess`) does check. That asymmetry is the product's
 * stance, not an oversight: **verification gates privilege escalation, not
 * basic use.** It mirrors the server, which is where the real boundary lives —
 * `protectedProcedure` has no verification check either, only the shared
 * admin gate `isAdminSessionAuthorized` does.
 * A guard here is UX; adding a check the procedures don't enforce would be
 * theater.
 *
 * Unverified sessions are reachable in practice, so this is load-bearing:
 * `requireEmailVerification` only governs email/password sign-in.
 *
 * If a deployment requires verification for all access, do NOT just add the
 * check — returning `redirect-to-login` for an unverified session bounces off
 * `decideAnonymousOnlyRouteAccess` (which redirects any authenticated visitor
 * back) and loops forever. See docs/operations/production-hardening.md §
 * "Who email verification gates" for the change that works.
 */
export function decideProtectedRouteAccess(
  resolution: ProtectedRouteSessionResolution,
): ProtectedRouteDecision {
  if (resolution.status === "error") return { kind: "error" };
  if (!resolution.session) return { kind: "redirect-to-login" };
  return {
    kind: "allow",
    session: resolution.session,
    forcedTwoFactorSettings: resolution.forcedTwoFactorSettings,
    passwordChangeRequired: resolution.passwordChangeRequired,
  };
}

export function decideAnonymousOnlyRouteAccess(
  resolution: RouteSessionResolution,
): AnonymousOnlyRouteDecision {
  if (resolution.status === "error") return { kind: "error" };
  if (!resolution.session) return { kind: "allow" };
  return { kind: "redirect-authenticated", session: resolution.session };
}

/**
 * Gate for `/$lang/device`: owner enrollment requires a signed-in, verified
 * account that satisfies forced 2FA (same bar as sensitive browser procedures).
 */
export function decideDeviceRouteAccess(
  resolution: RouteSessionResolution,
  forcedTwoFactorSettings: ForcedTwoFactorSettings,
): DeviceRouteDecision {
  if (resolution.status === "error") return { kind: "error" };
  if (!resolution.session) return { kind: "redirect-to-login" };
  const user = resolution.session.user;
  if (!user.emailVerified) return { kind: "redirect-to-security" };
  if (twoFactorEnrollmentState(forcedTwoFactorSettings, user).status === "blocked") {
    return { kind: "redirect-to-security" };
  }
  return { kind: "allow", session: resolution.session };
}

/**
 * What the `/admin` guard learned on the server: the route-safe session plus
 * the verdict of `isAdminSessionAuthorized` — the SAME function the oRPC admin
 * procedures and the Hono admin gate call (`server/admin-route-access.ts`).
 * The browser never re-derives the admin decision from a cookie-cached
 * session, so the page and the API cannot disagree about who sees the area.
 */
export type AdminRouteResolution =
  | { status: "resolved"; session: RouteSession | null; authorized: boolean }
  | { status: "error" };

/**
 * Gate for the whole `/admin` tree. Everyone the server gate refuses —
 * anonymous, non-admin, unverified, banned, revoked session, or an admin whose
 * forced-2FA grace has lapsed — gets the router's ordinary not-found, never an
 * "access denied" that would reveal the area exists. A lookup failure is a
 * retryable route error, not a 404.
 */
export function decideAdminRouteAccess(resolution: AdminRouteResolution): AdminRouteDecision {
  if (resolution.status === "error") return { kind: "error" };
  if (!resolution.session || !resolution.authorized) return { kind: "not-found" };
  return { kind: "allow", session: resolution.session };
}

type AdminNavigationUser = TwoFactorPolicySessionUser & { emailVerified?: boolean | null };

/**
 * Whether shell navigation (header, bottom nav, user menu) offers the admin
 * area. A browser-side mirror of the server gate built from the session and
 * the public force-2FA settings: it omits the link for non-admins, unverified
 * admins and admins locked out by forced 2FA, and while settings are still
 * unknown. It is UX only — a stale cookie cache can briefly disagree, and the
 * route guard above (server-authoritative) still renders a plain not-found.
 */
export function showsAdminNavigation(
  user: AdminNavigationUser | null | undefined,
  forcedTwoFactorSettings: ForcedTwoFactorSettings | undefined,
  now: number = Date.now(),
): boolean {
  if (user?.emailVerified !== true || !isAdminRole(user.role)) return false;
  if (!forcedTwoFactorSettings) return false;
  return twoFactorEnrollmentState(forcedTwoFactorSettings, user, now).status !== "blocked";
}

/**
 * The public root (`/$lang/`): a signed-in visitor goes to the dashboard; an
 * anonymous visitor sees the landing page. A failed session lookup also shows
 * the landing page: the public page must never become an error screen, and
 * every dashboard route re-runs its own gate anyway.
 */
export function decideRootLanding(resolution: RouteSessionResolution): RootLandingDecision {
  if (resolution.status === "resolved" && resolution.session) return { kind: "dashboard" };
  return { kind: "landing" };
}

/**
 * Redirect options for a gate that sends an anonymous visitor to sign in. The
 * intended route (the full in-app href: locale path, search and hash) rides in
 * `redirectTo`, and `safeRedirectTo` on the login page returns there after
 * sign-in. Every protected route builds its login redirect here.
 */
export function loginRedirect(lang: string, href: string) {
  return {
    to: "/$lang/login" as const,
    params: { lang },
    search: { redirectTo: href },
  };
}
