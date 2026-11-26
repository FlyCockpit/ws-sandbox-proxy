import { createServerFn } from "@tanstack/react-start";
import { getRequestHeaders } from "@tanstack/react-start/server";

import {
  failedRouteSessionResolution,
  type ProtectedRouteSessionResolution,
  type RouteSession,
  type RouteSessionResolution,
  resolvedRouteSession,
} from "@/lib/route-session-access";
import { clientReadableForcedTwoFactorSettings } from "@/utils/two-factor-policy";

type BetterAuthRouteSession = {
  user: {
    id: string;
    name: string;
    email: string;
    emailVerified: boolean;
    role?: string | null;
    twoFactorEnabled?: boolean | null;
    createdAt?: Date | string | number | null;
  };
};

type GetBetterAuthSession = (context: {
  headers: Headers;
}) => Promise<BetterAuthRouteSession | null>;

/**
 * Server-backed session probe for TanStack route guards.
 *
 * The app branch remains client-rendered, but route access decisions call this
 * server function so navigation uses the canonical Better Auth instance and
 * request cookies instead of browser-side session probes. It resolves to a
 * {@link RouteSessionResolution} — a lookup failure becomes an `error`
 * resolution the pure access decisions turn into a retryable route error,
 * never a silent logout or fake 404. The returned projection omits
 * token-bearing session fields; operations still authorize independently at
 * the oRPC/Hono boundary.
 */
export const getRouteSession = createServerFn({ method: "GET" }).handler(
  async (): Promise<RouteSessionResolution> => {
    const { auth } = await import("@wssp/auth");
    return resolveRouteSessionFromAuth(getRequestHeaders(), auth.api.getSession);
  },
);

/**
 * The `_auth` layout's guard: the route session plus, for a signed-in visitor
 * only, the client-readable force-2FA settings the layout's enrollment
 * takeover needs — in ONE round trip, so the dashboard no longer waits on
 * session → `settings.getAll` → page data. The settings come from the same
 * server helper the oRPC 2FA gates read (`getForcedTwoFactorSettingsRecord`),
 * so the takeover and the procedures cannot disagree. Likewise whether an
 * admin-set temporary password must be replaced first, read from the user row.
 */
export const getProtectedRouteSession = createServerFn({ method: "GET" }).handler(
  async (): Promise<ProtectedRouteSessionResolution> => {
    const { auth } = await import("@wssp/auth");
    return resolveProtectedRouteSessionFromAuth(
      getRequestHeaders(),
      auth.api.getSession,
      async () => {
        const { getForcedTwoFactorSettingsRecord } = await import(
          "@wssp/api/lib/two-factor-policy"
        );
        return getForcedTwoFactorSettingsRecord();
      },
      async (userId) => {
        // The same user row the oRPC gates read (`sensitiveSessionRefusal`).
        const { loadSensitiveSessionGateUser } = await import(
          "@wssp/api/lib/sensitive-session-two-factor-gate"
        );
        return (await loadSensitiveSessionGateUser(userId))?.mustChangePassword === true;
      },
    );
  },
);

/**
 * Same authorization as `settings.getAll` (`authenticatedProcedure`): an
 * anonymous request gets no settings and never triggers the read, and a
 * signed-in one gets only the client-readable force-2FA keys. A failed
 * settings read is an `error` resolution (a retryable route error), never a
 * session without settings — the layout must not render protected content
 * before it can decide the forced-2FA and password-change takeovers.
 */
export async function resolveProtectedRouteSessionFromAuth(
  headers: Headers,
  getSession: GetBetterAuthSession,
  loadForcedTwoFactorSettings: () => Promise<Readonly<Record<string, string | undefined>>>,
  loadPasswordChangeRequired: (userId: string) => Promise<boolean>,
): Promise<ProtectedRouteSessionResolution> {
  const resolution = await resolveRouteSessionFromAuth(headers, getSession);
  if (resolution.status === "error") return resolution;
  if (!resolution.session) return { status: "resolved", session: null };
  try {
    const [settings, passwordChangeRequired] = await Promise.all([
      loadForcedTwoFactorSettings(),
      loadPasswordChangeRequired(resolution.session.user.id),
    ]);
    return {
      status: "resolved",
      session: resolution.session,
      forcedTwoFactorSettings: clientReadableForcedTwoFactorSettings(settings),
      passwordChangeRequired,
    };
  } catch {
    return { status: "error" };
  }
}

/**
 * Better-Auth's session cookie names: `PREFIX.session_token`, with
 * `__Secure-` added when cookies are secure. The prefix is Better-Auth's
 * default because this app sets no `advanced.cookiePrefix`; if you set one,
 * update this list along with `apps/server/src/ssr-cache.ts` and
 * `apps/server/src/two-factor-otp-limit.ts`.
 */
const SESSION_TOKEN_COOKIES = new Set([
  "__Secure-better-auth.session_token",
  "better-auth.session_token",
]);

/**
 * True when the Cookie header carries a non-empty Better-Auth session token.
 * Presence only: the token is never read for meaning or validated here.
 */
export function hasSessionTokenCookie(cookieHeader: string | null | undefined): boolean {
  if (!cookieHeader) return false;
  return cookieHeader.split(";").some((pair) => {
    const eq = pair.indexOf("=");
    if (eq === -1) return false;
    return SESSION_TOKEN_COOKIES.has(pair.slice(0, eq).trim()) && pair.slice(eq + 1).trim() !== "";
  });
}

/**
 * Cheap "is this visitor probably signed in?" hint for public pages (the
 * landing redirect and the public header's "Open app", lib/session-hint.ts).
 *
 * It checks only whether the session cookie exists: no database lookup, and
 * no Better-Auth import on the public render path. That makes it a hint for
 * where to send someone, and **never** an access check. A stale or forged
 * cookie just sends the visitor to the signed-in home, whose `_auth` gate does
 * the real check and sends them to login. Do not use this to show or hide
 * data; use a route guard (`resolveRouteSession()`, lib/route-session.ts) or a
 * procedure for that.
 *
 * Cache safety: `apps/server/src/ssr-cache.ts` never caches a request that
 * carries a Better-Auth cookie, so a page rendered from this hint is never
 * replayed to an anonymous visitor.
 */
export const getSessionCookieHint = createServerFn({ method: "GET" }).handler(
  async (): Promise<boolean> => hasSessionTokenCookie(getRequestHeaders().get("cookie")),
);

export async function resolveRouteSessionFromAuth(
  headers: Headers,
  getSession: GetBetterAuthSession,
): Promise<RouteSessionResolution> {
  try {
    const session = await getSession({ headers });
    return resolvedRouteSession(toRouteSession(session));
  } catch {
    return failedRouteSessionResolution();
  }
}

export function toRouteSession(session: BetterAuthRouteSession | null): RouteSession | null {
  if (!session) return null;

  return {
    user: {
      id: session.user.id,
      name: session.user.name,
      email: session.user.email,
      emailVerified: session.user.emailVerified,
      role: session.user.role,
      twoFactorEnabled: session.user.twoFactorEnabled,
      createdAt: toEpochMs(session.user.createdAt),
    },
  };
}

/**
 * Normalize `User.createdAt` to epoch milliseconds so the projection survives
 * `createServerFn` serialization. An unreadable value becomes `null`, which
 * the forced-2FA grace window treats as "no grace" (fail closed).
 */
function toEpochMs(value: Date | string | number | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  const ms = value instanceof Date ? value.getTime() : new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}
