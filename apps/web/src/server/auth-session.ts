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
 * so the takeover and the procedures cannot disagree.
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
    );
  },
);

/**
 * Same authorization as `settings.getAll` (`authenticatedProcedure`): an
 * anonymous request gets no settings and never triggers the read, and a
 * signed-in one gets only the client-readable force-2FA keys. A failed
 * settings read is an `error` resolution (a retryable route error), never a
 * session without settings — the layout must not render protected content
 * before it can decide the forced-2FA takeover.
 */
export async function resolveProtectedRouteSessionFromAuth(
  headers: Headers,
  getSession: GetBetterAuthSession,
  loadForcedTwoFactorSettings: () => Promise<Readonly<Record<string, string | undefined>>>,
): Promise<ProtectedRouteSessionResolution> {
  const resolution = await resolveRouteSessionFromAuth(headers, getSession);
  if (resolution.status === "error") return resolution;
  if (!resolution.session) return { status: "resolved", session: null };
  try {
    const forcedTwoFactorSettings = clientReadableForcedTwoFactorSettings(
      await loadForcedTwoFactorSettings(),
    );
    return { status: "resolved", session: resolution.session, forcedTwoFactorSettings };
  } catch {
    return { status: "error" };
  }
}

/**
 * Session probe for the public root (`/$lang/`), which sends a signed-in
 * visitor to the dashboard. Public pages stay static for anonymous visitors:
 * without a Better Auth cookie this resolves to "no session" without loading
 * the auth module or touching the database, so anonymous SSR output (and the
 * server's anonymous SSR cache, which is bypassed whenever the same cookie is
 * present) is unchanged.
 */
export const getRootLandingSession = createServerFn({ method: "GET" }).handler(
  async (): Promise<RouteSessionResolution> => {
    const headers = getRequestHeaders();
    return resolveRootLandingSession(headers, async (context) => {
      const { auth } = await import("@wssp/auth");
      return auth.api.getSession(context);
    });
  },
);

/**
 * Whether a request can carry a Better Auth session. Substring match on the
 * whole Cookie header, like the server's SSR cache bypass
 * (`hasAuthSessionCookie` in apps/server/src/ssr-cache.ts): a false positive
 * only costs one session lookup, a false negative would show the landing page.
 */
export function mayCarryAuthSession(cookieHeader: string | null): boolean {
  return cookieHeader?.includes("better-auth") ?? false;
}

export async function resolveRootLandingSession(
  headers: Headers,
  getSession: GetBetterAuthSession,
): Promise<RouteSessionResolution> {
  if (!mayCarryAuthSession(headers.get("cookie"))) return resolvedRouteSession(null);
  return resolveRouteSessionFromAuth(headers, getSession);
}

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
