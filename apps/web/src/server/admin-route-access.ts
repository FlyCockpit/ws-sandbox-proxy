import { createServerFn } from "@tanstack/react-start";
import { getRequestHeaders } from "@tanstack/react-start/server";
import type { AdminGateSession } from "@wssp/api/lib/sensitive-session-two-factor-gate";

import type { AdminRouteResolution } from "@/lib/route-session-access";

import { toRouteSession } from "./auth-session";

type BetterAuthAdminSession = Parameters<typeof toRouteSession>[0] & AdminGateSession;

type GetSession = (context: { headers: Headers }) => Promise<BetterAuthAdminSession | null>;
type AuthorizeAdminSession = (session: AdminGateSession) => Promise<boolean>;

/**
 * Server-side probe for the `/admin` route guard. It resolves the cookie
 * session and asks `isAdminSessionAuthorized` — the one gate the oRPC admin
 * procedures and the Hono API-reference gate use — so a page render and a
 * direct RPC/HTTP call always agree on who is hidden from. Bearer headers are
 * stripped: machine credentials never authorize browser administration.
 */
export const getRouteAdminAccess = createServerFn({ method: "GET" }).handler(
  async (): Promise<AdminRouteResolution> => {
    const [{ auth }, { isAdminSessionAuthorized }] = await Promise.all([
      import("@wssp/auth"),
      import("@wssp/api/lib/sensitive-session-two-factor-gate"),
    ]);
    return resolveAdminRouteAccess(
      getRequestHeaders(),
      auth.api.getSession as GetSession,
      (session) => isAdminSessionAuthorized(session),
    );
  },
);

export async function resolveAdminRouteAccess(
  headers: Headers,
  getSession: GetSession,
  authorize: AuthorizeAdminSession,
): Promise<AdminRouteResolution> {
  try {
    const cookieOnly = new Headers(headers);
    cookieOnly.delete("authorization");
    const session = await getSession({ headers: cookieOnly });
    if (!session) return { status: "resolved", session: null, authorized: false };
    const authorized = await authorize(session);
    return { status: "resolved", session: toRouteSession(session), authorized };
  } catch {
    return { status: "error" };
  }
}
