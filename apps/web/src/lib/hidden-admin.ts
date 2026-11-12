import { notFound } from "@tanstack/react-router";

import { type AdminRouteResolution, decideAdminRouteAccess } from "./route-session-access";

/**
 * Where a hidden admin page renders its not-found state: the `$lang` layout,
 * the same boundary that renders a genuinely unknown URL such as
 * `/en-US/definitely-not-a-page`. Rendering it there (not inside the `_app`
 * shell) keeps the two pages identical, header included.
 */
export const HIDDEN_ROUTE_NOT_FOUND_ID = "/$lang" as const;

const ADMIN_ROUTE_ID = "/$lang/_app/admin";

/**
 * Whether the router matched the admin subtree. Decided from the router's own
 * matches, not by re-parsing the pathname: the router matches paths
 * case-insensitively and decodes them, so `/en-US/ADMIN/users` renders the
 * admin tree and must be hidden the same way.
 */
export function isAdminRouteMatch(matches: ReadonlyArray<{ routeId: string }>): boolean {
  return matches.some(
    ({ routeId }) => routeId === ADMIN_ROUTE_ID || routeId.startsWith(`${ADMIN_ROUTE_ID}/`),
  );
}

/**
 * Server-render half of the admin 404 (M7-S13). `_app` is client-rendered, so
 * the `/admin` route's own guard never runs during SSR and the document would
 * go out as HTTP 200. `$lang` is SSR-capable: calling this from its
 * `beforeLoad` on the server throws the same `notFound` an unknown route gets,
 * so the response is a 404 with the same page. Resolution errors are left to
 * the admin route (a route error, not a 404).
 */
export async function hideAdminRoute(
  matches: ReadonlyArray<{ routeId: string }>,
  resolveAccess: () => Promise<AdminRouteResolution>,
): Promise<void> {
  if (!isAdminRouteMatch(matches)) return;
  if (decideAdminRouteAccess(await resolveAccess()).kind === "not-found")
    throw notFound({ routeId: HIDDEN_ROUTE_NOT_FOUND_ID });
}
