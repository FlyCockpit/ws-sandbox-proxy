import { appShellHydrated } from "@/lib/app-shell-hydration";
import { admitRouteIdentity } from "@/lib/document-identity";
import type {
  AdminRouteResolution,
  ProtectedRouteSessionResolution,
  RouteSessionResolution,
} from "@/lib/route-session-access";
import { getRouteAdminAccess } from "@/server/admin-route-access";
import { getProtectedRouteSession, getRouteSession } from "@/server/auth-session";

/**
 * The session guards' probes: each server probe, then the document's identity
 * check (`lib/document-identity.ts`). When the server answers with a different
 * identity than the one this document's cached data belongs to (a switch made
 * on a page the identity boundary was not watching, or in another tab), the
 * document is replaced and the probe never settles, so nothing under the guard
 * renders the previous identity's data. Each also waits for the
 * server-rendered app shell to hydrate, so a guard's redirect never lands
 * mid-hydration (lib/app-shell-hydration.ts). Every route guard uses one of
 * these, never the server functions alone (`pnpm policy:checks`).
 * docs/design/shell-rules.md § Query cache follows identity.
 */
async function admitted<T extends Parameters<typeof admitRouteIdentity>[0]>(
  probe: Promise<T>,
): Promise<T> {
  // Nothing a guard decides (redirect, not-found, error) may reach the router
  // while the server-rendered app shell is still hydrating. The wait runs
  // alongside the probe, and a failed probe (a transport error) also waits
  // before it reaches the router.
  const [settled] = await Promise.allSettled([probe, appShellHydrated()]);
  if (settled.status === "rejected") throw settled.reason;
  const resolution = settled.value;
  await admitRouteIdentity(resolution);
  return resolution;
}

/** `getRouteSession()` plus the identity check: anonymous-only, device and consent guards. */
export async function resolveRouteSession(): Promise<RouteSessionResolution> {
  return admitted(getRouteSession());
}

/** `getProtectedRouteSession()` plus the identity check: the `_auth` layout guard. */
export async function resolveProtectedRouteSession(): Promise<ProtectedRouteSessionResolution> {
  return admitted(getProtectedRouteSession());
}

/** `getRouteAdminAccess()` plus the identity check: the `/admin` guard and its SSR 404. */
export async function resolveRouteAdminAccess(): Promise<AdminRouteResolution> {
  return admitted(getRouteAdminAccess());
}
