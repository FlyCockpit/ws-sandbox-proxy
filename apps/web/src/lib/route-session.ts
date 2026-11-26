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
 * renders the previous identity's data. Every route guard uses one of these,
 * never the server functions alone (`pnpm policy:checks`).
 * docs/design/shell-rules.md § Query cache follows identity.
 */
async function admitted<T extends Parameters<typeof admitRouteIdentity>[0]>(
  resolution: T,
): Promise<T> {
  await admitRouteIdentity(resolution);
  return resolution;
}

/** `getRouteSession()` plus the identity check: anonymous-only, device and consent guards. */
export async function resolveRouteSession(): Promise<RouteSessionResolution> {
  return admitted(await getRouteSession());
}

/** `getProtectedRouteSession()` plus the identity check: the `_auth` layout guard. */
export async function resolveProtectedRouteSession(): Promise<ProtectedRouteSessionResolution> {
  return admitted(await getProtectedRouteSession());
}

/** `getRouteAdminAccess()` plus the identity check: the `/admin` guard and its SSR 404. */
export async function resolveRouteAdminAccess(): Promise<AdminRouteResolution> {
  return admitted(await getRouteAdminAccess());
}
