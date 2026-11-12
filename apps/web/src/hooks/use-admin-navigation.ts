import { useQuery } from "@tanstack/react-query";
import { isAdminRole } from "@wssp/auth/roles";

import { showsAdminNavigation } from "@/lib/route-session-access";
import { orpc } from "@/utils/orpc";

import { useAuthSession } from "./use-auth-session";

/**
 * Whether the shell offers the admin area to the signed-in user. Mirrors the
 * server admin gate from the session plus the public force-2FA settings; the
 * settings query only runs for verified admin-role sessions (it shares the
 * cache the `_auth` guard seeds from its session round trip). Unknown
 * settings mean "omit".
 */
export function useShowsAdminNavigation(): boolean {
  const authSession = useAuthSession();
  const user = authSession.state.status === "authenticated" ? authSession.state.session.user : null;
  const candidate = user?.emailVerified === true && isAdminRole(user.role);
  const { data: settings } = useQuery({
    ...orpc.settings.getAll.queryOptions(),
    enabled: candidate,
  });
  return showsAdminNavigation(user, candidate ? settings : undefined);
}
