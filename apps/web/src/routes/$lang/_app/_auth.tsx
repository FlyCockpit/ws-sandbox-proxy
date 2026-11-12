import { createFileRoute, redirect } from "@tanstack/react-router";

import { DashboardFrame } from "@/components/dashboard-frame";
import { ForcedTwoFactorGate } from "@/components/forced-two-factor-gate";
import { authRedirectHref, capturePoolInviteFragment } from "@/lib/pool-invite";
import { decideProtectedRouteAccess, loginRedirect } from "@/lib/route-session-access";
import { getProtectedRouteSession } from "@/server/auth-session";
import { clientReadableForcedTwoFactorSettings } from "@/utils/two-factor-policy";

export const Route = createFileRoute("/$lang/_app/_auth")({
  beforeLoad: async ({ context, location, params }) => {
    if (typeof window !== "undefined") capturePoolInviteFragment();
    // One round trip resolves the session AND the forced-2FA settings the
    // layout gates on, so the page's own queries start as soon as this
    // returns instead of waiting on a separate `settings.getAll` request.
    const decision = decideProtectedRouteAccess(await getProtectedRouteSession());
    if (decision.kind === "error") throw new Error("Route session unavailable");
    if (decision.kind === "redirect-to-login") {
      throw redirect(loginRedirect(params.lang, authRedirectHref(location)));
    }
    // Same payload `settings.getAll` returns for this caller: the shell's
    // admin-nav mirror and the admin 2FA nudge read it from the cache.
    context.queryClient.setQueryData(
      context.orpc.settings.getAll.queryKey(),
      clientReadableForcedTwoFactorSettings(decision.forcedTwoFactorSettings),
    );
    return {
      session: decision.session,
      forcedTwoFactorSettings: decision.forcedTwoFactorSettings,
    };
  },
  component: AuthLayout,
});

function AuthLayout() {
  const { session, forcedTwoFactorSettings } = Route.useRouteContext();
  const { lang } = Route.useParams();
  // The takeover replaces the whole frame, so no nav renders behind it.
  return (
    <ForcedTwoFactorGate user={session.user} forcedTwoFactorSettings={forcedTwoFactorSettings}>
      <DashboardFrame lang={lang} />
    </ForcedTwoFactorGate>
  );
}
