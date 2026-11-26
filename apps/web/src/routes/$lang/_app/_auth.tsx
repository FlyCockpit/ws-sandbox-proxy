import { createFileRoute, type ErrorComponentProps, redirect } from "@tanstack/react-router";
import { TwoFactorNudge } from "@/components/admin/two-factor-nudge";
import { PageSkeleton } from "@/components/app-shell";
import { DashboardFrame } from "@/components/dashboard-frame";
import ErrorState from "@/components/error-state";
import { ForcedPasswordChange } from "@/components/forced-password-change";
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
      passwordChangeRequired: decision.passwordChangeRequired,
    };
  },
  // While the session check runs (a hard refresh) and when it fails (offline),
  // the page body is the skeleton or the error, inside the same frame: the
  // sidebar and bottom nav never disappear.
  pendingComponent: AuthPending,
  errorComponent: AuthError,
  component: AuthLayout,
});

function AuthPending() {
  const { lang } = Route.useParams();
  return (
    <DashboardFrame lang={lang}>
      <PageSkeleton />
    </DashboardFrame>
  );
}

function AuthError(props: ErrorComponentProps) {
  const { lang } = Route.useParams();
  return (
    <DashboardFrame lang={lang}>
      <ErrorState {...props} />
    </DashboardFrame>
  );
}

function AuthLayout() {
  const { session, forcedTwoFactorSettings, passwordChangeRequired } = Route.useRouteContext();
  const { lang } = Route.useParams();
  // Each takeover replaces the whole frame, so no nav renders behind it. An
  // admin-set temporary password is replaced first: 2FA enrollment asks for
  // the account's own password.
  if (passwordChangeRequired) return <ForcedPasswordChange />;
  // Everyone under a forced 2FA policy sees their enrollment deadline here
  // (admins also under /admin, a sibling route tree, so it never renders twice).
  const banner = session.user.emailVerified === true ? <TwoFactorNudge variant="shell" /> : null;
  return (
    <ForcedTwoFactorGate user={session.user} forcedTwoFactorSettings={forcedTwoFactorSettings}>
      <DashboardFrame lang={lang} banner={banner} />
    </ForcedTwoFactorGate>
  );
}
