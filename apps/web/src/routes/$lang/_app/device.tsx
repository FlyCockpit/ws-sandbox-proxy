import { createFileRoute, redirect } from "@tanstack/react-router";

import { DevicePage } from "@/components/device-page";
import { resolveRouteSession } from "@/lib/route-session";
import { decideDeviceRouteAccess, loginRedirect } from "@/lib/route-session-access";
import { getRouteForcedTwoFactorSettings } from "@/server/route-forced-two-factor-settings";

export const Route = createFileRoute("/$lang/_app/device")({
  staticData: { pendingShape: "form", pendingWidth: "narrow" },
  validateSearch: (search: Record<string, unknown>) => {
    const userCode = typeof search.user_code === "string" ? search.user_code : undefined;
    return { user_code: userCode };
  },
  beforeLoad: async ({ params, location }) => {
    const [sessionResolution, forcedTwoFactorSettings] = await Promise.all([
      resolveRouteSession(),
      getRouteForcedTwoFactorSettings(),
    ]);
    const decision = decideDeviceRouteAccess(sessionResolution, forcedTwoFactorSettings);
    if (decision.kind === "error") throw new Error("Route session unavailable");
    if (decision.kind === "redirect-to-login") {
      throw redirect(loginRedirect(params.lang, location.href));
    }
    if (decision.kind === "redirect-to-security") {
      throw redirect({
        to: "/$lang/settings/security",
        params: { lang: params.lang },
      });
    }
    return { session: decision.session };
  },
  component: DeviceRoute,
});

function DeviceRoute() {
  const { lang } = Route.useParams();
  const { user_code: userCode } = Route.useSearch();
  const { session } = Route.useRouteContext();
  return <DevicePage lang={lang} userCode={userCode ?? ""} ownerId={session.user.id} />;
}
