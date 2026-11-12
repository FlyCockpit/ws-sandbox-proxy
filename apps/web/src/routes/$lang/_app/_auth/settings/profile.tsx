import { createFileRoute } from "@tanstack/react-router";

import { AccountSettingsLayout } from "@/components/settings/account-settings-layout";
import { ProfileSettings } from "@/components/settings/profile-settings";

export const Route = createFileRoute("/$lang/_app/_auth/settings/profile")({
  component: ProfileRoute,
});

function ProfileRoute() {
  const { lang } = Route.useParams();
  const { session } = Route.useRouteContext();
  return (
    <AccountSettingsLayout lang={lang}>
      <ProfileSettings user={session.user} />
    </AccountSettingsLayout>
  );
}
