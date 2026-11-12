import { createFileRoute } from "@tanstack/react-router";

import { AccountBuildsCard } from "@/components/settings/account-builds-card";
import { AccountImagePolicyCard } from "@/components/settings/account-image-policy-card";
import { AccountSettingsLayout } from "@/components/settings/account-settings-layout";

export const Route = createFileRoute("/$lang/_app/_auth/settings/images")({
  component: ImagesRoute,
});

function ImagesRoute() {
  const { lang } = Route.useParams();
  return (
    <AccountSettingsLayout lang={lang}>
      <AccountImagePolicyCard lang={lang} />
      <AccountBuildsCard />
    </AccountSettingsLayout>
  );
}
