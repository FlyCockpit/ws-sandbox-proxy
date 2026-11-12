import { createFileRoute } from "@tanstack/react-router";

import { SettingsHub } from "@/components/settings/settings-hub";

export const Route = createFileRoute("/$lang/_app/_auth/settings/")({
  component: SettingsHubRoute,
});

function SettingsHubRoute() {
  const { lang } = Route.useParams();
  return <SettingsHub lang={lang} />;
}
