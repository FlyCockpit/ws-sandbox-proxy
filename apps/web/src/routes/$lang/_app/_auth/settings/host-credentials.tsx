import { createFileRoute } from "@tanstack/react-router";

import { HostCredentialsPage } from "@/components/credentials/host-credentials-page";

export const Route = createFileRoute("/$lang/_app/_auth/settings/host-credentials")({
  component: HostCredentialsRoute,
});

function HostCredentialsRoute() {
  const { lang } = Route.useParams();
  return <HostCredentialsPage lang={lang} />;
}
