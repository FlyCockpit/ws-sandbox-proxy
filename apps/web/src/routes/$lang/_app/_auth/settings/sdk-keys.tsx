import { createFileRoute } from "@tanstack/react-router";

import { SdkKeysPage } from "@/components/credentials/sdk-keys-page";

export const Route = createFileRoute("/$lang/_app/_auth/settings/sdk-keys")({
  staticData: { pendingShape: "list" },
  component: SdkKeysRoute,
});

function SdkKeysRoute() {
  const { lang } = Route.useParams();
  return <SdkKeysPage lang={lang} />;
}
