import { createFileRoute } from "@tanstack/react-router";
import { WebhooksPage } from "@/components/webhooks/webhooks-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/webhooks/")({
  staticData: { pendingShape: "list" },
  component: WebhooksRoute,
});
function WebhooksRoute() {
  const { lang } = Route.useParams();
  return <WebhooksPage lang={lang} />;
}
