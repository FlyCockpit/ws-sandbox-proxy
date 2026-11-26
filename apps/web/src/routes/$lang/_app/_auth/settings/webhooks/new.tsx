import { createFileRoute } from "@tanstack/react-router";
import { CreateWebhookPage } from "@/components/webhooks/create-webhook-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/webhooks/new")({
  staticData: { pendingShape: "form" },
  component: NewWebhookRoute,
});
function NewWebhookRoute() {
  const { lang } = Route.useParams();
  return <CreateWebhookPage lang={lang} />;
}
