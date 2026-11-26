import { createFileRoute } from "@tanstack/react-router";
import { WebhookDetailPage } from "@/components/webhooks/webhook-detail-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/webhooks/$endpointId")({
  staticData: { pendingShape: "detail" },
  component: WebhookRoute,
});
function WebhookRoute() {
  const { lang, endpointId } = Route.useParams();
  return <WebhookDetailPage endpointId={endpointId} lang={lang} />;
}
