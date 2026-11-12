import { createFileRoute } from "@tanstack/react-router";
import { SkeletonList } from "@/components/skeleton-list";
import { WebhookDetailPage } from "@/components/webhooks/webhook-detail-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/webhooks/$endpointId")({
  component: WebhookRoute,
  pendingComponent: () => <SkeletonList count={3} />,
});
function WebhookRoute() {
  const { lang, endpointId } = Route.useParams();
  return <WebhookDetailPage endpointId={endpointId} lang={lang} />;
}
