import { createFileRoute } from "@tanstack/react-router";
import { SkeletonList } from "@/components/skeleton-list";
import { WebhooksPage } from "@/components/webhooks/webhooks-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/webhooks/")({
  component: WebhooksRoute,
  pendingComponent: () => <SkeletonList count={3} />,
});
function WebhooksRoute() {
  const { lang } = Route.useParams();
  return <WebhooksPage lang={lang} />;
}
