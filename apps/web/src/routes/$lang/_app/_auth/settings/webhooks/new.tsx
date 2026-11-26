import { createFileRoute } from "@tanstack/react-router";
import { SkeletonList } from "@/components/skeleton-list";
import { CreateWebhookPage } from "@/components/webhooks/create-webhook-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/webhooks/new")({
  component: NewWebhookRoute,
  pendingComponent: () => <SkeletonList count={3} />,
});
function NewWebhookRoute() {
  const { lang } = Route.useParams();
  return <CreateWebhookPage lang={lang} />;
}
