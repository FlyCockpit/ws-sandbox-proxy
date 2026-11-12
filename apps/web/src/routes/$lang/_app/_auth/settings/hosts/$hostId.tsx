import { createFileRoute } from "@tanstack/react-router";
import { HostDetailPage } from "@/components/hosts/host-detail-page";
import { SkeletonList } from "@/components/skeleton-list";
export const Route = createFileRoute("/$lang/_app/_auth/settings/hosts/$hostId")({
  component: HostRoute,
  pendingComponent: () => <SkeletonList count={3} />,
});
function HostRoute() {
  const { lang, hostId } = Route.useParams();
  return <HostDetailPage hostId={hostId} lang={lang} />;
}
