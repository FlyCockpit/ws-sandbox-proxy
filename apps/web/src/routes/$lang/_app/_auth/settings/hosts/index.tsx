import { createFileRoute } from "@tanstack/react-router";
import { HostsPage } from "@/components/hosts/hosts-page";
import { SkeletonList } from "@/components/skeleton-list";
export const Route = createFileRoute("/$lang/_app/_auth/settings/hosts/")({
  component: HostsRoute,
  pendingComponent: () => <SkeletonList count={3} />,
});
function HostsRoute() {
  const { lang } = Route.useParams();
  return <HostsPage lang={lang} />;
}
