import { createFileRoute } from "@tanstack/react-router";
import { PoolsPage } from "@/components/pools/pools-page";
import { SkeletonList } from "@/components/skeleton-list";
export const Route = createFileRoute("/$lang/_app/_auth/settings/pools/")({
  component: PoolsRoute,
  pendingComponent: () => <SkeletonList count={3} />,
});
function PoolsRoute() {
  const { lang } = Route.useParams();
  return <PoolsPage lang={lang} />;
}
