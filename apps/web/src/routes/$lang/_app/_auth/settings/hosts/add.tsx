import { createFileRoute } from "@tanstack/react-router";
import { AddHostPage } from "@/components/hosts/add-host-page";
import { SkeletonList } from "@/components/skeleton-list";
export const Route = createFileRoute("/$lang/_app/_auth/settings/hosts/add")({
  component: AddHostRoute,
  pendingComponent: () => <SkeletonList count={4} />,
});
function AddHostRoute() {
  const { lang } = Route.useParams();
  return <AddHostPage lang={lang} />;
}
