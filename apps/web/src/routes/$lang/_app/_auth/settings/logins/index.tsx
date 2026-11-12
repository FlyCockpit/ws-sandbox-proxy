import { createFileRoute } from "@tanstack/react-router";
import { LoginsPage } from "@/components/logins/logins-page";
import { SkeletonList } from "@/components/skeleton-list";
export const Route = createFileRoute("/$lang/_app/_auth/settings/logins/")({
  component: LoginsRoute,
  pendingComponent: () => <SkeletonList count={3} />,
});
function LoginsRoute() {
  const { lang } = Route.useParams();
  return <LoginsPage lang={lang} />;
}
