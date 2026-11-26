import { createFileRoute } from "@tanstack/react-router";
import { HostsPage } from "@/components/hosts/hosts-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/hosts/")({
  staticData: { pendingShape: "list" },
  component: HostsRoute,
});
function HostsRoute() {
  const { lang } = Route.useParams();
  return <HostsPage lang={lang} />;
}
