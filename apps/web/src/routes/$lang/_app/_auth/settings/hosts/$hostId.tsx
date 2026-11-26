import { createFileRoute } from "@tanstack/react-router";
import { HostDetailPage } from "@/components/hosts/host-detail-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/hosts/$hostId")({
  staticData: { pendingShape: "detail" },
  component: HostRoute,
});
function HostRoute() {
  const { lang, hostId } = Route.useParams();
  return <HostDetailPage hostId={hostId} lang={lang} />;
}
