import { createFileRoute } from "@tanstack/react-router";
import { AcceptPoolInvite } from "@/components/pools/accept-pool-invite";
export const Route = createFileRoute("/$lang/_app/_auth/settings/pools/invite")({
  staticData: { pendingShape: "detail" },
  component: AcceptPoolInviteRoute,
});
function AcceptPoolInviteRoute() {
  const { lang } = Route.useParams();
  return <AcceptPoolInvite lang={lang} />;
}
