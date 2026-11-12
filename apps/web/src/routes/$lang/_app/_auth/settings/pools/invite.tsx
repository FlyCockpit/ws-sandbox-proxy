import { createFileRoute } from "@tanstack/react-router";
import { AcceptPoolInvite } from "@/components/pools/accept-pool-invite";
import { SkeletonList } from "@/components/skeleton-list";
export const Route = createFileRoute("/$lang/_app/_auth/settings/pools/invite")({
  component: AcceptPoolInvite,
  pendingComponent: () => <SkeletonList count={3} />,
});
