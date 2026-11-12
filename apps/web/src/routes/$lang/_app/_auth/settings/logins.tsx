import { createFileRoute, Outlet } from "@tanstack/react-router";
import { SkeletonList } from "@/components/skeleton-list";
export const Route = createFileRoute("/$lang/_app/_auth/settings/logins")({
  component: Outlet,
  pendingComponent: () => <SkeletonList count={3} />,
});
