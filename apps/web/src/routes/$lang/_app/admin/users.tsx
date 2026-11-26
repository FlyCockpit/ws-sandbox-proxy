import { createFileRoute } from "@tanstack/react-router";

import { AdminUsersPage } from "@/components/admin/admin-users-page";

export const Route = createFileRoute("/$lang/_app/admin/users")({
  // Only the defaults: /admin's first frame equals any unframed URL's.
  staticData: { pendingShape: "list" },
  component: AdminUsersRoute,
});

function AdminUsersRoute() {
  const { session } = Route.useRouteContext();
  return <AdminUsersPage currentUserId={session.user.id} />;
}
