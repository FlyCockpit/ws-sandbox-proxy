import { createFileRoute } from "@tanstack/react-router";

import { AdminUsersPage } from "@/components/admin/admin-users-page";

export const Route = createFileRoute("/$lang/_app/admin/users")({
  component: AdminUsersRoute,
});

function AdminUsersRoute() {
  const { session } = Route.useRouteContext();
  return <AdminUsersPage currentUserId={session.user.id} />;
}
