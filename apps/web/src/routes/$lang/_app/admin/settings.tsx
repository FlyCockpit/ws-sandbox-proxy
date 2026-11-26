import { createFileRoute } from "@tanstack/react-router";

import { AdminSettingsPage } from "@/components/admin/admin-settings-page";

export const Route = createFileRoute("/$lang/_app/admin/settings")({
  // Only the defaults: /admin's first frame equals any unframed URL's.
  staticData: { pendingShape: "list" },
  component: AdminSettingsRoute,
});

function AdminSettingsRoute() {
  const { lang } = Route.useParams();
  const { session } = Route.useRouteContext();
  return <AdminSettingsPage lang={lang} adminHas2FA={session.user.twoFactorEnabled === true} />;
}
