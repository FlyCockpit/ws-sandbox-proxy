import { createFileRoute, redirect } from "@tanstack/react-router";

import { APP_HOME } from "@/lib/app-home";

// Sandboxes is the signed-in home (lib/app-home.ts): `/dashboard` (old links,
// bookmarks) lands there.
export const Route = createFileRoute("/$lang/_app/_auth/dashboard/")({
  staticData: { pendingShape: "list" },
  beforeLoad: ({ params }) => {
    throw redirect({ to: APP_HOME, params, replace: true });
  },
});
