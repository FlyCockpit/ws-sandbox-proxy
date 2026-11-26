import { createFileRoute, Outlet } from "@tanstack/react-router";

// The Settings hub and the set-up-once pages it links. The app frame comes
// from `_auth`; account pages render their own tab row.
export const Route = createFileRoute("/$lang/_app/_auth/settings")({
  staticData: { pendingShape: "hub" },
  component: Outlet,
});
