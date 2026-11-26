import { createFileRoute, Outlet } from "@tanstack/react-router";
export const Route = createFileRoute("/$lang/_app/_auth/settings/pools")({
  staticData: { pendingShape: "list" },
  component: Outlet,
});
