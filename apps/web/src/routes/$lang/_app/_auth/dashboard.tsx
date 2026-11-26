import { createFileRoute, Outlet } from "@tanstack/react-router";

// Gate and chrome: the parent `_auth` layout (signed-in session, forced-2FA
// takeover, then the app frame). Every section's data additionally comes from
// an owner-scoped `protectedProcedure`, which enforces the same policy
// server-side.
export const Route = createFileRoute("/$lang/_app/_auth/dashboard")({
  staticData: { pendingShape: "list" },
  component: Outlet,
});
