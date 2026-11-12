import { createFileRoute, redirect } from "@tanstack/react-router";

// Sandboxes is the signed-in home: `/dashboard` (login fallback, old links)
// lands there.
export const Route = createFileRoute("/$lang/_app/_auth/dashboard/")({
  beforeLoad: ({ params }) => {
    throw redirect({ to: "/$lang/dashboard/sandboxes", params, replace: true });
  },
});
