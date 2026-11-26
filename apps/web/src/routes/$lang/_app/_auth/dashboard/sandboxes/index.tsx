import { createFileRoute } from "@tanstack/react-router";

import { SandboxesPage } from "@/components/sandboxes/sandboxes-page";
import { parseSandboxesSearch } from "@/lib/sandbox-rules";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/sandboxes/")({
  staticData: { pendingShape: "list" },
  validateSearch: parseSandboxesSearch,
  component: SandboxesRoute,
});

function SandboxesRoute() {
  const { lang } = Route.useParams();
  const { status } = Route.useSearch();
  const navigate = Route.useNavigate();
  const { session } = Route.useRouteContext();
  return (
    <SandboxesPage
      lang={lang}
      userId={session.user.id}
      status={status ?? "active"}
      // The filter lives in the URL (Back restores it); a change replaces the
      // entry instead of stacking history. Active is the default and stays off
      // the URL.
      onStatusChange={(next) =>
        void navigate({
          search: next === "active" ? {} : { status: next },
          resetScroll: false,
          replace: true,
        })
      }
    />
  );
}
