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
  const { status, name } = Route.useSearch();
  const navigate = Route.useNavigate();
  const { session } = Route.useRouteContext();
  return (
    <SandboxesPage
      lang={lang}
      userId={session.user.id}
      status={status ?? "active"}
      name={name}
      // The filters live in the URL (Back restores them); a change replaces
      // the entry instead of stacking history. Active is the default and stays
      // off the URL, as does an empty name.
      onSearchChange={(next) =>
        void navigate({
          search: {
            ...(next.status === "active" ? {} : { status: next.status }),
            ...(next.name ? { name: next.name } : {}),
          },
          resetScroll: false,
          replace: true,
        })
      }
    />
  );
}
