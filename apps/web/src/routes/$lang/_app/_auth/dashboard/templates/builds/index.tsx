import { createFileRoute } from "@tanstack/react-router";

import { TemplateBuildsPage } from "@/components/template-builds/template-builds-page";
import { parseTemplateBuildsSearch, type TemplateBuildsSearch } from "@/lib/template-build-rules";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/templates/builds/")({
  staticData: { pendingShape: "list" },
  validateSearch: parseTemplateBuildsSearch,
  component: TemplateBuildsRoute,
});

function TemplateBuildsRoute() {
  const { lang } = Route.useParams();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <TemplateBuildsPage
      lang={lang}
      search={search}
      onSearchChange={(next: TemplateBuildsSearch) =>
        void navigate({ search: next, resetScroll: false, replace: true })
      }
    />
  );
}
