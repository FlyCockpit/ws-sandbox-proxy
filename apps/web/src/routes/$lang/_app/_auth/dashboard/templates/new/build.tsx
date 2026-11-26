import { createFileRoute } from "@tanstack/react-router";

import { BuildTemplatePage } from "@/components/template-builds/build-template-page";
import { parseNewTemplateSearch } from "@/lib/template-rules";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/templates/new/build")({
  staticData: { pendingShape: "form" },
  validateSearch: parseNewTemplateSearch,
  component: BuildTemplateRoute,
});

function BuildTemplateRoute() {
  const { lang } = Route.useParams();
  const search = Route.useSearch();
  return <BuildTemplatePage lang={lang} templateId={search.template} />;
}
