import { createFileRoute } from "@tanstack/react-router";

import { RegisterTemplatePage } from "@/components/templates/register-template-page";
import { parseNewTemplateSearch } from "@/lib/template-rules";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/templates/new/register")({
  validateSearch: parseNewTemplateSearch,
  component: RegisterTemplateRoute,
});

function RegisterTemplateRoute() {
  const { lang } = Route.useParams();
  const search = Route.useSearch();
  return (
    <RegisterTemplatePage lang={lang} templateId={search.template} fromRevisionId={search.from} />
  );
}
