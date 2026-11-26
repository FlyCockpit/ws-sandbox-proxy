import { createFileRoute } from "@tanstack/react-router";

import { TemplatesPage } from "@/components/templates/templates-page";
import { parseTemplatesSearch } from "@/lib/template-rules";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/templates/")({
  validateSearch: parseTemplatesSearch,
  component: TemplatesRoute,
});

function TemplatesRoute() {
  const { lang } = Route.useParams();
  const search = Route.useSearch();
  return <TemplatesPage lang={lang} initialChoosing={search.new === true} />;
}
