import { createFileRoute } from "@tanstack/react-router";

import { TemplatesPage } from "@/components/templates/templates-page";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/templates/")({
  component: TemplatesRoute,
});

function TemplatesRoute() {
  const { lang } = Route.useParams();
  return <TemplatesPage lang={lang} />;
}
