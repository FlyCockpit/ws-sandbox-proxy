import { createFileRoute } from "@tanstack/react-router";

import { TemplateBuildDetailPage } from "@/components/template-builds/template-build-detail-page";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/templates/builds/$buildId")({
  component: TemplateBuildDetailRoute,
});

function TemplateBuildDetailRoute() {
  const { lang, buildId } = Route.useParams();
  return <TemplateBuildDetailPage lang={lang} buildId={buildId} />;
}
