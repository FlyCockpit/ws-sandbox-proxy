import { createFileRoute } from "@tanstack/react-router";

import { OperationDetailPage } from "@/components/operations/operation-detail-page";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/operations/$operationId")({
  component: OperationDetailRoute,
});

function OperationDetailRoute() {
  const { lang, operationId } = Route.useParams();
  return <OperationDetailPage lang={lang} operationId={operationId} />;
}
