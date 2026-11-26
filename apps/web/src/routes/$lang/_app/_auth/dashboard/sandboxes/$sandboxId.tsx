import { createFileRoute } from "@tanstack/react-router";

import { SandboxDetailPage } from "@/components/sandboxes/sandbox-detail-page";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/sandboxes/$sandboxId")({
  staticData: { pendingShape: "detail" },
  component: SandboxDetailRoute,
});

function SandboxDetailRoute() {
  const { lang, sandboxId } = Route.useParams();
  return <SandboxDetailPage lang={lang} sandboxId={sandboxId} />;
}
