import { createFileRoute } from "@tanstack/react-router";

import { SandboxDetailPage } from "@/components/sandboxes/sandbox-detail-page";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/sandboxes/$sandboxId")({
  component: SandboxDetailRoute,
});

function SandboxDetailRoute() {
  const { lang, sandboxId } = Route.useParams();
  return <SandboxDetailPage lang={lang} sandboxId={sandboxId} />;
}
