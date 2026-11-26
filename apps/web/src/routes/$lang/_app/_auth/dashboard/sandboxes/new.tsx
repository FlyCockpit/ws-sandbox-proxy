import { createFileRoute } from "@tanstack/react-router";

import { CreateSandboxPage } from "@/components/sandboxes/create-sandbox-page";
import { parseCreateSandboxSearch } from "@/lib/sandbox-rules";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/sandboxes/new")({
  staticData: { pendingShape: "form" },
  validateSearch: parseCreateSandboxSearch,
  component: CreateSandboxRoute,
});

function CreateSandboxRoute() {
  const { lang } = Route.useParams();
  const { host } = Route.useSearch();
  return <CreateSandboxPage lang={lang} initialHostId={host} />;
}
