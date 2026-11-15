import { createFileRoute } from "@tanstack/react-router";
import { AgentTokensPage } from "@/components/credentials/agent-tokens-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/agent-tokens")({
  component: AgentTokensRoute,
});
function AgentTokensRoute() {
  const { lang } = Route.useParams();
  return <AgentTokensPage lang={lang} />;
}
