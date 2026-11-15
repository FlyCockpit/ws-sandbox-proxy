import { createFileRoute } from "@tanstack/react-router";
import { McpLoginPage } from "@/components/mcp/mcp-login-page";
export const Route = createFileRoute("/$lang/_app/mcp-login")({
  validateSearch: (search: Record<string, unknown>) => search,
  component: LoginRoute,
});
function LoginRoute() {
  const { lang } = Route.useParams();
  return <McpLoginPage lang={lang} search={Route.useSearch()} />;
}
