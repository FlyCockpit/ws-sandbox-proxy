import { createFileRoute, redirect } from "@tanstack/react-router";
import { McpConsentPage } from "@/components/mcp/mcp-consent-page";
import { resolveRouteSession } from "@/lib/route-session";
import { getRawMcpSearch } from "@/server/mcp-request";
export const Route = createFileRoute("/$lang/_app/mcp-consent")({
  staticData: { pendingShape: "form", pendingWidth: "narrow" },
  validateSearch: (search: Record<string, unknown>) => search,
  beforeLoad: async ({ params }) => {
    const resolution = await resolveRouteSession();
    if (resolution.status === "error") throw new Error("Route session unavailable");
    if (!resolution.session) {
      const raw = typeof window === "undefined" ? await getRawMcpSearch() : window.location.search;
      throw redirect({ href: `/${params.lang}/mcp-login${raw}`, reloadDocument: true });
    }
  },
  component: ConsentRoute,
});
function ConsentRoute() {
  const { lang } = Route.useParams();
  return <McpConsentPage lang={lang} search={Route.useSearch()} />;
}
