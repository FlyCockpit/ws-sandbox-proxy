import { createFileRoute } from "@tanstack/react-router";
import { PoolsPage } from "@/components/pools/pools-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/pools/")({
  staticData: { pendingShape: "list" },
  // `?tab=shared` opens Shared with me (links from the invitation page and
  // the empty states) and `?tab=owned` the owned list; without one the page
  // picks (Shared with me for someone who owns no pool but has a shared one).
  validateSearch: (search: Record<string, unknown>): { tab?: "owned" | "shared" } =>
    search.tab === "shared" || search.tab === "owned" ? { tab: search.tab } : {},
  component: PoolsRoute,
});
function PoolsRoute() {
  const { lang } = Route.useParams();
  const { tab } = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <PoolsPage
      lang={lang}
      tab={tab}
      onTabChange={(next) =>
        // In-place URL state: keep the scroll position (AGENTS.md web shell).
        void navigate({
          search: { tab: next },
          replace: true,
          resetScroll: false,
        })
      }
    />
  );
}
