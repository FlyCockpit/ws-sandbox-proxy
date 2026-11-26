import { createFileRoute } from "@tanstack/react-router";
import { PoolsPage } from "@/components/pools/pools-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/pools/")({
  staticData: { pendingShape: "list" },
  // `?tab=shared` opens Shared with me (links from the invitation page and
  // the empty states); anything else is the owned list.
  validateSearch: (search: Record<string, unknown>): { tab?: "shared" } =>
    search.tab === "shared" ? { tab: "shared" } : {},
  component: PoolsRoute,
});
function PoolsRoute() {
  const { lang } = Route.useParams();
  const { tab } = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <PoolsPage
      lang={lang}
      tab={tab ?? "owned"}
      onTabChange={(next) =>
        // In-place URL state: keep the scroll position (AGENTS.md web shell).
        void navigate({
          search: next === "shared" ? { tab: "shared" } : {},
          replace: true,
          resetScroll: false,
        })
      }
    />
  );
}
