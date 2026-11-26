import { createFileRoute } from "@tanstack/react-router";

import { OperationsPage } from "@/components/operations/operations-page";
import { type OperationsSearch, parseOperationsSearch } from "@/lib/operation-rules";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/operations/")({
  staticData: { pendingShape: "list" },
  validateSearch: parseOperationsSearch,
  component: OperationsRoute,
});

function OperationsRoute() {
  const { lang } = Route.useParams();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <OperationsPage
      lang={lang}
      search={search}
      // Filters live in the URL (Back restores them); a filter change replaces
      // the entry instead of stacking history.
      onSearchChange={(next: OperationsSearch) =>
        void navigate({ search: next, resetScroll: false, replace: true })
      }
    />
  );
}
