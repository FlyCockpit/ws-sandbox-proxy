import { createFileRoute, stripSearchParams } from "@tanstack/react-router";

import { AdminObservabilityPage } from "@/components/admin/admin-observability-page";
import {
  DEFAULT_OBSERVABILITY_SEARCH,
  parseObservabilitySearch,
} from "@/lib/admin-observability-search";

export const Route = createFileRoute("/$lang/_app/admin/observability")({
  // Only the defaults: /admin's first frame equals any unframed URL's.
  staticData: { pendingShape: "list" },
  validateSearch: parseObservabilitySearch,
  search: {
    middlewares: [stripSearchParams(DEFAULT_OBSERVABILITY_SEARCH)],
  },
  component: AdminObservabilityRoute,
});

function AdminObservabilityRoute() {
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <AdminObservabilityPage
      search={search}
      // Filter edits replace the history entry rather than flooding it.
      onSearch={(patch) =>
        void navigate({
          search: (prev) => ({ ...prev, ...patch }),
          resetScroll: false,
          replace: true,
        })
      }
    />
  );
}
