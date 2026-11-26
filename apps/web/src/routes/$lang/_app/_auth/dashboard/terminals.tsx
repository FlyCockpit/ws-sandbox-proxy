import { createFileRoute } from "@tanstack/react-router";

import { TerminalsPage } from "@/components/terminals/terminals-page";
import { parseTerminalsSearch } from "@/lib/terminal-page-search";

export const Route = createFileRoute("/$lang/_app/_auth/dashboard/terminals")({
  validateSearch: parseTerminalsSearch,
  component: TerminalsRoute,
});

function TerminalsRoute() {
  const { lang } = Route.useParams();
  const { kind } = Route.useSearch();
  const navigate = Route.useNavigate();
  return (
    <TerminalsPage
      lang={lang}
      kind={kind ?? "all"}
      // The filter lives in the URL (Back restores it); a change replaces the
      // entry instead of stacking history.
      onKindChange={(next) =>
        void navigate({
          search: next === "all" ? {} : { kind: next },
          resetScroll: false,
          replace: true,
        })
      }
    />
  );
}
