import { useQueryClient } from "@tanstack/react-query";
import { WifiOff } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useNetworkStatus } from "@/hooks/use-network-status";

/** The newest moment any cached query got its data, or null with no data cached. */
export function newestDataAt(updatedAt: readonly number[]): number | null {
  const newest = Math.max(0, ...updatedAt);
  return newest > 0 ? newest : null;
}

/**
 * The app-level offline notice under the header. The browser's own
 * connectivity hint decides it (presentation only): the cached pages keep
 * showing, and this says how old they are instead of letting each page blame
 * its hosts or the server.
 */
export function OfflineBanner() {
  const online = useNetworkStatus();
  const queryClient = useQueryClient();
  const { t, i18n } = useTranslation("common");
  if (online) return null;

  const since = newestDataAt(
    queryClient
      .getQueryCache()
      .getAll()
      .map((query) => query.state.dataUpdatedAt),
  );
  const message =
    since === null
      ? t("offline.noData")
      : t("offline.showingDataFrom", {
          time: new Intl.DateTimeFormat(i18n.language, {
            hour: "numeric",
            minute: "2-digit",
          }).format(since),
        });

  return (
    <div
      role="status"
      data-offline-banner
      className="flex min-w-0 items-center justify-center gap-2 border-b border-amber-600/40 bg-amber-600/10 px-4 py-2 text-center text-sm text-amber-800 dark:text-amber-300"
    >
      <WifiOff aria-hidden="true" className="size-4 shrink-0" />
      <span className="min-w-0">{message}</span>
    </div>
  );
}
