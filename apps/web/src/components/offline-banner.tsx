import { useQueryClient } from "@tanstack/react-query";
import { Wifi, WifiOff } from "lucide-react";
import { useTranslation } from "react-i18next";

import { useConnectivityNotice } from "@/hooks/use-connectivity-notice";

/** The newest moment any cached query got its data, or null with no data cached. */
export function newestDataAt(updatedAt: readonly number[]): number | null {
  const newest = Math.max(0, ...updatedAt);
  return newest > 0 ? newest : null;
}

/**
 * The offline notice under the header, in both shells. The browser's own
 * connectivity hint decides it (presentation only): the cached pages keep
 * showing, and this says how old they are instead of letting each page blame
 * its hosts or the server. On reconnect it says "Back online." for a few
 * seconds (lib/connectivity-notice.ts), then empties.
 *
 * The live region is always mounted (empty, so no height, while online), so
 * assistive tech announces the offline notice once when it appears and
 * "Back online." once on reconnect. See docs/design/shell-rules.md § Offline.
 */
export function OfflineBanner() {
  const notice = useConnectivityNotice();
  return (
    <div role="status" aria-live="polite" aria-atomic="true" data-offline-banner={notice ?? ""}>
      {notice === "offline" && <OfflineNotice />}
      {notice === "back-online" && <BackOnlineNotice />}
    </div>
  );
}

const NOTICE_CLASS =
  "flex min-w-0 items-center justify-center gap-2 border-b px-4 py-2 text-center text-sm motion-safe:animate-in motion-safe:fade-in-0";

function OfflineNotice() {
  const queryClient = useQueryClient();
  const { t, i18n } = useTranslation("common");
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
    <p
      className={`${NOTICE_CLASS} border-amber-600/40 bg-amber-600/10 text-amber-800 dark:text-amber-300`}
    >
      <WifiOff aria-hidden="true" className="size-4 shrink-0" />
      <span className="min-w-0">{message}</span>
    </p>
  );
}

function BackOnlineNotice() {
  const { t } = useTranslation("common");
  return (
    <p className={`${NOTICE_CLASS} bg-muted text-foreground`}>
      <Wifi aria-hidden="true" className="size-4 shrink-0 text-state-success" />
      <span className="min-w-0">{t("offline.backOnline")}</span>
    </p>
  );
}
