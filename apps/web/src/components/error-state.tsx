import { type ErrorComponentProps, useRouter } from "@tanstack/react-router";
import { Button } from "@wssp/ui/components/button";
import { AlertTriangle, WifiOff } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useNetworkStatus } from "@/hooks/use-network-status";
import { useRetryOnReconnect } from "@/hooks/use-retry-on-reconnect";
import { useRouteImportFailure } from "@/hooks/use-route-import-failure";
import { isFetchFailure } from "@/lib/network-failure";

import { friendly } from "../utils/friendly-error";

/**
 * A route's error screen. Rendered inside the nearest layout (the `_auth`
 * frame keeps the sidebar and bottom nav around it), so Try again only has to
 * redo the route: `router.invalidate()` re-runs every match's `beforeLoad`
 * and loader and re-imports a route chunk whose import failed (TanStack
 * retries the lazy import on the next load), then the boundary resets.
 *
 * Offline it says so, without a Reload (that would only land on the
 * browser's offline page), and retries by itself on reconnect; a fetch that
 * failed while online says the server could not be reached. See
 * docs/design/shell-rules.md § Offline.
 */
export default function ErrorState({ error, reset }: ErrorComponentProps) {
  useRouteImportFailure(error);
  const router = useRouter();
  const [retrying, setRetrying] = useState(false);
  const { t } = useTranslation(["common", "errors"]);
  const online = useNetworkStatus();

  const retry = async () => {
    setRetrying(true);
    try {
      await router.invalidate();
    } catch {
      // A route that fails again lands in its match's error state; the reset
      // below renders that new error.
    } finally {
      setRetrying(false);
      reset();
    }
  };
  useRetryOnReconnect(() => void retry(), !online);

  if (!online || isFetchFailure(error)) {
    const title = online ? t("errors:unreachablePage.title") : t("errors:offlinePage.title");
    const description = online
      ? t("errors:unreachablePage.description")
      : t("errors:offlinePage.description");
    return (
      <div
        role="alert"
        data-network-failure={online ? "unreachable" : "offline"}
        className="flex h-full flex-col items-center justify-center gap-3 px-6 py-8 text-center"
      >
        <WifiOff aria-hidden="true" className="size-8 text-muted-foreground" />
        <div className="space-y-1">
          <p className="text-base font-medium">{title}</p>
          <p className="text-sm text-muted-foreground break-words">{description}</p>
        </div>
        <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
          <Button onClick={retry} disabled={retrying} variant="outline" className="min-h-[44px]">
            {t("common:actions.tryAgain")}
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div
      role="alert"
      className="flex h-full flex-col items-center justify-center gap-3 px-6 py-8 text-center"
    >
      <AlertTriangle aria-hidden="true" className="size-8 text-destructive" />
      <div className="space-y-1">
        <p className="text-base font-medium">{t("common:somethingWentWrong")}</p>
        <p className="text-sm text-muted-foreground break-words">
          {friendly(error, t("errors:rootError"))}
        </p>
      </div>
      <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
        <Button onClick={retry} disabled={retrying} variant="outline" className="min-h-[44px]">
          {t("common:actions.tryAgain")}
        </Button>
        <Button onClick={() => window.location.reload()} className="min-h-[44px]">
          {t("common:actions.reload")}
        </Button>
      </div>
    </div>
  );
}
