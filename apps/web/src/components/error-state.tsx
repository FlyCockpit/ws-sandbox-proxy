import { type ErrorComponentProps, useRouter } from "@tanstack/react-router";
import { Button } from "@wssp/ui/components/button";
import { AlertTriangle } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useRouteImportFailure } from "@/hooks/use-route-import-failure";

import { friendly } from "../utils/friendly-error";

/**
 * A route's error screen. Rendered inside the nearest layout (the `_auth`
 * frame keeps the sidebar and bottom nav around it), so Try again only has to
 * redo the route: `router.invalidate()` re-runs every match's `beforeLoad`
 * and loader and re-imports a route chunk whose import failed (TanStack
 * retries the lazy import on the next load), then the boundary resets.
 */
export default function ErrorState({ error, reset }: ErrorComponentProps) {
  useRouteImportFailure(error);
  const router = useRouter();
  const [retrying, setRetrying] = useState(false);
  const { t } = useTranslation(["common", "errors"]);

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
