import type { AppRouterClient } from "@wssp/api/routers/index";
import { Badge } from "@wssp/ui/components/badge";
import { cn } from "@wssp/ui/lib/utils";
import { useTranslation } from "react-i18next";

import { type OperationState, type OperationTone, operationTone } from "@/lib/operation-rules";

/** Shared pieces of the Operations list and detail pages (C48). */

export type OperationListItem = Awaited<
  ReturnType<AppRouterClient["sandboxes"]["listOperations"]>
>["items"][number];
export type OperationView = Awaited<ReturnType<AppRouterClient["sandboxes"]["getOperationView"]>>;

const TONE_CLASS: Record<OperationTone, string> = {
  pending: "border-sky-600/40 bg-sky-600/10 text-sky-700 dark:text-sky-400",
  cancelling: "border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400",
  succeeded: "border-emerald-600/40 bg-emerald-600/10 text-emerald-700 dark:text-emerald-400",
  failed: "border-destructive/40 bg-destructive/10 text-destructive",
  cancelled: "border-border bg-muted text-muted-foreground",
  unknown: "border-destructive/40 bg-destructive/10 text-destructive",
};

export function OperationStatePill({ state }: { state: OperationState }) {
  const { t } = useTranslation(["operations"]);
  return (
    <Badge
      data-operation-state={state}
      className={cn(
        "inline-flex items-center whitespace-nowrap rounded-sm border px-2 py-0.5 text-xs font-medium",
        TONE_CLASS[operationTone(state)],
      )}
    >
      {t(`operations:state.${state}`)}
    </Badge>
  );
}

/** "Exit 0", the typed error, or a dash: the outcome a row can show without its payload. */
export function OperationResultText({
  exitCode,
  errorCode,
}: {
  exitCode: number | null;
  errorCode: OperationListItem["errorCode"];
}) {
  const { t } = useTranslation(["operations"]);
  if (exitCode !== null)
    return (
      <span data-exit-code={exitCode} className="font-mono">
        {t("operations:exitCode", { code: exitCode })}
      </span>
    );
  if (errorCode !== null)
    return (
      <span data-error-code={errorCode} className="text-destructive">
        {t(`operations:error.${errorCode}`)}
      </span>
    );
  return <span className="text-muted-foreground">—</span>;
}
