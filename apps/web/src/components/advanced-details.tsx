import { cn } from "@wssp/ui/lib/utils";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

/**
 * A closed-by-default disclosure for IDs, digests and other operator detail
 * that should stay reachable but out of the way. Native `<details>`, with a
 * 44px summary.
 */
export function AdvancedDetails({
  children,
  summary,
  className,
}: {
  children: ReactNode;
  /** Defaults to "Advanced". */
  summary?: string;
  className?: string;
}) {
  const { t } = useTranslation("common");
  return (
    <details data-advanced-details="" className={cn("min-w-0 text-sm", className)}>
      <summary className="flex min-h-11 cursor-pointer items-center font-medium text-muted-foreground">
        {summary ?? t("advanced.summary")}
      </summary>
      <div className="flex min-w-0 flex-col gap-3 pb-2">{children}</div>
    </details>
  );
}
