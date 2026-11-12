import { Skeleton } from "@wssp/ui/components/skeleton";
import { cn } from "@wssp/ui/lib/utils";
import type { ReactNode } from "react";

type SkeletonListProps = {
  count?: number;
  className?: string;
  children?: ReactNode;
  layout?: "compact" | "resource";
};

/** Layout-matching skeleton rows for admin-style lists. */
export function SkeletonList({
  count = 5,
  className,
  children,
  layout = "compact",
}: SkeletonListProps) {
  return (
    <ul className={cn("min-w-0 overflow-hidden rounded-xl bg-card divide-y", className)}>
      {Array.from({ length: count }, (_, index) => (
        <li key={`skel-${index}`} className="flex items-center justify-between gap-3 px-4 py-4">
          {children ?? (
            <div
              className={cn(
                "min-w-0 flex flex-1 gap-3",
                layout === "resource" ? "flex-col" : "items-center justify-between",
              )}
            >
              <div className="min-w-0 flex-1 space-y-2">
                <Skeleton className="h-5 w-1/3" />
                <Skeleton className="h-3 w-1/2" />
              </div>
              {layout === "resource" ? (
                <>
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                    <Skeleton className="h-10 w-full" />
                    <Skeleton className="h-10 w-full" />
                    <Skeleton className="hidden h-10 w-full sm:block" />
                  </div>
                  <div className="flex gap-2">
                    <Skeleton className="h-11 w-20" />
                    <Skeleton className="h-11 w-20" />
                  </div>
                </>
              ) : (
                <Skeleton className="h-11 w-20" />
              )}
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}
