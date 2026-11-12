import { cn } from "@wssp/ui/lib/utils";
import { Inbox } from "lucide-react";
import type { ReactNode } from "react";

type EmptyStateProps = {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
};

export function EmptyState({ title, description, action, className }: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex min-w-0 items-start gap-3 rounded-xl bg-card p-4 text-left text-card-foreground",
        className,
      )}
    >
      <Inbox aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-muted-foreground" />
      <div className="min-w-0 space-y-1">
        <p className="font-heading text-base font-semibold">{title}</p>
        {description ? (
          <div className="max-w-prose text-sm text-muted-foreground">{description}</div>
        ) : null}
        {action}
      </div>
    </div>
  );
}
