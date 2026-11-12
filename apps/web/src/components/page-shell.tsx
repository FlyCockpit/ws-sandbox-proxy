import { cn } from "@wssp/ui/lib/utils";
import type { ReactNode } from "react";

const WIDTH_CLASS = {
  narrow: "max-w-4xl",
  default: "max-w-5xl",
  wide: "max-w-7xl",
} as const;

type PageShellProps = {
  width?: keyof typeof WIDTH_CLASS;
  className?: string;
  children: ReactNode;
};

export function PageShell({ width = "default", className, children }: PageShellProps) {
  return (
    <div
      className={cn(
        "container mx-auto min-w-0 space-y-6 px-4 py-6 md:py-8",
        WIDTH_CLASS[width],
        className,
      )}
    >
      {children}
    </div>
  );
}

type PageHeaderProps = {
  /** A back link above the title, e.g. `<SettingsBackLink />` on Settings pages. */
  back?: ReactNode;
  title: string;
  description?: string;
  actions?: ReactNode;
  className?: string;
};

export function PageHeader({ back, title, description, actions, className }: PageHeaderProps) {
  return (
    <div
      className={cn("flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between", className)}
    >
      <header className="min-w-0 space-y-1.5">
        {back}
        <h1 className="font-heading text-2xl font-semibold tracking-tight text-balance [overflow-wrap:anywhere]">
          {title}
        </h1>
        {description ? <p className="text-sm text-muted-foreground">{description}</p> : null}
      </header>
      {actions}
    </div>
  );
}
