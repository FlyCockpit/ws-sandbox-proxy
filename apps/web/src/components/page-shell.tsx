import { cn } from "@wssp/ui/lib/utils";
import type { ReactNode } from "react";

const WIDTH_CLASS = {
  narrow: "max-w-4xl",
  default: "max-w-5xl",
  wide: "max-w-7xl",
} as const;

const PAGE_FRAME = "container mx-auto px-4";

/** The widest page column: the signed-in dashboard frame's content column and
 * the content of a full-bleed band (a banner, the admin section nav), whose
 * background spans the window while its content lines up with the page below.
 * rem, so it grows with the root viewport scale. See
 * docs/design/shell-rules.md § Viewport scale */
export const PAGE_COLUMN_CLASS = `${PAGE_FRAME} ${WIDTH_CLASS.wide}`;

type PageShellProps = {
  width?: keyof typeof WIDTH_CLASS;
  /** Inside `DashboardFrame`, which already owns the container and padding. */
  inFrame?: boolean;
  className?: string;
  children: ReactNode;
};

export function PageShell({
  width = "default",
  inFrame = false,
  className,
  children,
}: PageShellProps) {
  return (
    <div
      className={cn(
        inFrame ? "min-w-0 space-y-6" : [PAGE_FRAME, "min-w-0 space-y-6 py-6 md:py-8"],
        !inFrame && WIDTH_CLASS[width],
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
        {description ? (
          <p className="max-w-prose text-sm text-muted-foreground">{description}</p>
        ) : null}
      </header>
      {actions}
    </div>
  );
}
