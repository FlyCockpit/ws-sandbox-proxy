import { cn } from "@wssp/ui/lib/utils";
import { ChevronDown } from "lucide-react";
import type * as React from "react";
import { useId } from "react";

/**
 * Form surfaces (design-system "Form surfaces"): a form longer than about six
 * controls is a page or a wide sheet, not a dialog. `FormPage` is that page:
 * a sticky header (back link + title), sections with headings that sit in two
 * columns from `lg:`, and a sticky action bar so the primary action is always
 * visible. It renders inside the layout's one main scroller, so `sticky`
 * resolves against main and the page never adds a second scroller.
 *
 * Local wssp wrapper written against the template-forms API; phase B swaps it
 * for the template's identical copy.
 */
function FormPage({
  title,
  description,
  back,
  actions,
  status,
  className,
  children,
  ...formProps
}: Omit<React.ComponentProps<"form">, "title"> & {
  title: React.ReactNode;
  description?: React.ReactNode;
  /** A back link (the page's parent); rendered before the title. */
  back?: React.ReactNode;
  /** The sticky action bar's content, primary action first. */
  actions: React.ReactNode;
  /** A one-line live summary shown in the action bar ("2 vCPU · 4 GiB · stops after 1 hour"). */
  status?: React.ReactNode;
}) {
  const titleId = useId();
  return (
    <form
      noValidate
      aria-labelledby={titleId}
      data-slot="form-page"
      className={cn("flex min-w-0 flex-col", className)}
      {...formProps}
    >
      {/* Phones pin only back + title (a compact bar); the description
          scrolls away with the form. From sm: the whole header is pinned. */}
      <header
        data-slot="form-page-header"
        className="contents sm:sticky sm:top-0 sm:z-10 sm:-mx-4 sm:flex sm:min-w-0 sm:flex-col sm:gap-1 sm:border-b sm:bg-background/95 sm:px-4 sm:py-3 sm:backdrop-blur sm:supports-backdrop-filter:bg-background/80"
      >
        <div
          data-slot="form-page-header-bar"
          className="sticky top-0 z-10 -mx-4 flex min-w-0 flex-col border-b bg-background/95 px-4 py-2 backdrop-blur supports-backdrop-filter:bg-background/80 sm:static sm:z-auto sm:mx-0 sm:gap-1 sm:border-0 sm:bg-transparent sm:p-0 sm:backdrop-blur-none sm:supports-backdrop-filter:bg-transparent"
        >
          {back ? <div className="flex min-w-0 items-center">{back}</div> : null}
          <h1
            id={titleId}
            className="min-w-0 text-lg font-semibold tracking-tight text-balance sm:text-xl"
          >
            {title}
          </h1>
        </div>
        {description ? (
          <p
            data-slot="form-page-description"
            className="min-w-0 pt-2 text-sm text-muted-foreground text-pretty sm:pt-0"
          >
            {description}
          </p>
        ) : null}
      </header>
      <div data-slot="form-page-body" className="flex min-w-0 flex-col gap-6 py-6">
        {children}
      </div>
      {/* Phones: a compact bar, the status on one truncated line above the
          buttons, which stay in one row (an error still wraps in full). */}
      <div
        data-slot="form-page-actions"
        className="sticky bottom-0 z-10 -mx-4 flex min-w-0 flex-wrap items-center gap-x-4 gap-y-1 border-t bg-background/95 px-4 py-2 backdrop-blur supports-backdrop-filter:bg-background/80 sm:gap-y-2 sm:py-3"
      >
        <div className="flex min-w-0 flex-nowrap items-center gap-2 sm:flex-wrap">{actions}</div>
        {status ? (
          <div
            data-slot="form-page-status"
            className="min-w-0 flex-1 text-sm text-muted-foreground tabular-nums max-sm:order-first max-sm:basis-full max-sm:truncate max-sm:has-[[role=alert]]:whitespace-normal"
          >
            {status}
          </div>
        ) : null}
      </div>
    </form>
  );
}

/**
 * A titled section. On wide screens the heading column sits beside the fields
 * (two columns from `lg:`); on phones they stack.
 */
function FormSection({
  title,
  description,
  className,
  children,
  ...props
}: Omit<React.ComponentProps<"section">, "title"> & {
  title: React.ReactNode;
  description?: React.ReactNode;
}) {
  const headingId = useId();
  return (
    <section
      aria-labelledby={headingId}
      data-slot="form-section"
      className={cn(
        "grid min-w-0 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)] lg:gap-8",
        className,
      )}
      {...props}
    >
      <div className="flex min-w-0 flex-col gap-1">
        <h2 id={headingId} className="text-base font-medium">
          {title}
        </h2>
        {description ? (
          <div className="text-sm text-muted-foreground text-pretty">{description}</div>
        ) : null}
      </div>
      <div className="flex min-w-0 flex-col gap-4">{children}</div>
    </section>
  );
}

/**
 * A collapsed-by-default disclosure for expert fields. The summary line shows
 * the current values while closed ("2 vCPU · 4 GiB"), so nothing is secret.
 * Native `<details>`: keyboard and screen-reader behaviour come free, and a
 * closed section still keeps its fields mounted (values and validation stay).
 */
function AdvancedSection({
  title,
  summary,
  open,
  onToggle,
  className,
  children,
  ...props
}: Omit<React.ComponentProps<"details">, "title" | "onToggle"> & {
  title: React.ReactNode;
  /** The current values in one line, shown next to the title. */
  summary?: React.ReactNode;
  onToggle?: (open: boolean) => void;
}) {
  return (
    <details
      data-slot="advanced-section"
      open={open}
      onToggle={(event) => onToggle?.(event.currentTarget.open)}
      className={cn("group min-w-0 rounded-lg border", className)}
      {...props}
    >
      <summary className="flex min-h-11 cursor-pointer list-none items-center gap-3 px-3 py-2 [&::-webkit-details-marker]:hidden">
        <ChevronDown
          aria-hidden="true"
          className="size-4 shrink-0 -rotate-90 text-muted-foreground transition-transform group-open:rotate-0"
        />
        <span className="shrink-0 text-sm font-medium">{title}</span>
        {summary ? (
          <span
            data-slot="advanced-section-summary"
            className="min-w-0 flex-1 truncate text-end text-sm text-muted-foreground tabular-nums"
          >
            {summary}
          </span>
        ) : null}
      </summary>
      <div className="flex min-w-0 flex-col gap-4 border-t px-3 py-4">{children}</div>
    </details>
  );
}

/**
 * Focus the first invalid control in `root` (after a failed submit), opening
 * any closed `<details>` around it first. Returns whether one was found.
 */
function focusFirstInvalid(root: HTMLElement | null): boolean {
  if (!root) return false;
  const target = root.querySelector<HTMLElement>('[aria-invalid="true"]');
  if (!target) return false;
  for (let node = target.parentElement; node && node !== root; node = node.parentElement) {
    if (node instanceof HTMLDetailsElement && !node.open) node.open = true;
  }
  target.focus();
  target.scrollIntoView?.({ block: "center" });
  return true;
}

export { AdvancedSection, FormPage, FormSection, focusFirstInvalid };
