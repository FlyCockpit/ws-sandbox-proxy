import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { cn } from "@wssp/ui/lib/utils";
import type { FormEvent, ReactNode } from "react";

/**
 * A wide side sheet for forms and panels longer than a dialog allows
 * (form-surface rule): the header (title + close) and the action bar stay
 * put while only the body scrolls, the sheet uses the full width on phones
 * and up to 48rem on wider screens. With `onSubmit` the body and the action
 * bar are one `<form>`, so the primary action is a real submit button.
 */
export function WideSheet({
  title,
  description,
  closeLabel,
  onClose,
  busy = false,
  onSubmit,
  actions,
  children,
  className,
  ...data
}: {
  title: ReactNode;
  description?: ReactNode;
  closeLabel: string;
  onClose: () => void;
  /** While true the sheet cannot be dismissed (an in-flight write). */
  busy?: boolean;
  onSubmit?: (event: FormEvent<HTMLFormElement>) => void;
  /** The sticky action bar, primary action first. */
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
} & Record<`data-${string}`, string>) {
  const body = (
    <>
      <div
        data-slot="wide-sheet-body"
        className="flex min-h-0 min-w-0 flex-1 flex-col gap-6 overflow-x-hidden overflow-y-auto overscroll-contain p-4"
      >
        {children}
      </div>
      {actions ? (
        <div
          data-slot="wide-sheet-actions"
          className="flex min-w-0 shrink-0 flex-wrap items-center gap-2 border-t bg-background p-4 pb-[max(1rem,var(--safe-area-bottom))]"
        >
          {actions}
        </div>
      ) : null}
    </>
  );
  return (
    <Sheet open onOpenChange={(open) => (open || busy ? undefined : onClose())}>
      <SheetContent
        {...data}
        closeLabel={closeLabel}
        className={cn(
          "gap-0 overflow-hidden pt-[var(--safe-area-top)] data-[side=right]:w-full data-[side=right]:sm:max-w-3xl",
          className,
        )}
      >
        <SheetHeader className="border-b pr-16">
          <SheetTitle className="text-base">{title}</SheetTitle>
          {description ? (
            <SheetDescription className="text-sm">{description}</SheetDescription>
          ) : null}
        </SheetHeader>
        {onSubmit ? (
          <form
            noValidate
            className="flex min-h-0 min-w-0 flex-1 flex-col"
            onSubmit={(event) => {
              event.preventDefault();
              event.stopPropagation();
              onSubmit(event);
            }}
          >
            {body}
          </form>
        ) : (
          body
        )}
      </SheetContent>
    </Sheet>
  );
}
