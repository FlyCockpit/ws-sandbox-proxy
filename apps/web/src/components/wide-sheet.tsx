import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { cn } from "@wssp/ui/lib/utils";
import type { FormEvent, ReactNode } from "react";

/**
 * A wide side sheet for forms and panels longer than a dialog allows
 * (form-surface rule): `<SheetContent size="wide">` with the header (title +
 * close) and the pinned `SheetFooter` around one `SheetBody` scroller. Sections
 * in the body (`FormSection`, `AdvancedSection`) are spaced as on a
 * `FormPage`, so consecutive Advanced sections join into one ruled list.
 * With `onSubmit` the body and the action bar are one `<form>`, so the
 * primary action is a real submit button. Actions: primary last.
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
  /** The pinned action bar, primary action last. */
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
} & Record<`data-${string}`, string>) {
  const body = (
    <>
      <SheetBody className="min-w-0 space-y-8 pt-4">{children}</SheetBody>
      {actions ? <SheetFooter className="min-w-0">{actions}</SheetFooter> : null}
    </>
  );
  return (
    <Sheet open onOpenChange={(open) => (open || busy ? undefined : onClose())}>
      <SheetContent
        {...data}
        size="wide"
        closeLabel={closeLabel}
        className={cn("gap-0 overflow-hidden pt-[var(--safe-area-top)]", className)}
      >
        <SheetHeader className="border-b">
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
