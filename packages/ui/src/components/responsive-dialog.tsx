"use client";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { cn } from "@wssp/ui/lib/utils";
import { useSyncExternalStore } from "react";

const DESKTOP_QUERY = "(min-width: 768px)";

function subscribe(callback: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  const mql = window.matchMedia(DESKTOP_QUERY);
  mql.addEventListener("change", callback);
  return () => mql.removeEventListener("change", callback);
}

function useIsDesktop(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => window.matchMedia(DESKTOP_QUERY).matches,
    () => false,
  );
}

export type ResponsiveDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: React.ReactNode;
  description?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  className?: string;
  /** Translated accessible name for the desktop close control. */
  closeLabel: string;
  /** Restore focus to the control that opened these details. */
  finalFocus?: React.ComponentProps<typeof DialogContent>["finalFocus"];
};

/**
 * Family details pattern: desktop dialog, mobile bottom drawer. Both layouts
 * use Base UI's dialog manager, so nested Create dialogs and Delete alerts
 * share its focus, inertness and Escape stack. Swapping overlay libraries at
 * the breakpoint would leave the mobile parent trapping its children's focus.
 * SSR starts with the mobile layout; the media subscription upgrades it without
 * remounting the dialog or its contents.
 */
export function ResponsiveDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  className,
  closeLabel,
  finalFocus,
}: ResponsiveDialogProps) {
  const isDesktop = useIsDesktop();

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        data-slot={isDesktop ? "dialog-content" : "drawer-content"}
        showCloseButton={isDesktop}
        closeLabel={closeLabel}
        finalFocus={finalFocus}
        className={cn(
          !isDesktop &&
            "inset-x-0 top-auto bottom-0 left-0 flex max-h-[80dvh] w-full max-w-none translate-x-0 translate-y-0 flex-col gap-0 overflow-hidden border-t p-0 sm:max-w-none",
          className,
        )}
        style={isDesktop ? undefined : { paddingBottom: "var(--safe-area-bottom)" }}
      >
        {!isDesktop ? <div className="mx-auto mt-4 h-1 w-24 shrink-0 bg-muted" /> : null}
        <DialogHeader className={cn(!isDesktop && "shrink-0 p-4 text-center")}>
          <DialogTitle>{title}</DialogTitle>
          {description ? <DialogDescription>{description}</DialogDescription> : null}
        </DialogHeader>
        <div
          className={cn(
            "min-w-0",
            !isDesktop &&
              "min-h-0 overflow-x-hidden overflow-y-auto overscroll-contain px-4 py-1.5",
          )}
        >
          {children}
        </div>
        {footer ? (
          <DialogFooter className={cn(!isDesktop && "m-0 mt-auto shrink-0 flex-col border-0 p-4")}>
            {footer}
          </DialogFooter>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
