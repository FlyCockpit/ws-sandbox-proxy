import type { ReactNode } from "react";

/**
 * The live one-line summary at the start of a `FormPage` action bar ("2 vCPU
 * · 4 GiB · stops after 1 hour", or the refusal): pass it first in `actions`.
 * From `sm:` it fills the bar before the buttons; on phones it is its own
 * truncated line above them (an error still wraps in full).
 */
export function FormPageStatus({ children }: { children: ReactNode }) {
  return (
    <div
      data-form-page-status=""
      className="min-w-0 basis-full text-sm text-muted-foreground tabular-nums max-sm:truncate max-sm:has-[[role=alert]]:whitespace-normal sm:basis-0 sm:flex-1"
    >
      {children}
    </div>
  );
}
