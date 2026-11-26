import { AlertCircle } from "lucide-react";

/**
 * A failure that belongs to the whole form rather than one field (a rate
 * limit, a server that could not be reached), shown inside the form next to
 * its action instead of only as a toast.
 */
export function FormAlert({ message }: { message: string | null | undefined }) {
  if (!message) return null;
  return (
    <div
      role="alert"
      data-form-alert=""
      className="flex items-start gap-2 border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm text-destructive"
    >
      <AlertCircle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      <p className="min-w-0 break-words">{message}</p>
    </div>
  );
}
