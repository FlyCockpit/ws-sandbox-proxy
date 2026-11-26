import { toast } from "@wssp/ui/components/sileo";

/**
 * How long the "User archived" toast (and its Undo) stays up. Longer than a
 * plain success toast: the admin has to notice it and reach the button.
 */
export const ARCHIVE_UNDO_TOAST_MS = 8_000;

/**
 * The success toast after an archive carries an Undo that restores the user.
 * Undo calls the same `users.unarchive` as the row's "Restore user" action, so
 * it lifts the ban only: the sessions the archive ended stay ended.
 */
export function announceArchivedWithUndo({
  message,
  undoLabel,
  onUndo,
}: {
  message: string;
  undoLabel: string;
  onUndo: () => void;
}): string {
  return toast.success(message, {
    duration: ARCHIVE_UNDO_TOAST_MS,
    action: { label: undoLabel, onClick: onUndo },
  });
}
