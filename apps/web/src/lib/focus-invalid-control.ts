import { focusFirstInvalidField } from "@wssp/ui/lib/focus-first-invalid";

/**
 * The first invalid control a person can type into: Base UI also marks
 * `RangeField`'s slider group (a `div`) and its range thumb invalid, and they
 * come first in the DOM, so the shared selector would land on a box that
 * cannot take focus.
 */
const INVALID_CONTROL =
  ':is(input:not([type="range"]), textarea, select, button, [role="combobox"])[aria-invalid="true"]:not(:disabled)';

/**
 * `focusFirstInvalidField` (opens the closed Advanced section first, waits a
 * frame), restricted to typeable controls. Use it where a form holds a
 * `RangeField`.
 */
export function focusFirstInvalidControl(
  root: ParentNode | null | undefined,
  schedule?: (callback: () => void) => unknown,
): unknown {
  if (!root) return undefined;
  return focusFirstInvalidField(
    { querySelector: <E extends Element>() => root.querySelector<E>(INVALID_CONTROL) },
    schedule,
  );
}

/** Whether `root` holds an invalid control (synchronously, for submit gates). */
export function hasInvalidControl(root: ParentNode | null | undefined): boolean {
  return Boolean(root?.querySelector(INVALID_CONTROL));
}
