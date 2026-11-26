import { useSyncExternalStore } from "react";

import { isGettingStartedHidden, subscribeGettingStartedHidden } from "@/lib/getting-started";

/**
 * Whether `scope` (a user id) hid the getting-started checklist in this
 * browser, live: hiding, Undo, and another tab's change all re-render.
 */
export function useGettingStartedHidden(scope: string): boolean {
  // One getter for both snapshots: the app branch is client-only, and on a
  // server (no `window`) it reads "not hidden" anyway.
  const read = () => isGettingStartedHidden(scope);
  return useSyncExternalStore(subscribeGettingStartedHidden, read, read);
}
