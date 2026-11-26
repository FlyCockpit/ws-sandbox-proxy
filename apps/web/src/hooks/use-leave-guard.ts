import { useBlocker } from "@tanstack/react-router";

/**
 * Asks before leaving the page while `active` (a one-time secret is on
 * screen): in-app navigation is held by the router's blocker until the person
 * chooses `proceed` or `reset`, and closing or reloading the tab gets the
 * browser's own "leave site?" prompt (`beforeunload`).
 */
export function useLeaveGuard(active: boolean) {
  const blocker = useBlocker({
    shouldBlockFn: () => active,
    enableBeforeUnload: () => active,
    disabled: !active,
    withResolver: true,
  });
  return blocker.status === "blocked"
    ? { blocked: true as const, stay: blocker.reset, leave: blocker.proceed }
    : { blocked: false as const, stay: () => {}, leave: () => {} };
}
