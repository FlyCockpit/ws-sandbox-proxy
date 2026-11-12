import { useEffect, useReducer } from "react";

/**
 * Re-render once when the wall clock reaches `atMs` (epoch ms), independent of
 * any data refetch. Pass null for no deadline. A new `atMs` replaces the
 * pending timer; unmount clears it. Used by the Hosts page so a host whose
 * heartbeat stops turns stale on screen even while the server is unreachable.
 */
export function useRerenderAt(atMs: number | null): void {
  const [, bump] = useReducer((n: number) => n + 1, 0);
  useEffect(() => {
    if (atMs == null) return;
    const timer = setTimeout(bump, Math.max(0, atMs - Date.now()));
    return () => clearTimeout(timer);
  }, [atMs]);
}
