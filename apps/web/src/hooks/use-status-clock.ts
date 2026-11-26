import { useEffect, useReducer, useState } from "react";
import { useNetworkStatus } from "@/hooks/use-network-status";

/** How long a running refetch may keep cached data judged as of its fetch. */
export const REFRESH_GRACE_MS = 10_000;

/**
 * The "now" host and sandbox status is judged against. Online it is the wall
 * clock. Offline it stops at the moment the data was last fetched
 * (`dataUpdatedAt`), so heartbeats don't age past their stale thresholds
 * while the browser, not the host, has lost the connection (design-review2
 * #12: offline, every host flipped to "Connection stale").
 *
 * `refreshing` (the query's `isFetching`): cached data is being replaced, so
 * it is judged as of its fetch too, not as of now. A list shown from cache
 * when a view mounts or re-enables its query (the Terminals page's hosts,
 * after filtering to Sandboxes for a while) would otherwise call every
 * connected host stale until the refetch lands (e2e5 T2-stale). That grace
 * lasts at most `REFRESH_GRACE_MS` of one refetch: a refetch that hangs (the
 * RPC has no deadline) must not keep a dead host "Connected" forever, so
 * after the grace, or when the refetch fails, the wall clock applies again.
 */
export function useStatusClock(dataUpdatedAt: number, refreshing = false): number {
  const online = useNetworkStatus();
  const [refreshSince, setRefreshSince] = useState<number | null>(null);
  const [, rerender] = useReducer((n: number) => n + 1, 0);
  const now = Date.now();
  // Derived during render (no effect): when this refetch started.
  if (refreshing && refreshSince === null) setRefreshSince(now);
  if (!refreshing && refreshSince !== null) setRefreshSince(null);
  const graceEnds = refreshing ? (refreshSince ?? now) + REFRESH_GRACE_MS : 0;
  const inGrace = now < graceEnds;
  // Re-render when the grace runs out, so a hung refetch turns stale on time.
  useEffect(() => {
    if (!inGrace) return;
    const timer = setTimeout(rerender, graceEnds - Date.now() + 1);
    return () => clearTimeout(timer);
  }, [inGrace, graceEnds]);
  if (dataUpdatedAt <= 0) return now;
  return online && !inGrace ? now : Math.min(now, dataUpdatedAt);
}
