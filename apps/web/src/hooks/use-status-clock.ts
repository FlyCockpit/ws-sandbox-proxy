import { useNetworkStatus } from "@/hooks/use-network-status";

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
 * connected host stale until the refetch lands (e2e5 T2-stale). A refetch
 * that fails ends `refreshing`, and the wall clock applies again.
 */
export function useStatusClock(dataUpdatedAt: number, refreshing = false): number {
  const online = useNetworkStatus();
  const now = Date.now();
  if (dataUpdatedAt <= 0) return now;
  return online && !refreshing ? now : Math.min(now, dataUpdatedAt);
}
