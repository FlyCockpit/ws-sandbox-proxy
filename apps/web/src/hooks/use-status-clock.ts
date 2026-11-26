import { useNetworkStatus } from "@/hooks/use-network-status";

/**
 * The "now" host and sandbox status is judged against. Online it is the wall
 * clock. Offline it stops at the moment the data was last fetched
 * (`dataUpdatedAt`), so heartbeats don't age past their stale thresholds
 * while the browser, not the host, has lost the connection (design-review2
 * #12: offline, every host flipped to "Connection stale").
 */
export function useStatusClock(dataUpdatedAt: number): number {
  const online = useNetworkStatus();
  const now = Date.now();
  return online || dataUpdatedAt <= 0 ? now : Math.min(now, dataUpdatedAt);
}
