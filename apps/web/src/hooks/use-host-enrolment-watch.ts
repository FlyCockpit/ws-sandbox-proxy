import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import type { HostItem } from "@/components/hosts/host-row";
import { hostConnectionState } from "@/lib/host-status";
import { orpc } from "@/utils/orpc";

/** How often the Add host page looks for the new host. */
export const ENROLMENT_POLL_MS = 5_000;
/** The watch stops polling after this long; "Check again" restarts it. */
export const ENROLMENT_WATCH_MS = 30 * 60_000;
/** The newest hosts are enough: a host enrolled now is first in createdAt order. */
const WATCH_LIMIT = 20;

export type EnrolmentWatch =
  | { phase: "loading" }
  /** The first hosts read failed: nothing to compare against yet. */
  | { phase: "failed" }
  | { phase: "waiting"; expired: boolean }
  | { phase: "enrolled"; host: HostItem; expired: boolean }
  | { phase: "connected"; host: HostItem };

/**
 * Watches the owner's newest hosts while they follow the Add host steps.
 * The first answer is the baseline: a host that was not there then (or was
 * there but not connected, and connects now) is "yours". Polls every five
 * seconds, stops once it is connected or after thirty minutes, and never
 * reads anything the Hosts list does not already show.
 */
export function useHostEnrolmentWatch(): EnrolmentWatch & { restart: () => void } {
  const [startedAt, setStartedAt] = useState(() => Date.now());
  const [baseline, setBaseline] = useState<Map<string, boolean> | null>(null);
  const [connectedId, setConnectedId] = useState<string | null>(null);
  const query = useQuery({
    ...orpc.sandboxHosts.listHosts.queryOptions({ input: { limit: WATCH_LIMIT } }),
    staleTime: 0,
    refetchOnMount: "always",
    refetchInterval: () =>
      connectedId !== null || Date.now() - startedAt > ENROLMENT_WATCH_MS
        ? false
        : ENROLMENT_POLL_MS,
    meta: { skipGlobalErrorToast: true },
  });
  const restart = () => {
    setStartedAt(Date.now());
    void query.refetch();
  };
  const hosts = query.data?.items;
  if (!hosts) return { phase: query.isError ? "failed" : "loading", restart };
  const now = Date.now();
  // Derived state from the first answer (React's "previous render" pattern).
  if (baseline === null) {
    setBaseline(
      new Map(hosts.map((host) => [host.id, hostConnectionState(host, now) === "ready"])),
    );
    return { phase: "waiting", expired: false, restart };
  }
  const live = hosts.filter((host) => host.deletionRequestedAt == null);
  const fresh = live.filter((host) => !baseline.has(host.id));
  const connected =
    live.find((host) => host.id === connectedId) ??
    live.find(
      (host) => baseline.get(host.id) !== true && hostConnectionState(host, now) === "ready",
    );
  if (connected) {
    if (connectedId !== connected.id) setConnectedId(connected.id);
    return { phase: "connected", host: connected, restart };
  }
  const expired = now - startedAt > ENROLMENT_WATCH_MS;
  const enrolled = fresh[0];
  return enrolled
    ? { phase: "enrolled", host: enrolled, expired, restart }
    : { phase: "waiting", expired, restart };
}
