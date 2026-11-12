/**
 * Egress guard lease (default-open egress §2.0.5, M18). The daemon reports the
 * node guard's health in `host.egress-state` every 5 s; the server stores a
 * lease that expires on its OWN clock, so a daemon that stops reporting loses
 * schedulability within the lease without any further message.
 */

/** Lease granted per healthy report, from the server clock. */
export const EGRESS_GUARD_LEASE_MS = 15_000;

/**
 * The guard lease predicate: the last report said healthy, on the current
 * connection epoch, and its lease has not expired at `now` (server clock).
 * Placement's `guard` stage (`pool-placement.ts`) is the same predicate in SQL;
 * direct placement and `createEgressAdmissible` use this one.
 */
export function egressGuardLeased(
  host: {
    connectionEpoch: number;
    daemonEgressGuardOk: boolean;
    daemonEgressGuardEpoch: number | null;
    daemonEgressGuardLeaseUntil: Date | null;
  },
  now: Date,
): boolean {
  return (
    host.daemonEgressGuardOk &&
    host.daemonEgressGuardEpoch === host.connectionEpoch &&
    host.daemonEgressGuardLeaseUntil !== null &&
    host.daemonEgressGuardLeaseUntil.getTime() > now.getTime()
  );
}
