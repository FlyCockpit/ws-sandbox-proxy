import type { ServerCredentialMessage } from "@wssp/sandbox-contracts";

/**
 * Delivery of server-initiated credential frames (`credential.revoke`,
 * `credential.quarantine.discard`) from control-plane code to a host's
 * current relay session. The relay registers the sink at boot; without one
 * (worker, tests) delivery is a no-op. Delivery is best-effort by design:
 * a host that misses a revoke learns DISCARDED{force_released} on its next
 * capture, and a census that still lists a discarded quarantine id gets the
 * discard again.
 */
type Sink = (hostId: string, frame: ServerCredentialMessage) => boolean;

let sink: Sink | null = null;

export function registerCredentialFrameSink(next: Sink | null): void {
  sink = next;
}

export function deliverCredentialFrame(hostId: string, frame: ServerCredentialMessage): boolean {
  return sink ? sink(hostId, frame) : false;
}
