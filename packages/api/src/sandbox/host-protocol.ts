import { ORPCError } from "@orpc/server";
import type { Prisma } from "@wssp/db";
import { SANDBOX_RELAY_PROTOCOL_VERSION } from "@wssp/sandbox-contracts";
import { lockHostByEpoch, requireRelayFence } from "./relay-fence";

/** The durable negotiated facts both predicates read under H. */
export type FsProcessHostFacts = {
  connectionEpoch: number;
  relayProtocolVersion: string | null;
  relayProtocolEpoch: number | null;
  admissionRuntime: string | null;
  admissionEpoch: number | null;
};

const FS_PROCESS_RUNTIMES: ReadonlySet<string> = new Set(["FAKE", "INCUS_KVM"]);

/**
 * Call before S/O/reservation, after owner/K. No process-local session truth.
 * Refuses only on positive current-epoch evidence of no support
 * (`fsProcessHostRefused`). A host between hello and its admission report
 * (every relay reconnect) proves nothing yet: the operation is accepted and
 * queued, dispatch stays held until `fsProcessHostSupported`, and an
 * admission that then reports no support settles it `unsupported_capability`
 * in the outbox.
 */
export async function requireFsProcessHost(
  tx: Prisma.TransactionClient,
  ownerId: string,
  hostId: string,
) {
  const located = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: ownerId },
    select: { connectionEpoch: true },
  });
  requireRelayFence(located !== null);
  await lockHostByEpoch(tx, hostId, located.connectionEpoch, ownerId);
  const host = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: ownerId },
    select: {
      connectionEpoch: true,
      relayProtocolVersion: true,
      relayProtocolEpoch: true,
      admissionRuntime: true,
      admissionEpoch: true,
      status: true,
    },
  });
  if (!host || fsProcessHostRefused(host))
    throw new ORPCError("BAD_REQUEST", {
      data: { code: "UNSUPPORTED_CAPABILITY" },
      message: "Capability is unsupported.",
    });
  return host;
}

/** Send authority: every fact is current-epoch and supported. Dispatch,
 * effective capabilities and the final send all require this. */
export function fsProcessHostSupported(host: FsProcessHostFacts | null | undefined): boolean {
  return (
    !!host &&
    host.relayProtocolVersion === SANDBOX_RELAY_PROTOCOL_VERSION &&
    host.relayProtocolEpoch === host.connectionEpoch &&
    host.admissionEpoch === host.connectionEpoch &&
    host.admissionRuntime !== null &&
    FS_PROCESS_RUNTIMES.has(host.admissionRuntime)
  );
}

/**
 * Admission refusal: positive current-epoch evidence that this host cannot
 * serve fs/process work — a current negotiated protocol other than the
 * supported one, or a current admission of a runtime without fs/process
 * support. Missing or stale facts (post-hello, pre-admission) prove nothing.
 * The outbox applies the same evidence rule to CONNECTED hosts
 * (`fsProcessHostUnsupported` in apps/server/src/sandbox-relay/outbox-processor.ts).
 */
export function fsProcessHostRefused(host: FsProcessHostFacts): boolean {
  return (
    (host.relayProtocolEpoch === host.connectionEpoch &&
      host.relayProtocolVersion !== null &&
      host.relayProtocolVersion !== SANDBOX_RELAY_PROTOCOL_VERSION) ||
    (host.admissionEpoch === host.connectionEpoch &&
      host.admissionRuntime !== null &&
      !FS_PROCESS_RUNTIMES.has(host.admissionRuntime))
  );
}
