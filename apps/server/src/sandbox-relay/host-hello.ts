import { bindHostStaticCapacity } from "@wssp/api/sandbox/host-admission";
import { requestDigestMetadata } from "@wssp/api/sandbox/idempotency";
import { sandboxOutboxTransaction } from "@wssp/api/sandbox/outbox";
import { hostDatabaseNow, lockHostForHello } from "@wssp/api/sandbox/relay-fence";
import { notifySharingAccessChanged } from "@wssp/api/sandbox/sharing-access";
import type { NodeDaemonRuntime } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { Prisma } from "@wssp/db/client";
import { knownRelayProtocolVersion } from "@wssp/sandbox-contracts";
import { type DaemonControlMessage, type DaemonRuntimeKind } from "./protocol.js";

const DAEMON_RUNTIME = {
  fake: "FAKE",
  incus_kvm: "INCUS_KVM",
  unsupported: "UNSUPPORTED",
} as const satisfies Record<DaemonRuntimeKind, NodeDaemonRuntime>;

/**
 * The durable half of a host hello: one transaction that refreshes the
 * connection row — incrementing `connectionEpoch` and re-recording the
 * advertised capabilities, including the egress-enforcement admission gate —
 * and reopens every dispatch intent sent on an older epoch. `handleHello`
 * performs the socket bookkeeping around this commit. The race between this
 * transaction and an in-flight launch dispatch is covered by
 * egress-capability-race.pg.test.ts.
 */
export async function commitHostHello(input: {
  identity: { hostId: string; userId: string };
  message: Extract<DaemonControlMessage, { type: "hello" }>;
  now: Date;
}): Promise<number> {
  const { identity, message } = input;
  const protocolVersion = message.protocolVersion;
  if (!knownRelayProtocolVersion(protocolVersion)) throw new Error("unsupported relay protocol");
  const updated = await sandboxOutboxTransaction(async (tx) => {
    await lockOwnerForAdmission(tx, identity.userId);
    const existing = await tx.sandboxHost.findFirst({
      where: { id: identity.hostId, userId: identity.userId },
      select: { id: true },
    });
    if (existing == null) {
      throw new Error("missing host");
    }
    await lockHostForHello(tx, identity.hostId, identity.userId);
    const now = await hostDatabaseNow(tx);
    const host = await tx.sandboxHost.update({
      where: { id: identity.hostId, userId: identity.userId },
      data: {
        status: "CONNECTED",
        capacityReport: Prisma.DbNull,
        relayProtocolVersion: protocolVersion,
        inventoryAcknowledgedEpoch: null,
        journalKeyAcknowledgedEpoch: null,
        journalKeyVersion: 1,
        journalKeyId: requestDigestMetadata().requestDigestKeyId,
        admissionRuntime: null,
        admissionEpoch: null,
        admissionReportedAt: null,
        daemonSchedulable: null,
        // Hello-time image capabilities ride along until host.admission
        // folds them into the admitted feature set for this epoch.
        // B9 start/ready support rides along the same way.
        daemonFeatures: {
          ...(message.daemon.capabilities.image
            ? { helloImage: message.daemon.capabilities.image }
            : {}),
          ...(message.daemon.capabilities.templateStartup === true
            ? { helloTemplateStartup: true }
            : {}),
          // guestSudo rides along the same way; admitted as `guestSudo`.
          ...(message.daemon.capabilities.guestSudo === true ? { helloGuestSudo: true } : {}),
          // CLI logins: folded into `credentials` at admission (placement §8).
          ...(message.daemon.capabilities.credentials
            ? { helloCredentials: message.daemon.capabilities.credentials }
            : {}),
        },
        imageCacheCapBytes: null,
        imageCacheUsedBytes: null,
        imageCacheForeignBytes: null,
        imageCacheEpoch: null,
        availabilityEpoch: null,
        availabilityCensusComplete: false,
        lastConnectedAt: now,
        lastHeartbeatAt: now,
        connectionCount: { increment: 1 },
        connectionEpoch: { increment: 1 },
        // The owner-set label is authoritative (dashboard edits must stick);
        // the daemon's runtime and version are display-only metadata. The
        // egress capability is an admission gate, refreshed per hello.
        daemonRuntime: DAEMON_RUNTIME[message.daemon.capabilities.runtimeKind],
        daemonVersion: message.daemon.version ?? null,
        // Prior-epoch telemetry is not a report from this new connection.
        policyReconcilerHealth: {},
        egressEnforcement: message.daemon.capabilities.egressPolicy,
        // Persist the required ceiling under the host lock; null means unlimited.
        daemonMaxLeaseMs: message.daemon.capabilities.maxLeaseMs,
        daemonLeasePolicy: true,
        // Default-open egress (§2.5): the hello's guard bit is display
        // evidence only. Consent and the guard LEASE come from this
        // connection's `host.egress-state` reports, so a new connection is
        // not schedulable until its first healthy report; a daemon without
        // the egress capability never is (refused, not downgraded).
        daemonOpenEgressForOthers: false,
        // Same for guestSudo consent: fail closed until this connection
        // reports it (the resolver also needs the admitted capability).
        daemonGuestSudoForOthers: false,
        // Disk offload is optional runtime support, refreshed on every hello.
        daemonDiskOffload: message.daemon.capabilities.diskOffload === true,
        daemonEgressGuardOk: message.daemon.capabilities.egress.guard === true,
        daemonEgressGuardReason: null,
        daemonEgressGuardLeaseUntil: null,
        daemonEgressStateSequence: null,
      },
      select: { connectionEpoch: true },
    });
    await bindHostStaticCapacity(tx, {
      hostId: identity.hostId,
      ownerId: identity.userId,
      epoch: host.connectionEpoch,
      capacity: { vmCapacity: message.vmCapacity, storagePools: message.storagePools },
    });
    const bound = await tx.sandboxHost.updateMany({
      where: {
        id: identity.hostId,
        userId: identity.userId,
        connectionEpoch: host.connectionEpoch,
      },
      data: {
        relayProtocolEpoch: host.connectionEpoch,
        daemonEgressGuardEpoch: host.connectionEpoch,
      },
    });
    if (bound.count !== 1) throw new Error("relay protocol epoch binding failed");
    // Hello retains the last scalar VM budget for offline cold acceptance.
    // Current admission is established only by host.admission, before census.
    // Only unacknowledged dispatch intents survive progress. Reopen them for
    // the new epoch; accepted/running events are already processed.
    await tx.outboxEvent.updateMany({
      where: {
        userId: identity.userId,
        aggregateType: "sandbox",
        processedAt: null,
        sentConnectionEpoch: { lt: host.connectionEpoch },
        payload: { path: ["sandboxHostId"], equals: identity.hostId },
      },
      data: { sentAt: null, claimToken: null, claimedAt: null },
    });
    return host;
  });
  // After commit: the pull-in sweep re-checks this host's sandboxes against
  // the (possibly lowered) ceiling.
  notifySharingAccessChanged();
  return updated.connectionEpoch;
}
