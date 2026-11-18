import { HOST_HEARTBEAT_STALE_AFTER_MS } from "@wssp/config/host-status";
import type { Prisma } from "@wssp/db";
import { egressPolicyFromWire, vmRootChargeGiB } from "@wssp/sandbox-contracts";
import { egressGuardLeased } from "../egress-guard";
import { effectiveImagePlacement, hostImageFeatures } from "../image-store/config";
import { OFFLOADABLE_SANDBOX_PURPOSES } from "../managed-sandbox";

/**
 * Disk offload eligibility.
 *
 * Every predicate reads in the caller's transaction, under the locks the
 * caller already holds (the sandbox row at least). None writes.
 */

type Tx = Prisma.TransactionClient;

/** Lease states that hold no login value outside the vault (§4 safeguard 1). */
const SETTLED_LEASE_STATES = ["RELEASED", "FORCE_RELEASED", "ABANDONED"] as const;

/**
 * §4 safeguard 1 (I6): the sandbox's login state is settled, so an offload
 * neither loses nor duplicates a value. Checked under the sandbox lock at
 * enqueue, at disk begin and before STORED:
 * - no `CredentialLease` of the sandbox outside RELEASED | FORCE_RELEASED | ABANDONED;
 * - no recoverable, uncleared `CredentialResidue` (a newest value not yet in the vault);
 * - no `CredentialPendingCapture` for any lease of the sandbox.
 *
 * A recovery-state check, never a proof the disk is clean (`clearedAt`
 * proves nothing about the blocks). It never writes: `requireLeaseRecovery`
 * stays the only RECOVERY_REQUIRED writer.
 */
export async function loginStateSettled(tx: Tx, sandboxId: string): Promise<boolean> {
  const [row] = await tx.$queryRaw<{ unsettled: boolean }[]>`SELECT (
      EXISTS (SELECT 1 FROM credential_lease l WHERE l."sandboxId" = ${sandboxId}
        AND NOT (l.state::text = ANY(${[...SETTLED_LEASE_STATES]}::text[])))
      OR EXISTS (SELECT 1 FROM credential_residue r WHERE r."sandboxId" = ${sandboxId}
        AND r."clearedAt" IS NULL AND r.recoverable)
      OR EXISTS (SELECT 1 FROM credential_pending_capture p
        JOIN credential_lease l ON l.id = p."leaseId" WHERE l."sandboxId" = ${sandboxId})
    ) AS unsettled`;
  return row?.unsettled === false;
}

/** Operation states that are still in flight. */
const ACTIVE_STATES = ["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED"];

/**
 * §4a N4 receipt gate: the stopped generation holds no unretired UNKNOWN
 * receipt and no work in flight. An UNKNOWN_OUTCOME operation of that
 * generation counts as retired only once a host-observed stop of the same
 * generation succeeded after it was created (the stop retires it on the
 * stopped VM); a sandbox stopped any other way keeps it unretired, and so
 * stays local. Used by offload eligibility and the evict-grant CAS (C5).
 */
export async function offloadReceiptsSettled(
  tx: Tx,
  sandboxId: string,
  generation: number,
): Promise<boolean> {
  const [row] = await tx.$queryRaw<{ blocked: boolean }[]>`SELECT (
      EXISTS (SELECT 1 FROM sandbox_mutation_operation o WHERE o."sandboxId" = ${sandboxId}
        AND o.state::text = ANY(${ACTIVE_STATES}::text[]))
      OR EXISTS (SELECT 1 FROM sandbox_mutation_operation u WHERE u."sandboxId" = ${sandboxId}
        AND u.generation = ${generation} AND u.state::text = 'UNKNOWN_OUTCOME'
        AND NOT EXISTS (SELECT 1 FROM sandbox_mutation_operation s
          WHERE s."sandboxId" = ${sandboxId} AND s.generation = ${generation}
            AND s.kind::text = 'STOP_SANDBOX' AND s.state::text = 'SUCCEEDED'
            AND s.result->>'state' = 'stopped' AND s."createdAt" >= u."createdAt"))
    ) AS blocked`;
  return row?.blocked === false;
}

/** Whether a sandbox's purpose admits disk offload at all (R15.1). */
export function offloadablePurpose(purpose: string): boolean {
  return (OFFLOADABLE_SANDBOX_PURPOSES as readonly string[]).includes(purpose);
}

// ---------------------------------------------------------------- §5

/** The sandbox facts the restore-host predicate reads (from its row). */
export type RestoreSandboxFacts = {
  id: string;
  userId: string;
  templateId: string;
  purpose: string;
  diskGiB: number;
  guestSudo: boolean;
  egressPolicy: unknown;
  offloadPin: "ANY" | "OWN_HOSTS";
  credentialFilesEver: boolean;
  /** Preview tunnels: a tunnel sandbox (its declared ports ride the
   * restore dispatch). */
  tunnelEnabled?: boolean;
};

/**
 * The SDK-key placement restriction the caller resolved (C6b, §5a): the
 * intersection of the requesting key's and the creating key's live host
 * allowlists, and their pool selections. `null` legs impose no limit; a
 * revoked, expired, deleted or unrestricted key yields `null`.
 */
export type RestoreHostRestriction = {
  hostIds: ReadonlySet<string> | null;
  /** The pool the candidate is placed through (null = direct placement). */
  poolIds: ReadonlySet<string | null> | null;
};

export type RestoreHostIneligibleReason =
  | "purpose_managed"
  | "key_host_not_allowed"
  | "key_pool_not_allowed"
  | "host_missing"
  | "host_unavailable"
  | "host_draining"
  | "host_quarantined"
  | "egress_guard_unavailable"
  | "egress_unsupported"
  | "disk_offload_unsupported"
  | "guest_sudo_unsupported"
  | "tunnel_plan_unsupported"
  | "open_egress_not_permitted"
  | "image_fetch_unsupported"
  | "no_room"
  | "foreign_images_refused"
  | "pinned_to_own_hosts"
  | "login_history_own_hosts_only"
  | "image_placement_owned_only"
  | "stale_copy_on_host";

export type RestoreHostVerdict = { ok: true } | { ok: false; reason: RestoreHostIneligible };
type RestoreHostIneligible = RestoreHostIneligibleReason;

const HOST_FACTS_SELECT = {
  id: true,
  userId: true,
  status: true,
  lastHeartbeatAt: true,
  connectionEpoch: true,
  admissionEpoch: true,
  inventoryAcknowledgedEpoch: true,
  daemonSchedulable: true,
  draining: true,
  quarantinedAt: true,
  egressEnforcement: true,
  daemonFeatures: true,
  daemonDiskOffload: true,
  daemonTunnelPorts: true,
  daemonOpenEgressForOthers: true,
  daemonGuestSudoForOthers: true,
  daemonEgressGuardOk: true,
  daemonEgressGuardEpoch: true,
  daemonEgressGuardLeaseUntil: true,
} satisfies Prisma.SandboxHostSelect;

function featureFlag(features: Prisma.JsonValue | null, key: string): boolean {
  return (
    typeof features === "object" &&
    features !== null &&
    !Array.isArray(features) &&
    features[key] === true
  );
}

/**
 * THE restore-host predicate: whether `hostId` may take
 * a restore of `sandbox`. Used by the cached-host check, own-host selection,
 * pool and direct placement filters and an explicit `{hostId}`/`{poolId}`
 * body (C6), re-checked in the RESTORE_FETCH grant, and by the eviction CAS
 * ("at least one eligible restore host", C5). It requires:
 *
 * - an offloadable purpose (managed sandboxes are never restored);
 * - the SDK-key restriction the caller resolved (F10, §5a);
 * - a connected, admitted, schedulable host with a fresh heartbeat, neither
 *   draining nor quarantined, with a fresh egress guard lease, egress
 *   enforcement and the `diskOffload` capability;
 * - the guestSudo hard filter: when `sandbox.guestSudo`, the host advertises
 *   `guestSudo` and, if foreign, its owner allows guestSudo for others;
 * - open egress (hard filter): when the recorded effective mode is open and
 *   the host is foreign, `daemonOpenEgressForOthers` at the current epoch
 *   (the recorded policy is never re-derived or narrowed at restore);
 * - the image-fetch capability and a storage pool on the current epoch that
 *   can hold the root (`vmRootChargeGiB(diskGiB)`);
 * - on a foreign host: `acceptForeign`, and none of `offloadPin =
 *   OWN_HOSTS`, `credentialFilesEver`, or an `OWNED_NODES_ONLY` effective
 *   image placement of the template (F8);
 * - no `SandboxDiskCopy` of this sandbox on that host (R9). An unresolved
 *   census entry is recorded as a copy row by the census rule (C5).
 *
 * Reads under the caller's locks; never writes.
 */
export async function restoreHostEligibility(
  tx: Tx,
  sandbox: RestoreSandboxFacts,
  host: { hostId: string; poolId?: string | null },
  restriction: RestoreHostRestriction | null = null,
  now?: Date,
): Promise<RestoreHostVerdict> {
  const no = (reason: RestoreHostIneligibleReason): RestoreHostVerdict => ({ ok: false, reason });
  if (!offloadablePurpose(sandbox.purpose)) return no("purpose_managed");
  if (restriction?.hostIds && !restriction.hostIds.has(host.hostId))
    return no("key_host_not_allowed");
  if (restriction?.poolIds && !restriction.poolIds.has(host.poolId ?? null))
    return no("key_pool_not_allowed");
  const row = await tx.sandboxHost.findUnique({
    where: { id: host.hostId },
    select: HOST_FACTS_SELECT,
  });
  if (!row) return no("host_missing");
  const clock =
    now ??
    (await tx.$queryRaw<{ now: Date }[]>`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`)[0]
      ?.now ??
    new Date();
  const age = row.lastHeartbeatAt ? clock.getTime() - row.lastHeartbeatAt.getTime() : -1;
  if (
    row.status !== "CONNECTED" ||
    age < 0 ||
    age > HOST_HEARTBEAT_STALE_AFTER_MS ||
    row.admissionEpoch !== row.connectionEpoch ||
    row.inventoryAcknowledgedEpoch !== row.connectionEpoch ||
    row.daemonSchedulable !== true
  )
    return no("host_unavailable");
  if (row.draining) return no("host_draining");
  if (row.quarantinedAt) return no("host_quarantined");
  if (!egressGuardLeased(row, clock)) return no("egress_guard_unavailable");
  if (!row.egressEnforcement || !featureFlag(row.daemonFeatures, "egressPolicy"))
    return no("egress_unsupported");
  if (!row.daemonDiskOffload) return no("disk_offload_unsupported");
  const foreign = row.userId !== sandbox.userId;
  if (
    sandbox.guestSudo &&
    (!featureFlag(row.daemonFeatures, "guestSudo") || (foreign && !row.daemonGuestSudoForOthers))
  )
    return no("guest_sudo_unsupported");
  // Declared tunnel ports go only to a daemon that compiles them into its
  // network plan (an older one would refuse the whole dispatch).
  if (sandbox.tunnelEnabled && !row.daemonTunnelPorts) return no("tunnel_plan_unsupported");
  // A non-canonical stored policy is never treated as open here; launch
  // validation refuses it later.
  if (egressPolicyFromWire(sandbox.egressPolicy)?.mode === "open") {
    if (!featureFlag(row.daemonFeatures, "egressOpen")) return no("open_egress_not_permitted");
    if (foreign && !row.daemonOpenEgressForOthers) return no("open_egress_not_permitted");
  }
  const image = hostImageFeatures(row.daemonFeatures);
  if (!image?.fetch) return no("image_fetch_unsupported");
  const room = await tx.sandboxHostStoragePool.findFirst({
    where: {
      sandboxHostId: row.id,
      userId: row.userId,
      connectionEpoch: row.connectionEpoch,
      capacityGiB: { gte: vmRootChargeGiB(sandbox.diskGiB) },
    },
    select: { id: true },
  });
  if (!room) return no("no_room");
  if (foreign) {
    if (!image.acceptForeign) return no("foreign_images_refused");
    if (sandbox.offloadPin === "OWN_HOSTS") return no("pinned_to_own_hosts");
    if (sandbox.credentialFilesEver) return no("login_history_own_hosts_only");
    if ((await effectiveImagePlacement(tx, sandbox.userId, sandbox.templateId)) !== "ANY_NODE")
      return no("image_placement_owned_only");
  }
  const copy = await tx.sandboxDiskCopy.findFirst({
    where: { sandboxId: sandbox.id, hostId: row.id },
    select: { id: true },
  });
  if (copy) return no("stale_copy_on_host");
  return { ok: true };
}

/** The select that yields `RestoreSandboxFacts` from a sandbox row. */
export const RESTORE_SANDBOX_FACTS_SELECT = {
  id: true,
  userId: true,
  templateId: true,
  purpose: true,
  diskGiB: true,
  guestSudo: true,
  egressPolicy: true,
  offloadPin: true,
  credentialFilesEver: true,
  tunnelEnabled: true,
} satisfies Prisma.SandboxSelect;
