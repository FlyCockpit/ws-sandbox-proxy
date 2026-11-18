import { checkAcceptedDispatchAuthority } from "@wssp/api/lib/sdk-key-access";
import { type AuthorizingPrincipal, KEY_FREE_CLEANUP_KINDS } from "@wssp/api/sandbox/contracts";
import { egressGuardLeased } from "@wssp/api/sandbox/egress-guard";
import { requireRetainedStorage } from "@wssp/api/sandbox/host-admission";
import { decodeOutboxPrincipal, systemDispatchAllowed } from "@wssp/api/sandbox/outbox";
import { dispatchClassOf, recordedKeyIdOf } from "@wssp/api/sandbox/principal-kinds";
import type { Prisma } from "@wssp/db";
import {
  buildCopyV11Schema,
  buildIdOfContextPath,
  type DispatchStartupV11,
  dispatchBuildV11Schema,
  type EgressRefusalReason,
  egressPolicyFromWire,
  revisionStartup,
  runAsV11Schema,
} from "@wssp/sandbox-contracts";

/**
 * The dispatch-time gates that can change while a host is disconnected, shared
 * by the outbox processor's re-claim path and reconnect adoption
 * (`adoptOperation`). Every helper is a pure predicate: it reads, never writes.
 * Callers keep their own writes and their own ordering.
 */

type SandboxContext = {
  id: string;
  originHostId: string | null;
  templateRevisionId: string | null;
  originPoolId: string | null;
};

export type ReclaimAuthority = "active" | "inactive" | "indeterminate";

/** Authorizing-key/session authority of a dispatch principal. A malformed or
 * invalid-system principal is inactive without a lookup. Cleanup kinds and
 * cancellation are key-free (C21-9). */
export async function reclaimAuthorityVerdict(
  tx: Prisma.TransactionClient,
  input: {
    ownerId: string;
    principal: AuthorizingPrincipal | null;
    malformed: boolean;
    kind: string;
    sandbox: SandboxContext;
  },
): Promise<ReclaimAuthority> {
  if (input.malformed || !input.principal) return "inactive";
  return checkAcceptedDispatchAuthority(
    {
      ownerId: input.ownerId,
      principal: input.principal,
      cleanup: KEY_FREE_CLEANUP_KINDS.has(input.kind) || input.kind === "operation.cancel",
      operationKind: input.kind,
      context: {
        sandboxId: input.sandbox.id,
        sandboxHostId: input.sandbox.originHostId,
        templateRevisionId: input.sandbox.templateRevisionId,
        originPoolId: input.sandbox.originPoolId,
      },
    },
    tx,
  );
}

/** Mirrors authorizeOperation's SDK session-host binding before a send claim. */
export function sdkHostBindingHolds(
  authority: ReclaimAuthority,
  principal: AuthorizingPrincipal | null,
  sandboxHostId: string | null,
  hostId: string,
): boolean {
  return !(
    authority === "active" &&
    recordedKeyIdOf(principal) !== null &&
    sandboxHostId !== hostId
  );
}

/** C34: the current hello of `hostId` still advertises egress enforcement. The
 * caller holds the host row at its current epoch. */
export async function launchEgressAdvertised(
  tx: Prisma.TransactionClient,
  hostId: string,
  hostOwnerId: string,
): Promise<boolean> {
  const capable = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: hostOwnerId },
    select: { egressEnforcement: true },
  });
  return capable?.egressEnforcement === true;
}

/**
 * Default-open egress §1.4 (M7, M11, M18): the create-only backstop, run in
 * the epoch-locked dispatch transaction right after `launchEgressAdvertised`
 * and in `intentReclaimGates`. Callers invoke it ONLY for `sandbox.create`
 * Or a restore (a restore reconnect is a new VM on that
 * host, and no healthy guard means no new sandboxes; `restore` is derived
 * from the operation row, U9.1): the server never refuses an ordinary
 * reconnect for consent or guard reasons (the daemon decides cold vs warm). It never narrows the policy (that would be a
 * second producer of the effective policy): it admits or refuses.
 *
 * Requires an active guard lease at the current epoch (both modes) and, for
 * an open policy, the static `egressOpen` capability and either the host
 * owner's own sandbox or the owner's consent for others. Returns null when
 * admissible, else the typed refusal reason. The caller holds H.
 */
export async function createEgressAdmissible(
  tx: Prisma.TransactionClient,
  input: {
    hostId: string;
    hostOwnerId: string;
    sandboxOwnerId: string;
    /** The dispatched (effective) policy, stored wire form. */
    policy: unknown;
    /** Server clock of this transaction. */
    now: Date;
  },
): Promise<EgressRefusalReason | null> {
  const host = await tx.sandboxHost.findFirst({
    where: { id: input.hostId, userId: input.hostOwnerId },
    select: {
      connectionEpoch: true,
      daemonFeatures: true,
      daemonOpenEgressForOthers: true,
      daemonEgressGuardOk: true,
      daemonEgressGuardEpoch: true,
      daemonEgressGuardLeaseUntil: true,
    },
  });
  if (!host || !egressGuardLeased(host, input.now)) return "egress_guard_unavailable";
  // A non-canonical payload is refused later by launch validation; it is
  // never treated as open here.
  if (egressPolicyFromWire(input.policy)?.mode !== "open") return null;
  const features = host.daemonFeatures;
  const egressOpen =
    typeof features === "object" &&
    features !== null &&
    !Array.isArray(features) &&
    features.egressOpen === true;
  if (
    !egressOpen ||
    (input.hostOwnerId !== input.sandboxOwnerId && !host.daemonOpenEgressForOthers)
  )
    return "open_egress_not_permitted";
  return null;
}

/** Retained storage is present (and, for a create or a restore, admits new
 * roots and is not draining) for a create, a restore or a cold reconnect.
 * Other work needs no storage. `restore` comes from the operation row's
 * immutable launch mode and `restoreOffloadId` (`restoreOffloadOf`), never
 * from the outbox payload (offload plan U9.1); both callers pass it. */
export async function retainedStorageAdmits(
  tx: Prisma.TransactionClient,
  input: {
    hostId: string;
    ownerId: string;
    sandboxId: string;
    kind: string;
    sandboxState: string;
    restore: boolean;
  },
): Promise<boolean> {
  // A restore rides only on a reconnect; anything else is a producer bug.
  if (input.restore && input.kind !== "sandbox.reconnect") return false;
  const newRoot = input.kind === "sandbox.create" || input.restore;
  if (!(newRoot || (input.kind === "sandbox.reconnect" && input.sandboxState === "STOPPED")))
    return true;
  try {
    const storage = await requireRetainedStorage(tx, {
      hostId: input.hostId,
      ownerId: input.ownerId,
      sandboxId: input.sandboxId,
    });
    return !(newRoot && (!storage.newRootsAllowed || storage.draining));
  } catch {
    return false;
  }
}

/**
 * The processor's re-claim gates for work that has issued nothing yet (an
 * Intent-phase adoption): authority, SDK host binding, egress for launches and
 * retained storage, and (creates only) the egress consent/guard gate.
 * `indeterminate` never admits.
 */
export async function intentReclaimGates(
  tx: Prisma.TransactionClient,
  input: {
    ownerId: string;
    hostId: string;
    hostOwnerId: string;
    kind: string;
    payload: Record<string, unknown>;
    operationAuthorizingKeyId: string | null;
    sandbox: SandboxContext & { sandboxHostId: string | null; state: string };
    /** Server clock of this transaction (the egress guard lease). */
    now: Date;
    /** A restore attempt, from the operation row (`restoreOffloadOf`, U9.1). */
    restore: boolean;
  },
): Promise<"active" | "refused" | "indeterminate"> {
  const principal = decodeOutboxPrincipal(input.payload);
  const malformed =
    !principal ||
    input.operationAuthorizingKeyId !== recordedKeyIdOf(principal) ||
    (dispatchClassOf(principal, input.kind) === "system" &&
      !systemDispatchAllowed(input.kind, input.payload));
  const authority = await reclaimAuthorityVerdict(tx, {
    ownerId: input.ownerId,
    principal,
    malformed,
    kind: input.kind,
    sandbox: input.sandbox,
  });
  if (authority === "indeterminate") return "indeterminate";
  if (authority === "inactive") return "refused";
  if (!sdkHostBindingHolds(authority, principal, input.sandbox.sandboxHostId, input.hostId))
    return "refused";
  if (
    (input.kind === "sandbox.create" || input.kind === "sandbox.reconnect") &&
    !(await launchEgressAdvertised(tx, input.hostId, input.hostOwnerId))
  )
    return "refused";
  // §1.4 (M7): consent and guard gate creates (and restores, which boot a
  // new VM here), never an ordinary reconnect.
  if (
    (input.kind === "sandbox.create" || input.restore) &&
    (await createEgressAdmissible(tx, {
      hostId: input.hostId,
      hostOwnerId: input.hostOwnerId,
      sandboxOwnerId: input.ownerId,
      policy: input.payload.egressPolicy,
      now: input.now,
    })) !== null
  )
    return "refused";
  if (
    !(await retainedStorageAdmits(tx, {
      hostId: input.hostId,
      ownerId: input.ownerId,
      sandboxId: input.sandbox.id,
      kind: input.kind,
      sandboxState: input.sandbox.state,
      restore: input.restore,
    }))
  )
    return "refused";
  return "active";
}

/**
 * Defence in depth for template-build frame fields (plan template-builds §3.1
 * "Persistence, not context"; D1). `build` (create), `runAs` and `buildCopy`
 * (command) are written only by the build services, and only for the build
 * principal on its own `TEMPLATE_BUILD` VM. A payload whose fields do not
 * match the sandbox row they target is a producer bug: it is never dispatched
 * (the caller settles the operation as `protocol_error`). A build VM's create
 * must carry its own binding, so the daemon journals the build id that later
 * admits root steps.
 */
export function buildDispatchFieldsMatch(
  kind: string,
  payload: Record<string, unknown>,
  sandbox: { purpose: string; buildId: string | null; revisionSourceKind: string | null },
): boolean {
  const buildVm = sandbox.purpose === "TEMPLATE_BUILD" && sandbox.buildId !== null;
  // I12 (community-base), checked FIRST: an UPSTREAM revision boots only as a
  // community build VM's bootstrap create. Its reconnect never dispatches,
  // and bootstrap appears exactly on that create (bootstrap ⇔ UPSTREAM ∧
  // create ∧ build VM). `safeParse`: a malformed binding refuses, never throws.
  const bootstrap =
    payload.build !== undefined &&
    dispatchBuildV11Schema.safeParse(payload.build).data?.bootstrap === true;
  const upstream = sandbox.revisionSourceKind === "UPSTREAM";
  if (kind === "sandbox.reconnect" && (upstream || bootstrap)) return false;
  if (kind === "sandbox.create" && upstream !== (buildVm && bootstrap)) return false;
  if (bootstrap && !(upstream && buildVm && kind === "sandbox.create")) return false;
  const has = (field: "build" | "runAs" | "buildCopy") => payload[field] !== undefined;
  if (!has("build") && !has("runAs") && !has("buildCopy"))
    return !(buildVm && kind === "sandbox.create");
  if (!buildVm) return false;
  if (has("build")) {
    const parsed = dispatchBuildV11Schema.safeParse(payload.build);
    if (kind !== "sandbox.create" || !parsed.success || parsed.data.buildId !== sandbox.buildId)
      return false;
  } else if (kind === "sandbox.create") return false;
  if (has("runAs") && (kind !== "command.run" || !runAsV11Schema.safeParse(payload.runAs).success))
    return false;
  if (has("buildCopy")) {
    const parsed = buildCopyV11Schema.safeParse(payload.buildCopy);
    if (
      kind !== "command.run" ||
      !parsed.success ||
      has("runAs") ||
      buildIdOfContextPath(parsed.data.contextPath) !== sandbox.buildId
    )
      return false;
  }
  return true;
}

/**
 * B9: the start/ready commands a launch carries. Only `sandbox.create` and
 * `sandbox.reconnect` of an ordinary sandbox whose (immutable) revision has a
 * start command; never a build VM, which boots its base revision only to run
 * recipe steps.
 */
export async function launchStartup(
  tx: Prisma.TransactionClient,
  kind: string,
  sandbox: { userId: string; templateRevisionId: string | null; buildId: string | null },
): Promise<DispatchStartupV11 | undefined> {
  if (
    (kind !== "sandbox.create" && kind !== "sandbox.reconnect") ||
    sandbox.buildId !== null ||
    sandbox.templateRevisionId === null
  )
    return undefined;
  const revision = await tx.sandboxTemplateRevision.findFirst({
    where: { id: sandbox.templateRevisionId, userId: sandbox.userId },
    select: { startCmd: true, readyCmd: true, readyTimeoutMs: true, defaultCwd: true },
  });
  return revision ? revisionStartup(revision) : undefined;
}

/**
 * Caller holds H. DG-8: `guestSudo`/`guestRoot` go only to daemons that
 * admitted `guestSudo` on this epoch. A launch that needs this runtime
 * feature is refused (`unsupported_capability`) on
 * positive current-epoch evidence only; a disconnected or not yet admitted
 * host proves nothing.
 */
export function guestSudoHostUnsupported(
  host: {
    status: string;
    connectionEpoch: number;
    admissionEpoch: number | null;
    daemonFeatures: Prisma.JsonValue | null;
  } | null,
): boolean {
  if (host?.status !== "CONNECTED" || host.admissionEpoch !== host.connectionEpoch) return false;
  const features = host.daemonFeatures;
  return !(
    features != null &&
    typeof features === "object" &&
    !Array.isArray(features) &&
    features.guestSudo === true
  );
}

/**
 * Caller holds H. Startup goes only to daemons that admitted `templateStartup`
 * on this epoch; a launch that needs it is refused (`unsupported_capability`)
 * on positive current-epoch evidence only. A disconnected or not yet admitted
 * host proves nothing, so the launch stays pending until it reconnects.
 */
export function templateStartupHostUnsupported(
  host: {
    status: string;
    connectionEpoch: number;
    admissionEpoch: number | null;
    daemonFeatures: Prisma.JsonValue | null;
  } | null,
): boolean {
  if (host?.status !== "CONNECTED" || host.admissionEpoch !== host.connectionEpoch) return false;
  const features = host.daemonFeatures;
  return !(
    features != null &&
    typeof features === "object" &&
    !Array.isArray(features) &&
    features.templateStartup === true
  );
}

/**
 * Caller holds H. (U9.2): the disk fields (`restore`,
 * `launchMode`, `expectDisk`, `diskBaseFingerprint`) go only to daemons whose
 * hello on this epoch advertised `diskOffload`. A dispatch that needs
 * this runtime feature is refused
 * (`unsupported_capability`) on positive current-epoch evidence only; a
 * disconnected or not yet admitted host proves nothing.
 */
export function diskOffloadHostUnsupported(
  host: {
    status: string;
    connectionEpoch: number;
    admissionEpoch: number | null;
    daemonDiskOffload: boolean;
  } | null,
): boolean {
  if (host?.status !== "CONNECTED" || host.admissionEpoch !== host.connectionEpoch) return false;
  return !host.daemonDiskOffload;
}

/**
 * Caller holds H. Declared tunnel ports (`tunnelPorts`) go only to daemons
 * whose hello on this epoch advertised `tunnelPorts` (an older daemon's
 * strict dispatch parser would refuse the frame and drop the relay). Refused
 * (`unsupported_capability`) on positive current-epoch evidence only.
 */
export function tunnelPortsHostUnsupported(
  host: {
    status: string;
    connectionEpoch: number;
    admissionEpoch: number | null;
    daemonTunnelPorts: boolean;
  } | null,
): boolean {
  if (host?.status !== "CONNECTED" || host.admissionEpoch !== host.connectionEpoch) return false;
  return !host.daemonTunnelPorts;
}
