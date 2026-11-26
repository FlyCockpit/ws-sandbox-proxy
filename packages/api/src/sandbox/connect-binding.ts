/**
 * CLI shell authority (`GET /v1/sandboxes/{id}/connect`): the
 * retained `sandboxes.connect` authorization of one kind `API` key plus the
 * sandbox's live placement, read the same way the browser terminal re-reads
 * its binding. Used before the upgrade (HTTP refusals) and on every re-read
 * while the connection lives (heartbeat, authority commits, lifecycle
 * notifications, key or lease expiry).
 *
 * Authorization failures throw (the /v1 catalog maps them: FORBIDDEN 403,
 * another owner's or a missing sandbox NOT_FOUND 404, a managed sandbox
 * CONFLICT `sandbox.managed`). A sandbox that is authorized but not usable
 * now resolves `{ ok: false, intent }`.
 */
import prisma, { type Prisma } from "@wssp/db";
import {
  authorizeRetainedServiceAction,
  type RetainedServiceAuthorization,
  type ServicePrincipal,
} from "../lib/sdk-key-access";

/** The server-side identity of one CLI connection (never client-supplied). */
export type SandboxConnectBinding = {
  ownerId: string;
  keyId: string;
  sandboxId: string;
  hostId: string;
  hostOwnerId: string;
  generation: number;
  /** The host's registered connection epoch the channels ride. */
  epoch: number;
  /** The key's own expiry (null: none); the connection never outlives it. */
  keyExpiresAt: Date | null;
  leaseExpiresAt: Date | null;
};

/** Why an authorized connection cannot (any longer) use the sandbox. */
export type SandboxConnectRevocation =
  | "revoked"
  | "sandbox_stopped"
  | "sandbox_destroyed"
  | "superseded"
  | "expired"
  | "host_disconnected"
  | "unsupported"
  | "lifecycle_unconfirmed"
  /** An authority change overlapped the read: nothing is decided; read again. */
  | "stale";

const STOPPED_STATES = new Set(["STOPPING", "STOPPED", "OFFLOADED"]);
const DESTROYED_STATES = new Set(["DELETED", "RECLAIMING", "HOST_LOST"]);

const connectSandboxSelect = {
  state: true,
  purpose: true,
  buildId: true,
  verifyBuildId: true,
  generation: true,
  sandboxHostId: true,
  hostOwnerId: true,
  accessGraceUntil: true,
  leaseExpiresAt: true,
  SandboxHost: { select: { userId: true, connectionEpoch: true, deletionRequestedAt: true } },
  CurrentPlacement: {
    select: { userId: true, hostOwnerId: true, originHostId: true, generation: true },
  },
} satisfies Prisma.SandboxSelect;

export type SandboxConnectCheck =
  | {
      ok: true;
      binding: SandboxConnectBinding;
      retained: RetainedServiceAuthorization;
    }
  | { ok: false; intent: SandboxConnectRevocation };

/**
 * Authorize `sandboxes.connect` for `principal` on `sandboxId` and read the
 * sandbox's placement. `expected` (a live connection's re-read) pins the
 * host, host owner, generation and host connection epoch the connection was
 * opened against; any change ends it.
 */
export async function checkSandboxConnect(
  principal: ServicePrincipal,
  sandboxId: string,
  expected?: Pick<SandboxConnectBinding, "hostId" | "hostOwnerId" | "generation" | "epoch">,
  now: () => Date = () => new Date(),
): Promise<SandboxConnectCheck> {
  const retained = await authorizeRetainedServiceAction(principal, "sandboxes.connect", {
    sandboxId,
  });
  const sandbox = await prisma.sandbox.findFirst({
    where: { id: sandboxId, userId: principal.ownerId },
    select: connectSandboxSelect,
  });
  // The read is trusted only if no authority change started before or during it.
  if (!retained.current()) return { ok: false, intent: "stale" };
  const at = now();
  if (!sandbox) return { ok: false, intent: "sandbox_destroyed" };
  // Build, verify and CLI-login VMs never get a channel (the managed guard
  // already refused them; this is the explicit second check).
  if (sandbox.purpose !== "WORKLOAD" || sandbox.buildId || sandbox.verifyBuildId)
    return { ok: false, intent: "unsupported" };
  if (sandbox.accessGraceUntil) return { ok: false, intent: "revoked" };
  if (DESTROYED_STATES.has(sandbox.state)) return { ok: false, intent: "sandbox_destroyed" };
  if (STOPPED_STATES.has(sandbox.state)) return { ok: false, intent: "sandbox_stopped" };
  if (
    expected &&
    (sandbox.generation !== expected.generation || sandbox.sandboxHostId !== expected.hostId)
  )
    return { ok: false, intent: "superseded" };
  if (sandbox.leaseExpiresAt && sandbox.leaseExpiresAt.getTime() <= at.getTime())
    return { ok: false, intent: "expired" };
  if (sandbox.state !== "READY" || !sandbox.sandboxHostId)
    return { ok: false, intent: "lifecycle_unconfirmed" };
  const host = sandbox.SandboxHost;
  const placement = sandbox.CurrentPlacement;
  if (!host || host.deletionRequestedAt || host.userId !== sandbox.hostOwnerId)
    return { ok: false, intent: "revoked" };
  if (expected && expected.hostOwnerId !== host.userId) return { ok: false, intent: "superseded" };
  if (expected && expected.epoch !== host.connectionEpoch)
    return { ok: false, intent: "host_disconnected" };
  if (
    (placement &&
      (placement.userId !== principal.ownerId ||
        placement.hostOwnerId !== host.userId ||
        placement.originHostId !== sandbox.sandboxHostId ||
        placement.generation !== sandbox.generation)) ||
    (host.userId !== principal.ownerId && !placement)
  )
    return { ok: false, intent: "revoked" };
  return {
    ok: true,
    retained,
    binding: {
      ownerId: principal.ownerId,
      keyId: principal.keyId,
      sandboxId,
      hostId: sandbox.sandboxHostId,
      hostOwnerId: host.userId,
      generation: sandbox.generation,
      epoch: host.connectionEpoch,
      keyExpiresAt: principal.expiresAt,
      leaseExpiresAt: sandbox.leaseExpiresAt,
    },
  };
}
