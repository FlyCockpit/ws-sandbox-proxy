import prisma from "@wssp/db";
import {
  normalizeTunnelPorts,
  type SandboxTunnelDto,
  type SandboxTunnelPortsDto,
  TUNNEL_MAX_PORTS,
  type TunnelLinkDto,
  type TunnelLinkRevokedDto,
} from "@wssp/sandbox-contracts";
import { authorizeServiceAction, serviceProcedure } from "../../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../budgets";
import type { Principal } from "../contracts";
import {
  sandboxNotFound,
  tunnelLinkNotFound,
  tunnelNotFound,
  tunnelNotReady,
  tunnelPortsLimit,
  tunnelPortUndeclared,
  tunnelQuota,
  tunnelRefused,
  tunnelUnavailable,
} from "../errors";
import { budgetSubjectOf, recordedKeyIdOf } from "../principal-kinds";
import { wakeTunnelController } from "./bridge";
import {
  readTunnelServer,
  TUNNEL_CONFIG_ID,
  TunnelCredentialUnavailable,
  tunnelConfigured,
} from "./config";
import {
  readSandboxTunnelDto,
  recordTunnelEvent,
  type SandboxTunnelRow,
  sandboxTunnelSelect,
  TUNNEL_HOLD_MARGIN_MS,
  TUNNEL_HOLD_MS,
  toSandboxTunnelDto,
  tunnelLabel,
} from "./rows";
import {
  deleteTunnel,
  mintAccessLink,
  revokeAccessLink,
  TunServerError,
  tunnelsByLabel,
} from "./tun-client";

export { recordTunnelEvent, sandboxTunnelSelect, toSandboxTunnelDto };

/**
 * Preview tunnels, SDK/REST side (docs/guide/tunnels.md). These calls record
 * what the caller wants; the tunnel controller (`controller.ts`) creates,
 * rotates and deletes tunnels on the tunnel server and drives the host. A
 * caller never sees a tunnel credential: only preview origins and, from a link
 * mint, a one-time access URL.
 */

async function spend(owner: Principal) {
  const subject = budgetSubjectOf(owner)?.ownerId;
  if (subject) await consumeSandboxWriteBudget(subject, "tunnel");
}

async function requireConfigured() {
  if (!(await tunnelConfigured())) throw tunnelRefused("tunnel_off");
}

async function ownedSandbox(owner: Principal, id: string) {
  const sandbox = await prisma.sandbox.findFirst({
    where: { id, userId: owner.ownerId, state: { not: "DELETED" } },
    select: {
      id: true,
      purpose: true,
      tunnelEnabled: true,
      tunnelPorts: true,
      sandboxHostId: true,
      hostOwnerId: true,
    },
  });
  if (!sandbox) throw sandboxNotFound();
  return sandbox;
}

async function readServerOr503() {
  try {
    const server = await readTunnelServer();
    if (!server) throw tunnelRefused("tunnel_off");
    return server;
  } catch (error) {
    if (error instanceof TunnelCredentialUnavailable) throw tunnelUnavailable();
    throw error;
  }
}

export const getSandboxTunnel = serviceProcedure(
  { action: "sandboxes.tunnelGet", target: (input: { id: string }) => ({ sandboxId: input.id }) },
  async (owner: Principal, input: { id: string }): Promise<SandboxTunnelDto> => {
    await requireConfigured();
    await ownedSandbox(owner, input.id);
    // A closed tunnel too (its tombstone lives until the sandbox is
    // deleted): the caller learns when its clean-up is done.
    const dto = await readSandboxTunnelDto(prisma, input.id, owner.ownerId);
    if (!dto) throw tunnelNotFound();
    return dto;
  },
);

export const exposeSandboxTunnel = serviceProcedure(
  {
    action: "sandboxes.tunnelExpose",
    target: (input: { id: string; ports?: number[] }) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, input: { id: string; ports?: number[] }): Promise<SandboxTunnelDto> => {
    await spend(owner);
    await requireConfigured();
    const sandbox = await ownedSandbox(owner, input.id);
    const declared = new Set(sandbox.tunnelPorts);
    if (sandbox.purpose !== "WORKLOAD" || declared.size === 0) throw tunnelPortUndeclared();
    const ports = normalizeTunnelPorts(input.ports ?? sandbox.tunnelPorts);
    if (ports.length === 0 || !ports.every((port) => declared.has(port)))
      throw tunnelPortUndeclared();
    if (sandbox.sandboxHostId) {
      const host = await prisma.sandboxHost.findFirst({
        where: { id: sandbox.sandboxHostId },
        select: { userId: true, daemonTunnel: true },
      });
      const capability = host?.daemonTunnel as { allowForOthers?: unknown } | null | undefined;
      if (!host || !capability) throw tunnelRefused("tunnel_host_unsupported");
      if (host.userId !== owner.ownerId && capability.allowForOthers !== true)
        throw tunnelRefused("tunnel_not_shared");
    }
    const row = await prisma.$transaction(async (tx) => {
      // The caller's authority is re-checked (and its owner/key locked) by
      // the write itself: a key revoked meanwhile changes nothing.
      await authorizeServiceAction(owner, "sandboxes.tunnelExpose", { sandboxId: sandbox.id }, tx);
      // One owner at a time: the quota count and the insert are serialized.
      await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtext(${`wssp:tunnels:${owner.ownerId}`}))`;
      // Serialized with the turn-off's final removal (FOR UPDATE there): no
      // open row appears once tunnels are turning off or gone.
      const [config] = await tx.$queryRaw<
        { maxTunnelsPerOwner: number; disabledAt: Date | null }[]
      >`SELECT "maxTunnelsPerOwner", "disabledAt" FROM tunnel_server_config
        WHERE id = ${TUNNEL_CONFIG_ID} FOR SHARE`;
      if (!config || config.disabledAt) throw tunnelRefused("tunnel_off");
      // The sandbox row before the tunnel row (as the port update takes
      // them): the ports are validated against the declaration this write
      // is serialized with, so a concurrent removal is never undone.
      const [locked] = await tx.$queryRaw<{ tunnelPorts: number[] }[]>`
        SELECT "tunnelPorts" FROM sandbox_instance
        WHERE id = ${sandbox.id} AND "userId" = ${owner.ownerId} AND state <> 'DELETED'
        FOR SHARE`;
      if (!locked) throw sandboxNotFound();
      const lockedDeclared = new Set(locked.tunnelPorts);
      if (!ports.every((port) => lockedDeclared.has(port))) throw tunnelPortUndeclared();
      // The row's lock (as close takes it): the state read below is the one
      // this write replaces, so a concurrent close is never undone.
      await tx.$queryRaw`SELECT 1 AS locked FROM sandbox_tunnel
        WHERE "sandboxId" = ${sandbox.id} AND "userId" = ${owner.ownerId} FOR UPDATE`;
      const existing = await tx.sandboxTunnel.findFirst({
        where: { sandboxId: sandbox.id, userId: owner.ownerId },
        select: sandboxTunnelSelect,
      });
      const open = existing !== null && existing.closedAt === null;
      // A closed row whose remote state is not confirmed deleted yet must
      // not be reopened (its old links would work again): retry shortly.
      if (existing && !open && existing.serverKey !== null) throw tunnelNotReady();
      if (!open) {
        const held = await tx.sandboxTunnel.count({
          where: { userId: owner.ownerId, closedAt: null },
        });
        if (held >= config.maxTunnelsPerOwner) throw tunnelQuota();
      }
      const same =
        open &&
        existing.ports.length === ports.length &&
        existing.ports.every((port, index) => port === ports[index]);
      if (same && existing.state !== "ERROR") return existing;
      // Every change bumps the generation (never reset, also across a
      // close): an apply prepared for the old state fails its
      // compare-and-set, and a host never sees a generation twice.
      const saved = existing
        ? await tx.sandboxTunnel.update({
            where: { sandboxId: sandbox.id, userId: owner.ownerId },
            data: {
              ports,
              // A host the row named may still run the old client: the
              // trigger records it (`sandbox_tunnel_client_stop`).
              hostId: null,
              closedAt: null,
              cleanupForgottenAt: null,
              // credential-settlement: exempt (preview-tunnel row generation)
              generation: { increment: 1 },
              // A new port set is not connected until the host confirms it.
              state: "PENDING" as const,
              lastError: null,
              connectedAt: null,
            },
            select: sandboxTunnelSelect,
          })
        : await tx.sandboxTunnel.create({
            data: { sandboxId: sandbox.id, userId: owner.ownerId, ports, state: "PENDING" },
            select: sandboxTunnelSelect,
          });
      if (!same)
        await recordTunnelEvent(tx, {
          kind: "tunnel.enabled",
          userId: owner.ownerId,
          sandboxId: sandbox.id,
          actorId: owner.ownerId,
          actorKeyId: recordedKeyIdOf(owner),
          detail: ports.join(","),
        });
      return saved;
    });
    wakeTunnelController();
    return toSandboxTunnelDto(row, 0);
  },
);

export const closeSandboxTunnel = serviceProcedure(
  { action: "sandboxes.tunnelClose", target: (input: { id: string }) => ({ sandboxId: input.id }) },
  async (owner: Principal, input: { id: string }): Promise<SandboxTunnelDto> => {
    await spend(owner);
    await requireConfigured();
    await ownedSandbox(owner, input.id);
    await closeTunnelRow(owner, input.id);
    // The row as it is now: what the close (or an earlier one) left, so a
    // repeated close answers the closed tunnel and its clean-up too (or an
    // expose that came after it).
    const dto = await readSandboxTunnelDto(prisma, input.id, owner.ownerId);
    if (!dto) throw tunnelNotFound();
    return dto;
  },
);

/**
 * Close: mark the row closed (a tombstone that keeps its generation) and try
 * to delete its tunnel and every other one labelled for the sandbox at once,
 * with the configuration its remote state was made with, under the row's
 * clean-up hold taken by the close itself (so no other pass cleans up, and
 * no re-expose's create starts, while this sweeps; it settles by the hold).
 * The tunnel server's deletion is what stops every client and link; if it
 * cannot be reached now the controller keeps retrying (the row keeps its key
 * until then). The same write forgets the row's host, so the trigger records
 * that host's obligation to confirm its client stopped; the controller sends
 * it `tunnel.clear` until it does.
 * Returns the closed row, or null when there was no open tunnel.
 */
export async function closeTunnelRow(
  owner: Principal,
  sandboxId: string,
): Promise<SandboxTunnelRow | null> {
  const userId = owner.ownerId;
  const actor = { actorId: owner.ownerId, actorKeyId: recordedKeyIdOf(owner) };
  const closed = await prisma.$transaction(async (tx) => {
    // The caller's authority is re-checked (and its owner/key locked) by
    // the write itself: a key revoked meanwhile changes nothing.
    await authorizeServiceAction(owner, "sandboxes.tunnelClose", { sandboxId }, tx);
    // The row's lock: what it held when closed is exactly what is cleaned.
    await tx.$queryRaw`SELECT 1 AS locked FROM sandbox_tunnel
      WHERE "sandboxId" = ${sandboxId} AND "userId" = ${userId} FOR UPDATE`;
    const row = await tx.sandboxTunnel.findFirst({
      where: { sandboxId, userId, closedAt: null },
      select: { ...sandboxTunnelSelect, creatingUntil: true },
    });
    if (!row) return null;
    // Remote state and no create in flight (that one settles itself first):
    // this close cleans up, under the row's hold.
    const hold =
      row.serverKey !== null && row.creatingUntil === null
        ? new Date(Date.now() + TUNNEL_HOLD_MS)
        : null;
    const updated = await tx.sandboxTunnel.update({
      where: { sandboxId, userId },
      data: {
        closedAt: new Date(),
        // The bump fails a create hold or apply prepared on the open row.
        // credential-settlement: exempt (preview-tunnel row generation)
        generation: { increment: 1 },
        state: "SUSPENDED",
        lastError: null,
        // The trigger records this host's client-stop obligation.
        hostId: null,
        connectedAt: null,
        ...(hold ? { creatingUntil: hold } : {}),
      },
      select: sandboxTunnelSelect,
    });
    await recordTunnelEvent(tx, {
      kind: "tunnel.disabled",
      userId,
      sandboxId,
      ...actor,
      detail: row.tunTunnelId,
    });
    return { after: updated, hold };
  });
  if (!closed) return null;
  const { after, hold } = closed;
  // The host's `tunnel.clear` comes from the obligation (the controller's
  // next pass), before the tunnel-server calls below.
  wakeTunnelController();
  await cleanUpHeld({ sandboxId, userId, after, hold, tunnelId: after.tunTunnelId });
  wakeTunnelController();
  return after;
}

/**
 * The remote half of a close (or of a port removal that replaces the
 * tunnel): under the row's clean-up hold its transaction took, delete
 * `tunnelId` and every other tunnel labelled for the sandbox with the
 * configuration the remote state was made with. Settled by the hold and the
 * new generation; anything that fails is left to the controller (the row
 * keeps its key and owes the sweep). The host's client is stopped through
 * the obligation the transaction's trigger recorded (the controller).
 */
async function cleanUpHeld(input: {
  sandboxId: string;
  userId: string;
  after: SandboxTunnelRow;
  hold: Date | null;
  tunnelId: string | null;
}) {
  const { sandboxId, userId, after, hold, tunnelId } = input;
  if (!hold) return;
  // Each call starts early enough to end before the hold can expire.
  const inTime = () => {
    if (Date.now() > hold.getTime() - TUNNEL_HOLD_MARGIN_MS)
      throw new Error("tunnel clean-up hold ran out");
  };
  let settled = false;
  try {
    const server = await readTunnelServer();
    // Only with the configuration the remote state belongs to.
    if (server && server.serverKey === after.serverKey) {
      inTime();
      if (tunnelId) await deleteTunnel(server, tunnelId);
      for (const id of await tunnelsByLabel(
        server,
        tunnelLabel(server.serverKey, sandboxId),
        undefined,
        inTime,
      )) {
        inTime();
        await deleteTunnel(server, id);
      }
      // Settled by the hold and the change's generation (a late obligation
      // meanwhile bumps it: then the hold is given back and the controller
      // finishes). Until then a closed row refuses a re-expose.
      const done = await prisma.sandboxTunnel.updateMany({
        where: {
          sandboxId,
          userId,
          generation: after.generation,
          creatingUntil: hold,
          serverKey: after.serverKey,
        },
        data: {
          tunTunnelId: null,
          hostTemplate: null,
          hostId: null,
          sweepLabel: false,
          creatingUntil: null,
          serverKey: null,
        },
      });
      settled = done.count === 1;
    }
  } catch {
    // The controller retries the deletion.
  }
  if (!settled)
    await prisma.sandboxTunnel
      .updateMany({ where: { sandboxId, creatingUntil: hold }, data: { creatingUntil: null } })
      .catch(() => {
        // The hold expires into a label sweep.
      });
}

/**
 * Add or remove a tunnel sandbox's declared ports at runtime (audited). One
 * transaction re-authorizes the caller, locks the sandbox and its tunnel row,
 * bumps `tunnelPortsRevision` (the controller sends the host `tunnel.ports`
 * until the sandbox's current host acknowledges it), and narrows the exposed
 * set. Removing an EXPOSED port replaces the tunnel: tunnel-server access is
 * per tunnel, not per port, so the old tunnel (with every link and browser
 * session it granted) is deleted here, under the row's hold, before the host
 * hears of the change; the controller creates a new one for the kept ports.
 * Removing every exposed port closes the tunnel.
 */
export const updateSandboxTunnelPorts = serviceProcedure(
  {
    action: "sandboxes.tunnelPorts",
    target: (input: { id: string }) => ({ sandboxId: input.id }),
  },
  async (
    owner: Principal,
    input: { id: string; add?: number[]; remove?: number[] },
  ): Promise<SandboxTunnelPortsDto> => {
    await spend(owner);
    await requireConfigured();
    const sandbox = await ownedSandbox(owner, input.id);
    if (sandbox.purpose !== "WORKLOAD" || !sandbox.tunnelEnabled)
      throw tunnelRefused("tunnel_not_enabled");
    const add = input.add ?? [];
    const remove = new Set(input.remove ?? []);
    const userId = owner.ownerId;
    const actor = { actorId: owner.ownerId, actorKeyId: recordedKeyIdOf(owner) };
    const changed = await prisma.$transaction(async (tx) => {
      // The caller's authority is re-checked (and its owner/key locked) by
      // the write itself: a key revoked meanwhile changes nothing.
      await authorizeServiceAction(owner, "sandboxes.tunnelPorts", { sandboxId: sandbox.id }, tx);
      const [config] = await tx.$queryRaw<{ disabledAt: Date | null }[]>`
        SELECT "disabledAt" FROM tunnel_server_config WHERE id = ${TUNNEL_CONFIG_ID} FOR SHARE`;
      if (!config || config.disabledAt) throw tunnelRefused("tunnel_off");
      // The sandbox row first (as every lifecycle writer), then the tunnel row.
      const [current] = await tx.$queryRaw<
        {
          tunnelPorts: number[];
          tunnelPortsRevision: number;
          tunnelPortsAckHostId: string | null;
          tunnelPortsAckRevision: number;
          sandboxHostId: string | null;
        }[]
      >`SELECT "tunnelPorts", "tunnelPortsRevision", "tunnelPortsAckHostId",
               "tunnelPortsAckRevision", "sandboxHostId"
        FROM sandbox_instance
        WHERE id = ${sandbox.id} AND "userId" = ${userId} AND "tunnelEnabled"
          AND state <> 'DELETED' FOR UPDATE`;
      if (!current) throw sandboxNotFound();
      const next = normalizeTunnelPorts([
        ...new Set([...current.tunnelPorts, ...add].filter((port) => !remove.has(port))),
      ]);
      if (next.length > TUNNEL_MAX_PORTS) throw tunnelPortsLimit();
      const declared = normalizeTunnelPorts(current.tunnelPorts);
      if (next.length === declared.length && next.every((port, i) => port === declared[i]))
        return { ports: next, ...current, cleanup: null };
      const revision = current.tunnelPortsRevision + 1;
      await tx.sandbox.updateMany({
        where: { id: sandbox.id, userId },
        data: { tunnelPorts: next, tunnelPortsRevision: revision },
      });
      await tx.$queryRaw`SELECT 1 AS locked FROM sandbox_tunnel
        WHERE "sandboxId" = ${sandbox.id} AND "userId" = ${userId} FOR UPDATE`;
      const row = await tx.sandboxTunnel.findFirst({
        where: { sandboxId: sandbox.id, userId, closedAt: null },
        select: { ...sandboxTunnelSelect, creatingUntil: true },
      });
      const kept = row ? row.ports.filter((port) => next.includes(port)) : [];
      let cleanup: {
        after: SandboxTunnelRow;
        hold: Date | null;
        tunnelId: string | null;
      } | null = null;
      if (row && kept.length < row.ports.length) {
        // An exposed port leaves: this transaction replaces (or closes) the
        // tunnel. Remote state and no create in flight: it cleans up under
        // the row's hold (a create in flight fails its compare-and-set on the
        // bumped generation and deletes what it made).
        const hold =
          row.serverKey !== null && row.creatingUntil === null
            ? new Date(Date.now() + TUNNEL_HOLD_MS)
            : null;
        const after = await tx.sandboxTunnel.update({
          where: { sandboxId: sandbox.id, userId },
          data: {
            ...(kept.length === 0
              ? { closedAt: new Date(), state: "SUSPENDED" as const }
              : {
                  ports: kept,
                  state: "PENDING" as const,
                  connectedAt: null,
                  // The old tunnel is forgotten: the label sweep (here under
                  // the hold, else by the controller) deletes it before any
                  // new one is created.
                  tunTunnelId: null,
                  hostTemplate: null,
                  ...(row.serverKey !== null ? { sweepLabel: true } : {}),
                }),
            hostId: null,
            lastError: null,
            // credential-settlement: exempt (preview-tunnel row generation)
            generation: { increment: 1 },
            ...(hold ? { creatingUntil: hold } : {}),
          },
          select: sandboxTunnelSelect,
        });
        if (kept.length === 0)
          await recordTunnelEvent(tx, {
            kind: "tunnel.disabled",
            userId,
            sandboxId: sandbox.id,
            ...actor,
            detail: row.tunTunnelId,
          });
        cleanup = { after, hold, tunnelId: row.tunTunnelId };
      }
      await recordTunnelEvent(tx, {
        kind: "ports.changed",
        userId,
        sandboxId: sandbox.id,
        ...actor,
        detail: `${next.join(",")}@${revision}`,
      });
      return { ...current, ports: next, tunnelPortsRevision: revision, cleanup };
    });
    if (changed.cleanup) {
      // The host's `tunnel.clear` (from the obligation) first.
      wakeTunnelController();
      await cleanUpHeld({ sandboxId: sandbox.id, userId, ...changed.cleanup });
    }
    wakeTunnelController();
    const acked =
      changed.tunnelPortsRevision === 0 ||
      (changed.sandboxHostId !== null &&
        changed.tunnelPortsAckHostId === changed.sandboxHostId &&
        changed.tunnelPortsAckRevision >= changed.tunnelPortsRevision);
    return {
      sandboxId: sandbox.id,
      ports: changed.ports,
      revision: changed.tunnelPortsRevision,
      state: acked ? "applied" : "pending",
    };
  },
);

/** The declared ports of a tunnel sandbox and whether its host has them. */
export const getSandboxTunnelPorts = async (
  owner: Principal,
  id: string,
): Promise<SandboxTunnelPortsDto> => {
  const sandbox = await prisma.sandbox.findFirst({
    where: { id, userId: owner.ownerId, state: { not: "DELETED" }, tunnelEnabled: true },
    select: {
      tunnelPorts: true,
      tunnelPortsRevision: true,
      tunnelPortsAckHostId: true,
      tunnelPortsAckRevision: true,
      sandboxHostId: true,
    },
  });
  if (!sandbox) throw tunnelRefused("tunnel_not_enabled");
  const acked =
    sandbox.tunnelPortsRevision === 0 ||
    (sandbox.sandboxHostId !== null &&
      sandbox.tunnelPortsAckHostId === sandbox.sandboxHostId &&
      sandbox.tunnelPortsAckRevision >= sandbox.tunnelPortsRevision);
  return {
    sandboxId: id,
    ports: normalizeTunnelPorts(sandbox.tunnelPorts),
    revision: sandbox.tunnelPortsRevision,
    state: acked ? "applied" : "pending",
  };
};

export const createSandboxTunnelLink = serviceProcedure(
  {
    action: "sandboxes.tunnelLink",
    target: (input: { id: string }) => ({ sandboxId: input.id }),
  },
  async (
    owner: Principal,
    input: {
      id: string;
      port: number;
      ttlSeconds?: number;
      singleUse?: boolean;
      sessionTtlSeconds?: number;
    },
  ): Promise<TunnelLinkDto> => {
    await spend(owner);
    await requireConfigured();
    await ownedSandbox(owner, input.id);
    const row = await prisma.sandboxTunnel.findFirst({
      where: { sandboxId: input.id, userId: owner.ownerId, closedAt: null },
      select: sandboxTunnelSelect,
    });
    if (!row) throw tunnelNotFound();
    if (!row.ports.includes(input.port)) throw tunnelPortUndeclared();
    if (!row.tunTunnelId || row.state !== "CONNECTED") throw tunnelNotReady();
    const server = await readServerOr503();
    // The tunnel belongs to the configuration it was made with.
    if (row.serverKey !== server.serverKey) throw tunnelNotReady();
    const singleUse = input.singleUse ?? true;
    const sessionTtlSeconds = input.sessionTtlSeconds ?? 3600;
    let link: Awaited<ReturnType<typeof mintAccessLink>>;
    try {
      link = await mintAccessLink(server, row.tunTunnelId, {
        port: input.port,
        ttlSeconds: input.ttlSeconds ?? 60,
        singleUse,
        sessionTtlSeconds,
      });
    } catch (error) {
      if (error instanceof TunServerError && error.notFound) {
        wakeTunnelController();
        throw tunnelNotReady();
      }
      throw tunnelUnavailable();
    }
    // The record that scopes its revocation (and its audit), before the URL
    // is handed out: without one the link is revoked again and the mint fails.
    try {
      await prisma.$transaction(async (tx) => {
        // Serialized with remove-now and the turn-off's final removal (FOR
        // UPDATE there): a configuration no longer current is recorded as
        // forgotten (its tunnels may outlive it).
        const [config] = await tx.$queryRaw<{ serverKey: string }[]>`
          SELECT "serverKey" FROM tunnel_server_config WHERE id = ${TUNNEL_CONFIG_ID} FOR SHARE`;
        await tx.sandboxTunnelLink.create({
          data: {
            id: link.id,
            sandboxId: input.id,
            userId: owner.ownerId,
            serverKey: server.serverKey,
            port: input.port,
            liveUntil: new Date(link.expiresAt.getTime() + sessionTtlSeconds * 1000 + LINK_SKEW_MS),
            forgottenAt: config?.serverKey === server.serverKey ? null : new Date(),
          },
        });
        await recordTunnelEvent(tx, {
          kind: "link.minted",
          userId: owner.ownerId,
          sandboxId: input.id,
          actorId: owner.ownerId,
          actorKeyId: recordedKeyIdOf(owner),
          port: input.port,
          detail: link.id,
        });
      });
    } catch {
      await revokeAccessLink(server, link.id).catch(() => undefined);
      throw tunnelUnavailable();
    }
    return {
      id: link.id,
      url: link.url,
      port: input.port,
      expiresAt: link.expiresAt.toISOString(),
      singleUse,
    };
  },
);

/** Clock skew allowed between wssp and the tunnel server on link lifetimes. */
const LINK_SKEW_MS = 5 * 60_000;

/**
 * Revoke one access link of the sandbox's tunnel (audited, idempotent). The
 * link must be one this deployment minted for THIS sandbox and owner (its
 * `sandbox_tunnel_link` record; the service credential could revoke any link
 * of any of its tunnels): another sandbox's link is not found. One
 * transaction re-authorizes the caller and admits the request (recorded and
 * audited once, like a close); the tunnel server then ends the link and
 * every browser session it granted, while the tunnel's other links keep
 * working. A 404 from the tunnel server confirms the link gone only when the
 * current credential is the one that minted it, or the minting
 * configuration was drained (its tunnels confirmed deleted), or the link has
 * outlived any session: after a remove-now another server may still honour
 * it, so the call answers 503 instead of a false success.
 */
export const revokeSandboxTunnelLink = serviceProcedure(
  {
    action: "sandboxes.tunnelLinkRevoke",
    target: (input: { id: string; linkId: string }) => ({ sandboxId: input.id }),
  },
  async (
    owner: Principal,
    input: { id: string; linkId: string },
  ): Promise<TunnelLinkRevokedDto> => {
    await spend(owner);
    // Not refused while tunnels are off: a link of a forgotten configuration
    // still answers truthfully (503 while it may live).
    await ownedSandbox(owner, input.id);
    const result = { id: input.linkId, sandboxId: input.id };
    const admitted = await prisma.$transaction(async (tx) => {
      // The caller's authority is re-checked (and its owner/key locked) by
      // the admission itself: a key revoked meanwhile revokes nothing.
      await authorizeServiceAction(
        owner,
        "sandboxes.tunnelLinkRevoke",
        { sandboxId: input.id },
        tx,
      );
      // The configuration before the link: remove-now locks it FOR UPDATE
      // before it marks that configuration's links forgotten.
      const [config] = await tx.$queryRaw<{ serverKey: string }[]>`
        SELECT "serverKey" FROM tunnel_server_config WHERE id = ${TUNNEL_CONFIG_ID} FOR SHARE`;
      const [link] = await tx.$queryRaw<
        {
          serverKey: string;
          port: number;
          liveUntil: Date;
          revokeRequestedAt: Date | null;
          revokedAt: Date | null;
          forgottenAt: Date | null;
          now: Date;
        }[]
      >`SELECT "serverKey", port, "liveUntil", "revokeRequestedAt", "revokedAt", "forgottenAt",
               clock_timestamp() AS now
        FROM sandbox_tunnel_link
        WHERE id = ${input.linkId} AND "sandboxId" = ${input.id} AND "userId" = ${owner.ownerId}
        FOR UPDATE`;
      if (!link) throw tunnelLinkNotFound();
      if (link.revokeRequestedAt === null) {
        await tx.sandboxTunnelLink.update({
          where: { id: input.linkId },
          data: { revokeRequestedAt: link.now },
        });
        await recordTunnelEvent(tx, {
          kind: "link.revoked",
          userId: owner.ownerId,
          sandboxId: input.id,
          actorId: owner.ownerId,
          actorKeyId: recordedKeyIdOf(owner),
          port: link.port,
          detail: input.linkId,
        });
      }
      // Gone without asking: confirmed already, past any session's life, or
      // minted under a configuration that was drained (every tunnel of it
      // deleted on the tunnel server, its links with them).
      const dead =
        link.revokedAt !== null ||
        link.liveUntil < link.now ||
        (link.forgottenAt === null && link.serverKey !== config?.serverKey);
      if (dead && link.revokedAt === null)
        await tx.sandboxTunnelLink.update({
          where: { id: input.linkId },
          data: { revokedAt: link.now },
        });
      return { dead, current: config?.serverKey ?? null };
    });
    if (admitted.dead) return result;
    // Asked with the current credential (the same server may have been
    // configured again after a remove-now), opened only now (a confirmed
    // revocation never needs it); none, or a newer one than the admission
    // saw: unconfirmed, retry.
    let server: Awaited<ReturnType<typeof readTunnelServer>>;
    try {
      server = await readTunnelServer();
    } catch (error) {
      if (error instanceof TunnelCredentialUnavailable) throw tunnelUnavailable();
      throw error;
    }
    if (!server || server.serverKey !== admitted.current) throw tunnelUnavailable();
    let revoked: boolean;
    try {
      revoked = await revokeAccessLink(server, input.linkId);
    } catch {
      // The outcome is uncertain (the deletion may have landed): a retry is safe.
      throw tunnelUnavailable();
    }
    // A 404 confirms only what the row says NOW (a remove-now since the
    // admission marked it forgotten): read in the confirming statement.
    const now = new Date();
    const confirmed = await prisma.sandboxTunnelLink.updateMany({
      where: {
        id: input.linkId,
        revokedAt: null,
        ...(revoked ? {} : { OR: [{ forgottenAt: null }, { liveUntil: { lt: now } }] }),
      },
      data: { revokedAt: now },
    });
    if (confirmed.count === 0) {
      const row = await prisma.sandboxTunnelLink.findUnique({
        where: { id: input.linkId },
        select: { revokedAt: true },
      });
      if (!row?.revokedAt) throw tunnelUnavailable();
    }
    return result;
  },
);
