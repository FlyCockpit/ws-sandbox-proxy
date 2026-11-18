import prisma from "@wssp/db";
import {
  normalizeTunnelPorts,
  type SandboxTunnelDto,
  type TunnelLinkDto,
} from "@wssp/sandbox-contracts";
import { authorizeServiceAction, serviceProcedure } from "../../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../budgets";
import type { Principal } from "../contracts";
import {
  sandboxNotFound,
  tunnelNotFound,
  tunnelNotReady,
  tunnelPortUndeclared,
  tunnelQuota,
  tunnelRefused,
  tunnelUnavailable,
} from "../errors";
import { budgetSubjectOf, recordedKeyIdOf } from "../principal-kinds";
import { tunnelBridge, wakeTunnelController } from "./bridge";
import {
  readTunnelServer,
  TUNNEL_CONFIG_ID,
  TunnelCredentialUnavailable,
  tunnelConfigured,
} from "./config";
import {
  recordTunnelEvent,
  type SandboxTunnelRow,
  sandboxTunnelSelect,
  toSandboxTunnelDto,
  tunnelLabel,
} from "./rows";
import { deleteTunnel, mintAccessLink, TunServerError, tunnelsByLabel } from "./tun-client";

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
    const row = await prisma.sandboxTunnel.findFirst({
      where: { sandboxId: input.id, userId: owner.ownerId, closedAt: null },
      select: sandboxTunnelSelect,
    });
    if (!row) throw tunnelNotFound();
    return toSandboxTunnelDto(row);
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
              hostId: null,
              closedAt: null,
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
    return toSandboxTunnelDto(row);
  },
);

export const closeSandboxTunnel = serviceProcedure(
  { action: "sandboxes.tunnelClose", target: (input: { id: string }) => ({ sandboxId: input.id }) },
  async (owner: Principal, input: { id: string }): Promise<SandboxTunnelDto> => {
    await spend(owner);
    await requireConfigured();
    await ownedSandbox(owner, input.id);
    const row = await closeTunnelRow(owner, input.id);
    if (!row) throw tunnelNotFound();
    return toSandboxTunnelDto({
      ...row,
      tunTunnelId: null,
    });
  },
);

/**
 * Close: mark the row closed (a tombstone that keeps its generation) and try
 * to delete its tunnel and every other one labelled for the sandbox at once,
 * with the configuration its remote state was made with. The tunnel server's
 * deletion is what stops every client and link; if it cannot be reached now
 * the controller keeps retrying (the row keeps its key until then).
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
      select: sandboxTunnelSelect,
    });
    if (!row) return null;
    const updated = await tx.sandboxTunnel.update({
      where: { sandboxId, userId },
      data: {
        closedAt: new Date(),
        // The bump fails a create hold or apply prepared on the open row.
        // credential-settlement: exempt (preview-tunnel row generation)
        generation: { increment: 1 },
        state: "SUSPENDED",
        lastError: null,
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
    return { before: row, after: updated };
  });
  if (!closed) return null;
  const { before, after } = closed;
  if (before.hostId && before.generation > 0)
    tunnelBridge()
      ?.link(before.hostId)
      ?.send({ type: "tunnel.clear", sandboxId, generation: after.generation });
  try {
    const server = after.serverKey !== null ? await readTunnelServer() : null;
    // Only with the configuration the remote state belongs to (a create in
    // flight settles itself first: its hold keeps the row's key).
    if (server && server.serverKey === after.serverKey) {
      if (after.tunTunnelId) await deleteTunnel(server, after.tunTunnelId);
      for (const id of await tunnelsByLabel(server, tunnelLabel(server.serverKey, sandboxId)))
        await deleteTunnel(server, id);
      // Settled only if nothing raised a new obligation meanwhile (every
      // such write bumps the generation). Until then the row refuses a
      // re-expose.
      await prisma.sandboxTunnel.updateMany({
        where: {
          sandboxId,
          userId,
          generation: after.generation,
          serverKey: after.serverKey,
          creatingUntil: null,
        },
        data: {
          tunTunnelId: null,
          hostTemplate: null,
          hostId: null,
          sweepLabel: false,
          serverKey: null,
        },
      });
    }
  } catch {
    // The controller retries the deletion of a closed row's tunnels.
  }
  wakeTunnelController();
  return after;
}

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
    let link: Awaited<ReturnType<typeof mintAccessLink>>;
    try {
      link = await mintAccessLink(server, row.tunTunnelId, {
        port: input.port,
        ttlSeconds: input.ttlSeconds ?? 60,
        singleUse,
        sessionTtlSeconds: input.sessionTtlSeconds ?? 3600,
      });
    } catch (error) {
      if (error instanceof TunServerError && error.notFound) {
        wakeTunnelController();
        throw tunnelNotReady();
      }
      throw tunnelUnavailable();
    }
    await recordTunnelEvent(prisma, {
      kind: "link.minted",
      userId: owner.ownerId,
      sandboxId: input.id,
      actorId: owner.ownerId,
      actorKeyId: recordedKeyIdOf(owner),
      port: input.port,
      detail: link.id,
    });
    return {
      url: link.url,
      port: input.port,
      expiresAt: link.expiresAt.toISOString(),
      singleUse,
    };
  },
);
