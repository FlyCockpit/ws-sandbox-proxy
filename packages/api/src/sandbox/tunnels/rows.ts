import type { Prisma } from "@wssp/db";
import { type SandboxTunnelDto, TUNNEL_ERRORS } from "@wssp/sandbox-contracts";
import { previewUrls } from "./tun-client";

export const sandboxTunnelSelect = {
  sandboxId: true,
  userId: true,
  ports: true,
  state: true,
  lastError: true,
  tunTunnelId: true,
  hostTemplate: true,
  hostId: true,
  generation: true,
  connectedAt: true,
  closedAt: true,
  sweepLabel: true,
  serverKey: true,
  cleanupForgottenAt: true,
  updatedAt: true,
} satisfies Prisma.SandboxTunnelSelect;
export type SandboxTunnelRow = Prisma.SandboxTunnelGetPayload<{
  select: typeof sandboxTunnelSelect;
}>;

/** A tunnel-server create or clean-up in flight holds its row
 * (`creatingUntil`) this long at most (its calls time out after 10 s each);
 * an expired hold becomes a label sweep. */
export const TUNNEL_HOLD_MS = 120_000;
/** A create, or a clean-up's next call, starts only this long before its
 * hold ends (≥ the request timeout). */
export const TUNNEL_HOLD_MARGIN_MS = 30_000;

/** Rows that may have a tunnel on the tunnel server (a recorded one, a
 * label sweep owed, or a create in flight): exactly those with a server key. */
const TUNNEL_REMOTE_OWED = {
  serverKey: { not: null },
} satisfies Prisma.SandboxTunnelWhereInput;

/** Rows that still owe the tunnel server something, or want a tunnel. */
export const TUNNEL_OWED = {
  OR: [{ closedAt: null }, TUNNEL_REMOTE_OWED],
} satisfies Prisma.SandboxTunnelWhereInput;

/** A row whose remote state may include labelled tunnels other than its
 * recorded one: a lost or ambiguous create, or a key left without a tunnel. */
export function owesSweep(row: {
  serverKey: string | null;
  tunTunnelId: string | null;
  sweepLabel: boolean;
}): boolean {
  return row.serverKey !== null && (row.sweepLabel || row.tunTunnelId === null);
}

/** The tunnel server label of a sandbox's tunnels made with one
 * configuration (the durable record). The configuration's key in it scopes
 * every sweep to that configuration's own tunnels, even on the same server
 * and credential configured again. `tunnelLabel(key, "")` is its prefix. */
export function tunnelLabel(serverKey: string, sandboxId: string) {
  return `wssp:${serverKey}:${sandboxId}`;
}

/**
 * A closed row's clean-up is done once nothing of it can serve a visitor:
 * the tunnel server confirmed every tunnel of it deleted (no remote state,
 * none forgotten by a remove-now) and no host may still run its client (no
 * host recorded, no `sandbox_tunnel_client_stop` obligation left).
 */
function tunnelCleanupDone(
  row: Pick<SandboxTunnelRow, "serverKey" | "hostId" | "cleanupForgottenAt">,
  clientStopsLeft: number,
): boolean {
  return (
    row.serverKey === null &&
    row.hostId === null &&
    row.cleanupForgottenAt === null &&
    clientStopsLeft === 0
  );
}

/** `clientStopsLeft`: the row's `sandbox_tunnel_client_stop` count (only
 * read for a closed row; pass 0 for an open one). */
export function toSandboxTunnelDto(
  row: SandboxTunnelRow,
  clientStopsLeft: number,
): SandboxTunnelDto {
  const closed = row.closedAt !== null;
  const lastError = (TUNNEL_ERRORS as readonly string[]).includes(row.lastError ?? "")
    ? (row.lastError as SandboxTunnelDto["lastError"])
    : null;
  return {
    sandboxId: row.sandboxId,
    ports: [...row.ports],
    state: closed ? "closed" : (row.state.toLowerCase() as SandboxTunnelDto["state"]),
    lastError: !closed && row.state === "ERROR" ? lastError : null,
    urls: !closed && row.tunTunnelId ? previewUrls(row.hostTemplate, row.ports) : [],
    connectedAt: closed ? null : (row.connectedAt?.toISOString() ?? null),
    cleanup: closed ? (tunnelCleanupDone(row, clientStopsLeft) ? "done" : "pending") : null,
    updatedAt: row.updatedAt.toISOString(),
  };
}

/**
 * The DTO of a sandbox's tunnel row as stored now, or null. ONE statement
 * (one snapshot) reads the row and its client-stop obligations together: a
 * row read and a separate count could pair a stale "closed, confirmed
 * deleted" row with obligations settled after a later re-expose and close,
 * and report `done` for a tunnel that still exists.
 */
export async function readSandboxTunnelDto(
  client: Pick<Prisma.TransactionClient, "$queryRaw">,
  sandboxId: string,
  userId: string,
): Promise<SandboxTunnelDto | null> {
  const [row] = await client.$queryRaw<(SandboxTunnelRow & { clientStops: number })[]>`
    SELECT t."sandboxId", t."userId", t.ports, t.state::text AS state, t."lastError",
           t."tunTunnelId", t."hostTemplate", t."hostId", t.generation, t."connectedAt",
           t."closedAt", t."sweepLabel", t."serverKey", t."cleanupForgottenAt", t."updatedAt",
           (SELECT count(*)::int FROM sandbox_tunnel_client_stop s
             WHERE s."sandboxId" = t."sandboxId") AS "clientStops"
    FROM sandbox_tunnel t
    WHERE t."sandboxId" = ${sandboxId} AND t."userId" = ${userId}`;
  if (!row) return null;
  return toSandboxTunnelDto(row, row.closedAt === null ? 0 : row.clientStops);
}

export async function recordTunnelEvent(
  client: Pick<Prisma.TransactionClient, "sandboxTunnelEvent">,
  event: {
    kind: string;
    userId?: string | null;
    sandboxId?: string | null;
    actorId?: string | null;
    actorKeyId?: string | null;
    port?: number | null;
    detail?: string | null;
  },
) {
  await client.sandboxTunnelEvent.create({
    data: {
      kind: event.kind,
      userId: event.userId ?? null,
      sandboxId: event.sandboxId ?? null,
      actorId: event.actorId ?? null,
      actorKeyId: event.actorKeyId ?? null,
      port: event.port ?? null,
      detail: event.detail ?? null,
    },
  });
}
