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

export function toSandboxTunnelDto(row: SandboxTunnelRow): SandboxTunnelDto {
  const lastError = (TUNNEL_ERRORS as readonly string[]).includes(row.lastError ?? "")
    ? (row.lastError as SandboxTunnelDto["lastError"])
    : null;
  return {
    sandboxId: row.sandboxId,
    ports: [...row.ports],
    state: row.state.toLowerCase() as SandboxTunnelDto["state"],
    lastError: row.state === "ERROR" ? lastError : null,
    urls: row.tunTunnelId ? previewUrls(row.hostTemplate, row.ports) : [],
    connectedAt: row.connectedAt?.toISOString() ?? null,
    updatedAt: row.updatedAt.toISOString(),
  };
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
