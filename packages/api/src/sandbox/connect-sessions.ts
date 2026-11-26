/**
 * The `SandboxConnectSession` audit (one row per CLI
 * connection). Metadata only: who connected (owner, key, the key's origin),
 * to which sandbox and host, when, how it ended, how many channels of each
 * kind and how many data bytes moved. Never content, commands, argv, env or
 * paths.
 *
 * Writers are the server's connect relay (`apps/server/src/sandbox-relay/
 * connect-audit.ts`, off the relay path). Readers are the owner's dashboard
 * (cookie plane): the sandbox detail "Recent connections" list and the
 * SDK keys page "last connect". The daily sweep purges rows 90 days after
 * `openedAt` in bounded batches (`connect-session-retention.ts`, which the
 * worker imports without the server environment).
 */
import { ORPCError } from "@orpc/server";
import prisma, { connectAuditPrisma, type Prisma, type SdkKeyOrigin } from "@wssp/db";
import { z } from "zod";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../lib/pagination";
import { entityId } from "../lib/schemas";
import { serviceProcedure } from "../lib/sdk-key-access";
import type { Principal } from "./contracts";
import { sandboxNotFound } from "./errors";

/**
 * A connection lives at most 12 h (`CONNECT_MAX_LIFETIME_MS`); a row still
 * open well past that lost its close to a process exit and is shown as ended
 * at an unknown time, never as live.
 */
export const CONNECT_SESSION_STALE_MS = 13 * 60 * 60 * 1000;

// -- writes (the server relay) ----------------------------------------------

export type ConnectSessionEnd = {
  /** When the relay ended the connection (not when this write ran). */
  closedAt: Date;
  closeIntent: string;
  ptyChannels: number;
  execChannels: number;
  /** `tcp` and `unix` relay channels. */
  relayChannels: number;
  /** Distinct guest tcp ports relayed (the first `CONNECT_AUDIT_FORWARDED_PORTS_MAX`). */
  forwardedPorts: readonly number[];
  bytesIn: number;
  bytesOut: number;
};

export type ConnectSessionOpen = {
  /** The server-minted client `connectionId`. */
  id: string;
  ownerId: string;
  sandboxId: string;
  hostId: string;
  keyId: string;
  /** When the connection went live (not when this write ran). */
  openedAt: Date;
  /** Set when the connection ended before its open was written: one write. */
  end?: ConnectSessionEnd;
};

export type ConnectSessionClose = ConnectSessionEnd & {
  id: string;
  ownerId: string;
};

/**
 * Every audit write is one short interactive transaction on the audit's own
 * client (`connectAuditPrisma()`, `CONNECT_AUDIT_POOL` in `@wssp/db/client`),
 * never the shared one: a pool of at most two connections whose acquisition
 * and connection startup fail after 2 s, whose session `statement_timeout`
 * (a startup setting, so it covers BEGIN too) is 2 s and whose client-side
 * query bound is 3 s. A stalled database therefore holds at most two extra
 * connections per server process and never queues audit work on the shared
 * pool that relay authorization reads need. `maxWait` sits above the driver's
 * acquisition bound so the driver, which really removes the waiter, fails
 * first; Prisma aborts the transaction after
 * `CONNECT_AUDIT_TRANSACTION_TIMEOUT_MS`.
 */
export const CONNECT_AUDIT_MAX_WAIT_MS = 3_000;
export const CONNECT_AUDIT_TRANSACTION_TIMEOUT_MS = 5_000;

function auditWrite<T>(write: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
  return connectAuditPrisma().$transaction(write, {
    maxWait: CONNECT_AUDIT_MAX_WAIT_MS,
    timeout: CONNECT_AUDIT_TRANSACTION_TIMEOUT_MS,
  });
}

const counter = (value: number) => (Number.isSafeInteger(value) && value > 0 ? value : 0);

/** At most this many distinct forwarded guest ports are kept per connection. */
export const CONNECT_AUDIT_FORWARDED_PORTS_MAX = 16;

/**
 * The audit's port list: valid tcp ports, distinct, in first-seen order, the
 * first `CONNECT_AUDIT_FORWARDED_PORTS_MAX` only.
 */
export function forwardedPortsColumn(ports: readonly number[]): number[] {
  const kept: number[] = [];
  for (const port of ports) {
    if (kept.length >= CONNECT_AUDIT_FORWARDED_PORTS_MAX) break;
    if (Number.isInteger(port) && port >= 1 && port <= 65_535 && !kept.includes(port))
      kept.push(port);
  }
  return kept;
}

const endColumns = (end: ConnectSessionEnd) => ({
  closedAt: end.closedAt,
  closeIntent: end.closeIntent.slice(0, 64),
  ptyChannels: counter(end.ptyChannels),
  execChannels: counter(end.execChannels),
  relayChannels: counter(end.relayChannels),
  forwardedPorts: forwardedPortsColumn(end.forwardedPorts),
  bytesIn: BigInt(counter(end.bytesIn)),
  bytesOut: BigInt(counter(end.bytesOut)),
});

/**
 * Record a live connection (already complete when `end` is set). The origin
 * is the key's own (read here, owner scoped): false when the key row is gone
 * (nothing is written).
 */
export function recordConnectSessionOpen(open: ConnectSessionOpen): Promise<boolean> {
  return auditWrite(async (tx) => {
    const key = await tx.sdkKey.findFirst({
      where: { id: open.keyId, userId: open.ownerId },
      select: { origin: true } satisfies Prisma.SdkKeySelect,
    });
    if (!key) return false;
    await tx.sandboxConnectSession.create({
      data: {
        id: open.id,
        userId: open.ownerId,
        sandboxId: open.sandboxId,
        hostId: open.hostId,
        keyId: open.keyId,
        origin: key.origin,
        openedAt: open.openedAt,
        ...(open.end ? endColumns(open.end) : {}),
      },
      select: { id: true } satisfies Prisma.SandboxConnectSessionSelect,
    });
    return true;
  });
}

/** Complete a connection's row once (a closed row is never rewritten). */
export function recordConnectSessionClose(close: ConnectSessionClose): Promise<boolean> {
  return auditWrite(async (tx) => {
    const updated = await tx.sandboxConnectSession.updateMany({
      where: { id: close.id, userId: close.ownerId, closedAt: null },
      data: endColumns(close),
    });
    return updated.count > 0;
  });
}

// -- reads (the owner's dashboard) ----------------------------------------------

export const listSandboxConnectSessionsInput = cursorPageInput.extend({ id: entityId }).strict();

const connectSessionSelect = {
  id: true,
  keyId: true,
  hostId: true,
  origin: true,
  openedAt: true,
  closedAt: true,
  closeIntent: true,
  ptyChannels: true,
  execChannels: true,
  relayChannels: true,
  forwardedPorts: true,
  bytesIn: true,
  bytesOut: true,
} satisfies Prisma.SandboxConnectSessionSelect;

export type SandboxConnectSessionDto = {
  id: string;
  keyId: string;
  /** The key's name, null once the key row is gone. */
  keyName: string | null;
  hostId: string;
  origin: SdkKeyOrigin;
  openedAt: Date;
  closedAt: Date | null;
  /** `open`: live; `closed`: ended at `closedAt`; `unknown`: its end was never recorded. */
  status: "open" | "closed" | "unknown";
  closeIntent: string | null;
  ptyChannels: number;
  execChannels: number;
  relayChannels: number;
  /** Distinct guest tcp ports relayed (at most 16); never Unix socket paths. */
  forwardedPorts: number[];
  /** Decimal strings (the counters are 64-bit). */
  bytesIn: string;
  bytesOut: string;
};

/** The owner's recent connections to one of their sandboxes, newest first. */
export const listSandboxConnectSessions = serviceProcedure(
  { sessionOnly: true },
  async (
    owner: Principal,
    raw: z.input<typeof listSandboxConnectSessionsInput>,
  ): Promise<{ items: SandboxConnectSessionDto[]; nextCursor: string | null }> => {
    const parsed = listSandboxConnectSessionsInput.safeParse(raw);
    if (!parsed.success)
      throw new ORPCError("BAD_REQUEST", { message: "Invalid connection list input." });
    const page = parsed.data;
    const sandbox = await prisma.sandbox.findFirst({
      where: { id: page.id, userId: owner.ownerId },
      select: { id: true } satisfies Prisma.SandboxSelect,
    });
    if (!sandbox) throw sandboxNotFound();
    const rows = await prisma.sandboxConnectSession.findMany({
      where: withCursor(
        { userId: owner.ownerId, sandboxId: sandbox.id },
        "openedAt",
        page.cursor,
        "desc",
      ),
      orderBy: [{ openedAt: "desc" }, { id: "desc" }],
      take: pageTake(page.limit),
      select: connectSessionSelect,
    });
    const result = cursorPage(rows, page.limit, "openedAt");
    const keyIds = [...new Set(result.items.map((row) => row.keyId))];
    const keys = keyIds.length
      ? await prisma.sdkKey.findMany({
          where: { userId: owner.ownerId, id: { in: keyIds } },
          take: keyIds.length,
          select: { id: true, name: true } satisfies Prisma.SdkKeySelect,
        })
      : [];
    const names = new Map(keys.map((key) => [key.id, key.name]));
    const now = Date.now();
    return {
      items: result.items.map((row) => ({
        id: row.id,
        keyId: row.keyId,
        keyName: names.get(row.keyId) ?? null,
        hostId: row.hostId,
        origin: row.origin,
        openedAt: row.openedAt,
        closedAt: row.closedAt,
        status:
          row.closedAt !== null
            ? "closed"
            : now - row.openedAt.getTime() > CONNECT_SESSION_STALE_MS
              ? "unknown"
              : "open",
        closeIntent: row.closeIntent,
        ptyChannels: row.ptyChannels,
        execChannels: row.execChannels,
        relayChannels: row.relayChannels,
        forwardedPorts: forwardedPortsColumn(row.forwardedPorts ?? []),
        bytesIn: row.bytesIn.toString(),
        bytesOut: row.bytesOut.toString(),
      })),
      nextCursor: result.nextCursor,
    };
  },
);

/**
 * The newest connection `openedAt` per key, for one page of the owner's keys
 * (at most the page size of ids, one indexed aggregate).
 */
export async function lastConnectByKey(
  ownerId: string,
  keyIds: readonly string[],
): Promise<Map<string, Date>> {
  if (keyIds.length === 0) return new Map();
  const groups = await prisma.sandboxConnectSession.groupBy({
    by: ["keyId"],
    where: { userId: ownerId, keyId: { in: [...keyIds] } },
    _max: { openedAt: true },
    orderBy: { keyId: "asc" },
    take: keyIds.length,
  });
  const last = new Map<string, Date>();
  for (const group of groups) if (group._max.openedAt) last.set(group.keyId, group._max.openedAt);
  return last;
}
