import prisma, { type Prisma, type SandboxState } from "@wssp/db";
import type { TunnelStatusV11 } from "@wssp/sandbox-contracts";
import { fenceWriteKey, readDataKeyEpoch } from "../../crypto/data-key-epoch";
import { currentHostUsability } from "../sharing-access";
import { type TunnelBridge, type TunnelHostLink, tunnelBridge } from "./bridge";
import {
  readTunnelServer,
  sealCredential,
  TUNNEL_CONFIG_ID,
  type TunnelServer,
  tunnelKeys,
} from "./config";
import {
  owesSweep,
  recordTunnelEvent,
  type SandboxTunnelRow,
  sandboxTunnelSelect,
  TUNNEL_HOLD_MARGIN_MS,
  TUNNEL_HOLD_MS,
  TUNNEL_OWED,
  tunnelLabel,
} from "./rows";
import * as tun from "./tun-client";

/**
 * The preview-tunnel controller (docs/guide/tunnels.md). It runs in each
 * server process that holds host sockets and converges every tunnel row:
 *
 * - open row + sandbox RUNNING + its host registered HERE with a verified
 *   client → a tunnel exists on the tunnel server and the host runs it. The
 *   per-tunnel token is created (or rotated) right before each apply, sent
 *   only to that host, and never stored. Each apply bumps `generation`
 *   (compare-and-set), and the host ignores older frames.
 * - anything else (closed, sandbox stopped since the apply, offloaded,
 *   destroyed, host away longer than the grace, integration turning off) →
 *   every tunnel labelled for the sandbox is deleted on the tunnel server
 *   (which cuts every client and link off even if the host never hears
 *   about it), then the host is told to stop the client. Rows of deleted
 *   sandboxes are removed only after the tunnel server confirmed the
 *   deletion: the row IS the cleanup obligation. Turning off closes every
 *   other row (a tombstone keeps its generation: hosts fence on it).
 * - the sandbox's guest access through its host's pool path lapsed (the
 *   gate of commands and files) → the tunnel is taken down too.
 * - A host connected to ANOTHER server process is left alone.
 *
 * Every remote state of a row (its tunnel id, an owed label sweep, a create
 * in flight) carries the identity (`serverKey`) of the configuration it was
 * made with. A key is given to a row only while that configuration is
 * current (its row locked FOR SHARE), and a configuration goes only once no
 * row references its key (or by the admin's remove-now, which forgets them
 * all): so a non-null row key is always the current configuration's, every
 * settlement compare-and-sets it, and a pass whose snapshot is older never
 * acts on a row of a newer configuration.
 */
const TICK_MS = 5_000;
/** A connected host that stops heartbeating keeps its tunnels this long. */
const HOST_AWAY_GRACE_MS = 60_000;
/** After registration the host first reports its running clients. */
const SETTLE_MS = 5_000;
const RETRY_MS = 60_000;
const REPLACED_RETRIES = 5;
const CREATE_LEASE_MS = TUNNEL_HOLD_MS;
const CREATE_START_MARGIN_MS = TUNNEL_HOLD_MARGIN_MS;
/** An apply the connection could not take is retried after this. */
const UNSENT_RETRY_MS = 10_000;
const EVENT_RETENTION_MS = 90 * 24 * 3600 * 1000;
const PAGE = 500;

type Tun = Pick<
  typeof tun,
  | "createTunnel"
  | "rotateTunnelToken"
  | "deleteTunnel"
  | "tunnelsByLabel"
  | "tunnelsWithLabelPrefix"
>;

type Row = SandboxTunnelRow & {
  appliedAt: Date | null;
  creatingUntil: Date | null;
};
/** A create (or clean-up) hold: its exact deadline identifies it; a
 * create's bumped the generation. */
type Hold = { until: Date; generation: number };
type SandboxFacts = {
  id: string;
  userId: string;
  state: SandboxState;
  sandboxHostId: string | null;
  hostOwnerId: string | null;
  usagePoolId: string | null;
  accessGraceUntil: Date | null;
  tunnelPorts: number[];
  lastStoppedAt: Date | null;
};
type Host = {
  id: string;
  userId: string;
  lastHeartbeatAt: Date | null;
  deletionRequestedAt: Date | null;
  daemonTunnel: Prisma.JsonValue | null;
};

function capabilityOf(host: Host | null): { allowForOthers: boolean } | null {
  const value = host?.daemonTunnel;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return { allowForOthers: (value as { allowForOthers?: unknown }).allowForOthers === true };
}

export class TunnelController {
  /** What a host received (or reported) for a sandbox, per connection epoch. */
  private applied = new Map<string, { hostId: string; epoch: number; generation: number }>();
  private retryAt = new Map<string, number>();
  /** Applies that failed on the tunnel server: retried after the backoff
   * whatever the host reports meanwhile (independent of `applied`). */
  private failed = new Set<string>();
  private replaced = new Map<string, number>();
  /** Consecutive `tunnel_gone` reports per sandbox (reset when connected). */
  private gone = new Map<string, number>();
  private running: Promise<void> | null = null;
  private again = false;
  private lastPrune = 0;
  /** Keyset cursor: each pass visits the next page, wrapping around. */
  private cursor: string | null = null;
  /** Where the turn-off's listing of a configuration's tunnels continues. */
  private drainFrom: { serverKey: string; cursor: string } | null = null;

  constructor(
    private readonly deps: {
      now?: () => number;
      tun?: Tun;
      bridge?: () => TunnelBridge | null;
      server?: () => Promise<TunnelServer | null>;
    } = {},
  ) {}

  private now() {
    return this.deps.now?.() ?? Date.now();
  }
  private get tun(): Tun {
    return this.deps.tun ?? tun;
  }
  private bridge() {
    return (this.deps.bridge ?? tunnelBridge)();
  }

  /** One pass now (coalesced with a pass already running). */
  tick(): Promise<void> {
    if (this.running) {
      this.again = true;
      return this.running;
    }
    this.running = (async () => {
      try {
        do {
          this.again = false;
          await this.pass();
        } while (this.again);
      } finally {
        this.running = null;
      }
    })();
    return this.running;
  }

  start(signal: AbortSignal): () => Promise<void> {
    const timer = setInterval(() => {
      void this.tick().catch(() => console.error("[tunnels] controller pass failed"));
    }, TICK_MS);
    timer.unref?.();
    const stop = () => clearInterval(timer);
    signal.addEventListener("abort", stop, { once: true });
    return async () => {
      stop();
      await this.running?.catch(() => undefined);
    };
  }

  private async pass() {
    // Audit retention holds whether or not tunnels are configured.
    if (this.now() - this.lastPrune > 3_600_000) {
      this.lastPrune = this.now();
      await prisma.sandboxTunnelEvent
        .deleteMany({ where: { createdAt: { lt: new Date(this.now() - EVENT_RETENTION_MS) } } })
        .catch(() => undefined);
    }
    let server: TunnelServer | null;
    try {
      server = await (this.deps.server ?? readTunnelServer)();
    } catch {
      // A configured server whose credential no key opens: nothing can be
      // created or deleted until the admin fixes the key (or removes it now).
      return;
    }
    if (!server) return;
    await this.rewrap(server).catch(() => false);
    const start = this.cursor;
    const rows: Row[] = await prisma.sandboxTunnel.findMany({
      take: PAGE,
      ...(start ? { where: { sandboxId: { gt: start } } } : {}),
      orderBy: { sandboxId: "asc" },
      select: { ...sandboxTunnelSelect, appliedAt: true, creatingUntil: true },
    });
    this.cursor = rows.length === PAGE ? (rows[rows.length - 1]?.sandboxId ?? null) : null;
    // No relation (rows outlive their sandbox): read the facts by id.
    const sandboxes = new Map(
      // pagination:audited — bounded by the page's ≤PAGE sandbox ids
      (
        await prisma.sandbox.findMany({
          where: { id: { in: rows.map((row) => row.sandboxId) } },
          select: {
            id: true,
            userId: true,
            state: true,
            sandboxHostId: true,
            hostOwnerId: true,
            usagePoolId: true,
            accessGraceUntil: true,
            tunnelPorts: true,
            lastStoppedAt: true,
          },
        })
      ).map((sandbox) => [`${sandbox.id}\0${sandbox.userId}`, sandbox]),
    );
    const hostIds = [
      ...new Set(
        [...sandboxes.values()].flatMap((sandbox) =>
          sandbox.sandboxHostId ? [sandbox.sandboxHostId] : [],
        ),
      ),
    ];
    const hosts = new Map(
      // pagination:audited — bounded by the hosts of the page's ≤PAGE sandboxes
      (
        await prisma.sandboxHost.findMany({
          where: { id: { in: hostIds } },
          select: {
            id: true,
            userId: true,
            lastHeartbeatAt: true,
            deletionRequestedAt: true,
            daemonTunnel: true,
          },
        })
      ).map((host) => [host.id, host]),
    );
    for (const row of rows) {
      if (row.serverKey !== null && row.serverKey !== server.serverKey) {
        // Another configuration's row: this pass's snapshot is older than
        // it (the configuration was replaced meanwhile). The next pass starts
        // over with the current one; a row that is foreign to the current one too is an
        // anomaly, left alone.
        const current = await prisma.tunnelServerConfig.findUnique({
          where: { id: TUNNEL_CONFIG_ID },
          select: { serverKey: true },
        });
        if (current?.serverKey !== server.serverKey) {
          this.cursor = start;
          return;
        }
        console.error(`[tunnels] sandbox ${row.sandboxId} carries an unknown server key`);
        continue;
      }
      const sandbox = sandboxes.get(`${row.sandboxId}\0${row.userId}`) ?? null;
      const hostId = sandbox?.sandboxHostId ?? null;
      try {
        await this.converge(server, row, sandbox, hostId ? (hosts.get(hostId) ?? null) : null);
      } catch {
        // Never a token or URL: ids only. Retried on a later pass.
        console.error(`[tunnels] converge failed for sandbox ${row.sandboxId}`);
      }
    }
    if (server.draining) await this.finishDraining(server);
  }

  /** Turning off: once no row is left, the configuration goes too. */
  private async finishDraining(server: TunnelServer) {
    if ((await prisma.sandboxTunnel.count({ where: TUNNEL_OWED })) > 0) return;
    // Still this configuration, still turning off (a pass may be old).
    const current = await prisma.tunnelServerConfig.findUnique({
      where: { id: TUNNEL_CONFIG_ID },
      select: { serverKey: true, disabledAt: true },
    });
    if (current?.serverKey !== server.serverKey || !current.disabledAt) return;
    // The tunnel server is the durable record: delete every tunnel labelled
    // for this configuration that its credential still holds (whatever a
    // lost write left behind) before the credential is forgotten. No create
    // can start while turning off.
    // A long listing continues where the last run ended (only after its
    // deletions succeeded), so other services' tunnels never stall it.
    const from = this.drainFrom?.serverKey === server.serverKey ? this.drainFrom.cursor : null;
    const left = await this.tun.tunnelsWithLabelPrefix(
      server,
      tunnelLabel(server.serverKey, ""),
      from,
    );
    for (const id of left.ids) await this.tun.deleteTunnel(server, id);
    this.drainFrom = left.next ? { serverKey: server.serverKey, cursor: left.next } : null;
    if (left.next) return;
    await prisma.$transaction(async (tx) => {
      const [config] = await tx.$queryRaw<{ serverKey: string }[]>`
        SELECT "serverKey" FROM tunnel_server_config
        WHERE id = ${TUNNEL_CONFIG_ID} AND "disabledAt" IS NOT NULL FOR UPDATE`;
      if (config?.serverKey !== server.serverKey) return;
      if ((await tx.sandboxTunnel.count({ where: TUNNEL_OWED })) > 0) return;
      await tx.tunnelServerConfig.deleteMany({
        where: { id: TUNNEL_CONFIG_ID, serverKey: server.serverKey },
      });
      await recordTunnelEvent(tx, { kind: "config.cleared", detail: server.apiUrl });
    });
    this.reset();
  }

  /** Reseal the credential when the data-key epoch moved on; true if resealed. */
  private async rewrap(server: TunnelServer): Promise<boolean> {
    const keys = tunnelKeys();
    if (!keys) return false;
    // The database epoch picks the write key (as for every other sealed
    // column), not this process's environment order.
    const epoch = await readDataKeyEpoch();
    if ((epoch?.currentKid ?? keys.current.rootKeyId) === server.keyId) return false;
    return prisma.$transaction(async (tx) => {
      const key = await fenceWriteKey(tx, keys.all);
      if (key.rootKeyId === server.keyId) return false;
      const sealed = sealCredential(server.credential, server.apiUrl, key);
      const resealed = await tx.tunnelServerConfig.updateMany({
        // The identity too: another configuration is never overwritten.
        where: {
          id: TUNNEL_CONFIG_ID,
          serverKey: server.serverKey,
          credentialKeyId: server.keyId,
        },
        data: {
          credentialCiphertext: new Uint8Array(sealed.ciphertext),
          credentialNonce: new Uint8Array(sealed.nonce),
          credentialKeyId: sealed.keyId,
        },
      });
      return resealed.count === 1;
    });
  }

  /**
   * The turn-off's close of a row is valid only while this configuration is
   * the one turning off (a row without a key carries no identity to
   * compare-and-set): never closes a row a newer configuration serves.
   */
  private async requireDraining(tx: Prisma.TransactionClient, server: TunnelServer) {
    const [config] = await tx.$queryRaw<{ serverKey: string; disabledAt: Date | null }[]>`
      SELECT "serverKey", "disabledAt" FROM tunnel_server_config
      WHERE id = ${TUNNEL_CONFIG_ID} FOR SHARE`;
    if (config?.serverKey !== server.serverKey || !config.disabledAt)
      throw new Error("tunnel server configuration changed");
  }

  private async setRow(row: Row, data: Prisma.SandboxTunnelUpdateManyMutationInput) {
    const updated = await prisma.sandboxTunnel.updateMany({
      where: { sandboxId: row.sandboxId, userId: row.userId, generation: row.generation },
      data,
    });
    return updated.count === 1;
  }

  /** Delete every tunnel labelled for the sandbox except `keep`, each call
   * only while `hold` (when given) has time left for it. */
  private async sweepLabel(
    server: TunnelServer,
    sandboxId: string,
    keep: string | null,
    hold?: Hold,
  ) {
    for (const id of await this.tun.tunnelsByLabel(
      server,
      tunnelLabel(server.serverKey, sandboxId),
      undefined,
      () => this.requireHoldTime(hold),
    ))
      if (id !== keep) {
        this.requireHoldTime(hold);
        await this.tun.deleteTunnel(server, id);
      }
  }

  /** A remote call never starts late in its hold: it must end before the
   * hold can expire into a sweep (and so before a newer create can start). */
  private requireHoldTime(hold: Hold | undefined) {
    if (hold && this.now() > hold.until.getTime() - CREATE_START_MARGIN_MS)
      throw new Error("tunnel clean-up hold ran out");
  }

  /**
   * Take the row's hold for a clean-up before any remote call: a
   * compare-and-set on the generation and key this pass read. Every create
   * (its own hold), expose and settlement of remote state changes one of
   * them, so a pass whose read is stale (another process settled the
   * clean-up, and the owner may have exposed again since) misses it and makes
   * no call at all: its label sweep can never delete a newer tunnel. A create
   * waits for the hold, so none starts during the sweep. No bump: an in-sync
   * tunnel whose label is swept stays applied.
   */
  private async holdForCleanup(row: Row): Promise<Hold | null> {
    if (row.serverKey === null || row.creatingUntil !== null) return null;
    const until = new Date(this.now() + CREATE_LEASE_MS);
    const held = await prisma.sandboxTunnel.updateMany({
      where: {
        sandboxId: row.sandboxId,
        userId: row.userId,
        generation: row.generation,
        serverKey: row.serverKey,
        tunTunnelId: row.tunTunnelId,
        creatingUntil: null,
      },
      data: { creatingUntil: until },
    });
    return held.count === 1 ? { until, generation: row.generation } : null;
  }

  /** A clean-up that could not finish gives its hold back; the row keeps
   * every obligation it had (if this fails, the hold expires into a sweep). */
  private async releaseCleanup(row: Row, hold: Hold) {
    await prisma.sandboxTunnel
      .updateMany({
        where: { sandboxId: row.sandboxId, creatingUntil: hold.until },
        data: { creatingUntil: null },
      })
      .catch(() => {
        console.error(`[tunnels] could not release a clean-up hold for ${row.sandboxId}`);
      });
  }

  /**
   * Delete the live tunnel and every other one labelled for the sandbox
   * (tunnel server first, with the row's own configuration, under the row's
   * clean-up hold), tell the host, then record it: the row has no remote
   * state left, so its key goes. The settle compare-and-sets (generation,
   * key) and, with remote state, this pass's hold: an expose, close or late
   * obligation meanwhile (each bumps the generation), an expired hold or a
   * remove-now makes it miss, and the hold is given back with every
   * obligation kept. Throws while the tunnel server cannot confirm: the row
   * keeps its obligation. A pass that cannot take the hold (its read is
   * stale) does nothing.
   */
  private async takeDown(
    server: TunnelServer,
    row: Row,
    next: Prisma.SandboxTunnelUpdateManyMutationInput | "delete",
    drain = false,
  ) {
    let hold: Hold | null = null;
    if (row.serverKey !== null) {
      hold = await this.holdForCleanup(row);
      if (!hold) return;
      try {
        this.requireHoldTime(hold);
        if (row.tunTunnelId) await this.tun.deleteTunnel(server, row.tunTunnelId);
        await this.sweepLabel(server, row.sandboxId, null, hold);
      } catch (error) {
        await this.releaseCleanup(row, hold);
        throw error;
      }
    }
    if (row.hostId && row.generation > 0)
      this.bridge()
        ?.link(row.hostId)
        ?.send({ type: "tunnel.clear", sandboxId: row.sandboxId, generation: row.generation });
    this.applied.delete(row.sandboxId);
    const settle = async (tx: Prisma.TransactionClient) => {
      if (drain) await this.requireDraining(tx, server);
      // By this pass's hold (when it has remote state) AND the generation it
      // read: an expose, close or late obligation meanwhile bumped it, and
      // then the row is left to a pass that sees it (the hold is released).
      const where = {
        sandboxId: row.sandboxId,
        userId: row.userId,
        generation: row.generation,
        serverKey: row.serverKey,
        ...(hold ? { creatingUntil: hold.until } : {}),
      };
      const changed =
        next === "delete"
          ? await tx.sandboxTunnel.deleteMany({ where })
          : await tx.sandboxTunnel.updateMany({
              where,
              data: {
                ...next,
                tunTunnelId: null,
                hostTemplate: null,
                hostId: null,
                sweepLabel: false,
                creatingUntil: null,
                serverKey: null,
              },
            });
      if (changed.count !== 1 && hold) throw new Error("tunnel clean-up superseded");
      if (changed.count === 1 && row.tunTunnelId)
        await recordTunnelEvent(tx, {
          kind: "tunnel.deleted",
          userId: row.userId,
          sandboxId: row.sandboxId,
          detail: row.tunTunnelId,
        });
    };
    try {
      await prisma.$transaction(settle);
    } catch (error) {
      if (hold) await this.releaseCleanup(row, hold);
      throw error;
    }
  }

  private async converge(
    server: TunnelServer,
    row: Row,
    sandbox: SandboxFacts | null,
    host: Host | null,
  ) {
    if (row.creatingUntil) {
      // A create is in flight (another pass or process): its save or
      // compensation settles the row. An expired hold is an ambiguous create:
      // its label sweep is owed, and the bump fences its late save.
      if (row.creatingUntil.getTime() < this.now())
        await prisma.sandboxTunnel.updateMany({
          where: {
            sandboxId: row.sandboxId,
            creatingUntil: row.creatingUntil,
            serverKey: row.serverKey,
          },
          // credential-settlement: exempt (preview-tunnel row generation)
          data: { sweepLabel: true, creatingUntil: null, generation: { increment: 1 } },
        });
      return;
    }
    if (!sandbox || sandbox.state === "DELETED") {
      await this.takeDown(server, row, "delete");
      return;
    }
    if (server.draining) {
      // Turning off closes the row but keeps it: its generation stays the
      // floor a host fences on, so a later expose continues above it. The
      // bump fences a create hold from an older read.
      if (!row.closedAt || row.serverKey !== null)
        await this.takeDown(
          server,
          row,
          {
            closedAt: row.closedAt ?? new Date(this.now()),
            state: "SUSPENDED",
            lastError: null,
            // credential-settlement: exempt (preview-tunnel row generation)
            generation: { increment: 1 },
          },
          true,
        );
      return;
    }
    if (row.closedAt) {
      // Closed by its owner: only the cleanup is left.
      if (row.serverKey !== null) await this.takeDown(server, row, { state: "SUSPENDED" });
      return;
    }
    const now = this.now();
    // READY is the one state whose guest runs (docs/state-machine).
    const running = sandbox.state === "READY";
    const capability = capabilityOf(host);
    const shared =
      !!host &&
      !!capability &&
      !host.deletionRequestedAt &&
      (host.userId === row.userId || capability.allowForOthers) &&
      (!running || (await this.guestAccess(sandbox)));
    // Heartbeats only: a short relay drop (status DISCONNECTED) keeps the
    // tunnel for the grace like a silent connection.
    const stale = (beat: Date | null | undefined) =>
      !beat || this.now() - beat.getTime() > HOST_AWAY_GRACE_MS;
    // The pass's snapshot may be old by now (slow tunnel-server calls before
    // this row): confirm absence with a fresh heartbeat before acting on it.
    const away =
      stale(host?.lastHeartbeatAt) &&
      (!host ||
        stale(
          (
            await prisma.sandboxHost.findUnique({
              where: { id: host.id },
              select: { lastHeartbeatAt: true },
            })
          )?.lastHeartbeatAt,
        ));
    const link = host ? this.bridge()?.link(host.id) : null;
    const usable = !!link && link.capable && link.ownerId === host?.userId;
    // A stop (and a start) since the apply invalidates the tunnel even if no
    // pass saw the sandbox stopped: links never survive a restart.
    const restarted =
      !!row.tunTunnelId &&
      !!row.appliedAt &&
      !!sandbox.lastStoppedAt &&
      sandbox.lastStoppedAt.getTime() >= row.appliedAt.getTime();

    const lostCapability = (!!link && !link.capable) || (!!host && !shared);
    if (row.tunTunnelId && (!running || restarted || away || lostCapability)) {
      // A running sandbox whose host still heartbeats (to another server
      // process, or reconnecting within the grace) keeps its tunnel.
      if (running && !restarted && !away && !lostCapability) return;
      const lostHost = running && !restarted;
      await this.takeDown(server, row, {
        state: lostHost && host && !shared ? "ERROR" : "SUSPENDED",
        lastError:
          lostHost && host && capability && !shared
            ? "not_shared"
            : lostHost && host && !capability
              ? "refused"
              : null,
      });
      return;
    }
    if (running && shared && !away && usable && link && host) {
      if (now - link.reconciledAt < SETTLE_MS) return;
      if ((this.retryAt.get(row.sandboxId) ?? 0) > now) return;
      const seen = this.applied.get(row.sandboxId);
      const current =
        !!seen &&
        seen.hostId === host.id &&
        seen.epoch === link.epoch &&
        seen.generation === row.generation &&
        row.hostId === host.id;
      // In sync, or failed on this very connection (a new connection or a
      // new expose retries).
      if (
        current &&
        !this.failed.has(row.sandboxId) &&
        (row.tunTunnelId || row.state === "ERROR")
      ) {
        if (owesSweep(row)) await this.clearSweep(server, row);
        return;
      }
      await this.apply(server, row, host, link, sandbox);
      return;
    }
    // A running sandbox on a heartbeating host this process holds no usable
    // session for is driven by the process that does (or by the next one to
    // register it): its state and sweep are left to that process, which a
    // snapshot from here could only undo.
    if (running && shared && !away) return;
    if (owesSweep(row)) await this.clearSweep(server, row);
    const state = !running ? "SUSPENDED" : host && !shared ? "ERROR" : "PENDING";
    const lastError = state !== "ERROR" ? null : capability ? "not_shared" : "refused";
    if (row.state !== state || (state === "ERROR" && row.lastError !== lastError)) {
      if (row.state === "ERROR" && state === "PENDING" && row.lastError !== null) return;
      await this.setRow(row, { state, lastError });
    }
  }

  /**
   * The gate of commands and files (`requireGuestAccess`): a sandbox on
   * another owner's host, or placed through a pool, keeps its tunnel only
   * while its access path is current.
   */
  private async guestAccess(sandbox: SandboxFacts): Promise<boolean> {
    if (
      !sandbox.sandboxHostId ||
      sandbox.hostOwnerId == null ||
      (sandbox.hostOwnerId === sandbox.userId && !sandbox.usagePoolId && !sandbox.accessGraceUntil)
    )
      return true;
    return prisma.$transaction((tx) => currentHostUsability(tx, sandbox.userId, sandbox.id));
  }

  /**
   * Record a create before it starts: the row takes this configuration's key
   * (under its row FOR SHARE: the turn-off's final removal and remove-now
   * lock it FOR UPDATE), so the credential that makes a tunnel stays
   * configured until its save or compensation settled. The bump fences every
   * write from an older read of the row.
   */
  private async holdForCreate(server: TunnelServer, row: Row): Promise<Hold | null> {
    return prisma
      .$transaction(async (tx) => {
        const [config] = await tx.$queryRaw<{ disabledAt: Date | null; serverKey: string }[]>`
          SELECT "disabledAt", "serverKey" FROM tunnel_server_config
          WHERE id = ${TUNNEL_CONFIG_ID} FOR SHARE`;
        if (!config || config.disabledAt || config.serverKey !== server.serverKey) return null;
        const until = new Date(this.now() + CREATE_LEASE_MS);
        const held = await tx.sandboxTunnel.updateMany({
          where: {
            sandboxId: row.sandboxId,
            userId: row.userId,
            generation: row.generation,
            serverKey: row.serverKey,
            creatingUntil: null,
            closedAt: null,
          },
          data: {
            creatingUntil: until,
            serverKey: server.serverKey,
            // credential-settlement: exempt (preview-tunnel row generation)
            generation: { increment: 1 },
          },
        });
        // credential-settlement: exempt (preview-tunnel row generation)
        return held.count === 1 ? { until, generation: row.generation + 1 } : null;
      })
      .catch(() => null);
  }

  /**
   * The create settled: its tunnel is deleted again (`owe` false), or it may
   * exist without a record (`owe`: an ambiguous create, or a compensating
   * delete that failed) and the label sweep is owed. One write moves the hold
   * into the obligation (the row keeps the key); if it fails, the hold stays
   * and expires into a sweep. If the hold is gone already (expired, or the
   * row was retired), the obligation is recorded again only while this
   * configuration is current: a closed tombstone carries it if the row is gone.
   */
  private async releaseCreate(server: TunnelServer, row: Row, hold: Hold, owe: boolean) {
    const mine = { sandboxId: row.sandboxId, creatingUntil: hold.until };
    try {
      if (!owe) {
        await prisma.$transaction(async (tx) => {
          const released = await tx.sandboxTunnel.updateMany({
            where: mine,
            data: { creatingUntil: null },
          });
          if (released.count !== 1) return;
          // Nothing else remote (this hold swept the label): the key goes.
          await tx.sandboxTunnel.updateMany({
            where: {
              sandboxId: row.sandboxId,
              serverKey: server.serverKey,
              tunTunnelId: null,
              sweepLabel: false,
              creatingUntil: null,
            },
            data: { serverKey: null },
          });
        });
        return;
      }
      const moved = await prisma.sandboxTunnel.updateMany({
        where: mine,
        // The bump makes every compare-and-set from an older read (a
        // take-down or sweep that might clear the flag) miss.
        // credential-settlement: exempt (preview-tunnel row generation)
        data: { sweepLabel: true, creatingUntil: null, generation: { increment: 1 } },
      });
      if (moved.count === 1) return;
      await prisma.$transaction(async (tx) => {
        const [config] = await tx.$queryRaw<{ serverKey: string }[]>`
          SELECT "serverKey" FROM tunnel_server_config
          WHERE id = ${TUNNEL_CONFIG_ID} FOR SHARE`;
        if (config?.serverKey !== server.serverKey) {
          // Removed now by the admin (who forgot its tunnels): nothing can
          // be recorded against it any more.
          console.error(`[tunnels] a create for ${row.sandboxId} outlived its configuration`);
          return;
        }
        await tx.sandboxTunnel.upsert({
          where: { sandboxId: row.sandboxId },
          // The bump makes a clean-up holding the row meanwhile miss its
          // settle (it compares the generation too): the obligation stays.
          // credential-settlement: exempt (preview-tunnel row generation)
          update: { sweepLabel: true, serverKey: server.serverKey, generation: { increment: 1 } },
          create: {
            sandboxId: row.sandboxId,
            userId: row.userId,
            ports: [...row.ports],
            state: "SUSPENDED",
            // credential-settlement: exempt (preview-tunnel row generation)
            generation: hold.generation + 1,
            closedAt: new Date(this.now()),
            sweepLabel: true,
            serverKey: server.serverKey,
          },
        });
      });
    } catch {
      console.error(`[tunnels] could not settle a create hold for ${row.sandboxId}`);
    }
  }

  /** Delete every labelled tunnel but the live one (under the row's clean-up
   * hold, settled by it); without one, the key goes. */
  private async clearSweep(server: TunnelServer, row: Row) {
    const hold = await this.holdForCleanup(row);
    if (!hold) return;
    try {
      await this.sweepLabel(server, row.sandboxId, row.tunTunnelId, hold);
      const settled = await prisma.sandboxTunnel.updateMany({
        where: {
          sandboxId: row.sandboxId,
          userId: row.userId,
          generation: row.generation,
          creatingUntil: hold.until,
          serverKey: row.serverKey,
          tunTunnelId: row.tunTunnelId,
        },
        data: {
          sweepLabel: false,
          creatingUntil: null,
          ...(row.tunTunnelId ? {} : { serverKey: null }),
        },
      });
      // A missed settle (a late obligation bumped the generation) keeps the
      // row's obligations and gives the hold back.
      if (settled.count !== 1) await this.releaseCleanup(row, hold);
    } catch (error) {
      await this.releaseCleanup(row, hold);
      throw error;
    }
  }

  private async apply(
    server: TunnelServer,
    row: Row,
    host: Host,
    link: TunnelHostLink,
    sandbox: SandboxFacts,
  ) {
    let tunnelId = row.tunTunnelId;
    let hostTemplate = row.hostTemplate;
    let token: string;
    let created = false;
    let hold: Hold | null = null;
    // This attempt is the retry; a failure below owes the next one.
    this.failed.delete(row.sandboxId);
    /** The create request itself is what failed (not the sweep before it). */
    let creating = false;
    try {
      if (tunnelId) {
        try {
          token = await this.tun.rotateTunnelToken(server, tunnelId);
        } catch (error) {
          if (error instanceof tun.TunServerError && error.notFound) {
            // Deleted or expired out of band: forget it (the row keeps its
            // key, so its label is swept), recreate next pass.
            await prisma.sandboxTunnel.updateMany({
              where: {
                sandboxId: row.sandboxId,
                userId: row.userId,
                generation: row.generation,
                serverKey: row.serverKey,
                creatingUntil: null,
              },
              data: { tunTunnelId: null, hostTemplate: null, hostId: null },
            });
            return;
          }
          throw error;
        }
      } else {
        // The hold first: it proves this configuration is current and the
        // row unchanged since the pass read it, before anything remote.
        hold = await this.holdForCreate(server, row);
        if (!hold) return;
        // A create whose answer (or save) was lost left a labelled tunnel
        // nothing records: delete such leftovers first (each call only while
        // the hold has time left: a stalled sweep must never outlive it).
        await this.sweepLabel(server, row.sandboxId, null, hold);
        // A create never starts late in its hold (a stalled process): its
        // request must end before the hold can expire into a sweep.
        if (this.now() > hold.until.getTime() - CREATE_START_MARGIN_MS) {
          await this.releaseCreate(server, row, hold, false);
          return;
        }
        creating = true;
        const fresh = await this.tun.createTunnel(server, {
          label: tunnelLabel(server.serverKey, row.sandboxId),
          maxPorts: Math.max(1, sandbox.tunnelPorts.length),
        });
        tunnelId = fresh.id;
        hostTemplate = fresh.hostTemplate;
        token = fresh.token;
        created = true;
      }
    } catch (error) {
      this.retryAt.set(row.sandboxId, this.now() + RETRY_MS);
      // Retried after the backoff even if a status report for the current
      // generation lands meanwhile (that shortcut is for host failures).
      this.failed.add(row.sandboxId);
      const status = error instanceof tun.TunServerError ? error.status : 0;
      const quota = status === 429;
      // Only a definite refusal of the create proves nothing was created
      // and the label is clean; any other failure (timeout, 5xx, malformed
      // answer, or the sweep before it) owes the label sweep (and keeps the
      // configuration).
      const definite = creating && status >= 400 && status < 500;
      await this.setRow(
        { ...row, generation: hold?.generation ?? row.generation },
        { state: "ERROR", lastError: quota ? "quota" : "server_unavailable" },
      );
      if (hold) await this.releaseCreate(server, row, hold, !definite);
      return;
    }
    // The generation this apply was prepared on (a hold bumped it).
    const base = hold?.generation ?? row.generation;
    // credential-settlement: exempt (the tunnel row's own apply generation,
    // not a sandbox generation writer).
    const generation = base + 1;
    const outcome = await prisma
      .$transaction(async (tx) => {
        // Serialized with the admin's turn-off: a tunnel made under a
        // configuration that is now turning off is recorded (so the drain
        // deletes it) but never applied.
        const [config] = await tx.$queryRaw<{ disabledAt: Date | null; serverKey: string }[]>`
          SELECT "disabledAt", "serverKey" FROM tunnel_server_config
          WHERE id = ${TUNNEL_CONFIG_ID} FOR SHARE`;
        if (config?.serverKey !== server.serverKey) return "stale" as const;
        // The sandbox must still be in the run the pass observed: a stop
        // (and start) meanwhile means links must not carry over.
        const [current] = await tx.$queryRaw<
          { state: string; lastStoppedAt: Date | null; now: Date }[]
        >`SELECT state::text AS state, "lastStoppedAt", clock_timestamp() AS now
          FROM sandbox_instance WHERE id = ${row.sandboxId} AND "userId" = ${row.userId} FOR SHARE`;
        if (
          current?.state !== "READY" ||
          (current.lastStoppedAt?.getTime() ?? null) !== (sandbox.lastStoppedAt?.getTime() ?? null)
        )
          return "stale" as const;
        const updated = await tx.sandboxTunnel.updateMany({
          where: {
            sandboxId: row.sandboxId,
            userId: row.userId,
            generation: base,
            serverKey: server.serverKey,
            // A rotation never lands during another pass's clean-up hold.
            creatingUntil: hold ? hold.until : null,
          },
          data: {
            tunTunnelId: tunnelId,
            hostTemplate,
            hostId: host.id,
            generation,
            creatingUntil: null,
            state: "CONNECTING",
            lastError: null,
            // The database clock, like `lastStoppedAt` it is compared with.
            appliedAt: current.now,
          },
        });
        if (updated.count !== 1) return "stale" as const;
        if (created)
          await recordTunnelEvent(tx, {
            kind: "tunnel.created",
            userId: row.userId,
            sandboxId: row.sandboxId,
            detail: tunnelId,
          });
        return config.disabledAt == null ? ("saved" as const) : ("draining" as const);
      })
      .catch(() => "failed" as const);
    if (outcome === "stale" || outcome === "failed") {
      // Closed, re-exposed or turned off meanwhile: a tunnel we just made
      // must not leak. If it cannot be deleted now, the row's label sweep is
      // owed (the tunnel server keeps the label as the durable record).
      if (created && tunnelId) {
        const gone = await this.tun.deleteTunnel(server, tunnelId).then(
          () => true,
          () => false,
        );
        if (hold) await this.releaseCreate(server, row, hold, !gone);
      }
      return;
    }
    if (outcome === "draining") return;
    const sent = link.send({
      type: "tunnel.apply",
      sandboxId: row.sandboxId,
      generation,
      server: server.apiUrl,
      token,
      ports: [...row.ports].sort((a, b) => a - b),
    });
    if (sent) this.applied.set(row.sandboxId, { hostId: host.id, epoch: link.epoch, generation });
    else {
      // Not delivered (the connection went away): retry later, never in a
      // rotate-per-tick loop.
      this.applied.delete(row.sandboxId);
      this.retryAt.set(row.sandboxId, this.now() + UNSENT_RETRY_MS);
    }
  }

  /** `tunnel.status` from a registered host session. */
  async onStatus(hostId: string, epoch: number, status: TunnelStatusV11): Promise<void> {
    const row = await prisma.sandboxTunnel.findFirst({
      where: { sandboxId: status.sandboxId, hostId, generation: status.generation },
      select: sandboxTunnelSelect,
    });
    if (!row) return;
    if (status.state === "stopped") {
      // The host stopped this generation's client (a network teardown):
      // the next pass re-applies if the sandbox still runs.
      this.applied.delete(row.sandboxId);
      return;
    }
    this.applied.set(row.sandboxId, { hostId, epoch, generation: status.generation });
    const where = {
      sandboxId: row.sandboxId,
      userId: row.userId,
      generation: status.generation,
      hostId,
    };
    if (status.state === "connecting") {
      if (row.state !== "CONNECTING")
        await prisma.sandboxTunnel.updateMany({
          where,
          data: { state: "CONNECTING", lastError: null },
        });
      return;
    }
    if (status.state === "connected") {
      this.replaced.delete(row.sandboxId);
      this.gone.delete(row.sandboxId);
      if (row.state !== "CONNECTED")
        await prisma.sandboxTunnel.updateMany({
          where,
          data: { state: "CONNECTED", lastError: null, connectedAt: new Date(this.now()) },
        });
      return;
    }
    switch (status.error) {
      case "tunnel_gone": {
        // Deleted or expired on the tunnel server, or its token refused. The
        // next pass rotates the token: a tunnel that still exists keeps its
        // hostname, one that is gone (404/410) is forgotten and recreated.
        // A host that keeps reporting it gone backs off, then stops (error)
        // until a new connection or expose.
        const tries = (this.gone.get(row.sandboxId) ?? 0) + 1;
        this.gone.set(row.sandboxId, tries);
        if (tries > REPLACED_RETRIES) {
          await prisma.sandboxTunnel.updateMany({
            where,
            data: { state: "ERROR", lastError: "tunnel_gone" },
          });
          return;
        }
        this.applied.delete(row.sandboxId);
        await prisma.sandboxTunnel.updateMany({
          where,
          data: { state: "CONNECTING", lastError: "tunnel_gone" },
        });
        if (tries > 1) this.retryAt.set(row.sandboxId, this.now() + 2_000 * 2 ** tries);
        else this.wake();
        return;
      }
      case "replaced": {
        const tries = (this.replaced.get(row.sandboxId) ?? 0) + 1;
        this.replaced.set(row.sandboxId, tries);
        if (tries <= REPLACED_RETRIES) {
          // Another client took the tunnel (a stale host): rotate again.
          this.applied.delete(row.sandboxId);
          this.retryAt.set(row.sandboxId, this.now() + 2_000 * 2 ** tries);
          return;
        }
        await prisma.sandboxTunnel.updateMany({
          where,
          data: { state: "ERROR", lastError: "replaced" },
        });
        return;
      }
      default:
        await prisma.sandboxTunnel.updateMany({
          where,
          data: { state: "ERROR", lastError: status.error ?? "client_failed" },
        });
    }
  }

  private wake() {
    void this.tick().catch(() => undefined);
  }

  /** Forget everything this process told any host (tests, config changes). */
  reset() {
    this.applied.clear();
    this.retryAt.clear();
    this.failed.clear();
    this.replaced.clear();
    this.gone.clear();
    this.drainFrom = null;
  }
}

let controller: TunnelController | null = null;
export function tunnelController(): TunnelController {
  controller ??= new TunnelController();
  return controller;
}
