import { beforeEach, describe, expect, it, vi } from "vitest";

type Row = {
  sandboxId: string;
  userId: string;
  ports: number[];
  state: string;
  lastError: string | null;
  tunTunnelId: string | null;
  hostTemplate: string | null;
  hostId: string | null;
  generation: number;
  connectedAt: Date | null;
  closedAt: Date | null;
  appliedAt: Date | null;
  sweepLabel: boolean;
  creatingUntil: Date | null;
  serverKey: string | null;
  cleanupForgottenAt?: Date | null;
  updatedAt: Date;
};
type Stop = { sandboxId: string; hostId: string; generation: number };

const db = vi.hoisted(() => ({
  rows: new Map<string, Row>(),
  /** `sandbox_tunnel_client_stop`, written as its trigger does (`write`). */
  stops: new Map<string, Stop>(),
  /** The host row is deleted. */
  hostGone: false,
  sandbox: {
    state: "READY",
    sandboxHostId: "host-1",
    tunnelPorts: [3000, 5173],
    tunnelPortsRevision: 0,
    tunnelPortsAckHostId: null,
    tunnelPortsAckRevision: 0,
    lastStoppedAt: null,
  } as {
    state: string;
    sandboxHostId: string | null;
    tunnelPorts: number[];
    tunnelPortsRevision: number;
    tunnelPortsAckHostId: string | null;
    tunnelPortsAckRevision: number;
    lastStoppedAt: Date | null;
  } | null,
  /** Rows an acknowledgement updates. */
  ackCount: 1,
  /** The port-sync scan's answer (sandboxes whose host owes an ack). */
  portsDue: [] as {
    id: string;
    sandboxHostId: string;
    tunnelPorts: number[];
    tunnelPortsRevision: number;
  }[],
  config: { disabledAt: null as Date | null, serverKey: "key-1" },
  clock: 1_000_000,
  host: {
    id: "host-1",
    userId: "owner",
    status: "CONNECTED",
    lastHeartbeatAt: new Date(),
    daemonTunnel: { clientSha256: "a".repeat(64), maxTunnels: 4, allowForOthers: false },
  } as Record<string, unknown>,
  events: [] as string[],
  /** The pass's (possibly old) snapshot of the host's heartbeat, if set. */
  snapshotBeat: null as Date | null,
  usable: true,
  hostOwnerId: "owner" as string | null,
  usagePoolId: null as string | null,
}));

vi.mock("../sharing-access", () => ({
  currentHostUsability: vi.fn(async () => db.usable),
}));

/** Prisma-style update data, `{ increment }` included; records a host the
 * row stops naming as the `wssp_tunnel_client_stop` trigger does. */
function write(row: Row, data: Record<string, unknown>) {
  const host = row.hostId;
  for (const [key, value] of Object.entries(data)) {
    const increment = (value as { increment?: number } | null)?.increment;
    (row as Record<string, unknown>)[key] =
      typeof increment === "number" ? (row[key as keyof Row] as number) + increment : value;
  }
  row.updatedAt = new Date();
  checkRow(row);
  if (host !== null && row.hostId !== host) {
    const key = `${row.sandboxId}\0${host}`;
    const generation = Math.max(db.stops.get(key)?.generation ?? 0, row.generation);
    db.stops.set(key, { sandboxId: row.sandboxId, hostId: host, generation });
  }
}

function generationMatches(value: number, filter: { lte?: number; lt?: number }) {
  return (
    (filter.lte === undefined || value <= filter.lte) &&
    (filter.lt === undefined || value < filter.lt)
  );
}

/** The `sandbox_tunnel_server_key` CHECK: remote state always carries its key. */
function checkRow(row: Row) {
  if (row.serverKey === null && (row.tunTunnelId || row.sweepLabel || row.creatingUntil))
    throw new Error("violates sandbox_tunnel_server_key");
}

function matches(row: Row, where: Record<string, unknown>) {
  return Object.entries(where).every(([key, value]) => row[key as keyof Row] === value);
}

vi.mock("@wssp/db", () => {
  const client = {
    sandboxTunnel: {
      findMany: vi.fn(async () => [...db.rows.values()].map((row) => ({ ...row }))),
      count: vi.fn(async (args?: { where?: { OR?: unknown[] } }) =>
        args?.where?.OR
          ? [...db.rows.values()].filter((row) => row.closedAt === null || row.serverKey !== null)
              .length
          : db.rows.size,
      ),
      upsert: vi.fn(
        async ({
          where,
          update,
          create,
        }: {
          where: { sandboxId: string };
          update: Partial<Row>;
          create: Row;
        }) => {
          const row = db.rows.get(where.sandboxId);
          if (row) write(row, update);
          else {
            const created: Row = {
              lastError: null,
              tunTunnelId: null,
              hostTemplate: null,
              hostId: null,
              connectedAt: null,
              appliedAt: null,
              creatingUntil: null,
              serverKey: null,
              updatedAt: new Date(),
              ...create,
            };
            checkRow(created);
            db.rows.set(where.sandboxId, created);
          }
          return {};
        },
      ),
      findFirst: vi.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const row = [...db.rows.values()].find((candidate) => matches(candidate, where));
        return row ? { ...row } : null;
      }),
      updateMany: vi.fn(
        async ({ where, data }: { where: Record<string, unknown>; data: Partial<Row> }) => {
          const row = [...db.rows.values()].find((candidate) => matches(candidate, where));
          if (!row) return { count: 0 };
          write(row, data);
          return { count: 1 };
        },
      ),
      deleteMany: vi.fn(async ({ where }: { where: Record<string, unknown> }) => {
        const row = [...db.rows.values()].find((candidate) => matches(candidate, where));
        if (!row) return { count: 0 };
        db.rows.delete(row.sandboxId);
        // The trigger's DELETE branch.
        for (const [key, stop] of db.stops)
          if (stop.sandboxId === row.sandboxId) db.stops.delete(key);
        return { count: 1 };
      }),
    },
    sandboxTunnelClientStop: {
      findMany: vi.fn(
        async ({
          where,
          take,
        }: {
          where: {
            sandboxId?: string;
            OR?: [{ sandboxId: { gt: string } }, { sandboxId: string; hostId: { gt: string } }];
          };
          take: number;
        }) =>
          [...db.stops.values()]
            .filter((stop) =>
              where.sandboxId !== undefined
                ? stop.sandboxId === where.sandboxId
                : where.OR
                  ? stop.sandboxId > where.OR[0].sandboxId.gt ||
                    (stop.sandboxId === where.OR[1].sandboxId &&
                      stop.hostId > where.OR[1].hostId.gt)
                  : true,
            )
            .sort((a, b) =>
              a.sandboxId === b.sandboxId
                ? a.hostId.localeCompare(b.hostId)
                : a.sandboxId.localeCompare(b.sandboxId),
            )
            .slice(0, take)
            .map((stop) => ({ ...stop })),
      ),
      deleteMany: vi.fn(
        async ({
          where,
        }: {
          where: { sandboxId: string; hostId: string; generation: { lte?: number; lt?: number } };
        }) => {
          const key = `${where.sandboxId}\0${where.hostId}`;
          const stop = db.stops.get(key);
          if (!stop || !generationMatches(stop.generation, where.generation)) return { count: 0 };
          db.stops.delete(key);
          return { count: 1 };
        },
      ),
    },
    sandboxHost: {
      findMany: vi.fn(async ({ select }: { select: Record<string, unknown> }) =>
        // The client-stop scan asks only for ids: a deleted host has no row.
        Object.keys(select).length === 1 && db.hostGone
          ? []
          : [db.snapshotBeat ? { ...db.host, lastHeartbeatAt: db.snapshotBeat } : db.host],
      ),
      findUnique: vi.fn(async () => db.host),
    },
    sandbox: {
      findMany: vi.fn(async () =>
        db.sandbox
          ? [
              {
                id: "sbx",
                userId: "owner",
                hostOwnerId: db.hostOwnerId,
                usagePoolId: db.usagePoolId,
                accessGraceUntil: null,
                ...db.sandbox,
              },
            ]
          : [],
      ),
    },
    tunnelServerConfig: {
      deleteMany: vi.fn(async () => ({ count: 1 })),
      findUnique: vi.fn(async () => ({ ...db.config })),
    },
    $queryRaw: vi.fn(async (query: TemplateStringsArray) =>
      query.join("?").includes("tunnelPortsAckHostId")
        ? db.portsDue
        : query.join("?").includes("sandbox_instance")
          ? db.sandbox
            ? [
                {
                  state: db.sandbox.state,
                  lastStoppedAt: db.sandbox.lastStoppedAt,
                  now: new Date(db.clock),
                },
              ]
            : []
          : [{ ...db.config, apiUrl: "https://tunnel.example.com" }],
    ),
    $executeRaw: vi.fn(async () => db.ackCount),
    sandboxTunnelEvent: {
      create: vi.fn(async ({ data }: { data: { kind: string } }) => {
        db.events.push(data.kind);
        return {};
      }),
      deleteMany: vi.fn(async () => ({ count: 0 })),
    },
    $transaction: vi.fn(async (fn: (tx: unknown) => unknown) => fn(client)),
  };
  return { default: client };
});

import { TunnelController } from "./controller";

const server = {
  apiUrl: "https://tunnel.example.com",
  credential: `tnsvc_${"s".repeat(43)}`,
  maxTunnelsPerOwner: 10,
  keyId: "k",
  draining: false,
  serverKey: "key-1",
};

function setup() {
  let now = 1_000_000;
  const sent: { type: string; generation: number; token?: string; ports?: number[] }[] = [];
  let epoch = 7;
  let linked = true;
  let capable = true;
  const tun = {
    createTunnel: vi.fn(async () => ({
      id: "tun1",
      token: `tntun_${"a".repeat(43)}`,
      hostTemplate: "{port}-tun1.tunnel.example.com",
    })),
    rotateTunnelToken: vi.fn(async () => `tntun_${"b".repeat(43)}`),
    deleteTunnel: vi.fn(async () => undefined),
    // Calls the caller's per-page deadline check, as the real listing does.
    tunnelsByLabel: vi.fn(
      async (_server: unknown, _label: string, _fetch?: unknown, beforePage?: () => void) => {
        beforePage?.();
        return [] as string[];
      },
    ),
    tunnelsWithLabelPrefix: vi.fn(async () => ({
      ids: [] as string[],
      next: null as string | null,
    })),
  };
  const controller = new TunnelController({
    now: () => now,
    tun,
    server: async () => server,
    bridge: () => ({
      link: (hostId: string) =>
        linked
          ? {
              hostId,
              ownerId: "owner",
              epoch,
              reconciledAt: now - 60_000,
              capable,
              plan: true,
              send: (frame) => {
                sent.push(frame as (typeof sent)[number]);
                return true;
              },
            }
          : null,
    }),
  });
  return {
    controller,
    tun,
    sent,
    advance: (ms: number) => {
      now += ms;
    },
    reconnect: () => {
      epoch += 1;
    },
    unlink: () => {
      linked = false;
    },
    relink: (withClient = true) => {
      linked = true;
      capable = withClient;
      epoch += 1;
    },
  };
}

beforeEach(() => {
  db.rows.clear();
  db.stops.clear();
  db.hostGone = false;
  db.events.length = 0;
  db.sandbox = {
    state: "READY",
    sandboxHostId: "host-1",
    tunnelPorts: [3000, 5173],
    tunnelPortsRevision: 0,
    tunnelPortsAckHostId: null,
    tunnelPortsAckRevision: 0,
    lastStoppedAt: null,
  };
  db.portsDue = [];
  db.ackCount = 1;
  db.host.status = "CONNECTED";
  db.host.lastHeartbeatAt = new Date(1_000_000);
  db.rows.set("sbx", {
    sandboxId: "sbx",
    userId: "owner",
    ports: [3000],
    state: "PENDING",
    lastError: null,
    tunTunnelId: null,
    hostTemplate: null,
    hostId: null,
    generation: 0,
    connectedAt: null,
    closedAt: null,
    appliedAt: null,
    sweepLabel: false,
    creatingUntil: null,
    serverKey: null,
    updatedAt: new Date(),
  });
  db.config.disabledAt = null;
  db.config.serverKey = "key-1";
  db.snapshotBeat = null;
  db.usable = true;
  db.hostOwnerId = "owner";
  db.usagePoolId = null;
  db.host.userId = "owner";
  db.host.daemonTunnel = { clientSha256: "a".repeat(64), maxTunnels: 4, allowForOthers: false };
});

describe("tunnel controller", () => {
  it("creates a tunnel for a running sandbox and applies it once", async () => {
    const t = setup();
    await t.controller.tick();
    expect(t.tun.createTunnel).toHaveBeenCalledWith(server, {
      label: "wssp:key-1:sbx",
      maxPorts: 8,
    });
    expect(t.sent).toEqual([
      expect.objectContaining({ type: "tunnel.apply", generation: 2, ports: [3000] }),
    ]);
    // The create's hold took generation 1, its apply 2; the row keeps the key.
    expect(db.rows.get("sbx")).toMatchObject({
      tunTunnelId: "tun1",
      hostId: "host-1",
      generation: 2,
      state: "CONNECTING",
      serverKey: "key-1",
      creatingUntil: null,
    });
    expect(db.events).toEqual(["tunnel.created"]);
    await t.controller.tick();
    expect(t.sent).toHaveLength(1);
    await t.controller.onStatus("host-1", 7, {
      type: "tunnel.status",
      sandboxId: "sbx",
      generation: 2,
      state: "connected",
      tunnelId: "tun1",
    });
    expect(db.rows.get("sbx")?.state).toBe("CONNECTED");
    // A stale generation changes nothing.
    await t.controller.onStatus("host-1", 7, {
      type: "tunnel.status",
      sandboxId: "sbx",
      generation: 9,
      state: "error",
      error: "client_failed",
    });
    expect(db.rows.get("sbx")?.state).toBe("CONNECTED");
  });

  it("rotates the token and re-applies after the host reconnects", async () => {
    const t = setup();
    await t.controller.tick();
    t.reconnect();
    await t.controller.tick();
    expect(t.tun.rotateTunnelToken).toHaveBeenCalledWith(server, "tun1");
    expect(t.tun.createTunnel).toHaveBeenCalledTimes(1);
    expect(t.sent.map((frame) => frame.generation)).toEqual([2, 3]);
    expect(db.rows.get("sbx")?.tunTunnelId).toBe("tun1");
  });

  it("deletes the tunnel when the sandbox stops and recreates it when it runs", async () => {
    const t = setup();
    await t.controller.tick();
    db.sandbox = {
      state: "STOPPED",
      sandboxHostId: "host-1",
      tunnelPorts: [3000, 5173],
      tunnelPortsRevision: 0,
      tunnelPortsAckHostId: null,
      tunnelPortsAckRevision: 0,
      lastStoppedAt: new Date(2_000_000),
    };
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "tun1");
    expect(t.sent.at(-1)).toMatchObject({ type: "tunnel.clear", generation: 2 });
    expect(db.rows.get("sbx")).toMatchObject({
      tunTunnelId: null,
      state: "SUSPENDED",
      serverKey: null,
    });
    db.sandbox = {
      state: "READY",
      sandboxHostId: "host-1",
      tunnelPorts: [3000, 5173],
      tunnelPortsRevision: 0,
      tunnelPortsAckHostId: null,
      tunnelPortsAckRevision: 0,
      lastStoppedAt: null,
    };
    await t.controller.tick();
    expect(t.tun.createTunnel).toHaveBeenCalledTimes(2);
    expect(db.rows.get("sbx")).toMatchObject({ generation: 4, state: "CONNECTING" });
  });

  it("keeps the tunnel through a short host outage and deletes it after the grace", async () => {
    const t = setup();
    await t.controller.tick();
    t.unlink();
    // The relay dropped (status DISCONNECTED): only heartbeats count.
    db.host.status = "DISCONNECTED";
    t.advance(30_000);
    await t.controller.tick();
    expect(t.tun.deleteTunnel).not.toHaveBeenCalled();
    t.advance(60_000);
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "tun1");
    expect(db.rows.get("sbx")?.tunTunnelId).toBeNull();
  });

  it("removes the row and the tunnel of a destroyed sandbox", async () => {
    const t = setup();
    await t.controller.tick();
    db.sandbox = {
      state: "DELETED",
      sandboxHostId: "host-1",
      tunnelPorts: [3000, 5173],
      tunnelPortsRevision: 0,
      tunnelPortsAckHostId: null,
      tunnelPortsAckRevision: 0,
      lastStoppedAt: null,
    };
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "tun1");
    expect(db.rows.has("sbx")).toBe(false);
    expect(db.events).toEqual(["tunnel.created", "tunnel.deleted"]);
  });

  it("rotates a tunnel the host reports gone, and recreates it only if it is really gone", async () => {
    const t = setup();
    await t.controller.tick();
    const gone = {
      type: "tunnel.status" as const,
      sandboxId: "sbx",
      state: "error" as const,
      error: "tunnel_gone" as const,
    };
    // Token refused but the tunnel still exists: rotate, keep the hostname.
    await t.controller.onStatus("host-1", 7, { ...gone, generation: 2 });
    await t.controller.tick();
    expect(t.tun.rotateTunnelToken).toHaveBeenCalledTimes(1);
    expect(t.tun.createTunnel).toHaveBeenCalledTimes(1);
    expect(db.rows.get("sbx")).toMatchObject({ generation: 3, tunTunnelId: "tun1" });
    // Deleted out of band: the rotation answers 404, the id is forgotten
    // (the key stays), the next pass sweeps labelled leftovers and creates a
    // new tunnel.
    const { TunServerError } = await import("./tun-client");
    t.tun.rotateTunnelToken.mockRejectedValueOnce(new TunServerError(404, "not_found"));
    t.tun.tunnelsByLabel.mockResolvedValueOnce(["orphan1"]);
    await t.controller.onStatus("host-1", 7, { ...gone, generation: 3 });
    // A repeated report backs off before the next rotation.
    await t.controller.tick();
    expect(t.tun.rotateTunnelToken).toHaveBeenCalledTimes(1);
    t.advance(10_000);
    await t.controller.tick();
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "orphan1");
    expect(t.tun.createTunnel).toHaveBeenCalledTimes(2);
  });

  it("stops rotating a tunnel the host keeps reporting gone", async () => {
    const t = setup();
    await t.controller.tick();
    let clock = 1_000_000;
    const later = () => {
      clock += 200_000;
      t.advance(200_000);
      db.host.lastHeartbeatAt = new Date(clock);
    };
    for (let i = 0; i < 6; i += 1) {
      const generation = db.rows.get("sbx")?.generation ?? 0;
      await t.controller.onStatus("host-1", 7, {
        type: "tunnel.status",
        sandboxId: "sbx",
        generation,
        state: "error",
        error: "tunnel_gone",
      });
      later();
      await t.controller.tick();
    }
    expect(db.rows.get("sbx")).toMatchObject({ state: "ERROR", lastError: "tunnel_gone" });
    const rotations = t.tun.rotateTunnelToken.mock.calls.length;
    later();
    await t.controller.tick();
    expect(t.tun.rotateTunnelToken).toHaveBeenCalledTimes(rotations);
  });

  it("deletes a closed row's tunnel and keeps retrying until the tunnel server confirms", async () => {
    const t = setup();
    await t.controller.tick();
    const row = db.rows.get("sbx");
    if (!row) throw new Error("row");
    row.closedAt = new Date();
    row.generation += 1;
    t.tun.deleteTunnel.mockRejectedValueOnce(new Error("unreachable"));
    await t.controller.tick();
    expect(db.rows.get("sbx")?.tunTunnelId).toBe("tun1");
    await t.controller.tick();
    expect(db.rows.get("sbx")).toMatchObject({ tunTunnelId: null, state: "SUSPENDED" });
    expect(t.sent.at(-1)).toMatchObject({ type: "tunnel.clear", generation: 3 });
    expect(db.rows.get("sbx")?.serverKey).toBeNull();
    // A closed row never gets a tunnel again.
    await t.controller.tick();
    expect(t.tun.createTunnel).toHaveBeenCalledTimes(1);
  });

  it("an expose that changes the ports during an apply wins (generation compare-and-set)", async () => {
    const t = setup();
    t.tun.createTunnel.mockImplementationOnce(async () => {
      const row = db.rows.get("sbx");
      if (row) {
        row.ports = [5173];
        row.generation += 1;
        row.hostId = null;
      }
      return {
        id: "tunX",
        token: `tntun_${"c".repeat(43)}`,
        hostTemplate: "{port}-tunX.t.example.com",
      };
    });
    await t.controller.tick();
    // The stale apply was dropped and its tunnel deleted; nothing was sent.
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "tunX");
    expect(t.sent).toEqual([]);
    await t.controller.tick();
    expect(t.sent).toEqual([expect.objectContaining({ type: "tunnel.apply", ports: [5173] })]);
  });

  it("never applies on a host that does not allow other owners", async () => {
    const t = setup();
    db.host.userId = "someone-else";
    await t.controller.tick();
    expect(t.tun.createTunnel).not.toHaveBeenCalled();
    expect(db.rows.get("sbx")).toMatchObject({ state: "ERROR", lastError: "not_shared" });
    db.host.userId = "owner";
  });
});

describe("tunnel controller invalidation", () => {
  it("a stop and start no pass saw still replaces the tunnel", async () => {
    const t = setup();
    await t.controller.tick();
    // Stopped and started again between two passes.
    t.advance(1_000);
    db.sandbox = {
      state: "READY",
      sandboxHostId: "host-1",
      tunnelPorts: [3000, 5173],
      tunnelPortsRevision: 0,
      tunnelPortsAckHostId: null,
      tunnelPortsAckRevision: 0,
      lastStoppedAt: new Date(1_000_500),
    };
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "tun1");
    await t.controller.tick();
    expect(t.tun.createTunnel).toHaveBeenCalledTimes(2);
  });

  it("turning off deletes every tunnel, closes the rows and then removes the configuration", async () => {
    const t = setup();
    await t.controller.tick();
    db.config.disabledAt = new Date();
    const draining = new TunnelController({
      now: () => 1_000_000,
      tun: t.tun,
      server: async () => ({ ...server, draining: true }),
      bridge: () => null,
    });
    await draining.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(
      expect.objectContaining({ draining: true }),
      "tun1",
    );
    // The final remote sweep lists this configuration's labels.
    expect(t.tun.tunnelsWithLabelPrefix).toHaveBeenCalledWith(
      expect.objectContaining({ draining: true }),
      "wssp:key-1:",
      null,
    );
    // The row stays (closed) with its generation: the host's floor.
    expect(db.rows.get("sbx")).toMatchObject({
      tunTunnelId: null,
      state: "SUSPENDED",
      generation: 3,
      serverKey: null,
    });
    expect(db.rows.get("sbx")?.closedAt).not.toBeNull();
    const prisma = (await import("@wssp/db")).default as unknown as {
      tunnelServerConfig: { deleteMany: ReturnType<typeof vi.fn> };
    };
    expect(prisma.tunnelServerConfig.deleteMany).toHaveBeenCalled();
    // Configured again, a re-expose continues above the generation a host saw.
    db.config.disabledAt = null;
    const row = db.rows.get("sbx");
    if (!row) throw new Error("row");
    Object.assign(row, { closedAt: null, generation: row.generation + 1, state: "PENDING" });
    const again = setup();
    await again.controller.tick();
    // The turn-off ran with no host session: its client stop is delivered
    // (at the turned-off generation) as soon as one exists, before the apply.
    expect(again.sent).toEqual([
      expect.objectContaining({ type: "tunnel.clear", generation: 3 }),
      expect.objectContaining({ type: "tunnel.apply", generation: 6 }),
    ]);
  });

  it("a create that outlives its row's retirement leaves a sweep obligation", async () => {
    const t = setup();
    t.tun.createTunnel.mockImplementationOnce(async () => {
      // Meanwhile the sandbox was destroyed and another process retired
      // the row after sweeping a label this create was not visible under.
      if (db.sandbox) db.sandbox.state = "DELETED";
      db.rows.delete("sbx");
      return {
        id: "tunLate",
        token: `tntun_${"d".repeat(43)}`,
        hostTemplate: "{port}-tunLate.t.example.com",
      };
    });
    t.tun.deleteTunnel.mockRejectedValueOnce(new Error("unreachable"));
    await t.controller.tick();
    expect(t.sent).toEqual([]);
    expect(db.rows.get("sbx")).toMatchObject({ sweepLabel: true });
    expect(db.rows.get("sbx")?.closedAt).not.toBeNull();
    // The next pass sweeps the label (finding the late tunnel) and retires it.
    t.tun.tunnelsByLabel.mockResolvedValueOnce(["tunLate"]);
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenLastCalledWith(server, "tunLate");
    expect(db.rows.has("sbx")).toBe(false);
  });

  it("confirms a host's absence with a fresh heartbeat before deleting", async () => {
    const t = setup();
    await t.controller.tick();
    // The pass's snapshot is old, the host kept heartbeating meanwhile.
    t.advance(90_000);
    db.snapshotBeat = new Date(1_000_000);
    db.host.lastHeartbeatAt = new Date(1_000_000 + 85_000);
    await t.controller.tick();
    expect(t.tun.deleteTunnel).not.toHaveBeenCalled();
    expect(db.rows.get("sbx")?.tunTunnelId).toBe("tun1");
  });

  it("a hold taken while a pass retires the row keeps the row", async () => {
    const t = setup();
    // The row owes a label sweep (a key without a tunnel).
    db.rows.get("sbx")!.serverKey = "key-1";
    db.sandbox = null;
    t.tun.tunnelsByLabel.mockImplementationOnce(async () => {
      // Another pass took its create hold (it read the sandbox as READY).
      const row = db.rows.get("sbx");
      if (row)
        Object.assign(row, {
          creatingUntil: new Date(1_000_000 + 60_000),
          serverKey: "key-1",
          generation: row.generation + 1,
        });
      return [];
    });
    await t.controller.tick();
    expect(db.rows.has("sbx")).toBe(true);
  });

  it("an ambiguous create whose obligation cannot be written keeps its hold", async () => {
    const t = setup();
    const { TunServerError } = await import("./tun-client");
    t.tun.createTunnel.mockRejectedValueOnce(new TunServerError(0, "timeout"));
    const prisma = (await import("@wssp/db")).default as unknown as {
      sandboxTunnel: { updateMany: ReturnType<typeof vi.fn> };
    };
    // The hold, the error state, then the write that would move the hold
    // into the sweep obligation fails.
    const real = prisma.sandboxTunnel.updateMany.getMockImplementation();
    let calls = 0;
    prisma.sandboxTunnel.updateMany.mockImplementation(async (args: unknown) => {
      calls += 1;
      if (calls === 3) throw new Error("db down");
      return real?.(args);
    });
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await t.controller.tick();
    error.mockRestore();
    prisma.sandboxTunnel.updateMany.mockImplementation(real as never);
    expect(db.rows.get("sbx")?.creatingUntil).not.toBeNull();
    expect(db.rows.get("sbx")?.sweepLabel).toBe(false);
  });

  it("a creator never releases another creator's hold", async () => {
    const t = setup();
    const other = new Date(1_000_000 + 99_000);
    t.tun.createTunnel.mockImplementationOnce(async () => {
      // This hold expired into a sweep and a newer create took its own.
      const row = db.rows.get("sbx");
      if (row) Object.assign(row, { creatingUntil: other, generation: row.generation + 1 });
      return {
        id: "tunOld",
        token: `tntun_${"e".repeat(43)}`,
        hostTemplate: "{port}-tunOld.t.example.com",
      };
    });
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "tunOld");
    expect(db.rows.get("sbx")?.creatingUntil).toBe(other);
  });

  it("a pass with an older configuration never settles a cleanup", async () => {
    const t = setup();
    await t.controller.tick();
    db.sandbox = null;
    const stale = new TunnelController({
      now: () => 1_000_000,
      tun: t.tun,
      server: async () => ({ ...server, serverKey: "key-0" }),
      bridge: () => null,
    });
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await stale.tick();
    error.mockRestore();
    expect(db.rows.get("sbx")?.tunTunnelId).toBe("tun1");
  });

  it("a process without the host's session leaves a live tunnel's state alone", async () => {
    const t = setup();
    await t.controller.tick();
    await t.controller.onStatus("host-1", 7, {
      type: "tunnel.status",
      sandboxId: "sbx",
      generation: 2,
      state: "connected",
      tunnelId: "tun1",
    });
    const elsewhere = new TunnelController({
      now: () => 1_000_000,
      tun: t.tun,
      server: async () => server,
      bridge: () => ({ link: () => null }),
    });
    db.rows.get("sbx")!.sweepLabel = true;
    await elsewhere.tick();
    expect(db.rows.get("sbx")).toMatchObject({ state: "CONNECTED", tunTunnelId: "tun1" });
    expect(t.tun.tunnelsByLabel).toHaveBeenCalledTimes(1); // the create's own sweep only
  });

  it("a create holds its row: retirement waits, and an expired hold becomes a sweep", async () => {
    const t = setup();
    const row = db.rows.get("sbx")!;
    Object.assign(row, { creatingUntil: new Date(1_000_000 + 60_000), serverKey: "key-1" });
    db.sandbox = null;
    await t.controller.tick();
    expect(db.rows.has("sbx")).toBe(true);
    expect(t.tun.createTunnel).not.toHaveBeenCalled();
    t.advance(120_000);
    await t.controller.tick();
    expect(db.rows.get("sbx")).toMatchObject({
      sweepLabel: true,
      creatingUntil: null,
      generation: 1,
    });
    t.tun.tunnelsByLabel.mockResolvedValueOnce(["late"]);
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "late");
    expect(db.rows.has("sbx")).toBe(false);
  });

  it("a pass never acts on a row of a newer configuration", async () => {
    const t = setup();
    await t.controller.tick();
    // The configuration was turned off and another one configured since
    // this pass read its snapshot; the row now belongs to the new one.
    db.config.serverKey = "key-2";
    db.rows.get("sbx")!.serverKey = "key-2";
    db.sandbox = null;
    await t.controller.tick();
    expect(t.tun.deleteTunnel).not.toHaveBeenCalled();
    expect(t.tun.tunnelsByLabel).toHaveBeenCalledTimes(1); // the create's own sweep only
    expect(db.rows.get("sbx")).toMatchObject({ tunTunnelId: "tun1", serverKey: "key-2" });
  });

  it("a rotation 404 forgets the tunnel but keeps the key until the label is swept", async () => {
    const t = setup();
    await t.controller.tick();
    t.reconnect();
    const { TunServerError } = await import("./tun-client");
    t.tun.rotateTunnelToken.mockRejectedValueOnce(new TunServerError(404, "not_found"));
    await t.controller.tick();
    expect(db.rows.get("sbx")).toMatchObject({ tunTunnelId: null, serverKey: "key-1" });
    // The sandbox stopped meanwhile: the owed sweep runs, then the key goes.
    db.sandbox = { ...db.sandbox!, state: "STOPPED", lastStoppedAt: new Date(2_000_000) };
    t.tun.tunnelsByLabel.mockResolvedValueOnce(["stray"]);
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "stray");
    expect(db.rows.get("sbx")).toMatchObject({ tunTunnelId: null, serverKey: null });
  });

  it("a turn-off pass from an old snapshot never closes a newer configuration's row", async () => {
    setup();
    // Snapshot: key-0 turning off. Current: key-1, on; the row is open and
    // has nothing remote yet (no key to compare-and-set).
    const stale = new TunnelController({
      now: () => 1_000_000,
      tun: setup().tun,
      server: async () => ({ ...server, serverKey: "key-0", draining: true }),
      bridge: () => null,
    });
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await stale.tick();
    error.mockRestore();
    expect(db.rows.get("sbx")?.closedAt).toBeNull();
  });

  it("a transient rotation failure is retried even if the host reports the generation meanwhile", async () => {
    const t = setup();
    await t.controller.tick();
    t.reconnect();
    const { TunServerError } = await import("./tun-client");
    t.tun.rotateTunnelToken.mockImplementationOnce(async () => {
      // A delayed `connected` for the current generation lands meanwhile.
      await t.controller.onStatus("host-1", 8, {
        type: "tunnel.status",
        sandboxId: "sbx",
        generation: 2,
        state: "connected",
        tunnelId: "tun1",
      });
      throw new TunServerError(503, "unavailable");
    });
    const prisma = (await import("@wssp/db")).default as unknown as {
      sandboxTunnel: { updateMany: ReturnType<typeof vi.fn> };
    };
    const real = prisma.sandboxTunnel.updateMany.getMockImplementation();
    prisma.sandboxTunnel.updateMany.mockImplementation(async (args: unknown) => {
      const data = (args as { data?: { lastError?: string } }).data;
      // ... and once more just before the failure is recorded (it reads the
      // row still CONNECTED, so it only refills the applied cache).
      if (data?.lastError === "server_unavailable")
        await t.controller.onStatus("host-1", 8, {
          type: "tunnel.status",
          sandboxId: "sbx",
          generation: 2,
          state: "connected",
          tunnelId: "tun1",
        });
      return real?.(args);
    });
    await t.controller.tick();
    prisma.sandboxTunnel.updateMany.mockImplementation(real as never);
    expect(db.rows.get("sbx")).toMatchObject({ state: "ERROR", lastError: "server_unavailable" });
    t.advance(61_000);
    db.host.lastHeartbeatAt = new Date(1_000_000 + 61_000);
    await t.controller.tick();
    expect(t.tun.rotateTunnelToken).toHaveBeenCalledTimes(2);
    expect(db.rows.get("sbx")).toMatchObject({ state: "CONNECTING", generation: 3 });
  });

  it("never creates a tunnel for a host without a fresh heartbeat", async () => {
    const t = setup();
    // The socket is registered here, but the host stopped heartbeating.
    t.advance(90_000);
    await t.controller.tick();
    expect(t.tun.createTunnel).not.toHaveBeenCalled();
    expect(db.rows.get("sbx")).toMatchObject({ state: "PENDING", serverKey: null });
  });

  it("the turn-off's listing continues where the last run ended", async () => {
    const t = setup();
    db.config.disabledAt = new Date();
    db.rows.clear();
    t.tun.tunnelsWithLabelPrefix
      .mockResolvedValueOnce({ ids: ["w1"], next: "c20" })
      .mockResolvedValueOnce({ ids: [], next: null });
    const draining = new TunnelController({
      now: () => 1_000_000,
      tun: t.tun,
      server: async () => ({ ...server, draining: true }),
      bridge: () => null,
    });
    const prisma = (await import("@wssp/db")).default as unknown as {
      tunnelServerConfig: { deleteMany: ReturnType<typeof vi.fn> };
    };
    prisma.tunnelServerConfig.deleteMany.mockClear();
    await draining.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(expect.anything(), "w1");
    expect(prisma.tunnelServerConfig.deleteMany).not.toHaveBeenCalled();
    await draining.tick();
    expect(t.tun.tunnelsWithLabelPrefix).toHaveBeenLastCalledWith(
      expect.anything(),
      "wssp:key-1:",
      "c20",
    );
    expect(prisma.tunnelServerConfig.deleteMany).toHaveBeenCalled();
  });

  it("never creates under a configuration that changed since the pass read it", async () => {
    const t = setup();
    const stale = new TunnelController({
      now: () => 1_000_000,
      tun: t.tun,
      server: async () => ({ ...server, serverKey: "key-0" }),
      bridge: () => ({
        link: (hostId: string) => ({
          hostId,
          ownerId: "owner",
          epoch: 7,
          reconciledAt: 0,
          capable: true,
          send: () => true,
        }),
      }),
    });
    await stale.tick();
    expect(t.tun.createTunnel).not.toHaveBeenCalled();
    // Nor sweeps the label: a newer configuration's tunnel may carry it.
    expect(t.tun.tunnelsByLabel).not.toHaveBeenCalled();
    expect(db.rows.get("sbx")?.creatingUntil).toBeNull();
  });

  it("takes the tunnel down when guest access through the host's pool path lapses", async () => {
    const t = setup();
    db.host.userId = "contributor";
    db.host.daemonTunnel = { clientSha256: "a".repeat(64), maxTunnels: 4, allowForOthers: true };
    db.hostOwnerId = "contributor";
    db.usagePoolId = "pool-1";
    const local = new TunnelController({
      now: () => 1_000_000,
      tun: t.tun,
      server: async () => server,
      bridge: () => ({
        link: (hostId: string) => ({
          hostId,
          ownerId: "contributor",
          epoch: 7,
          reconciledAt: 0,
          capable: true,
          send: (frame) => {
            t.sent.push(frame as (typeof t.sent)[number]);
            return true;
          },
        }),
      }),
    });
    await local.tick();
    expect(t.sent).toEqual([expect.objectContaining({ type: "tunnel.apply" })]);
    db.usable = false;
    await local.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "tun1");
    expect(t.sent.at(-1)).toMatchObject({ type: "tunnel.clear" });
    expect(db.rows.get("sbx")).toMatchObject({
      tunTunnelId: null,
      state: "ERROR",
      lastError: "not_shared",
    });
    await local.tick();
    expect(t.tun.createTunnel).toHaveBeenCalledTimes(1);
  });
});

describe("tunnel controller clean-up holds", () => {
  const prismaMock = async () =>
    (await import("@wssp/db")).default as unknown as {
      sandboxTunnel: { findMany: ReturnType<typeof vi.fn> };
    };

  it("a pass with an old snapshot of a closed row never sweeps a re-exposed tunnel", async () => {
    const t = setup();
    await t.controller.tick();
    // The owner closed the row (tun1 still recorded): this is the stale
    // pass's snapshot.
    const row = db.rows.get("sbx");
    if (!row) throw new Error("row");
    Object.assign(row, { closedAt: new Date(), generation: row.generation + 1 });
    const snapshot = { ...row };
    // Meanwhile another process finished that cleanup, the owner exposed the
    // port again and a create made tun2 (same configuration, same label).
    Object.assign(row, {
      closedAt: null,
      tunTunnelId: "tun2",
      hostTemplate: "{port}-tun2.tunnel.example.com",
      generation: row.generation + 3,
      state: "CONNECTED",
    });
    (await prismaMock()).sandboxTunnel.findMany.mockResolvedValueOnce([snapshot]);
    t.tun.tunnelsByLabel.mockClear();
    t.tun.tunnelsByLabel.mockResolvedValue(["tun2"]);
    t.tun.deleteTunnel.mockClear();
    await t.controller.tick();
    // No call at all: its hold's compare-and-set missed.
    expect(t.tun.deleteTunnel).not.toHaveBeenCalled();
    expect(t.tun.tunnelsByLabel).not.toHaveBeenCalled();
    expect(db.rows.get("sbx")).toMatchObject({
      tunTunnelId: "tun2",
      closedAt: null,
      creatingUntil: null,
      serverKey: "key-1",
    });
    t.tun.tunnelsByLabel.mockResolvedValue([]);
  });

  it("a pass with an old snapshot owing a sweep never sweeps a newer tunnel", async () => {
    const t = setup();
    // The snapshot: a key without a tunnel (a label sweep owed).
    const row = db.rows.get("sbx");
    if (!row) throw new Error("row");
    Object.assign(row, { serverKey: "key-1", state: "SUSPENDED" });
    db.sandbox = { ...db.sandbox!, state: "STOPPED" };
    const snapshot = { ...row };
    // Another process swept, a create recorded tun2 since.
    Object.assign(row, { tunTunnelId: "tun2", generation: row.generation + 2 });
    (await prismaMock()).sandboxTunnel.findMany.mockResolvedValueOnce([snapshot]);
    t.tun.tunnelsByLabel.mockResolvedValue(["tun2"]);
    await t.controller.tick();
    expect(t.tun.tunnelsByLabel).not.toHaveBeenCalled();
    expect(t.tun.deleteTunnel).not.toHaveBeenCalled();
    expect(db.rows.get("sbx")).toMatchObject({ tunTunnelId: "tun2", creatingUntil: null });
    t.tun.tunnelsByLabel.mockResolvedValue([]);
  });

  it("a take-down holds its row: no create starts and no rotation lands during the sweep", async () => {
    const t = setup();
    await t.controller.tick();
    db.sandbox = { ...db.sandbox!, state: "STOPPED" };
    let during: Row | undefined;
    t.tun.tunnelsByLabel.mockImplementationOnce(async () => {
      during = { ...db.rows.get("sbx")! };
      return [];
    });
    await t.controller.tick();
    // The sweep ran under the hold, without a generation bump.
    expect(during?.creatingUntil).not.toBeNull();
    expect(during?.generation).toBe(2);
    expect(db.rows.get("sbx")).toMatchObject({
      tunTunnelId: null,
      serverKey: null,
      creatingUntil: null,
      state: "SUSPENDED",
    });
  });

  it("a held row refuses another pass's create and rotation", async () => {
    const t = setup();
    await t.controller.tick();
    const row = db.rows.get("sbx");
    if (!row) throw new Error("row");
    // Another process holds the row for a clean-up; this pass rotates.
    t.reconnect();
    row.creatingUntil = new Date(1_000_000 + 60_000);
    const before = t.sent.length;
    (await prismaMock()).sandboxTunnel.findMany.mockResolvedValueOnce([
      { ...row, creatingUntil: null },
    ]);
    await t.controller.tick();
    expect(t.tun.rotateTunnelToken).toHaveBeenCalledTimes(1);
    // Its save missed (the hold): nothing applied, the hold untouched.
    expect(t.sent).toHaveLength(before);
    expect(db.rows.get("sbx")?.creatingUntil).toEqual(new Date(1_000_000 + 60_000));
  });

  it("a clean-up the tunnel server refuses gives its hold back and keeps the obligation", async () => {
    const t = setup();
    await t.controller.tick();
    db.sandbox = null;
    t.tun.deleteTunnel.mockRejectedValueOnce(new Error("unreachable"));
    await t.controller.tick();
    expect(db.rows.get("sbx")).toMatchObject({
      tunTunnelId: "tun1",
      serverKey: "key-1",
      creatingUntil: null,
    });
    await t.controller.tick();
    expect(db.rows.has("sbx")).toBe(false);
  });

  it("a clean-up never starts a call late in its hold", async () => {
    const t = setup();
    await t.controller.tick();
    db.sandbox = { ...db.sandbox!, state: "STOPPED" };
    t.tun.deleteTunnel.mockImplementationOnce(async () => {
      // The first delete stalled until the hold is nearly over.
      t.advance(100_000);
    });
    t.tun.tunnelsByLabel.mockClear();
    await t.controller.tick();
    // The listing refused to start its request (the hold's deadline).
    await expect(t.tun.tunnelsByLabel.mock.results[0]?.value).rejects.toThrow("hold ran out");
    // The hold was given back; the row keeps its obligation for the next pass.
    expect(db.rows.get("sbx")).toMatchObject({ serverKey: "key-1", creatingUntil: null });
  });

  it("a create's leftover sweep never runs late in its hold", async () => {
    const t = setup();
    t.tun.tunnelsByLabel.mockResolvedValueOnce(["old1", "old2"]);
    t.tun.deleteTunnel.mockImplementationOnce(async () => {
      // The first delete stalled until the hold is nearly over.
      t.advance(100_000);
    });
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledTimes(1);
    expect(t.tun.createTunnel).not.toHaveBeenCalled();
    // The hold became the label sweep it owes.
    expect(db.rows.get("sbx")).toMatchObject({
      creatingUntil: null,
      sweepLabel: true,
      serverKey: "key-1",
    });
  });

  it("a sweep from a snapshot whose tunnel was forgotten since takes no hold", async () => {
    const t = setup();
    await t.controller.tick();
    const row = db.rows.get("sbx");
    if (!row) throw new Error("row");
    row.sweepLabel = true;
    const snapshot = { ...row };
    // A rotation 404 forgot tun1 meanwhile (no generation bump).
    Object.assign(row, { tunTunnelId: null, hostTemplate: null, hostId: null });
    (await prismaMock()).sandboxTunnel.findMany.mockResolvedValueOnce([snapshot]);
    t.tun.tunnelsByLabel.mockClear();
    await t.controller.tick();
    expect(t.tun.tunnelsByLabel).not.toHaveBeenCalled();
    expect(db.rows.get("sbx")?.creatingUntil).toBeNull();
  });

  it("an expose during a take-down keeps its state; the next pass settles", async () => {
    const t = setup();
    await t.controller.tick();
    db.sandbox = { ...db.sandbox!, state: "STOPPED" };
    t.tun.tunnelsByLabel.mockImplementationOnce(async () => {
      // The owner exposes other ports meanwhile (bumps the generation).
      const row = db.rows.get("sbx");
      if (row)
        Object.assign(row, { ports: [5173], state: "PENDING", generation: row.generation + 1 });
      return [];
    });
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await t.controller.tick();
    error.mockRestore();
    // The settle missed: the hold is given back, every obligation kept.
    expect(db.rows.get("sbx")).toMatchObject({
      tunTunnelId: "tun1",
      serverKey: "key-1",
      creatingUntil: null,
      state: "PENDING",
      ports: [5173],
    });
    await t.controller.tick();
    expect(db.rows.get("sbx")).toMatchObject({
      tunTunnelId: null,
      serverKey: null,
      creatingUntil: null,
      ports: [5173],
    });
  });

  it("a late create's sweep obligation recorded during a clean-up hold survives it", async () => {
    const t = setup();
    await t.controller.tick();
    db.sandbox = { ...db.sandbox!, state: "STOPPED" };
    let hold: Date | null = null;
    t.tun.tunnelsByLabel.mockImplementationOnce(async () => {
      // A create that outlived its hold records its sweep obligation (the
      // fallback upsert: flag + bump, the foreign hold left in place).
      const row = db.rows.get("sbx");
      if (row) {
        hold = row.creatingUntil;
        Object.assign(row, { sweepLabel: true, generation: row.generation + 1 });
      }
      return [];
    });
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await t.controller.tick();
    error.mockRestore();
    expect(hold).not.toBeNull();
    expect(db.rows.get("sbx")).toMatchObject({
      sweepLabel: true,
      serverKey: "key-1",
      creatingUntil: null,
    });
  });
});

describe("tunnel controller: runtime port changes", () => {
  it("sends tunnel.ports to the sandbox's host until it acknowledges, throttled", async () => {
    const t = setup();
    db.rows.clear();
    db.portsDue = [
      { id: "sbx", sandboxHostId: "host-1", tunnelPorts: [5173, 3000], tunnelPortsRevision: 2 },
    ];
    await t.controller.tick();
    expect(t.sent).toContainEqual({
      type: "tunnel.ports",
      sandboxId: "sbx",
      revision: 2,
      ports: [3000, 5173],
    });
    const count = () => t.sent.filter((frame) => frame.type === "tunnel.ports").length;
    expect(count()).toBe(1);
    // Not again within the resend interval; again after it.
    t.advance(5_000);
    await t.controller.tick();
    expect(count()).toBe(1);
    t.advance(6_000);
    await t.controller.tick();
    expect(count()).toBe(2);
    // A host without a plan backs the resend off.
    await t.controller.onPortsStatus("host-1", 7, {
      type: "tunnel.portsStatus",
      sandboxId: "sbx",
      revision: 2,
      outcome: "absent",
    });
    t.advance(11_000);
    await t.controller.tick();
    expect(count()).toBe(2);
    // A new revision goes at once.
    db.portsDue[0]!.tunnelPortsRevision = 3;
    await t.controller.tick();
    expect(count()).toBe(3);
  });

  it("rotates through more due sandboxes than one page and reaches every one", async () => {
    const t = setup();
    db.rows.clear();
    const prisma = (await import("@wssp/db")).default as unknown as {
      $queryRaw: ReturnType<typeof vi.fn>;
    };
    const all = Array.from({ length: 501 }, (_, i) => ({
      id: `sbx-${String(i).padStart(4, "0")}`,
      sandboxHostId: "host-1",
      tunnelPorts: [3000],
      tunnelPortsRevision: 1,
    }));
    // The scan honours its keyset cursor and page size, as the SQL does.
    const original = prisma.$queryRaw.getMockImplementation();
    prisma.$queryRaw.mockImplementation(
      async (query: TemplateStringsArray, ...values: unknown[]) => {
        if (!query.join("?").includes("tunnelPortsAckHostId")) return original?.(query, ...values);
        const from = values[0] as string;
        return all.filter((sandbox) => sandbox.id > from).slice(0, 500);
      },
    );
    try {
      const sentTo = () =>
        t.sent
          .filter((frame) => frame.type === "tunnel.ports")
          .map((frame) => (frame as unknown as { sandboxId: string }).sandboxId);
      await t.controller.tick();
      expect(sentTo()).toHaveLength(500);
      expect(sentTo()).not.toContain("sbx-0500");
      // The next pass continues after the first page: the 501st is reached.
      await t.controller.tick();
      expect(sentTo()).toContain("sbx-0500");
      expect(sentTo()).toHaveLength(501);
      // Wrapping around within the resend interval sends nothing again ...
      await t.controller.tick();
      expect(sentTo()).toHaveLength(501);
      // ... and after it, both pages again.
      t.advance(11_000);
      await t.controller.tick();
      await t.controller.tick();
      expect(sentTo()).toHaveLength(1002);
    } finally {
      prisma.$queryRaw.mockImplementation(original as never);
    }
  });

  it("waits while the tunnel row is held (the replaced tunnel goes first)", async () => {
    const t = setup();
    const row = db.rows.get("sbx")!;
    row.serverKey = "key-1";
    row.creatingUntil = new Date(1_000_000 + 60_000);
    db.portsDue = [
      { id: "sbx", sandboxHostId: "host-1", tunnelPorts: [3000], tunnelPortsRevision: 1 },
    ];
    const prisma = (await import("@wssp/db")).default as unknown as {
      sandboxTunnel: { findMany: ReturnType<typeof vi.fn> };
    };
    prisma.sandboxTunnel.findMany.mockImplementationOnce(async () => [{ sandboxId: "sbx" }]);
    await t.controller.tick();
    expect(t.sent.some((frame) => frame.type === "tunnel.ports")).toBe(false);
  });

  it("an owed sweep of a replaced tunnel never waits for the acknowledgement", async () => {
    const t = setup();
    // A removal forgot tun1 and owes the sweep; its own clean-up was lost.
    const row = db.rows.get("sbx")!;
    Object.assign(row, { serverKey: "key-1", sweepLabel: true, generation: 5 });
    db.sandbox!.tunnelPortsRevision = 2;
    t.tun.tunnelsByLabel.mockResolvedValueOnce(["tun1"]);
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "tun1");
    expect(t.tun.createTunnel).not.toHaveBeenCalled();
    expect(db.rows.get("sbx")).toMatchObject({ sweepLabel: false, serverKey: null });
  });

  it("applies a tunnel only once the current host acknowledged the current ports", async () => {
    const t = setup();
    db.sandbox!.tunnelPortsRevision = 2;
    db.sandbox!.tunnelPortsAckHostId = "host-1";
    db.sandbox!.tunnelPortsAckRevision = 1;
    await t.controller.tick();
    expect(t.tun.createTunnel).not.toHaveBeenCalled();
    // An acknowledgement from another (earlier) host does not count either.
    db.sandbox!.tunnelPortsAckHostId = "host-0";
    db.sandbox!.tunnelPortsAckRevision = 2;
    await t.controller.tick();
    expect(t.tun.createTunnel).not.toHaveBeenCalled();
    db.sandbox!.tunnelPortsAckHostId = "host-1";
    await t.controller.tick();
    expect(t.tun.createTunnel).toHaveBeenCalledTimes(1);
  });

  it("records an applied acknowledgement only for the sandbox's current host", async () => {
    const t = setup();
    const prisma = (await import("@wssp/db")).default as unknown as {
      $executeRaw: ReturnType<typeof vi.fn>;
    };
    prisma.$executeRaw.mockClear();
    await t.controller.onPortsStatus("host-1", 7, {
      type: "tunnel.portsStatus",
      sandboxId: "sbx",
      revision: 4,
      outcome: "applied",
    });
    expect(prisma.$executeRaw).toHaveBeenCalledTimes(1);
    const [query, ...values] = prisma.$executeRaw.mock.calls[0] as [
      TemplateStringsArray,
      ...unknown[],
    ];
    const text = query.join("?");
    expect(text).toContain('"sandboxHostId" = ?');
    expect(text).toContain('<= "tunnelPortsRevision"');
    expect(values).toContain("host-1");
    expect(values).toContain(4);
    // Refusals never acknowledge.
    for (const outcome of ["absent", "refused", "failed"] as const)
      await t.controller.onPortsStatus("host-1", 7, {
        type: "tunnel.portsStatus",
        sandboxId: "sbx",
        revision: 5,
        outcome,
      });
    expect(prisma.$executeRaw).toHaveBeenCalledTimes(1);
  });
});

describe("client-stop obligations", () => {
  const stopped = (generation: number) =>
    ({ type: "tunnel.status", sandboxId: "sbx", generation, state: "stopped" }) as const;
  const stopSandbox = () => {
    db.sandbox = {
      state: "STOPPED",
      sandboxHostId: "host-1",
      tunnelPorts: [3000, 5173],
      tunnelPortsRevision: 0,
      tunnelPortsAckHostId: null,
      tunnelPortsAckRevision: 0,
      lastStoppedAt: new Date(2_000_000),
    };
  };
  const clears = (t: ReturnType<typeof setup>) =>
    t.sent.filter((frame) => frame.type === "tunnel.clear").map((frame) => frame.generation);

  it("a take-down records the host's obligation and re-sends its clear until the host confirms", async () => {
    const t = setup();
    await t.controller.tick();
    stopSandbox();
    await t.controller.tick();
    expect([...db.stops.values()]).toEqual([{ sandboxId: "sbx", hostId: "host-1", generation: 2 }]);
    expect(clears(t)).toEqual([2]);
    // Throttled within one connection, then sent again.
    t.advance(5_000);
    await t.controller.tick();
    expect(clears(t)).toEqual([2]);
    t.advance(10_000);
    await t.controller.tick();
    expect(clears(t)).toEqual([2, 2]);
    // A new connection gets it at once.
    t.reconnect();
    await t.controller.tick();
    expect(clears(t)).toEqual([2, 2, 2]);
    await t.controller.onStatus("host-1", 8, stopped(2));
    expect(db.stops.size).toBe(0);
    t.advance(60_000);
    await t.controller.tick();
    expect(clears(t)).toEqual([2, 2, 2]);
  });

  it("a host that missed the stop gets it when it is back, and only its stopped report settles it", async () => {
    const t = setup();
    await t.controller.tick();
    // The host is away past the grace: the tunnel is deleted without it.
    t.unlink();
    t.advance(120_000);
    await t.controller.tick();
    expect(t.tun.deleteTunnel).toHaveBeenCalledWith(server, "tun1");
    expect(db.rows.get("sbx")).toMatchObject({ hostId: null, serverKey: null });
    expect(clears(t)).toEqual([]);
    expect(db.stops.get("sbx\0host-1")?.generation).toBe(2);
    // Back: it re-reports its still running generation-2 client first. That
    // report proves nothing about the client's stop.
    t.relink();
    await t.controller.onStatus("host-1", 8, {
      type: "tunnel.status",
      sandboxId: "sbx",
      generation: 2,
      state: "connected",
      tunnelId: "tun1",
    });
    expect(db.stops.has("sbx\0host-1")).toBe(true);
    await t.controller.tick();
    expect(clears(t)).toEqual([2]);
    // A stopped report below the obligation does not settle it either.
    await t.controller.onStatus("host-1", 8, stopped(1));
    expect(db.stops.has("sbx\0host-1")).toBe(true);
    await t.controller.onStatus("host-1", 8, stopped(2));
    expect(db.stops.has("sbx\0host-1")).toBe(false);
  });

  it("a report above the obligation's generation settles it (the client was replaced)", async () => {
    const t = setup();
    await t.controller.tick();
    db.stops.set("sbx\0host-1", { sandboxId: "sbx", hostId: "host-1", generation: 2 });
    await t.controller.onStatus("host-1", 7, {
      type: "tunnel.status",
      sandboxId: "sbx",
      generation: 2,
      state: "error",
      error: "client_failed",
    });
    expect(db.stops.has("sbx\0host-1")).toBe(true);
    await t.controller.onStatus("host-1", 7, {
      type: "tunnel.status",
      sandboxId: "sbx",
      generation: 3,
      state: "connecting",
    });
    expect(db.stops.has("sbx\0host-1")).toBe(false);
  });

  it("only the obligation's own host settles it", async () => {
    const t = setup();
    db.stops.set("sbx\0host-1", { sandboxId: "sbx", hostId: "host-1", generation: 4 });
    await t.controller.onStatus("host-2", 7, stopped(9));
    expect(db.stops.has("sbx\0host-1")).toBe(true);
  });

  it("a session without a tunnel client manager proves no client runs; a deleted host can never confirm", async () => {
    const t = setup();
    db.rows.clear();
    db.stops.set("sbx\0host-1", { sandboxId: "sbx", hostId: "host-1", generation: 4 });
    t.relink(false);
    await t.controller.tick();
    expect(db.stops.size).toBe(0);
    expect(clears(t)).toEqual([]);
    db.stops.set("sbx\0host-1", { sandboxId: "sbx", hostId: "host-1", generation: 4 });
    t.unlink();
    await t.controller.tick();
    expect(db.stops.size).toBe(1);
    db.hostGone = true;
    await t.controller.tick();
    expect(db.stops.size).toBe(0);
  });

  it("delivers obligations without any tunnel configuration (after a remove-now)", async () => {
    const t = setup();
    db.rows.clear();
    db.stops.set("sbx\0host-1", { sandboxId: "sbx", hostId: "host-1", generation: 4 });
    const unconfigured = new TunnelController({
      now: () => 1_000_000,
      tun: t.tun,
      server: async () => null,
      bridge: () => ({
        link: (hostId: string) => ({
          hostId,
          ownerId: "owner",
          epoch: 1,
          reconciledAt: 0,
          capable: true,
          plan: true,
          send: (frame) => {
            t.sent.push(frame as (typeof t.sent)[number]);
            return true;
          },
        }),
      }),
    });
    await unconfigured.tick();
    expect(clears(t)).toEqual([4]);
  });

  it("pages through more obligations than one page and reaches every one", async () => {
    const t = setup();
    db.rows.clear();
    for (let i = 0; i < 501; i++) {
      const id = `s${String(i).padStart(4, "0")}`;
      db.stops.set(`${id}\0host-1`, { sandboxId: id, hostId: "host-1", generation: 1 });
    }
    await t.controller.tick();
    expect(clears(t)).toHaveLength(500);
    await t.controller.tick();
    expect(t.sent.at(-1)).toMatchObject({ type: "tunnel.clear", sandboxId: "s0500" });
  });

  it("a destroyed sandbox's row takes its obligations with it", async () => {
    const t = setup();
    await t.controller.tick();
    db.stops.set("sbx\0host-9", { sandboxId: "sbx", hostId: "host-9", generation: 1 });
    db.sandbox = null;
    await t.controller.tick();
    expect(db.rows.has("sbx")).toBe(false);
    expect(db.stops.size).toBe(0);
  });
});
