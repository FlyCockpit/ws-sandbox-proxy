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
  updatedAt: Date;
};

const db = vi.hoisted(() => ({
  rows: new Map<string, Row>(),
  sandbox: {
    state: "READY",
    sandboxHostId: "host-1",
    tunnelPorts: [3000, 5173],
    lastStoppedAt: null,
  } as {
    state: string;
    sandboxHostId: string | null;
    tunnelPorts: number[];
    lastStoppedAt: Date | null;
  } | null,
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

/** Prisma-style update data, `{ increment }` included. */
function write(row: Row, data: Record<string, unknown>) {
  for (const [key, value] of Object.entries(data)) {
    const increment = (value as { increment?: number } | null)?.increment;
    (row as Record<string, unknown>)[key] =
      typeof increment === "number" ? (row[key as keyof Row] as number) + increment : value;
  }
  row.updatedAt = new Date();
  checkRow(row);
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
        return { count: 1 };
      }),
    },
    sandboxHost: {
      findMany: vi.fn(async () => [
        db.snapshotBeat ? { ...db.host, lastHeartbeatAt: db.snapshotBeat } : db.host,
      ]),
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
      query.join("?").includes("sandbox_instance")
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
  const tun = {
    createTunnel: vi.fn(async () => ({
      id: "tun1",
      token: `tntun_${"a".repeat(43)}`,
      hostTemplate: "{port}-tun1.tunnel.example.com",
    })),
    rotateTunnelToken: vi.fn(async () => `tntun_${"b".repeat(43)}`),
    deleteTunnel: vi.fn(async () => undefined),
    tunnelsByLabel: vi.fn(async () => [] as string[]),
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
              capable: true,
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
  };
}

beforeEach(() => {
  db.rows.clear();
  db.events.length = 0;
  db.sandbox = {
    state: "READY",
    sandboxHostId: "host-1",
    tunnelPorts: [3000, 5173],
    lastStoppedAt: null,
  };
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
      maxPorts: 2,
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
    expect(again.sent).toEqual([expect.objectContaining({ type: "tunnel.apply", generation: 6 })]);
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
