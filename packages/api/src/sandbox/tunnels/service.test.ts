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
  sweepLabel: boolean;
  creatingUntil: Date | null;
  serverKey: string | null;
  cleanupForgottenAt: Date | null;
  updatedAt: Date;
};

const db = vi.hoisted(() => ({
  row: null as Row | null,
  serverKey: "key-1",
  /** Client-stop obligations left for the row (`sandbox_tunnel_client_stop`). */
  stops: 0,
  /** Run inside the label listing (another process acting meanwhile). */
  duringSweep: null as null | (() => void),
}));

function matches(row: Row, where: Record<string, unknown>) {
  return Object.entries(where).every(([key, value]) => {
    const actual = row[key as keyof Row];
    return value instanceof Date && actual instanceof Date
      ? value.getTime() === actual.getTime()
      : actual === value;
  });
}

function write(row: Row, data: Record<string, unknown>) {
  for (const [key, value] of Object.entries(data)) {
    const increment = (value as { increment?: number } | null)?.increment;
    (row as Record<string, unknown>)[key] =
      typeof increment === "number" ? (row[key as keyof Row] as number) + increment : value;
  }
  if (row.serverKey === null && (row.tunTunnelId || row.sweepLabel || row.creatingUntil))
    throw new Error("violates sandbox_tunnel_server_key");
}

vi.mock("@wssp/db", () => {
  const client = {
    $transaction: vi.fn(async (fn: (tx: unknown) => unknown) => fn(client)),
    // The DTO read: the row and its obligation count in one statement.
    $queryRaw: vi.fn(async (query: TemplateStringsArray) =>
      query.join("?").includes("sandbox_tunnel_client_stop") && db.row
        ? [{ ...db.row, clientStops: db.stops }]
        : [],
    ),
    sandboxTunnel: {
      findFirst: vi.fn(async ({ where }: { where: Record<string, unknown> }) =>
        db.row && matches(db.row, where) ? { ...db.row } : null,
      ),
      update: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
        if (!db.row) throw new Error("no row");
        write(db.row, data);
        return { ...db.row };
      }),
      updateMany: vi.fn(
        async ({
          where,
          data,
        }: {
          where: Record<string, unknown>;
          data: Record<string, unknown>;
        }) => {
          if (!db.row || !matches(db.row, where)) return { count: 0 };
          write(db.row, data);
          return { count: 1 };
        },
      ),
    },
    sandboxTunnelEvent: { create: vi.fn(async () => ({})) },
    sandbox: {
      findFirst: vi.fn(async () => ({
        id: "sbx",
        purpose: "WORKLOAD",
        tunnelEnabled: true,
        tunnelPorts: [3000],
        sandboxHostId: "host-1",
        hostOwnerId: "owner",
      })),
    },
  };
  return { default: client };
});

vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
vi.mock("../budgets", () => ({ consumeSandboxWriteBudget: vi.fn(async () => undefined) }));

vi.mock("../../lib/sdk-key-access", () => ({
  authorizeServiceAction: vi.fn(async () => undefined),
  serviceProcedure: (_meta: unknown, fn: unknown) => fn,
}));

vi.mock("./bridge", () => ({
  tunnelBridge: () => null,
  wakeTunnelController: vi.fn(),
}));

vi.mock("./config", () => ({
  readTunnelServer: vi.fn(async () => ({
    apiUrl: "https://tunnel.example.com",
    credential: `tnsvc_${"s".repeat(43)}`,
    serverKey: db.serverKey,
    draining: false,
  })),
  TUNNEL_CONFIG_ID: "default",
  TunnelCredentialUnavailable: class extends Error {},
  tunnelConfigured: vi.fn(async () => true),
}));

const tun = vi.hoisted(() => ({
  deleteTunnel: vi.fn(async () => undefined),
  tunnelsByLabel: vi.fn(async () => {
    db.duringSweep?.();
    return [] as string[];
  }),
}));
vi.mock("./tun-client", async (original) => ({
  ...(await original<typeof import("./tun-client")>()),
  deleteTunnel: tun.deleteTunnel,
  tunnelsByLabel: tun.tunnelsByLabel,
}));

import { closeSandboxTunnel, closeTunnelRow, getSandboxTunnel } from "./service";

const owner = { kind: "session", ownerId: "owner" } as never;

beforeEach(() => {
  vi.clearAllMocks();
  db.serverKey = "key-1";
  db.duringSweep = null;
  db.stops = 0;
  db.row = {
    sandboxId: "sbx",
    userId: "owner",
    ports: [3000],
    state: "CONNECTED",
    lastError: null,
    tunTunnelId: "tun1",
    hostTemplate: "{port}-tun1.tunnel.example.com",
    hostId: "host-1",
    generation: 4,
    connectedAt: new Date(),
    closedAt: null,
    sweepLabel: false,
    creatingUntil: null,
    serverKey: "key-1",
    cleanupForgottenAt: null,
    updatedAt: new Date(),
  };
});

describe("closing a tunnel", () => {
  it("cleans up under the row's hold and settles by it", async () => {
    let held: Date | null = null;
    db.duringSweep = () => {
      held = db.row?.creatingUntil ?? null;
    };
    const closed = await closeTunnelRow(owner, "sbx");
    expect(closed?.closedAt).not.toBeNull();
    expect(held).not.toBeNull();
    expect(tun.deleteTunnel).toHaveBeenCalledWith(expect.anything(), "tun1");
    expect(tun.tunnelsByLabel).toHaveBeenCalledWith(
      expect.anything(),
      "wssp:key-1:sbx",
      undefined,
      expect.any(Function),
    );
    expect(db.row).toMatchObject({
      tunTunnelId: null,
      serverKey: null,
      creatingUntil: null,
      generation: 5,
      state: "SUSPENDED",
    });
  });

  it("a failed clean-up gives the hold back and keeps the obligation", async () => {
    tun.deleteTunnel.mockRejectedValueOnce(new Error("unreachable"));
    await closeTunnelRow(owner, "sbx");
    expect(db.row).toMatchObject({ tunTunnelId: "tun1", serverKey: "key-1", creatingUntil: null });
  });

  it("leaves a create in flight to settle itself", async () => {
    const createHold = new Date(Date.now() + 60_000);
    if (db.row) Object.assign(db.row, { tunTunnelId: null, creatingUntil: createHold });
    await closeTunnelRow(owner, "sbx");
    expect(tun.tunnelsByLabel).not.toHaveBeenCalled();
    expect(db.row?.creatingUntil).toEqual(createHold);
    expect(db.row?.serverKey).toBe("key-1");
  });

  it("never cleans up with another configuration's credential", async () => {
    db.serverKey = "key-2";
    await closeTunnelRow(owner, "sbx");
    expect(tun.deleteTunnel).not.toHaveBeenCalled();
    expect(db.row).toMatchObject({ tunTunnelId: "tun1", serverKey: "key-1", creatingUntil: null });
  });
});

describe("reporting a closed tunnel's clean-up", () => {
  it("the close forgets the row's host in its own write (its client-stop obligation commits with it)", async () => {
    let hostDuringSweep: string | null | undefined;
    db.duringSweep = () => {
      hostDuringSweep = db.row?.hostId;
    };
    await closeTunnelRow(owner, "sbx");
    expect(hostDuringSweep).toBeNull();
    expect(db.row).toMatchObject({ hostId: null, connectedAt: null });
  });

  it("pending until the host confirmed its client stopped, then done; a repeated close answers it too", async () => {
    db.stops = 1;
    const closed = await closeSandboxTunnel(owner, { id: "sbx" });
    expect(closed).toMatchObject({ state: "closed", cleanup: "pending", urls: [] });
    expect(await getSandboxTunnel(owner, { id: "sbx" })).toMatchObject({
      state: "closed",
      cleanup: "pending",
    });
    db.stops = 0;
    expect(await getSandboxTunnel(owner, { id: "sbx" })).toMatchObject({ cleanup: "done" });
    expect(await closeSandboxTunnel(owner, { id: "sbx" })).toMatchObject({
      state: "closed",
      cleanup: "done",
    });
  });

  it("pending while the tunnel server has not confirmed the deletion (unreachable)", async () => {
    tun.deleteTunnel.mockRejectedValueOnce(new Error("unreachable"));
    const closed = await closeSandboxTunnel(owner, { id: "sbx" });
    expect(closed).toMatchObject({ state: "closed", cleanup: "pending" });
    expect(db.row?.serverKey).toBe("key-1");
    // The controller confirms it later.
    if (db.row) Object.assign(db.row, { serverKey: null, tunTunnelId: null, hostTemplate: null });
    expect(await getSandboxTunnel(owner, { id: "sbx" })).toMatchObject({ cleanup: "done" });
  });

  it("never done after a remove-now forgot the remote state", async () => {
    if (db.row)
      Object.assign(db.row, {
        closedAt: new Date(),
        state: "SUSPENDED",
        tunTunnelId: null,
        hostTemplate: null,
        hostId: null,
        serverKey: null,
        cleanupForgottenAt: new Date(),
      });
    expect(await getSandboxTunnel(owner, { id: "sbx" })).toMatchObject({
      state: "closed",
      cleanup: "pending",
    });
  });

  it("reads the row and its obligations in one statement (one snapshot)", async () => {
    const prisma = (await import("@wssp/db")).default as unknown as {
      $queryRaw: ReturnType<typeof vi.fn>;
      sandboxTunnel: { findFirst: ReturnType<typeof vi.fn> };
    };
    vi.clearAllMocks();
    await getSandboxTunnel(owner, { id: "sbx" });
    expect(prisma.sandboxTunnel.findFirst).not.toHaveBeenCalled();
    const reads = prisma.$queryRaw.mock.calls.map(([query]) => (query as string[]).join("?"));
    expect(reads).toHaveLength(1);
    expect(reads[0]).toMatch(/FROM sandbox_tunnel t[\s\S]*/);
    expect(reads[0]).toMatch(/SELECT count\(\*\)::int FROM sandbox_tunnel_client_stop/);
  });

  it("an open tunnel reports no clean-up", async () => {
    expect(await getSandboxTunnel(owner, { id: "sbx" })).toMatchObject({
      state: "connected",
      cleanup: null,
    });
  });
});
