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

type Link = {
  id: string;
  sandboxId: string;
  userId: string;
  serverKey: string;
  port: number;
  liveUntil: Date;
  revokeRequestedAt: Date | null;
  revokedAt: Date | null;
  forgottenAt: Date | null;
};

const db = vi.hoisted(() => ({
  row: null as Row | null,
  serverKey: "key-1",
  /** Client-stop obligations left for the row (`sandbox_tunnel_client_stop`). */
  stops: 0,
  /** `sandbox_tunnel_link` records. */
  links: new Map<string, Link>(),
  /** The configuration row's key (null: no configuration). */
  configKey: "key-1" as string | null,
  /** Audit records written. */
  events: [] as Record<string, unknown>[],
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
    $queryRaw: vi.fn(async (query: TemplateStringsArray, ...values: unknown[]) => {
      const text = query.join("?");
      if (text.includes("sandbox_tunnel_client_stop"))
        return db.row ? [{ ...db.row, clientStops: db.stops }] : [];
      if (text.includes("FROM tunnel_server_config"))
        return db.configKey ? [{ serverKey: db.configKey }] : [];
      if (text.includes("FROM sandbox_tunnel_link")) {
        const [id, sandboxId, userId] = values;
        const link = db.links.get(String(id));
        return link && link.sandboxId === sandboxId && link.userId === userId
          ? [{ ...link, now: new Date() }]
          : [];
      }
      return [];
    }),
    sandboxTunnelLink: {
      create: vi.fn(async ({ data }: { data: Omit<Link, "revokeRequestedAt" | "revokedAt"> }) => {
        if (db.links.has(data.id)) throw new Error("unique");
        db.links.set(data.id, { revokeRequestedAt: null, revokedAt: null, ...data });
        return {};
      }),
      update: vi.fn(async ({ where, data }: { where: { id: string }; data: Partial<Link> }) => {
        const link = db.links.get(where.id);
        if (!link) throw new Error("no link");
        Object.assign(link, data);
        return {};
      }),
      updateMany: vi.fn(
        async ({
          where,
          data,
        }: {
          where: { id: string; revokedAt: null; OR?: unknown[] };
          data: Partial<Link>;
        }) => {
          const link = db.links.get(where.id);
          const now = Date.now();
          if (
            !link ||
            link.revokedAt !== null ||
            (where.OR && link.forgottenAt !== null && link.liveUntil.getTime() >= now)
          )
            return { count: 0 };
          Object.assign(link, data);
          return { count: 1 };
        },
      ),
      findUnique: vi.fn(async ({ where }: { where: { id: string } }) => {
        const link = db.links.get(where.id);
        return link ? { revokedAt: link.revokedAt } : null;
      }),
    },
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
    sandboxTunnelEvent: {
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
        db.events.push(data);
        return {};
      }),
    },
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
  revokeAccessLink: vi.fn(async (): Promise<boolean> => true),
  mintAccessLink: vi.fn(async () => ({
    id: "al_minted01",
    url: "https://tunnel.example.com/__access/3000-tun1/tnacc_secret",
    expiresAt: new Date(1_800_000_000_000),
  })),
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
  revokeAccessLink: tun.revokeAccessLink,
  mintAccessLink: tun.mintAccessLink,
}));

import {
  closeSandboxTunnel,
  closeTunnelRow,
  createSandboxTunnelLink,
  getSandboxTunnel,
  revokeSandboxTunnelLink,
} from "./service";

const owner = { kind: "session", ownerId: "owner" } as never;

beforeEach(() => {
  vi.clearAllMocks();
  db.serverKey = "key-1";
  db.duringSweep = null;
  db.stops = 0;
  db.events = [];
  db.configKey = "key-1";
  db.links = new Map(
    [
      ["al_mine0001", "sbx"],
      ["al_other001", "other-sbx"],
    ].map(([id, sandboxId]) => [
      id as string,
      {
        id: id as string,
        sandboxId: sandboxId as string,
        userId: "owner",
        serverKey: "key-1",
        port: 3000,
        liveUntil: new Date(Date.now() + 3_600_000),
        revokeRequestedAt: null,
        revokedAt: null,
        forgottenAt: null,
      },
    ]),
  );
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

describe("access links", () => {
  const mine = () => {
    const link = db.links.get("al_mine0001");
    if (!link) throw new Error("fixture");
    return link;
  };
  const revoke = () => revokeSandboxTunnelLink(owner, { id: "sbx", linkId: "al_mine0001" });
  const unavailable = { data: expect.objectContaining({ code: "sandbox.tunnel_unavailable" }) };

  it("a minted link carries its stable id and is recorded with the configuration that minted it", async () => {
    const link = await createSandboxTunnelLink(owner, { id: "sbx", port: 3000 });
    expect(link.id).toBe("al_minted01");
    expect(db.links.get("al_minted01")).toMatchObject({
      sandboxId: "sbx",
      userId: "owner",
      serverKey: "key-1",
      port: 3000,
      forgottenAt: null,
      // link expiry + the 1 h default session + 5 min skew
      liveUntil: new Date(1_800_000_000_000 + 3_600_000 + 300_000),
    });
    expect(db.events).toContainEqual(
      expect.objectContaining({ kind: "link.minted", detail: "al_minted01" }),
    );
  });

  it("a link that cannot be recorded is revoked again and never handed out", async () => {
    const prisma = (await import("@wssp/db")).default as unknown as {
      sandboxTunnelLink: { create: ReturnType<typeof vi.fn> };
    };
    prisma.sandboxTunnelLink.create.mockRejectedValueOnce(new Error("db down"));
    await expect(createSandboxTunnelLink(owner, { id: "sbx", port: 3000 })).rejects.toMatchObject(
      unavailable,
    );
    expect(tun.revokeAccessLink).toHaveBeenCalledWith(expect.anything(), "al_minted01");
  });

  it("a link minted while its configuration was being replaced is recorded as forgotten", async () => {
    db.configKey = "key-2";
    await createSandboxTunnelLink(owner, { id: "sbx", port: 3000 });
    expect(db.links.get("al_minted01")?.forgottenAt).toBeInstanceOf(Date);
  });

  it("revokes this sandbox's link: admitted, audited once, confirmed", async () => {
    await expect(revoke()).resolves.toEqual({ id: "al_mine0001", sandboxId: "sbx" });
    expect(tun.revokeAccessLink).toHaveBeenCalledWith(expect.anything(), "al_mine0001");
    expect(mine().revokeRequestedAt).toBeInstanceOf(Date);
    expect(mine().revokedAt).toBeInstanceOf(Date);
    expect(db.events).toEqual([
      expect.objectContaining({
        kind: "link.revoked",
        sandboxId: "sbx",
        userId: "owner",
        actorId: "owner",
        port: 3000,
        detail: "al_mine0001",
      }),
    ]);
    // Idempotent: confirmed already, no second call or audit.
    await expect(revoke()).resolves.toEqual({ id: "al_mine0001", sandboxId: "sbx" });
    expect(tun.revokeAccessLink).toHaveBeenCalledTimes(1);
    expect(db.events).toHaveLength(1);
  });

  it("never revokes another sandbox's link (or an unknown one)", async () => {
    for (const linkId of ["al_other001", "al_unknown1"])
      await expect(revokeSandboxTunnelLink(owner, { id: "sbx", linkId })).rejects.toMatchObject({
        data: expect.objectContaining({ code: "sandbox.tunnel_link_not_found" }),
      });
    expect(tun.revokeAccessLink).not.toHaveBeenCalled();
    expect(db.events).toEqual([]);
  });

  it("a caller whose authority lapsed revokes nothing", async () => {
    const access = await import("../../lib/sdk-key-access");
    vi.mocked(access.authorizeServiceAction).mockRejectedValueOnce(new Error("key revoked"));
    await expect(revoke()).rejects.toThrow("key revoked");
    expect(tun.revokeAccessLink).not.toHaveBeenCalled();
    expect(mine().revokeRequestedAt).toBeNull();
  });

  it("an unanswered DELETE is a retryable 503; the retry's 404 confirms it (audited once)", async () => {
    tun.revokeAccessLink.mockRejectedValueOnce(new Error("timeout"));
    await expect(revoke()).rejects.toMatchObject(unavailable);
    expect(mine().revokedAt).toBeNull();
    tun.revokeAccessLink.mockResolvedValueOnce(false);
    await expect(revoke()).resolves.toEqual({ id: "al_mine0001", sandboxId: "sbx" });
    expect(mine().revokedAt).toBeInstanceOf(Date);
    expect(db.events).toHaveLength(1);
  });

  it("a confirmed revocation never needs the credential (unreadable now)", async () => {
    mine().revokedAt = new Date();
    const config = await import("./config");
    await expect(revoke()).resolves.toEqual({ id: "al_mine0001", sandboxId: "sbx" });
    // Not even opened: an undecryptable credential could not refuse it.
    expect(config.readTunnelServer).not.toHaveBeenCalled();
    expect(tun.revokeAccessLink).not.toHaveBeenCalled();
  });

  it("a link of a drained earlier configuration is gone without a call", async () => {
    db.configKey = "key-2";
    db.serverKey = "key-2";
    await expect(revoke()).resolves.toEqual({ id: "al_mine0001", sandboxId: "sbx" });
    expect(tun.revokeAccessLink).not.toHaveBeenCalled();
  });

  it("a remove-now's link: revoked by the same server configured again, unconfirmed by a 404 while it may live", async () => {
    mine().forgottenAt = new Date();
    db.configKey = "key-2";
    db.serverKey = "key-2";
    tun.revokeAccessLink.mockResolvedValueOnce(false);
    await expect(revoke()).rejects.toMatchObject(unavailable);
    expect(mine().revokedAt).toBeNull();
    tun.revokeAccessLink.mockResolvedValueOnce(true);
    await expect(revoke()).resolves.toEqual({ id: "al_mine0001", sandboxId: "sbx" });
    expect(mine().revokedAt).toBeInstanceOf(Date);
  });

  it("a remove-now's link past any session's life is gone without a call", async () => {
    Object.assign(mine(), { forgottenAt: new Date(), liveUntil: new Date(Date.now() - 1_000) });
    db.configKey = null;
    const config = await import("./config");
    vi.mocked(config.readTunnelServer).mockResolvedValueOnce(null);
    await expect(revoke()).resolves.toEqual({ id: "al_mine0001", sandboxId: "sbx" });
    expect(tun.revokeAccessLink).not.toHaveBeenCalled();
  });

  it("with tunnels off, a forgotten live link is unconfirmed (no credential to ask)", async () => {
    mine().forgottenAt = new Date();
    db.configKey = null;
    const config = await import("./config");
    vi.mocked(config.readTunnelServer).mockResolvedValueOnce(null);
    await expect(revoke()).rejects.toMatchObject(unavailable);
  });

  it("a remove-now between the admission and the 404 leaves it unconfirmed", async () => {
    tun.revokeAccessLink.mockImplementationOnce(async () => {
      mine().forgottenAt = new Date();
      return false;
    });
    await expect(revoke()).rejects.toMatchObject(unavailable);
    expect(mine().revokedAt).toBeNull();
  });
});
