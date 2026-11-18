/**
 * Tunnel clean-up holds on real PostgreSQL: a controller pass whose snapshot
 * of a row is stale never calls the tunnel server for it (its hold's
 * compare-and-set misses), and of two passes cleaning up the same row only
 * one takes the hold.
 */
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("../sharing-access", () => ({ currentHostUsability: vi.fn(async () => true) }));

import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TunnelController } from "./controller";

const db = await pgTestDatabase();
afterAll(() => db.close());

const server = {
  apiUrl: "https://tunnel.example.com",
  credential: `tnsvc_${"s".repeat(43)}`,
  maxTunnelsPerOwner: 10,
  keyId: "k",
  draining: false,
  serverKey: "key-1",
};

function tunDouble() {
  return {
    createTunnel: vi.fn(async () => ({ id: "tunX", token: "t", hostTemplate: "{port}-x.example" })),
    rotateTunnelToken: vi.fn(async () => "t"),
    deleteTunnel: vi.fn(async () => undefined),
    tunnelsByLabel: vi.fn(async () => [] as string[]),
    tunnelsWithLabelPrefix: vi.fn(async () => ({ ids: [] as string[], next: null })),
  };
}

function controller(tun: ReturnType<typeof tunDouble>) {
  return new TunnelController({ tun, server: async () => server, bridge: () => null });
}

beforeEach(async () => {
  await db.prisma.sandboxTunnel.deleteMany({ where: { userId: "owner" } });
});

describe("tunnel clean-up holds (PostgreSQL)", () => {
  it("a pass with an old snapshot of a closed row never deletes the re-exposed tunnel", async () => {
    const sandboxId = "sbx-stale";
    await db.prisma.sandboxTunnel.create({
      data: {
        sandboxId,
        userId: "owner",
        ports: [3000],
        state: "SUSPENDED",
        tunTunnelId: "tun1",
        generation: 5,
        closedAt: new Date(),
        serverKey: "key-1",
      },
    });
    const tun = tunDouble();
    tun.tunnelsByLabel.mockResolvedValue(["tun2"]);
    // After this pass read the row: another process finished its clean-up,
    // the owner exposed again and a create recorded tun2 under the same label.
    const spy = vi.spyOn(db.prisma.sandbox, "findMany");
    spy.mockImplementationOnce((async (...args: Parameters<typeof db.prisma.sandbox.findMany>) => {
      await db.prisma.sandboxTunnel.update({
        where: { sandboxId },
        data: { tunTunnelId: null, serverKey: null },
      });
      await db.prisma.sandboxTunnel.update({
        where: { sandboxId },
        data: {
          closedAt: null,
          generation: 8,
          state: "CONNECTED",
          tunTunnelId: "tun2",
          serverKey: "key-1",
        },
      });
      spy.mockRestore();
      return db.prisma.sandbox.findMany(...args);
    }) as never);
    await controller(tun).tick();
    expect(tun.tunnelsByLabel).not.toHaveBeenCalled();
    expect(tun.deleteTunnel).not.toHaveBeenCalled();
    expect(
      await db.prisma.sandboxTunnel.findUnique({
        where: { sandboxId },
        select: { tunTunnelId: true, serverKey: true, creatingUntil: true, closedAt: true },
      }),
    ).toEqual({ tunTunnelId: "tun2", serverKey: "key-1", creatingUntil: null, closedAt: null });
  });

  it("of two passes holding the same snapshot only one calls the tunnel server", async () => {
    const sandboxId = "sbx-race";
    await db.prisma.sandboxTunnel.create({
      data: {
        sandboxId,
        userId: "owner",
        ports: [3000],
        state: "SUSPENDED",
        tunTunnelId: "tun1",
        generation: 3,
        closedAt: new Date(),
        serverKey: "key-1",
      },
    });
    // Barrier: both passes have read the row before either goes on to its
    // hold (the sandbox read follows the row read in every pass).
    const original = db.prisma.sandbox.findMany.bind(db.prisma.sandbox);
    let arrived = 0;
    let both!: () => void;
    const met = new Promise<void>((resolve) => {
      both = resolve;
    });
    const spy = vi.spyOn(db.prisma.sandbox, "findMany").mockImplementation((async (
      ...args: Parameters<typeof db.prisma.sandbox.findMany>
    ) => {
      arrived += 1;
      if (arrived === 2) both();
      await met;
      return original(...args);
    }) as never);
    const tun = tunDouble();
    try {
      await Promise.all([controller(tun).tick(), controller(tun).tick()]);
    } finally {
      spy.mockRestore();
    }
    expect(arrived).toBe(2);
    expect(tun.deleteTunnel).toHaveBeenCalledTimes(1);
    expect(tun.tunnelsByLabel).toHaveBeenCalledTimes(1);
    expect(await db.prisma.sandboxTunnel.findUnique({ where: { sandboxId } })).toBeNull();
  });

  it("an expose during a take-down keeps the obligation; the next pass settles", async () => {
    const sandboxId = "sbx-expose";
    await db.prisma.sandboxTunnel.create({
      data: {
        sandboxId,
        userId: "owner",
        ports: [3000],
        state: "SUSPENDED",
        tunTunnelId: "tun1",
        generation: 3,
        closedAt: new Date(),
        serverKey: "key-1",
      },
    });
    const tun = tunDouble();
    tun.tunnelsByLabel.mockImplementationOnce(async () => {
      // An expose (or a late obligation) bumps the generation meanwhile.
      await db.prisma.sandboxTunnel.update({
        where: { sandboxId },
        data: { generation: { increment: 1 } },
      });
      return [];
    });
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await controller(tun).tick();
    error.mockRestore();
    expect(
      await db.prisma.sandboxTunnel.findUnique({
        where: { sandboxId },
        select: { tunTunnelId: true, serverKey: true, creatingUntil: true, generation: true },
      }),
    ).toEqual({ tunTunnelId: "tun1", serverKey: "key-1", creatingUntil: null, generation: 4 });
    await controller(tun).tick();
    expect(await db.prisma.sandboxTunnel.findUnique({ where: { sandboxId } })).toBeNull();
  });
});
