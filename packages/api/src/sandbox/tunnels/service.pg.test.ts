vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "tunnel-service-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: vi.fn(async () => {}),
  consumeSandboxWriteBudget: vi.fn(async () => {}),
}));
vi.mock("../budgets", () => ({
  consumeCreateConnectBudget: vi.fn(async () => {}),
  consumeSandboxWriteBudget: vi.fn(async () => {}),
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("../sharing-access", () => ({ currentHostUsability: vi.fn(async () => true) }));
const tunServer = vi.hoisted(() => ({
  apiUrl: "https://tunnel.example.com",
  credential: `tnsvc_${"s".repeat(43)}`,
  maxTunnelsPerOwner: 10,
  keyId: "k",
  draining: false,
  serverKey: "key-1",
}));
vi.mock("./config", async (actual) => ({
  ...(await actual<typeof import("./config")>()),
  readTunnelServer: vi.fn(async () => tunServer),
}));
const tun = vi.hoisted(() => ({
  createTunnel: vi.fn(),
  rotateTunnelToken: vi.fn(),
  deleteTunnel: vi.fn(),
  tunnelsByLabel: vi.fn(),
  tunnelsWithLabelPrefix: vi.fn(),
  mintAccessLink: vi.fn(),
  revokeAccessLink: vi.fn(),
}));
vi.mock("./tun-client", async (actual) => ({
  ...(await actual<typeof import("./tun-client")>()),
  ...tun,
}));

/**
 * Preview tunnels on real PostgreSQL: runtime port changes (one transaction
 * per change, serialized on the sandbox row; an exposed port's removal
 * replaces the tunnel under the row's hold before the host hears of it), and
 * the interleavings the (c) review asked to see with the real expose/close
 * paths: an expose or close racing a controller take-down, and an expired
 * creator whose compensation fails while another process holds the row for
 * a clean-up.
 */
import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { runCapacityQueuePass } from "../capacity-queue";
import { leaseNow } from "../lease";
import { createSandbox } from "../services/sandboxes";
import { poolFixture } from "../testing/pool-fixtures";
import { seedSandboxInstance } from "../testing/resource-fixtures";
import { TunnelController } from "./controller";
import {
  closeSandboxTunnel,
  closeTunnelRow,
  createSandboxTunnelLink,
  exposeSandboxTunnel,
  getSandboxTunnel,
  revokeSandboxTunnelLink,
  updateSandboxTunnelPorts,
} from "./service";

const db = await pgTestDatabase();
afterAll(() => db.close());

type Fixture = Awaited<ReturnType<typeof poolFixture>>;
let f: Fixture;

beforeEach(async () => {
  vi.clearAllMocks();
  tun.createTunnel.mockResolvedValue({ id: "tunX", token: "t", hostTemplate: "{port}-x.example" });
  tun.rotateTunnelToken.mockResolvedValue("t");
  tun.deleteTunnel.mockResolvedValue(undefined);
  tun.tunnelsByLabel.mockResolvedValue([]);
  tun.tunnelsWithLabelPrefix.mockResolvedValue({ ids: [], next: null });
  f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: {
      daemonTunnel: { clientSha256: "a".repeat(64), maxTunnels: 4, allowForOthers: false },
      daemonTunnelPorts: true,
    },
  });
  await db.inspect.tunnelServerConfig.upsert({
    where: { id: "default" },
    update: { disabledAt: null, serverKey: "key-1" },
    create: {
      id: "default",
      apiUrl: tunServer.apiUrl,
      credentialCiphertext: new Uint8Array([1]),
      credentialNonce: new Uint8Array([2]),
      credentialKeyId: "k",
      credentialSha256: "b".repeat(64),
      serverKey: "key-1",
    },
  });
});

async function sandbox(data: Record<string, unknown> = {}) {
  return seedSandboxInstance(db.inspect, {
    data: {
      id: randomUUID(),
      userId: f.id,
      templateId: f.revision.templateId,
      templateRevisionId: f.revision.id,
      originHostId: f.host.id,
      sandboxHostId: f.host.id,
      state: "READY",
      tunnelEnabled: true,
      tunnelPorts: [3000],
      ...data,
    },
  });
}

function row(sandboxId: string) {
  return db.inspect.sandboxTunnel.findUnique({ where: { sandboxId } });
}

function controller(now = () => Date.now()) {
  return new TunnelController({ tun, now, server: async () => tunServer, bridge: () => null });
}

describe("runtime tunnel-port changes (PostgreSQL)", () => {
  it("adds and removes declared ports, bumping the revision once per real change", async () => {
    const s = await sandbox();
    const added = await updateSandboxTunnelPorts(f.owner, { id: s.id, add: [5173, 4000] });
    expect(added).toEqual({
      sandboxId: s.id,
      ports: [3000, 4000, 5173],
      revision: 1,
      state: "pending",
    });
    // Nothing to change: no new revision.
    const same = await updateSandboxTunnelPorts(f.owner, { id: s.id, add: [4000], remove: [9] });
    expect(same.revision).toBe(1);
    const removed = await updateSandboxTunnelPorts(f.owner, { id: s.id, remove: [3000] });
    expect(removed).toMatchObject({ ports: [4000, 5173], revision: 2 });
    const stored = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.id } });
    expect(stored.tunnelPorts).toEqual([4000, 5173]);
    expect(stored.tunnelPortsRevision).toBe(2);
    const events = await db.inspect.sandboxTunnelEvent.findMany({
      where: { sandboxId: s.id, kind: "ports.changed" },
      orderBy: { createdAt: "asc" },
    });
    expect(events.map((event) => event.detail)).toEqual(["3000,4000,5173@1", "4000,5173@2"]);
    expect(events.every((event) => event.actorId === f.id)).toBe(true);
    // The current host acknowledging the revision makes it applied.
    await db.inspect.sandbox.update({
      where: { id: s.id },
      data: { tunnelPortsAckHostId: f.host.id, tunnelPortsAckRevision: 2 },
    });
    const applied = await updateSandboxTunnelPorts(f.owner, { id: s.id, add: [4000] });
    expect(applied.state).toBe("applied");
  });

  it("refuses a sandbox created without tunnels and more than eight ports", async () => {
    const plain = await sandbox({ tunnelEnabled: false, tunnelPorts: [] });
    await expect(
      updateSandboxTunnelPorts(f.owner, { id: plain.id, add: [3000] }),
    ).rejects.toMatchObject({ data: { reason: "tunnel_not_enabled" } });
    const full = await sandbox({ tunnelPorts: [1, 2, 3, 4, 5, 6, 7, 8] });
    await expect(
      updateSandboxTunnelPorts(f.owner, { id: full.id, add: [9] }),
    ).rejects.toMatchObject({ data: { code: "sandbox.tunnel_ports_limit" } });
    expect(
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: full.id } })).tunnelPortsRevision,
    ).toBe(0);
  });

  it("concurrent changes serialize on the sandbox row: none is lost", async () => {
    const s = await sandbox();
    const gate = db.pauseAt("first", { after: /FOR UPDATE$/ });
    const first = db.run("first", () =>
      updateSandboxTunnelPorts(f.owner, { id: s.id, add: [4000] }),
    );
    await gate.waitReached();
    const second = updateSandboxTunnelPorts(f.owner, { id: s.id, add: [5000] });
    // The second waits for the first's row lock.
    await new Promise((resolve) => setTimeout(resolve, 200));
    gate.release();
    await Promise.all([first, second]);
    const stored = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.id } });
    expect([...stored.tunnelPorts].sort((a, b) => a - b)).toEqual([3000, 4000, 5000]);
    expect(stored.tunnelPortsRevision).toBe(2);
  });

  it("removing an exposed port deletes the old tunnel under the row's hold and narrows the row", async () => {
    const s = await sandbox({ tunnelPorts: [3000, 5173] });
    await db.inspect.sandboxTunnel.create({
      data: {
        sandboxId: s.id,
        userId: f.id,
        ports: [3000, 5173],
        state: "CONNECTED",
        tunTunnelId: "tun1",
        hostId: f.host.id,
        generation: 4,
        serverKey: "key-1",
      },
    });
    tun.tunnelsByLabel.mockResolvedValueOnce(["tunStray"]);
    const out = await updateSandboxTunnelPorts(f.owner, { id: s.id, remove: [5173] });
    expect(out).toMatchObject({ ports: [3000], revision: 1 });
    // Every link and gate session of the old tunnel dies with it (they are
    // per tunnel on the tunnel server), before the host hears of the change.
    expect(tun.deleteTunnel).toHaveBeenCalledWith(tunServer, "tun1");
    expect(tun.deleteTunnel).toHaveBeenCalledWith(tunServer, "tunStray");
    expect(await row(s.id)).toMatchObject({
      ports: [3000],
      state: "PENDING",
      tunTunnelId: null,
      hostId: null,
      sweepLabel: false,
      creatingUntil: null,
      serverKey: null,
      closedAt: null,
      generation: 5,
    });
    // The last exposed port: the tunnel closes.
    const last = await updateSandboxTunnelPorts(f.owner, { id: s.id, remove: [3000] });
    expect(last).toMatchObject({ ports: [], revision: 2 });
    expect((await row(s.id))?.closedAt).not.toBeNull();
  });

  it("a failed clean-up keeps the sweep owed and lets the hold go", async () => {
    const s = await sandbox({ tunnelPorts: [3000, 5173] });
    await db.inspect.sandboxTunnel.create({
      data: {
        sandboxId: s.id,
        userId: f.id,
        ports: [3000, 5173],
        state: "CONNECTED",
        tunTunnelId: "tun1",
        generation: 4,
        serverKey: "key-1",
      },
    });
    tun.deleteTunnel.mockRejectedValueOnce(new Error("tunnel server down"));
    await updateSandboxTunnelPorts(f.owner, { id: s.id, remove: [5173] });
    expect(await row(s.id)).toMatchObject({
      ports: [3000],
      tunTunnelId: null,
      sweepLabel: true,
      serverKey: "key-1",
      creatingUntil: null,
    });
  });
});

describe("runtime port changes vs other writers (PostgreSQL)", () => {
  it("an expose validated before a removal never writes the removed port back", async () => {
    const s = await sandbox({ tunnelPorts: [3000, 5173] });
    // The expose read the declaration [3000, 5173] and parks before its write.
    const gate = db.pauseAt("expose", { after: /tunnel_server_config[\s\S]*FOR SHARE$/ });
    const expose = db
      .run("expose", () => exposeSandboxTunnel(f.owner, { id: s.id, ports: [3000, 5173] }))
      .catch((error: unknown) => error);
    await gate.waitReached();
    // The removal commits completely while the expose is parked (it holds no
    // lock the removal needs).
    await updateSandboxTunnelPorts(f.owner, { id: s.id, remove: [5173] });
    gate.release();
    const exposed = await expose;
    expect(exposed).toMatchObject({ data: { code: "sandbox.tunnel_port_undeclared" } });
    expect(await row(s.id)).toBeNull();
    expect(
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.id } })).tunnelPorts,
    ).toEqual([3000]);
  });

  it("a capacity-queued tunnel sandbox keeps a port change made while it waited", async () => {
    await db.inspect.sandboxHost.updateMany({
      where: { id: { in: [f.host.id, f.other.id] } },
      data: {
        daemonTunnel: { clientSha256: "a".repeat(64), maxTunnels: 4, allowForOthers: false },
        daemonTunnelPorts: true,
        memoryReservedMiB: 65536,
      },
    });
    const waiting = await createSandbox(f.owner, {
      ...f.input,
      idempotencyKey: randomUUID(),
      waitForCapacityMs: 3_600_000,
      network: { tunnelPorts: [3000] },
    });
    expect(waiting.state).toBe("WAITING_FOR_CAPACITY");
    const changed = await updateSandboxTunnelPorts(f.owner, {
      id: waiting.id,
      add: [4000],
      remove: [3000],
    });
    expect(changed).toMatchObject({ ports: [4000], revision: 1, state: "pending" });
    await db.inspect.sandboxHost.updateMany({
      where: { id: f.host.id },
      data: { memoryReservedMiB: 0 },
    });
    await runCapacityQueuePass(leaseNow, () => false, { poolIds: [f.pool.id] });
    const placed = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: waiting.id } });
    expect(placed.state).toBe("REQUESTED");
    expect(placed).toMatchObject({
      tunnelEnabled: true,
      tunnelPorts: [4000],
      tunnelPortsRevision: 1,
    });
  });
});

describe("carried (c) interleavings on real PostgreSQL", () => {
  it("an expose racing a take-down of a closed row is refused until the take-down settles", async () => {
    const s = await sandbox();
    await db.inspect.sandboxTunnel.create({
      data: {
        sandboxId: s.id,
        userId: f.id,
        ports: [3000],
        state: "SUSPENDED",
        tunTunnelId: "tun1",
        generation: 3,
        closedAt: new Date(),
        serverKey: "key-1",
      },
    });
    let exposed: unknown;
    tun.tunnelsByLabel.mockImplementationOnce(async () => {
      // The take-down holds the row and has deleted tun1; the owner exposes.
      exposed = await exposeSandboxTunnel(f.owner, { id: s.id }).catch((error) => error);
      return [];
    });
    await controller().tick();
    expect(exposed).toMatchObject({ data: { code: "sandbox.tunnel_not_ready" } });
    expect(tun.deleteTunnel).toHaveBeenCalledWith(tunServer, "tun1");
    expect(await row(s.id)).toMatchObject({
      tunTunnelId: null,
      serverKey: null,
      creatingUntil: null,
    });
    // Settled: the expose now reopens the row above the old generation.
    const reopened = await exposeSandboxTunnel(f.owner, { id: s.id });
    expect(reopened.state).toBe("pending");
    expect((await row(s.id))?.generation).toBeGreaterThan(3);
  });

  it("a close racing a take-down keeps the obligation; the next pass finishes it", async () => {
    const s = await sandbox({ state: "STOPPED" });
    await db.inspect.sandboxTunnel.create({
      data: {
        sandboxId: s.id,
        userId: f.id,
        ports: [3000],
        state: "CONNECTED",
        tunTunnelId: "tun1",
        generation: 3,
        serverKey: "key-1",
      },
    });
    tun.tunnelsByLabel.mockImplementationOnce(async () => {
      // The take-down (sandbox stopped) holds the row; the owner closes.
      await closeTunnelRow(f.owner, s.id);
      return [];
    });
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await controller().tick();
    error.mockRestore();
    // The close bumped the generation: the take-down's settle missed and
    // gave its hold back; the close (held row) left the clean-up owed.
    const between = await row(s.id);
    expect(between).toMatchObject({ creatingUntil: null, serverKey: "key-1" });
    expect(between?.closedAt).not.toBeNull();
    await controller().tick();
    expect(await row(s.id)).toMatchObject({
      tunTunnelId: null,
      serverKey: null,
      creatingUntil: null,
    });
  });

  it("an expired creator whose compensation fails during another process's clean-up hold leaves the sweep owed", async () => {
    const s = await sandbox();
    await db.inspect.sandboxTunnel.create({
      data: { sandboxId: s.id, userId: f.id, ports: [3000], state: "PENDING", generation: 1 },
    });
    // A's apply needs a usable host link to create.
    const t0 = Date.now();
    const link = {
      hostId: f.host.id,
      ownerId: f.id,
      epoch: 1,
      reconciledAt: t0 - 60_000,
      capable: true,
      plan: true,
      send: () => true,
    };
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { lastHeartbeatAt: new Date() },
    });
    const creatorA = new TunnelController({
      tun,
      now: () => t0,
      server: async () => tunServer,
      bridge: () => ({ link: () => link }),
    });
    // Another process, 3 minutes later (A's hold expired), without a link.
    const later = () => t0 + 180_000;
    let cleanup: Promise<void> | null = null;
    tun.createTunnel.mockImplementationOnce(async () => {
      // B: the expired hold becomes an owed sweep (generation bumped) ...
      await controller(later).tick();
      // ... and B's clean-up of it holds the row while A's create returns.
      tun.tunnelsByLabel.mockImplementationOnce(async () => {
        await new Promise((resolve) => setTimeout(resolve, 300));
        return [];
      });
      cleanup = controller(later).tick();
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect((await row(s.id))?.creatingUntil).not.toBeNull();
      return { id: "tunA", token: "t", hostTemplate: "{port}-a.example" };
    });
    // A's compensating delete fails: its fallback must record the sweep.
    tun.deleteTunnel.mockRejectedValueOnce(new Error("tunnel server down"));
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await creatorA.tick();
    await cleanup;
    error.mockRestore();
    const owed = await row(s.id);
    expect(owed).toMatchObject({ sweepLabel: true, serverKey: "key-1", creatingUntil: null });
    // The next pass sweeps A's leftover by its label.
    tun.tunnelsByLabel.mockResolvedValueOnce(["tunA"]);
    await controller(later).tick();
    expect(tun.deleteTunnel).toHaveBeenLastCalledWith(tunServer, "tunA");
    expect(await row(s.id)).toMatchObject({ sweepLabel: false, creatingUntil: null });
  });
});

describe("a closed tunnel's clean-up (PostgreSQL)", () => {
  function stops(sandboxId: string) {
    return db.inspect.sandboxTunnelClientStop.findMany({
      where: { sandboxId },
      select: { hostId: true, generation: true },
    });
  }

  async function appliedTunnel() {
    const s = await sandbox();
    await db.inspect.sandboxTunnel.create({
      data: {
        sandboxId: s.id,
        userId: f.id,
        ports: [3000],
        state: "CONNECTED",
        tunTunnelId: "tun1",
        hostTemplate: "{port}-tun1.example",
        hostId: f.host.id,
        generation: 3,
        serverKey: "key-1",
      },
    });
    return s;
  }

  it("pending through an unreachable tunnel server and a host that missed the stop; done once both confirmed", async () => {
    const s = await appliedTunnel();
    tun.deleteTunnel.mockRejectedValue(new Error("unreachable"));
    const closed = await closeSandboxTunnel(f.owner, { id: s.id });
    expect(closed).toMatchObject({ state: "closed", cleanup: "pending", urls: [] });
    // The close's own write recorded the host's obligation (the trigger), at
    // the closed generation.
    expect(await stops(s.id)).toEqual([{ hostId: f.host.id, generation: 4 }]);
    expect(await row(s.id)).toMatchObject({ hostId: null, serverKey: "key-1", generation: 4 });
    // No host session yet (it missed the stop), the tunnel server still down.
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await controller().tick();
    expect(await getSandboxTunnel(f.owner, { id: s.id })).toMatchObject({ cleanup: "pending" });
    // The tunnel server is back: its deletion is confirmed, the host's stop
    // is still owed.
    tun.deleteTunnel.mockResolvedValue(undefined);
    await controller().tick();
    error.mockRestore();
    expect(await row(s.id)).toMatchObject({ serverKey: null, tunTunnelId: null });
    expect(await getSandboxTunnel(f.owner, { id: s.id })).toMatchObject({ cleanup: "pending" });
    // The host is back: it gets the clear at the obligation's generation.
    const sent: { type: string; sandboxId: string; generation: number }[] = [];
    const linked = new TunnelController({
      tun,
      server: async () => tunServer,
      bridge: () => ({
        link: (hostId) => ({
          hostId,
          ownerId: f.id,
          epoch: 1,
          reconciledAt: 0,
          capable: true,
          plan: true,
          send: (frame) => {
            sent.push(frame as (typeof sent)[number]);
            return true;
          },
        }),
      }),
    });
    await linked.tick();
    expect(sent).toContainEqual({ type: "tunnel.clear", sandboxId: s.id, generation: 4 });
    // Its still-running client's own report settles nothing; the stop does.
    await linked.onStatus(f.host.id, 1, {
      type: "tunnel.status",
      sandboxId: s.id,
      generation: 4,
      state: "connected",
      tunnelId: "tun1",
    });
    expect(await stops(s.id)).toHaveLength(1);
    await linked.onStatus(f.host.id, 1, {
      type: "tunnel.status",
      sandboxId: s.id,
      generation: 4,
      state: "stopped",
    });
    expect(await stops(s.id)).toEqual([]);
    expect(await getSandboxTunnel(f.owner, { id: s.id })).toMatchObject({
      state: "closed",
      cleanup: "done",
    });
    // A repeated close answers the same.
    expect(await closeSandboxTunnel(f.owner, { id: s.id })).toMatchObject({ cleanup: "done" });
  });

  it("the trigger keeps the highest generation per host, one row per host, and goes with the tunnel row", async () => {
    const s = await appliedTunnel();
    const other = `${f.host.id}-b`;
    const set = (data: { hostId: string | null; generation: number }) =>
      db.inspect.sandboxTunnel.update({ where: { sandboxId: s.id }, data });
    await set({ hostId: null, generation: 5 });
    await set({ hostId: f.host.id, generation: 6 });
    await set({ hostId: other, generation: 7 });
    await set({ hostId: null, generation: 7 });
    // A stale lower generation never lowers an obligation.
    await set({ hostId: f.host.id, generation: 7 });
    await db.inspect.$executeRaw`UPDATE sandbox_tunnel SET "hostId" = NULL, generation = 2
      WHERE "sandboxId" = ${s.id}`;
    expect((await stops(s.id)).sort((a, b) => a.hostId.localeCompare(b.hostId))).toEqual([
      { hostId: f.host.id, generation: 7 },
      { hostId: other, generation: 7 },
    ]);
    // Unchanged host or other columns: nothing new.
    await db.inspect.sandboxTunnelClientStop.deleteMany({ where: { sandboxId: s.id } });
    await set({ hostId: null, generation: 9 });
    expect(await stops(s.id)).toEqual([]);
    // The row's deletion (its sandbox deleted, tunnels confirmed) takes them.
    await set({ hostId: f.host.id, generation: 10 });
    await set({ hostId: null, generation: 11 });
    expect(await stops(s.id)).toHaveLength(1);
    await db.inspect.sandboxTunnel.delete({ where: { sandboxId: s.id } });
    expect(await stops(s.id)).toEqual([]);
  });
});

describe("revoking one access link (PostgreSQL)", () => {
  it("revokes only a link minted for this sandbox, by its stable id, and audits it", async () => {
    const mine = await sandbox();
    const other = await sandbox();
    for (const s of [mine, other])
      await db.inspect.sandboxTunnel.create({
        data: {
          sandboxId: s.id,
          userId: f.id,
          ports: [3000],
          state: "CONNECTED",
          tunTunnelId: `tun${s.id.slice(0, 4)}`,
          hostTemplate: "{port}-x.example",
          hostId: f.host.id,
          generation: 2,
          serverKey: "key-1",
        },
      });
    tun.mintAccessLink
      .mockResolvedValueOnce({
        id: "al_mine0001",
        url: "https://tunnel.example.com/__access/3000-x/tnacc_a",
        expiresAt: new Date(Date.now() + 60_000),
      })
      .mockResolvedValueOnce({
        id: "al_other001",
        url: "https://tunnel.example.com/__access/3000-y/tnacc_b",
        expiresAt: new Date(Date.now() + 60_000),
      });
    expect((await createSandboxTunnelLink(f.owner, { id: mine.id, port: 3000 })).id).toBe(
      "al_mine0001",
    );
    await createSandboxTunnelLink(f.owner, { id: other.id, port: 3000 });
    // The other sandbox's link is not this sandbox's to revoke.
    await expect(
      revokeSandboxTunnelLink(f.owner, { id: mine.id, linkId: "al_other001" }),
    ).rejects.toMatchObject({
      data: expect.objectContaining({ code: "sandbox.tunnel_link_not_found" }),
    });
    expect(tun.revokeAccessLink).not.toHaveBeenCalled();
    tun.revokeAccessLink.mockResolvedValueOnce(true).mockResolvedValueOnce(false);
    for (let i = 0; i < 2; i++)
      await expect(
        revokeSandboxTunnelLink(f.owner, { id: mine.id, linkId: "al_mine0001" }),
      ).resolves.toEqual({ id: "al_mine0001", sandboxId: mine.id });
    expect(tun.revokeAccessLink).toHaveBeenCalledWith(tunServer, "al_mine0001");
    // Audited once: the repeat found it gone already.
    const revoked = await db.inspect.sandboxTunnelEvent.findMany({
      where: { sandboxId: mine.id, kind: "link.revoked" },
      select: { detail: true, port: true, actorId: true },
    });
    expect(revoked).toEqual([{ detail: "al_mine0001", port: 3000, actorId: f.id }]);
    expect(tun.revokeAccessLink).toHaveBeenCalledTimes(1);
    const record = await db.inspect.sandboxTunnelLink.findUnique({ where: { id: "al_mine0001" } });
    expect(record).toMatchObject({ sandboxId: mine.id, serverKey: "key-1", forgottenAt: null });
    expect(record?.revokedAt).not.toBeNull();
  });

  it("a remove-now's link is never confirmed gone by a later configuration's 404 while it may live", async () => {
    const s = await sandbox();
    await db.inspect.sandboxTunnelLink.create({
      data: {
        id: "al_forgot001",
        sandboxId: s.id,
        userId: f.id,
        serverKey: "key-1",
        port: 3000,
        liveUntil: new Date(Date.now() + 3_600_000),
        forgottenAt: new Date(),
      },
    });
    // Another configuration is current now (the first was removed now).
    await db.inspect.tunnelServerConfig.update({
      where: { id: "default" },
      data: { serverKey: "key-2" },
    });
    tunServer.serverKey = "key-2";
    try {
      tun.revokeAccessLink.mockResolvedValueOnce(false);
      await expect(
        revokeSandboxTunnelLink(f.owner, { id: s.id, linkId: "al_forgot001" }),
      ).rejects.toMatchObject({
        data: expect.objectContaining({ code: "sandbox.tunnel_unavailable" }),
      });
      expect(
        (await db.inspect.sandboxTunnelLink.findUnique({ where: { id: "al_forgot001" } }))
          ?.revokedAt,
      ).toBeNull();
      // Its request was admitted and audited once even so.
      expect(
        await db.inspect.sandboxTunnelEvent.count({
          where: { sandboxId: s.id, kind: "link.revoked" },
        }),
      ).toBe(1);
    } finally {
      tunServer.serverKey = "key-1";
    }
  });
});
