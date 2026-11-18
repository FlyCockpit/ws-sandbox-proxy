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
import { closeTunnelRow, exposeSandboxTunnel, updateSandboxTunnelPorts } from "./service";

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
