// WP4 boot sweep against real PostgreSQL: the epoch CAS, bounded paging,
// the owner → H lock order and error propagation (a failure fails boot).
import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
const db = await pgTestDatabase();
const { sweepConnectedHosts, HOST_LIVENESS_SWEEP_PAGE } = await import("./host-liveness.js");
afterAll(() => db.close());

/** Every test starts from a database with no CONNECTED host. */
beforeEach(async () => {
  await db.inspect.sandboxHost.updateMany({
    where: { status: "CONNECTED" },
    data: { status: "DISCONNECTED" },
  });
});

async function connectedHost(epoch = 4, status: "CONNECTED" | "DISCONNECTED" = "CONNECTED") {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: { id: userId, name: "Owner", email: `${userId}@example.test` },
  });
  return seedLaunchHost(db.inspect, {
    data: {
      userId,
      slug: "host",
      label: "Host",
      status,
      connectionEpoch: epoch,
      journalKeyAcknowledgedEpoch: epoch,
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: epoch,
      admissionRuntime: "FAKE",
      admissionEpoch: epoch,
    },
  });
}
const hostRow = (id: string) => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id } });

it("marks every CONNECTED host DISCONNECTED with its epoch revoked, across pages", async () => {
  const hosts = [];
  for (let i = 0; i < HOST_LIVENESS_SWEEP_PAGE * 2 + 3; i++) hosts.push(await connectedHost());
  const idle = await connectedHost(9, "DISCONNECTED");
  const pages: { take?: number }[] = [];
  const findMany = db.prisma.sandboxHost.findMany.bind(db.prisma.sandboxHost);
  const spy = vi.spyOn(db.prisma.sandboxHost, "findMany").mockImplementation(((args: {
    take?: number;
  }) => {
    pages.push({ take: args.take });
    return findMany(args as never);
  }) as never);
  try {
    expect(await sweepConnectedHosts()).toEqual({ disconnected: hosts.length });
  } finally {
    spy.mockRestore();
  }
  // Bounded: three pages of at most 100 rows.
  expect(pages).toEqual(Array.from({ length: 3 }, () => ({ take: HOST_LIVENESS_SWEEP_PAGE })));
  for (const host of hosts)
    expect(await hostRow(host.id)).toMatchObject({
      status: "DISCONNECTED",
      lastDisconnectedAt: expect.any(Date),
      connectionEpoch: 5,
      journalKeyAcknowledgedEpoch: null,
      // Protocol and admission facts move to the revoked epoch, as on a live end.
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 5,
      admissionRuntime: "FAKE",
      admissionEpoch: 5,
    });
  // A host already DISCONNECTED is not read or rewritten.
  expect(await hostRow(idle.id)).toMatchObject({ status: "DISCONNECTED", connectionEpoch: 9 });
  // Idempotent: nothing is CONNECTED any more.
  expect(await sweepConnectedHosts()).toEqual({ disconnected: 0 });
});

it("a host whose epoch moved after its page was read loses the CAS and is left alone", async () => {
  const raced = await connectedHost(4);
  const plain = await connectedHost(4);
  const gate = db.pauseAt("sweep", { before: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/ });
  const sweeping = db.run("sweep", () => sweepConnectedHosts());
  await gate.waitReached();
  // A hello on another epoch committed meanwhile (the first host in id order).
  const first = [raced, plain].sort((a, b) => a.id.localeCompare(b.id))[0]!;
  const second = first.id === raced.id ? plain : raced;
  await db.inspect.sandboxHost.update({ where: { id: first.id }, data: { connectionEpoch: 6 } });
  gate.release();
  expect(await sweeping).toEqual({ disconnected: 1 });
  expect(await hostRow(first.id)).toMatchObject({ status: "CONNECTED", connectionEpoch: 6 });
  expect(await hostRow(second.id)).toMatchObject({ status: "DISCONNECTED", connectionEpoch: 5 });
});

it("takes the owner lock before the host lock (owner → H)", async () => {
  const host = await connectedHost(4);
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let locked!: () => void;
  const ownerLocked = new Promise<void>((resolve) => {
    locked = resolve;
  });
  // An account-deletion style writer holds the owner row.
  const owner = db.run("owner", () =>
    db.prisma.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${host.userId} FOR UPDATE`;
        locked();
        await held;
      },
      { timeout: 30_000 },
    ),
  );
  await ownerLocked;
  const sweeping = db.run("sweep", () => sweepConnectedHosts());
  const blocked = await db.waitUntilBlocked("sweep", { by: "owner" });
  expect(blocked.query).toMatch(/FROM "user"/);
  // While waiting on the owner, the sweep holds no host lock.
  const free = await db.inspect.$transaction(
    async (tx) =>
      tx.$queryRaw<
        { id: string }[]
      >`SELECT id FROM sandbox_host WHERE id = ${host.id} FOR UPDATE NOWAIT`,
  );
  expect(free).toHaveLength(1);
  release();
  await owner;
  expect(await sweeping).toEqual({ disconnected: 1 });
  expect(await hostRow(host.id)).toMatchObject({ status: "DISCONNECTED", connectionEpoch: 5 });
});

it("a database error propagates (the caller fails boot) and commits nothing for that host", async () => {
  const host = await connectedHost(4);
  const gate = db.pauseAt("sweep", { before: /^sandboxHost\.updateMany$/ });
  const sweeping = db.run("sweep", () => sweepConnectedHosts());
  await gate.waitReached();
  gate.fail(new Error("injected database failure"));
  await expect(sweeping).rejects.toThrow();
  expect(await hostRow(host.id)).toMatchObject({ status: "CONNECTED", connectionEpoch: 4 });
});
