import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { seedLaunchHost } from "./testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/auth", () => ({
  auth: { $context: Promise.resolve({ secretConfig: "host-terminal-matrix-fixture-secret" }) },
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "host-terminal-matrix-fixture",
    SANDBOX_REQUEST_HMAC_SECRET: "a".repeat(64),
  },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("./terminal-budgets", () => ({
  consumeTerminalMintBudget: async () => {},
  consumeHostProofBudget: async () => {},
}));
const db = await pgTestDatabase();
const { bindHostTerminalPolicy } = await import("./host-terminal-policy");
const { mintHostTerminalTicket } = await import("./host-terminal-tickets");
afterEach(() => bindHostTerminalPolicy(null));
afterAll(() => db.close());
async function person() {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const session = await db.inspect.session.create({
    data: { userId: id, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
  });
  return { userId: id, sessionId: session.id };
}
it("node-reported terminal off refuses, on admits only the live owner session; a dashboard veto refuses while the node still reports on", async () => {
  const a = await person(),
    b = await person();
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: a.userId,
      slug: "terminal-matrix",
      label: "Terminal",
      connectionEpoch: 7,
      status: "CONNECTED",
    },
  });
  const policy = {
    hostTerminal: false,
    requireHostTerminalTotp: false,
    policyRevision: 1,
    epoch: 7,
  };
  bindHostTerminalPolicy({
    read: (hostId, ownerId) =>
      hostId === host.id && ownerId === a.userId ? { ...policy } : undefined,
    raise: async () => false,
    // Fake relay binding still enforces the durable, DB-backed lower veto.
    authorize: async (hostId, ownerId, epoch, tx) =>
      Boolean(
        await tx.sandboxHost.findFirst({
          where: {
            id: hostId,
            userId: ownerId,
            connectionEpoch: epoch,
            hostTerminalVetoedAt: null,
          },
          select: { id: true },
        }),
      ),
  });
  const input = { hostId: host.id, rows: 24, cols: 80 };
  await expect(mintHostTerminalTicket(a, input)).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "HOST_TERMINAL_UNAVAILABLE" },
  });
  policy.hostTerminal = true;
  policy.policyRevision++;
  await expect(mintHostTerminalTicket(a, input)).resolves.toMatchObject({
    ticket: expect.any(String),
  });
  await expect(mintHostTerminalTicket(b, input)).rejects.toMatchObject({ code: "NOT_FOUND" });
  await expect(
    mintHostTerminalTicket({ ...a, sessionId: "credential-is-not-a-session" }, input),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: { hostTerminalVetoedAt: new Date() },
  });
  // A dashboard veto refuses exactly like a node that has host terminals off.
  await expect(mintHostTerminalTicket(a, input)).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "HOST_TERMINAL_UNAVAILABLE" },
  });
  expect(await db.inspect.hostTerminalTicket.count({ where: { sandboxHostId: host.id } })).toBe(1);
});
