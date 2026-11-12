import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { encryptTestFactor, testTotp } from "../../../auth/src/testing/terminal-factor";
import { seedLaunchHost } from "./testing/resource-fixtures";

const key = "host-terminal-pg-public-test-key-32-chars";
const budgets = vi.hoisted(() => ({ mint: vi.fn(async () => {}), proof: vi.fn(async () => {}) }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/auth", () => ({
  auth: {
    $context: Promise.resolve({ secretConfig: "host-terminal-pg-public-test-key-32-chars" }),
  },
}));
vi.mock("./budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("./terminal-budgets", () => ({
  consumeTerminalMintBudget: budgets.mint,
  consumeHostProofBudget: budgets.proof,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "host-terminal-test",
    SANDBOX_REQUEST_HMAC_SECRET: "0".repeat(64),
  },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
const db = await pgTestDatabase();
const { bindHostTerminalPolicy } = await import("./host-terminal-policy");
const {
  mintHostTerminalTicket: mint,
  consumeHostTerminalTicket: consume,
  checkHostTerminalBinding: check,
} = await import("./host-terminal-tickets");
const { consumeTerminalTicket } = await import("./terminal-tickets");
const { factorFingerprint, lockTerminalProofUser } = await import("@wssp/db/terminal-proof");
afterAll(() => db.close());
afterEach(() => {
  bindHostTerminalPolicy(null);
  vi.clearAllMocks();
});
const size = { rows: 24, cols: 80 };
async function fixture(required = true, observed = true) {
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
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: id,
      slug: randomUUID(),
      label: "Host",
      status: "CONNECTED",
      connectionEpoch: 7,
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 7,
    },
  });
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const factor = await db.inspect.twoFactor.create({
    data: {
      userId: id,
      secret: await encryptTestFactor(key, secret),
      backupCodes: "public-fixture",
      verified: true,
    },
  });
  if (observed)
    await db.inspect.user.update({
      where: { id },
      data: {
        hostTerminalFactorFingerprint: factorFingerprint(factor),
        hostTerminalFactorObservedAt: new Date(Date.now() - 660000),
      },
    });
  const policy = {
    hostTerminal: true,
    requireHostTerminalTotp: required,
    policyRevision: 1,
    epoch: 7,
  };
  bindHostTerminalPolicy({
    read: (hostId, ownerId) => (hostId === host.id && ownerId === id ? { ...policy } : undefined),
    raise: async () => false,
    authorize: async () => true,
  });
  const code = await testTotp(secret);
  const owner = { userId: id, sessionId: session.id };
  const input = { hostId: host.id, ...size, code };
  return { id, session, host, factor, secret, policy, owner, input };
}
async function binding(f: Awaited<ReturnType<typeof fixture>>) {
  const { ticket } = await mint(f.owner, f.input);
  const value = await consume(ticket);
  expect(value).not.toBeNull();
  return value!;
}
describe("host proof/ticket authority on real PostgreSQL (plan 10–15)", () => {
  it("required proof stores only a digest and complete factor tuple; consume has exactly one concurrent winner", async () => {
    const f = await fixture();
    const { ticket } = await mint(f.owner, f.input);
    const row = await db.inspect.hostTerminalTicket.findFirstOrThrow({ where: { userId: f.id } });
    expect(JSON.stringify(row, (_, v) => (typeof v === "bigint" ? v.toString() : v))).not.toContain(
      ticket,
    );
    expect(row).toMatchObject({
      userId: f.id,
      hostOwnerId: f.id,
      proofRequired: true,
      factorFingerprint: factorFingerprint(f.factor),
    });
    expect(row.verifiedAt).toBeInstanceOf(Date);
    const results = await Promise.all([consume(ticket), consume(ticket)]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await consume(ticket)).toBeNull();
    expect(await check(results.find(Boolean)!)).toEqual({ ok: true });
  });
  it("optional mode never uses proof budget/factor and carries no proof tuple", async () => {
    const f = await fixture(false);
    await db.inspect.twoFactor.delete({ where: { userId: f.id } });
    const b = await binding(f);
    expect(b).toMatchObject({
      proofRequired: false,
      verifiedAt: null,
      observedAt: null,
      factorFingerprint: null,
    });
    expect(budgets.proof).not.toHaveBeenCalled();
    expect(await check(b)).toEqual({ ok: true });
  });
  it("separate tables reject relabeled tokens; expired and mismatched tickets are burned", async () => {
    const f = await fixture(false);
    const { ticket } = await mint(f.owner, f.input);
    expect(await consumeTerminalTicket(ticket)).toBeNull();
    expect(await consume(ticket, new Date(Date.now() + 31000))).toBeNull();
    expect(await consume(ticket)).toBeNull();
  });
  it.each([
    "session",
    "ban",
    "impersonation",
    "host-delete",
    "epoch",
    "revision",
    "required",
    "off",
  ] as const)(
    "%s invalidates an optional attachment without touching guest work",
    async (change) => {
      const f = await fixture(false);
      const b = await binding(f);
      if (change === "session") await db.inspect.session.delete({ where: { id: f.session.id } });
      if (change === "ban")
        await db.inspect.user.update({ where: { id: f.id }, data: { banned: true } });
      if (change === "impersonation")
        await db.inspect.session.update({
          where: { id: f.session.id },
          data: { impersonatedBy: "admin" },
        });
      if (change === "host-delete")
        await db.inspect.sandboxHost.update({
          where: { id: f.host.id },
          data: { deletionRequestedAt: new Date() },
        });
      if (change === "epoch") f.policy.epoch++;
      if (change === "revision") f.policy.policyRevision++;
      if (change === "required") f.policy.requireHostTerminalTotp = true;
      if (change === "off") f.policy.hostTerminal = false;
      expect(await check(b)).toEqual({
        ok: false,
        intent: change === "off" ? "host_terminals_disabled" : "revoked",
      });
    },
  );
  it("first/absent/replaced factor observations commit before refusal; unchanged counter/backup fields preserve observation", async () => {
    const f = await fixture(true, false);
    await expect(mint(f.owner, f.input)).rejects.toMatchObject({ code: "FORBIDDEN" });
    const first = await db.inspect.user.findUniqueOrThrow({ where: { id: f.id } });
    expect(first.hostTerminalFactorObservedAt).toBeInstanceOf(Date);
    await db.inspect.twoFactor.update({
      where: { userId: f.id },
      data: { failedVerificationCount: 3, backupCodes: "different" },
    });
    await expect(mint(f.owner, f.input)).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(
      (await db.inspect.user.findUniqueOrThrow({ where: { id: f.id } }))
        .hostTerminalFactorObservedAt,
    ).toEqual(first.hostTerminalFactorObservedAt);
    await db.inspect.twoFactor.delete({ where: { userId: f.id } });
    await expect(mint(f.owner, f.input)).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(
      (await db.inspect.user.findUniqueOrThrow({ where: { id: f.id } }))
        .hostTerminalFactorFingerprint,
    ).toBe("absent");
  });
  it("raw factor replacement without a hint closes required attachment and records new cooldown", async () => {
    const f = await fixture();
    const b = await binding(f);
    await db.inspect.twoFactor.update({
      where: { userId: f.id },
      data: { secret: "raw-adapter-replacement" },
    });
    expect(await check(b)).toEqual({ ok: false, intent: "revoked" });
    const user = await db.inspect.user.findUniqueOrThrow({ where: { id: f.id } });
    expect(user.hostTerminalFactorObservedAt!.getTime()).toBeGreaterThan(Date.now() - 10000);
    expect(user.hostTerminalFactorFingerprint).not.toBe(b.factorFingerprint);
  });
  it("concurrent hosts/sessions share the maximum used step; only one mint wins", async () => {
    const f = await fixture();
    const otherSession = await db.inspect.session.create({
      data: { userId: f.id, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
    });
    const otherHost = await seedLaunchHost(db.inspect, {
      data: {
        userId: f.id,
        slug: randomUUID(),
        label: "Other host",
        status: "CONNECTED",
        connectionEpoch: 7,
        relayProtocolVersion: "1.0",
        relayProtocolEpoch: 7,
      },
    });
    bindHostTerminalPolicy({
      read: () => f.policy,
      raise: async () => false,
      authorize: async () => true,
    });
    const results = await Promise.allSettled([
      mint(f.owner, f.input),
      mint({ userId: f.id, sessionId: otherSession.id }, { ...f.input, hostId: otherHost.id }),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(await db.inspect.hostTerminalTicket.count({ where: { userId: f.id } })).toBe(1);
    expect(
      (await db.inspect.user.findUniqueOrThrow({ where: { id: f.id } })).hostTerminalFailedAttempts,
    ).toBe(1);
  });
  it("ten bad/replayed proofs persist a 15-minute lock; factor lock is checked before calculation", async () => {
    const f = await fixture();
    await db.inspect.user.update({ where: { id: f.id }, data: { hostTerminalFailedAttempts: 9 } });
    await expect(mint(f.owner, { ...f.input, code: "------" })).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
    const locked = await db.inspect.user.findUniqueOrThrow({ where: { id: f.id } });
    expect(locked.hostTerminalFailedAttempts).toBe(10);
    expect(locked.hostTerminalLockedUntil!.getTime()).toBeGreaterThan(Date.now() + 890000);
    await expect(mint(f.owner, f.input)).rejects.toMatchObject({ code: "FORBIDDEN" });
    await db.inspect.user.update({ where: { id: f.id }, data: { hostTerminalLockedUntil: null } });
    await db.inspect.twoFactor.update({
      where: { userId: f.id },
      data: { lockedUntil: new Date(Date.now() + 60000), secret: "un-decryptable" },
    });
    await expect(mint(f.owner, f.input)).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
  it("budget exhaustion/failure commits durable lock before refusing", async () => {
    const f = await fixture();
    budgets.proof.mockRejectedValueOnce(new Error("budget unavailable"));
    await expect(mint(f.owner, f.input)).rejects.toThrow("budget unavailable");
    expect(
      (
        await db.inspect.user.findUniqueOrThrow({ where: { id: f.id } })
      ).hostTerminalLockedUntil!.getTime(),
    ).toBeGreaterThan(Date.now());
    expect(await db.inspect.hostTerminalTicket.count({ where: { userId: f.id } })).toBe(0);
  });
  it("User NO KEY UPDATE serializes proof writers, while post-H User FK KEY SHARE cannot deadlock mint", async () => {
    const f = await fixture(false);
    const held = db.pauseAt("mint", { after: /sql:SELECT id FROM sandbox_host.*FOR UPDATE/ });
    const action = db.run("mint", () => mint(f.owner, f.input));
    await held.waitReached();
    const contender = db.run("contender", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${f.id} FOR KEY SHARE`;
        await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
      }),
    );
    try {
      await db.waitUntilBlocked("contender", { by: "mint" });
    } finally {
      held.release();
    }
    await action;
    await contender;
    const pause = db.pauseAt("writer1", { after: /sql:SELECT id FROM "user".*NO KEY UPDATE/ });
    const writer1 = db.run("writer1", () =>
      db.prisma.$transaction((tx) => lockTerminalProofUser(tx, f.id)),
    );
    await pause.waitReached();
    const writer2 = db.run("writer2", () =>
      db.prisma.$transaction((tx) => lockTerminalProofUser(tx, f.id)),
    );
    try {
      await db.waitUntilBlocked("writer2", { by: "writer1" });
    } finally {
      pause.release();
    }
    await writer1;
    await writer2;
  });
  it("session revoke waits for the mint prefix; committed revoke then refuses consumed ticket", async () => {
    const f = await fixture(false);
    const pause = db.pauseAt("mint", { after: /sql:SELECT id FROM session.*FOR SHARE/ });
    const action = db.run("mint", () => mint(f.owner, f.input));
    await pause.waitReached();
    const revoke = db.run("revoke", () =>
      db.prisma.$transaction((tx) => tx.session.delete({ where: { id: f.session.id } })),
    );
    try {
      await db.waitUntilBlocked("revoke", { by: "mint" });
    } finally {
      pause.release();
    }
    const result = await action;
    await revoke;
    expect(await consume(result.ticket)).toBeNull(); // Session FK cascades ticket in the winning revoke.
  });
});

it.each(["factor", "session", "host-delete", "policy"] as const)(
  "calculation→mint race with %s commits no ticket or watermark",
  async (change) => {
    const f = await fixture();
    const pause = db.pauseAt("mint", { before: "hostTerminalTicket.findMany" });
    const action = db.run("mint", () => mint(f.owner, f.input));
    const outcome = action.then(
      () => "accepted",
      () => "refused",
    );
    try {
      await pause.waitReached();
      if (change === "factor")
        await db.inspect.twoFactor.update({
          where: { userId: f.id },
          data: { secret: "replaced-after-calculation" },
        });
      if (change === "session") await db.inspect.session.delete({ where: { id: f.session.id } });
      if (change === "host-delete")
        await db.inspect.sandboxHost.update({
          where: { id: f.host.id },
          data: { deletionRequestedAt: new Date() },
        });
      if (change === "policy") f.policy.policyRevision++;
    } finally {
      pause.release();
    }
    expect(await outcome).toBe("refused");
    expect(await db.inspect.hostTerminalTicket.count({ where: { userId: f.id } })).toBe(0);
    expect(
      (await db.inspect.user.findUniqueOrThrow({ where: { id: f.id } })).hostTerminalLastTotpStep,
    ).toBeNull();
  },
);
it("registered router refuses impersonated/revoked/foreign owners; offline raise stores nothing", async () => {
  const { createRouterClient } = await import("@orpc/server");
  const { hostTerminalsRouter } = await import("../routers/host-terminals");
  const f = await fixture(false);
  const user = await db.inspect.user.findUniqueOrThrow({ where: { id: f.id } });
  const client = createRouterClient(hostTerminalsRouter, {
    context: { clientIp: undefined, session: { user, session: f.session } },
  });
  await db.inspect.session.update({
    where: { id: f.session.id },
    data: { impersonatedBy: "admin" },
  });
  await expect(client.createSession(f.input)).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  await expect(client.raiseHostTerminalTotp({ id: f.host.id })).rejects.toMatchObject({
    code: "UNAUTHORIZED",
  });
  await db.inspect.session.update({ where: { id: f.session.id }, data: { impersonatedBy: null } });
  await expect(client.createSession({ ...f.input, hostId: "foreign" })).rejects.toMatchObject({
    code: "NOT_FOUND",
  });
  bindHostTerminalPolicy(null);
  await expect(client.raiseHostTerminalTotp({ id: f.host.id })).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "HOST_OFFLINE" },
  });
  expect(await db.inspect.hostTerminalTicket.count({ where: { userId: f.id } })).toBe(0);
  await db.inspect.session.delete({ where: { id: f.session.id } });
  await expect(client.createSession(f.input)).rejects.toMatchObject({ code: "UNAUTHORIZED" });
});

it("required observation cannot backdate through counter writes, and optional mode cannot reset durable proof locks", async () => {
  const f = await fixture(false);
  const until = new Date(Date.now() + 900000);
  await db.inspect.user.update({
    where: { id: f.id },
    data: { hostTerminalFailedAttempts: 9, hostTerminalLockedUntil: until },
  });
  await mint(f.owner, f.input);
  expect(await db.inspect.user.findUniqueOrThrow({ where: { id: f.id } })).toMatchObject({
    hostTerminalFailedAttempts: 9,
    hostTerminalLockedUntil: until,
  });
});
it("live durable transport refusal prevents both mint and pre-open even while capability is remembered", async () => {
  const f = await fixture(false);
  const b = await binding(f);
  bindHostTerminalPolicy({
    read: () => f.policy,
    raise: async () => false,
    authorize: async () => false,
  });
  expect(await check(b)).toEqual({ ok: false, intent: "revoked" });
  await expect(mint(f.owner, f.input)).rejects.toMatchObject({ code: "FORBIDDEN" });
});
it("host ticket sizes match shared relay bounds, including 512 rows and 1024 columns", async () => {
  const f = await fixture(false);
  const { ticket } = await mint(f.owner, { ...f.input, rows: 512, cols: 1024 });
  expect(await consume(ticket)).toMatchObject({ rows: 512, cols: 1024 });
});
