import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "./testing/resource-fixtures";

/**
 * C53 browser terminal tickets against real PostgreSQL: only a digest is
 * stored; the ticket is bound to (session, owner, sandbox, host, generation);
 * consume is ONE atomic `DELETE ... RETURNING` (concurrent presentations have
 * exactly one winner, a replay finds nothing, an expired ticket is burned);
 * logout cascades outstanding tickets away; and the binding re-read refuses
 * every revocation and lifecycle change.
 */

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "c53-pg-fixture",
  },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const db = await pgTestDatabase();
const { checkTerminalBinding, consumeTerminalTicket, mintTerminalTicket, terminalTicketDigest } =
  await import("./terminal-tickets");
const { invalidateForceTwoFactorSettingsCache } = await import("../lib/two-factor-policy");
afterAll(() => db.close());
beforeEach(() => invalidateForceTwoFactorSettingsCache());

const FP = `sha256:${"d".repeat(64)}`;

async function owner(options: { twoFactorEnabled?: boolean; createdAt?: Date } = {}) {
  const id = `term-${randomUUID()}`;
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      twoFactorEnabled: options.twoFactorEnabled ?? true,
      emailVerified: true,
      ...(options.createdAt ? { createdAt: options.createdAt } : {}),
    },
  });
  const session = await db.inspect.session.create({
    data: { userId: id, token: `tok-${id}`, expiresAt: new Date(Date.now() + 3_600_000) },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: id,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      lastHeartbeatAt: new Date(),
      egressEnforcement: true,
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "ubuntu",
      label: "Ubuntu",
      imageRef: "local:ubuntu",
      incusFingerprint: FP,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      originHostId: host.id,
      templateId: template.id,
      originPoolId: null,
      state: "READY",
      generation: 3,
      liveResourcesHeld: true,
    },
  });
  return { id, session, host, sandbox };
}

const SIZE = { rows: 24, cols: 80 };

describe("mint", () => {
  it("stores only the digest, bound to session, owner, sandbox, host and generation", async () => {
    const o = await owner();
    const { ticket, expiresAt } = await mintTerminalTicket(
      { userId: o.id, sessionId: o.session.id },
      { sandboxId: o.sandbox.id, ...SIZE },
    );
    expect(ticket).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(expiresAt.getTime() - Date.now()).toBeLessThanOrEqual(30_000);
    const rows = await db.inspect.sandboxTerminalTicket.findMany({ where: { userId: o.id } });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      tokenDigest: terminalTicketDigest(ticket),
      sessionId: o.session.id,
      sandboxId: o.sandbox.id,
      sandboxHostId: o.host.id,
      generation: 3,
      ...SIZE,
    });
    // The plaintext ticket is in no column.
    expect(JSON.stringify(rows)).not.toContain(ticket);
  });

  it("another owner's sandbox is NOT_FOUND and a non-READY sandbox is a conflict; neither mints", async () => {
    const a = await owner();
    const b = await owner();
    await expect(
      mintTerminalTicket(
        { userId: b.id, sessionId: b.session.id },
        { sandboxId: a.sandbox.id, ...SIZE },
      ),
    ).rejects.toMatchObject({ code: "NOT_FOUND", message: "Sandbox not found" });
    await db.inspect.sandbox.update({ where: { id: a.sandbox.id }, data: { state: "STOPPED" } });
    await expect(
      mintTerminalTicket(
        { userId: a.id, sessionId: a.session.id },
        { sandboxId: a.sandbox.id, ...SIZE },
      ),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    expect(
      await db.inspect.sandboxTerminalTicket.count({ where: { userId: { in: [a.id, b.id] } } }),
    ).toBe(0);
  });
});

describe("consume", () => {
  async function minted() {
    const o = await owner();
    const { ticket } = await mintTerminalTicket(
      { userId: o.id, sessionId: o.session.id },
      { sandboxId: o.sandbox.id, ...SIZE },
    );
    return { o, ticket };
  }

  it("returns the server-side binding once; a replay returns nothing", async () => {
    const { o, ticket } = await minted();
    expect(await consumeTerminalTicket(ticket)).toEqual({
      hostOwnerId: o.id,
      epoch: 1,
      userId: o.id,
      sessionId: o.session.id,
      sandboxId: o.sandbox.id,
      hostId: o.host.id,
      generation: 3,
      ...SIZE,
    });
    expect(await consumeTerminalTicket(ticket)).toBeNull();
    expect(await db.inspect.sandboxTerminalTicket.count({ where: { userId: o.id } })).toBe(0);
  });

  it("concurrent presentations: exactly one of 16 wins", async () => {
    const { ticket } = await minted();
    const results = await Promise.all(
      Array.from({ length: 16 }, () => consumeTerminalTicket(ticket)),
    );
    expect(results.filter((result) => result !== null)).toHaveLength(1);
  });

  it("two consumes blocked on the same row lock: exactly one receives the row", async () => {
    const { o, ticket } = await minted();
    const row = await db.inspect.sandboxTerminalTicket.findFirstOrThrow({
      where: { userId: o.id },
    });
    let releaseLock!: () => void;
    const held = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });
    let locked!: () => void;
    const lockTaken = new Promise<void>((resolve) => {
      locked = resolve;
    });
    // A third party holds the row lock; both consumes queue behind it.
    const holder = db.inspect.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM "sandbox_browser_terminal_ticket" WHERE id = ${row.id} FOR UPDATE`;
      locked();
      await held;
    });
    await lockTaken;
    const first = consumeTerminalTicket(ticket);
    const second = consumeTerminalTicket(ticket);
    const deadline = Date.now() + 10_000;
    for (;;) {
      const waiting = await db.inspect.$queryRaw<{ n: bigint }[]>`
        SELECT count(*) AS n FROM pg_stat_activity
        WHERE wait_event_type = 'Lock' AND query LIKE '%"sandbox_browser_terminal_ticket"%RETURNING%'`;
      if (Number(waiting[0]?.n ?? 0) >= 2) break;
      if (Date.now() > deadline) throw new Error("both consumes never blocked on the row lock");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    releaseLock();
    await holder;
    const results = await Promise.all([first, second]);
    expect(results.filter((result) => result !== null)).toHaveLength(1);
  });

  it("an expired ticket is refused and burned", async () => {
    const { o, ticket } = await minted();
    expect(await consumeTerminalTicket(ticket, new Date(Date.now() + 31_000))).toBeNull();
    expect(await db.inspect.sandboxTerminalTicket.count({ where: { userId: o.id } })).toBe(0);
    expect(await consumeTerminalTicket(ticket)).toBeNull();
  });

  it("malformed and unknown tickets never reach a row", async () => {
    const { o } = await minted();
    expect(await consumeTerminalTicket("short")).toBeNull();
    expect(await consumeTerminalTicket("A".repeat(43))).toBeNull();
    expect(await db.inspect.sandboxTerminalTicket.count({ where: { userId: o.id } })).toBe(1);
  });

  it("logout (session row delete) cascades outstanding tickets away", async () => {
    const { o, ticket } = await minted();
    await db.inspect.session.delete({ where: { id: o.session.id } });
    expect(await consumeTerminalTicket(ticket)).toBeNull();
  });
});

describe("checkTerminalBinding (the re-read behind upgrade, heartbeat and notifications)", () => {
  const binding = (o: Awaited<ReturnType<typeof owner>>) => ({
    userId: o.id,
    sessionId: o.session.id,
    sandboxId: o.sandbox.id,
    hostId: o.host.id,
    generation: 3,
  });

  it("an active binding passes", async () => {
    const o = await owner();
    expect(await checkTerminalBinding(binding(o))).toMatchObject({ ok: true });
  });

  it("E1-A-06: the grant carries the revision's default cwd, and none without one", async () => {
    const o = await owner();
    const checked = await checkTerminalBinding(binding(o));
    expect(checked.ok && checked.grant && "defaultCwd" in checked.grant).toBe(false);
    await db.inspect.sandboxTemplateRevision.update({
      where: { id: o.sandbox.templateRevisionId },
      data: { defaultCwd: "/srv/app" },
    });
    expect(await checkTerminalBinding(binding(o))).toMatchObject({
      ok: true,
      grant: { defaultCwd: "/srv/app" },
    });
  });

  it.each([
    [
      "session deleted (logout)",
      async (o: Awaited<ReturnType<typeof owner>>) => {
        await db.inspect.session.delete({ where: { id: o.session.id } });
      },
    ],
    [
      "session expired",
      async (o: Awaited<ReturnType<typeof owner>>) => {
        await db.inspect.session.update({
          where: { id: o.session.id },
          data: { expiresAt: new Date(Date.now() - 1000) },
        });
      },
    ],
    [
      "admin impersonation session",
      async (o: Awaited<ReturnType<typeof owner>>) => {
        await db.inspect.session.update({
          where: { id: o.session.id },
          data: { impersonatedBy: "some-admin" },
        });
      },
    ],
    [
      "user banned",
      async (o: Awaited<ReturnType<typeof owner>>) => {
        await db.inspect.user.update({ where: { id: o.id }, data: { banned: true } });
      },
    ],
    [
      "account deletion requested",
      async (o: Awaited<ReturnType<typeof owner>>) => {
        await db.inspect.user.update({
          where: { id: o.id },
          data: { deletionRequestedAt: new Date() },
        });
      },
    ],
  ])("%s → revoked", async (_label, mutate) => {
    const o = await owner();
    await mutate(o);
    expect(await checkTerminalBinding(binding(o))).toEqual({ ok: false, intent: "revoked" });
  });

  it("2FA disabled past the grace under forced 2FA → revoked; within policy → ok", async () => {
    const o = await owner({ twoFactorEnabled: false, createdAt: new Date("2020-01-01") });
    expect(await checkTerminalBinding(binding(o))).toMatchObject({ ok: true });
    await db.inspect.appSetting.upsert({
      where: { key: "force2faPublicUsers" },
      create: { key: "force2faPublicUsers", value: "true" },
      update: { value: "true" },
    });
    invalidateForceTwoFactorSettingsCache();
    try {
      expect(await checkTerminalBinding(binding(o))).toEqual({ ok: false, intent: "revoked" });
    } finally {
      await db.inspect.appSetting.delete({ where: { key: "force2faPublicUsers" } });
      invalidateForceTwoFactorSettingsCache();
    }
  });

  it.each([
    ["STOPPING", "sandbox_stopped"],
    ["STOPPED", "sandbox_stopped"],
    ["DELETED", "sandbox_destroyed"],
    ["RECLAIMING", "sandbox_destroyed"],
    ["UNREACHABLE", "lifecycle_unconfirmed"],
    ["ERROR", "lifecycle_unconfirmed"],
  ] as const)("sandbox %s → %s", async (state, intent) => {
    const o = await owner();
    await db.inspect.sandbox.update({ where: { id: o.sandbox.id }, data: { state } });
    expect(await checkTerminalBinding(binding(o))).toEqual({ ok: false, intent });
  });

  it("an OFFLOADED sandbox (disk only in the image store) → sandbox_stopped (offload C7)", async () => {
    const o = await owner();
    const { offloadSandboxForTest } = await import("./testing/offload-fixtures");
    await offloadSandboxForTest(db.inspect, {
      userId: o.id,
      sandboxId: o.sandbox.id,
      hostId: o.host.id,
    });
    expect(await checkTerminalBinding(binding(o))).toEqual({
      ok: false,
      intent: "sandbox_stopped",
    });
    await expect(
      mintTerminalTicket(
        { userId: o.id, sessionId: o.session.id },
        { sandboxId: o.sandbox.id, ...SIZE },
      ),
    ).rejects.toMatchObject({ data: { code: "sandbox.state_conflict" } });
  });

  it("a new generation, another host or an expired lease supersedes the binding", async () => {
    const o = await owner();
    await db.inspect.sandbox.update({ where: { id: o.sandbox.id }, data: { generation: 4 } });
    expect(await checkTerminalBinding(binding(o))).toEqual({ ok: false, intent: "superseded" });
    expect(await checkTerminalBinding({ ...binding(o), generation: 4, hostId: "other" })).toEqual({
      ok: false,
      intent: "superseded",
    });
    await db.inspect.sandbox.update({
      where: { id: o.sandbox.id },
      data: { leaseExpiresAt: new Date(Date.now() - 1000) },
    });
    expect(await checkTerminalBinding({ ...binding(o), generation: 4 })).toEqual({
      ok: false,
      intent: "expired",
    });
  });

  it("another owner's sandbox reads as destroyed (no existence oracle)", async () => {
    const a = await owner();
    const b = await owner();
    expect(await checkTerminalBinding({ ...binding(b), sandboxId: a.sandbox.id })).toEqual({
      ok: false,
      intent: "sandbox_destroyed",
    });
  });
});

it("guest tickets pin the transport owner and connection epoch", async () => {
  const o = await owner();
  const { ticket } = await mintTerminalTicket(
    { userId: o.id, sessionId: o.session.id },
    { sandboxId: o.sandbox.id, ...SIZE },
  );
  const b = (await consumeTerminalTicket(ticket))!;
  await db.inspect.sandboxHost.update({ where: { id: o.host.id }, data: { connectionEpoch: 2 } });
  // WP8: only the host's connection moved on (a reconnect, or a restarted
  // server's boot sweep): a host disconnect, never a supersession.
  expect(await checkTerminalBinding(b)).toEqual({ ok: false, intent: "host_disconnected" });
  // Another transport owner still supersedes, whatever the epoch.
  expect(await checkTerminalBinding({ ...b, hostOwnerId: "someone-else" })).toEqual({
    ok: false,
    intent: "superseded",
  });
  expect(await checkTerminalBinding({ ...b, epoch: 2, hostOwnerId: "someone-else" })).toEqual({
    ok: false,
    intent: "superseded",
  });
  expect(await checkTerminalBinding({ ...b, epoch: 2 })).toMatchObject({ ok: true });
});
