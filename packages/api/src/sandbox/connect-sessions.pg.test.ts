import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import {
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "./testing/resource-fixtures";

/**
 * wssp-ssh §10 against real PostgreSQL: the connect audit row is written with
 * the key's origin, completed once, read back owner-scoped through the
 * dashboard projection, deleted with its owner (FK cascade), and purged after
 * 90 days in bounded batches that never touch younger rows.
 */

vi.mock("@wssp/db", async () => {
  const { pgTestDatabase } = await import("@wssp/db/testing/pg");
  const { createConnectAuditPrismaClient } = await import("@wssp/db/client");
  const testDb = await pgTestDatabase();
  // The production audit factory (isolated pool, driver bounds) on this file's clone.
  const audit = createConnectAuditPrismaClient(testDb.url);
  return { default: testDb.prisma, connectAuditPrisma: () => audit };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "connect-sessions-pg",
  },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const db = await pgTestDatabase();
const { connectAuditPrisma } = await import("@wssp/db");
const { CONNECT_AUDIT_POOL } = await import("@wssp/db/client");
const {
  CONNECT_AUDIT_MAX_WAIT_MS,
  lastConnectByKey,
  listSandboxConnectSessions,
  recordConnectSessionClose,
  recordConnectSessionOpen,
} = await import("./connect-sessions");
const { purgeConnectSessions } = await import("./connect-session-retention");
const { sessionPrincipal } = await import("./contracts");
afterAll(async () => {
  await connectAuditPrisma().$disconnect();
  await db.close();
});

const FP = `sha256:${"e".repeat(64)}`;
const DAY = 86_400_000;
const connectionId = () => `c${randomUUID().replaceAll("-", "")}`;

async function user() {
  const id = `conn-${randomUUID()}`;
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  return id;
}

async function key(userId: string, origin: "DASHBOARD" | "CLI_LOGIN" = "DASHBOARD") {
  const row = await db.inspect.sdkKey.create({
    data: {
      userId,
      kind: "API",
      origin,
      name: `key-${randomUUID()}`,
      resourceMode: "ALL_OWNED",
      poolMode: "ALL_USABLE",
      scopes: ["sandboxes:connect"],
      lookupPrefix: `lp-${randomUUID()}`,
      secretDigest: `sd-${randomUUID()}`,
    },
    select: { id: true, name: true },
  });
  return row;
}

async function sandboxOf(userId: string) {
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId,
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
      userId,
      sandboxHostId: host.id,
      slug: "ubuntu",
      label: "Ubuntu",
      imageRef: "local:ubuntu",
      incusFingerprint: FP,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      originHostId: host.id,
      templateId: template.id,
      originPoolId: null,
      state: "READY",
      generation: 1,
      liveResourcesHeld: true,
    },
  });
  return { hostId: host.id, sandboxId: sandbox.id };
}

describe("SandboxConnectSession writes and reads", () => {
  it("records the key's origin, completes once and reads back owner-scoped", async () => {
    const ownerId = await user();
    const cli = await key(ownerId, "CLI_LOGIN");
    const { hostId, sandboxId } = await sandboxOf(ownerId);
    const first = connectionId();
    const second = connectionId();
    // The relay's own instants, not the write's (a delayed write keeps them).
    const openedAt = new Date(Date.now() - 60_000);
    const closedAt = new Date(Date.now() - 30_000);
    await expect(
      recordConnectSessionOpen({ id: first, ownerId, sandboxId, hostId, keyId: cli.id, openedAt }),
    ).resolves.toBe(true);
    await expect(
      recordConnectSessionOpen({
        id: second,
        ownerId,
        sandboxId,
        hostId,
        keyId: cli.id,
        openedAt: new Date(),
      }),
    ).resolves.toBe(true);
    // A key of another owner never records (the origin read is owner scoped).
    const stranger = await user();
    await expect(
      recordConnectSessionOpen({
        id: connectionId(),
        ownerId: stranger,
        sandboxId,
        hostId,
        keyId: cli.id,
        openedAt,
      }),
    ).resolves.toBe(false);
    const close = {
      id: first,
      ownerId,
      closedAt,
      closeIntent: "client",
      ptyChannels: 1,
      execChannels: 3,
      bytesIn: 4096,
      bytesOut: 2 ** 40,
    };
    await expect(recordConnectSessionClose(close)).resolves.toBe(true);
    // Closed rows are never rewritten; another owner's close matches nothing.
    await expect(recordConnectSessionClose({ ...close, closeIntent: "revoked" })).resolves.toBe(
      false,
    );
    await expect(
      recordConnectSessionClose({ ...close, id: second, ownerId: stranger }),
    ).resolves.toBe(false);

    const page = await listSandboxConnectSessions(sessionPrincipal(ownerId), {
      id: sandboxId,
      limit: 1,
    });
    expect(page.items).toHaveLength(1);
    expect(page.nextCursor).not.toBeNull();
    const rest = await listSandboxConnectSessions(sessionPrincipal(ownerId), {
      id: sandboxId,
      limit: 1,
      cursor: page.nextCursor ?? undefined,
    });
    const rows = [...page.items, ...rest.items];
    expect(rows.map((row) => row.id).sort()).toEqual([first, second].sort());
    const closed = rows.find((row) => row.id === first)!;
    expect(closed).toEqual({
      id: first,
      keyId: cli.id,
      keyName: cli.name,
      hostId,
      origin: "CLI_LOGIN",
      openedAt,
      closedAt,
      status: "closed",
      closeIntent: "client",
      ptyChannels: 1,
      execChannels: 3,
      bytesIn: "4096",
      bytesOut: String(2 ** 40),
    });
    expect(rows.find((row) => row.id === second)?.status).toBe("open");
    // Another owner sees nothing of this sandbox.
    await expect(
      listSandboxConnectSessions(sessionPrincipal(stranger), { id: sandboxId }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });

    const last = await lastConnectByKey(ownerId, [cli.id, "unknown-key"]);
    expect([...last.keys()]).toEqual([cli.id]);
    expect(await lastConnectByKey(stranger, [cli.id])).toEqual(new Map());
  });

  it("a coalesced open writes the complete row; a blocked write is cancelled by its statement timeout", async () => {
    const ownerId = await user();
    const dashboard = await key(ownerId);
    const id = connectionId();
    const openedAt = new Date(Date.now() - 5_000);
    const closedAt = new Date(Date.now() - 4_000);
    await expect(
      recordConnectSessionOpen({
        id,
        ownerId,
        sandboxId: "sbx-gone",
        hostId: "host-gone",
        keyId: dashboard.id,
        openedAt,
        end: {
          closedAt,
          closeIntent: "shutdown",
          ptyChannels: 1,
          execChannels: 2,
          bytesIn: 3,
          bytesOut: 4,
        },
      }),
    ).resolves.toBe(true);
    expect(
      await db.inspect.sandboxConnectSession.findUniqueOrThrow({
        where: { id },
        select: { openedAt: true, closedAt: true, closeIntent: true, bytesOut: true },
      }),
    ).toEqual({ openedAt, closedAt, closeIntent: "shutdown", bytesOut: 4n });

    // A row lock held elsewhere: the close waits at most the audit pool's
    // session statement timeout (a startup setting, not SET LOCAL), then
    // fails instead of holding a connection.
    const [setting] = await connectAuditPrisma().$queryRaw<
      { statement_timeout: string }[]
    >`SHOW statement_timeout`;
    expect(setting?.statement_timeout).toBe("2s");
    const open = connectionId();
    await recordConnectSessionOpen({
      id: open,
      ownerId,
      sandboxId: "sbx-gone",
      hostId: "host-gone",
      keyId: dashboard.id,
      openedAt,
    });
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let locked!: () => void;
    const isLocked = new Promise<void>((resolve) => {
      locked = resolve;
    });
    const holder = db.inspect.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_connect_session WHERE id = ${open} FOR UPDATE`;
        locked();
        await held;
      },
      { timeout: 20_000 },
    );
    await isLocked;
    const started = Date.now();
    const error = await recordConnectSessionClose({
      id: open,
      ownerId,
      closedAt,
      closeIntent: "client",
      ptyChannels: 0,
      execChannels: 0,
      bytesIn: 0,
      bytesOut: 0,
    }).then(
      () => undefined,
      (caught: unknown) => caught,
    );
    const elapsed = Date.now() - started;
    expect(String(error)).toMatch(/statement timeout/i);
    expect(elapsed).toBeGreaterThanOrEqual(CONNECT_AUDIT_POOL.driver.statementTimeoutMs - 100);
    expect(elapsed).toBeLessThan(CONNECT_AUDIT_POOL.driver.statementTimeoutMs + 1_000);
    release();
    await holder;
  }, 30_000);

  it("a saturated audit pool fails the next write within its connection timeout; the shared client still answers", async () => {
    const ownerId = await user();
    const dashboard = await key(ownerId);
    const id = connectionId();
    await recordConnectSessionOpen({
      id,
      ownerId,
      sandboxId: "sbx-gone",
      hostId: "host-gone",
      keyId: dashboard.id,
      openedAt: new Date(),
    });
    // Hold both audit connections inside idle transactions (no statement
    // runs, so the statement timeout never frees them), the way a stalled
    // database would.
    const audit = connectAuditPrisma();
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started: Promise<void>[] = [];
    const holders = Array.from({ length: CONNECT_AUDIT_POOL.max }, () => {
      let begun!: () => void;
      started.push(
        new Promise<void>((resolve) => {
          begun = resolve;
        }),
      );
      return audit.$transaction(
        async (tx) => {
          await tx.$queryRaw`SELECT 1`;
          begun();
          await held;
        },
        { timeout: 20_000, maxWait: 5_000 },
      );
    });
    await Promise.all(started);
    try {
      const close = {
        id,
        ownerId,
        closedAt: new Date(),
        closeIntent: "client",
        ptyChannels: 0,
        execChannels: 0,
        bytesIn: 0,
        bytesOut: 0,
      };
      const begin = Date.now();
      const third = recordConnectSessionClose(close).then(
        () => undefined,
        (caught: unknown) => caught,
      );
      // Meanwhile the shared pool is untouched and answers at once.
      const sharedBegin = Date.now();
      await expect(db.prisma.$queryRaw`SELECT 1 AS one`).resolves.toEqual([{ one: 1 }]);
      expect(Date.now() - sharedBegin).toBeLessThan(500);
      const error = await third;
      const elapsed = Date.now() - begin;
      // The driver's acquisition bound fails it (and drops the waiter), before
      // Prisma's own maxWait would.
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).toMatch(/timeout exceeded when trying to connect/i);
      expect(elapsed).toBeGreaterThanOrEqual(
        CONNECT_AUDIT_POOL.driver.connectionTimeoutMillis - 100,
      );
      expect(elapsed).toBeLessThan(CONNECT_AUDIT_MAX_WAIT_MS);
      expect(
        await db.inspect.sandboxConnectSession.findUniqueOrThrow({
          where: { id },
          select: { closedAt: true },
        }),
      ).toEqual({ closedAt: null });
    } finally {
      release();
      await Promise.all(holders);
    }
    // Once the connections are free the audit writes again.
    await expect(
      recordConnectSessionClose({
        id,
        ownerId,
        closedAt: new Date(),
        closeIntent: "client",
        ptyChannels: 0,
        execChannels: 0,
        bytesIn: 0,
        bytesOut: 0,
      }),
    ).resolves.toBe(true);
  }, 30_000);

  it("rows are deleted with their owner", async () => {
    const ownerId = await user();
    const dashboard = await key(ownerId);
    const id = connectionId();
    await recordConnectSessionOpen({
      id,
      ownerId,
      sandboxId: "sbx-gone",
      hostId: "host-gone",
      keyId: dashboard.id,
      openedAt: new Date(),
    });
    expect(await db.inspect.sandboxConnectSession.count({ where: { id } })).toBe(1);
    await db.inspect.user.delete({ where: { id: ownerId } });
    expect(await db.inspect.sandboxConnectSession.count({ where: { id } })).toBe(0);
  });

  it("the purge deletes only rows opened 90+ days ago, in bounded batches", async () => {
    const ownerId = await user();
    const dashboard = await key(ownerId);
    const now = new Date();
    const old = new Date(now.getTime() - 90 * DAY - 60_000);
    const young = new Date(now.getTime() - 89 * DAY);
    const base = { userId: ownerId, sandboxId: "s", hostId: "h", keyId: dashboard.id };
    const oldIds = Array.from({ length: 5 }, connectionId);
    const youngIds = Array.from({ length: 2 }, connectionId);
    await db.inspect.sandboxConnectSession.createMany({
      data: [
        ...oldIds.map((id) => ({ ...base, id, origin: "DASHBOARD" as const, openedAt: old })),
        ...youngIds.map((id) => ({ ...base, id, origin: "DASHBOARD" as const, openedAt: young })),
      ],
    });
    const remaining = () =>
      db.inspect.sandboxConnectSession.count({ where: { id: { in: oldIds } } });
    // One bounded batch per run when capped.
    expect(await purgeConnectSessions({ now, batch: 2, maxBatches: 1 })).toBeGreaterThanOrEqual(2);
    expect(await remaining()).toBeLessThanOrEqual(3);
    await purgeConnectSessions({ now, batch: 2 });
    expect(await remaining()).toBe(0);
    expect(await db.inspect.sandboxConnectSession.count({ where: { id: { in: youngIds } } })).toBe(
      2,
    );
  });
});
