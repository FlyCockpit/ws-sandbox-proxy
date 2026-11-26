import { createRouterClient } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Context } from "../context";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const budget = vi.hoisted(() => ({ keys: [] as string[], fail: undefined as unknown }));
vi.mock("../sandbox/terminal-budgets", () => ({
  consumeTerminalEndBudget: async (key: string) => {
    budget.keys.push(key);
    if (budget.fail) throw budget.fail;
  },
}));

const { default: db } = await import("@wssp/db");
const { terminalsRouter } = await import("./terminals");
const { registerLiveTerminalDirectory } = await import("../sandbox/live-terminals");

const now = new Date("2026-11-26T00:00:00Z");
const ID_A = `bt_${"a".repeat(32)}`;
const ID_B = `bt_${"b".repeat(32)}`;

function client(session: Session | null) {
  const context: Context = { session, clientIp: undefined };
  return createRouterClient(terminalsRouter, { context });
}

function session(userId: string, role = "user"): Session {
  return {
    user: {
      id: userId,
      email: `${userId}@example.com`,
      name: userId,
      emailVerified: true,
      role,
      twoFactorEnabled: true,
      image: null,
      banned: false,
      banReason: null,
      banExpires: null,
      createdAt: now,
      updatedAt: now,
    },
    session: {
      id: `auth-${userId}`,
      userId,
      token: "token",
      expiresAt: new Date("2027-01-01"),
      ipAddress: null,
      userAgent: null,
      createdAt: now,
      updatedAt: now,
    },
  } as Session;
}

const entry = (id: string, userId: string) => ({
  id,
  userId,
  target: { kind: "sandbox" as const, sandboxId: `sbx-${userId}` },
  sessionId: `auth-${userId}`,
  status: "attached" as const,
  openedAt: now,
  lastActivityAt: now,
});
const live = [entry(ID_A, "owner-1"), entry(ID_B, "owner-2")];
const ends: string[] = [];

describe("terminals router", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    ends.length = 0;
    budget.keys = [];
    budget.fail = undefined;
    db.appSetting.findMany.mockResolvedValue([]);
    db.session.findUnique.mockResolvedValue({ id: "auth" } as never);
    db.session.findMany.mockResolvedValue([]);
    db.sandbox.findMany.mockResolvedValue([]);
    registerLiveTerminalDirectory({
      list: (userId) => live.filter((e) => e.userId === userId),
      end: async (userId, id) => {
        ends.push(`${userId}:${id}`);
        return live.some((e) => e.id === id && e.userId === userId);
      },
    });
  });

  it("anonymous callers are UNAUTHORIZED and see nothing", async () => {
    await expect(client(null).list()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    await expect(client(null).end({ id: ID_A })).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(ends).toEqual([]);
  });

  it("a signed-out (deleted) session row is UNAUTHORIZED", async () => {
    db.session.findUnique.mockResolvedValue(null);
    await expect(client(session("owner-1")).list()).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("lists only the caller's own terminals; another user's never appear", async () => {
    const { terminals } = await client(session("owner-1")).list();
    expect(terminals.map((t) => t.id)).toEqual([ID_A]);
    expect(terminals[0]!.thisBrowser).toBe(true);
  });

  it("an admin sees only their own terminals here", async () => {
    const { terminals } = await client(session("owner-2", "admin")).list();
    expect(terminals.map((t) => t.id)).toEqual([ID_B]);
  });

  it("ending another user's terminal is NOT_FOUND, like a closed one", async () => {
    await expect(client(session("owner-1")).end({ id: ID_B })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    expect(ends).toEqual([`owner-1:${ID_B}`]);
  });

  it("ends the caller's own terminal, charged to the caller's end budget", async () => {
    await expect(client(session("owner-1")).end({ id: ID_A })).resolves.toEqual({ ended: true });
    expect(budget.keys).toEqual(["uid:owner-1"]);
  });

  it("an exhausted (or unavailable) end budget ends nothing", async () => {
    const { ORPCError } = await import("@orpc/server");
    budget.fail = new ORPCError("TOO_MANY_REQUESTS");
    await expect(client(session("owner-1")).end({ id: ID_A })).rejects.toMatchObject({
      code: "TOO_MANY_REQUESTS",
    });
    expect(ends).toEqual([]);
  });

  it("hostTargets is owner-scoped and needs a session", async () => {
    await expect(client(null).hostTargets()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    db.sandboxHost.findMany.mockResolvedValue([]);
    await expect(client(session("owner-2", "admin")).hostTargets()).resolves.toEqual({
      hosts: [],
      more: false,
    });
    expect(db.sandboxHost.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: "owner-2", deletionRequestedAt: null } }),
    );
  });

  it("refuses ids that are not listing ids", async () => {
    await expect(
      client(session("owner-1")).end({ id: `t${"a".repeat(32)}` }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(ends).toEqual([]);
  });
});
