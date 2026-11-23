vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

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
vi.mock("../lib/procedure-budget", () => ({
  createProcedureBudget: (options: { keyPrefix: string; failClosed: boolean }) => {
    expect(options.failClosed).toBe(true);
    expect([
      "sandbox-terminal-session",
      "host-terminal-proof-day",
      "host-terminal-proof-minute",
    ]).toContain(options.keyPrefix);
    return async (key: string) => {
      budget.keys.push(key);
      if (budget.fail) throw budget.fail;
    };
  },
}));

const { default: db } = await import("@wssp/db");
const { sandboxTerminalsRouter } = await import("./sandbox-terminals");
const { ORPCError } = await import("@orpc/server");

const now = new Date("2026-10-01T00:00:00Z");

function client(session: Session | null) {
  const context: Context = { session, clientIp: undefined };
  return createRouterClient(sandboxTerminalsRouter, { context });
}

function session(userId = "owner-1"): Session {
  return {
    user: {
      id: userId,
      email: "owner@example.com",
      name: "Owner",
      emailVerified: true,
      role: "user",
      twoFactorEnabled: true,
      image: null,
      banned: false,
      banReason: null,
      banExpires: null,
      createdAt: now,
      updatedAt: now,
    },
    session: {
      id: "auth-session-1",
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

const input = { sandboxId: "sbx-1", rows: 24, cols: 80 };

describe("sandboxTerminals.createSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    budget.keys = [];
    budget.fail = undefined;
    db.appSetting.findMany.mockResolvedValue([]);
    db.session.findUnique.mockResolvedValue({ id: "auth-session-1" } as never);
    db.sandbox.findFirst.mockResolvedValue({
      id: "sbx-1",
      state: "READY",
      purpose: "WORKLOAD",
      generation: 2,
      sandboxHostId: "host-1",
      hostOwnerId: "owner-1",
      SandboxHost: { userId: "owner-1", connectionEpoch: 1, deletionRequestedAt: null },
      SandboxTemplateRevision: { defaultCwd: null },
    } as never);
    db.sandboxTerminalTicket.create.mockResolvedValue({ id: "t" } as never);
  });

  it("anonymous callers are UNAUTHORIZED and mint nothing", async () => {
    await expect(client(null).createSession(input)).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(db.sandboxTerminalTicket.create).not.toHaveBeenCalled();
    expect(budget.keys).toEqual([]);
  });

  it("a cookie-cached session whose durable row is gone (logged out) is UNAUTHORIZED", async () => {
    db.session.findUnique.mockResolvedValue(null);
    await expect(client(session()).createSession(input)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
    // protectedProcedure's durable session check refuses it first.
    expect(db.session.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.objectContaining({ id: "auth-session-1" }) }),
    );
    expect(db.sandboxTerminalTicket.create).not.toHaveBeenCalled();
  });

  it("charges the per-user budget, binds the ticket server-side and returns it only as a subprotocol", async () => {
    const result = await client(session()).createSession(input);
    expect(budget.keys).toEqual(["uid:owner-1"]);
    expect(result.path).toBe("/api/dashboard/sandboxes/sbx-1/terminal/ws");
    expect(result.protocols).toHaveLength(2);
    expect(result.protocols[0]).toBe("wssp.terminal.v1");
    const ticket = result.protocols[1]!.slice("wssp.terminal.ticket.".length);
    expect(ticket).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(result.path).not.toContain(ticket);
    const data = db.sandboxTerminalTicket.create.mock.calls[0]![0].data;
    expect(data).toMatchObject({
      userId: "owner-1",
      sessionId: "auth-session-1",
      sandboxId: "sbx-1",
      sandboxHostId: "host-1",
      generation: 2,
      rows: 24,
      cols: 80,
    });
    expect(JSON.stringify(data)).not.toContain(ticket);
    // The owner clause is part of the sandbox lookup itself.
    expect(db.sandbox.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { AND: [{ id: "sbx-1" }, { userId: "owner-1" }] },
      }),
    );
  });

  it("an exhausted budget refuses before any ticket", async () => {
    budget.fail = new ORPCError("TOO_MANY_REQUESTS");
    await expect(client(session()).createSession(input)).rejects.toMatchObject({
      code: "TOO_MANY_REQUESTS",
    });
    expect(db.sandboxTerminalTicket.create).not.toHaveBeenCalled();
  });

  it("refuses out-of-range sizes before any work", async () => {
    await expect(client(session()).createSession({ ...input, rows: 0 })).rejects.toMatchObject({
      code: "BAD_REQUEST",
    });
    await expect(client(session()).createSession({ ...input, cols: 1025 })).rejects.toMatchObject({
      code: "BAD_REQUEST",
    });
    expect(db.sandboxTerminalTicket.create).not.toHaveBeenCalled();
  });

  describe("WP8 reattach", () => {
    const terminalId = `t${"a".repeat(32)}`;
    const row = {
      userId: "owner-1",
      sessionId: "auth-session-1",
      sandboxId: "sbx-1",
      hostId: "host-1",
      generation: 2,
      openedAt: new Date(),
      closedAt: null,
    };

    it("version 2 offers wssp.terminal.v2; v1 stays the default", async () => {
      const result = await client(session()).createSession({ ...input, version: 2 });
      expect(result.protocols[0]).toBe("wssp.terminal.v2");
      expect(db.sandboxTerminalTicket.create.mock.calls[0]![0].data).not.toHaveProperty(
        "resumeTerminalId",
      );
    });

    it("a resume costs one budget point and binds the target to the ticket", async () => {
      db.sandboxTerminalSession.findUnique.mockResolvedValue(row as never);
      await client(session()).createSession({
        ...input,
        version: 2,
        resume: { terminalId, nextOutputSeq: 12 },
      });
      expect(budget.keys).toEqual(["uid:owner-1"]);
      expect(db.sandboxTerminalSession.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: terminalId } }),
      );
      expect(db.sandboxTerminalTicket.create.mock.calls[0]![0].data).toMatchObject({
        resumeTerminalId: terminalId,
        resumeOutputSeq: 12,
      });
    });

    it("an unresumable target is one CONFLICT and mints nothing (budget still charged)", async () => {
      db.sandboxTerminalSession.findUnique.mockResolvedValue({
        ...row,
        closedAt: new Date(),
      } as never);
      await expect(
        client(session()).createSession({
          ...input,
          version: 2,
          resume: { terminalId, nextOutputSeq: 0 },
        }),
      ).rejects.toMatchObject({
        code: "CONFLICT",
        data: { code: "sandbox.terminal_resume_unavailable" },
      });
      expect(budget.keys).toEqual(["uid:owner-1"]);
      expect(db.sandboxTerminalTicket.create).not.toHaveBeenCalled();
    });

    it("a resume without v2 or naming a malformed id is refused before any work", async () => {
      for (const extra of [
        { resume: { terminalId, nextOutputSeq: 0 } },
        { version: 2, resume: { terminalId: "host-term", nextOutputSeq: 0 } },
        { version: 2, resume: { terminalId, nextOutputSeq: -1 } },
        { version: 3 },
      ])
        await expect(
          client(session()).createSession({ ...input, ...extra } as never),
        ).rejects.toMatchObject({ code: "BAD_REQUEST" });
      expect(budget.keys).toEqual([]);
      expect(db.sandboxTerminalTicket.create).not.toHaveBeenCalled();
    });
  });
});
