import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "./testing/resource-fixtures";

/**
 * WP8 (D10) resume gate against real PostgreSQL: a `SandboxTerminalSession`
 * row resumes only for the same owner, auth session, sandbox, host and
 * current generation, while open and inside the lifetime measured from the
 * stored `openedAt` (never reset). Revoking the auth session cascades the row
 * away; the composite FKs refuse a row naming another owner's session or
 * sandbox; the sweep is bounded.
 */

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "wp8-pg-fixture",
  },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const db = await pgTestDatabase();
const { checkTerminalBinding, consumeTerminalTicket, mintTerminalTicket } = await import(
  "./terminal-tickets"
);
const {
  TERMINAL_SESSION_CLOSED_RETENTION_MS,
  closeTerminalSession,
  recordTerminalSessionOpened,
  sweepTerminalSessions,
  terminalResumeTargetOk,
} = await import("./terminal-sessions");
const { BROWSER_TERMINAL_MAX_LIFETIME_MS } = await import("@wssp/config/browser-terminal");
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
const terminalId = () => `t${randomUUID().replaceAll("-", "")}`;

async function opened(o: Awaited<ReturnType<typeof owner>>, at = new Date()) {
  const identity = {
    terminalId: terminalId(),
    userId: o.id,
    sessionId: o.session.id,
    sandboxId: o.sandbox.id,
    hostId: o.host.id,
    generation: 3,
  };
  await recordTerminalSessionOpened(identity, at);
  return identity;
}

function resumeInput(o: Awaited<ReturnType<typeof owner>>, id: string, nextOutputSeq = 0) {
  return {
    sandboxId: o.sandbox.id,
    ...SIZE,
    version: 2 as const,
    resume: { terminalId: id, nextOutputSeq },
  };
}

function binding(o: Awaited<ReturnType<typeof owner>>, id: string) {
  return {
    userId: o.id,
    sessionId: o.session.id,
    sandboxId: o.sandbox.id,
    hostId: o.host.id,
    generation: 3,
    resume: { terminalId: id, nextOutputSeq: 0 },
  };
}

const unavailable = { data: { code: "sandbox.terminal_resume_unavailable" } };

describe("the resume gate", () => {
  it("mints a resume ticket that carries the target, and consume hands it back once", async () => {
    const o = await owner();
    const target = await opened(o);
    const { ticket } = await mintTerminalTicket(
      { userId: o.id, sessionId: o.session.id },
      resumeInput(o, target.terminalId, 41),
    );
    const row = await db.inspect.sandboxTerminalTicket.findFirstOrThrow({
      where: { userId: o.id },
    });
    expect(row).toMatchObject({ resumeTerminalId: target.terminalId, resumeOutputSeq: 41 });
    expect(await consumeTerminalTicket(ticket)).toMatchObject({
      sessionId: o.session.id,
      resume: { terminalId: target.terminalId, nextOutputSeq: 41 },
    });
    expect(await consumeTerminalTicket(ticket)).toBeNull();
    expect(await checkTerminalBinding(binding(o, target.terminalId))).toMatchObject({ ok: true });
  });

  it("wrong owner, auth session, sandbox, host or generation is refused with one answer", async () => {
    const o = await owner();
    const other = await owner();
    const target = await opened(o);
    expect(await terminalResumeTargetOk(target)).toBe(true);
    for (const change of [
      { userId: other.id },
      { sessionId: other.session.id },
      { sandboxId: other.sandbox.id },
      { hostId: other.host.id },
      { generation: 4 },
      { terminalId: terminalId() },
    ])
      expect(await terminalResumeTargetOk({ ...target, ...change }), JSON.stringify(change)).toBe(
        false,
      );
    // Another owner cannot mint against it (their own sandbox, their session).
    await expect(
      mintTerminalTicket(
        { userId: other.id, sessionId: other.session.id },
        resumeInput(other, target.terminalId),
      ),
    ).rejects.toMatchObject(unavailable);
    // A second auth session of the same owner is refused too.
    const second = await db.inspect.session.create({
      data: { userId: o.id, token: `tok2-${o.id}`, expiresAt: new Date(Date.now() + 3_600_000) },
    });
    await expect(
      mintTerminalTicket({ userId: o.id, sessionId: second.id }, resumeInput(o, target.terminalId)),
    ).rejects.toMatchObject(unavailable);
    // A new generation of the same sandbox supersedes the terminal.
    await db.inspect.sandbox.update({ where: { id: o.sandbox.id }, data: { generation: 4 } });
    await expect(
      mintTerminalTicket(
        { userId: o.id, sessionId: o.session.id },
        resumeInput(o, target.terminalId),
      ),
    ).rejects.toMatchObject(unavailable);
    expect(await db.inspect.sandboxTerminalTicket.count({ where: { userId: o.id } })).toBe(0);
  });

  it("a revoked (deleted) auth session cascades its rows away; an expired one is refused", async () => {
    const o = await owner();
    const target = await opened(o);
    await db.inspect.session.delete({ where: { id: o.session.id } });
    expect(
      await db.inspect.sandboxTerminalSession.count({ where: { id: target.terminalId } }),
    ).toBe(0);
    expect(await terminalResumeTargetOk(target)).toBe(false);
    const p = await owner();
    const expiring = await opened(p);
    await db.inspect.session.update({
      where: { id: p.session.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    expect(await checkTerminalBinding(binding(p, expiring.terminalId))).toEqual({
      ok: false,
      intent: "revoked",
    });
  });

  it("the lifetime runs from the stored openedAt and is never reset by reattaching", async () => {
    const o = await owner();
    const t0 = new Date(Date.now() - 60_000);
    const target = await opened(o, t0);
    // A second "open" of the same id (a retried write) keeps the original.
    await recordTerminalSessionOpened(target, new Date());
    const row = await db.inspect.sandboxTerminalSession.findUniqueOrThrow({
      where: { id: target.terminalId },
    });
    expect(row.openedAt.getTime()).toBe(t0.getTime());
    // Reattach after reattach: each passes, none moves openedAt.
    for (let i = 0; i < 3; i += 1) {
      const { ticket } = await mintTerminalTicket(
        { userId: o.id, sessionId: o.session.id },
        resumeInput(o, target.terminalId, i),
      );
      expect((await consumeTerminalTicket(ticket))?.resume?.terminalId).toBe(target.terminalId);
    }
    const after = await db.inspect.sandboxTerminalSession.findUniqueOrThrow({
      where: { id: target.terminalId },
    });
    expect(after.openedAt.getTime()).toBe(t0.getTime());
    const end = new Date(t0.getTime() + BROWSER_TERMINAL_MAX_LIFETIME_MS);
    expect(await terminalResumeTargetOk(target, new Date(end.getTime() - 1))).toBe(true);
    expect(await terminalResumeTargetOk(target, end)).toBe(false);
    expect(await checkTerminalBinding(binding(o, target.terminalId), end)).toEqual({
      ok: false,
      intent: "resume_unavailable",
    });
  });

  it("a closed row is refused at mint and on every re-read", async () => {
    const o = await owner();
    const target = await opened(o);
    await closeTerminalSession(target.terminalId);
    expect(await terminalResumeTargetOk(target)).toBe(false);
    await expect(
      mintTerminalTicket(
        { userId: o.id, sessionId: o.session.id },
        resumeInput(o, target.terminalId),
      ),
    ).rejects.toMatchObject(unavailable);
    expect(await checkTerminalBinding(binding(o, target.terminalId))).toEqual({
      ok: false,
      intent: "resume_unavailable",
    });
    // Closing is idempotent and never reopens.
    const closedAt = (
      await db.inspect.sandboxTerminalSession.findUniqueOrThrow({
        where: { id: target.terminalId },
      })
    ).closedAt;
    await closeTerminalSession(target.terminalId, new Date(Date.now() + 60_000));
    expect(
      (
        await db.inspect.sandboxTerminalSession.findUniqueOrThrow({
          where: { id: target.terminalId },
        })
      ).closedAt,
    ).toEqual(closedAt);
  });

  it("composite FKs refuse a row naming another owner's session or sandbox (P2003)", async () => {
    const o = await owner();
    const other = await owner();
    for (const change of [{ sessionId: other.session.id }, { sandboxId: other.sandbox.id }])
      await expect(
        db.inspect.sandboxTerminalSession.create({
          data: {
            id: terminalId(),
            userId: o.id,
            sessionId: o.session.id,
            sandboxId: o.sandbox.id,
            hostId: o.host.id,
            generation: 3,
            ...change,
          },
        }),
      ).rejects.toMatchObject({ code: "P2003" });
  });
});

describe("sandbox-terminal-session-sweep", () => {
  it("deletes closed rows past retention and open rows past the lifetime, in bounded batches", async () => {
    const o = await owner();
    const now = new Date();
    const old = new Date(now.getTime() - BROWSER_TERMINAL_MAX_LIFETIME_MS - 1000);
    const eligible: string[] = [];
    for (let i = 0; i < 3; i += 1) eligible.push((await opened(o, old)).terminalId);
    for (let i = 0; i < 2; i += 1) {
      const id = (await opened(o)).terminalId;
      await closeTerminalSession(
        id,
        new Date(now.getTime() - TERMINAL_SESSION_CLOSED_RETENTION_MS - 1000),
      );
      eligible.push(id);
    }
    const kept = [(await opened(o)).terminalId];
    const recentlyClosed = (await opened(o)).terminalId;
    await closeTerminalSession(recentlyClosed, now);
    kept.push(recentlyClosed);
    const remaining = () =>
      db.inspect.sandboxTerminalSession.count({ where: { id: { in: eligible } } });
    // One batch only: a zero budget stops after the first `take`.
    expect(await sweepTerminalSessions(now, { batch: 2, budgetMs: 0 })).toEqual({ deleted: 2 });
    expect(await remaining()).toBe(3);
    // An aborted sweep does nothing.
    const aborted = new AbortController();
    aborted.abort();
    expect(await sweepTerminalSessions(now, { batch: 2, signal: aborted.signal })).toEqual({
      deleted: 0,
    });
    const { deleted } = await sweepTerminalSessions(now, { batch: 2 });
    expect(deleted).toBeGreaterThanOrEqual(3);
    expect(await remaining()).toBe(0);
    expect(await db.inspect.sandboxTerminalSession.count({ where: { id: { in: kept } } })).toBe(2);
  });
});
