import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import {
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

/**
 * C53-CC-1 / C53-CC-2 on the REAL revocation path: Better Auth's own
 * `/sign-out` and `/revoke-sessions` handlers (so the prisma adapter's real
 * `deleteMany({ where: { token | userId: { equals } } })` call shape reaches
 * the `packages/auth` hook), real PostgreSQL, the real session-revocation
 * signal, the real `BrowserTerminalService` and the real
 * `checkTerminalBinding`. Only the host terminal manager is a stub; its
 * `open`/`close` calls are the PTY observable.
 *
 * Ported from the C53 r1 correctness reviewer's probe P-CC-A / P-CC-B.
 */

const { BASE_URL } = vi.hoisted(() => ({ BASE_URL: "http://localhost:3000" }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: BASE_URL,
    BETTER_AUTH_SECRET: "c53-revocation-pg-test-secret-at-least-32-chars",
    NODE_ENV: "test",
  },
  ADMIN_EMAILS: new Set<string>(),
  SIGNUP_ENABLED: true,
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/mailer", () => ({
  isEmailConfigured: () => false,
  renderResetPassword: () => ({ subject: "", html: "" }),
  renderTwoFactorOtp: () => ({ subject: "", html: "" }),
  renderVerifyEmail: () => ({ subject: "", html: "" }),
  sendEmail: vi.fn(async () => undefined),
}));

const db = await pgTestDatabase();
const { auth } = await import("@wssp/auth");
const { onAuthSessionsRevoked } = await import("@wssp/db/session-revocation");
const { checkBrowserTerminalBinding: checkTerminalBinding } = await import(
  "@wssp/api/sandbox/terminal-tickets"
);
const { bindHostTerminalPolicy } = await import("@wssp/api/sandbox/host-terminal-policy");
// This suite stubs host transport; real foreign credential proof is in lifecycle-conformance.pg.test.ts.
bindHostTerminalPolicy({
  read: () => undefined,
  raise: async () => false,
  authorize: async () => true,
});
afterAll(() => bindHostTerminalPolicy(null));
const { BrowserTerminalService } = await import("./browser-terminal.js");
afterAll(() => db.close());

const PASSWORD = "correct-horse-battery-staple";
const FINGERPRINT = `sha256:${"d".repeat(64)}`;

function cookiesFrom(response: Response): string {
  const jar = new Map<string, string>();
  for (const header of response.headers.getSetCookie()) {
    const [pair = ""] = header.split(";");
    const index = pair.indexOf("=");
    const value = pair.slice(index + 1);
    if (value !== "") jar.set(pair.slice(0, index), value);
  }
  return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}

function post(path: string, body: unknown, cookie = ""): Promise<Response> {
  return auth.handler(
    new Request(`${BASE_URL}/api/auth${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: BASE_URL,
        ...(cookie ? { cookie } : {}),
      },
      body: JSON.stringify(body),
    }),
  );
}

async function signUp() {
  const email = `${randomUUID()}@example.test`;
  const response = await post("/sign-up/email", { email, password: PASSWORD, name: "Ada" });
  expect(response.status, await response.clone().text()).toBe(200);
  // Enrolled, so the protected (forced-2FA) policy passes on every re-read.
  const user = await db.inspect.user.update({
    where: { email },
    data: { emailVerified: true, twoFactorEnabled: true },
  });
  return { email, userId: user.id };
}

async function signIn(email: string) {
  // Password-only sign-in (no 2FA challenge), then back to enrolled.
  await db.inspect.user.update({ where: { email }, data: { twoFactorEnabled: false } });
  const response = await post("/sign-in/email", { email, password: PASSWORD });
  await db.inspect.user.update({ where: { email }, data: { twoFactorEnabled: true } });
  expect(response.status, await response.clone().text()).toBe(200);
  const cookie = cookiesFrom(response);
  const signed = decodeURIComponent(cookie.split("session_token=")[1]!.split(";")[0]!);
  const session = await db.inspect.session.findFirstOrThrow({
    where: { token: signed.split(".")[0]! },
  });
  return { cookie, sessionId: session.id };
}

async function readySandbox(userId: string) {
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
      incusFingerprint: FINGERPRINT,
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
      generation: 3,
      liveResourcesHeld: true,
    },
  });
  return { hostId: host.id, sandboxId: sandbox.id };
}

class FakeBrowser {
  readyState = 1;
  bufferedAmount = 0;
  text: Record<string, unknown>[] = [];
  closes: { code: number; reason: string }[] = [];
  send(data: string | Uint8Array) {
    if (typeof data === "string") this.text.push(JSON.parse(data));
  }
  close(code: number, reason: string) {
    this.closes.push({ code, reason });
    this.readyState = 3;
  }
}

/** Stub host manager: an open becomes ready at once; a close notifies the attachment. */
function stubManager() {
  const opens: string[] = [];
  const closes: string[] = [];
  const manager = {
    open(input: {
      sandboxId: string;
      attachment: { ready(size: unknown): void; close(notice: unknown): void };
    }) {
      opens.push(input.sandboxId);
      queueMicrotask(() => input.attachment.ready({ rows: 24, cols: 80 }));
      return {
        ok: true,
        session: {
          sessionId: randomUUID(),
          input: () => ({ ok: true }),
          resize: () => ({ ok: true }),
          close(intent?: string) {
            closes.push(`${input.sandboxId}:${intent}`);
            input.attachment.close({ code: 4401, intent });
          },
        },
      };
    },
    closeSandbox(sandboxId: string, intent: string) {
      closes.push(`closeSandbox:${sandboxId}:${intent}`);
      return 0;
    },
  };
  return { manager, opens, closes };
}

async function until(condition: () => boolean, ms = 3000) {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > ms) throw new Error("timed out");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

const settle = (ms = 150) => new Promise((resolve) => setTimeout(resolve, ms));

/** A service whose heartbeat is far away: every re-read below is notification-driven. */
function terminalService() {
  const checks: string[] = [];
  const stub = stubManager();
  const service = new BrowserTerminalService(
    () => stub.manager as never,
    async (binding, now) => {
      checks.push(binding.userId);
      return checkTerminalBinding(binding, now);
    },
    600_000,
  );
  return { service, checks, ...stub };
}

async function attachedTerminal(
  service: InstanceType<typeof BrowserTerminalService>,
  owner: { userId: string },
  session: { sessionId: string },
) {
  const sandbox = await readySandbox(owner.userId);
  const browser = new FakeBrowser();
  service
    .attach({
      userId: owner.userId,
      sessionId: session.sessionId,
      ...sandbox,
      generation: 3,
      rows: 24,
      cols: 80,
    })
    .opened(browser);
  await until(() => browser.text.some((frame) => frame.type === "ready"));
  return browser;
}

const count = (checks: string[], userId: string) => checks.filter((id) => id === userId).length;

describe("real Better Auth session deletes → browser terminal (C53-CC-1 / C53-CC-2)", () => {
  it("sign-out: notifies ONLY the signing-out user; their terminal closes {4401, revoked}; the other user's is not even re-read", async () => {
    const owner = await signUp();
    const ownerSession = await signIn(owner.email);
    const other = await signUp();
    const otherSession = await signIn(other.email);
    const payloads: unknown[] = [];
    const off = onAuthSessionsRevoked((payload) => payloads.push(payload));
    const { service, checks, opens } = terminalService();
    try {
      const ownerBrowser = await attachedTerminal(service, owner, ownerSession);
      const otherBrowser = await attachedTerminal(service, other, otherSession);
      expect(opens).toHaveLength(2);
      const otherChecks = count(checks, other.userId);

      const response = await post("/sign-out", {}, ownerSession.cookie);
      expect(response.status, await response.clone().text()).toBe(200);
      expect(await db.inspect.session.count({ where: { id: ownerSession.sessionId } })).toBe(0);
      await until(() => ownerBrowser.closes.length > 0);
      expect(ownerBrowser.closes).toEqual([{ code: 4401, reason: "revoked" }]);
      expect(ownerBrowser.text.filter((frame) => frame.type === "close")).toEqual([
        { type: "close", code: 4401, intent: "revoked" },
      ]);
      await settle();
      // The adapter's `{ token: { equals } }` delete is resolved to its owner.
      expect(payloads).toEqual([{ userId: owner.userId, sessionId: ownerSession.sessionId }]);
      expect(count(checks, other.userId)).toBe(otherChecks);
      expect(otherBrowser.closes).toEqual([]);
      expect(service.count()).toBe(1);
    } finally {
      off();
      service.dispose();
    }
  });

  it("revoke-sessions (`{ userId: { equals } }`): notifies only that user and closes only their terminals", async () => {
    const owner = await signUp();
    const ownerSession = await signIn(owner.email);
    await signIn(owner.email);
    const other = await signUp();
    const otherSession = await signIn(other.email);
    const payloads: unknown[] = [];
    const off = onAuthSessionsRevoked((payload) => payloads.push(payload));
    const { service, checks } = terminalService();
    try {
      const ownerBrowser = await attachedTerminal(service, owner, ownerSession);
      const otherBrowser = await attachedTerminal(service, other, otherSession);
      const otherChecks = count(checks, other.userId);
      const response = await post("/revoke-sessions", {}, ownerSession.cookie);
      expect(response.status, await response.clone().text()).toBe(200);
      expect(await db.inspect.session.count({ where: { userId: owner.userId } })).toBe(0);
      await until(() => ownerBrowser.closes.length > 0);
      expect(ownerBrowser.closes).toEqual([{ code: 4401, reason: "revoked" }]);
      await settle();
      expect(payloads.length).toBeGreaterThan(0);
      expect(
        payloads.every(
          (payload) => JSON.stringify(payload) === JSON.stringify({ userId: owner.userId }),
        ),
      ).toBe(true);
      expect(count(checks, other.userId)).toBe(otherChecks);
      expect(otherBrowser.closes).toEqual([]);
    } finally {
      off();
      service.dispose();
    }
  });

  it("unscoped notifications (the genuinely-unknown fallback) racing real re-reads never close a live terminal", async () => {
    const victim = await signUp();
    const victimSession = await signIn(victim.email);
    const { service, checks } = terminalService();
    const { notifyAuthSessionsRevoked } = await import("@wssp/db/session-revocation");
    try {
      const victimBrowser = await attachedTerminal(service, victim, victimSession);
      const before = count(checks, victim.userId);
      // A sustained burst for 200 ms: one notification per event-loop turn,
      // so (real re-reads taking milliseconds) every read is raced by one.
      const end = Date.now() + 200;
      while (Date.now() < end) {
        notifyAuthSessionsRevoked({});
        await new Promise((resolve) => setImmediate(resolve));
      }
      await settle(300);
      // The burst re-read the terminal many times (coalesced) and never ended it.
      expect(victimBrowser.closes).toEqual([]);
      expect(count(checks, victim.userId) - before).toBeGreaterThan(3);
      expect(service.count()).toBe(1);
    } finally {
      service.dispose();
    }
  });

  for (const run of [1, 2, 3])
    it(`a burst of another user's sign-outs never closes (or re-reads) the victim's live terminal, and the victim's own logout still closes {4401, revoked} (run ${run})`, async () => {
      const victim = await signUp();
      const victimSession = await signIn(victim.email);
      const attacker = await signUp();
      const attackerSessions = [];
      for (let i = 0; i < 12; i += 1) attackerSessions.push(await signIn(attacker.email));
      const { service, checks } = terminalService();
      try {
        const victimBrowser = await attachedTerminal(service, victim, victimSession);
        const victimChecks = count(checks, victim.userId);
        const signOuts: Promise<Response>[] = [];
        for (const session of attackerSessions) {
          signOuts.push(post("/sign-out", {}, session.cookie));
          await new Promise((resolve) => setTimeout(resolve, 1));
        }
        for (const response of await Promise.all(signOuts)) expect(response.status).toBe(200);
        expect(await db.inspect.session.count({ where: { userId: attacker.userId } })).toBe(0);
        await settle(300);
        expect(victimBrowser.closes).toEqual([]);
        expect(victimBrowser.text.filter((frame) => frame.type === "close")).toEqual([]);
        expect(count(checks, victim.userId)).toBe(victimChecks);
        expect(service.count()).toBe(1);

        // Inverse: the victim's own logout still closes at once.
        const started = Date.now();
        const response = await post("/sign-out", {}, victimSession.cookie);
        expect(response.status).toBe(200);
        await until(() => victimBrowser.closes.length > 0);
        expect(Date.now() - started).toBeLessThan(3000);
        expect(victimBrowser.closes).toEqual([{ code: 4401, reason: "revoked" }]);
        expect(victimBrowser.text.filter((frame) => frame.type === "close")).toEqual([
          { type: "close", code: 4401, intent: "revoked" },
        ]);
      } finally {
        service.dispose();
      }
    });
});

describe("PTY open waits for a clean session read (C53-CC-1 inverse)", () => {
  it("the owner's real sign-out committing DURING the first read: no PTY ever, closes {4401, revoked}", async () => {
    const owner = await signUp();
    const ownerSession = await signIn(owner.email);
    const stub = stubManager();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let calls = 0;
    let readStarted!: () => void;
    const started = new Promise<void>((resolve) => (readStarted = resolve));
    const service = new BrowserTerminalService(
      () => stub.manager as never,
      async (binding, now) => {
        calls += 1;
        const verdict = await checkTerminalBinding(binding, now);
        if (calls === 1) {
          readStarted();
          await gate; // the first read saw a live session; hold its verdict
        }
        return verdict;
      },
      600_000,
    );
    try {
      const sandbox = await readySandbox(owner.userId);
      const browser = new FakeBrowser();
      service
        .attach({
          userId: owner.userId,
          sessionId: ownerSession.sessionId,
          ...sandbox,
          generation: 3,
          rows: 24,
          cols: 80,
        })
        .opened(browser);
      await started;
      const response = await post("/sign-out", {}, ownerSession.cookie);
      expect(response.status).toBe(200);
      await settle(50);
      release();
      await until(() => browser.closes.length > 0);
      expect(stub.opens).toEqual([]);
      expect(browser.text.filter((f) => f.type === "ready")).toEqual([]);
      expect(browser.closes).toEqual([{ code: 4401, reason: "revoked" }]);
      expect(calls).toBe(2);
    } finally {
      service.dispose();
    }
  });

  it("attaching during another user's sign-out burst: the victim PTY opens and is never re-read by it", async () => {
    const victim = await signUp();
    const victimSession = await signIn(victim.email);
    const attacker = await signUp();
    const attackerSessions = [];
    for (let i = 0; i < 12; i += 1) attackerSessions.push(await signIn(attacker.email));
    const { service, checks, opens } = terminalService();
    try {
      const signOuts: Promise<Response>[] = [];
      const sandbox = await readySandbox(victim.userId);
      const browser = new FakeBrowser();
      for (const [i, session] of attackerSessions.entries()) {
        signOuts.push(post("/sign-out", {}, session.cookie));
        if (i === 3)
          service
            .attach({
              userId: victim.userId,
              sessionId: victimSession.sessionId,
              ...sandbox,
              generation: 3,
              rows: 24,
              cols: 80,
            })
            .opened(browser);
        await new Promise((resolve) => setTimeout(resolve, 1));
      }
      for (const r of await Promise.all(signOuts)) expect(r.status).toBe(200);
      await until(() => browser.text.some((f) => f.type === "ready"));
      await settle(200);
      expect(opens).toHaveLength(1);
      expect(browser.closes).toEqual([]);
      expect(count(checks, victim.userId)).toBe(1);
    } finally {
      service.dispose();
    }
  });
});

it("T2 real session-targeted sign-out closes host and guest bindings while another session survives", async () => {
  const owner = await signUp();
  const first = await signIn(owner.email),
    second = await signIn(owner.email);
  const sandbox = await readySandbox(owner.userId);
  const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: sandbox.hostId } });
  bindHostTerminalPolicy({
    read: () => ({
      hostTerminal: true,
      requireHostTerminalTotp: false,
      policyRevision: 1,
      epoch: host.connectionEpoch,
    }),
    raise: async () => false,
    authorize: async () => true,
  });
  const { service } = terminalService();
  try {
    const guest = new FakeBrowser();
    service
      .attach({
        userId: owner.userId,
        sessionId: first.sessionId,
        ...sandbox,
        generation: 3,
        rows: 24,
        cols: 80,
      })
      .opened(guest);
    await until(() => guest.text.some((frame) => frame.type === "ready"));
    const hostBrowser = new FakeBrowser(),
      survivingHostBrowser = new FakeBrowser();
    const b = {
      kind: "host" as const,
      userId: owner.userId,
      sessionId: first.sessionId,
      hostId: host.id,
      hostOwnerId: owner.userId,
      epoch: host.connectionEpoch,
      rows: 24,
      cols: 80,
      policyRevision: 1,
      proofRequired: false,
      verifiedAt: null,
      factorFingerprint: null,
      observedAt: null,
    };
    service.attach(b).opened(hostBrowser);
    service.attach({ ...b, sessionId: second.sessionId }).opened(survivingHostBrowser);
    await until(
      () =>
        hostBrowser.text.some((f) => f.type === "ready") &&
        survivingHostBrowser.text.some((f) => f.type === "ready"),
    );
    expect((await post("/sign-out", {}, first.cookie)).status).toBe(200);
    await until(() => guest.closes.length === 1 && hostBrowser.closes.length === 1);
    expect(guest.closes[0]).toEqual({ code: 4401, reason: "revoked" });
    expect(hostBrowser.closes[0]).toEqual({ code: 4401, reason: "revoked" });
    expect(survivingHostBrowser.closes).toEqual([]);
  } finally {
    service.dispose();
    bindHostTerminalPolicy({
      read: () => undefined,
      raise: async () => false,
      authorize: async () => true,
    });
  }
});

it("WP8: sign-out cascades a resumable terminal's row away, closes its resumed attachment, and no later session can resume it", async () => {
  const { recordTerminalSessionOpened, terminalResumeTargetOk } = await import(
    "@wssp/api/sandbox/terminal-sessions"
  );
  const { mintTerminalTicket } = await import("@wssp/api/sandbox/terminal-tickets");
  const owner = await signUp();
  const first = await signIn(owner.email);
  const sandbox = await readySandbox(owner.userId);
  const target = {
    terminalId: `t${randomUUID().replaceAll("-", "")}`,
    userId: owner.userId,
    sessionId: first.sessionId,
    ...sandbox,
    generation: 3,
  };
  await recordTerminalSessionOpened(target);
  expect(await terminalResumeTargetOk(target)).toBe(true);
  const { service, opens } = terminalService();
  try {
    // A resumed v2 attachment: the re-read includes the row on every pass.
    const browser = new FakeBrowser();
    service
      .attach(
        {
          userId: owner.userId,
          sessionId: first.sessionId,
          ...sandbox,
          generation: 3,
          rows: 24,
          cols: 80,
          resume: { terminalId: target.terminalId, nextOutputSeq: 0 },
        },
        "req-wp8",
        2,
      )
      .opened(browser);
    await until(() => browser.text.some((frame) => frame.type === "ready"));
    expect(opens).toHaveLength(1);
    const response = await post("/sign-out", {}, first.cookie);
    expect(response.status, await response.clone().text()).toBe(200);
    expect(
      await db.inspect.sandboxTerminalSession.count({ where: { id: target.terminalId } }),
    ).toBe(0);
    await until(() => browser.closes.length > 0);
    expect(browser.closes).toEqual([{ code: 4401, reason: "revoked" }]);
    // A new sign-in is a new auth session: the terminal is not resumable.
    const second = await signIn(owner.email);
    expect(await terminalResumeTargetOk({ ...target, sessionId: second.sessionId })).toBe(false);
    await expect(
      mintTerminalTicket(
        { userId: owner.userId, sessionId: second.sessionId },
        {
          sandboxId: sandbox.sandboxId,
          rows: 24,
          cols: 80,
          version: 2,
          resume: { terminalId: target.terminalId, nextOutputSeq: 0 },
        },
      ),
    ).rejects.toMatchObject({ data: { code: "sandbox.terminal_resume_unavailable" } });
  } finally {
    service.dispose();
  }
});

/** A node relay socket: the server→host frames a terminal manager sends. */
class FakeHostSocket {
  readyState = 1;
  sends: Record<string, unknown>[] = [];
  send(data: string | Uint8Array) {
    if (typeof data === "string") this.sends.push(JSON.parse(data));
  }
  frames(type: string) {
    return this.sends.filter((frame) => frame.type === type);
  }
}

it("WP8 live P1: a start-first deploy (new process's boot sweep revokes the epoch under the old one) reconnects the terminal; it resumes the same PTY on the new process", async () => {
  const { SandboxTerminalManager } = await import("./terminal-manager.js");
  const { sweepConnectedHosts } = await import("./host-liveness.js");
  const { terminalResumeTargetOk } = await import("@wssp/api/sandbox/terminal-sessions");
  const { mintTerminalTicket, consumeTerminalTicket } = await import(
    "@wssp/api/sandbox/terminal-tickets"
  );
  const owner = await signUp();
  const login = await signIn(owner.email);
  const sandbox = await readySandbox(owner.userId);
  // The relay connection the process under test holds in memory (null: none).
  let live: number | null = 1;
  bindHostTerminalPolicy({
    read: () => undefined,
    raise: async () => false,
    authorize: async (_hostId, _ownerId, epoch) => epoch === live,
    connected: (_hostId, _ownerId, epoch) => epoch === live,
  });
  const processOn = (epoch: number) => {
    const socket = new FakeHostSocket();
    const manager = new SandboxTerminalManager({
      terminalHost: () => ({
        link: {
          socket,
          hostId: sandbox.hostId,
          ownerId: owner.userId,
          epoch,
          protocolVersion: "1.0",
          resumeGraceMs: 120_000,
          authorized: () => true,
        },
      }),
      closeHostSocket: () => undefined,
    });
    const service = new BrowserTerminalService(() => manager, checkTerminalBinding, 600_000);
    return { socket, manager, service };
  };
  const ticketFor = async (resume?: { terminalId: string; nextOutputSeq: number }) => {
    const { ticket } = await mintTerminalTicket(
      { userId: owner.userId, sessionId: login.sessionId },
      {
        sandboxId: sandbox.sandboxId,
        rows: 24,
        cols: 80,
        version: 2,
        ...(resume ? { resume } : {}),
      },
    );
    return (await consumeTerminalTicket(ticket))!;
  };
  const old = processOn(1);
  const next = processOn(3);
  try {
    // The old process: a v2 terminal open on the node.
    const browser = new FakeBrowser();
    const terminal = old.service.attach(await ticketFor(), "req-open", 2);
    terminal.opened(browser);
    await until(() => old.socket.frames("terminal.open").length === 1);
    const [open] = old.socket.frames("terminal.open") as {
      requestId: string;
      fence: { sessionId: string };
    }[];
    old.manager.handleHostControl(old.socket, {
      type: "terminal.ready",
      requestId: open!.requestId,
      fence: open!.fence as never,
      rows: 24,
      cols: 80,
    });
    const terminalId = open!.fence.sessionId;
    expect(browser.text.filter((f) => f.type === "ready")).toEqual([
      { type: "ready", rows: 24, cols: 80, terminalId, outputSeq: 0 },
    ]);
    const target = {
      terminalId,
      userId: owner.userId,
      sessionId: login.sessionId,
      ...sandbox,
      generation: 3,
    };
    for (let i = 0; i < 100 && !(await terminalResumeTargetOk(target)); i += 1) await settle(10);
    expect(await terminalResumeTargetOk(target)).toBe(true);

    // The new process boots while the old one still holds the relay.
    expect((await sweepConnectedHosts()).disconnected).toBeGreaterThanOrEqual(1);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({
        where: { id: sandbox.hostId },
        select: { status: true, connectionEpoch: true },
      }),
    ).toEqual({ status: "DISCONNECTED", connectionEpoch: 2 });
    // The old process's heartbeat re-read: a resumable close, never `superseded`.
    await terminal.revalidate();
    await until(() => browser.closes.length > 0);
    expect(browser.text.filter((f) => f.type === "reconnecting")).toEqual([
      { type: "reconnecting", terminalId, graceMs: 120_000 },
    ]);
    expect(browser.text.filter((f) => f.type === "close")).toEqual([]);
    expect(browser.closes).toEqual([{ code: 4402, reason: "reconnecting" }]);
    // The node is never asked to close the PTY, even by the old process's drain.
    old.service.dispose();
    old.manager.closeAll("shutdown");
    expect(old.socket.frames("terminal.close")).toEqual([]);
    live = null;
    await settle(50);
    expect(await terminalResumeTargetOk(target)).toBe(true);

    // First reattach attempt before the node is back: retryable, nothing sent.
    const early = new FakeBrowser();
    next.service
      .attach(await ticketFor({ terminalId, nextOutputSeq: 0 }), "req-early", 2)
      .opened(early);
    await until(() => early.closes.length > 0);
    expect(early.text.filter((f) => f.type === "close")).toEqual([
      {
        type: "close",
        code: 4401,
        error: { code: "disconnected", message: "host is not connected" },
        requestId: "req-early",
      },
    ]);
    // A ticket minted before the node's hello, consumed after it: retryable too.
    const stale = await ticketFor({ terminalId, nextOutputSeq: 0 });
    await db.inspect.sandboxHost.update({
      where: { id: sandbox.hostId },
      data: { status: "CONNECTED", connectionEpoch: 3 },
    });
    live = 3;
    expect(await checkTerminalBinding(stale)).toEqual({ ok: false, intent: "host_disconnected" });
    expect(next.socket.sends).toEqual([]);

    // The node is back on the new process: the same PTY resumes.
    const resumed = new FakeBrowser();
    next.service
      .attach(await ticketFor({ terminalId, nextOutputSeq: 0 }), "req-resume", 2)
      .opened(resumed);
    await until(() => next.socket.frames("terminal.resume").length === 1);
    const [resume] = next.socket.frames("terminal.resume") as {
      requestId: string;
      fence: { sessionId: string; epoch: number };
      nextOutputSeq: number;
    }[];
    expect(resume).toMatchObject({ fence: { sessionId: terminalId, epoch: 3 }, nextOutputSeq: 0 });
    next.manager.handleHostControl(next.socket, {
      type: "terminal.ready",
      requestId: resume!.requestId,
      fence: resume!.fence as never,
      rows: 24,
      cols: 80,
      outputSeq: 0,
    });
    expect(resumed.text.filter((f) => f.type === "ready")).toEqual([
      { type: "ready", rows: 24, cols: 80, terminalId, outputSeq: 0 },
    ]);
    expect(resumed.closes).toEqual([]);
    expect(next.socket.frames("terminal.open")).toEqual([]);
  } finally {
    old.service.dispose();
    next.service.dispose();
    bindHostTerminalPolicy({
      read: () => undefined,
      raise: async () => false,
      authorize: async () => true,
    });
  }
});
