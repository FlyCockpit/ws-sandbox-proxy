import { bindHostTerminalPolicy } from "@wssp/api/sandbox/host-terminal-policy";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { serve } from "@hono/node-server";
import { invalidateForceTwoFactorSettingsCache } from "@wssp/api/lib/two-factor-policy";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocketServer } from "ws";
import { createApp } from "../app.js";
import { browserTerminalService } from "./browser-terminal.js";
import { selectWebSocketSubprotocol } from "./browser-terminal-upgrade.js";
import { SANDBOX_FRAME_MAX_BYTES, type TerminalFence } from "./protocol.js";

/**
 * C54: the REAL web `TerminalClient` (apps/web/src/lib/terminal-client.ts, run
 * in a child process by apps/web/src/test/terminal-client-server-child.ts)
 * against the REAL application (`createApp`), the real Node HTTP server and
 * the shared `ws` server with the production subprotocol selection. The child
 * uses the web app's real oRPC client stack for `createSession`; only the
 * xterm view and ResizeObserver are stand-ins. This is the client-to-server
 * contract gate that the DOM tests (which mock the backend) cannot give.
 *
 * Only IO is replaced: Prisma (an in-memory model of the rows these checks
 * read; the atomic-consume claim itself is proven in
 * `terminal-tickets.pg.test.ts`), Better Auth's cookie lookup and Redis. The
 * host side is a real `SandboxTerminalManager` over a recording host socket.
 */

const state = vi.hoisted(() => ({
  env: {
    NODE_ENV: "test",
    CORS_ORIGIN: "https://web.example",
    BETTER_AUTH_URL: "https://api.example",
    BETTER_AUTH_SECRET: "c53-upgrade-matrix",
    RATE_LIMIT_AUTH_POINTS: 30,
    RATE_LIMIT_AUTH_WINDOW_SECONDS: 60,
    // The production default: the terminal-upgrade budget (scaled from this
    // family) is exercised at its real 30/60 s (C53-CO-3).
    RATE_LIMIT_RPC_POINTS: 100,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 300,
    RATE_LIMIT_SDK_KEY_POINTS: 100,
    RATE_LIMIT_SDK_OWNER_POINTS: 300,
    RATE_LIMIT_EMAIL_POINTS: 3,
    RATE_LIMIT_EMAIL_WINDOW_SECONDS: 3600,
    TRUST_PROXY_HOPS: undefined as number | undefined,
  },
  getSession: vi.fn(),
}));

vi.mock("@wssp/env/server", () => ({
  env: state.env,
  ADMIN_EMAILS: new Set(),
  SIGNUP_ENABLED: true,
  resolveAppName: () => "WS Sandbox Proxy",
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/auth", () => ({
  auth: { api: { getSession: state.getSession }, handler: vi.fn() },
}));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  QUEUE_NAMES: {
    reapExpiredAuthTokens: "reap",
    checkBackupFreshness: "check",
    webhookDelivery: "webhook-delivery",
    reapWebhookLog: "reap-webhook-log",
  },
  reapExpiredAuthTokensQueue: {},
  imageStoreMaintenanceQueue: {
    add: vi.fn(),
    upsertJobScheduler: vi.fn(),
    removeJobScheduler: vi.fn(),
  },
  checkBackupFreshnessQueue: {},
  notifyDataDeletionsQueue: {},
  webhookDeliveryQueue: {},
  reapWebhookLogQueue: {},
}));
vi.mock("@wssp/queue/consumer-health", () => ({ hasExternalConsumer: vi.fn() }));
vi.mock("@wssp/mailer", () => ({ isEmailConfigured: () => false }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.7" } }),
}));
vi.mock("../lifecycle.js", () => ({ withTimeout: (promise: Promise<unknown>) => promise }));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  // Only Redis IO is replaced; the real library accounts points and windows.
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});
vi.mock("./session-manager.js", async (original) => {
  const actual = await original<typeof import("./session-manager.js")>();
  const { SandboxTerminalManager } = await import("./terminal-manager.js");
  const host = {
    readyState: 1,
    sends: [] as string[],
    binary: [] as Uint8Array[],
    send(data: string | ArrayBuffer | Uint8Array) {
      if (typeof data !== "string") {
        this.binary.push(new Uint8Array(data instanceof ArrayBuffer ? data : data.slice()));
        return;
      }
      this.sends.push(data);
      // Model the host: a requested close is confirmed (PTY reaped) by its final exit.
      const frame = JSON.parse(data);
      if (frame.type === "terminal.close")
        queueMicrotask(() =>
          terminals.handleHostControl(host, {
            type: "terminal.exit",
            requestId: frame.requestId,
            fence: frame.fence,
            intent: frame.intent,
            reaped: true,
          }),
        );
    },
  };
  const terminals = new SandboxTerminalManager({
    terminalHost: (hostId: string) =>
      hostId === "host-1"
        ? {
            link: {
              socket: host,
              hostId: "host-1",
              ownerId: "owner-1",
              epoch: 5,
              protocolVersion: "1.0",
              authorized: () => true,
            },
          }
        : { error: { code: "disconnected" as const, message: "host is not connected" } },
    closeHostSocket: () => undefined,
  });
  return {
    ...actual,
    fakeHost: host,
    fakeTerminals: terminals,
    sandboxRelaySessionManager: Object.assign(Object.create(actual.sandboxRelaySessionManager), {
      terminals,
    }),
  };
});

const { default: prisma } = await import("@wssp/db");
const db = prisma as import("@wssp/api/test/mock-prisma").MockPrisma;
const sessionModule = (await import("./session-manager.js")) as unknown as {
  fakeHost: { readyState: number; sends: string[]; binary: Uint8Array[]; send(data: string): void };
  fakeTerminals: import("./terminal-manager.js").SandboxTerminalManager;
};
const { fakeHost, fakeTerminals } = sessionModule;

// -- in-memory rows ----------------------------------------------------------

type SessionRow = { id: string; userId: string; expiresAt: Date; impersonatedBy: string | null };
const sessions = new Map<string, SessionRow>();
const users = new Map<string, Record<string, unknown>>();
const sandboxes = new Map<string, Record<string, unknown>>();
const tickets = new Map<string, Record<string, unknown>>();

function seed() {
  sessions.clear();
  users.clear();
  sandboxes.clear();
  tickets.clear();
  for (const n of [1, 2]) {
    sessions.set(`auth-${n}`, {
      id: `auth-${n}`,
      userId: `owner-${n}`,
      expiresAt: new Date(Date.now() + 3_600_000),
      impersonatedBy: null,
    });
    users.set(`owner-${n}`, {
      twoFactorEnabled: true,
      role: "user",
      emailVerified: true,
      banned: false,
      banExpires: null,
      createdAt: new Date("2020-01-01"),
      deletionRequestedAt: null,
    });
  }
  sandboxes.set("sbx-1", {
    id: "sbx-1",
    userId: "owner-1",
    state: "READY",
    purpose: "WORKLOAD",
    generation: 3,
    sandboxHostId: "host-1",
    hostOwnerId: "owner-1",
    SandboxHost: { userId: "owner-1", connectionEpoch: 5, deletionRequestedAt: null },
    leaseExpiresAt: null,
    SandboxTemplateRevision: { defaultCwd: null },
  });
  sandboxes.set("sbx-2", {
    id: "sbx-2",
    userId: "owner-2",
    state: "READY",
    purpose: "WORKLOAD",
    generation: 1,
    sandboxHostId: "host-2",
    hostOwnerId: "owner-2",
    SandboxHost: { userId: "owner-2", connectionEpoch: 1, deletionRequestedAt: null },
    leaseExpiresAt: null,
    SandboxTemplateRevision: { defaultCwd: null },
  });
}

function flatWhere(where: Record<string, unknown>): Record<string, unknown> {
  if (Array.isArray(where.AND))
    return Object.assign(
      {},
      ...where.AND.map((part) => flatWhere(part as Record<string, unknown>)),
    );
  return where;
}

function wireDb() {
  db.session.findUnique.mockImplementation((async (args: { where: Record<string, unknown> }) => {
    const row = sessions.get(String(args.where.id));
    if (!row || row.userId !== args.where.userId) return null;
    if (row.expiresAt.getTime() <= Date.now() || row.impersonatedBy !== null) return null;
    return { id: row.id };
  }) as never);
  db.user.findUnique.mockImplementation(
    (async (args: { where: { id: string } }) => users.get(args.where.id) ?? null) as never,
  );
  db.appSetting.findMany.mockResolvedValue([]);
  db.sandbox.findFirst.mockImplementation((async (args: { where: Record<string, unknown> }) => {
    const where = flatWhere(args.where);
    const row = sandboxes.get(String(where.id));
    if (!row || row.userId !== where.userId) return null;
    return { ...row };
  }) as never);
  db.sandboxTerminalTicket.deleteMany.mockResolvedValue({ count: 0 } as never);
  db.sandboxTerminalTicket.create.mockImplementation((async (args: {
    data: Record<string, unknown>;
  }) => {
    tickets.set(String(args.data.tokenDigest), { ...args.data });
    return { id: "ticket" };
  }) as never);
  // Models the single `DELETE ... RETURNING` (atomicity: terminal-tickets.pg.test.ts).
  db.$queryRaw.mockImplementation(((strings: TemplateStringsArray, ...values: unknown[]) => {
    if (!/"sandbox_browser_terminal_ticket"[\s\S]*RETURNING/.test(strings.join("?")))
      return Promise.resolve([]);
    const row = tickets.get(String(values[0]));
    tickets.delete(String(values[0]));
    return Promise.resolve(row ? [row] : []);
  }) as never);
}

// -- the real server ---------------------------------------------------------

let base = "";
let server: ReturnType<typeof serve>;
let app: Awaited<ReturnType<typeof createApp>>;
const logs: string[] = [];

beforeAll(async () => {
  bindHostTerminalPolicy({
    read: () => undefined,
    raise: async () => false,
    authorize: async () => true,
  });
  for (const method of ["log", "info", "warn", "error", "debug"] as const)
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });
  app = await createApp({ isShuttingDown: () => false, isWorkerReady: () => true });
  server = serve({
    fetch: app.fetch,
    port: 0,
    hostname: "127.0.0.1",
    websocket: {
      server: new WebSocketServer({
        maxPayload: SANDBOX_FRAME_MAX_BYTES,
        noServer: true,
        handleProtocols: (protocols, request) => selectWebSocketSubprotocol(protocols, request.url),
      }),
    },
  });
  await once(server, "listening");
  base = `127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => {
  bindHostTerminalPolicy(null);
  browserTerminalService.dispose();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

// Each test runs in its own budget minute (the real procedure and upgrade
// limiters stay mounted); only Date is faked, the sockets use real timers.
let clock = Date.now();
beforeEach(() => {
  clock += 61_000;
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(clock);
  seed();
  wireDb();
  invalidateForceTwoFactorSettingsCache();
  state.getSession.mockImplementation(async ({ headers }: { headers: Headers }) => {
    if (headers.has("authorization")) return null; // cookie surfaces strip it (session-middleware)
    const sid = /(?:^|;\s*)sid=([^;]+)/.exec(headers.get("cookie") ?? "")?.[1];
    const row = sid ? sessions.get(sid) : undefined;
    return row
      ? {
          user: { id: row.userId, role: "user", emailVerified: true, twoFactorEnabled: true },
          session: { id: row.id, userId: row.userId },
        }
      : null;
  });
});

const ORIGIN = "https://web.example";

const hostFrames = (type: string) =>
  fakeHost.sends.map((s) => JSON.parse(s)).filter((frame) => frame.type === type);
const ptyOpens = () => hostFrames("terminal.open").length;

import { type ChildProcess as Child, spawn as spawnChild } from "node:child_process";
import { fileURLToPath as toPath } from "node:url";

const WEB_DIR = toPath(new URL("../../../web", import.meta.url));
const ROOT_DIR = toPath(new URL("../../../..", import.meta.url));
const WS_MODULE = toPath(new URL("../../node_modules/ws/wrapper.mjs", import.meta.url));
const probeChildren = new Set<Child>();
afterAll(() => {
  for (const child of probeChildren) child.kill();
});

type Ev = {
  event: string;
  text?: string;
  line?: string;
  code?: number | string;
  status?: number;
  protocol?: string;
  frame?: { type: string; [field: string]: unknown };
  snapshot?: {
    status: string;
    size: { rows: number; cols: number } | null;
    notice: { kind: string; code?: string; exitCode?: number } | null;
  };
};
type Command = Record<string, unknown>;
function startWebClient(options: { cookie?: string; wsOrigin?: string } = {}) {
  const child = spawnChild(
    process.execPath,
    [
      "--import",
      "tsx",
      `${WEB_DIR}/src/test/terminal-client-server-child.ts`,
      JSON.stringify({
        serverUrl: `http://${base}`,
        sandboxId: "sbx-1",
        cookie: options.cookie ?? "sid=auth-1",
        rpcOrigin: ORIGIN,
        wsOrigin: options.wsOrigin ?? ORIGIN,
        wsModule: WS_MODULE,
      }),
    ],
    { cwd: ROOT_DIR, stdio: ["pipe", "pipe", "inherit"] },
  );
  probeChildren.add(child);
  const events: Ev[] = [];
  let buffer = "";
  child.stdout!.on("data", (chunk: Buffer) => {
    buffer += chunk.toString();
    for (let i = buffer.indexOf("\n"); i >= 0; i = buffer.indexOf("\n")) {
      const line = buffer.slice(0, i);
      buffer = buffer.slice(i + 1);
      try {
        events.push(JSON.parse(line));
      } catch {
        events.push({ event: "raw", line });
      }
    }
  });
  const send = (command: Command) => child.stdin!.write(`${JSON.stringify(command)}\n`);
  const of = (name: string) => events.filter((e) => e.event === name);
  const last = () => of("state").at(-1)?.snapshot;
  return { child, events, send, of, last };
}

async function waitFor(check: () => boolean, label: string, ms = 15_000) {
  const deadline = performance.now() + ms;
  while (!check()) {
    if (performance.now() > deadline) throw new Error(`timed out: ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe("real TerminalClient against the real C53 endpoint", {
  timeout: 60_000,
}, () => {
  it("P1 attach + output + clamped resize + input + CloseIntent detach observed server-side", async () => {
    const web = startWebClient();
    await waitFor(() => web.of("ready").length === 1, "child ready");
    const opensBefore = ptyOpens();
    web.send({ attach: true });
    await waitFor(() => ptyOpens() === opensBefore + 1, "terminal.open reached the host");
    const open = hostFrames("terminal.open").at(-1);
    // createSession size (30x100 from fit) became the PTY size via the server binding.
    expect(open).toMatchObject({ rows: 30, cols: 100 });
    // The child reports the socket open on its own stdout line, which can trail the host frame.
    await waitFor(() => web.of("socket-open").length === 1, "socket-open reported");
    expect(web.of("socket-open")[0]?.protocol).toBe("wssp.terminal.v1");
    fakeTerminals.handleHostControl(fakeHost, {
      type: "terminal.ready",
      requestId: open.requestId,
      fence: open.fence as TerminalFence,
      rows: 30,
      cols: 100,
    });
    await waitFor(() => web.last()?.status === "attached", "client attached");
    expect(web.last()?.size).toEqual({ rows: 30, cols: 100 });
    expect(browserTerminalService.count()).toBe(1);

    // Output.
    fakeTerminals.handleHostData(
      fakeHost,
      { type: "terminal.data", fence: open.fence as TerminalFence, sequence: 0 },
      new TextEncoder().encode("hello from pty"),
    );
    await waitFor(() => web.of("output").some((e) => e.text === "hello from pty"), "output");

    // Input (binary frame through the real server to the host).
    const binBefore = fakeHost.binary.length;
    web.send({ type: "ls\r" });
    await waitFor(() => fakeHost.binary.length > binBefore, "input reached host");

    // Resize out of bounds: clamped to 512x1024 on the wire, accepted by the server.
    web.send({ resize: { rows: 4000, cols: 9000 } });
    await waitFor(() => hostFrames("terminal.resize").length >= 1, "resize reached host");
    const resize = hostFrames("terminal.resize").at(-1);
    expect(resize).toMatchObject({ rows: 512, cols: 1024 });
    fakeTerminals.handleHostControl(fakeHost, {
      type: "terminal.ready",
      requestId: resize.requestId,
      fence: open.fence as TerminalFence,
      rows: 512,
      cols: 1024,
    });
    await waitFor(() => web.last()?.size?.rows === 512, "resize confirmed");
    // No protocol_violation / error frame from the server along the way.
    expect(web.of("socket-text").filter((e) => e.frame?.type === "error")).toEqual([]);

    // Detach: CloseIntent + close(1000); server closes the PTY with intent client.
    const closesBefore = hostFrames("terminal.close").length;
    web.send({ detach: true });
    await waitFor(
      () => hostFrames("terminal.close").length > closesBefore,
      "terminal.close at host",
    );
    expect(hostFrames("terminal.close").at(-1)).toMatchObject({
      intent: "client",
      fence: open.fence,
    });
    await waitFor(() => browserTerminalService.count() === 0, "server forgot the terminal");
    await waitFor(() => web.of("socket-close").length === 1, "socket closed");
    expect(web.last()).toMatchObject({ status: "ended", notice: { kind: "client" } });
    expect(web.of("create")).toHaveLength(1);
    expect(web.of("socket-new")).toHaveLength(1);
    web.send({ exit: true });
  });

  it("P2 post-consume refusal (stopped after mint) is classified sandboxStopped, no retry, no PTY", async () => {
    const original = db.sandboxTerminalTicket.create.getMockImplementation()!;
    db.sandboxTerminalTicket.create.mockImplementation((async (a: never) => {
      const result = await (original as (a: never) => Promise<unknown>)(a);
      Object.assign(sandboxes.get("sbx-1")!, { state: "STOPPED" });
      return result;
    }) as never);
    const web = startWebClient();
    await waitFor(() => web.of("ready").length === 1, "child ready");
    const opensBefore = ptyOpens();
    web.send({ attach: true });
    await waitFor(() => web.last()?.status === "ended", "ended");
    expect(web.last()?.notice).toEqual({ kind: "sandboxStopped" });
    expect(web.of("socket-open")).toHaveLength(1);
    const closeFrame = web.of("socket-text").find((e) => e.frame?.type === "close")?.frame;
    expect(closeFrame).toMatchObject({ type: "close", code: 4401, intent: "sandbox_stopped" });
    expect(web.of("socket-close")[0]).toMatchObject({ code: 4401 });
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(web.of("create")).toHaveLength(1);
    expect(web.of("socket-new")).toHaveLength(1);
    expect(ptyOpens()).toBe(opensBefore);
    web.send({ exit: true });
  });

  it("P3 pre-upgrade refusal (bad Origin): one classifying createSession, one more upgrade, then couldNotConnect", async () => {
    const web = startWebClient({ wsOrigin: "https://evil.example" });
    await waitFor(() => web.of("ready").length === 1, "child ready");
    const opensBefore = ptyOpens();
    web.send({ attach: true });
    await waitFor(() => web.last()?.status === "ended", "ended");
    expect(web.last()?.notice).toEqual({ kind: "couldNotConnect" });
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(web.of("create")).toHaveLength(2);
    expect(web.of("create-ok")).toHaveLength(2);
    expect(web.of("socket-new")).toHaveLength(2);
    expect(web.of("socket-open")).toHaveLength(0);
    expect(web.of("socket-close").map((e) => e.code)).toEqual([1006, 1006]);
    expect(ptyOpens()).toBe(opensBefore);
    web.send({ exit: true });
  });

  it("P4 pre-upgrade refusal (session revoked after mint): classifying createSession is UNAUTHORIZED -> signedOut", async () => {
    const original = state.getSession.getMockImplementation()!;
    state.getSession.mockImplementation(async (args: { headers: Headers }) => {
      const result = await original(args);
      // The ticket response has already passed its exit check. Revoke when
      // the upgrade presents the cookie; the classifying RPC sees it gone.
      if (args.headers.get("upgrade") === "websocket") {
        sessions.delete("auth-1");
        return null;
      }
      return result;
    });
    const web = startWebClient();
    await waitFor(() => web.of("ready").length === 1, "child ready");
    web.send({ attach: true });
    await waitFor(() => web.last()?.status === "ended", "ended");
    expect(web.of("create-error")[0]).toMatchObject({ code: "UNAUTHORIZED", status: 401 });
    expect(web.last()?.notice).toEqual({ kind: "signedOut" });
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(web.of("create")).toHaveLength(2);
    expect(web.of("socket-new")).toHaveLength(1);
    expect(web.of("socket-close").map((e) => e.code)).toEqual([1006]);
    web.send({ exit: true });
  });

  it("S0 revocation during ticket mint denies the response before any socket", async () => {
    const original = db.sandboxTerminalTicket.create.getMockImplementation()!;
    db.sandboxTerminalTicket.create.mockImplementation((async (a: never) => {
      const result = await (original as (a: never) => Promise<unknown>)(a);
      sessions.delete("auth-1");
      return result;
    }) as never);
    const web = startWebClient();
    await waitFor(() => web.of("ready").length === 1, "child ready");
    const before = ptyOpens();
    web.send({ attach: true });
    await waitFor(() => web.last()?.status === "ended", "ended");
    expect(web.of("create-error")[0]).toMatchObject({ code: "UNAUTHORIZED", status: 401 });
    expect(web.last()?.notice).toEqual({ kind: "signedOut" });
    expect(web.of("create")).toHaveLength(1);
    expect(web.of("create-ok")).toHaveLength(0);
    expect(web.of("socket-new")).toHaveLength(0);
    expect(ptyOpens()).toBe(before);
    web.send({ exit: true });
  });

  it("P5 replaced: a second attach replaces the first; the first is classified replaced", async () => {
    const a = startWebClient();
    await waitFor(() => a.of("ready").length === 1, "a ready");
    const before = ptyOpens();
    a.send({ attach: true });
    await waitFor(() => ptyOpens() === before + 1, "a open");
    const openA = hostFrames("terminal.open").at(-1);
    fakeTerminals.handleHostControl(fakeHost, {
      type: "terminal.ready",
      requestId: openA.requestId,
      fence: openA.fence as TerminalFence,
      rows: 30,
      cols: 100,
    });
    await waitFor(() => a.last()?.status === "attached", "a attached");
    const b = startWebClient();
    await waitFor(() => b.of("ready").length === 1, "b ready");
    b.send({ attach: true });
    await waitFor(() => a.last()?.status === "ended", "a ended");
    expect(a.last()?.notice).toEqual({ kind: "replaced" });
    expect(a.of("create")).toHaveLength(1);
    b.send({ dispose: true });
    await waitFor(() => b.of("socket-close").length === 1, "b closed");
    a.send({ exit: true });
    b.send({ exit: true });
  });

  it.each([
    [
      "P6 host refuses with unsupported_capability (pre-C52 sandbox)",
      { error: { code: "unsupported_capability", message: "no guest identity" } },
      { kind: "noTerminalIdentity", code: "unsupported_capability" },
      false,
    ],
    ["P7 shell exits with code 3", { exitCode: 3 }, { kind: "exited", exitCode: 3 }, true],
  ] as const)("%s", async (_label, exit, notice, ready) => {
    const web = startWebClient();
    await waitFor(() => web.of("ready").length === 1, "child ready");
    const before = ptyOpens();
    web.send({ attach: true });
    await waitFor(() => ptyOpens() === before + 1, "open");
    const open = hostFrames("terminal.open").at(-1);
    if (ready) {
      fakeTerminals.handleHostControl(fakeHost, {
        type: "terminal.ready",
        requestId: open.requestId,
        fence: open.fence as TerminalFence,
        rows: 30,
        cols: 100,
      });
      await waitFor(() => web.last()?.status === "attached", "attached");
    }
    fakeTerminals.handleHostControl(fakeHost, {
      type: "terminal.exit",
      fence: open.fence as TerminalFence,
      reaped: true,
      ...exit,
    } as never);
    await waitFor(() => web.last()?.status === "ended", "ended");
    expect(web.last()?.notice).toEqual(notice);
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(web.of("create")).toHaveLength(1);
    expect(web.of("socket-new")).toHaveLength(1);
    web.send({ exit: true });
  });
});
