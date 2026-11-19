import { bindHostTerminalPolicy } from "@wssp/api/sandbox/host-terminal-policy";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createHash } from "node:crypto";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { serve } from "@hono/node-server";
import { invalidateForceTwoFactorSettingsCache } from "@wssp/api/lib/two-factor-policy";
import { withAuthorityChange } from "@wssp/db/authority";
import { notifyAuthSessionsRevoked } from "@wssp/db/session-revocation";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocketServer } from "ws";
import { createApp } from "../app.js";
import { terminalUpgradeLimiter } from "../rate-limit.js";
import { BrowserTerminal, browserTerminalService } from "./browser-terminal.js";
import {
  killBrowserClients,
  type Upgrade,
  upgradeBrowserTerminal,
} from "./browser-terminal-client-harness.js";
import {
  type BrowserProbe,
  killBrowserProbes,
  type ProbeAttempt,
  startBrowserProbe,
} from "./browser-terminal-probe-harness.js";
import { selectWebSocketSubprotocol } from "./browser-terminal-upgrade.js";
import { SANDBOX_FRAME_MAX_BYTES, type TerminalFence } from "./protocol.js";

/**
 * C53 upgrade auth matrix against the REAL application (`createApp`) served
 * by the real Node HTTP server and the shared `ws` server with the production
 * subprotocol selection. Only IO is replaced: Prisma (an in-memory model of
 * the rows these checks read; the atomic-consume claim itself is proven in
 * `terminal-tickets.pg.test.ts`), Better Auth's cookie lookup and Redis.
 *
 * The host side is a real `SandboxTerminalManager` over a recording host
 * socket: `terminal.open` frames there are the only way a PTY can be
 * allocated, so every refused leg asserts that count is unchanged.
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
  /** WP8: the fake node's negotiated reattach grace (absent: never detaches). */
  resumeGraceMs: undefined as number | undefined,
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
              ...(state.resumeGraceMs === undefined ? {} : { resumeGraceMs: state.resumeGraceMs }),
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
/** C53-FS-2: the lifecycle's shutdown flag, flipped by one test. */
let shuttingDown = false;
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
  app = await createApp({ isShuttingDown: () => shuttingDown, isWorkerReady: () => true });
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
  killBrowserClients();
  killBrowserProbes();
  browserTerminalService.dispose();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

const issued: string[] = [];
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

async function createSession(
  options: { sid?: string; sandboxId?: string; csrf?: boolean; origin?: string } = {},
) {
  const response = await app.request("/rpc/sandboxTerminals/createSession", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: `sid=${options.sid ?? "auth-1"}`,
      origin: options.origin ?? ORIGIN,
      ...(options.csrf === false ? {} : { "x-csrf-token": "orpc" }),
    },
    body: JSON.stringify({ json: { sandboxId: options.sandboxId ?? "sbx-1", rows: 24, cols: 80 } }),
  });
  const body = (await response.json()) as { json: Record<string, unknown> };
  if (response.ok) {
    const protocols = body.json.protocols as string[];
    issued.push(protocols[1]!.slice("wssp.terminal.ticket.".length));
  }
  return { status: response.status, body: body.json };
}

function upgrade(options: {
  path?: string;
  protocols: string[];
  cookie?: string;
  origin?: string | null;
  authorization?: string;
  autoPong?: boolean;
}): Promise<Upgrade> {
  return upgradeBrowserTerminal({
    ...options,
    base,
    path: options.path ?? "/api/dashboard/sandboxes/sbx-1/terminal/ws",
    origin: options.origin === null ? null : (options.origin ?? ORIGIN),
  });
}

/**
 * One browser process for a scenario's many sequential attempts (budget
 * scenarios): each attempt is a real upgrade, without booting a process per
 * attempt. An opened socket is closed by the browser before the next attempt.
 */
const probes: BrowserProbe[] = [];
afterEach(() => {
  for (const probe of probes.splice(0)) probe.dispose();
});
function browserProbe() {
  const probe = startBrowserProbe(base);
  probes.push(probe);
  return (options: { protocols: string[]; cookie?: string } & Partial<ProbeAttempt>) =>
    probe.attempt({
      ...options,
      path: options.path ?? "/api/dashboard/sandboxes/sbx-1/terminal/ws",
      origin: options.origin === null ? null : (options.origin ?? ORIGIN),
    });
}

async function until(check: () => boolean, label: string) {
  const deadline = Date.now() + 5000;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`timed out: ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

const hostFrames = (type: string) =>
  fakeHost.sends.map((s) => JSON.parse(s)).filter((frame) => frame.type === type);
const ptyOpens = () => hostFrames("terminal.open").length;

function answerOpen() {
  const open = hostFrames("terminal.open").at(-1);
  fakeTerminals.handleHostControl(fakeHost, {
    type: "terminal.ready",
    requestId: open.requestId,
    fence: open.fence as TerminalFence,
    rows: 24,
    cols: 80,
  });
  return open.fence as TerminalFence;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * A refusal AFTER the ticket was consumed and matched (C53-CO-1): the upgrade
 * is accepted, the browser reads the CloseIntent (stable intent / error code
 * and the upgrade requestId) and 4401, and the host never sees a PTY open.
 */
async function closedWithoutPty(
  attempt: Promise<Upgrade>,
  expected: { intent?: string; error?: Record<string, unknown> },
) {
  const before = ptyOpens();
  const result = await attempt;
  expect(result.kind).toBe("open");
  if (result.kind !== "open") return;
  const closed = await result.closed;
  expect(closed.code).toBe(4401);
  const frames = result.text.filter((f) => f.type === "close");
  expect(frames).toHaveLength(1);
  expect(frames[0]).toEqual({
    type: "close",
    code: 4401,
    ...expected,
    requestId: expect.any(String),
  });
  expect(String(frames[0]!.requestId)).toMatch(UUID);
  expect(result.text.filter((f) => f.type === "ready")).toEqual([]);
  await new Promise((resolve) => setTimeout(resolve, 20));
  expect(ptyOpens()).toBe(before);
}

async function refusedWithoutPty(attempt: Promise<Upgrade>, status: number, code: string) {
  const before = ptyOpens();
  const result = await attempt;
  expect(result).toMatchObject({ kind: "refused", status });
  if (result.kind === "refused") expect(result.refusal).toBe(code);
  await new Promise((resolve) => setTimeout(resolve, 20));
  expect(ptyOpens()).toBe(before);
}

describe("happy path and the wire", () => {
  it("cookie session + ticket opens the PTY from the server-side binding; the ticket is never echoed", async () => {
    const created = await createSession();
    expect(created.status).toBe(200);
    expect(created.body.path).toBe("/api/dashboard/sandboxes/sbx-1/terminal/ws");
    const protocols = created.body.protocols as string[];
    const before = ptyOpens();
    const result = await upgrade({ protocols, cookie: "sid=auth-1" });
    expect(result.kind).toBe("open");
    if (result.kind !== "open") return;
    expect(result.protocol).toBe("wssp.terminal.v1");
    const inbox = result;
    await until(() => ptyOpens() === before + 1, "terminal.open");
    const fence = answerOpen();
    expect(fence).toMatchObject({
      hostId: "host-1",
      target: { kind: "sandbox", sandboxId: "sbx-1", generation: 3 },
      epoch: 5,
    });
    await until(() => inbox.text.some((f) => f.type === "ready"), "ready");
    result.sendBinary(Buffer.from("echo hi\n"));
    await until(() => fakeHost.binary.length > 0, "input reached the host");
    result.sendText(JSON.stringify({ type: "close", requestId: "bye" }));
    expect(await inbox.closed).toEqual({ code: 4401, reason: "client" });
    expect(inbox.text.at(-1)).toEqual({
      type: "close",
      code: 4401,
      intent: "client",
      requestId: "bye",
    });
    expect(hostFrames("terminal.close").at(-1)).toMatchObject({ intent: "client", fence });
  });
});

describe("ticket legs (no PTY on any refusal)", () => {
  it("replay: a consumed ticket never opens a second terminal", async () => {
    const { body } = await createSession();
    const protocols = body.protocols as string[];
    const first = await upgrade({ protocols, cookie: "sid=auth-1" });
    expect(first.kind).toBe("open");
    if (first.kind === "open") first.close();
    await refusedWithoutPty(upgrade({ protocols, cookie: "sid=auth-1" }), 401, "TICKET_INVALID");
  });

  it("concurrent presentation: exactly one upgrade is accepted", async () => {
    const { body } = await createSession();
    const protocols = body.protocols as string[];
    const results = await Promise.all(
      Array.from({ length: 4 }, () => upgrade({ protocols, cookie: "sid=auth-1" })),
    );
    expect(results.filter((r) => r.kind === "open")).toHaveLength(1);
    expect(results.filter((r) => r.kind === "refused" && r.status === 401)).toHaveLength(3);
    for (const r of results) if (r.kind === "open") r.close();
  });

  it("expiry: a ticket presented after its TTL is refused", async () => {
    const { body } = await createSession();
    const digest = createHash("sha256").update(issued.at(-1)!).digest("hex");
    tickets.get(digest)!.expiresAt = new Date(Date.now() - 1);
    await refusedWithoutPty(
      upgrade({ protocols: body.protocols as string[], cookie: "sid=auth-1" }),
      401,
      "TICKET_INVALID",
    );
  });

  it.each([
    ["stale generation (reconnected since the mint)", "superseded", { generation: 4 }],
    ["moved to another host", "superseded", { sandboxHostId: "host-9" }],
    ["stopped since the mint", "sandbox_stopped", { state: "STOPPED" }],
    ["destroyed since the mint", "sandbox_destroyed", { state: "DELETED" }],
    ["lease expired since the mint", "expired", { leaseExpiresAt: new Date(0) }],
  ] as const)("%s: readable CloseIntent %s + 4401, NO PTY", async (_label, intent, change) => {
    const { body } = await createSession();
    Object.assign(sandboxes.get("sbx-1")!, change);
    await closedWithoutPty(
      upgrade({ protocols: body.protocols as string[], cookie: "sid=auth-1" }),
      { intent },
    );
    // The consumed ticket is burned: it cannot be presented again.
    await refusedWithoutPty(
      upgrade({ protocols: body.protocols as string[], cookie: "sid=auth-1" }),
      401,
      "TICKET_INVALID",
    );
  });

  it("host unavailable: readable CloseIntent with the host error code + 4401, NO PTY", async () => {
    const { body } = await createSession({ sid: "auth-2", sandboxId: "sbx-2" });
    await closedWithoutPty(
      upgrade({
        path: "/api/dashboard/sandboxes/sbx-2/terminal/ws",
        protocols: body.protocols as string[],
        cookie: "sid=auth-2",
      }),
      { error: { code: "disconnected", message: "host is not connected" } },
    );
  });

  it("another owner's session cannot use the ticket (and burns it)", async () => {
    const { body } = await createSession();
    const protocols = body.protocols as string[];
    await refusedWithoutPty(upgrade({ protocols, cookie: "sid=auth-2" }), 401, "TICKET_INVALID");
    await refusedWithoutPty(upgrade({ protocols, cookie: "sid=auth-1" }), 401, "TICKET_INVALID");
  });

  it("a ticket is bound to its sandbox path", async () => {
    sandboxes.set("sbx-9", { ...sandboxes.get("sbx-1")!, id: "sbx-9" });
    const { body } = await createSession();
    await refusedWithoutPty(
      upgrade({
        path: "/api/dashboard/sandboxes/sbx-9/terminal/ws",
        protocols: body.protocols as string[],
        cookie: "sid=auth-1",
      }),
      401,
      "TICKET_INVALID",
    );
  });

  it("missing, malformed and extra subprotocols are refused", async () => {
    const { body } = await createSession();
    const [terminal, ticket] = body.protocols as string[];
    for (const protocols of [
      [terminal!],
      [ticket!],
      [ticket!, terminal!],
      [terminal!, ticket!, "x"],
    ])
      await refusedWithoutPty(
        upgrade({ protocols, cookie: "sid=auth-1" }),
        400,
        "SUBPROTOCOL_REQUIRED",
      );
    // None of those consumed the ticket.
    const ok = await upgrade({ protocols: [terminal!, ticket!], cookie: "sid=auth-1" });
    expect(ok.kind).toBe("open");
    if (ok.kind === "open") ok.close();
  });
});

describe("plane separation, session, Origin, CSRF and policy", () => {
  it.each([
    ["SDK key", `Bearer wssp_sdk_${"A".repeat(43)}`],
    ["host token", `Bearer wssp_host_${"B".repeat(43)}`],
    ["device credential", `Bearer wssp_device_${"C".repeat(43)}`],
    ["any bearer", "Bearer anything"],
  ])(
    "%s on the browser endpoint → CREDENTIAL_PLANE, ticket untouched",
    async (_label, authorization) => {
      const { body } = await createSession();
      const protocols = body.protocols as string[];
      await refusedWithoutPty(
        upgrade({ protocols, cookie: "sid=auth-1", authorization }),
        401,
        "CREDENTIAL_PLANE",
      );
      expect(tickets.size).toBe(1);
    },
  );

  it("machine credentials smuggled as subprotocols, or the relay subprotocol, are refused", async () => {
    const { body } = await createSession();
    const [terminal] = body.protocols as string[];
    for (const protocols of [
      [terminal!, `wssp_sdk_${"A".repeat(43)}`],
      [terminal!, `wssp.terminal.ticket.wssp_host_${"B".repeat(20)}`],
      ["ws-sandbox-proxy.relay.v1", ...(body.protocols as string[])],
    ])
      await refusedWithoutPty(
        upgrade({ protocols, cookie: "sid=auth-1" }),
        401,
        "CREDENTIAL_PLANE",
      );
    expect(tickets.size).toBe(1);
  });

  it("browser credentials never authenticate the host plane", async () => {
    const { body } = await createSession();
    const result = await upgrade({
      path: "/ws/sandbox-host",
      protocols: ["ws-sandbox-proxy.relay.v1", ...(body.protocols as string[])],
      cookie: "sid=auth-1",
    });
    expect(result).toMatchObject({ kind: "refused", status: 401 });
    expect(tickets.size).toBe(1);
  });

  it("no cookie session → UNAUTHORIZED and the ticket survives", async () => {
    const { body } = await createSession();
    await refusedWithoutPty(
      upgrade({ protocols: body.protocols as string[] }),
      401,
      "UNAUTHORIZED",
    );
    expect(tickets.size).toBe(1);
  });

  it.each([
    ["foreign", "https://evil.example"],
    ["suffix", "https://web.example.evil"],
    ["port", "https://web.example:8443"],
    ["scheme", "http://web.example"],
    ["opaque", "null"],
    ["missing", null],
  ])("Origin %s is refused before any session or ticket work", async (_label, origin) => {
    const { body } = await createSession();
    const calls = state.getSession.mock.calls.length;
    await refusedWithoutPty(
      upgrade({ protocols: body.protocols as string[], cookie: "sid=auth-1", origin }),
      403,
      "ORIGIN_REFUSED",
    );
    expect(state.getSession.mock.calls.length).toBe(calls);
    expect(tickets.size).toBe(1);
  });

  it("the API origin itself is also an allowed exact origin", async () => {
    const { body } = await createSession();
    const result = await upgrade({
      protocols: body.protocols as string[],
      cookie: "sid=auth-1",
      origin: "https://api.example",
    });
    expect(result.kind).toBe("open");
    if (result.kind === "open") result.close();
  });

  it("CSRF: a create without the CSRF header mints nothing", async () => {
    const result = await createSession({ csrf: false });
    expect(result.status).toBeGreaterThanOrEqual(400);
    expect(tickets.size).toBe(0);
  });

  it("wrong owner: another owner's sandbox is NOT_FOUND at create", async () => {
    const result = await createSession({ sid: "auth-2", sandboxId: "sbx-1" });
    expect(result.status).toBe(404);
    expect(tickets.size).toBe(0);
  });

  it("2FA: an unenrolled account past the grace under forced 2FA cannot create a session", async () => {
    users.get("owner-1")!.twoFactorEnabled = false;
    db.appSetting.findMany.mockResolvedValue([
      { key: "force2faPublicUsers", value: "true" },
    ] as never);
    invalidateForceTwoFactorSettingsCache();
    const result = await createSession();
    expect(result.status).toBe(403);
    expect(tickets.size).toBe(0);
  });

  it("a ticket minted before 2FA was disabled cannot upgrade", async () => {
    const { body } = await createSession();
    users.get("owner-1")!.twoFactorEnabled = false;
    db.appSetting.findMany.mockResolvedValue([
      { key: "force2faPublicUsers", value: "true" },
    ] as never);
    invalidateForceTwoFactorSettingsCache();
    await closedWithoutPty(
      upgrade({ protocols: body.protocols as string[], cookie: "sid=auth-1" }),
      { intent: "revoked" },
    );
  });

  it("a non-READY sandbox cannot create a session", async () => {
    sandboxes.get("sbx-1")!.state = "STOPPED";
    const result = await createSession();
    expect(result.status).toBe(409);
    expect(tickets.size).toBe(0);
  });
});

describe("budgets", () => {
  it("createSession is a spend-bearing procedure: 20 per user per minute, then 429 and no ticket", async () => {
    for (let i = 0; i < 20; i += 1) expect((await createSession()).status).toBe(200);
    const before = tickets.size;
    expect((await createSession()).status).toBe(429);
    expect(tickets.size).toBe(before);
  });

  // A well-formed ticket that was never issued: an authenticated attempt that
  // spends the budget and is refused at the consume.
  const unknownTicket = ["wssp.terminal.v1", `wssp.terminal.ticket.${"Z".repeat(43)}`];

  it("upgrade budget (real 30/60 s): anonymous attempts from one IP never deny an owner on that IP", async () => {
    const { body } = await createSession();
    const protocols = body.protocols as string[];
    const attempt = browserProbe();
    for (let i = 0; i < 30; i += 1)
      expect(await attempt({ protocols })).toMatchObject({ kind: "refused", status: 401 });
    // The 31st anonymous attempt from the IP is over its budget.
    const anonymous = await attempt({ protocols });
    expect(anonymous).toMatchObject({ kind: "refused", status: 429, refusal: "RATE_LIMITED" });
    expect(tickets.size).toBe(1);
    // The owner behind the same IP is keyed by user: still admitted.
    const owner = await attempt({ protocols, cookie: "sid=auth-1" });
    expect(owner.kind).toBe("open");
  });

  it("upgrade budget (real 30/60 s): the 31st authenticated attempt is 429, ticket intact, NO PTY; another user on the IP is unaffected", async () => {
    const { body } = await createSession();
    const protocols = body.protocols as string[];
    const attempt = browserProbe();
    // Every refusal is fully answered before the next attempt starts, and the
    // PTY count is re-read after each one: no refused attempt ever opened one.
    const opens = ptyOpens();
    const refused = async (
      options: { protocols: string[]; cookie: string },
      status: number,
      code: string,
    ) => {
      expect(await attempt(options)).toEqual({ kind: "refused", status, refusal: code });
      expect(ptyOpens()).toBe(opens);
    };
    for (let i = 0; i < 30; i += 1)
      await refused({ protocols: unknownTicket, cookie: "sid=auth-1" }, 401, "TICKET_INVALID");
    await refused({ protocols, cookie: "sid=auth-1" }, 429, "RATE_LIMITED");
    expect(tickets.size).toBe(1);
    // owner-2 shares the IP but not the bucket.
    await refused({ protocols: unknownTicket, cookie: "sid=auth-2" }, 401, "TICKET_INVALID");
    // Next minute: the intact ticket (TTL moved past the jump) opens.
    clock += 61_000;
    vi.setSystemTime(clock);
    for (const row of tickets.values()) row.expiresAt = new Date(clock + 30_000);
    const ok = await attempt({ protocols, cookie: "sid=auth-1" });
    expect(ok.kind).toBe("open");
    // Exactly one PTY: none of the refusals above opened one late.
    expect(ptyOpens()).toBe(opens + 1);
  });

  it("upgrade budget store failure fails closed (503), ticket intact, NO PTY; recovery opens", async () => {
    const { body } = await createSession();
    const protocols = body.protocols as string[];
    const spy = vi
      .spyOn(terminalUpgradeLimiter, "consume")
      .mockRejectedValue(new Error("redis down"));
    try {
      await refusedWithoutPty(
        upgrade({ protocols, cookie: "sid=auth-1" }),
        503,
        "SERVICE_UNAVAILABLE",
      );
    } finally {
      spy.mockRestore();
    }
    expect(tickets.size).toBe(1);
    const ok = await upgrade({ protocols, cookie: "sid=auth-1" });
    expect(ok.kind).toBe("open");
    if (ok.kind === "open") ok.close();
  });
});

describe("C55 shutdown refuses new upgrades (C53-FS-2)", () => {
  it("once shutdown begins an upgrade is refused before the ticket is consumed, NO PTY", async () => {
    const { body } = await createSession();
    const protocols = body.protocols as string[];
    shuttingDown = true;
    try {
      await refusedWithoutPty(
        upgrade({ protocols, cookie: "sid=auth-1" }),
        503,
        "SERVICE_UNAVAILABLE",
      );
    } finally {
      shuttingDown = false;
    }
    // Not burned: the refusal happened before any ticket work.
    expect(tickets.size).toBe(1);
    const ok = await upgrade({ protocols, cookie: "sid=auth-1" });
    expect(ok.kind).toBe("open");
    if (ok.kind === "open") ok.close();
  });
});

describe("revocation mid-session closes the socket with 4401", () => {
  async function connected() {
    const opens = ptyOpens();
    const { body } = await createSession();
    const result = await upgrade({ protocols: body.protocols as string[], cookie: "sid=auth-1" });
    if (result.kind !== "open") throw new Error("expected an open terminal");
    const inbox = result;
    await until(() => ptyOpens() > opens, "open");
    const fence = answerOpen();
    await until(() => inbox.text.some((f) => f.type === "ready"), "ready");
    return { inbox, fence };
  }

  it("logout: the session row is deleted → CloseIntent revoked + 4401, PTY asked to close", async () => {
    const { inbox, fence } = await connected();
    sessions.delete("auth-1");
    notifyAuthSessionsRevoked({ userId: "owner-1" });
    expect(await inbox.closed).toEqual({ code: 4401, reason: "revoked" });
    expect(inbox.text.at(-1)).toEqual({
      type: "close",
      code: 4401,
      intent: "revoked",
      requestId: expect.stringMatching(UUID),
    });
    expect(hostFrames("terminal.close").at(-1)).toMatchObject({ intent: "revoked", fence });
  });

  it("ban: an owner authority commit → 4401 revoked", async () => {
    const { inbox } = await connected();
    users.get("owner-1")!.banned = true;
    await withAuthorityChange({ ownerId: "owner-1" }, async () => undefined);
    expect(await inbox.closed).toEqual({ code: 4401, reason: "revoked" });
  });
});

describe("redaction", () => {
  it("no issued ticket ever appears in any log line", () => {
    expect(issued.length).toBeGreaterThan(10);
    const output = logs.join("\n");
    for (const ticket of issued) expect(output).not.toContain(ticket);
  });
});

describe("C55-CO-1: browser liveness through the REAL ws adapter (ping/pong)", () => {
  // The production singleton, with a short heartbeat and a test-driven idle
  // clock for these tests only. The pings and pongs are real (the ws adapter
  // and a child-process browser); only the clock the idle bound is measured
  // on is moved by the test, so no outcome depends on how fast the machine is.
  const liveness = browserTerminalService as unknown as {
    heartbeatMs: number;
    idleMs: number;
    now: () => number;
  };
  let saved: [number, number, () => number];
  let idleClock = 0;
  /** Resolvers waiting for the next browser activity (a pong on a silent socket). */
  let activityWaiters: (() => void)[] = [];
  const nextActivity = () =>
    new Promise<void>((resolve) => {
      activityWaiters.push(resolve);
    });
  beforeEach(() => {
    saved = [liveness.heartbeatMs, liveness.idleMs, liveness.now];
    liveness.heartbeatMs = 50;
    liveness.idleMs = 300;
    idleClock = 1_000_000;
    liveness.now = () => idleClock;
    activityWaiters = [];
    const activity = BrowserTerminal.prototype.activity;
    vi.spyOn(BrowserTerminal.prototype, "activity").mockImplementation(function (
      this: BrowserTerminal,
    ) {
      activity.call(this);
      for (const resolve of activityWaiters.splice(0)) resolve();
    });
  });
  afterEach(() => {
    vi.mocked(BrowserTerminal.prototype.activity).mockRestore();
    [liveness.heartbeatMs, liveness.idleMs, liveness.now] = saved;
  });

  async function connected(autoPong: boolean) {
    const opens = ptyOpens();
    const { body } = await createSession();
    const result = await upgrade({
      protocols: body.protocols as string[],
      cookie: "sid=auth-1",
      autoPong,
    });
    if (result.kind !== "open") throw new Error("expected an open terminal");
    await until(() => ptyOpens() > opens, "terminal.open");
    answerOpen();
    await until(() => result.text.some((frame) => frame.type === "ready"), "ready");
    return result;
  }

  it("a silent browser that answers pings stays open well past the idle bound", async () => {
    const before = hostFrames("terminal.close").length;
    const inbox = await connected(true);
    const { sessionId } = hostFrames("terminal.open").at(-1).fence as TerminalFence;
    // Six heartbeat rounds: after each pong the idle clock moves 3/4 of the
    // bound, so the socket outlives 4.5 idle bounds. Every heartbeat measures
    // from the last pong; without pongs it would be closed by the second round.
    const closedEarly = inbox.closed.then((closed) => {
      throw new Error(`closed while answering pings: ${JSON.stringify(closed)}`);
    });
    // Handled here: the test's own close below settles it after the rounds.
    closedEarly.catch(() => undefined);
    for (let round = 0; round < 6; round += 1) {
      const pong = nextActivity();
      idleClock += (liveness.idleMs * 3) / 4;
      await Promise.race([pong, closedEarly]);
    }
    expect(inbox.text.filter((frame) => frame.type === "close")).toEqual([]);
    expect(hostFrames("terminal.close").slice(before)).toEqual([]);
    inbox.close();
    await inbox.closed;
    // The browser's close reaches the host as `terminal.close` only after the
    // socket settles here; wait for it, or on a loaded machine it lands in
    // the next test's frame window as a second close.
    await until(
      () => hostFrames("terminal.close").some((frame) => frame.fence.sessionId === sessionId),
      "host terminal.close",
    );
  });

  it("a browser that never answers (half-open) is closed detached + timeout with 4401", async () => {
    const before = hostFrames("terminal.close").length;
    const inbox = await connected(false);
    // No pong ever arrives: once the idle bound has passed since the open, the
    // next heartbeat closes the socket.
    idleClock += liveness.idleMs;
    expect(await inbox.closed).toEqual({ code: 4401, reason: "detached" });
    expect(inbox.text.at(-1)).toMatchObject({
      type: "close",
      intent: "detached",
      error: { code: "timeout" },
    });
    expect(hostFrames("terminal.close").slice(before)).toEqual([
      expect.objectContaining({ intent: "detached" }),
    ]);
  });
});

describe("WP8 reattach: v2 subprotocol, resume tickets and the multi-tab budget", () => {
  const TERMINAL_ID = `t${"d".repeat(32)}`;
  type Row = {
    userId: string;
    sessionId: string;
    sandboxId: string;
    hostId: string;
    generation: number;
    openedAt: Date;
    closedAt: Date | null;
  };
  let rows: Map<string, Row>;
  beforeEach(() => {
    state.resumeGraceMs = 120_000;
    // The fake node's per-socket open window runs on the real clock; earlier
    // scenarios' opens must not rate-limit these (a fresh node connection).
    fakeTerminals.removeHostSocket(fakeHost as never);
    rows = new Map([
      [
        TERMINAL_ID,
        {
          userId: "owner-1",
          sessionId: "auth-1",
          sandboxId: "sbx-1",
          hostId: "host-1",
          generation: 3,
          openedAt: new Date(Date.now() - 60_000),
          closedAt: null,
        },
      ],
    ]);
    db.sandboxTerminalSession.findUnique.mockImplementation(
      (async (args: { where: { id: string } }) => rows.get(args.where.id) ?? null) as never,
    );
    db.sandboxTerminalSession.createMany.mockResolvedValue({ count: 1 } as never);
    db.sandboxTerminalSession.updateMany.mockResolvedValue({ count: 1 } as never);
  });
  afterEach(() => {
    state.resumeGraceMs = undefined;
  });

  async function mint(json: Record<string, unknown>, sid = "auth-1") {
    const response = await app.request("/rpc/sandboxTerminals/createSession", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `sid=${sid}`,
        origin: ORIGIN,
        "x-csrf-token": "orpc",
      },
      body: JSON.stringify({ json: { sandboxId: "sbx-1", rows: 24, cols: 80, ...json } }),
    });
    const body = (await response.json()) as { json: Record<string, unknown> };
    if (response.ok) {
      const protocols = body.json.protocols as string[];
      issued.push(protocols[1]!.slice("wssp.terminal.ticket.".length));
    }
    return { status: response.status, body: body.json };
  }
  const resume = (nextOutputSeq = 5) => ({
    version: 2,
    resume: { terminalId: TERMINAL_ID, nextOutputSeq },
  });

  it("v2: the sandbox path selects wssp.terminal.v2; ready carries the id; the row is written", async () => {
    const { status, body } = await mint({ version: 2 });
    expect(status).toBe(200);
    expect((body.protocols as string[])[0]).toBe("wssp.terminal.v2");
    const before = ptyOpens();
    const result = await upgrade({ protocols: body.protocols as string[], cookie: "sid=auth-1" });
    expect(result.kind).toBe("open");
    if (result.kind !== "open") return;
    expect(result.protocol).toBe("wssp.terminal.v2");
    await until(() => ptyOpens() === before + 1, "terminal.open");
    const fence = answerOpen();
    await until(() => result.text.some((f) => f.type === "ready"), "ready");
    expect(result.text.find((f) => f.type === "ready")).toEqual({
      type: "ready",
      rows: 24,
      cols: 80,
      terminalId: fence.sessionId,
      outputSeq: 0,
    });
    await until(() => db.sandboxTerminalSession.createMany.mock.calls.length > 0, "row");
    expect(db.sandboxTerminalSession.createMany.mock.calls[0]?.[0]).toMatchObject({
      data: [{ id: fence.sessionId, userId: "owner-1", sessionId: "auth-1", generation: 3 }],
    });
    result.close();
  });

  it("v1 keeps 4401 and the host path never selects v2", async () => {
    const { body } = await mint({});
    expect((body.protocols as string[])[0]).toBe("wssp.terminal.v1");
    const ticket = (body.protocols as string[])[1]!;
    await refusedWithoutPty(
      upgrade({
        path: "/api/dashboard/hosts/host-1/terminal/ws",
        protocols: ["wssp.terminal.v2", ticket.replace("wssp.terminal.", "wssp.host-terminal.")],
        cookie: "sid=auth-1",
      }),
      400,
      "SUBPROTOCOL_REQUIRED",
    );
  });

  it("a resume ticket reattaches through the normal one-use upgrade and sends terminal.resume", async () => {
    const { status, body } = await mint(resume(5));
    expect(status).toBe(200);
    expect([...tickets.values()].at(-1)).toMatchObject({
      resumeTerminalId: TERMINAL_ID,
      resumeOutputSeq: 5,
    });
    const protocols = body.protocols as string[];
    const result = await upgrade({ protocols, cookie: "sid=auth-1" });
    expect(result.kind).toBe("open");
    if (result.kind !== "open") return;
    await until(() => hostFrames("terminal.resume").length > 0, "terminal.resume");
    expect(hostFrames("terminal.resume").at(-1)).toMatchObject({
      fence: { sessionId: TERMINAL_ID, epoch: 5 },
      nextOutputSeq: 5,
    });
    expect(hostFrames("terminal.open").some((f) => f.fence.sessionId === TERMINAL_ID)).toBe(false);
    // One use: the same ticket never reattaches twice.
    await refusedWithoutPty(upgrade({ protocols, cookie: "sid=auth-1" }), 401, "TICKET_INVALID");
    result.close();
  });

  it("a resume ticket presented on v1 is refused (and burned)", async () => {
    const { body } = await mint(resume());
    const [, ticket] = body.protocols as string[];
    await refusedWithoutPty(
      upgrade({ protocols: ["wssp.terminal.v1", ticket!], cookie: "sid=auth-1" }),
      401,
      "TICKET_INVALID",
    );
    expect(tickets.size).toBe(0);
  });

  it("the mint gate refuses every non-matching row with one answer and no ticket", async () => {
    const base = rows.get(TERMINAL_ID)!;
    for (const change of [
      { sessionId: "auth-other" },
      { userId: "owner-2" },
      { sandboxId: "sbx-2" },
      { hostId: "host-2" },
      { generation: 2 },
      { closedAt: new Date() },
      // Lifetime from the stored openedAt (4 h), never reset.
      { openedAt: new Date(Date.now() - 4 * 3_600_000) },
    ]) {
      rows.set(TERMINAL_ID, { ...base, ...change });
      const refused = await mint(resume());
      expect(refused.status, JSON.stringify(change)).toBe(409);
      expect(refused.body).toMatchObject({
        data: { code: "sandbox.terminal_resume_unavailable" },
      });
    }
    rows.delete(TERMINAL_ID);
    expect((await mint(resume())).status).toBe(409);
    expect(tickets.size).toBe(0);
    // A resume without v2 is a validation error.
    expect((await mint({ resume: { terminalId: TERMINAL_ID, nextOutputSeq: 0 } })).status).toBe(
      400,
    );
  });

  it("the upgrade re-checks the row: closed after mint → readable refusal, NO resume frame", async () => {
    const { body } = await mint(resume());
    rows.get(TERMINAL_ID)!.closedAt = new Date();
    const before = hostFrames("terminal.resume").length;
    const result = await upgrade({ protocols: body.protocols as string[], cookie: "sid=auth-1" });
    expect(result.kind).toBe("open");
    if (result.kind !== "open") return;
    expect(await result.closed).toMatchObject({ code: 4401 });
    expect(result.text.find((f) => f.type === "close")).toMatchObject({
      intent: "expired",
      error: { code: "state_conflict" },
    });
    expect(hostFrames("terminal.resume")).toHaveLength(before);
  });

  it("multi-tab policy within the unchanged budgets: 15 tabs reattach one at a time in one minute", async () => {
    // Each reattach costs one mint point (20/60 s) and one upgrade point
    // (30/60 s). Tabs go one at a time (a Web Lock), so after a deploy
    // ~15 tabs fit both budgets with room to spare; beyond that the client
    // shows "Attach again". Neither budget is raised.
    const ids = Array.from({ length: 15 }, (_, i) => `t${i.toString(16).padStart(32, "e")}`);
    for (const id of ids) rows.set(id, { ...rows.get(TERMINAL_ID)! });
    const attempt = browserProbe();
    for (const [index, id] of ids.entries()) {
      const { status, body } = await mint({
        version: 2,
        resume: { terminalId: id, nextOutputSeq: 0 },
      });
      expect(status, `tab ${index}`).toBe(200);
      // The upgrade budget is spent at the HTTP upgrade; what the node then
      // answers (here: per-host open and capacity limits) is not budgeted.
      // Each tab's socket is closed before the next tab attaches.
      const result = await attempt({ protocols: body.protocols as string[], cookie: "sid=auth-1" });
      expect(result.kind, `tab ${index}`).toBe("open");
    }
    // Headroom remains: 5 more mints pass, the 21st in the minute is refused.
    for (let i = 0; i < 5; i += 1) expect((await mint({ version: 2 })).status).toBe(200);
    const over = await mint(resume());
    expect(over.status).toBe(429);
  });
});
