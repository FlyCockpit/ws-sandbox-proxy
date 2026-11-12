import { Hono } from "hono";
import { beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ host: vi.fn(), guest: vi.fn() }));
vi.mock("@wssp/api/sandbox/host-terminal-tickets", () => ({
  consumeHostTerminalTicket: state.host,
}));
vi.mock("@wssp/api/sandbox/terminal-tickets", () => ({
  consumeTerminalTicket: state.guest,
  isHostTerminalBinding: (b: { kind?: string }) => b.kind === "host",
}));
vi.mock("./browser-terminal.js", () => ({ browserTerminalService: { shuttingDown: false } }));
vi.mock("../rate-limit.js", () => ({
  terminalUpgradeLimiter: {},
  createRateLimiterMiddleware: () => async (_c: unknown, next: () => Promise<void>) => next(),
}));
vi.mock("../request-origin.js", () => ({
  isAllowedBrowserOrigin: (origin: string) => origin === "https://wssp.test",
}));
vi.mock("../session-middleware.js", () => ({
  sessionMiddleware: async (
    c: { set(key: string, value: unknown): void },
    next: () => Promise<void>,
  ) => {
    c.set("session", { user: { id: "owner" }, session: { id: "session" } });
    await next();
  },
}));
const {
  createBrowserTerminalUpgradeMiddleware,
  HOST_TERMINAL_ROUTE,
  BROWSER_TERMINAL_ROUTE,
  selectWebSocketSubprotocol,
} = await import("./browser-terminal-upgrade.js");
const token = "a".repeat(43);
const app = new Hono();
for (const route of [HOST_TERMINAL_ROUTE, BROWSER_TERMINAL_ROUTE]) {
  app.use(route, createBrowserTerminalUpgradeMiddleware());
  app.get(route, (c) => c.json({ upgraded: true }));
}
beforeEach(() => {
  vi.clearAllMocks();
  state.host.mockResolvedValue({
    kind: "host",
    userId: "owner",
    sessionId: "session",
    hostId: "host",
  });
  state.guest.mockResolvedValue({ userId: "owner", sessionId: "session", sandboxId: "guest" });
});
function request(
  kind: "hosts" | "sandboxes",
  prefix: string,
  extras: Record<string, string | undefined> = {},
) {
  const headers = new Headers({
    upgrade: "websocket",
    origin: "https://wssp.test",
    "sec-websocket-protocol": `wssp.terminal.v1, ${prefix}${token}`,
  });
  for (const [name, value] of Object.entries(extras))
    if (value !== undefined) headers.set(name, value);
  return app.request(`/api/dashboard/${kind}/${kind === "hosts" ? "host" : "guest"}/terminal/ws`, {
    headers,
  });
}
it.each(["hosts", "sandboxes"] as const)(
  "%s chooses only its own ticket parser BEFORE consuming",
  async (kind) => {
    const correct = kind === "hosts" ? "wssp.host-terminal.ticket." : "wssp.terminal.ticket.";
    const opposite = kind === "hosts" ? "wssp.terminal.ticket." : "wssp.host-terminal.ticket.";
    expect((await request(kind, opposite)).status).toBe(400);
    expect(state.host).not.toHaveBeenCalled();
    expect(state.guest).not.toHaveBeenCalled();
    const accepted = await request(kind, correct);
    expect(accepted.status).toBe(200);
    expect(await accepted.text()).not.toContain(token);
    expect(kind === "hosts" ? state.host : state.guest).toHaveBeenCalledExactlyOnceWith(token);
    expect(kind === "hosts" ? state.guest : state.host).not.toHaveBeenCalled();
  },
);
it("path mismatches and relabeled guest token burn/refuse without PTY open", async () => {
  state.host.mockResolvedValueOnce(null);
  expect((await request("hosts", "wssp.host-terminal.ticket.")).status).toBe(401);
  state.host.mockResolvedValueOnce({
    kind: "host",
    userId: "owner",
    sessionId: "session",
    hostId: "other",
  });
  expect((await request("hosts", "wssp.host-terminal.ticket.")).status).toBe(401);
});
it.each([
  { authorization: "Bearer wssp_sdk_test" },
  { origin: "https://evil.test" },
  { "sec-websocket-protocol": `wssp.terminal.v1, wssp.host-terminal.ticket.${token}, extra` },
])("host upgrade preserves plane/origin/shape refusal before consume: %j", async (headers) => {
  expect(
    (await request("hosts", "wssp.host-terminal.ticket.", headers)).status,
  ).toBeGreaterThanOrEqual(400);
  expect(state.host).not.toHaveBeenCalled();
});
it("both paths select the public protocol and never echo a ticket", () => {
  expect(
    selectWebSocketSubprotocol(
      new Set(["wssp.terminal.v1", `wssp.host-terminal.ticket.${token}`]),
      "/api/dashboard/hosts/host/terminal/ws",
    ),
  ).toBe("wssp.terminal.v1");
});
