import { beforeEach, describe, expect, it, vi } from "vitest";

const policy = vi.hoisted(() => ({
  read: vi.fn<(hostId: string, ownerId: string) => unknown>(() => undefined),
}));
vi.mock("./host-terminal-policy", () => ({
  readHostTerminalPolicy: (hostId: string, ownerId: string) => policy.read(hostId, ownerId),
}));
vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});

const { default: db } = await import("@wssp/db");
const {
  HOST_TARGETS_MAX,
  listHostTargets,
  describeUserAgent,
  endLiveTerminal,
  LIVE_TERMINALS_MAX,
  listLiveTerminals,
  registerLiveTerminalDirectory,
} = await import("./live-terminals");
type Entry = import("./live-terminals").LiveTerminalEntry;

const at = (minute: number) => new Date(Date.UTC(2026, 10, 26, 0, minute));
const sandboxEntry = (id: string, userId: string, minute: number, sessionId = "s-1"): Entry => ({
  id,
  userId,
  target: { kind: "sandbox", sandboxId: `sbx-${id}` },
  sessionId,
  status: "attached",
  openedAt: at(minute),
  lastActivityAt: at(minute + 1),
});

let entries: Entry[];
const ended: [string, string][] = [];

beforeEach(() => {
  vi.clearAllMocks();
  entries = [];
  ended.length = 0;
  registerLiveTerminalDirectory({
    // A deliberately careless directory: the API must still filter by owner.
    list: () => entries,
    end: async (userId, id) => {
      ended.push([userId, id]);
      return entries.some((entry) => entry.id === id && entry.userId === userId);
    },
  });
  db.sandbox.findMany.mockResolvedValue([]);
  db.sandboxHost.findMany.mockResolvedValue([]);
  db.session.findMany.mockResolvedValue([]);
});

describe("listLiveTerminals", () => {
  it("without a relay (worker, tests) lists nothing and reads nothing", async () => {
    registerLiveTerminalDirectory(null);
    await expect(listLiveTerminals({ userId: "u-1", sessionId: "s-1" })).resolves.toEqual({
      terminals: [],
      truncated: false,
    });
    expect(db.sandbox.findMany).not.toHaveBeenCalled();
  });

  it("another user's terminals never appear, even from a directory that returns them", async () => {
    entries = [sandboxEntry("a", "u-1", 1), sandboxEntry("b", "u-2", 2, "s-other")];
    const { terminals } = await listLiveTerminals({ userId: "u-1", sessionId: "s-1" });
    expect(terminals.map((t) => t.id)).toEqual(["a"]);
    // Every enrichment read is owner-scoped and names only the caller's ids.
    expect(db.sandbox.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: { in: ["sbx-a"] }, userId: "u-1" } }),
    );
    expect(db.session.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: { in: ["s-1"] }, userId: "u-1" } }),
    );
    expect(db.sandboxHost.findMany).not.toHaveBeenCalled();
  });

  it("joins names and states, marks this browser, never returns the session id", async () => {
    entries = [
      sandboxEntry("a", "u-1", 1),
      {
        id: "h",
        userId: "u-1",
        target: { kind: "host", hostId: "host-1" },
        sessionId: "s-2",
        status: "connecting",
        openedAt: at(5),
        lastActivityAt: at(5),
      },
    ];
    db.sandbox.findMany.mockResolvedValue([
      { id: "sbx-a", name: "dev box", state: "READY" },
    ] as never);
    db.sandboxHost.findMany.mockResolvedValue([
      { id: "host-1", label: "halo", status: "CONNECTED" },
    ] as never);
    db.session.findMany.mockResolvedValue([
      {
        id: "s-2",
        userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
      },
    ] as never);
    const { terminals } = await listLiveTerminals({ userId: "u-1", sessionId: "s-1" });
    // Newest first.
    expect(terminals).toEqual([
      {
        id: "h",
        status: "connecting",
        openedAt: at(5),
        lastActivityAt: at(5),
        thisBrowser: false,
        device: { browser: "Firefox", os: "Linux" },
        target: { kind: "host", id: "host-1", name: "halo", status: "CONNECTED" },
      },
      {
        id: "a",
        status: "attached",
        openedAt: at(1),
        lastActivityAt: at(2),
        thisBrowser: true,
        device: { browser: null, os: null },
        target: { kind: "sandbox", id: "sbx-a", name: "dev box", state: "READY" },
      },
    ]);
    expect(JSON.stringify(terminals)).not.toContain("s-2");
  });

  it("a target the owner no longer has keeps a null name", async () => {
    entries = [sandboxEntry("a", "u-1", 1)];
    const { terminals } = await listLiveTerminals({ userId: "u-1", sessionId: "s-1" });
    expect(terminals[0]!.target).toEqual({ kind: "sandbox", id: "sbx-a", name: null, state: null });
  });

  it("is bounded and says so", async () => {
    entries = Array.from({ length: LIVE_TERMINALS_MAX + 3 }, (_, i) =>
      sandboxEntry(`e${i}`, "u-1", i % 50),
    );
    const result = await listLiveTerminals({ userId: "u-1", sessionId: "s-1" });
    expect(result.terminals).toHaveLength(LIVE_TERMINALS_MAX);
    expect(result.truncated).toBe(true);
  });
});

describe("endLiveTerminal", () => {
  it("asks the directory for the caller only", async () => {
    entries = [sandboxEntry("a", "u-2", 1)];
    expect(await endLiveTerminal({ userId: "u-1" }, "a")).toBe(false);
    expect(ended).toEqual([["u-1", "a"]]);
    registerLiveTerminalDirectory(null);
    expect(await endLiveTerminal({ userId: "u-2" }, "a")).toBe(false);
  });

  it("an end that could not be made durable is SERVICE_UNAVAILABLE, with no detail", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    registerLiveTerminalDirectory({
      list: () => [],
      end: async () => {
        throw new Error("connection to db-secret-host refused");
      },
    });
    const error = await endLiveTerminal({ userId: "u-1" }, "a").catch((e: unknown) => e);
    expect(error).toMatchObject({ code: "SERVICE_UNAVAILABLE" });
    expect(String((error as Error).message)).not.toContain("db-secret-host");
  });
});

describe("describeUserAgent", () => {
  it.each([
    [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
      { browser: "Chrome", os: "macOS" },
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
      { browser: "Edge", os: "Windows" },
    ],
    [
      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
      { browser: "Safari", os: "iOS" },
    ],
    [
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36",
      { browser: "Chrome", os: "Linux" },
    ],
    [
      "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36",
      { browser: "Chrome", os: "Android" },
    ],
    ["curl/8.5.0", { browser: null, os: null }],
    [null, { browser: null, os: null }],
  ])("%s", (ua, expected) => {
    expect(describeUserAgent(ua)).toEqual(expected);
  });
});

describe("listHostTargets", () => {
  const row = (id: string, vetoed: Date | null = null) => ({
    id,
    label: id,
    status: "CONNECTED",
    lastConnectedAt: at(1),
    lastHeartbeatAt: at(2),
    deletionRequestedAt: null,
    quarantinedAt: null,
    hostTerminalVetoedAt: vetoed,
  });

  it("reads only the caller's own, live hosts, bounded, and says whether a host terminal can open", async () => {
    db.sandboxHost.findMany.mockResolvedValue([
      row("on"),
      row("off"),
      row("vetoed", at(3)),
      row("offline"),
    ] as never);
    policy.read.mockImplementation((hostId) =>
      hostId === "offline"
        ? undefined
        : {
            hostTerminal: hostId !== "off",
            requireHostTerminalTotp: true,
            policyRevision: 1,
            epoch: 1,
          },
    );
    const result = await listHostTargets({ userId: "u-1" });
    expect(db.sandboxHost.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { userId: "u-1", deletionRequestedAt: null },
        take: HOST_TARGETS_MAX + 1,
      }),
    );
    expect(policy.read.mock.calls.every(([, ownerId]) => ownerId === "u-1")).toBe(true);
    expect(result.hosts.map((h) => [h.id, h.hostTerminal])).toEqual([
      ["on", true],
      ["off", false],
      ["vetoed", false],
      ["offline", null],
    ]);
    // Nothing else of the policy, and not the veto timestamp, leaves.
    expect(JSON.stringify(result)).not.toMatch(
      /policyRevision|requireHostTerminalTotp|hostTerminalVetoedAt/,
    );
    expect(result.more).toBe(false);
  });

  it("says when there are more hosts than it lists", async () => {
    db.sandboxHost.findMany.mockResolvedValue(
      Array.from({ length: HOST_TARGETS_MAX + 1 }, (_, i) => row(`h${i}`)) as never,
    );
    const result = await listHostTargets({ userId: "u-1" });
    expect(result.hosts).toHaveLength(HOST_TARGETS_MAX);
    expect(result.more).toBe(true);
  });
});
