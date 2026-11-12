import { describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  sandboxTemplateBuild: { findFirst: vi.fn(), findMany: vi.fn() },
  sdkKey: { findUnique: vi.fn() },
  $transaction: vi.fn(),
  $queryRaw: vi.fn(),
}));
vi.mock("@wssp/db", () => ({ default: db }));
vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
const budget = vi.hoisted(() => vi.fn(async () => {}));
vi.mock("../sandbox/budgets", () => ({
  consumeSandboxWriteBudget: budget,
  consumeCreateConnectBudget: async () => {},
}));
/** The stored key row the real authenticator revalidates. */
function storeKey(mode: "ALL_OWNED" | "ALLOWLIST", scopes: readonly string[]) {
  db.sdkKey.findUnique.mockResolvedValue({
    id: `key-${mode}`,
    userId: "owner-1",
    resourceMode: mode,
    poolMode: mode === "ALL_OWNED" ? "ALL_USABLE" : "SELECTED",
    scopes: [...scopes],
    revokedAt: null,
    expiresAt: null,
    HostAllowlist: mode === "ALL_OWNED" ? [] : [{ sandboxHostId: "h" }],
    RevisionAllowlist: mode === "ALL_OWNED" ? [] : [{ templateRevisionId: "r" }],
    PoolAllowlist: [],
    User: {
      banned: false,
      banExpires: null,
      twoFactorEnabled: true,
      createdAt: new Date("2020-01-01"),
      role: "user",
    },
  });
}

const { visibleBuildWhere } = await import("./visibility");
const views = await import("./views");
const { loadBuildPrincipal } = await import("./principal");
const { sessionPrincipal } = await import("../sandbox/contracts");
const { SERVICE_SCOPES } = await import("../lib/service-scopes");

type Scope = (typeof SERVICE_SCOPES)[number];
function key(mode: "ALL_OWNED" | "ALLOWLIST", scopes: readonly Scope[] = SERVICE_SCOPES) {
  const principal = {
    kind: "sdkKey" as const,
    ownerId: "owner-1",
    keyId: `key-${mode}`,
    expiresAt: null,
    resourceMode: mode,
    scopes: new Set<Scope>(scopes),
    allowedHostIds: mode === "ALL_OWNED" ? ("allOwned" as const) : new Set<string>(["h"]),
    allowedRevisionIds: mode === "ALL_OWNED" ? ("allOwned" as const) : new Set<string>(["r"]),
    allowedPoolIds: mode === "ALL_OWNED" ? ("allUsable" as const) : new Set<string>(),
  };
  return principal;
}
const NOTHING = { id: { in: [] } };

/** Rows a where-clause matches, evaluated in memory (the clause is flat). */
function matches(where: Record<string, unknown>, row: Record<string, unknown>): boolean {
  if ("id" in where && typeof where.id === "object") return false;
  return Object.entries(where).every(([field, value]) => row[field] === value);
}
const builds = [
  { id: "by-session", userId: "owner-1", principalKind: "session", authorizingKeyId: null },
  {
    id: "by-allowlist",
    userId: "owner-1",
    principalKind: "sdkKey",
    authorizingKeyId: "key-ALLOWLIST",
  },
  { id: "by-other-key", userId: "owner-1", principalKind: "sdkKey", authorizingKeyId: "key-other" },
  { id: "by-system", userId: "owner-1", principalKind: "system", authorizingKeyId: null },
  { id: "other-owner", userId: "owner-2", principalKind: "session", authorizingKeyId: null },
];
const visible = (where: Record<string, unknown>) =>
  builds.filter((row) => matches(where, row)).map((row) => row.id);

describe("visibleBuildWhere (r3 N20)", () => {
  it("a session sees every build of its owner, never another owner's", () => {
    const where = visibleBuildWhere(sessionPrincipal("owner-1"));
    expect(where).toEqual({ userId: "owner-1" });
    expect(visible(where)).toEqual(["by-session", "by-allowlist", "by-other-key", "by-system"]);
  });

  it("an ALL_OWNED key sees every build of its owner (session, other keys, system)", () => {
    const where = visibleBuildWhere(key("ALL_OWNED"));
    expect(visible(where)).toEqual(["by-session", "by-allowlist", "by-other-key", "by-system"]);
  });

  it("an ALLOWLIST key sees only builds it accepted itself", () => {
    const where = visibleBuildWhere(key("ALLOWLIST"));
    expect(where).toEqual({
      userId: "owner-1",
      principalKind: "sdkKey",
      authorizingKeyId: "key-ALLOWLIST",
    });
    expect(visible(where)).toEqual(["by-allowlist"]);
  });

  it("a key without templates:build sees nothing", () => {
    for (const mode of ["ALL_OWNED", "ALLOWLIST"] as const)
      expect(
        visibleBuildWhere(
          key(
            mode,
            SERVICE_SCOPES.filter((s) => s !== "templates:build"),
          ),
        ),
      ).toEqual(NOTHING);
  });

  it("a build principal sees no build through the routes", async () => {
    db.sandboxTemplateBuild.findFirst.mockResolvedValueOnce({
      id: "b1",
      userId: "owner-1",
      authorizingKeyId: null,
    });
    const build = await loadBuildPrincipal(db as never, "b1", "owner-1");
    expect(build).not.toBeNull();
    expect(visibleBuildWhere(build!)).toEqual(NOTHING);
  });
});

describe("template-build entries require templates:build before any IO", () => {
  const withoutScope = () =>
    Object.assign(
      key(
        "ALL_OWNED",
        SERVICE_SCOPES.filter((s) => s !== "templates:build"),
      ),
      {},
    );
  const calls: [string, (p: never) => Promise<unknown>][] = [
    ["getTemplateBuild", (p) => views.getTemplateBuild(p, { id: "b1" })],
    ["listTemplateBuilds", (p) => views.listTemplateBuilds(p, {})],
    ["getTemplateBuildLogs", (p) => views.getTemplateBuildLogs(p, { id: "b1", step: 0 })],
    ["cancelTemplateBuild", (p) => views.cancelTemplateBuild(p, { id: "b1" })],
    [
      "createTemplateBuild",
      (p) =>
        views.createTemplateBuild(p, {
          idempotencyKey: "k",
          template: { slug: "t" },
          recipe: {},
          sandboxHostId: "h",
        }),
    ],
  ];
  for (const [name, call] of calls)
    it(`${name} refuses FORBIDDEN without the scope`, async () => {
      vi.clearAllMocks();
      const principal = withoutScope();
      storeKey("ALL_OWNED", [...principal.scopes]);
      await expect(call(principal as never)).rejects.toMatchObject({
        code: "FORBIDDEN",
        message: expect.not.stringContaining("inactive"),
      });
      expect(db.sdkKey.findUnique).toHaveBeenCalled();
      expect(db.sandboxTemplateBuild.findFirst).not.toHaveBeenCalled();
      expect(db.sandboxTemplateBuild.findMany).not.toHaveBeenCalled();
      expect(db.$transaction).not.toHaveBeenCalled();
      expect(budget).not.toHaveBeenCalled();
    });

  it("a visible-build miss is NOT_FOUND (cross-owner ids look absent)", async () => {
    vi.clearAllMocks();
    const principal = key("ALL_OWNED");
    storeKey("ALL_OWNED", SERVICE_SCOPES);
    db.sandboxTemplateBuild.findFirst.mockResolvedValue(null);
    await expect(views.getTemplateBuild(principal as never, { id: "b1" })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    expect(db.sandboxTemplateBuild.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          AND: [{ userId: "owner-1" }, { id: "b1" }],
        },
      }),
    );
  });
});

describe("getTemplateBuildFailureTail (owner-only projection, plan §5)", () => {
  it("returns the owner's failure tail as text through the session visibility rule", async () => {
    vi.clearAllMocks();
    db.sandboxTemplateBuild.findFirst.mockResolvedValue({
      failureTail: new TextEncoder().encode("E: Unable to locate package nope\n"),
    });
    await expect(
      views.getTemplateBuildFailureTail(sessionPrincipal("owner-1"), { id: "b1" }),
    ).resolves.toEqual({ tail: "E: Unable to locate package nope\n" });
    expect(db.sandboxTemplateBuild.findFirst).toHaveBeenCalledWith({
      where: { AND: [{ userId: "owner-1" }, { id: "b1", userId: "owner-1" }] },
      select: { failureTail: true },
    });
  });

  it("returns null when the build kept no tail", async () => {
    vi.clearAllMocks();
    db.sandboxTemplateBuild.findFirst.mockResolvedValue({ failureTail: null });
    await expect(
      views.getTemplateBuildFailureTail(sessionPrincipal("owner-1"), { id: "b1" }),
    ).resolves.toEqual({ tail: null });
  });

  it("is NOT_FOUND for a build the session cannot see", async () => {
    vi.clearAllMocks();
    db.sandboxTemplateBuild.findFirst.mockResolvedValue(null);
    await expect(
      views.getTemplateBuildFailureTail(sessionPrincipal("owner-1"), { id: "b1" }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("refuses every SDK key before any read, even an ALL_OWNED one", async () => {
    vi.clearAllMocks();
    storeKey("ALL_OWNED", SERVICE_SCOPES);
    await expect(
      views.getTemplateBuildFailureTail(key("ALL_OWNED") as never, { id: "b1" }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(db.sandboxTemplateBuild.findFirst).not.toHaveBeenCalled();
  });
});
