import { createRouterClient } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "agent-mint-fixture",
    WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY: true,
    WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS: 90,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));
const { env } = await import("@wssp/env/server");
const { default: db } = await import("@wssp/db");
const { agentTokensRouter } = await import("./agent-tokens");
const { createAgentTokenInput, createAgentToken } = await import(
  "../sandbox/services/agent-tokens"
);
const { invalidateForceTwoFactorSettingsCache } = await import("../lib/two-factor-policy");
const user = {
  id: "owner",
  email: "test@example.test",
  name: "Owner",
  emailVerified: true,
  role: "user",
  twoFactorEnabled: true,
  createdAt: new Date(0),
  banned: false,
};
const session = {
  user,
  session: {
    id: "session",
    userId: user.id,
    token: "session",
    expiresAt: new Date(Date.now() + 86_400_000),
  },
} as Session;
const client = () => createRouterClient(agentTokensRouter, { context: { session } });
const input = () => ({
  name: "Agent",
  scopes: ["sandboxes:read" as const],
  resourceMode: "ALL_OWNED" as const,
  expiresAt: new Date(Date.now() + 7 * 86_400_000),
});
const row = () => ({
  id: "key",
  name: "Agent",
  kind: "AGENT_TOKEN",
  ownSandboxesOnly: true,
  resourceMode: "ALL_OWNED",
  poolMode: "ALL_USABLE",
  scopes: ["sandboxes:read"],
  lookupPrefix: "wssp_agent_public",
  createdAt: new Date(),
  expiresAt: input().expiresAt,
  revokedAt: null,
  lastUsedAt: null,
  HostAllowlist: [],
  RevisionAllowlist: [],
  PoolAllowlist: [],
  CredentialAllowlist: [],
});
beforeEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
  env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY = true;
  env.WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS = 90;
  invalidateForceTwoFactorSettingsCache();
  db.appSetting.findMany.mockResolvedValue([]);
  db.$transaction.mockImplementation(async (fn) => fn(db));
  db.sdkKey.count.mockResolvedValue(0);
  db.sdkKey.create.mockResolvedValue(row());
});
it.each([undefined, new Date(0), new Date(Date.now() + 91 * 86_400_000)])(
  "rejects missing, past and over-90-day expiry %s",
  async (expiresAt) => {
    if (expiresAt === undefined)
      expect(createAgentTokenInput.safeParse({ ...input(), expiresAt }).success).toBe(false);
    await expect(client().create({ ...input(), expiresAt } as never)).rejects.toMatchObject({
      code: "BAD_REQUEST",
    });
    expect(db.sdkKey.create).not.toHaveBeenCalled();
  },
);
it("defaults own-only true and stores a domain-separated secret digest", async () => {
  const result = await client().create(input());
  expect(result.secret).toMatch(/^wssp_agent_[A-Za-z0-9_-]{43}$/);
  expect(result.key).toMatchObject({ kind: "AGENT_TOKEN", ownSandboxesOnly: true });
  expect(result.key).not.toHaveProperty("secretDigest");
  expect(db.sdkKey.create).toHaveBeenCalledWith(
    expect.objectContaining({
      data: expect.objectContaining({
        kind: "AGENT_TOKEN",
        ownSandboxesOnly: true,
        expiresAt: expect.any(Date),
        secretDigest: expect.any(String),
      }),
    }),
  );
  expect(
    db.$queryRaw.mock.calls.some(([query]) => query.join("?").includes("pg_advisory_xact_lock")),
  ).toBe(true);
});
it("allows an explicit own-only opt-out", async () => {
  await client().create({ ...input(), ownSandboxesOnly: false });
  expect(db.sdkKey.create).toHaveBeenCalledWith(
    expect.objectContaining({ data: expect.objectContaining({ ownSandboxesOnly: false }) }),
  );
});
it("refuses the eleventh active token inside the transaction", async () => {
  db.sdkKey.count.mockResolvedValue(10);
  await expect(client().create(input())).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "agent_token.limit" },
  });
  expect(db.sdkKey.create).not.toHaveBeenCalled();
  expect(db.sdkKey.count).toHaveBeenCalledWith({
    where: {
      userId: "owner",
      kind: "AGENT_TOKEN",
      revokedAt: null,
      OR: [{ expiresAt: null }, { expiresAt: { gt: expect.any(Date) } }],
    },
  });
});
it("lists only the owner's agent tokens with bounded pagination", async () => {
  db.sdkKey.findMany.mockResolvedValue([row()]);
  await client().list({ limit: 2 });
  expect(db.sdkKey.findMany).toHaveBeenCalledWith(
    expect.objectContaining({
      take: 3,
      where: { AND: [{ userId: "owner", kind: "AGENT_TOKEN", revokedAt: null }] },
    }),
  );
});
it("revocation cannot select an API key or another owner's token", async () => {
  db.sdkKey.findFirst.mockResolvedValue(null);
  await expect(client().revoke({ id: "foreign" })).rejects.toMatchObject({ code: "NOT_FOUND" });
  expect(db.sdkKey.findFirst).toHaveBeenCalledWith({
    where: { id: "foreign", userId: "owner", kind: "AGENT_TOKEN", revokedAt: null },
    select: { id: true },
  });
});
it("requires a person session", async () => {
  const anonymous = createRouterClient(agentTokensRouter, { context: { session: null } });
  await expect(anonymous.create(input())).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  expect(db.sdkKey.create).not.toHaveBeenCalled();
});

it("direct service callers get BAD_REQUEST for an invalid expiry", async () => {
  await expect(
    createAgentToken({ kind: "session", ownerId: "owner" }, { ...input(), expiresAt: new Date(0) }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  expect(db.sdkKey.create).not.toHaveBeenCalled();
});

it("exposes the mint policy only to authenticated sessions", async () => {
  expect(await client().expiryPolicy()).toEqual({ allowNoExpiry: true, maxLifetimeDays: 90 });
  const anonymous = createRouterClient(agentTokensRouter, { context: { session: null } });
  await expect(anonymous.expiryPolicy()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
});
it("requires the expiry key even though null is allowed", () => {
  const { expiresAt: _, ...missing } = input();
  expect(createAgentTokenInput.safeParse(missing).success).toBe(false);
  expect(createAgentTokenInput.safeParse({ ...input(), expiresAt: null }).success).toBe(true);
});
it("allows no-expiry tokens when enabled", async () => {
  await client().create({ ...input(), expiresAt: null });
  expect(db.sdkKey.create).toHaveBeenCalledWith(
    expect.objectContaining({
      data: expect.objectContaining({ expiresAt: null }),
    }),
  );
});
it("refuses null with a clear error when no-expiry minting is disabled", async () => {
  env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY = false;
  await expect(client().create({ ...input(), expiresAt: null })).rejects.toMatchObject({
    code: "BAD_REQUEST",
    message: "Agent tokens without expiry are disabled by this deployment.",
    data: { code: "agent_token.expiry_policy" },
  });
  expect(db.sdkKey.create).not.toHaveBeenCalled();
});
it("accepts exactly the configured maximum and rejects one millisecond more", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-11-13T12:00:00.000Z"));
  env.WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS = 30;
  const maximum = Date.now() + 30 * 86_400_000;
  await client().create({ ...input(), expiresAt: new Date(maximum) });
  db.sdkKey.create.mockClear();
  await expect(
    client().create({ ...input(), expiresAt: new Date(maximum + 1) }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  expect(db.sdkKey.create).not.toHaveBeenCalled();
  vi.useRealTimers();
});
it("accepts an explicit ISO custom date and lifetimes beyond 90 days when configured", async () => {
  env.WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS = 365;
  const expiresAt = new Date(Date.now() + 120 * 86_400_000).toISOString();
  await client().create({ ...input(), expiresAt });
  expect(db.sdkKey.create).toHaveBeenCalledWith(
    expect.objectContaining({
      data: expect.objectContaining({ expiresAt: new Date(expiresAt) }),
    }),
  );
});

it("accepts an explicit custom ISO datetime within the deployment maximum", async () => {
  const expiresAt = new Date(Date.now() + 11 * 86_400_000).toISOString();
  await client().create({ ...input(), expiresAt });
  expect(db.sdkKey.create).toHaveBeenCalledWith(
    expect.objectContaining({
      data: expect.objectContaining({ expiresAt: new Date(expiresAt) }),
    }),
  );
});
it("never mints an agent token with sandboxes:connect (CLI shells are kind API only)", async () => {
  await expect(
    client().create({ ...input(), scopes: ["sandboxes:read", "sandboxes:connect"] }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST", data: { code: "sdk_key.unusable_scopes" } });
  expect(db.sdkKey.create).not.toHaveBeenCalled();
});
