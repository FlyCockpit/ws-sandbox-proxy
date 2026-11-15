import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "consent-test-secret" },
  ADMIN_EMAILS: new Set(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
const { default: prisma } = await import("@wssp/db");
const db = prisma as import("../../test/mock-prisma").MockPrisma;
const { recordMcpConsent, activeMcpConsent, revokedMcpConsent, revokeMcpOAuthTokens } =
  await import("./mcp-consent");
const input = () => ({
  userId: "owner",
  sessionId: "session",
  clientId: "client",
  referenceId: "reference",
  requestedScopes: ["sandboxes:read", "hosts:read"],
  choices: { scopes: ["sandboxes:read"], resourceMode: "ALL_OWNED" },
});
beforeEach(() => {
  vi.clearAllMocks();
  db.$transaction.mockImplementation(async (fn) => fn(db));
  db.$queryRaw.mockResolvedValue([{ now: new Date() }]);
  db.user.findUnique.mockResolvedValue({
    id: "owner",
    banned: false,
    banExpires: null,
    deletionRequestedAt: null,
    twoFactorEnabled: true,
    createdAt: new Date(0),
    role: "user",
  } as never);
  db.session.findFirst.mockResolvedValue({ id: "session" } as never);
  db.appSetting.findMany.mockResolvedValue([]);
  db.mcpGrant.findUnique.mockResolvedValue(null);
  db.sdkKey.create.mockResolvedValue({ id: "backing-key" } as never);
});
it("records consent in a secretless OAUTH_GRANT key with own-only true by default", async () => {
  await recordMcpConsent(input());
  expect(db.sdkKey.create).toHaveBeenCalledWith(
    expect.objectContaining({
      data: expect.objectContaining({
        kind: "OAUTH_GRANT",
        ownSandboxesOnly: true,
        scopes: ["sandboxes:read"],
        lookupPrefix: null,
        secretDigest: null,
      }),
    }),
  );
  expect(db.mcpGrant.create).toHaveBeenCalledWith(
    expect.objectContaining({
      data: {
        userId: "owner",
        clientId: "client",
        referenceId: "reference",
        sdkKeyId: "backing-key",
      },
    }),
  );
});
it("refuses unrequested scopes before writes", async () => {
  await expect(
    recordMcpConsent({
      ...input(),
      choices: { scopes: ["hosts:execute"], resourceMode: "ALL_OWNED" },
    }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  expect(db.sdkKey.create).not.toHaveBeenCalled();
});
it("refuses a foreign host allowlist and never revives a revoked generation", async () => {
  db.sandboxHost.findMany.mockResolvedValue([]);
  await expect(
    recordMcpConsent({
      ...input(),
      choices: { scopes: ["hosts:read"], resourceMode: "ALLOWLIST", hostIds: ["foreign-host"] },
    }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  db.mcpGrant.findUnique.mockResolvedValue({
    sdkKeyId: "key",
    revokedAt: new Date(),
    SdkKey: { revokedAt: null },
  } as never);
  await expect(recordMcpConsent(input())).rejects.toMatchObject({ code: "FORBIDDEN" });
  expect(db.sdkKey.create).not.toHaveBeenCalled();
  expect(db.sdkKey.update).not.toHaveBeenCalled();
});
it("requires a live owner and replaces existing grant choices without changing its identity", async () => {
  db.mcpGrant.findUnique.mockResolvedValue({
    id: "grant",
    sdkKeyId: "key",
    revokedAt: null,
    SdkKey: {
      revokedAt: null,
      scopes: ["sandboxes:read"],
      resourceMode: "ALL_OWNED",
      poolMode: "ALL_USABLE",
      ownSandboxesOnly: false,
      CredentialAllowlist: [],
    },
  } as never);
  await recordMcpConsent({ ...input(), choices: { ...input().choices, ownSandboxesOnly: false } });
  expect(db.sdkKey.update).toHaveBeenCalledWith(
    expect.objectContaining({
      where: { id: "key" },
      data: expect.objectContaining({
        ownSandboxesOnly: false,
        HostAllowlist: { deleteMany: {}, create: [] },
      }),
    }),
  );
  expect(db.mcpGrant.create).not.toHaveBeenCalled();
  db.user.findUnique.mockResolvedValue({ deletionRequestedAt: new Date() } as never);
  await expect(recordMcpConsent(input())).rejects.toThrow();
});
it("requires the exact live generation for token claims", async () => {
  expect(
    await activeMcpConsent({ userId: "owner", clientId: "client", referenceId: "reference" }),
  ).toBeNull();
  db.mcpGrant.findUnique.mockResolvedValue({
    id: "grant",
    revokedAt: null,
    SdkKey: { kind: "OAUTH_GRANT", revokedAt: null, expiresAt: null },
  } as never);
  expect(
    await activeMcpConsent({ userId: "owner", clientId: "client", referenceId: "reference" }),
  ).toBe("grant");
  db.mcpGrant.findUnique.mockResolvedValue({
    id: "grant",
    revokedAt: null,
    SdkKey: { kind: "OAUTH_GRANT", revokedAt: new Date(), expiresAt: null },
  } as never);
  expect(
    await activeMcpConsent({ userId: "owner", clientId: "client", referenceId: "reference" }),
  ).toBeNull();
  expect(
    await revokedMcpConsent({ userId: "owner", clientId: "client", referenceId: "reference" }),
  ).toBe(true);
});
it("deletes access and refresh tokens only for the revoking user and client", async () => {
  await revokeMcpOAuthTokens("owner", "client");
  expect(db.oauthAccessToken.deleteMany).toHaveBeenCalledWith({
    where: { userId: "owner", clientId: "client" },
  });
  expect(db.oauthRefreshToken.deleteMany).toHaveBeenCalledWith({
    where: { userId: "owner", clientId: "client" },
  });
});

it("checks durable session ownership, expiry and impersonation before any backing writes", async () => {
  db.session.findFirst.mockResolvedValue(null);
  await expect(recordMcpConsent(input())).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  expect(db.session.findFirst).toHaveBeenCalledWith({
    where: {
      id: "session",
      userId: "owner",
      expiresAt: { gt: expect.any(Date) },
      impersonatedBy: null,
    },
    select: { id: true },
  });
  expect(db.sdkKey.create).not.toHaveBeenCalled();
  expect(db.sdkKey.update).not.toHaveBeenCalled();
});
it.each([
  { scopes: ["sandboxes:read", "hosts:read"] },
  { resourceMode: "ALL_OWNED", hostIds: [], templateRevisionIds: [] },
  { poolMode: "ALL_USABLE" },
  { ownSandboxesOnly: false },
  { hostIds: ["new-host"] },
  { credentialIds: ["new-login"] },
  { scope: "sandboxes:read offline_access" },
])("refuses widening an existing generation: %j", async (change) => {
  db.mcpGrant.findUnique.mockResolvedValue({
    id: "grant",
    sdkKeyId: "key",
    revokedAt: null,
    SdkKey: {
      revokedAt: null,
      scopes: ["sandboxes:read"],
      resourceMode: "ALLOWLIST",
      poolMode: "SELECTED",
      ownSandboxesOnly: true,
      HostAllowlist: [{ sandboxHostId: "known-host" }],
      RevisionAllowlist: [{ templateRevisionId: "known-revision" }],
      PoolAllowlist: [],
      CredentialAllowlist: [],
    },
  } as never);
  db.oauthConsent.findFirst.mockResolvedValue({ scopes: ["sandboxes:read"] } as never);
  await expect(
    recordMcpConsent({
      ...input(),
      choices: {
        scopes: ["sandboxes:read"],
        resourceMode: "ALLOWLIST",
        poolMode: "SELECTED",
        hostIds: ["known-host"],
        templateRevisionIds: ["known-revision"],
        ...change,
      },
    }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  expect(db.sdkKey.update).not.toHaveBeenCalled();
  expect(db.sdkKey.create).not.toHaveBeenCalled();
});
