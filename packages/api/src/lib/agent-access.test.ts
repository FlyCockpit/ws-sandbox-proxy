import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("../sandbox/sharing-authority", async (original) => ({
  ...(await original<typeof import("../sandbox/sharing-authority")>()),
  requirePoolUse: vi.fn(async () => ({})),
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "agent-access-fixture",
    WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY: false,
    WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS: 1,
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
const { default: db } = await import("@wssp/db");
const access = await import("./sdk-key-access");
const { SERVICE_SCOPES } = await import("./service-scopes");
const crypto = await import("@wssp/db/credential-security");
const { sandboxListReadQuery, sandboxListPage } = await import("../sandbox/sandbox-list");
const user = {
  banned: false,
  banExpires: null,
  deletionRequestedAt: null,
  twoFactorEnabled: true,
  role: "user",
  createdAt: new Date(0),
};
function fixture(ownSandboxesOnly = true) {
  const row = {
    id: "key",
    userId: "owner",
    kind: "API" as const,
    ownSandboxesOnly,
    resourceMode: "ALL_OWNED" as const,
    poolMode: "ALL_USABLE" as const,
    scopes: [...SERVICE_SCOPES],
    revokedAt: null,
    expiresAt: null,
    HostAllowlist: [],
    RevisionAllowlist: [],
    PoolAllowlist: [],
    User: user,
  };
  db.sdkKey.findUnique.mockResolvedValue(row);
  db.sandbox.findFirst.mockResolvedValue({
    id: "sandbox",
    sandboxHostId: "host",
    hostOwnerId: "owner",
    usagePoolId: null,
    originPoolId: null,
    templateRevisionId: "rev",
    purpose: "WORKLOAD",
  } as never);
  db.sandboxOperation.findFirst.mockResolvedValue({ authorizingKeyId: "other" } as never);
  db.sandboxHost.findFirst.mockResolvedValue({ id: "host" } as never);
  db.user.findUnique.mockResolvedValue(user as never);
  return {
    kind: "sdkKey",
    credentialKind: "API",
    ownSandboxesOnly,
    keyId: "key",
    ownerId: "owner",
    expiresAt: null,
    resourceMode: "ALL_OWNED",
    scopes: new Set(SERVICE_SCOPES),
    allowedHostIds: "allOwned",
    allowedRevisionIds: "allOwned",
    allowedPoolIds: "allUsable",
  } satisfies access.ServicePrincipal;
}
beforeEach(() => {
  vi.clearAllMocks();
  db.appSetting.findMany.mockResolvedValue([]);
});
it("all-owned own-only applies a creator predicate to list queries", () => {
  const p = fixture();
  expect(access.serviceResourceFilter(p, "sandbox")).toMatchObject({
    Operations: { some: { authorizingKeyId: "key", kind: "CREATE_SANDBOX" } },
  });
  expect(access.serviceResourceFilter(fixture(false), "sandbox")).toEqual({ userId: "owner" });
});
it("own-only cannot use retained creator reads of another key", async () => {
  const p = fixture();
  await expect(
    access.authorizeServiceAction(p, "sandboxes.get", { sandboxId: "sandbox" }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  db.sandboxOperation.findFirst.mockResolvedValue({ authorizingKeyId: "key" } as never);
  await expect(
    access.authorizeServiceAction(p, "sandboxes.get", { sandboxId: "sandbox" }),
  ).resolves.toMatchObject({ sandboxId: "sandbox" });
});
it("own-only dispatch refuses cleanup accepted by a sibling credential", async () => {
  fixture();
  const input = {
    ownerId: "owner",
    principal: { kind: "sdkKey" as const, keyId: "key" },
    context: {
      sandboxId: "sandbox",
      sandboxHostId: "host",
      templateRevisionId: "rev",
      originPoolId: null,
    },
    cleanup: true,
  };
  expect(await access.checkAcceptedDispatchAuthority(input)).toBe("inactive");
  db.sandboxOperation.findFirst.mockResolvedValue({ authorizingKeyId: "key" } as never);
  expect(await access.checkAcceptedDispatchAuthority(input)).toBe("active");
});
it("own-only changes invalidate list cursors", async () => {
  const broad = await sandboxListReadQuery(fixture(false), { limit: 1 });
  const { nextCursor } = sandboxListPage(
    [
      { id: "sandbox", createdAt: new Date(0) },
      { id: "next", createdAt: new Date(0) },
    ],
    broad,
  );
  await expect(
    sandboxListReadQuery(fixture(), { limit: 1, cursor: nextCursor! }),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
});
it("own-only does not get the retained read exception without a creator proof", async () => {
  const p = fixture();
  db.sandboxHost.findFirst.mockResolvedValue(null);
  await expect(
    access.authorizeServiceAction(p, "operations.getReceipt", {
      sandboxHostId: "deleted-host",
      originPoolId: null,
    }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  const unrestricted = fixture(false);
  db.sandboxHost.findFirst.mockResolvedValue(null);
  await expect(
    access.authorizeServiceAction(unrestricted, "operations.getReceipt", {
      sandboxHostId: "deleted-host",
      originPoolId: null,
    }),
  ).resolves.toBeDefined();
});
it.each(["hostCommands.run", "hostCommands.queue", "hostFiles.read"] as const)(
  "%s refuses a host reached through a shared pool",
  async (action) => {
    const p = fixture(false);
    db.sandboxPoolMember.findFirst.mockResolvedValue({ id: "membership" } as never);
    db.sandboxHost.findFirst.mockResolvedValue(null);
    // No need to reach the pool graph: a direct host request must prove DB ownership.
    await expect(
      access.authorizeServiceAction(p, action, {
        sandboxHostId: "foreign",
        originPoolId: "shared-pool",
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN", data: { code: "host.not_owned" } });
    expect(db.sandboxHost.findFirst).toHaveBeenCalledWith({
      where: { id: "foreign", userId: "owner" },
      select: { id: true },
    });
  },
);
it("host tools remain available with own-only for a DB-owned host", async () => {
  await expect(
    access.authorizeServiceAction(fixture(), "hostCommands.run", { sandboxHostId: "host" }),
  ).resolves.toBeDefined();
});
it("API and agent secrets never authenticate across planes or a mismatched row kind", async () => {
  const agent = crypto.generateProductCredentialSecret("agentToken");
  const api = crypto.generateProductCredentialSecret("sdkKey");
  expect(await access.authenticateSdkKeySecret(agent.raw)).toBeNull();
  expect(await access.authenticateAgentTokenSecret(api.raw)).toBeNull();
  fixture();
  const row = await db.sdkKey.findUnique({ where: { id: "key" } });
  db.sdkKey.findUnique.mockResolvedValue({
    ...row,
    kind: "AGENT_TOKEN",
    expiresAt: new Date(Date.now() + 86_400_000),
    secretDigest: crypto.hmacDigestForProductPurpose({ purpose: "agentToken", value: agent.raw }),
  } as never);
  expect(await access.authenticateSdkKeySecret(api.raw)).toBeNull();
  expect(await access.authenticateAgentTokenSecret(agent.raw)).toMatchObject({
    credentialKind: "AGENT_TOKEN",
  });
  db.sdkKey.findUnique.mockResolvedValue({
    ...row,
    kind: "OAUTH_GRANT",
    secretDigest: access.digestSdkKeySecret(api.raw),
  } as never);
  expect(await access.authenticateSdkKeySecret(api.raw)).toBeNull();
});
it("MCP grants bind owner, client and credential kind", async () => {
  fixture();
  const row = await db.sdkKey.findUnique({ where: { id: "key" } });
  db.sdkKey.findUnique.mockResolvedValue({ ...row, kind: "OAUTH_GRANT" } as never);
  db.mcpGrant.findFirst.mockResolvedValue({ id: "grant", sdkKeyId: "key" } as never);
  expect(await access.principalForMcpGrant("grant", "owner", "client")).toMatchObject({
    credentialKind: "OAUTH_GRANT",
  });
  expect(db.mcpGrant.findFirst).toHaveBeenCalledWith({
    where: { id: "grant", userId: "owner", clientId: "client", revokedAt: null },
    select: { sdkKeyId: true },
  });
  db.mcpGrant.findFirst.mockResolvedValue(null);
  expect(await access.principalForMcpGrant("grant", "owner", "client")).toBeNull();
});

it("read tickets fail if own-only authority changes while a request awaits", async () => {
  const p = fixture(false);
  const call = access.serviceProcedure({ action: "capabilities.get" }, async (principal) => {
    if (principal.kind === "sdkKey") principal.ownSandboxesOnly = true;
    return "private";
  });
  await expect(call(p, undefined)).rejects.toMatchObject({ code: "FORBIDDEN" });
});

it("capabilities reports the credential's own-only setting", async () => {
  const { getKeyGrant } = await import("../sandbox/services/capabilities");
  expect(await getKeyGrant(fixture(), undefined)).toMatchObject({
    ownSandboxesOnly: true,
    resourceMode: "allOwned",
  });
});

it("OAuth revalidation preserves the access token's narrower scope ceiling", async () => {
  const p: access.ServicePrincipal = {
    ...fixture(),
    credentialKind: "OAUTH_GRANT",
    scopes: new Set(["sandboxes:read"]),
  };
  const row = await db.sdkKey.findUnique({ where: { id: p.keyId } });
  db.sdkKey.findUnique.mockResolvedValue({ ...row, kind: "OAUTH_GRANT" } as never);
  await expect(
    access.authorizeServiceAction(p, "hostCommands.run", { sandboxHostId: "host" }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  expect([...p.scopes]).toEqual(["sandboxes:read"]);
});

it("refuses never-expiring agent tokens while no-expiry is off, accepts them once on, and always refuses expired tokens", async () => {
  const { env } = (await import("@wssp/env/server")) as unknown as {
    env: { WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY: boolean };
  };
  const agent = crypto.generateProductCredentialSecret("agentToken");
  fixture();
  const row = await db.sdkKey.findUnique({ where: { id: "key" } });
  const token = {
    ...row,
    kind: "AGENT_TOKEN",
    expiresAt: null,
    secretDigest: crypto.hmacDigestForProductPurpose({ purpose: "agentToken", value: agent.raw }),
  };
  db.sdkKey.findUnique.mockResolvedValue(token as never);
  try {
    env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY = false;
    await expect(access.authenticateAgentTokenSecret(agent.raw)).rejects.toMatchObject({
      code: "agent_token.no_expiry_blocked",
    });
    env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY = true;
    expect(await access.authenticateAgentTokenSecret(agent.raw)).toMatchObject({
      credentialKind: "AGENT_TOKEN",
      expiresAt: null,
    });
    const now = new Date();
    for (const allow of [true, false]) {
      env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY = allow;
      for (const expiresAt of [new Date(now.getTime() - 1), now]) {
        db.sdkKey.findUnique.mockResolvedValue({ ...token, expiresAt } as never);
        expect(await access.authenticateAgentTokenSecret(agent.raw, now)).toBeNull();
      }
    }
  } finally {
    env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY = false;
  }
});
