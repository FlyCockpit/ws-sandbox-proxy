import { digestContextSnapshot } from "../sandbox/digest-context";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "sdk-key-test-secret",
  },
}));

const { default: prisma } = await import("@wssp/db");
const crypto = await import("@wssp/db/credential-security");
const access = await import("./sdk-key-access");
const scopes = await import("./service-scopes");
const authority = await import("@wssp/db/authority");
const { ORPCError } = await import("@orpc/server");

const now = new Date("2026-09-17T00:00:00Z");

function fullScopePrincipal(
  overrides: Partial<access.ServicePrincipal> = {},
): access.ServicePrincipal {
  const principal = {
    kind: "sdkKey",
    expiresAt: null,
    keyId: "key-1",
    ownerId: "user-a",
    resourceMode: "ALL_OWNED",
    scopes: new Set(scopes.SERVICE_SCOPES),
    allowedHostIds: "allOwned",
    allowedRevisionIds: "allOwned",
    allowedPoolIds: "allUsable",
    ...overrides,
  } satisfies access.ServicePrincipal;
  prisma.sdkKey.findUnique.mockResolvedValue({
    id: principal.keyId,
    userId: principal.ownerId,
    resourceMode: principal.resourceMode,
    scopes: [...principal.scopes],
    revokedAt: null,
    expiresAt: null,
    HostAllowlist:
      principal.allowedHostIds === "allOwned"
        ? []
        : [...principal.allowedHostIds].map((sandboxHostId) => ({
            sandboxHostId,
            SandboxHost: { userId: principal.ownerId },
          })),
    RevisionAllowlist:
      principal.allowedRevisionIds === "allOwned"
        ? []
        : [...principal.allowedRevisionIds].map((templateRevisionId) => ({ templateRevisionId })),
    User: {
      banned: false,
      banExpires: null,
      deletionRequestedAt: null,
      twoFactorEnabled: true,
      createdAt: new Date("2020-01-01"),
      role: "user",
    },
  } as never);
  prisma.sandboxHost.findFirst.mockResolvedValue({ id: "host-1", userId: "user-a" } as never);
  prisma.sandboxTemplateRevision.findFirst.mockResolvedValue({ id: "tpl-1" } as never);
  return principal;
}

function allowlistPrincipal(
  hostIds: string[],
  templateRevisionIds: string[],
  scopeList: scopes.ServiceScope[],
): access.ServicePrincipal {
  const principal = {
    kind: "sdkKey",
    expiresAt: null,
    keyId: "key-allow",
    ownerId: "user-a",
    resourceMode: "ALLOWLIST",
    scopes: new Set(scopeList),
    allowedHostIds: new Set(hostIds),
    allowedRevisionIds: new Set(templateRevisionIds),
    allowedPoolIds: new Set<string>(),
  } satisfies access.ServicePrincipal;
  prisma.sdkKey.findUnique.mockResolvedValue({
    id: principal.keyId,
    userId: principal.ownerId,
    resourceMode: principal.resourceMode,
    scopes: [...principal.scopes],
    revokedAt: null,
    expiresAt: null,
    HostAllowlist:
      principal.allowedHostIds === "allOwned"
        ? []
        : [...principal.allowedHostIds].map((sandboxHostId) => ({
            sandboxHostId,
            SandboxHost: { userId: principal.ownerId },
          })),
    RevisionAllowlist:
      principal.allowedRevisionIds === "allOwned"
        ? []
        : [...principal.allowedRevisionIds].map((templateRevisionId) => ({ templateRevisionId })),
    User: {
      banned: false,
      banExpires: null,
      deletionRequestedAt: null,
      twoFactorEnabled: true,
      createdAt: new Date("2020-01-01"),
      role: "user",
    },
  } as never);
  prisma.sandboxHost.findFirst.mockResolvedValue({ id: "host-1", userId: "user-a" } as never);
  prisma.sandboxTemplateRevision.findFirst.mockResolvedValue({ id: "tpl-1" } as never);
  return principal;
}

describe("parseServiceScopeSet", () => {
  it("rejects empty, wildcard, and unknown scopes", () => {
    expect(() => scopes.parseServiceScopeSet([])).toThrow(/At least one/);
    expect(() => scopes.parseServiceScopeSet(["hosts:read", ""])).toThrow(/empty/);
    expect(() => scopes.parseServiceScopeSet(["*"])).toThrow(/Wildcard/);
    expect(() => scopes.parseServiceScopeSet(["hosts:read", "bogus:write"])).toThrow(/Unknown/);
  });

  it("deduplicates known scopes", () => {
    expect(scopes.parseServiceScopeSet(["hosts:read", "hosts:read", "sandboxes:read"])).toEqual([
      "hosts:read",
      "sandboxes:read",
    ]);
  });
});

describe("authorizeServiceAction scope matrix", () => {
  it("separates operation metadata from command output and file bytes", async () => {
    const metadataOnly = allowlistPrincipal(["host-1"], ["tpl-1"], ["operations:read"]);
    await access.authorizeServiceAction(metadataOnly, "operations.get", {
      sandboxHostId: "host-1",
      templateRevisionId: "tpl-1",
      originPoolId: null,
    });
    await expect(
      access.authorizeServiceAction(metadataOnly, "operations.getCommandOutput", {
        sandboxHostId: "host-1",
        templateRevisionId: "tpl-1",
        originPoolId: null,
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(
      access.authorizeServiceAction(metadataOnly, "operations.downloadFile", {
        sandboxHostId: "host-1",
        templateRevisionId: "tpl-1",
        originPoolId: null,
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("requires mutation scope plus operations:cancel", async () => {
    const cancelOnly = allowlistPrincipal(["host-1"], ["tpl-1"], ["operations:cancel"]);
    await expect(
      access.authorizeServiceAction(cancelOnly, "operations.cancel", {
        sandboxHostId: "host-1",
        templateRevisionId: "tpl-1",
        originPoolId: null,
        operationKind: "RUN_COMMAND",
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });

    const allowed = allowlistPrincipal(
      ["host-1"],
      ["tpl-1"],
      ["operations:cancel", "commands:execute"],
    );
    await access.authorizeServiceAction(allowed, "operations.cancel", {
      sandboxHostId: "host-1",
      templateRevisionId: "tpl-1",
      originPoolId: null,
      operationKind: "RUN_COMMAND",
    });
  });

  it("rejects out-of-allowlist hosts and templates", async () => {
    const principal = allowlistPrincipal(["host-1"], ["tpl-1"], ["sandboxes:write"]);
    await expect(
      access.authorizeServiceAction(principal, "sandboxes.create", {
        sandboxHostId: "host-2",
        templateRevisionId: "tpl-1",
        originPoolId: null,
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(
      access.authorizeServiceAction(principal, "sandboxes.create", {
        sandboxHostId: "host-1",
        templateRevisionId: "tpl-2",
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("treats empty allowlists as granting no restricted resources", async () => {
    const principal = allowlistPrincipal([], [], ["sandboxes:write"]);
    await expect(
      access.authorizeServiceAction(principal, "sandboxes.create", {
        sandboxHostId: "host-1",
        templateRevisionId: "tpl-1",
        originPoolId: null,
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});

describe("authenticateSdkKeySecret", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    prisma.appSetting.findMany.mockResolvedValue([]);
  });

  const activeOwner = {
    banned: false,
    banExpires: null,
    twoFactorEnabled: true,
    createdAt: now,
    role: "user",
  };

  it("returns null for malformed, revoked, expired, banned-owner, and wrong-digest keys", async () => {
    expect(await access.authenticateSdkKeySecret("not-a-key", now)).toBeNull();

    const credential = crypto.generateProductCredentialSecret("sdkKey");
    prisma.sdkKey.findUnique.mockResolvedValue(null);
    expect(await access.authenticateSdkKeySecret(credential.raw, now)).toBeNull();

    prisma.sdkKey.findUnique.mockResolvedValue({
      id: "key-1",
      userId: "user-a",
      resourceMode: "ALL_OWNED",
      scopes: ["hosts:read"],
      lookupPrefix: crypto.credentialLookupPrefix(credential),
      secretDigest: "bad-digest",
      revokedAt: null,
      expiresAt: null,
      HostAllowlist: [],
      RevisionAllowlist: [],
      User: activeOwner,
    });
    expect(await access.authenticateSdkKeySecret(credential.raw, now)).toBeNull();

    prisma.sdkKey.findUnique.mockResolvedValue({
      id: "key-1",
      userId: "user-a",
      resourceMode: "ALL_OWNED",
      scopes: ["hosts:read"],
      lookupPrefix: crypto.credentialLookupPrefix(credential),
      secretDigest: access.digestSdkKeySecret(credential.raw),
      revokedAt: new Date("2026-01-01"),
      expiresAt: null,
      HostAllowlist: [],
      RevisionAllowlist: [],
      User: activeOwner,
    });
    expect(await access.authenticateSdkKeySecret(credential.raw, now)).toBeNull();

    prisma.sdkKey.findUnique.mockResolvedValue({
      id: "key-1",
      userId: "user-a",
      resourceMode: "ALL_OWNED",
      scopes: ["hosts:read"],
      lookupPrefix: crypto.credentialLookupPrefix(credential),
      secretDigest: access.digestSdkKeySecret(credential.raw),
      revokedAt: null,
      expiresAt: new Date("2026-01-01"),
      HostAllowlist: [],
      RevisionAllowlist: [],
      User: { ...activeOwner, banned: true, banExpires: null },
    });
    expect(await access.authenticateSdkKeySecret(credential.raw, now)).toBeNull();
  });

  it("authenticates active keys and stamps lastUsedAt", async () => {
    const credential = crypto.generateProductCredentialSecret("sdkKey");
    prisma.sdkKey.findUnique.mockResolvedValue({
      id: "key-1",
      userId: "user-a",
      resourceMode: "ALLOWLIST",
      scopes: ["sandboxes:read"],
      lookupPrefix: crypto.credentialLookupPrefix(credential),
      secretDigest: access.digestSdkKeySecret(credential.raw),
      revokedAt: null,
      expiresAt: null,
      HostAllowlist: [{ sandboxHostId: "host-1", SandboxHost: { userId: "user-a" } }],
      RevisionAllowlist: [{ templateRevisionId: "tpl-1" }],
      User: activeOwner,
    });
    prisma.sdkKey.updateMany.mockResolvedValue({ count: 1 });

    const principal = await access.authenticateSdkKeySecret(credential.raw, now);
    expect(principal).toMatchObject({
      ownerId: "user-a",
      resourceMode: "ALLOWLIST",
    });
    expect(principal?.allowedHostIds).toEqual(new Set(["host-1"]));
    // The first lookup is narrow; allowlists come from the full revalidation read.
    expect(prisma.sdkKey.findUnique.mock.calls[0]?.[0]).toMatchObject({
      where: { lookupPrefix: crypto.credentialLookupPrefix(credential) },
    });
    expect(prisma.sdkKey.findUnique.mock.calls[0]?.[0]?.select).not.toHaveProperty("HostAllowlist");
    expect(prisma.sdkKey.findUnique.mock.calls[1]?.[0]?.select).toHaveProperty("HostAllowlist");
    // lastUsedAt is throttled to one write per precision window.
    expect(prisma.sdkKey.updateMany).toHaveBeenCalledWith({
      where: {
        id: "key-1",
        OR: [
          { lastUsedAt: null },
          {
            lastUsedAt: {
              lt: new Date(now.getTime() - access.SDK_KEY_LAST_USED_PRECISION_MS),
            },
          },
        ],
      },
      data: { lastUsedAt: now },
    });
  });

  it("refuses a key deleted between the lookup and the lastUsedAt write", async () => {
    const credential = crypto.generateProductCredentialSecret("sdkKey");
    prisma.sdkKey.findUnique
      .mockResolvedValueOnce({
        id: "key-1",
        userId: "user-a",
        scopes: ["sandboxes:read"],
        secretDigest: access.digestSdkKeySecret(credential.raw),
        revokedAt: null,
        expiresAt: null,
        User: activeOwner,
      } as never)
      .mockResolvedValueOnce(null);
    prisma.sdkKey.updateMany.mockResolvedValue({ count: 0 });
    await expect(access.authenticateSdkKeySecret(credential.raw, now)).resolves.toBeNull();
    expect(prisma.sdkKey.update).not.toHaveBeenCalled();
  });

  it("rejects keys whose owner is past forced-2FA enrollment without re-enabling", async () => {
    const { invalidateForceTwoFactorSettingsCache } = await import("./two-factor-policy");
    prisma.appSetting.findMany.mockResolvedValue([{ key: "force2faPublicUsers", value: "true" }]);
    invalidateForceTwoFactorSettingsCache();
    const credential = crypto.generateProductCredentialSecret("sdkKey");
    prisma.sdkKey.findUnique.mockResolvedValue({
      id: "key-1",
      userId: "user-a",
      resourceMode: "ALL_OWNED",
      scopes: ["hosts:read"],
      lookupPrefix: crypto.credentialLookupPrefix(credential),
      secretDigest: access.digestSdkKeySecret(credential.raw),
      revokedAt: null,
      expiresAt: null,
      HostAllowlist: [],
      RevisionAllowlist: [],
      User: {
        banned: false,
        banExpires: null,
        twoFactorEnabled: false,
        createdAt: new Date("2020-01-01T00:00:00.000Z"),
        role: "user",
      },
    });
    await expect(access.authenticateSdkKeySecret(credential.raw, now)).resolves.toBeNull();
    expect(prisma.sdkKey.updateMany).not.toHaveBeenCalled();
  });
});

describe("service idempotency replay authorization", () => {
  it("reauthorizes create replay instead of skipping scope checks", async () => {
    const { createSandbox } = await import("../sandbox/services/sandboxes");
    const { hashRequestBody, requestDigestMetadata } = await import("../sandbox/idempotency");
    const input = {
      sandboxHostId: "host-1",
      template: "revision/" + "tpl-1",
      idempotencyKey: "retry",
    };
    const receipt = {
      id: "sbx-1",
      state: "DESTROYED",
      sandboxHostId: null,
      originHostId: "host-1",
      hostOwnerId: "user-a",
      templateId: "tpl-1",
      templateRevisionId: "tpl-1",
      originPoolId: null,
    };
    prisma.sandboxOperation.findFirst.mockResolvedValue({
      authorizingKeyId: "key-allow",
      digestContext: digestContextSnapshot({
        domain: "wssp-request-v2",
        hostId: "host-1",
        hostOwnerId: "user-a",
      }),
      requestBodyHash: hashRequestBody(
        { ...input, timeoutMs: 300000, lifecycle: { onTimeout: "kill", autoResume: false } },
        {
          ownerId: "user-a",
          hostOwnerId: "user-a",
          hostId: "host-1",
          authorizingKeyId: "key-allow",
        },
      ),
      ...requestDigestMetadata(),
      kind: "CREATE_SANDBOX",
      id: "op-1",
      sandboxId: "sbx-1",
      Sandbox: receipt,
    });
    prisma.sandbox.findFirst.mockResolvedValue(receipt as never);
    prisma.$transaction.mockImplementation(async (fn: (tx: typeof prisma) => Promise<unknown>) =>
      fn(prisma),
    );
    const principal = allowlistPrincipal(["host-1"], ["tpl-1"], ["sandboxes:write"]);
    const { hostOwnerId: _transportOwner, ...publicReceipt } = receipt;
    await expect(createSandbox(principal, input)).resolves.toEqual({
      ...publicReceipt,
      acceptedGraceSeconds: 0,
    });
    await expect(
      createSandbox(
        fullScopePrincipal({ keyId: "key-allow", scopes: new Set(["sandboxes:write"]) }),
        input,
      ),
    ).resolves.toEqual({
      ...publicReceipt,
      acceptedGraceSeconds: 0,
    });
    prisma.sandboxOperation.findFirst.mockClear();
    await expect(
      createSandbox(allowlistPrincipal(["host-1"], ["tpl-1"], ["sandboxes:read"]), input),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(prisma.sandboxOperation.findFirst).not.toHaveBeenCalled();
  });
});

describe("sdkKeyListSelect", () => {
  it("excludes secret digests from list projections", () => {
    expect(access.sdkKeyListSelect).not.toHaveProperty("secretDigest");
  });
});

describe("persisted SDK credentials", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    prisma.appSetting.findMany.mockResolvedValue([]);
  });
  const credential = crypto.generateProductCredentialSecret("sdkKey");
  function activeRow(overrides: Record<string, unknown> = {}) {
    return {
      id: "key-1",
      userId: "user-a",
      resourceMode: "ALL_OWNED",
      scopes: ["hosts:read"],
      lookupPrefix: crypto.credentialLookupPrefix(credential),
      secretDigest: access.digestSdkKeySecret(credential.raw),
      revokedAt: null,
      expiresAt: null,
      HostAllowlist: [],
      RevisionAllowlist: [],
      User: {
        banned: false,
        banExpires: null,
        twoFactorEnabled: true,
        createdAt: now,
        role: "user",
      },
      ...overrides,
    };
  }
  it.each([
    [],
    ["bogus:write"],
    ["hosts:read", "bogus:write"],
    [""],
    ["*"],
    ["hosts:read", " "],
    [" hosts:read"],
    Array(access.SERVICE_SCOPES.length + 1).fill("hosts:read"),
  ])("rejects invalid persisted scope set %j using the real authenticator", async (...values) => {
    // Vitest spreads array rows, so collect the row's scope values.
    prisma.sdkKey.findUnique.mockResolvedValue(activeRow({ scopes: values }));
    await expect(access.authenticateSdkKeySecret(credential.raw, now)).resolves.toBeNull();
    expect(prisma.sdkKey.updateMany).not.toHaveBeenCalled();
  });
  it.each([
    { name: "expired key", change: { expiresAt: now }, allowed: false },
    { name: "revoked key", change: { revokedAt: now }, allowed: false },
    {
      name: "permanent ban",
      change: {
        User: {
          banned: true,
          banExpires: null,
          twoFactorEnabled: true,
          createdAt: now,
          role: "user",
        },
      },
      allowed: false,
    },
    {
      name: "future ban",
      change: {
        User: {
          banned: true,
          banExpires: new Date(now.getTime() + 1),
          twoFactorEnabled: true,
          createdAt: now,
          role: "user",
        },
      },
      allowed: false,
    },
    {
      name: "exact ban boundary",
      change: {
        User: {
          banned: true,
          banExpires: now,
          twoFactorEnabled: true,
          createdAt: now,
          role: "user",
        },
      },
      allowed: false,
    },
    {
      name: "expired temporary ban",
      change: {
        User: {
          banned: true,
          banExpires: new Date(now.getTime() - 1),
          twoFactorEnabled: true,
          createdAt: now,
          role: "user",
        },
      },
      allowed: true,
    },
    { name: "unbanned", change: {}, allowed: true },
  ])("$name is evaluated independently", async ({ change, allowed }) => {
    prisma.sdkKey.findUnique.mockResolvedValue(activeRow(change));
    const result = await access.authenticateSdkKeySecret(credential.raw, now);
    expect(result !== null).toBe(allowed);
    expect(prisma.sdkKey.updateMany).toHaveBeenCalledTimes(allowed ? 1 : 0);
  });
  it("rejects a digest made with a different server secret or purpose", async () => {
    for (const secretDigest of [
      crypto.hmacDigestForProductPurpose({ purpose: "hostToken", value: credential.raw }),
      "0".repeat(64),
    ]) {
      prisma.sdkKey.findUnique.mockResolvedValue(activeRow({ secretDigest }));
      await expect(access.authenticateSdkKeySecret(credential.raw, now)).resolves.toBeNull();
    }
    expect(prisma.sdkKey.updateMany).not.toHaveBeenCalled();
  });
});

describe("active SDK credential authority", () => {
  it("rejects expiry crossing during authorization and before read disclosure", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(now);
      const actor = fullScopePrincipal();
      const row = await prisma.sdkKey.findUnique({ where: { id: actor.keyId } });
      if (!row) throw new Error("fixture missing");
      const expiresAt = new Date(now.getTime() + 1);
      prisma.sdkKey.findUnique.mockResolvedValue({ ...row, expiresAt });
      prisma.sandboxHost.findFirst.mockImplementationOnce(async () => {
        vi.setSystemTime(expiresAt);
        return { id: "host-1", userId: "user-a" } as never;
      });
      await expect(
        access.authorizeServiceAction(actor, "commands.run", {
          sandboxHostId: "host-1",
          templateRevisionId: "tpl-1",
          originPoolId: null,
        }),
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
      vi.setSystemTime(now);
      const disclose = access.serviceProcedure(
        { action: "hosts.list" },
        async (_principal, cross: boolean) => {
          if (cross) vi.setSystemTime(expiresAt);
          return "disclosed";
        },
      );
      await expect(disclose({ ...actor }, false)).resolves.toBe("disclosed");
      vi.setSystemTime(now);
      await expect(disclose({ ...actor }, true)).rejects.toMatchObject({
        code: "FORBIDDEN",
        message: "Authority changed during request.",
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    "revoke",
    "ban",
    "delete-owner",
    "expire",
    "remove-host-grant",
    "remove-template-grant",
  ])("rechecks a cached principal after %s", async (change) => {
    const actor = allowlistPrincipal(["host-1"], ["tpl-1"], ["commands:execute"]);
    const row = await prisma.sdkKey.findUnique({ where: { id: actor.keyId } });
    if (!row) throw new Error("fixture missing");
    const changed = { ...row };
    if (change === "revoke") changed.revokedAt = new Date();
    if (change === "expire") changed.expiresAt = new Date(0);
    if (change === "ban") changed.User = { ...row.User, banned: true };
    if (change === "delete-owner") changed.User = { ...row.User, deletionRequestedAt: new Date() };
    if (change === "remove-host-grant") changed.HostAllowlist = [];
    if (change === "remove-template-grant") changed.RevisionAllowlist = [];
    prisma.sdkKey.findUnique.mockResolvedValue(changed);
    await expect(
      access.authorizeServiceAction(actor, "commands.run", {
        sandboxHostId: "host-1",
        templateRevisionId: "tpl-1",
        originPoolId: null,
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    prisma.sdkKey.findUnique.mockResolvedValue(row);
    await expect(
      access.authorizeServiceAction(actor, "commands.run", {
        sandboxHostId: "host-1",
        templateRevisionId: "tpl-1",
        originPoolId: null,
      }),
    ).resolves.toEqual(expect.any(Object));
  });
});

describe("C21-READEXIT serviceProcedure wrapper", () => {
  const { withAuthorityChange } = authority;
  const revoke = () =>
    withAuthorityChange({ ownerId: "user-a", credentialId: "key-1" }, async () => undefined);
  const STALE = { code: "FORBIDDEN", message: "Authority changed during request." };

  it("replaces a RESOLVED result with FORBIDDEN when a revoke commits after entry authorization", async () => {
    const procedure = access.serviceProcedure({ action: "hosts.list" }, async () => {
      await revoke();
      return { secret: "post-revocation data" };
    });
    await expect(procedure(fullScopePrincipal(), undefined)).rejects.toMatchObject(STALE);
  });

  it("replaces a REJECTED data-dependent error with FORBIDDEN when a revoke commits after entry", async () => {
    const procedure = access.serviceProcedure({ action: "hosts.list" }, async () => {
      await revoke();
      throw new ORPCError("NOT_FOUND", { message: "Sandbox not found" });
    });
    await expect(procedure(fullScopePrincipal(), undefined)).rejects.toMatchObject(STALE);
  });

  it("passes results and errors through unchanged when authority is unchanged", async () => {
    const ok = access.serviceProcedure({ action: "hosts.list" }, async () => "value");
    const miss = access.serviceProcedure({ action: "hosts.list" }, async () => {
      throw new ORPCError("NOT_FOUND", { message: "Sandbox not found" });
    });
    await expect(ok(fullScopePrincipal(), undefined)).resolves.toBe("value");
    await expect(miss(fullScopePrincipal(), undefined)).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
  });

  it("an unrelated key's revoke does not fence this request", async () => {
    const procedure = access.serviceProcedure({ action: "hosts.list" }, async () => {
      await withAuthorityChange(
        { ownerId: "user-b", credentialId: "key-9" },
        async () => undefined,
      );
      return "value";
    });
    await expect(procedure(fullScopePrincipal(), undefined)).resolves.toBe("value");
  });

  it("a revoke before entry is denied by entry authorization, before the body runs", async () => {
    const body = vi.fn(async () => "value");
    const procedure = access.serviceProcedure({ action: "hosts.list" }, body);
    const actor = fullScopePrincipal();
    prisma.sdkKey.findUnique.mockResolvedValue(null);
    await expect(procedure(actor, undefined)).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(body).not.toHaveBeenCalled();
  });
});

it("3B undefined origin pool fails closed; stored operations.getReceipt requires the exact revision", async () => {
  const key = allowlistPrincipal(["host-1"], ["tpl-1"], ["sandboxes:read", "operations:read"]);
  await expect(
    access.authorizeServiceAction(key, "sandboxes.get", {
      sandboxHostId: "host-1",
      templateRevisionId: "tpl-1",
    }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  prisma.sandboxOperation.findFirst.mockResolvedValue({
    kind: "RUN_COMMAND",
    Sandbox: { id: "s1", originHostId: "host-1", templateRevisionId: "other", originPoolId: null },
  } as never);
  await expect(
    access.authorizeServiceAction(key, "operations.getReceipt", { operationId: "o1" }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
  prisma.sandboxOperation.findFirst.mockResolvedValue({
    kind: "RUN_COMMAND",
    authorizingKeyId: "key-allow",
    Sandbox: { id: "s1", originHostId: "host-1", templateRevisionId: "tpl-1", originPoolId: null },
  } as never);
  await expect(
    access.authorizeServiceAction(key, "operations.getReceipt", { operationId: "o1" }),
  ).resolves.toMatchObject({ templateRevisionId: "tpl-1", originPoolId: null });
});

it("session_reads_retained_history_after_host_deletion bypasses SDK resolution and grant fences", async () => {
  prisma.sandboxHost.findFirst.mockClear();
  prisma.sdkKey.findUnique.mockClear();
  prisma.sandbox.findFirst.mockClear();
  const target = { operationId: "retained-operation" };
  expect(
    await access.authorizeServiceAction(
      { kind: "session", ownerId: "user-a" },
      "operations.getCommandOutput",
      target,
    ),
  ).toBe(target);
  expect(prisma.sandboxHost.findFirst).not.toHaveBeenCalled();
  expect(prisma.sdkKey.findUnique).not.toHaveBeenCalled();
  expect(prisma.sandbox.findFirst).not.toHaveBeenCalled();
});

it("3B dispatch checks rows and stored grants, never mutation scopes or ambiguous revalidation", async () => {
  fullScopePrincipal({ scopes: new Set(["hosts:read"]) });
  const input = {
    ownerId: "user-a",
    principal: { kind: "sdkKey" as const, keyId: "key-1" },
    context: { sandboxHostId: "host-1", templateRevisionId: "tpl-1", originPoolId: null },
  };
  expect(await access.checkAcceptedDispatchAuthority(input, prisma)).toBe("active");
  const currentRow = await prisma.sdkKey.findUnique({ where: { id: "key-1" } });
  prisma.sdkKey.findUnique.mockResolvedValue({ ...currentRow, revokedAt: new Date() } as never);
  expect(await access.checkAcceptedDispatchAuthority(input, prisma)).toBe("inactive");
  prisma.sdkKey.findUnique.mockRejectedValueOnce(new Error("synthetic query failure"));
  expect(await access.checkAcceptedDispatchAuthority(input, prisma)).toBe("indeterminate");
});

it("3B moved authority fence is indeterminate even when its row is active", async () => {
  fullScopePrincipal();
  const read = prisma.sdkKey.findUnique.getMockImplementation()!;
  prisma.sdkKey.findUnique.mockImplementationOnce(async (args) => {
    const row = await read(args);
    await authority.withGlobalAuthorityChange(async () => undefined);
    return row;
  });
  expect(
    await access.checkAcceptedDispatchAuthority(
      {
        ownerId: "user-a",
        principal: { kind: "sdkKey", keyId: "key-1" },
        context: { sandboxHostId: "host-1", templateRevisionId: "tpl-1", originPoolId: null },
      },
      prisma,
    ),
  ).toBe("indeterminate");
});

it("retains a distinct pool owner's policy proof through session dispatch IO", async () => {
  const policy = {
    banned: false,
    banExpires: null,
    deletionRequestedAt: null,
    twoFactorEnabled: true,
    role: "user",
    createdAt: new Date("2020-01-01"),
  };
  prisma.user.findUnique.mockResolvedValue(policy as never);
  prisma.sandbox.findFirst
    .mockResolvedValueOnce({ hostOwnerId: "transport-owner", usagePoolId: "pool" } as never)
    .mockResolvedValueOnce(null)
    .mockResolvedValueOnce({
      sandboxHostId: "host",
      hostOwnerId: "transport-owner",
      usagePoolId: "pool",
      usageMemberId: "member",
      accessGraceUntil: null,
      SandboxHost: { userId: "transport-owner", deletionRequestedAt: null, User: policy },
    } as never);
  prisma.sandboxPool.findUnique.mockResolvedValue({ userId: "pool-owner" } as never);
  prisma.sandboxPoolMember.findFirst.mockResolvedValue({ Pool: { User: policy } } as never);
  let proof = () => false;
  expect(
    await access.checkAcceptedDispatchAuthority(
      {
        ownerId: "creator",
        principal: { kind: "session" },
        context: { sandboxId: "sandbox", sandboxHostId: "host" },
        onActiveAuthority: (current) => {
          proof = current;
        },
      },
      prisma,
    ),
  ).toBe("active");
  expect(proof()).toBe(true);
  await authority.withAuthorityChange({ ownerId: "unrelated" }, async () => undefined);
  expect(proof()).toBe(true);
  await authority.withAuthorityChange({ ownerId: "pool-owner" }, async () => undefined);
  expect(proof()).toBe(false);
});

it("ALL_OWNED dispatch uses durable creator ownership on a foreign transport; selected keys still need the initial CREATE key (PG: lifecycle-conformance.pg.test.ts)", async () => {
  const input = {
    ownerId: "user-a",
    principal: { kind: "sdkKey" as const, keyId: "key-1" },
    cleanup: true,
    context: {
      sandboxId: "owned-sandbox",
      sandboxHostId: "foreign-host",
      templateRevisionId: "tpl-1",
      originPoolId: "foreign-pool",
    },
  };
  fullScopePrincipal();
  prisma.sandboxOperation.findFirst.mockResolvedValue({ authorizingKeyId: "initial-key" } as never);
  prisma.sandboxHost.findFirst.mockResolvedValue(null);
  prisma.sandboxPool.findFirst.mockResolvedValue(null);
  expect(await access.checkAcceptedDispatchAuthority(input, prisma)).toBe("active");
  // An unbound context cannot inherit the retained-creator exception.
  prisma.sandboxOperation.findFirst.mockResolvedValue(null);
  expect(await access.checkAcceptedDispatchAuthority(input, prisma)).toBe("inactive");
  fullScopePrincipal({
    resourceMode: "ALLOWLIST",
    allowedHostIds: new Set(),
    allowedRevisionIds: new Set(["tpl-1"]),
    allowedPoolIds: new Set(["foreign-pool"]),
  });
  prisma.sandboxOperation.findFirst.mockResolvedValue({ authorizingKeyId: "initial-key" } as never);
  expect(await access.checkAcceptedDispatchAuthority(input, prisma)).toBe("inactive");
  prisma.sandboxOperation.findFirst.mockResolvedValue({ authorizingKeyId: "key-1" } as never);
  expect(await access.checkAcceptedDispatchAuthority(input, prisma)).toBe("active");
});

describe("§5a retained-creator classification (V1)", () => {
  it("classifies every ServiceAction exactly once", () => {
    expect(Object.keys(access.SERVICE_ACTION_CUSTODY).sort()).toEqual(
      [...scopes.SERVICE_ACTIONS].sort(),
    );
  });

  it("keeps the shortcut only for history reads and cleanup", () => {
    expect([...access.RETAINED_CREATOR_ACTIONS].sort()).toEqual(
      [
        "operations.cancel",
        "operations.downloadFile",
        "operations.get",
        "operations.getCommandOutput",
        "operations.getCommandResult",
        "operations.getFileMutationResult",
        "operations.getFileResult",
        "operations.getReceipt",
        "operations.getRenameResult",
        "operations.getSignalResult",
        "sandboxes.capabilities",
        "sandboxes.get",
        "sandboxes.kill",
        "sandboxes.list",
        "sandboxes.replayCreate",
        "sandboxes.stop",
      ].sort(),
    );
    // Guest IO, terminals, reconnect/restore, timeout, logins and capture
    // need current custody.
    for (const action of [
      "commands.run",
      "files.read",
      "processes.connect",
      "sandboxes.reconnect",
      "sandboxes.setTimeout",
      "sandboxCredentials.attach",
      "sandboxCredentials.free",
      "sandboxes.capture",
    ] as const)
      expect(access.SERVICE_ACTION_CUSTODY[action]).toBe("custody");
  });

  it("currentCustodyAllowed: host leg for ALLOWLIST only, pool leg whenever SELECTED (W1)", () => {
    const key = (over: Partial<Parameters<typeof access.currentCustodyAllowed>[0]>) => ({
      kind: "sdkKey" as const,
      expiresAt: null,
      keyId: "k",
      ownerId: "o",
      resourceMode: "ALLOWLIST" as const,
      scopes: new Set<never>(),
      allowedHostIds: new Set(["a"]),
      allowedRevisionIds: "allOwned" as const,
      allowedPoolIds: "allUsable" as const,
      ...over,
    });
    const at = (hostId: string, poolId: string | null, hostOwnerId = "o") => ({
      hostId,
      hostOwnerId,
      poolId,
    });
    expect(access.currentCustodyAllowed(key({}), at("a", null))).toBe(true);
    expect(access.currentCustodyAllowed(key({}), at("b", null))).toBe(false);
    // A foreign host is reached through a pool only.
    expect(access.currentCustodyAllowed(key({}), at("f", "p", "other"))).toBe(true);
    expect(access.currentCustodyAllowed(key({}), at("f", null, "other"))).toBe(false);
    const allOwnedSelected = key({
      resourceMode: "ALL_OWNED",
      allowedHostIds: "allOwned",
      allowedPoolIds: new Set(["p"]),
    });
    expect(access.currentCustodyAllowed(allOwnedSelected, at("b", "p"))).toBe(true);
    expect(access.currentCustodyAllowed(allOwnedSelected, at("b", "q"))).toBe(false);
    expect(access.currentCustodyAllowed(allOwnedSelected, at("b", null))).toBe(true);
    const allUsable = key({ resourceMode: "ALL_OWNED", allowedHostIds: "allOwned" });
    expect(access.currentCustodyAllowed(allUsable, at("b", "q"))).toBe(true);
  });
});
