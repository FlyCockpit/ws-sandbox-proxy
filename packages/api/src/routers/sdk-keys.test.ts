vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createRouterClient, type ORPCError } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";
import { invalidateForceTwoFactorSettingsCache } from "../lib/two-factor-policy";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "sdk-router-test-secret" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { default: db } = await import("@wssp/db");
const { sdkKeysRouter } = await import("./sdk-keys");

const now = new Date("2026-09-17T00:00:00Z");
/** An owned, active template on host-1 (what an allowlist may name with host-1). */
const ACTIVE_TPL = {
  id: "tpl-1",
  retiredAt: null,
  Template: { archivedAt: null },
  Availability: [{ hostId: "host-1" }],
};

const keyRow = (overrides: Record<string, unknown> = {}) => ({
  id: "key-1",
  kind: "API",
  ownSandboxesOnly: false,
  name: "ci",
  resourceMode: "ALLOWLIST" as const,
  scopes: ["sandboxes:read"],
  lookupPrefix: "wssp_sdk_prefix",
  lastUsedAt: null,
  revokedAt: null,
  expiresAt: null,
  createdAt: now,
  HostAllowlist: [{ sandboxHostId: "host-1", SandboxHost: { slug: "desk-01", label: "Desk" } }],
  RevisionAllowlist: [
    { templateRevisionId: "tpl-1", Revision: { revision: 1, Template: { label: "Ubuntu" } } },
  ],
  ...overrides,
});

function client(userId = "user-a", twoFactorEnabled = true) {
  invalidateForceTwoFactorSettingsCache();
  const context: Context = {
    session: {
      user: {
        id: userId,
        email: "test@example.com",
        name: "Test User",
        emailVerified: true,
        role: "user",
        twoFactorEnabled,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        createdAt: now,
        updatedAt: now,
      },
      session: {
        id: "auth-session",
        userId,
        token: "token",
        expiresAt: new Date("2027-01-01"),
        ipAddress: null,
        userAgent: null,
        createdAt: now,
        updatedAt: now,
      },
    } as Session,
  };
  return createRouterClient(sdkKeysRouter, { context });
}

describe("sdkKeysRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.appSetting.findMany.mockResolvedValue([]);
    db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) => fn(db));
    invalidateForceTwoFactorSettingsCache();
  });

  it("rejects unauthenticated list calls", async () => {
    const anonymous = createRouterClient(sdkKeysRouter, { context: { session: null } });
    await expect(anonymous.list({ limit: 20 })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "UNAUTHORIZED",
    );
  });

  it("lists owner keys with cursor pagination and no digest field", async () => {
    db.sdkKey.findMany.mockResolvedValue([keyRow()]);
    const result = await client().list({ limit: 20 });
    expect(result.items).toHaveLength(1);
    expect(result.items[0]).not.toHaveProperty("secretDigest");
    // M7-S11: allowlists carry names so the owner can audit a key's reach.
    expect(result.items[0]?.hostAllowlist).toEqual([
      { id: "host-1", slug: "desk-01", label: "Desk" },
    ]);
    expect(result.items[0]?.revisionAllowlist).toEqual([{ id: "tpl-1", label: "Ubuntu #1" }]);
    expect(db.sdkKey.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          AND: expect.arrayContaining([{ userId: "user-a", kind: "API", revokedAt: null }]),
        }),
      }),
    );
  });

  it("mints a key with one-time secret reveal", async () => {
    db.sandboxHost.findMany.mockResolvedValue([{ id: "host-1" }]);
    db.sandboxTemplateRevision.findMany.mockResolvedValue([ACTIVE_TPL]);
    db.sdkKey.create.mockResolvedValue(keyRow());
    const result = await client().create({
      name: "ci",
      scopes: ["sandboxes:read"],
      resourceMode: "ALLOWLIST",
      hostIds: ["host-1"],
      templateRevisionIds: ["tpl-1"],
    });
    expect(result.secret.startsWith("wssp_sdk_")).toBe(true);
    expect(result.key.lookupPrefix).toBeTruthy();
    expect(db.sdkKey.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          userId: "user-a",
          scopes: ["sandboxes:read"],
        }),
      }),
    );
  });

  it("rejects empty scopes and foreign allowlist resources", async () => {
    await expect(
      client().create({
        name: "bad",
        scopes: [],
        resourceMode: "ALLOWLIST",
        hostIds: ["host-1"],
        templateRevisionIds: [],
      }),
    ).rejects.toSatisfy((error: ORPCError) => error.code === "BAD_REQUEST");

    db.sandboxHost.findMany.mockResolvedValue([]);
    await expect(
      client().create({
        name: "bad",
        scopes: ["hosts:read"],
        resourceMode: "ALLOWLIST",
        hostIds: ["foreign-host"],
        templateRevisionIds: ["tpl-1"],
      }),
    ).rejects.toSatisfy((error: ORPCError) => error.code === "FORBIDDEN");
  });

  it("hides another user's key on revoke", async () => {
    db.sdkKey.findFirst.mockResolvedValue(null);
    db.sdkKey.updateMany.mockResolvedValue({ count: 0 });
    await expect(client("user-b").revoke({ id: "key-1" })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "NOT_FOUND",
    );
    expect(db.sdkKey.findFirst).toHaveBeenCalledWith({
      where: { id: "key-1", userId: "user-b", kind: "API", revokedAt: null },
      select: { id: true },
    });
    expect(db.sdkKey.updateMany).not.toHaveBeenCalled();
  });

  it("does not list another owner's keys", async () => {
    db.sdkKey.findMany.mockResolvedValue([]);
    await client("user-b").list({ limit: 20 });
    expect(db.sdkKey.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          AND: [{ userId: "user-b", kind: "API", revokedAt: null }],
        },
      }),
    );
  });
});

describe("unit (mocked Prisma; no real-DB test yet for the P2003 mapping) — C17 SDK key validation and concurrency", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.appSetting.findMany.mockResolvedValue([]);
    db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) => fn(db));
  });
  const mint = {
    name: "ci",
    scopes: ["hosts:read" as const],
    resourceMode: "ALLOWLIST" as const,
    hostIds: ["host-1"],
    templateRevisionIds: ["tpl-1"],
  };

  it.each(["", "not-a-valid-cursor", "eyJpZCI6ImtleS0xIn0"])(
    "rejects malformed cursor %s before list query",
    async (cursor) => {
      await expect(client().list({ cursor, limit: 1 })).rejects.toMatchObject({
        code: "BAD_REQUEST",
      });
      expect(db.sdkKey.findMany).not.toHaveBeenCalled();
    },
  );
  it("uses bounded lookahead and follows a valid cursor", async () => {
    db.sdkKey.findMany.mockResolvedValueOnce([keyRow({ id: "key-3" }), keyRow({ id: "key-2" })]);
    const first = await client().list({ limit: 1 });
    expect(first.items.map((row) => row.id)).toEqual(["key-3"]);
    expect(first.nextCursor).toBeTruthy();
    db.sdkKey.findMany.mockResolvedValueOnce([keyRow({ id: "key-2" })]);
    const second = await client().list({ limit: 1, cursor: first.nextCursor! });
    expect(second.items.map((row) => row.id)).toEqual(["key-2"]);
    expect(second.nextCursor).toBeNull();
    expect(db.sdkKey.findMany).toHaveBeenLastCalledWith(
      expect.objectContaining({
        take: 2,
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        where: {
          AND: [
            { userId: "user-a", kind: "API", revokedAt: null },
            { OR: [{ createdAt: { lt: now } }, { createdAt: now, id: { lt: "key-3" } }] },
          ],
        },
      }),
    );
  });
  it.each(Array.from({ length: 32 }, (_, code) => code))(
    "rejects key name C0 %i with BAD_REQUEST",
    async (code) => {
      await expect(
        client().create({ ...mint, name: `ci${String.fromCharCode(code)}` }),
      ).rejects.toMatchObject({ code: "BAD_REQUEST" });
      expect(db.sdkKey.create).not.toHaveBeenCalled();
    },
  );
  it.each([
    { hostIds: [], templateRevisionIds: [] },
    { hostIds: [], templateRevisionIds: ["tpl-1"] },
  ])("requires a host or pool grant %j", async (restrictions) => {
    await expect(client().create({ ...mint, ...restrictions })).rejects.toMatchObject({
      code: "BAD_REQUEST",
    });
    expect(db.sdkKey.create).not.toHaveBeenCalled();
  });
  it.each(["host", "template"])(
    "rejects a foreign %s using an owner-sensitive preflight",
    async (foreign) => {
      db.sandboxHost.findMany.mockImplementation(
        async ({ where }: { where: { userId?: string } }) =>
          where.userId === "user-a" && foreign === "host" ? [] : [{ id: "host-1" }],
      );
      db.sandboxTemplateRevision.findMany.mockImplementation(
        async ({ where }: { where: { userId?: string } }) =>
          where.userId === "user-a" && foreign === "template" ? [] : [ACTIVE_TPL],
      );
      await expect(client().create(mint)).rejects.toMatchObject({ code: "FORBIDDEN" });
      expect(db.sdkKey.create).not.toHaveBeenCalled();
    },
  );
  // C46 carry-in (C45 R4): the two mint rules the browser explains are
  // enforced here, with stable 400 codes, from the one shared definition.
  it.each([[["operations:cancel"], "a cancel scope with nothing to cancel"]] as const)(
    "refuses unusable scopes %j (%s) with sdk_key.unusable_scopes",
    async (scopes) => {
      await expect(
        client().create({
          ...mint,
          resourceMode: "ALL_OWNED",
          hostIds: [],
          templateRevisionIds: [],
          scopes: [...scopes],
        }),
      ).rejects.toMatchObject({ code: "BAD_REQUEST", data: { code: "sdk_key.unusable_scopes" } });
      expect(db.sdkKey.create).not.toHaveBeenCalled();
      expect(db.$transaction).not.toHaveBeenCalled();
    },
  );
  it("accepts the same scopes once each can grant something", async () => {
    db.sdkKey.create.mockResolvedValue(keyRow());
    await client().create({
      ...mint,
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
      scopes: ["operations:cancel", "operations:read", "commands:read", "commands:execute"],
    });
    expect(db.sdkKey.create).toHaveBeenCalledTimes(1);
  });
  it.each([
    ["on a host that is not allowlisted", { ...ACTIVE_TPL, Availability: [] }],
    ["retired", { ...ACTIVE_TPL, retiredAt: now }],
    ["logically archived", { ...ACTIVE_TPL, Template: { archivedAt: now } }],
  ] as const)(
    "refuses an allowlisted template %s with sdk_key.template_not_on_selected_host",
    async (_label, template) => {
      db.sandboxHost.findMany.mockResolvedValue([{ id: "host-1" }]);
      db.sandboxTemplateRevision.findMany.mockResolvedValue([template]);
      await expect(client().create(mint)).rejects.toMatchObject({
        code: "BAD_REQUEST",
        data: { code: "sdk_key.template_not_on_selected_host" },
      });
      expect(db.sdkKey.create).not.toHaveBeenCalled();
    },
  );
  it("maps concurrent resource deletion P2003 to CONFLICT without retry", async () => {
    db.sandboxHost.findMany.mockResolvedValue([{ id: "host-1" }]);
    db.sandboxTemplateRevision.findMany.mockResolvedValue([ACTIVE_TPL]);
    db.sdkKey.create.mockRejectedValueOnce({ code: "P2003" });
    await expect(client().create(mint)).rejects.toMatchObject({ code: "CONFLICT" });
    expect(db.sdkKey.create).toHaveBeenCalledTimes(1);
  });
  it("mints only validated unique grants and persists the revealed secret's digest", async () => {
    db.sandboxHost.findMany.mockResolvedValue([{ id: "host-1" }]);
    db.sandboxTemplateRevision.findMany.mockResolvedValue([ACTIVE_TPL]);
    db.sdkKey.create.mockResolvedValue(keyRow());
    const result = await client().create({
      ...mint,
      hostIds: ["host-1", "host-1"],
      templateRevisionIds: ["tpl-1", "tpl-1"],
    });
    const { digestSdkKeySecret, sdkKeyLookupPrefix } = await import("../lib/sdk-key-access");
    expect(db.sdkKey.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          secretDigest: digestSdkKeySecret(result.secret),
          lookupPrefix: sdkKeyLookupPrefix(result.secret),
          HostAllowlist: { create: [{ sandboxHostId: "host-1" }] },
          RevisionAllowlist: { create: [{ templateRevisionId: "tpl-1" }] },
        }),
      }),
    );
    db.sdkKey.findMany.mockResolvedValue([keyRow()]);
    const listed = JSON.stringify(await client().list({}));
    expect(listed).not.toContain(result.secret);
    expect(listed).not.toContain("secretDigest");
  });
  it("revokes once atomically; concurrent repeat and foreign owner receive NOT_FOUND", async () => {
    let revoked = false;
    db.sdkKey.updateMany.mockImplementation(
      async ({ where }: { where: { id: string; userId: string; revokedAt?: null } }) => {
        if (
          where.id !== "key-1" ||
          where.userId !== "user-a" ||
          (where.revokedAt === null && revoked)
        )
          return { count: 0 };
        revoked = true;
        return { count: 1 };
      },
    );
    db.sdkKey.findFirst.mockImplementation(
      async ({ where }: { where: { id: string; userId: string } }) =>
        where.id === "key-1" && where.userId === "user-a" && !revoked ? { id: "key-1" } : null,
    );
    await expect(client("user-b").revoke({ id: "key-1" })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    const first = client().revoke({ id: "key-1" });
    const second = client().revoke({ id: "key-1" });
    await Promise.all([
      expect(first).resolves.toEqual({ ok: true }),
      expect(second).rejects.toMatchObject({ code: "NOT_FOUND" }),
    ]);
    expect(db.sdkKey.update).not.toHaveBeenCalled();
    expect(db.sdkKey.updateMany).toHaveBeenCalledTimes(2);
    expect(db.sdkKey.updateMany).toHaveBeenCalledWith({
      where: { id: "key-1", userId: "user-a", kind: "API", revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
  });
  it("revoking unknown key ids allocates no authority state", async () => {
    const { trackedAuthorityKeyCount } = await import("@wssp/db/authority");
    db.sdkKey.findFirst.mockResolvedValue(null);
    const before = trackedAuthorityKeyCount();
    for (let i = 0; i < 25; i += 1)
      await expect(client().revoke({ id: `missing-key-${i}` })).rejects.toMatchObject({
        code: "NOT_FOUND",
      });
    expect(db.sdkKey.updateMany).not.toHaveBeenCalled();
    expect(trackedAuthorityKeyCount()).toBe(before);
  });
});
