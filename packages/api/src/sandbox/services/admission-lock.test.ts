vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { readFileSync } from "node:fs";

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "admission-lock-test-secret",
    BETTER_AUTH_URL: "http://localhost:3000",
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { default: db } = await import("@wssp/db");
const { bindHostImageVerifier } = await import("../host-image-verifier");
const { createHostInput, createHostTokenInput, createTemplateInput } = await import("../contracts");
const { createHost, createHostToken } = await import("./hosts");
const { createTemplate } = await import("./templates");
const { createSdkKey, createSdkKeyInput } = await import("./sdk-keys");

const owner = { kind: "session" as const, ownerId: "owner-1" };
const FP = `sha256:${"a".repeat(64)}`;

/** The recording transaction is the mock client itself: every statement's global
 * invocation order is recorded, so lock-before-insert is a mechanical comparison. */
function ownerLockOrder(): number {
  const index = db.$queryRaw.mock.calls.findIndex(([parts]) =>
    (parts as unknown as string[]).join("?").includes('FROM "user" WHERE id = ? FOR SHARE'),
  );
  expect(index).toBeGreaterThanOrEqual(0);
  expect(db.$queryRaw.mock.calls[index]?.[1]).toBe("owner-1");
  return db.$queryRaw.mock.invocationCallOrder[index]!;
}
function insertOrder(mock: { mock: { invocationCallOrder: number[] } }): number {
  expect(mock.mock.invocationCallOrder.length).toBe(1);
  return mock.mock.invocationCallOrder[0]!;
}

beforeEach(() => {
  vi.clearAllMocks();
  db.appSetting.findMany.mockResolvedValue([]);
  db.$queryRaw.mockImplementation(async (query) => {
    const sql = Array.isArray(query) ? query.join("?") : "";
    if (sql.includes("clock_timestamp()")) return [{ now: new Date() }];
    return sql.startsWith("SELECT id FROM sandbox_host") ||
      sql.startsWith("SELECT id FROM sandbox_instance WHERE")
      ? [{ id: "locked" }]
      : [];
  });
  db.user.findUnique.mockResolvedValue({ deletionRequestedAt: null } as never);
  // A distinct transaction client (as in production) that records into the same mocks.
  db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) =>
    fn(new Proxy(db, {})),
  );
  db.sandboxHost.findFirst.mockResolvedValue({
    id: "host-1",
    userId: "owner-1",
    connectionEpoch: 1,
    status: "CONNECTED",
  } as never);
  db.sandboxHost.updateMany.mockResolvedValue({ count: 1 });
  db.sandboxTemplateRevision.create.mockResolvedValue({
    id: "rev-1",
    incusFingerprint: FP,
  } as never);
  bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));
});

const sites = [
  {
    name: "host create",
    realDb: "admission-lock.pg.test.ts",
    run: () => createHost(owner, createHostInput.parse({ slug: "lab", label: "Lab" })),
    insert: () => db.sandboxHost.create,
    arrange: () => db.sandboxHost.create.mockResolvedValue({ id: "host-2" } as never),
  },
  {
    name: "host token create",
    realDb: "admission-lock.pg.test.ts",
    run: () =>
      createHostToken(owner, createHostTokenInput.parse({ hostId: "host-1", name: "daemon" })),
    insert: () => db.hostToken.create,
    arrange: () => db.hostToken.create.mockResolvedValue({ id: "token-1" } as never),
  },
  {
    name: "SDK key create",
    realDb: "admission-lock.pg.test.ts",
    run: () =>
      createSdkKey(
        owner,
        createSdkKeyInput.parse({
          name: "ci",
          scopes: ["sandboxes:read"],
          resourceMode: "ALL_OWNED",
        }),
      ),
    insert: () => db.sdkKey.create,
    arrange: () =>
      db.sdkKey.create.mockResolvedValue({
        id: "key-1",
        name: "ci",
        resourceMode: "ALL_OWNED",
        scopes: ["sandboxes:read"],
        lookupPrefix: "p",
        lastUsedAt: null,
        revokedAt: null,
        expiresAt: null,
        createdAt: new Date(),
        HostAllowlist: [],
        RevisionAllowlist: [],
      } as never),
  },
  {
    name: "template create",
    realDb: "admission-lock.pg.test.ts",
    run: () =>
      createTemplate(
        owner,
        createTemplateInput.parse({
          hostId: "host-1",
          slug: "base",
          label: "Base",
          imageRef: "images:ubuntu/24.04/cloud",
        }),
      ),
    insert: () => db.sandboxTemplate.create,
    arrange: () =>
      db.sandboxTemplate.create.mockResolvedValue({
        id: "tpl-1",
        SandboxHost: null,
        _count: { Sandboxes: 0 },
      } as never),
  },
] as const;

describe("unit (recording tx; real-DB coverage named per site) — C21-ACCTDEL-RACE: owner FOR SHARE lock precedes each owner-row insert", () => {
  it("C21c-B-1 each site's real-DB marking matches the sites admission-lock.pg.test.ts actually runs", () => {
    const pg = readFileSync(new URL("./admission-lock.pg.test.ts", import.meta.url), "utf8");
    const covered = new Set([...pg.matchAll(/^\s*name: "([^"]+)",$/gm)].map((match) => match[1]));
    expect(covered.size).toBeGreaterThan(0);
    expect(sites.map((site) => ({ site: site.name, realDb: site.realDb }))).toEqual(
      sites.map((site) => ({
        site: site.name,
        realDb: covered.has(site.name) ? "admission-lock.pg.test.ts" : "no real-DB test yet",
      })),
    );
  });

  it.each(sites)("$name locks the owner before inserting ($realDb)", async (site) => {
    site.arrange();
    await site.run();
    expect(ownerLockOrder()).toBeLessThan(insertOrder(site.insert()));
  });

  it.each(sites)(
    "$name refuses a tombstoned owner with CONFLICT and inserts nothing ($realDb)",
    async (site) => {
      site.arrange();
      db.user.findUnique.mockResolvedValue({ deletionRequestedAt: new Date() } as never);
      await expect(site.run()).rejects.toMatchObject({
        code: "CONFLICT",
        message: "Account deletion is in progress.",
      });
      expect(site.insert()).not.toHaveBeenCalled();
    },
  );

  it.each(sites)("$name maps an owner-FK P2003 race to CONFLICT ($realDb)", async (site) => {
    site.arrange();
    site.insert().mockRejectedValueOnce(Object.assign(new Error("fk"), { code: "P2003" }) as never);
    await expect(site.run()).rejects.toMatchObject({ code: "CONFLICT" });
  });
});
