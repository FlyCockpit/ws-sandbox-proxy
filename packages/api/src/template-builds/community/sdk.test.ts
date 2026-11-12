import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: {},
  SIGNUP_ENABLED: false,
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

const mocks = vi.hoisted(() => ({
  create: vi.fn(),
  buildDto: vi.fn((build: { id: string }) => ({ id: build.id, dto: true })),
}));
vi.mock("./procedures", () => ({ createCommunityTemplateService: mocks.create }));
vi.mock("../views", () => ({ toTemplateBuildDto: mocks.buildDto }));

const { default: prisma } = await import("@wssp/db");
const { createCommunityTemplateForSdk } = await import("./sdk");

const key = { kind: "sdkKey", ownerId: "owner-1", keyId: "key-1" } as never;
const row = {
  id: "tpl_1",
  slug: "ubuntu-26-04",
  label: "Ubuntu 26.04 LTS",
  archivedAt: null,
  createdAt: new Date("2026-11-06T00:00:00Z"),
  updatedAt: new Date("2026-11-06T00:00:00Z"),
  imagePlacement: "INHERIT",
  captureKeep: 3,
  pruneAfterDays: null,
  communitySource: "ubuntu-26.04",
  communityRefresh: true,
};

describe("createCommunityTemplateForSdk (community-base S11)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(prisma.sandboxTemplate.findFirstOrThrow).mockResolvedValue(row as never);
  });

  it("maps the body to the shared service and answers the template DTO and build", async () => {
    mocks.create.mockResolvedValue({
      template: { id: "tpl_1", slug: row.slug, label: row.label },
      build: { id: "tb_1" },
      existing: false,
    });
    const created = await createCommunityTemplateForSdk(
      key,
      { source: "ubuntu-26.04", poolId: "pool_1", label: "Base" },
      "idem-1",
    );
    expect(mocks.create).toHaveBeenCalledWith(key, {
      source: "ubuntu-26.04",
      idempotencyKey: "idem-1",
      target: { poolId: "pool_1" },
      label: "Base",
    });
    // The template is read owner-scoped, never by id alone.
    expect(prisma.sandboxTemplate.findFirstOrThrow).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: "tpl_1", userId: "owner-1" } }),
    );
    expect(created).toEqual({
      template: expect.objectContaining({
        id: "tpl_1",
        createdAt: "2026-11-06T00:00:00.000Z",
        community: { source: "ubuntu-26.04", refresh: true },
      }),
      build: { id: "tb_1", dto: true },
      existing: false,
    });
  });

  it("targets a host and passes a joined template with no active build through", async () => {
    mocks.create.mockResolvedValue({
      template: { id: "tpl_1", slug: row.slug, label: row.label },
      build: null,
      existing: true,
    });
    const created = await createCommunityTemplateForSdk(
      key,
      { source: "ubuntu-26.04", sandboxHostId: "host_1" },
      "idem-2",
    );
    expect(mocks.create).toHaveBeenCalledWith(key, {
      source: "ubuntu-26.04",
      idempotencyKey: "idem-2",
      target: { sandboxHostId: "host_1" },
    });
    expect(created).toMatchObject({ build: null, existing: true });
    expect(mocks.buildDto).not.toHaveBeenCalled();
  });

  it("propagates the service's typed allowlist refusal", async () => {
    const refusal = Object.assign(new Error("forbidden"), {
      data: { code: "template.community_key_scope" },
    });
    mocks.create.mockRejectedValue(refusal);
    await expect(
      createCommunityTemplateForSdk(key, { source: "ubuntu-26.04", poolId: "p" }, "idem-3"),
    ).rejects.toBe(refusal);
    expect(prisma.sandboxTemplate.findFirstOrThrow).not.toHaveBeenCalled();
  });
});
