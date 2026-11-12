import { createRouterClient } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";

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

const services = vi.hoisted(() => ({
  failureTail: vi.fn(async () => ({ tail: "boom\n" })),
  usage: vi.fn(async () => ({ enabled: true })),
  list: vi.fn(async () => ({
    items: [
      { id: "b1", templateId: "tpl_1", revisionId: "rev_1" },
      { id: "b2", templateId: "tpl_gone", revisionId: null },
    ],
    nextCursor: null,
  })),
}));
vi.mock("../template-builds/views", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../template-builds/views")>()),
  getTemplateBuildFailureTail: services.failureTail,
  getTemplateBuildUsage: services.usage,
  listTemplateBuilds: services.list,
}));

const { default: prisma } = await import("@wssp/db");
const { wireSensitiveSessionGateUser } = await import("@wssp/api/test/mock-prisma");
const { templateBuildsRouter } = await import("./template-builds");

function context(): Context {
  const user = {
    id: "owner-1",
    email: "owner@example.com",
    name: "Owner",
    emailVerified: true,
    role: "user",
    twoFactorEnabled: true,
    image: null,
    banned: false,
    banReason: null,
    banExpires: null,
    createdAt: new Date("2025-01-01"),
    updatedAt: new Date("2025-01-01"),
  };
  wireSensitiveSessionGateUser(prisma as never, {
    role: user.role,
    emailVerified: user.emailVerified,
    twoFactorEnabled: user.twoFactorEnabled,
    createdAt: user.createdAt,
    banned: user.banned,
    banExpires: user.banExpires,
  });
  return {
    session: {
      user,
      session: {
        id: "s",
        userId: user.id,
        token: "t",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: "127.0.0.1",
        userAgent: "vitest",
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
      },
    } as Session,
  };
}

describe("templateBuildsRouter session-only reads", () => {
  beforeEach(() => vi.clearAllMocks());

  it("failureTail and usage run as the session's own principal", async () => {
    const client = createRouterClient(templateBuildsRouter, { context: context() });
    await expect(client.failureTail({ id: "build_1" })).resolves.toEqual({ tail: "boom\n" });
    expect(services.failureTail).toHaveBeenCalledWith(
      { kind: "session", ownerId: "owner-1" },
      { id: "build_1" },
    );
    await expect(client.usage()).resolves.toEqual({ enabled: true });
    expect(services.usage).toHaveBeenCalledWith({ kind: "session", ownerId: "owner-1" }, undefined);
  });

  it("refuses a signed-out caller before any read", async () => {
    const client = createRouterClient(templateBuildsRouter, { context: { session: null } });
    await expect(client.failureTail({ id: "build_1" })).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
    await expect(client.usage()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(services.failureTail).not.toHaveBeenCalled();
    expect(services.usage).not.toHaveBeenCalled();
  });
});

describe("templateBuildsRouter template names", () => {
  it("lists builds with their template's name, owner-scoped (E1-A P3)", async () => {
    vi.mocked(prisma.sandboxTemplate.findMany).mockResolvedValue([
      { id: "tpl_1", slug: "my-app", label: "My app" },
    ] as never);
    vi.mocked(prisma.sandboxTemplateRevision.findMany).mockResolvedValue([] as never);
    const client = createRouterClient(templateBuildsRouter, { context: context() });
    const page = await client.list({});
    expect(page.items.map((build) => [build.id, build.templateName])).toEqual([
      ["b1", "My app"],
      ["b2", null],
    ]);
    expect(prisma.sandboxTemplate.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { userId: "owner-1", id: { in: ["tpl_1", "tpl_gone"] } },
        take: 2,
      }),
    );
  });

  it("adds the template slug and the result revision's number, owner-scoped", async () => {
    vi.mocked(prisma.sandboxTemplate.findMany).mockResolvedValue([
      { id: "tpl_1", slug: "my-app", label: "My app" },
    ] as never);
    vi.mocked(prisma.sandboxTemplateRevision.findMany).mockResolvedValue([
      { id: "rev_1", revision: 3 },
    ] as never);
    const client = createRouterClient(templateBuildsRouter, { context: context() });
    const page = await client.list({});
    expect(page.items.map((build) => [build.id, build.templateSlug, build.revisionNumber])).toEqual(
      [
        ["b1", "my-app", 3],
        ["b2", null, null],
      ],
    );
    expect(prisma.sandboxTemplateRevision.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: { in: ["rev_1"] }, Template: { userId: "owner-1" } },
        take: 1,
      }),
    );
  });
});
