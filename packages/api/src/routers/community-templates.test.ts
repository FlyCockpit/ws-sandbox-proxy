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
  create: vi.fn(async () => ({
    template: { id: "tpl_1", slug: "ubuntu-26-04", label: "Ubuntu 26.04 LTS" },
    build: null,
    existing: false,
  })),
  setRefresh: vi.fn(async () => ({ ok: true as const })),
}));
vi.mock("../template-builds/community/procedures", () => ({
  createCommunityTemplateService: services.create,
  retryCommunityTemplateService: services.create,
  refreshCommunityTemplateService: services.create,
  setCommunityRefreshService: services.setRefresh,
}));

const { default: prisma } = await import("@wssp/db");
const { wireSensitiveSessionGateUser } = await import("@wssp/api/test/mock-prisma");
const { communityTemplatesRouter } = await import("./community-templates");

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

describe("communityTemplatesRouter (community-base S8, S12)", () => {
  beforeEach(() => vi.clearAllMocks());

  it("lists the tested catalog for a signed-in owner", async () => {
    const client = createRouterClient(communityTemplatesRouter, { context: context() });
    const { images } = await client.images();
    expect(images.map((image) => image.id)).toEqual(["ubuntu-26.04"]);
  });

  it("creates and toggles as the session's own principal", async () => {
    const client = createRouterClient(communityTemplatesRouter, { context: context() });
    await expect(
      client.create({
        source: "ubuntu-26.04",
        idempotencyKey: "k-1",
        target: { sandboxHostId: "h" },
      }),
    ).resolves.toMatchObject({ template: { id: "tpl_1" }, build: null, existing: false });
    expect(services.create).toHaveBeenCalledWith(
      { kind: "session", ownerId: "owner-1" },
      { source: "ubuntu-26.04", idempotencyKey: "k-1", target: { sandboxHostId: "h" } },
    );
    await client.setRefresh({ templateId: "tpl_1", refresh: false });
    expect(services.setRefresh).toHaveBeenCalledWith(
      { kind: "session", ownerId: "owner-1" },
      { templateId: "tpl_1", refresh: false },
    );
  });

  it("refuses a signed-out caller and a malformed target", async () => {
    const anonymous = createRouterClient(communityTemplatesRouter, { context: { session: null } });
    await expect(anonymous.images()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    const client = createRouterClient(communityTemplatesRouter, { context: context() });
    await expect(
      client.create({
        source: "ubuntu-26.04",
        idempotencyKey: "k-1",
        target: { sandboxHostId: "h", poolId: "p" } as never,
      }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(services.create).not.toHaveBeenCalled();
  });
});
