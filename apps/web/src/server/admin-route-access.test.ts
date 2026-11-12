import { createRouterClient, ORPCError } from "@orpc/server";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { decideAdminRouteAccess } from "@/lib/route-session-access";

// The web app does not depend on @wssp/db, so mock the Prisma entry the API
// package resolves (by path) with the API's own deep mock.
vi.mock("../../../../packages/db/src/index", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));

const { default: prisma } = await import("../../../../packages/db/src/index");
const { adminOr404Procedure } = await import("@wssp/api");
const { isAdminSessionAuthorized } = await import(
  "@wssp/api/lib/sensitive-session-two-factor-gate"
);
const { invalidateForceTwoFactorSettingsCache } = await import("@wssp/api/lib/two-factor-policy");
const { resolveAdminRouteAccess } = await import("./admin-route-access");

const db = prisma as unknown as {
  appSetting: { findMany: MockInstance };
  user: { findUnique: MockInstance };
  session: { findUnique: MockInstance };
};

function betterAuthSession(overrides: Record<string, unknown> = {}) {
  return {
    user: {
      id: "admin-1",
      name: "Admin",
      email: "admin@example.com",
      emailVerified: true,
      role: "admin",
      twoFactorEnabled: true,
      createdAt: new Date("2020-01-01T00:00:00.000Z"),
      ...overrides,
    },
    session: { id: "session-1", userId: "admin-1", token: "secret-token" },
  };
}

describe("resolveAdminRouteAccess", () => {
  it("strips bearer credentials and never authorizes an anonymous request", async () => {
    const getSession = vi.fn().mockResolvedValue(null);
    const authorize = vi.fn();
    const headers = new Headers({ authorization: "Bearer wssp_sdk_x", cookie: "a=b" });

    expect(await resolveAdminRouteAccess(headers, getSession, authorize)).toEqual({
      status: "resolved",
      session: null,
      authorized: false,
    });
    const sent = getSession.mock.calls[0]?.[0].headers as Headers;
    expect(sent.get("authorization")).toBeNull();
    expect(sent.get("cookie")).toBe("a=b");
    expect(authorize).not.toHaveBeenCalled();
  });

  it("returns the gate's verdict with a token-free route session", async () => {
    const session = betterAuthSession();
    const authorize = vi.fn().mockResolvedValue(false);
    const resolution = await resolveAdminRouteAccess(
      new Headers(),
      vi.fn().mockResolvedValue(session),
      authorize,
    );
    expect(authorize).toHaveBeenCalledWith(session);
    expect(resolution).toMatchObject({ status: "resolved", authorized: false });
    expect(JSON.stringify(resolution)).not.toContain("secret-token");
  });

  it("turns a session or gate failure into a route error, never a 404 or an allow", async () => {
    expect(
      await resolveAdminRouteAccess(new Headers(), vi.fn().mockRejectedValue(new Error()), vi.fn()),
    ).toEqual({ status: "error" });
    expect(
      await resolveAdminRouteAccess(
        new Headers(),
        vi.fn().mockResolvedValue(betterAuthSession()),
        vi.fn().mockRejectedValue(new Error("db down")),
      ),
    ).toEqual({ status: "error" });
  });
});

describe("page guard and admin RPC agree", () => {
  const router = { ping: adminOr404Procedure.handler(() => ({ ok: true })) };

  beforeEach(() => {
    vi.clearAllMocks();
    invalidateForceTwoFactorSettingsCache();
    db.appSetting.findMany.mockResolvedValue([]);
    db.session.findUnique.mockResolvedValue({ id: "session-1" });
  });

  // The route guard renders not-found exactly when the RPC answers NOT_FOUND.
  it.each([
    ["enrolled admin", {}, true, true],
    [
      "grace-window admin",
      { twoFactorEnabled: false, createdAt: new Date(Date.now() - 60_000) },
      true,
      true,
    ],
    ["admin past the 2FA grace", { twoFactorEnabled: false }, true, false],
    ["unverified admin", { emailVerified: false }, true, false],
    ["non-admin", { role: "user" }, true, false],
    ["banned admin", { banned: true }, true, false],
    ["revoked admin session", {}, false, false],
  ] as const)("%s", async (_label, userOverrides, sessionRowExists, allowed) => {
    const session = betterAuthSession(userOverrides);
    db.user.findUnique.mockResolvedValue({
      twoFactorEnabled: session.user.twoFactorEnabled,
      role: session.user.role,
      emailVerified: session.user.emailVerified,
      banned: "banned" in userOverrides ? userOverrides.banned : false,
      banExpires: null,
      deletionRequestedAt: null,
      createdAt: session.user.createdAt,
    });
    if (!sessionRowExists) db.session.findUnique.mockResolvedValue(null);

    const decision = decideAdminRouteAccess(
      await resolveAdminRouteAccess(
        new Headers(),
        async () => session,
        (candidate) => isAdminSessionAuthorized(candidate),
      ),
    );
    const client = createRouterClient(router, {
      context: { session: session as never, clientIp: undefined },
    });
    const rpc = await client.ping().then(
      () => "ok" as const,
      (error: unknown) => (error instanceof ORPCError ? error.code : "other"),
    );

    expect(decision.kind).toBe(allowed ? "allow" : "not-found");
    expect(rpc).toBe(allowed ? "ok" : "NOT_FOUND");
  });
});
