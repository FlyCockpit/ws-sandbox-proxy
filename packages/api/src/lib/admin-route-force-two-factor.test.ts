import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  decideAdminRouteAccess,
  type RouteSession,
} from "../../../../apps/web/src/lib/route-session-access";
import { resolveAdminRouteAccess } from "../../../../apps/web/src/server/admin-route-access";

vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "admin-route-policy-test" },
}));

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

const { invalidateForceTwoFactorSettingsCache } = await import("./two-factor-policy");
const { isAdminSessionAuthorized } = await import("./sensitive-session-two-factor-gate");
const { default: prisma } = await import("@wssp/db");
const { wireSensitiveSessionGateUser } = await import("@wssp/api/test/mock-prisma");

const db = prisma as unknown as {
  appSetting: { findMany: MockInstance };
};

const establishedAdmin: RouteSession = {
  user: {
    id: "admin-1",
    name: "Admin",
    email: "admin@example.com",
    emailVerified: true,
    role: "admin",
    twoFactorEnabled: false,
    createdAt: Date.UTC(2020, 0, 1),
  },
};

const graceAdmin: RouteSession = {
  user: {
    ...establishedAdmin.user,
    createdAt: Date.now() - 60_000,
  },
};

const enrolledAdmin: RouteSession = {
  user: {
    ...establishedAdmin.user,
    twoFactorEnabled: true,
  },
};

beforeEach(() => {
  vi.clearAllMocks();
  db.appSetting.findMany.mockResolvedValue([]);
  invalidateForceTwoFactorSettingsCache();
});

/**
 * The web `/admin` guard end to end below the HTTP layer: Better Auth's session
 * (the authoritative row mirrors it) resolved through the production resolver
 * and the shared server gate, with live force-2FA settings.
 */
async function decideWithLiveSettings(session: RouteSession | null) {
  if (session) {
    wireSensitiveSessionGateUser(prisma as never, {
      role: session.user.role as "admin",
      emailVerified: session.user.emailVerified,
      twoFactorEnabled: session.user.twoFactorEnabled ?? false,
      createdAt: new Date(session.user.createdAt ?? 0),
    });
  }
  const betterAuthSession = session
    ? {
        user: { ...session.user, createdAt: new Date(session.user.createdAt ?? 0) },
        session: { id: "session-1", userId: session.user.id },
      }
    : null;
  return decideAdminRouteAccess(
    await resolveAdminRouteAccess(
      new Headers(),
      async () => betterAuthSession,
      (candidate) => isAdminSessionAuthorized(candidate),
    ),
  );
}

describe("admin route gate with production force-2FA settings load", () => {
  it("404-hides established unenrolled admins when internal force defaults to on", async () => {
    await expect(decideWithLiveSettings(establishedAdmin)).resolves.toEqual({
      kind: "not-found",
    });
  });

  it("404-hides established unenrolled admins when internal force is explicitly on", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "true" }]);
    invalidateForceTwoFactorSettingsCache();
    await expect(decideWithLiveSettings(establishedAdmin)).resolves.toEqual({
      kind: "not-found",
    });
  });

  it("admits established unenrolled admins when internal force is explicitly off", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "false" }]);
    invalidateForceTwoFactorSettingsCache();
    await expect(decideWithLiveSettings(establishedAdmin)).resolves.toEqual({
      kind: "allow",
      session: establishedAdmin,
    });
  });

  it("admits grace-period admins while internal force is on", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "true" }]);
    invalidateForceTwoFactorSettingsCache();
    await expect(decideWithLiveSettings(graceAdmin)).resolves.toEqual({
      kind: "allow",
      session: graceAdmin,
    });
  });

  it("allows enrolled admins regardless of force settings", async () => {
    await expect(decideWithLiveSettings(enrolledAdmin)).resolves.toEqual({
      kind: "allow",
      session: enrolledAdmin,
    });
  });
});
