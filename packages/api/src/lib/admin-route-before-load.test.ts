import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "admin-before-load-route-test" },
}));

vi.mock("@wssp/env/shared", () => ({ env: {} }));

vi.mock("@wssp/auth", () => ({
  auth: {
    api: {
      getSession: vi.fn(),
    },
  },
}));

vi.mock("@wssp/ui/components/selector-row", () => ({
  SelectorRow: () => null,
}));

vi.mock("@wssp/ui/lib/utils", () => ({
  cn: () => "",
}));

vi.mock("lucide-react", () => ({
  Activity: () => null,
  LayoutDashboard: () => null,
  Settings: () => null,
  Users: () => null,
}));

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (x: string) => x }),
}));

vi.mock("@/components/admin/two-factor-nudge", () => ({
  TwoFactorNudge: () => null,
}));

const { default: prisma } = await import("@wssp/db");
const { wireSensitiveSessionGateUser } = await import("@wssp/api/test/mock-prisma");
const { auth } = await import("@wssp/auth");
const { invalidateForceTwoFactorSettingsCache } = await import("./two-factor-policy");
const { Route } = await import("../../../../apps/web/src/routes/$lang/_app/admin");

const beforeLoad = Route.beforeLoad as () => Promise<{ session: { user: { id: string } } }>;

const establishedAdmin = {
  id: "admin",
  name: "Admin",
  email: "admin@example.com",
  role: "admin",
  emailVerified: true,
  twoFactorEnabled: false,
  createdAt: new Date("2020-01-01"),
};

/** Better Auth's session for `user`; the authoritative user row mirrors it. */
function sessionFor(user: typeof establishedAdmin) {
  wireSensitiveSessionGateUser(prisma as never, {
    role: user.role as "admin",
    emailVerified: user.emailVerified,
    twoFactorEnabled: user.twoFactorEnabled,
    createdAt: user.createdAt,
  });
  return { user, session: { id: "session-1", userId: user.id } };
}

describe("admin route beforeLoad through production server handlers", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invalidateForceTwoFactorSettingsCache();
  });

  it.each([undefined, "true", "false"] as const)(
    "uses live force-2FA settings when force is %s",
    async (force) => {
      prisma.appSetting.findMany.mockResolvedValue(
        force === undefined ? [] : [{ key: "force2faInternalUsers", value: force }],
      );
      vi.mocked(auth.api.getSession).mockResolvedValue(sessionFor(establishedAdmin));

      if (force === "false") {
        await expect(beforeLoad()).resolves.toMatchObject({
          session: { user: { id: "admin" } },
        });
      } else {
        await expect(beforeLoad()).rejects.toEqual({ isNotFound: true });
      }
      expect(prisma.appSetting.findMany).toHaveBeenCalledTimes(1);
      expect(auth.api.getSession).toHaveBeenCalledTimes(1);
    },
  );

  it("preserves grace, 404-hides non-admins and revoked sessions, and turns settings load failures into route errors", async () => {
    prisma.appSetting.findMany.mockResolvedValue([]);
    vi.mocked(auth.api.getSession).mockResolvedValue(
      sessionFor({ ...establishedAdmin, createdAt: new Date() }),
    );
    await expect(beforeLoad()).resolves.toMatchObject({
      session: { user: { id: "admin" } },
    });

    invalidateForceTwoFactorSettingsCache();
    prisma.appSetting.findMany.mockResolvedValue([
      { key: "force2faInternalUsers", value: "false" },
    ]);
    vi.mocked(auth.api.getSession).mockResolvedValue(
      sessionFor({ ...establishedAdmin, role: "user" }),
    );
    await expect(beforeLoad()).rejects.toEqual({ isNotFound: true });

    invalidateForceTwoFactorSettingsCache();
    vi.mocked(auth.api.getSession).mockResolvedValue(sessionFor(establishedAdmin));
    prisma.appSetting.findMany.mockRejectedValue(new Error("settings down"));
    // A gate that cannot decide is a retryable route error, never a 404 or an allow.
    await expect(beforeLoad()).rejects.toThrow("Route session unavailable");

    // A session without a live durable session row is hidden like any refusal.
    invalidateForceTwoFactorSettingsCache();
    prisma.appSetting.findMany.mockResolvedValue([]);
    vi.mocked(auth.api.getSession).mockResolvedValue(
      sessionFor({ ...establishedAdmin, twoFactorEnabled: true }),
    );
    prisma.session.findUnique.mockResolvedValueOnce(null);
    await expect(beforeLoad()).rejects.toEqual({ isNotFound: true });
  });
});
