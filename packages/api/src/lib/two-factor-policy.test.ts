import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "two-factor-policy-test-secret" },
}));

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

const { default: prisma } = await import("@wssp/db");
const {
  getForcedTwoFactorSettingsRecord,
  invalidateForceTwoFactorSettingsCache,
  isForcedTwoFactorEnabledForRole,
} = await import("./two-factor-policy");

const db = prisma as unknown as {
  appSetting: { findMany: MockInstance };
};

describe("force-2FA settings cache generation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invalidateForceTwoFactorSettingsCache();
    db.appSetting.findMany.mockResolvedValue([]);
  });

  it("does not publish a stale read after invalidation during enable", async () => {
    let releaseFirstRead: (() => void) | undefined;
    const firstReadBlocked = new Promise<void>((resolve) => {
      releaseFirstRead = resolve;
    });

    db.appSetting.findMany
      .mockImplementationOnce(async () => {
        await firstReadBlocked;
        return [{ key: "force2faPublicUsers", value: "false" }];
      })
      .mockResolvedValue([{ key: "force2faPublicUsers", value: "true" }]);

    const inFlight = isForcedTwoFactorEnabledForRole("user");
    invalidateForceTwoFactorSettingsCache();
    releaseFirstRead?.();
    await expect(inFlight).resolves.toBe(true);

    invalidateForceTwoFactorSettingsCache();
    await expect(isForcedTwoFactorEnabledForRole("user")).resolves.toBe(true);
    expect(db.appSetting.findMany.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it("does not publish a stale read after invalidation during disable", async () => {
    let releaseFirstRead: (() => void) | undefined;
    const firstReadBlocked = new Promise<void>((resolve) => {
      releaseFirstRead = resolve;
    });

    db.appSetting.findMany
      .mockImplementationOnce(async () => {
        await firstReadBlocked;
        return [{ key: "force2faPublicUsers", value: "true" }];
      })
      .mockResolvedValue([{ key: "force2faPublicUsers", value: "false" }]);

    const inFlight = isForcedTwoFactorEnabledForRole("user");
    invalidateForceTwoFactorSettingsCache();
    releaseFirstRead?.();
    await expect(inFlight).resolves.toBe(false);

    invalidateForceTwoFactorSettingsCache();
    await expect(isForcedTwoFactorEnabledForRole("user")).resolves.toBe(false);
  });

  it("exposes settings through getForcedTwoFactorSettingsRecord", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "false" }]);
    invalidateForceTwoFactorSettingsCache();
    await expect(getForcedTwoFactorSettingsRecord()).resolves.toEqual({
      force2faInternalUsers: "false",
    });
  });
});
