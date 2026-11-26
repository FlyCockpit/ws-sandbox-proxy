import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});

const { default: prisma } = await import("@wssp/db");
const { adminExistsForAppConfig, adminUserExists, resetAdminPresenceCache } = await import(
  "./admin-presence"
);
const db = prisma as unknown as { $queryRaw: MockInstance };

beforeEach(() => {
  db.$queryRaw.mockReset();
  resetAdminPresenceCache();
});

describe("adminUserExists", () => {
  it("asks the admin governance's active-administrator question", async () => {
    db.$queryRaw.mockResolvedValueOnce([{ present: true }]);
    expect(await adminUserExists()).toBe(true);
    db.$queryRaw.mockResolvedValueOnce([{ present: false }]);
    expect(await adminUserExists()).toBe(false);
    const strings = db.$queryRaw.mock.calls[0]?.[0] as TemplateStringsArray | undefined;
    const sql = strings ? strings.join("?") : "";
    // Verified, not deleting, not banned: the set `assertAdminRemains` keeps.
    expect(sql).toContain('"emailVerified" = true');
    expect(sql).toContain('"deletionRequestedAt" IS NULL');
  });
});

describe("adminExistsForAppConfig", () => {
  it("caches only a positive answer, for a minute", async () => {
    db.$queryRaw.mockResolvedValueOnce([{ present: false }]);
    expect(await adminExistsForAppConfig(0)).toBe(false);
    db.$queryRaw.mockResolvedValueOnce([{ present: true }]);
    expect(await adminExistsForAppConfig(1_000)).toBe(true);
    // Within the TTL: no query.
    expect(await adminExistsForAppConfig(60_000)).toBe(true);
    expect(db.$queryRaw).toHaveBeenCalledTimes(2);
    // After it: asks again, and sees a demoted last admin.
    db.$queryRaw.mockResolvedValueOnce([{ present: false }]);
    expect(await adminExistsForAppConfig(61_001)).toBe(false);
    expect(db.$queryRaw).toHaveBeenCalledTimes(3);
  });
});
