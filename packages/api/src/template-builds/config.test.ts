import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("@wssp/db", () => ({ default: {} }));

const { resolveTemplateBuildsConfig, accountTemplateBuildQuotas } = await import("./config");

const ENV = {
  TEMPLATE_BUILDS: "auto" as "auto" | "off",
  TEMPLATE_BUILD_MAX_MINUTES: 60,
  TEMPLATE_BUILD_MAX_CONCURRENT_PER_ACCOUNT: 2 as number | null,
  TEMPLATE_BUILD_MINUTES_PER_MONTH: 1000 as number | null,
  TEMPLATE_BUILD_CAPTURE_WINDOW_MINUTES: 60,
  TEMPLATE_BUILD_CONTEXT_MAX_BYTES: 1024 ** 3,
  TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT: 2 * 1024 ** 3,
  TEMPLATE_BUILD_CONTEXT_STAGED_BYTES: 8 * 1024 ** 3,
  TRANSFER_MAX_BYTES: 1024 ** 3,
};
const DAY = 24 * 60 * 60_000;
const resolve = (over: Partial<typeof ENV> = {}, leaseCeilingMs = DAY, image = "peer" as const) =>
  resolveTemplateBuildsConfig({
    env: { ...ENV, ...over },
    imageDistribution: image,
    leaseCeilingMs,
  });

describe("templateBuildsConfig resolution", () => {
  it("defaults: enabled, unclamped, 6 h context wait", () => {
    expect(resolve()).toMatchObject({
      enabled: true,
      reason: null,
      maxMinutes: 60,
      maxMinutesClamped: false,
      contextMaxBytes: 1024 ** 3,
      contextWaitMaxMs: 6 * 60 * 60_000,
      adjustments: [],
    });
  });

  it("a low lease ceiling shortens the max build time instead of disabling builds", () => {
    // 100 min ceiling - 60 window - 15 slack = 25 min.
    expect(resolve({}, 100 * 60_000)).toMatchObject({
      enabled: true,
      maxMinutes: 25,
      maxMinutesClamped: true,
    });
    // Exactly one minute of room still builds.
    expect(resolve({}, 76 * 60_000)).toMatchObject({ enabled: true, maxMinutes: 1 });
  });

  it("disables with lease_ceiling only below one minute of room", () => {
    expect(resolve({}, 75 * 60_000 + 59_999)).toMatchObject({
      enabled: false,
      reason: "lease_ceiling",
      maxMinutes: 0,
    });
  });

  it("reports off and image_distribution_off ahead of the lease reason", () => {
    expect(resolve({ TEMPLATE_BUILDS: "off" }, 0).reason).toBe("off");
    expect(resolve({}, 0, "off" as never).reason).toBe("image_distribution_off");
  });

  it("clamps inconsistent byte budgets down, never up", () => {
    const config = resolve({
      TEMPLATE_BUILD_CONTEXT_MAX_BYTES: 1024 ** 3,
      TRANSFER_MAX_BYTES: 512 * 1024 ** 2,
      TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT: 4 * 1024 ** 3,
      TEMPLATE_BUILD_CONTEXT_STAGED_BYTES: 256 * 1024 ** 2,
    });
    expect(config.contextStagedBytesPerAccount).toBe(256 * 1024 ** 2);
    expect(config.contextMaxBytes).toBe(256 * 1024 ** 2);
    expect(config.adjustments).toHaveLength(2);
    expect(config.enabled).toBe(true);
  });

  it("admin quotas only lower the deployment ceiling", async () => {
    const config = resolve({ TEMPLATE_BUILD_MINUTES_PER_MONTH: null });
    const tx = (row: object | null) => ({
      accountImagePolicy: { findUnique: vi.fn().mockResolvedValue(row) },
    });
    expect(await accountTemplateBuildQuotas(tx(null) as never, "u", config)).toEqual({
      maxConcurrent: 2,
      minutesPerMonth: null,
    });
    expect(
      await accountTemplateBuildQuotas(
        tx({ adminConcurrentBuildsMax: 5, adminBuildMinutesPerMonthMax: 30 }) as never,
        "u",
        config,
      ),
    ).toEqual({ maxConcurrent: 2, minutesPerMonth: 30 });
  });
});
