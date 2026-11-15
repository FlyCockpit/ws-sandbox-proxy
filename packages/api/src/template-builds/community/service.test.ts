import { describe, expect, it, vi } from "vitest";

const transaction = vi.hoisted(() => vi.fn());
const findTemplates = vi.hoisted(() => vi.fn());
vi.mock("@wssp/db", () => ({
  default: { $transaction: transaction, sandboxTemplate: { findMany: findTemplates } },
}));
vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
const config = vi.hoisted(() => ({
  enabled: true,
  reason: null as string | null,
  maxMinutes: 60,
  captureWindowMinutes: 60,
  leaseCeilingMs: 24 * 3_600_000,
  contextMaxBytes: 1024,
}));
vi.mock("../config", async (original) => ({
  ...(await original<typeof import("../config")>()),
  templateBuildsConfig: () => config,
}));
const mode = vi.hoisted(() => ({ value: "peer" as "peer" | "s3" | "off" }));
vi.mock("../../sandbox/image-store/config", async (original) => ({
  ...(await original<typeof import("../../sandbox/image-store/config")>()),
  imageDistributionMode: () => mode.value,
}));

const {
  createCommunityTemplate,
  communityTimeoutMinutes,
  listCommunityImages,
  runCommunityRefreshScan,
} = await import("./service");
const { COMMUNITY_IMAGES } = await import("./catalog");

const session = { kind: "session" as const, ownerId: "owner-1" };
const allowlistKey = {
  kind: "sdkKey" as const,
  ownerId: "owner-1",
  keyId: "key-1",
  resourceMode: "ALLOWLIST" as const,
  scopes: new Set(["templates:write", "templates:build"]),
  allowedHostIds: new Set<string>(),
  allowedPoolIds: new Set<string>(),
  allowedRevisionIds: new Set<string>(),
};
const index = { newest: vi.fn(async () => Promise.reject(new Error("unused"))) };
const create = (principal: unknown) =>
  createCommunityTemplate(
    principal as never,
    { source: "ubuntu-26.04", idempotencyKey: "k", target: { sandboxHostId: "h" } },
    new Date(),
    index as never,
  );

describe("community create refusals before any row (S8 order)", () => {
  it("builds disabled, then image distribution off (D-M)", async () => {
    config.enabled = false;
    config.reason = "off";
    await expect(create(session)).rejects.toMatchObject({
      data: { code: "template.build_disabled", reason: "off" },
    });
    config.enabled = true;
    config.reason = null;
    mode.value = "off";
    await expect(create(session)).rejects.toMatchObject({
      data: { code: "template.build_disabled", reason: "image_distribution_off" },
    });
    mode.value = "peer";
    expect(listCommunityImages().disabledReason).toBeNull();
  });

  it("refuses an ALLOWLIST key with 403 template.community_key_scope (D-K)", async () => {
    await expect(create(allowlistKey)).rejects.toMatchObject({
      code: "FORBIDDEN",
      data: { code: "template.community_key_scope" },
    });
  });

  it("refuses a timeout misfit, never truncates it (S8)", async () => {
    expect(communityTimeoutMinutes(COMMUNITY_IMAGES[0]!)).toBe(40);
    config.maxMinutes = 35;
    await expect(create(session)).rejects.toMatchObject({
      data: { code: "template.build_disabled", reason: "community_timeout_exceeds_max" },
    });
    config.maxMinutes = 60;
  });

  it("maps an index failure to 409 template.community_unavailable before any transaction", async () => {
    const { CommunityIndexError } = await import("./index-client");
    index.newest.mockRejectedValueOnce(new CommunityIndexError("no_tested_version"));
    await expect(create(session)).rejects.toMatchObject({
      code: "CONFLICT",
      data: { code: "template.community_unavailable", reason: "no_tested_version" },
    });
    expect(transaction).not.toHaveBeenCalled();
  });

  it("lists tested entries only", () => {
    expect(listCommunityImages().images.map((image) => image.id)).toEqual(["ubuntu-26.04"]);
  });
});

describe("daily refresh scan (S10)", () => {
  const live = { id: "t1", userId: "owner-1", communitySource: COMMUNITY_IMAGES[0]!.id };

  it("reads nothing while builds or image distribution are off", async () => {
    findTemplates.mockClear();
    index.newest.mockClear();
    config.enabled = false;
    config.reason = "off";
    await expect(runCommunityRefreshScan(new Date(), index as never)).resolves.toEqual({
      started: 0,
      skipped: 0,
      stopped: false,
    });
    config.enabled = true;
    config.reason = null;
    mode.value = "off";
    await runCommunityRefreshScan(new Date(), index as never);
    mode.value = "peer";
    expect(findTemplates).not.toHaveBeenCalled();
    expect(index.newest).not.toHaveBeenCalled();
  });

  it("stops between templates when asked, before any index read or transaction", async () => {
    findTemplates.mockClear().mockResolvedValueOnce([live]);
    index.newest.mockClear();
    transaction.mockClear();
    await expect(runCommunityRefreshScan(new Date(), index as never, () => true)).resolves.toEqual({
      started: 0,
      skipped: 0,
      stopped: true,
    });
    expect(findTemplates).toHaveBeenCalledTimes(1);
    expect(index.newest).not.toHaveBeenCalled();
    expect(transaction).not.toHaveBeenCalled();
  });
});
