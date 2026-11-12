import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("../sandbox/image-store/config", () => ({
  effectiveImagePlacement: vi.fn(async () => "ANY_NODE"),
  imageDistributionMode: vi.fn(() => "s3"),
}));

const { builderSql, foreignBuildsPermitted, loadBuildPlacement, requireBuildPlacement } =
  await import("./placement");
const { effectiveImagePlacement } = await import("../sandbox/image-store/config");

const placement = (over: Partial<Parameters<typeof foreignBuildsPermitted>[0]> = {}) => ({
  allowForeign: true,
  targetPlacement: "ANY_NODE" as const,
  imageMode: "s3" as const,
  ...over,
});

type BuildRow = { templateId: string; state?: string; cancelRequestedAt?: Date | null };
function txWith(row: BuildRow | null, allowForeignBuilds?: boolean) {
  const build = row && { state: "QUEUED", cancelRequestedAt: null, ...row };
  return {
    sandboxTemplateBuild: { findFirst: vi.fn(async () => build) },
    accountImagePolicy: {
      findUnique: vi.fn(async () =>
        allowForeignBuilds === undefined ? null : { allowForeignBuilds },
      ),
    },
  };
}

describe("foreignBuildsPermitted (r1 M-4)", () => {
  it.each([
    [placement(), true],
    [placement({ allowForeign: false }), false],
    [placement({ imageMode: "peer" }), false],
    [placement({ imageMode: "off" }), false],
    [placement({ targetPlacement: "OWNED_NODES_ONLY" }), false],
  ])("%o → %s", (input, expected) => {
    expect(foreignBuildsPermitted(input)).toBe(expected);
  });
});

describe("builderSql", () => {
  it("binds the requester-side policy as one parameter and tests every node flag", () => {
    for (const permitted of [true, false]) {
      const { offers, admits } = builderSql("owner-1", placement({ allowForeign: permitted }));
      for (const flag of ["'build'", "'acceptForeignBuilds'"]) {
        expect(offers.sql).toContain(flag);
        expect(admits.sql).toContain(flag);
      }
      expect(offers.sql).not.toContain("'acceptForeign')");
      expect(admits.sql).toContain("'acceptForeign')");
      expect(admits.values).toContain("owner-1");
      expect(admits.values).toContain(permitted);
    }
  });
});

describe("loadBuildPlacement", () => {
  it("is null for a build the owner does not have", async () => {
    const tx = txWith(null, true);
    await expect(loadBuildPlacement(tx as never, "owner-1", "build-1")).resolves.toBeNull();
    expect(tx.sandboxTemplateBuild.findFirst).toHaveBeenCalledWith({
      where: { id: "build-1", userId: "owner-1" },
      select: { templateId: true, state: true, cancelRequestedAt: true },
    });
    expect(tx.accountImagePolicy.findUnique).not.toHaveBeenCalled();
  });

  it("reads the owner opt-in, the target template policy and the image mode", async () => {
    const tx = txWith({ templateId: "tpl-1" }, true);
    await expect(loadBuildPlacement(tx as never, "owner-1", "build-1")).resolves.toEqual({
      allowForeign: true,
      targetPlacement: "ANY_NODE",
      imageMode: "s3",
    });
    expect(effectiveImagePlacement).toHaveBeenCalledWith(tx, "owner-1", "tpl-1");
  });

  it("defaults the opt-in to off without a policy row", async () => {
    const tx = txWith({ templateId: "tpl-1" });
    await expect(loadBuildPlacement(tx as never, "owner-1", "build-1")).resolves.toMatchObject({
      allowForeign: false,
    });
  });

  // The create-side state check (§3.4, N18): read after owner placement, which
  // cancel also takes, so a cancelled build can never place its VM.
  it.each([
    ["QUEUED", null, true],
    ["PLACING", null, true],
    ["QUEUED", new Date(), false],
    ["PLACING", new Date(), false],
    ["CANCELLING", new Date(), false],
    ["RUNNING", null, false],
    ["AWAITING_CONTEXT", null, false],
    ["FAILED", null, false],
  ])("a %s build (cancel %s) places: %s", async (state, cancelRequestedAt, places) => {
    const tx = txWith({ templateId: "tpl-1", state, cancelRequestedAt }, true);
    const result = loadBuildPlacement(tx as never, "owner-1", "build-1");
    if (places) await expect(result).resolves.not.toBeNull();
    else {
      await expect(result).resolves.toBeNull();
      await expect(requireBuildPlacement(tx as never, "owner-1", "build-1")).rejects.toMatchObject({
        code: "FORBIDDEN",
        data: { code: "build.authority_lost" },
      });
    }
  });

  it("refuses a missing build with the typed authority code", async () => {
    await expect(
      requireBuildPlacement(txWith(null) as never, "owner-1", "build-1"),
    ).rejects.toMatchObject({ code: "FORBIDDEN", data: { code: "build.authority_lost" } });
  });
});
