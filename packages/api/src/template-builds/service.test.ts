import { describe, expect, it, vi } from "vitest";

const transaction = vi.hoisted(() => vi.fn());
vi.mock("@wssp/db", () => ({ default: { $transaction: transaction } }));
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
vi.mock("./config", async (original) => ({
  ...(await original<typeof import("./config")>()),
  templateBuildsConfig: () => config,
}));

const { acceptTemplateBuild, chargeMonthOf, frozenCapacityWait } = await import("./service");

const session = { kind: "session" as const, ownerId: "owner-1" };
const recipe = (steps: unknown[] = [{ type: "run", script: "true" }], extra = {}) => ({
  version: 1,
  from: { template: "base" },
  steps,
  ...extra,
});
const input = (over: Record<string, unknown> = {}) => ({
  idempotencyKey: "k1",
  template: { slug: "target" },
  recipe: recipe(),
  sandboxHostId: "host-1",
  ...over,
});
const refused = (over: Record<string, unknown>, data: Record<string, unknown>) =>
  expect(acceptTemplateBuild(session, input(over) as never)).rejects.toMatchObject({ data });

describe("acceptance refusals before any row (§3.3 lease ceiling, §3.6, §6.3)", () => {
  it("refuses a timeout whose lease would exceed the deployment ceiling, and one above the max", async () => {
    config.leaseCeilingMs = 120 * 60_000;
    await refused(
      { timeoutMinutes: 50 },
      { code: "template.build_recipe_invalid", recipeCode: "timeout_exceeds_lease_ceiling" },
    );
    config.leaseCeilingMs = 24 * 3_600_000;
    await refused(
      { timeoutMinutes: 61 },
      { code: "template.build_recipe_invalid", recipeCode: "timeout_exceeds_max" },
    );
    expect(transaction).not.toHaveBeenCalled();
  });

  it("reports the disabled reason (off, lease_ceiling, …)", async () => {
    config.enabled = false;
    config.reason = "lease_ceiling";
    await refused({}, { code: "template.build_disabled", reason: "lease_ceiling" });
    config.enabled = true;
    config.reason = null;
  });

  it("accepts open egress: it follows the egress plan at materialization (§6.3)", async () => {
    transaction.mockRejectedValueOnce(new Error("reached the transaction"));
    await expect(
      acceptTemplateBuild(
        session,
        input({
          recipe: recipe(undefined, { egress: { mode: "open", presets: ["pypi"] } }),
        }) as never,
      ),
    ).rejects.toThrow("reached the transaction");
  });

  it("COPY requires a context (≤ the max); no COPY refuses one", async () => {
    const copy = recipe([
      { type: "workdir", path: "/app" },
      { type: "copy", src: ["."], dest: "./" },
    ]);
    await refused({ recipe: copy }, { code: "template.build_context_required" });
    await refused(
      { recipe: copy, contextSha256: "a".repeat(64), contextBytes: 4096 },
      { code: "template.build_context_too_large" },
    );
    await refused(
      { contextSha256: "a".repeat(64), contextBytes: 10 },
      { code: "template.build_recipe_invalid", recipeCode: "context_without_copy" },
    );
  });

  it("SDK keys move only latest; a wait needs a pool; exactly one target", async () => {
    const key = {
      kind: "sdkKey" as const,
      keyId: "key-1",
      ownerId: "owner-1",
      expiresAt: null,
      resourceMode: "ALL_OWNED" as const,
      scopes: new Set<string>(),
      allowedHostIds: new Set<string>(),
      allowedRevisionIds: new Set<string>(),
      allowedPoolIds: new Set<string>(),
    };
    await expect(
      acceptTemplateBuild(key as never, input({ tag: "v2" }) as never),
    ).rejects.toMatchObject({
      data: { recipeCode: "tag_not_latest" },
    });
    await refused({ waitForCapacityMs: 60_000 }, { recipeCode: "wait_needs_pool" });
    await refused({ poolId: "pool-1" }, { recipeCode: "target_invalid" });
  });

  it("a recipe error carries its typed code and position", async () => {
    await refused(
      { recipe: undefined, dockerfile: "FROM base\nADD x /x\n" },
      {
        code: "template.build_recipe_invalid",
        recipeCode: "recipe_unsupported_instruction",
        line: 2,
      },
    );
  });
});

describe("frozen capacity wait (§3.7, I25)", () => {
  it("unlimited is the longest finite wait; a COPY build waits at most 6 h", () => {
    expect(frozenCapacityWait(undefined, true)).toBeNull();
    expect(frozenCapacityWait(60_000, true)).toBe(60_000);
    expect(frozenCapacityWait("unlimited", false)).toBe(2_073_600_000);
    expect(frozenCapacityWait("unlimited", true)).toBe(6 * 3_600_000);
    expect(frozenCapacityWait(7 * 3_600_000, true)).toBe(6 * 3_600_000);
  });
  it("charges the UTC month of the start", () => {
    expect(chargeMonthOf(new Date("2026-11-30T23:59:59Z")).toISOString()).toBe(
      "2026-11-01T00:00:00.000Z",
    );
  });
});
