import {
  egressPolicyInputSchema,
  isNormalizedEgressPolicy,
  normalizeEgressPolicy,
} from "@wssp/sandbox-contracts";
import { describe, expect, it } from "vitest";
import { EGRESS_PRESETS, expandRecipeEgress } from "./egress";
import { RecipeError } from "./errors";

describe("egress presets (security)", () => {
  it("ships exactly the planned presets", () => {
    expect(EGRESS_PRESETS.map((preset) => preset.name)).toEqual([
      "ubuntu-apt",
      "debian-apt",
      "pypi",
      "npm",
      "github",
    ]);
  });

  it.each(EGRESS_PRESETS.map((preset) => [preset.name, preset] as const))(
    "%s passes the egress input schema and the protected-set refusal unchanged",
    (_name, preset) => {
      const input = { domains: preset.domains, cidrs: preset.cidrs };
      expect(egressPolicyInputSchema.safeParse(input).success).toBe(true);
      // normalizeEgressPolicy refuses any CIDR intersecting a protected range
      // and any non-exact domain; the preset must already be canonical.
      const normalized = normalizeEgressPolicy(input);
      expect(normalized.domains).toEqual([...preset.domains].sort());
      expect(isNormalizedEgressPolicy(normalized)).toBe(true);
    },
  );

  it("routes preset grants through the same protected-range refusal as written grants", () => {
    for (const cidr of ["169.254.169.254/32", "100.100.100.200/32", "192.0.2.0/24"]) {
      try {
        expandRecipeEgress({ cidrs: [cidr], presets: ["pypi"] });
        throw new Error(`expected ${cidr} to be refused`);
      } catch (error) {
        expect(error).toBeInstanceOf(RecipeError);
        expect((error as RecipeError).code).toBe("recipe_egress_invalid");
      }
    }
  });

  it("refuses unknown presets and too many presets", () => {
    expect(() => expandRecipeEgress({ presets: ["nope"] })).toThrow(/Unknown egress preset/);
    expect(() =>
      expandRecipeEgress({ presets: Array.from({ length: 17 }, (_, i) => `p${i}`) }),
    ).toThrow(RecipeError);
  });
});

describe("egress request inference", () => {
  it("is null without a request", () => {
    expect(expandRecipeEgress(undefined)).toBeNull();
    expect(expandRecipeEgress({})).toBeNull();
  });
  it("infers allowlist from grants or presets (fail-safe) and keeps an explicit mode", () => {
    expect(expandRecipeEgress({ presets: ["npm"] })).toEqual({
      request: { mode: "allowlist", domains: ["registry.npmjs.org"], cidrs: [] },
      presets: ["npm"],
    });
    expect(expandRecipeEgress({ domains: [] })?.request.mode).toBe("allowlist");
    expect(
      expandRecipeEgress({ mode: "open", presets: ["pypi", "pypi"], domains: ["Example.COM"] }),
    ).toEqual({
      request: {
        mode: "open",
        domains: ["example.com", "files.pythonhosted.org", "pypi.org"],
        cidrs: [],
      },
      presets: ["pypi"],
    });
  });
});
