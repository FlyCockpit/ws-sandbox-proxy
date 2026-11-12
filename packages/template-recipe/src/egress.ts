import {
  EgressPolicyValidationError,
  type NormalizedEgressPolicy,
  normalizeEgressPolicy,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import presetsFile from "../../config/src/egress-presets.json";
import { recipeFail } from "./errors";

/**
 * Egress presets. Presets are pure data:
 * named lists of domains and CIDRs. They are expanded into ordinary grants
 * BEFORE the egress normalizer runs, so the normalizer (and the egress input
 * schema, which has no `presets` key) never sees a preset name, and every
 * preset grant passes the same protected-range refusal as a hand-written one.
 */
const presetSchema = z.strictObject({
  name: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  description: z.string().min(1).max(200),
  domains: z.array(z.string()),
  cidrs: z.array(z.string()),
});
export type EgressPreset = z.infer<typeof presetSchema>;

export const EGRESS_PRESETS: readonly EgressPreset[] = Object.freeze(
  z
    .strictObject({ version: z.literal(1), presets: z.array(presetSchema) })
    .parse(presetsFile)
    .presets.map((preset) => Object.freeze(preset)),
);
export const EGRESS_PRESET_NAMES: readonly string[] = Object.freeze(
  EGRESS_PRESETS.map((preset) => preset.name),
);
export const RECIPE_EGRESS_PRESETS_MAX = 16;

const presetByName = new Map(EGRESS_PRESETS.map((preset) => [preset.name, preset]));

export function egressPreset(name: string): EgressPreset | undefined {
  return presetByName.get(name);
}

/**
 * The normalized egress REQUEST of a build (never its effective policy, which
 * the server derives at materialization). `mode` follows the egress plan's
 * fail-safe inference: explicit `mode` wins; otherwise any grant or preset key
 * makes the request `allowlist`. In `open` mode the grants are fallback grants.
 */
export type RecipeEgressRequest = {
  mode: "open" | "allowlist";
  domains: string[];
  cidrs: string[];
};
export type ExpandedRecipeEgress = {
  request: RecipeEgressRequest;
  /** Sorted, de-duplicated preset names, for display and the build digest. */
  presets: string[];
};

export type RecipeEgressInput = {
  mode?: "open" | "allowlist" | undefined;
  presets?: string[] | undefined;
  domains?: string[] | undefined;
  cidrs?: string[] | undefined;
};

/**
 * Expand presets into grants and normalize. Returns null when the recipe makes
 * no egress request (absent or `{}`): the server then applies the same
 * default as a plain sandbox create.
 */
export function expandRecipeEgress(
  egress: RecipeEgressInput | undefined,
): ExpandedRecipeEgress | null {
  if (egress === undefined) return null;
  const keys = (["mode", "presets", "domains", "cidrs"] as const).filter(
    (key) => egress[key] !== undefined,
  );
  if (keys.length === 0) return null;
  const presets = [...new Set(egress.presets ?? [])].sort();
  if (presets.length > RECIPE_EGRESS_PRESETS_MAX)
    recipeFail({
      code: "recipe_egress_invalid",
      message: `At most ${RECIPE_EGRESS_PRESETS_MAX} egress presets.`,
    });
  const domains = [...(egress.domains ?? [])];
  const cidrs = [...(egress.cidrs ?? [])];
  for (const name of presets) {
    const preset = presetByName.get(name);
    if (!preset)
      recipeFail({
        code: "recipe_egress_preset_unknown",
        message: `Unknown egress preset "${name}". Known presets: ${EGRESS_PRESET_NAMES.join(", ")}.`,
      });
    domains.push(...preset!.domains);
    cidrs.push(...preset!.cidrs);
  }
  let normalized: NormalizedEgressPolicy;
  try {
    normalized = normalizeEgressPolicy({ domains, cidrs });
  } catch (error) {
    if (error instanceof EgressPolicyValidationError)
      recipeFail({ code: "recipe_egress_invalid", message: error.message });
    throw error;
  }
  const mode = egress.mode ?? "allowlist";
  return { request: { mode, domains: normalized.domains, cidrs: normalized.cidrs }, presets };
}
