import { z } from "zod";
import { canonicalJson, sha256Hex, utf8Bytes } from "./canonical";
import { type ExpandedRecipeEgress, expandRecipeEgress, type RecipeEgressRequest } from "./egress";
import { recipeFail } from "./errors";
import { type PlanOptions, planRecipe, type RecipePlan } from "./plan";
import { RECIPE_LIMITS, type Recipe, recipeSchema } from "./schema";

export type ParseRecipeOptions = PlanOptions;

export type ParsedRecipe = {
  recipe: Recipe;
  /** Canonical JSON (the `recipeDigest` input). */
  canonical: string;
  plan: RecipePlan;
  egress: ExpandedRecipeEgress | null;
};

function issueCode(issues: z.ZodError["issues"]) {
  const first = issues[0];
  const path = first?.path ?? [];
  if (path[0] === "steps" && path.length === 1 && first?.code === "too_big")
    return "recipe_too_many_steps" as const;
  if (path[0] === "scrubPaths") return "recipe_scrub_invalid" as const;
  if (path[0] === "resources") return "recipe_resources_invalid" as const;
  if (path[0] === "egress") return "recipe_egress_invalid" as const;
  if (path[0] === "from") return "recipe_from_invalid" as const;
  if (path[0] === "steps" && path[2] === "script" && first?.code !== "too_small")
    return "recipe_step_payload_too_large" as const;
  if (path[0] === "steps" && path[2] === "user") return "recipe_user_unsupported" as const;
  if (path[0] === "steps" && path[2] === "values") return "recipe_env_invalid" as const;
  return "recipe_invalid" as const;
}

/**
 * Validate a canonical recipe (JSON form, or the output of the Dockerfile
 * compiler) and dry-run it against the given build args. Every recipe bound
 * is checked here; acceptance calls it again with the request's args and
 * the base revision's default envs.
 */
export function parseRecipe(input: unknown, options: ParseRecipeOptions = {}): ParsedRecipe {
  const parsed = recipeSchema.safeParse(input);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const stepIndex =
      issue?.path[0] === "steps" && typeof issue.path[1] === "number" ? issue.path[1] : undefined;
    recipeFail({
      code: issueCode(parsed.error.issues),
      message: `${issue?.path.join(".") || "recipe"}: ${issue?.message ?? "invalid"}`,
      stepIndex,
    });
  }
  const recipe = parsed.data!;
  const canonical = canonicalJson(recipe);
  if (utf8Bytes(canonical) > RECIPE_LIMITS.recipeBytes)
    recipeFail({
      code: "recipe_too_large",
      message: `The canonical recipe is larger than ${RECIPE_LIMITS.recipeBytes} bytes.`,
    });
  const egress = expandRecipeEgress(recipe.egress);
  const plan = planRecipe(recipe, options);
  return { recipe, canonical, plan, egress };
}

export function canonicalRecipeJson(recipe: Recipe): string {
  return canonicalJson(recipe);
}

/** sha256 (lowercase hex) of the canonical recipe JSON. */
export function recipeDigest(recipe: Recipe): Promise<string> {
  return sha256Hex(canonicalJson(recipe));
}

export type BuildDigestInput = {
  recipeDigest: string;
  baseRevisionId: string;
  baseFingerprint: string;
  /** Effective args (`RecipePlan.args`). */
  args: Record<string, string>;
  contextSha256: string | null;
  /** Normalized request after preset expansion, or null when none. */
  egressRequest: RecipeEgressRequest | null;
  /**
   * The resolved build VM size (base < recipe `resources` < request
   * overrides) and the published revision's default disk. The build VM's
   * disk becomes the revision's `minDiskGiB`, so builds that differ only in
   * size are different results.
   */
  resources: { cpuCount: number; memoryMiB: number; diskGiB: number; defaultDiskGiB: number };
};

/**
 * The whole-recipe cache key component: recipe, resolved
 * base, effective args, context, the normalized egress request and the
 * resolved VM size, including the published default disk. Both the cache
 * lookup and active-build dedupe key on it, so a differently sized result is
 * never reused.
 */
export function buildDigest(input: BuildDigestInput): Promise<string> {
  return sha256Hex(
    canonicalJson({
      v: 1,
      recipe: input.recipeDigest,
      base: { revisionId: input.baseRevisionId, fingerprint: input.baseFingerprint },
      args: input.args,
      context: input.contextSha256 ?? "",
      egress: input.egressRequest,
      resources: {
        cpuCount: input.resources.cpuCount,
        memoryMiB: input.resources.memoryMiB,
        diskGiB: input.resources.diskGiB,
        defaultDiskGiB: input.resources.defaultDiskGiB,
      },
    }),
  );
}
