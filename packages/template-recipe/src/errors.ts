/**
 * Every refusal the recipe package raises. The server maps a `RecipeError` to
 * `template.build_recipe_invalid{line?, column?, code}`; `code` is a stable
 * machine value, `message` is English diagnostic text for logs and the SDK.
 */
export const RECIPE_ERROR_CODES = [
  "recipe_invalid",
  "recipe_too_large",
  "recipe_too_many_steps",
  "recipe_step_payload_too_large",
  "recipe_env_invalid",
  "recipe_env_reserved",
  "recipe_arg_undeclared",
  "recipe_substitution_invalid",
  "recipe_expansion_too_large",
  "recipe_path_invalid",
  "recipe_workdir_relative",
  "recipe_copy_dest_not_dir",
  "recipe_user_unsupported",
  "recipe_from_invalid",
  "recipe_from_missing",
  "recipe_multi_stage",
  "recipe_unsupported_instruction",
  "recipe_unknown_instruction",
  "recipe_unsupported_flag",
  "recipe_unsupported_directive",
  "recipe_unknown_extension",
  "recipe_extension_misplaced",
  "recipe_syntax",
  "recipe_egress_invalid",
  "recipe_egress_preset_unknown",
  "recipe_scrub_invalid",
  "recipe_resources_invalid",
] as const;
export type RecipeErrorCode = (typeof RECIPE_ERROR_CODES)[number];

export type RecipeErrorDetail = {
  code: RecipeErrorCode;
  message: string;
  /** 1-based Dockerfile position, when the recipe came from a Dockerfile. */
  line?: number;
  column?: number;
  /** Recipe step index (0-based), when the refusal belongs to one step. */
  stepIndex?: number;
};

export class RecipeError extends Error {
  readonly code: RecipeErrorCode;
  readonly line: number | undefined;
  readonly column: number | undefined;
  readonly stepIndex: number | undefined;
  constructor(detail: RecipeErrorDetail) {
    super(detail.message);
    this.name = "RecipeError";
    this.code = detail.code;
    this.line = detail.line;
    this.column = detail.column;
    this.stepIndex = detail.stepIndex;
  }
  toJSON(): RecipeErrorDetail {
    return {
      code: this.code,
      message: this.message,
      ...(this.line === undefined ? {} : { line: this.line }),
      ...(this.column === undefined ? {} : { column: this.column }),
      ...(this.stepIndex === undefined ? {} : { stepIndex: this.stepIndex }),
    };
  }
}

export function recipeFail(detail: RecipeErrorDetail): never {
  throw new RecipeError(detail);
}

/** Non-fatal notes (ignored instructions or directives). */
export type RecipeWarning = {
  code: "directive_ignored" | "instruction_ignored";
  message: string;
  line: number;
};
