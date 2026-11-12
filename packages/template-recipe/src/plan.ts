import { commandPayloadBytes, envSchema, guestPathSchema } from "@wssp/sandbox-contracts";
import { recipeFail } from "./errors";
import { RECIPE_LIMITS, RESERVED_ENV_NAMES, type Recipe, type RecipeUser } from "./schema";
import { type ExpansionBudget, substitute } from "./substitute";

/**
 * A recipe resolved against concrete build args: what the orchestrator runs.
 * ENV, ARG, WORKDIR and USER fold into state; only RUN and COPY become
 * operations. `stepIndex` is the recipe step index (failures report it).
 */
export type PlannedRun = {
  kind: "run";
  stepIndex: number;
  script: string;
  user: RecipeUser;
  /** Current WORKDIR, or null for the sandbox default. */
  cwd: string | null;
  /** In-scope ARG values overlaid by ENV values (ENV wins, as in Docker). */
  envs: Record<string, string>;
};
export type PlannedCopy = {
  kind: "copy";
  stepIndex: number;
  /** Normalized context-relative sources; "." is the context root. */
  src: string[];
  /** Absolute guest destination, lexically normalized. */
  dest: string;
  /** Destination was written with a trailing "/" (Docker directory form). */
  destIsDir: boolean;
  owner: RecipeUser;
  mode: string | null;
};
export type PlannedStep = PlannedRun | PlannedCopy;

export type RecipePlan = {
  steps: PlannedStep[];
  /** Effective values of declared ARGs that have one. Never persisted. */
  args: Record<string, string>;
  /** Final ENV of the recipe (merged over the base defaults by the server). */
  env: Record<string, string>;
  /** Final WORKDIR (the revision's default cwd), or null. */
  workdir: string | null;
  /** Every WORKDIR in order; the orchestrator creates them like Docker does. */
  workdirs: string[];
  user: RecipeUser;
  /**
   * Any part of the execution runs with root authority: a root RUN, any COPY
   * (the copy helper writes as root, whatever the final owner) or the WORKDIR
   * prelude (root creates every WORKDIR). Derived from the complete plan.
   */
  builtWithRoot: boolean;
  hasCopy: boolean;
};

/** Whether a planned step executes with root authority in the build VM.
 * COPY always does: the helper extracts and places files as root before it
 * applies `owner`, so it can replace any file in the image. */
export function plannedStepPrivileged(step: PlannedStep): boolean {
  return step.kind === "copy" || step.user === "root";
}

export type PlanOptions = {
  /** Request build args; each key must be a declared ARG. */
  buildArgs?: Record<string, string>;
  /** Base revision default envs: substitution fallbacks and payload sizing. */
  baseEnvs?: Record<string, string>;
};

function reservedName(name: string, stepIndex: number): void {
  if (RESERVED_ENV_NAMES.includes(name))
    recipeFail({
      code: "recipe_env_reserved",
      message: `${name} is reserved for the guest identity and cannot be set by a recipe.`,
      stepIndex,
    });
}

function pathFail(message: string, stepIndex: number): never {
  return recipeFail({ code: "recipe_path_invalid", message, stepIndex });
}

/** Absolute guest path, `.` removed; `..` refused (as the host refuses it). */
function resolveGuestPath(
  raw: string,
  workdir: string | null,
  stepIndex: number,
): { path: string; trailingSlash: boolean } {
  let absolute = raw;
  if (!raw.startsWith("/")) {
    if (workdir === null)
      recipeFail({
        code: "recipe_workdir_relative",
        message: `Relative path "${raw}" needs an earlier absolute WORKDIR.`,
        stepIndex,
      });
    absolute = `${workdir}/${raw}`;
  }
  const parts = absolute.split("/").filter((part) => part !== "" && part !== ".");
  if (parts.includes("..")) pathFail(`Path "${raw}" must not contain "..".`, stepIndex);
  const path = `/${parts.join("/")}`;
  const parsed = guestPathSchema.safeParse(path);
  if (!parsed.success) pathFail(`Path "${raw}" is not a valid guest path.`, stepIndex);
  return { path, trailingSlash: raw.endsWith("/") || raw.endsWith("/.") || raw === "." };
}

/**
 * Context-relative COPY source: no absolute paths, no `..`, `*` only in the
 * last segment. Leading `./` and repeated `/` are removed; a trailing `/` is
 * kept (directory hint). The context root is ".".
 */
export function normalizeCopySource(raw: string, stepIndex = 0): string {
  if (raw.startsWith("/")) pathFail(`COPY source "${raw}" must be context-relative.`, stepIndex);
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control bytes are refused, not matched away
  if (/[\x00-\x1f\x7f]/.test(raw))
    pathFail(`COPY source "${raw}" contains control characters.`, stepIndex);
  const trailing = raw.endsWith("/");
  const parts = raw.split("/").filter((part) => part !== "" && part !== ".");
  if (parts.length === 0) return ".";
  if (parts.includes("..")) pathFail(`COPY source "${raw}" must not contain "..".`, stepIndex);
  if (parts.slice(0, -1).some((part) => part.includes("*")))
    pathFail(`COPY source "${raw}" may use "*" only in its last segment.`, stepIndex);
  return `${parts.join("/")}${trailing ? "/" : ""}`;
}

export function planRecipe(recipe: Recipe, options: PlanOptions = {}): RecipePlan {
  const declared = new Set<string>();
  recipe.steps.forEach((step, index) => {
    if (step.type === "arg") {
      reservedName(step.name, index);
      declared.add(step.name);
    }
  });
  for (const [source, values] of [
    ["recipe args", recipe.args],
    ["build args", options.buildArgs],
  ] as const) {
    for (const name of Object.keys(values ?? {})) {
      if (!declared.has(name))
        recipeFail({
          code: "recipe_arg_undeclared",
          message: `${source} sets "${name}", which no ARG declares.`,
        });
    }
  }

  const base = options.baseEnvs ?? {};
  const args = new Map<string, string>();
  const env = new Map<string, string>();
  const vars = () => new Map([...Object.entries(base), ...args, ...env]);
  let user: RecipeUser = "user";
  let workdir: string | null = null;
  const workdirs: string[] = [];
  const steps: PlannedStep[] = [];
  // Substitution is bounded while it runs: each expanded value is capped at
  // the value limit and every expansion draws from one shared budget, so
  // self-referencing ENV/ARG chains cannot grow exponentially.
  const budget: ExpansionBudget = { remaining: RECIPE_LIMITS.expansionBytes };
  const at = (stepIndex: number) => ({
    stepIndex,
    maxBytes: RECIPE_LIMITS.textBytes,
    budget,
  });

  recipe.steps.forEach((step, stepIndex) => {
    switch (step.type) {
      case "arg": {
        const value =
          options.buildArgs?.[step.name] ??
          recipe.args?.[step.name] ??
          (step.default === undefined
            ? undefined
            : substitute(step.default, vars(), at(stepIndex)));
        if (value !== undefined) args.set(step.name, value);
        return;
      }
      case "env": {
        const scope = vars();
        for (const [name, raw] of Object.entries(step.values)) {
          reservedName(name, stepIndex);
          env.set(name, substitute(raw, scope, at(stepIndex)));
        }
        return;
      }
      case "workdir": {
        workdir = resolveGuestPath(
          substitute(step.path, vars(), at(stepIndex)),
          workdir,
          stepIndex,
        ).path;
        workdirs.push(workdir);
        return;
      }
      case "user":
        user = step.user;
        return;
      case "run": {
        const runAs = step.user ?? user;
        const envs = Object.fromEntries([...args, ...env]);
        const effective = { ...base, ...envs };
        if (!envSchema.safeParse(effective).success)
          recipeFail({
            code: "recipe_env_invalid",
            message: "The effective environment of this step exceeds the sandbox env limits.",
            stepIndex,
          });
        const payload = commandPayloadBytes({
          script: step.script,
          cwd: workdir ?? undefined,
          envs: effective,
        });
        if (payload > RECIPE_LIMITS.stepPayloadBytes)
          recipeFail({
            code: "recipe_step_payload_too_large",
            message: `Step payload is ${payload} bytes (script, cwd and envs); the limit is ${RECIPE_LIMITS.stepPayloadBytes}.`,
            stepIndex,
          });
        steps.push({
          kind: "run",
          stepIndex,
          script: step.script,
          user: runAs,
          cwd: workdir,
          envs,
        });
        return;
      }
      case "copy": {
        const scope = vars();
        const src = step.src.map((raw) =>
          normalizeCopySource(substitute(raw, scope, at(stepIndex)), stepIndex),
        );
        const dest = resolveGuestPath(
          substitute(step.dest, scope, at(stepIndex)),
          workdir,
          stepIndex,
        );
        if ((src.length > 1 || src.some((item) => item.includes("*"))) && !dest.trailingSlash)
          recipeFail({
            code: "recipe_copy_dest_not_dir",
            message: "COPY with several sources or a wildcard needs a destination ending in /.",
            stepIndex,
          });
        steps.push({
          kind: "copy",
          stepIndex,
          src,
          dest: dest.path,
          destIsDir: dest.trailingSlash,
          owner: step.owner ?? "root",
          mode: step.mode ?? null,
        });
        return;
      }
    }
  });

  const finalEnv = Object.fromEntries(env);
  if (!envSchema.safeParse({ ...base, ...finalEnv }).success)
    recipeFail({
      code: "recipe_env_invalid",
      message: "The final environment exceeds the sandbox env limits.",
    });
  return {
    steps,
    args: Object.fromEntries(args),
    env: finalEnv,
    workdir,
    workdirs,
    user,
    // Every WORKDIR is created by the root prelude (exec-plan), so any
    // WORKDIR is privileged execution too.
    builtWithRoot: workdirs.length > 0 || steps.some(plannedStepPrivileged),
    hasCopy: steps.some((step) => step.kind === "copy"),
  };
}
