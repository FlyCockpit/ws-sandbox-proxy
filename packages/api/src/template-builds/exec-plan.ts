import type { Prisma } from "@wssp/db";
import {
  type PlannedCopy,
  type PlannedRun,
  parseRecipe,
  plannedStepPrivileged,
  type Recipe,
  type RecipePlan,
  type RecipeUser,
} from "@wssp/template-recipe";
import { loadRevisionDefaults } from "../sandbox/revision-config";

/**
 * What a build VM executes, in order: an optional root prelude that creates the recipe's WORKDIRs the
 * way Docker does (each new directory owned by the USER in effect when it was
 * declared), then every planned RUN and COPY. ENV, ARG, WORKDIR and USER fold
 * into state and become no operation.
 *
 * Pure and deterministic: the orchestrator recomputes it from the stored
 * recipe, build args and the base revision's defaults whenever it freezes a
 * step's input, and the capture finalizer recomputes it for the revision
 * defaults (final ENV, WORKDIR as default cwd, `builtWithRoot`).
 */
type PreludeStep = {
  kind: "prelude";
  /** Recipe index of the first WORKDIR (failures report it). */
  stepIndex: number;
  script: string;
};
export type ExecStep = PreludeStep | PlannedRun | PlannedCopy;
/** `start`: the recipe's start/ready commands, stored on the revision (B9).
 * `builtWithRoot`: any executed step had root authority (see
 * `execStepPrivileged`); the revision's provenance comes from here. */
export type ExecPlan = {
  plan: RecipePlan;
  steps: ExecStep[];
  start: Recipe["start"] | null;
  builtWithRoot: boolean;
};

/** Whether an exec step runs with root authority: the prelude always, a
 * COPY always (the helper writes as root), a RUN when its user is root. */
function execStepPrivileged(step: ExecStep): boolean {
  return step.kind === "prelude" || plannedStepPrivileged(step);
}

/** POSIX single-quote a value for `sh` (any byte except NUL, which guest
 * paths already refuse). */
function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

/** The root script that creates each WORKDIR that does not exist yet. */
function workdirPreludeScript(
  dirs: readonly { path: string; owner: RecipeUser }[],
  guest: { uid: number; gid: number },
): string {
  const lines = [
    "set -eu",
    'mk() { if [ ! -e "$1" ]; then mkdir -p -- "$1"; if [ "$2" = user ]; then chown -- "$3" "$1"; fi; fi; }',
    ...dirs.map(
      (dir) => `mk ${shellQuote(dir.path)} ${dir.owner} ${shellQuote(`${guest.uid}:${guest.gid}`)}`,
    ),
  ];
  return `${lines.join("\n")}\n`;
}

/** Each WORKDIR of the plan, paired with the USER in effect at its step. */
function workdirOwners(recipe: Recipe, plan: RecipePlan) {
  const out: { path: string; owner: RecipeUser; stepIndex: number }[] = [];
  let user: RecipeUser = "user";
  let next = 0;
  recipe.steps.forEach((step, stepIndex) => {
    if (step.type === "user") user = step.user;
    if (step.type === "workdir") {
      const path = plan.workdirs[next++];
      if (path !== undefined) out.push({ path, owner: user, stepIndex });
    }
  });
  return out;
}

/** Throws the recipe package's `RecipeError` when the stored recipe no longer
 * plans (it was planned at acceptance with the same inputs). */
export function buildExecPlan(input: {
  recipe: unknown;
  buildArgs: Record<string, string>;
  baseEnvs: Record<string, string>;
  guest: { uid: number; gid: number };
}): ExecPlan {
  const parsed = parseRecipe(input.recipe, {
    buildArgs: input.buildArgs,
    baseEnvs: input.baseEnvs,
  });
  const dirs = workdirOwners(parsed.recipe, parsed.plan);
  const steps: ExecStep[] = [];
  // Deduplicate (a later WORKDIR may repeat an earlier one), keep the first.
  const seen = new Set<string>();
  const unique = dirs.filter((dir) => !seen.has(dir.path) && seen.add(dir.path));
  if (unique.length > 0)
    steps.push({
      kind: "prelude",
      stepIndex: unique[0]!.stepIndex,
      script: workdirPreludeScript(unique, input.guest),
    });
  steps.push(...parsed.plan.steps);
  return {
    plan: parsed.plan,
    steps,
    start: parsed.recipe.start ?? null,
    builtWithRoot: steps.some(execStepPrivileged),
  };
}

/** The exec plan of a stored build: its recipe and args against the base
 * revision's guest identity and private default envs. */
export async function loadBuildExecPlan(
  tx: Prisma.TransactionClient,
  build: { userId: string; baseRevisionId: string; recipe: unknown; buildArgs: unknown },
): Promise<ExecPlan> {
  const base = await tx.sandboxTemplateRevision.findFirstOrThrow({
    where: { id: build.baseRevisionId, userId: build.userId },
    select: { guestUid: true, guestGid: true },
  });
  const baseEnvs = Object.fromEntries(
    await loadRevisionDefaults(tx, build.baseRevisionId, build.userId),
  );
  return buildExecPlan({
    recipe: build.recipe,
    buildArgs: (build.buildArgs ?? {}) as Record<string, string>,
    baseEnvs,
    guest: { uid: base.guestUid, gid: base.guestGid },
  });
}

/** Display metadata of one exec step, stored in `SandboxTemplateBuild.steps`. */
export type BuildStepRecord = {
  n: number;
  /** Recipe step index (the prelude reports its first WORKDIR). */
  stepIndex: number;
  kind: "prelude" | "run" | "copy";
  state: "pending" | "running" | "succeeded" | "failed";
  operationId: string | null;
  exitCode: number | null;
};

export function initialStepRecords(steps: readonly ExecStep[]): BuildStepRecord[] {
  return steps.map((step, n) => ({
    n,
    stepIndex: step.stepIndex,
    kind: step.kind,
    state: "pending",
    operationId: null,
    exitCode: null,
  }));
}

export function parseStepRecords(value: unknown): BuildStepRecord[] {
  return Array.isArray(value) ? (value as BuildStepRecord[]) : [];
}
