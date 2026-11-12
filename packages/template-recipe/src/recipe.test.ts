// biome-ignore-all lint/suspicious/noTemplateCurlyInString: recipe substitution syntax is literal ${…} text
import { commandPayloadBytes } from "@wssp/sandbox-contracts";
import { describe, expect, it } from "vitest";
import { RecipeError } from "./errors";
import { buildDigest, canonicalRecipeJson, parseRecipe, recipeDigest } from "./recipe";
import { RECIPE_LIMITS, type Recipe } from "./schema";

const base = { version: 1, from: { template: "wssp-base" } } as const;

function refusal(run: () => unknown): RecipeError {
  try {
    run();
  } catch (error) {
    if (error instanceof RecipeError) return error;
    throw error;
  }
  throw new Error("expected a RecipeError");
}

describe("recipe bounds (security)", () => {
  it("refuses exponential ENV self-expansion while substituting, quickly", () => {
    // Each step quadruples A: unbounded, step 40 would be 4^40 characters.
    const steps = [
      { type: "env" as const, values: { A: "xxxxxxxx" } },
      ...Array.from({ length: 200 }, () => ({
        type: "env" as const,
        values: { A: "$A$A$A$A" },
      })),
    ];
    const started = performance.now();
    const error = refusal(() => parseRecipe({ ...base, steps }));
    expect(error.code).toBe("recipe_expansion_too_large");
    // 8 * 4^5 = 8192 bytes: step 5 is the first over the 4096-byte value cap.
    expect(error.stepIndex).toBe(5);
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it("refuses ARG-default chains the same way", () => {
    const steps = [
      { type: "arg" as const, name: "A", default: "y".repeat(64) },
      ...Array.from({ length: 64 }, () => ({
        type: "arg" as const,
        name: "A",
        default: "${A}${A}",
      })),
    ];
    expect(refusal(() => parseRecipe({ ...base, steps })).code).toBe("recipe_expansion_too_large");
  });

  it("bounds the total expansion of a recipe, not just each value", () => {
    // Every value stays under the per-value cap (4000 bytes); the sum of
    // 5 x 64 of them (1.28 MB) exceeds the shared planning budget.
    const values = Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`V${i}`, "$A$A$A$A"]));
    const steps = [
      { type: "arg" as const, name: "A", default: "z".repeat(1000) },
      ...Array.from({ length: 5 }, () => ({ type: "env" as const, values })),
    ];
    const error = refusal(() => parseRecipe({ ...base, steps }));
    expect(error.code).toBe("recipe_expansion_too_large");
    expect(error.message).toMatch(/budget/);
  });

  it("accepts exactly the step limit and refuses one more", () => {
    const steps = Array.from({ length: RECIPE_LIMITS.steps }, () => ({
      type: "user" as const,
      user: "user" as const,
    }));
    expect(parseRecipe({ ...base, steps }).recipe.steps).toHaveLength(256);
    const error = refusal(() =>
      parseRecipe({ ...base, steps: [...steps, { type: "user", user: "root" }] }),
    );
    expect(error.code).toBe("recipe_too_many_steps");
  });

  it("refuses a canonical recipe over 64 KiB", () => {
    // 20 run steps of ~3.5 KiB each: every step is in bounds, the whole is not.
    const steps = Array.from({ length: 20 }, (_, i) => ({
      type: "run" as const,
      script: `echo ${i} ${"x".repeat(3500)}`,
    }));
    expect(refusal(() => parseRecipe({ ...base, steps })).code).toBe("recipe_too_large");
    expect(() => parseRecipe({ ...base, steps: steps.slice(0, 15) })).not.toThrow();
  });

  it("accepts a run step whose merged payload is exactly 32 KiB and refuses +1 byte", () => {
    const envs = { A: "1", NODE_MAJOR: "22" };
    const cwd = "/home/user/app";
    const steps = (script: string) => [
      { type: "arg", name: "NODE_MAJOR", default: "22" },
      { type: "env", values: { A: "1" } },
      { type: "workdir", path: cwd },
      { type: "run", script },
    ];
    const overhead = commandPayloadBytes({ script: "", cwd, envs });
    const exact = "x".repeat(RECIPE_LIMITS.stepPayloadBytes - overhead);
    expect(commandPayloadBytes({ script: exact, cwd, envs })).toBe(32768);
    expect(() => parseRecipe({ ...base, steps: steps(exact) })).not.toThrow();
    const error = refusal(() => parseRecipe({ ...base, steps: steps(`${exact}x`) }));
    expect(error.code).toBe("recipe_step_payload_too_large");
    expect(error.stepIndex).toBe(3);
  });

  it("counts the base revision's default envs in the payload at acceptance", () => {
    const script = "x".repeat(RECIPE_LIMITS.stepPayloadBytes - 100);
    expect(() => parseRecipe({ ...base, steps: [{ type: "run", script }] })).not.toThrow();
    const error = refusal(() =>
      parseRecipe(
        { ...base, steps: [{ type: "run", script }] },
        { baseEnvs: { BIG: "y".repeat(200) } },
      ),
    );
    expect(error.code).toBe("recipe_step_payload_too_large");
  });

  it("refuses an effective env over the sandbox env limits", () => {
    const values = Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`V${i}`, "1"]));
    const error = refusal(() =>
      parseRecipe({
        ...base,
        steps: [
          { type: "env", values },
          { type: "run", script: "true" },
        ],
      }),
    );
    expect(error.code).toBe("recipe_env_invalid");
  });

  it("refuses reserved env names, unknown users and too many scrub paths or copy sources", () => {
    expect(
      refusal(() => parseRecipe({ ...base, steps: [{ type: "env", values: { HOME: "/x" } }] }))
        .code,
    ).toBe("recipe_env_reserved");
    expect(
      refusal(() => parseRecipe({ ...base, steps: [{ type: "user", user: "nobody" }] })).code,
    ).toBe("recipe_user_unsupported");
    expect(
      refusal(() =>
        parseRecipe({ ...base, steps: [], scrubPaths: Array.from({ length: 17 }, () => "/x") }),
      ).code,
    ).toBe("recipe_scrub_invalid");
    expect(
      refusal(() =>
        parseRecipe({
          ...base,
          steps: [
            { type: "workdir", path: "/app" },
            { type: "copy", src: Array.from({ length: 65 }, () => "a"), dest: "./" },
          ],
        }),
      ).code,
    ).toBe("recipe_invalid");
  });

  it("accepts start and ready within their bounds (B9)", () => {
    const start = { command: "npm start", ready: "curl -sf localhost:3000", readyTimeoutMs: 60000 };
    expect(parseRecipe({ ...base, steps: [], start }).recipe.start).toEqual(start);
    for (const bad of [
      { command: "" },
      { command: "npm start", readyTimeoutMs: 999 },
      { command: "npm start", readyTimeoutMs: 600001 },
      { command: "x".repeat(4097) },
      { command: "npm start", user: "root" },
    ])
      expect(
        refusal(() => parseRecipe({ ...base, steps: [], start: bad })).code,
        JSON.stringify(bad),
      ).toBe("recipe_invalid");
  });

  it("refuses unknown keys anywhere (strict schema)", () => {
    expect(refusal(() => parseRecipe({ ...base, steps: [], extra: 1 })).code).toBe(
      "recipe_invalid",
    );
    expect(
      refusal(() => parseRecipe({ ...base, steps: [{ type: "run", script: "x", shell: "zsh" }] }))
        .code,
    ).toBe("recipe_invalid");
  });

  it("refuses build args no ARG declares", () => {
    expect(refusal(() => parseRecipe({ ...base, steps: [] }, { buildArgs: { X: "1" } })).code).toBe(
      "recipe_arg_undeclared",
    );
  });
});

describe("COPY path rules (security)", () => {
  const copy = (src: string[], dest: string) =>
    parseRecipe({
      ...base,
      steps: [
        { type: "workdir", path: "/home/user/app" },
        { type: "copy", src, dest },
      ],
    });
  it("refuses absolute and parent sources and inner wildcards", () => {
    expect(refusal(() => copy(["/etc/passwd"], "./")).code).toBe("recipe_path_invalid");
    expect(refusal(() => copy(["../secret"], "./")).code).toBe("recipe_path_invalid");
    expect(refusal(() => copy(["a/../../b"], "./")).code).toBe("recipe_path_invalid");
    expect(refusal(() => copy(["*/x"], "./")).code).toBe("recipe_path_invalid");
    expect(refusal(() => copy(["a"], "../../etc/")).code).toBe("recipe_path_invalid");
  });
  it("normalizes sources and resolves the destination against WORKDIR", () => {
    const { plan } = copy(["./app/", ".", "src/*.ts"], "out/");
    expect(plan.steps[0]).toMatchObject({
      kind: "copy",
      src: ["app/", ".", "src/*.ts"],
      dest: "/home/user/app/out",
      destIsDir: true,
      owner: "root",
    });
  });
  it("needs a directory destination for several sources or a wildcard", () => {
    expect(refusal(() => copy(["a", "b"], "out")).code).toBe("recipe_copy_dest_not_dir");
    expect(refusal(() => copy(["*.ts"], "out")).code).toBe("recipe_copy_dest_not_dir");
  });
  it("refuses a relative destination before any WORKDIR", () => {
    const error = refusal(() =>
      parseRecipe({ ...base, steps: [{ type: "copy", src: ["a"], dest: "x" }] }),
    );
    expect(error.code).toBe("recipe_workdir_relative");
  });
});

describe("plan", () => {
  it("folds ENV/ARG/WORKDIR/USER and substitutes in ENV, WORKDIR and COPY only", () => {
    const { plan } = parseRecipe(
      {
        ...base,
        args: { VERSION: "2" },
        steps: [
          { type: "arg", name: "VERSION", default: "1" },
          { type: "arg", name: "UNSET" },
          { type: "env", values: { APP: "/srv/app-$VERSION", LIT: "\\$VERSION" } },
          { type: "workdir", path: "${APP}" },
          { type: "run", script: "echo $VERSION", user: "root" },
          { type: "user", user: "root" },
          { type: "copy", src: ["dist-${VERSION}/"], dest: "./", owner: "user" },
          { type: "run", script: "id -u" },
        ],
      },
      { buildArgs: { VERSION: "3" } },
    );
    expect(plan.args).toEqual({ VERSION: "3" });
    expect(plan.env).toEqual({ APP: "/srv/app-3", LIT: "$VERSION" });
    expect(plan.workdir).toBe("/srv/app-3");
    expect(plan.builtWithRoot).toBe(true);
    expect(plan.hasCopy).toBe(true);
    expect(plan.steps).toEqual([
      {
        kind: "run",
        stepIndex: 4,
        script: "echo $VERSION",
        user: "root",
        cwd: "/srv/app-3",
        envs: { VERSION: "3", APP: "/srv/app-3", LIT: "$VERSION" },
      },
      {
        kind: "copy",
        stepIndex: 6,
        src: ["dist-3/"],
        dest: "/srv/app-3",
        destIsDir: true,
        owner: "user",
        mode: null,
      },
      {
        kind: "run",
        stepIndex: 7,
        script: "id -u",
        user: "root",
        cwd: "/srv/app-3",
        envs: { VERSION: "3", APP: "/srv/app-3", LIT: "$VERSION" },
      },
    ]);
  });
});

describe("builtWithRoot derives from the complete plan (security)", () => {
  const plan = (steps: Recipe["steps"]) => parseRecipe({ ...base, steps }).plan;

  it("is false only when every executed step runs as the guest user", () => {
    expect(plan([{ type: "run", script: "id -u" }]).builtWithRoot).toBe(false);
    expect(plan([{ type: "env", values: { A: "1" } }]).builtWithRoot).toBe(false);
  });

  it("is set by a COPY: the helper writes as root whatever the final owner", () => {
    expect(
      plan([
        { type: "run", script: "id -u" },
        { type: "copy", src: ["passwd"], dest: "/etc/passwd", owner: "user" },
      ]).builtWithRoot,
    ).toBe(true);
  });

  it("is set by a WORKDIR: the root prelude creates it", () => {
    expect(plan([{ type: "workdir", path: "/etc/cron.d/app" }]).builtWithRoot).toBe(true);
  });

  it("is set by a root RUN", () => {
    expect(plan([{ type: "run", script: "id -u", user: "root" }]).builtWithRoot).toBe(true);
  });
});

describe("digests", () => {
  const recipe: Recipe = {
    version: 1,
    from: { template: "wssp-base", tag: "latest" },
    steps: [{ type: "env", values: { B: "2", A: "1" } }],
  };
  it("canonicalizes key order", async () => {
    const reordered = {
      steps: [{ values: { A: "1", B: "2" }, type: "env" }],
      from: { tag: "latest", template: "wssp-base" },
      version: 1,
    } as Recipe;
    expect(canonicalRecipeJson(recipe)).toBe(
      '{"from":{"tag":"latest","template":"wssp-base"},"steps":[{"type":"env","values":{"A":"1","B":"2"}}],"version":1}',
    );
    expect(await recipeDigest(reordered)).toBe(await recipeDigest(recipe));
    expect(await recipeDigest(recipe)).toMatch(/^[0-9a-f]{64}$/);
  });
  it("changes the build digest with every input", async () => {
    const input = {
      recipeDigest: await recipeDigest(recipe),
      baseRevisionId: "rev1",
      baseFingerprint: "f".repeat(64),
      args: {},
      contextSha256: null,
      egressRequest: null,
      resources: { cpuCount: 2, memoryMiB: 2048, diskGiB: 10 },
    };
    const digest = await buildDigest(input);
    const variants = await Promise.all([
      buildDigest({ ...input, baseRevisionId: "rev2" }),
      buildDigest({ ...input, args: { A: "1" } }),
      buildDigest({ ...input, contextSha256: "0".repeat(64) }),
      buildDigest({
        ...input,
        egressRequest: { mode: "allowlist", domains: ["pypi.org"], cidrs: [] },
      }),
      buildDigest({ ...input, resources: { ...input.resources, cpuCount: 4 } }),
      buildDigest({ ...input, resources: { ...input.resources, memoryMiB: 4096 } }),
      buildDigest({ ...input, resources: { ...input.resources, diskGiB: 20 } }),
    ]);
    expect(new Set([digest, ...variants]).size).toBe(8);
  });
});
