import { describe, expect, it } from "vitest";
import {
  buildPhase,
  buildProblem,
  canCancelBuild,
  canRetryCommunity,
  checkBuildSource,
  communityRefreshSkip,
  composeBuildSource,
  disabledReasonKey,
  dockerfileEnvNames,
  isLaunchableRevision,
  parseBuildArgs,
  parseTemplateBuildsSearch,
  plainTail,
  recipeCodeKey,
  secretLikeNames,
} from "./template-build-rules";

const NONE = { mode: "asWritten" as const, presets: [], domains: "" };

describe("composeBuildSource", () => {
  it("keeps a Dockerfile as written by default", () => {
    expect(composeBuildSource("dockerfile", "FROM base\nRUN true\n", NONE)).toEqual({
      ok: true,
      body: { dockerfile: "FROM base\nRUN true\n" },
    });
  });

  it("appends egress extension lines after the user's text (line numbers unchanged)", () => {
    const composed = composeBuildSource("dockerfile", "FROM base\nRUN true", {
      mode: "allowlist",
      presets: ["pypi", "npm"],
      domains: "Example.com, api.example.com",
    });
    expect(composed).toEqual({
      ok: true,
      body: {
        dockerfile:
          "FROM base\nRUN true\n# wssp:egress-mode allowlist\n# wssp:egress-preset pypi npm\n# wssp:egress domain example.com api.example.com\n",
      },
    });
  });

  it("refuses to override egress a Dockerfile already declares", () => {
    expect(
      composeBuildSource("dockerfile", "FROM base\n# wssp:egress-preset pypi\n", {
        mode: "allowlist",
        presets: [],
        domains: "",
      }),
    ).toEqual({ ok: false, problem: { kind: "egressConflict" } });
  });

  it("replaces a recipe's egress and refuses non-object JSON", () => {
    expect(
      composeBuildSource("recipe", JSON.stringify({ version: 1, egress: { mode: "open" } }), {
        mode: "allowlist",
        presets: ["github"],
        domains: "",
      }),
    ).toEqual({
      ok: true,
      body: { recipe: { version: 1, egress: { mode: "allowlist", presets: ["github"] } } },
    });
    expect(composeBuildSource("recipe", "[1]", NONE)).toEqual({
      ok: false,
      problem: { kind: "json" },
    });
    expect(composeBuildSource("recipe", "{", NONE)).toEqual({
      ok: false,
      problem: { kind: "json" },
    });
    expect(composeBuildSource("dockerfile", "  ", NONE)).toEqual({
      ok: false,
      problem: { kind: "empty" },
    });
  });
});

describe("checkBuildSource (the server's recipe package, in the browser)", () => {
  it("reports a refused instruction with its line and column", () => {
    const check = checkBuildSource({ dockerfile: "FROM base\nADD x /x\n" }, {});
    expect(check.problem).toMatchObject({
      kind: "recipe",
      code: "recipe_unsupported_instruction",
      line: 2,
    });
  });

  it("detects COPY so the dialog can require a context", () => {
    expect(checkBuildSource({ dockerfile: "FROM base\nCOPY app/ /app/\n" }, {})).toEqual({
      problem: null,
      hasCopy: true,
    });
    expect(checkBuildSource({ dockerfile: "FROM base\nRUN true\n" }, {})).toEqual({
      problem: null,
      hasCopy: false,
    });
  });
});

describe("build args and secret names", () => {
  it("parses NAME=value lines and reports the first bad line", () => {
    expect(parseBuildArgs("A=1\n\nB_2=x=y\n")).toEqual({
      args: { A: "1", B_2: "x=y" },
      invalidLine: null,
    });
    expect(parseBuildArgs("A=1\n2B=x")).toEqual({ args: {}, invalidLine: 2 });
    expect(parseBuildArgs("NOEQUALS")).toEqual({ args: {}, invalidLine: 1 });
  });

  it("flags secret-looking names from args and Dockerfile ENV/ARG", () => {
    expect(
      secretLikeNames([
        "NODE_MAJOR",
        "GITHUB_TOKEN",
        ...dockerfileEnvNames("ENV API_KEY=x OTHER=y\nARG db_password\n"),
      ]),
    ).toEqual(["API_KEY", "GITHUB_TOKEN", "db_password"]);
  });
});

describe("typed refusals", () => {
  it("maps template.build_* codes with their typed fields", () => {
    expect(
      buildProblem({
        code: "BAD_REQUEST",
        data: {
          code: "template.build_recipe_invalid",
          recipeCode: "recipe_syntax",
          line: 3,
          column: 1,
        },
      }),
    ).toEqual({ kind: "recipe", code: "recipe_syntax", line: 3, column: 1 });
    expect(
      buildProblem({ data: { code: "template.build_disabled", reason: "lease_ceiling" } }),
    ).toEqual({ kind: "disabled", reason: "lease_ceiling" });
    expect(
      buildProblem({ data: { code: "template.build_concurrency", maxConcurrent: 2 } }),
    ).toEqual({ kind: "concurrency", max: 2 });
    expect(buildProblem({ data: { code: "template.build_not_cancellable" } })).toEqual({
      kind: "notCancellable",
    });
    expect(buildProblem({ code: "NOT_FOUND" })).toEqual({ kind: "notFound" });
    expect(buildProblem(new Error("x"))).toEqual({ kind: "generic" });
  });

  it("labels unknown recipe codes generically", () => {
    expect(recipeCodeKey("recipe_syntax")).toBe("recipe_syntax");
    expect(recipeCodeKey("timeout_exceeds_max")).toBe("timeout_exceeds_max");
    expect(recipeCodeKey("something_new")).toBe("other");
  });
});

describe("states, phases, search and tails", () => {
  it("cancels only non-terminal, non-cancelling builds", () => {
    expect(canCancelBuild("RUNNING")).toBe(true);
    expect(canCancelBuild("AWAITING_CONTEXT")).toBe(true);
    expect(canCancelBuild("CANCELLING")).toBe(false);
    expect(canCancelBuild("SUCCEEDED")).toBe(false);
  });

  it("reduces capture sub-phases and unknown phases", () => {
    expect(buildPhase("capturing:export")).toBe("capturing");
    expect(buildPhase("step")).toBe("step");
    expect(buildPhase("brand_new")).toBe("other");
    expect(buildPhase(null)).toBeNull();
  });

  it("keeps only valid search filters", () => {
    expect(parseTemplateBuildsSearch({ templateId: "tpl_1", state: "FAILED" })).toEqual({
      templateId: "tpl_1",
      state: "FAILED",
    });
    expect(parseTemplateBuildsSearch({ templateId: "../x", state: "NOPE" })).toEqual({});
  });

  it("drops terminal control characters from a failure tail", () => {
    expect(plainTail("\u001b[31merror\u001b[0m\n\tline\r\n")).toBe("[31merror[0m\n\tline\n");
  });
});

describe("community bases (community-base S12)", () => {
  it("maps the three community refusals and the timeout-misfit disabled reason", () => {
    expect(buildProblem({ data: { code: "template.community_key_scope" } })).toEqual({
      kind: "communityKeyScope",
    });
    expect(
      buildProblem({
        data: { code: "template.community_unavailable", reason: "no_tested_version" },
      }),
    ).toEqual({ kind: "communityUnavailable", reason: "no_tested_version" });
    expect(buildProblem({ data: { code: "template.community_unavailable" } })).toEqual({
      kind: "communityUnavailable",
      reason: "index_unreachable",
    });
    expect(buildProblem({ data: { code: "template.community_managed" } })).toEqual({
      kind: "communityManaged",
    });
    expect(disabledReasonKey("community_timeout_exceeds_max")).toBe(
      "community_timeout_exceeds_max",
    );
  });

  it("labels the verify phase", () => {
    expect(buildPhase("verifying")).toBe("verifying");
  });

  it("treats UPSTREAM pins and revisions awaiting verify as not launchable", () => {
    expect(isLaunchableRevision({ sourceKind: "BUILD", pendingVerifyBuildId: null })).toBe(true);
    expect(isLaunchableRevision({ sourceKind: "UPSTREAM", pendingVerifyBuildId: null })).toBe(
      false,
    );
    expect(isLaunchableRevision({ sourceKind: "BUILD", pendingVerifyBuildId: "tb_1" })).toBe(false);
  });

  it("offers Try again only after a failed or cancelled preparation", () => {
    expect(canRetryCommunity(undefined)).toBe(false);
    expect(canRetryCommunity({ state: "RUNNING" })).toBe(false);
    expect(canRetryCommunity({ state: "SUCCEEDED" })).toBe(false);
    expect(canRetryCommunity({ state: "FAILED" })).toBe(true);
    expect(canRetryCommunity({ state: "CANCELLED" })).toBe(true);
  });

  it("labels unknown refresh skips generically", () => {
    expect(communityRefreshSkip("too_recent")).toBe("too_recent");
    expect(communityRefreshSkip("brand_new")).toBe("other");
  });
});
