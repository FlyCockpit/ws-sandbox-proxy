// biome-ignore-all lint/suspicious/noTemplateCurlyInString: recipe substitution syntax is literal ${…} text
import { describe, expect, it } from "vitest";
import { compileDockerfile } from "./dockerfile";
import { RecipeError } from "./errors";

function refusal(text: string, options = {}): RecipeError {
  try {
    compileDockerfile(text, options);
  } catch (error) {
    if (error instanceof RecipeError) return error;
    throw error;
  }
  throw new Error("expected a RecipeError");
}

describe("Dockerfile directives and bounds (security)", () => {
  it("refuses # escape= at its line, in any spelling", () => {
    for (const [text, line] of [
      ["# escape=`\nFROM wssp-base\n", 1],
      ["#escape=\\\nFROM wssp-base\n", 1],
      ["# syntax=docker/dockerfile:1\n# ESCAPE = `\nFROM wssp-base\n", 2],
    ] as const) {
      const error = refusal(text);
      expect(error.code).toBe("recipe_unsupported_directive");
      expect(error.line).toBe(line);
    }
  });

  it("ignores # syntax= with a warning and treats later directive-shaped lines as comments", () => {
    const result = compileDockerfile("# syntax=docker/dockerfile:1\nFROM wssp-base\n");
    expect(result.warnings).toEqual([
      { code: "directive_ignored", message: "The syntax directive is ignored.", line: 1 },
    ]);
    // After the directive block, `# escape=` is an ordinary comment (as in Docker).
    expect(() => compileDockerfile("FROM wssp-base\n# escape=`\nRUN true\n")).not.toThrow();
    expect(() => compileDockerfile("# hello\n# escape=`\nFROM wssp-base\n")).not.toThrow();
  });

  it("refuses a Dockerfile over 64 KiB and a NUL byte", () => {
    const big = `FROM wssp-base\n${"# padding\n".repeat(7000)}`;
    expect(refusal(big).code).toBe("recipe_too_large");
    const nul = refusal("FROM wssp-base\nRUN a\0b\n");
    expect([nul.code, nul.line, nul.column]).toEqual(["recipe_syntax", 2, 6]);
  });

  it("refuses more than 256 steps", () => {
    const text = `FROM wssp-base\n${"USER user\n".repeat(257)}`;
    const error = refusal(text);
    expect(error.code).toBe("recipe_too_many_steps");
  });

  it("maps a step payload refusal to the instruction's line", () => {
    const text = `FROM wssp-base\nENV A=1\nRUN ${"x".repeat(32760)}\n`;
    const error = refusal(text);
    expect([error.code, error.line, error.column]).toEqual(["recipe_step_payload_too_large", 3, 1]);
  });
});

describe("Dockerfile refusals", () => {
  it.each([
    ["FROM wssp-base\nADD x /x\n", "recipe_unsupported_instruction", 2, 1],
    ['FROM wssp-base\nCMD ["x"]\n', "recipe_unsupported_instruction", 2, 1],
    ["FROM wssp-base\nENTRYPOINT x\n", "recipe_unsupported_instruction", 2, 1],
    ['FROM wssp-base\n  SHELL ["/bin/bash"]\n', "recipe_unsupported_instruction", 2, 3],
    ["FROM wssp-base\nCOPY --from=build /a /b\n", "recipe_unsupported_instruction", 2, 6],
    ["FROM wssp-base\nRUN cat <<EOF\n", "recipe_unsupported_instruction", 2, 9],
    ["FROM wssp-base\nRUN --mount=type=cache,target=/x true\n", "recipe_unsupported_flag", 2, 5],
    ["FROM wssp-base\nCOPY --link a /a\n", "recipe_unsupported_flag", 2, 6],
    ["FROM wssp-base AS build\n", "recipe_multi_stage", 1, 16],
    ["FROM wssp-base\nFROM other\n", "recipe_multi_stage", 2, 1],
    ["RUN true\n", "recipe_from_missing", 1, 1],
    ["ARG X\nFROM wssp-base\n", "recipe_from_missing", 1, 1],
    ["FROM ubuntu:22.04/x\n", "recipe_from_invalid", 1, 6],
    ["FROM Wssp\n", "recipe_from_invalid", 1, 6],
    ["FROM wssp-base\nUSER nobody\n", "recipe_user_unsupported", 2, 6],
    ["FROM wssp-base\nCOPY --chown=nobody a /a\n", "recipe_user_unsupported", 2, 6],
    ["FROM wssp-base\nENV 1A=x\n", "recipe_env_invalid", 2, 5],
    ["FROM wssp-base\nMAINTAINER me\n", "recipe_unknown_instruction", 2, 1],
    ["FROM wssp-base\nENV A='x\n", "recipe_syntax", 2, 7],
    ["FROM wssp-base\n# wssp:bogus x\n", "recipe_unknown_extension", 2, 1],
    ["FROM wssp-base\nRUN a \\\n# wssp:scrub /x\n  b\n", "recipe_extension_misplaced", 3, 1],
    ["FROM wssp-base\n# wssp:ready curl -sf localhost\n", "recipe_syntax", 2, 1],
    ["FROM wssp-base\n# wssp:egress-preset nope\n", "recipe_egress_preset_unknown", 2, 1],
    ["FROM wssp-base\n# wssp:egress cidr 169.254.0.0/16\n", "recipe_egress_invalid", 2, 1],
    ["FROM wssp-base\nWORKDIR app\n", "recipe_workdir_relative", 2, 1],
  ] as const)("%j → %s", (text, code, line, column) => {
    const error = refusal(text);
    expect(error.code).toBe(code);
    expect([error.line, error.column]).toEqual([line, column]);
  });
});

describe("Dockerfile goldens", () => {
  it("compiles every supported instruction into the canonical recipe", () => {
    const text = [
      "# syntax=docker/dockerfile:1",
      "# A comment",
      "FROM wssp-base:stable",
      "# wssp:egress-mode open",
      "# wssp:egress-preset ubuntu-apt pypi",
      "# wssp:egress domain example.com",
      "# wssp:resources cpu=2 memory=4096 disk=32",
      "# wssp:scrub /home/user/.cache/pip",
      "ARG NODE_MAJOR=22 CHANNEL",
      "ENV FOO=bar BAZ=\"a b\" LIT='$HOME' ESC=\\$X LIVE=${NODE_MAJOR:-20}",
      "ENV LEGACY hello world",
      "WORKDIR /home/user/app",
      "USER root",
      "RUN apt-get update && \\",
      "    # inline comment dropped",
      "    apt-get install -y jq",
      'RUN ["echo", "it\'s"]',
      "USER user",
      "COPY --chown=user --chmod=0644 app/ package.json ./",
      'COPY ["with space", "/opt/x"]',
      "EXPOSE 3000",
      "LABEL a=b",
    ].join("\n");
    const result = compileDockerfile(text);
    expect(result.recipe).toEqual({
      version: 1,
      from: { template: "wssp-base", tag: "stable" },
      steps: [
        { type: "arg", name: "NODE_MAJOR", default: "22" },
        { type: "arg", name: "CHANNEL" },
        {
          type: "env",
          values: {
            FOO: "bar",
            BAZ: "a b",
            LIT: "\\$HOME",
            ESC: "\\$X",
            LIVE: "${NODE_MAJOR:-20}",
          },
        },
        { type: "env", values: { LEGACY: "hello world" } },
        { type: "workdir", path: "/home/user/app" },
        { type: "user", user: "root" },
        { type: "run", script: "apt-get update &&     apt-get install -y jq" },
        { type: "run", script: "'echo' 'it'\\''s'" },
        { type: "user", user: "user" },
        { type: "copy", src: ["app/", "package.json"], dest: "./", owner: "user", mode: "0644" },
        { type: "copy", src: ["with space"], dest: "/opt/x" },
      ],
      resources: { cpuCount: 2, memoryMiB: 4096, diskGiB: 32 },
      egress: { mode: "open", presets: ["ubuntu-apt", "pypi"], domains: ["example.com"] },
      scrubPaths: ["/home/user/.cache/pip"],
    });
    expect(result.warnings.map((warning) => [warning.code, warning.line])).toEqual([
      ["directive_ignored", 1],
      ["instruction_ignored", 21],
      ["instruction_ignored", 22],
    ]);
    expect(result.plan.env).toEqual({
      FOO: "bar",
      BAZ: "a b",
      LIT: "$HOME",
      ESC: "$X",
      LIVE: "22",
      LEGACY: "hello world",
    });
    expect(result.plan.builtWithRoot).toBe(true);
    expect(result.egress?.request.mode).toBe("open");
    expect(result.egress?.presets).toEqual(["pypi", "ubuntu-apt"]);
  });

  it("compiles # wssp:start and # wssp:ready (B9)", () => {
    const { recipe } = compileDockerfile(
      "FROM wssp-base\n# wssp:start npm start\n# wssp:ready curl -sf localhost:3000\n",
    );
    expect(recipe.start).toEqual({ command: "npm start", ready: "curl -sf localhost:3000" });
    expect(compileDockerfile("FROM wssp-base\n# wssp:start ./serve\n").recipe.start).toEqual({
      command: "./serve",
    });
  });

  it("accepts FROM revision/<id> and a bare slug", () => {
    expect(compileDockerfile("FROM revision/abc_123\n").recipe.from).toEqual({
      revisionId: "abc_123",
    });
    expect(compileDockerfile("from wssp-base\n").recipe.from).toEqual({ template: "wssp-base" });
  });
});
