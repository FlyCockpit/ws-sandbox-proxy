// biome-ignore-all lint/suspicious/noTemplateCurlyInString: recipe substitution syntax is literal ${…} text
import { compileDockerfile } from "@wssp/template-recipe";
import { describe, expect, it } from "vitest";
import { WsspError } from "./errors";
import { Template } from "./template-builder";

describe("TemplateBuilder", () => {
  it("produces the same recipe as the equivalent Dockerfile", () => {
    const fromBuilder = Template()
      .fromTemplate("wssp-base:latest")
      .setUser("root")
      .runCmd("apt-get update && apt-get install -y jq")
      .setUser("user")
      .setEnvs({ FOO: "bar" })
      .setWorkdir("/home/user/app")
      .copy(["app/", "package.json"], "./", { owner: "user" })
      .runCmd(["npm ci", "npm run build"])
      .egress({ mode: "open", presets: ["npm"] })
      .toRecipe();
    const { recipe } = compileDockerfile(
      [
        "FROM wssp-base:latest",
        "# wssp:egress-mode open",
        "# wssp:egress-preset npm",
        "USER root",
        "RUN apt-get update && apt-get install -y jq",
        "USER user",
        "ENV FOO=bar",
        "WORKDIR /home/user/app",
        "COPY --chown=user app/ package.json ./",
        "RUN npm ci && npm run build",
      ].join("\n"),
    );
    expect(fromBuilder).toEqual(recipe);
  });

  it("keeps builder values literal (no $ substitution)", () => {
    const recipe = Template()
      .fromTemplate("wssp-base")
      .setEnvs({ PRICE: "$5", PATHISH: "${HOME}/x" })
      .toRecipe();
    expect(recipe.steps[0]).toEqual({
      type: "env",
      values: { PRICE: "\\$5", PATHISH: "\\${HOME}/x" },
    });
  });

  it("appends builder steps after a Dockerfile and applies sugar", () => {
    const recipe = Template()
      .fromDockerfile("FROM revision/r1\nRUN true\n")
      .aptInstall(["curl", "git"])
      .npmInstall("typescript", { global: true })
      .copy("bin/tool", "/usr/local/bin/", { mode: 0o755 })
      .toRecipe();
    expect(recipe.from).toEqual({ revisionId: "r1" });
    expect(recipe.steps).toEqual([
      { type: "run", script: "true" },
      {
        type: "run",
        user: "root",
        script:
          "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends 'curl' 'git' && rm -rf /var/lib/apt/lists/*",
      },
      { type: "run", user: "root", script: "npm install -g 'typescript'" },
      { type: "copy", src: ["bin/tool"], dest: "/usr/local/bin/", mode: "0755" },
    ]);
  });

  it("refuses bad input as invalid_request", () => {
    const fail = (run: () => unknown) => {
      try {
        run();
      } catch (error) {
        expect(error).toBeInstanceOf(WsspError);
        expect((error as WsspError).kind).toBe("invalid_request");
        return (error as WsspError).message;
      }
      throw new Error("expected a WsspError");
    };
    expect(fail(() => Template().toRecipe())).toMatch(/base/);
    expect(fail(() => Template().fromTemplate("Bad Name"))).toMatch(/selector/);
    expect(fail(() => Template().fromTemplate("a").fromTemplate("b"))).toMatch(/already set/);
    expect(fail(() => Template().fromTemplate("a").aptInstall("-oAPT::x"))).toMatch(/Invalid apt/);
    expect(fail(() => Template().fromDockerfile("FROM a\nADD x y\n"))).toMatch(/line 2/);
    expect(
      fail(() => Template().fromTemplate("a").setStartCmd("npm start", "true", 10).toRecipe()),
    ).toMatch(/recipe_invalid/);
    expect(fail(() => Template().fromTemplate("a").copy("../x", "/x").toRecipe())).toMatch(
      /recipe_path_invalid/,
    );
  });

  it("carries start and ready commands into the recipe (B9)", () => {
    const start = { command: "npm start", ready: "curl -sf localhost:3000", readyTimeoutMs: 5000 };
    expect(
      Template()
        .fromTemplate("wssp-base")
        .setStartCmd(start.command, start.ready, start.readyTimeoutMs)
        .toRecipe().start,
    ).toEqual(start);
    expect(
      Template()
        .fromDockerfile("FROM wssp-base\n# wssp:start npm start\n# wssp:ready true\n")
        .toRecipe().start,
    ).toEqual({ command: "npm start", ready: "true" });
  });

  it("records skipCache outside the recipe", () => {
    const builder = Template().fromTemplate("wssp-base").skipCache();
    expect(builder.noCache).toBe(true);
    expect(builder.toRecipe()).not.toHaveProperty("noCache");
  });
});
