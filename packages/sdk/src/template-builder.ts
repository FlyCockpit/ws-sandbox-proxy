import {
  aptInstallStep,
  compileDockerfile,
  escapeSubstitution,
  npmInstallStep,
  parseRecipe,
  pipInstallStep,
  type Recipe,
  RecipeError,
  type RecipeStep,
  type RecipeUser,
  TEMPLATE_SLUG_PATTERN,
  TEMPLATE_TAG_PATTERN,
} from "@wssp/template-recipe";
import { WsspError } from "./errors";

export type { Recipe, RecipeStep, RecipeUser } from "@wssp/template-recipe";

export type TemplateEgressOptions = {
  /** `open` or `allowlist`; omitted with any grant or preset means allowlist. */
  mode?: "open" | "allowlist";
  /** Preset names (`ubuntu-apt`, `debian-apt`, `pypi`, `npm`, `github`). */
  presets?: string[];
  domains?: string[];
  cidrs?: string[];
};

export type CopyOptions = {
  /** Owner of the copied files: `root` (default, as in Docker) or `user`. */
  owner?: RecipeUser;
  /** Permission bits, e.g. `0o644` or `"0644"`. */
  mode?: number | string;
};

function invalid(error: unknown): WsspError {
  if (error instanceof RecipeError) {
    const where = error.line === undefined ? "" : ` (line ${error.line}, column ${error.column})`;
    return new WsspError({
      kind: "invalid_request",
      message: `${error.code}: ${error.message}${where}`,
      cause: error,
    });
  }
  return new WsspError({
    kind: "invalid_request",
    message: error instanceof Error ? error.message : String(error),
    cause: error,
  });
}

function guard<T>(run: () => T): T {
  try {
    return run();
  } catch (error) {
    throw invalid(error);
  }
}

/**
 * Builds a template recipe step by step (E2B-like naming; the method set is
 * not E2B wire compatible). Values passed to `setEnvs`, `setWorkdir` and
 * `copy` are literal: unlike Dockerfile ENV, `$NAME` is not substituted.
 * Shell commands receive ENV values as environment variables as usual.
 */
export class TemplateBuilder {
  #from: Recipe["from"] | null = null;
  #steps: RecipeStep[] = [];
  #extras: Pick<Recipe, "resources" | "scrubPaths" | "start"> = {};
  #egress: TemplateEgressOptions | undefined;
  #noCache = false;

  #setFrom(from: Recipe["from"]): void {
    if (this.#from !== null)
      throw invalid(new Error("The template base is already set (one FROM per recipe)."));
    this.#from = from;
  }

  /** Base template: `slug`, `slug:tag` or `revision/<id>`. */
  fromTemplate(selector: string): this {
    if (selector.startsWith("revision/")) {
      const revisionId = selector.slice("revision/".length);
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(revisionId))
        throw invalid(new Error(`Invalid revision selector "${selector}".`));
      this.#setFrom({ revisionId });
      return this;
    }
    const [template = "", tag, extra] = selector.split(":");
    if (
      extra !== undefined ||
      template.length > 63 ||
      !TEMPLATE_SLUG_PATTERN.test(template) ||
      (tag !== undefined && !TEMPLATE_TAG_PATTERN.test(tag))
    )
      throw invalid(new Error(`Invalid template selector "${selector}".`));
    this.#setFrom(tag === undefined ? { template } : { template, tag });
    return this;
  }

  /**
   * Start from a Dockerfile (the wssp subset, given as text). Its FROM sets
   * the base; later builder calls append steps after its instructions.
   */
  fromDockerfile(content: string): this {
    const { recipe } = guard(() => compileDockerfile(content));
    this.#setFrom(recipe.from);
    this.#steps.push(...recipe.steps);
    const { resources, scrubPaths, start, egress } = recipe;
    this.#extras = {
      ...(resources ? { resources } : {}),
      ...(scrubPaths ? { scrubPaths } : {}),
      ...(start ? { start } : {}),
    };
    if (egress) this.#egress = egress;
    return this;
  }

  /** Root `apt-get install` with list cleanup. */
  aptInstall(packages: string | string[], options?: { noInstallRecommends?: boolean }): this {
    this.#steps.push(guard(() => aptInstallStep(packages, options)));
    return this;
  }

  pipInstall(packages: string | string[], options?: { user?: RecipeUser }): this {
    this.#steps.push(guard(() => pipInstallStep(packages, options)));
    return this;
  }

  npmInstall(packages: string | string[], options?: { global?: boolean; user?: RecipeUser }): this {
    this.#steps.push(guard(() => npmInstallStep(packages, options)));
    return this;
  }

  /** Shell command(s); several are joined with `&&`. */
  runCmd(command: string | string[], options: { user?: RecipeUser } = {}): this {
    const script = typeof command === "string" ? command : command.join(" && ");
    this.#steps.push({ type: "run", script, ...(options.user ? { user: options.user } : {}) });
    return this;
  }

  /** Copy context paths into the guest (relative `dest` follows the WORKDIR). */
  copy(src: string | string[], dest: string, options: CopyOptions = {}): this {
    const sources = typeof src === "string" ? [src] : src;
    const mode =
      options.mode === undefined
        ? undefined
        : typeof options.mode === "number"
          ? options.mode.toString(8).padStart(4, "0")
          : options.mode;
    this.#steps.push({
      type: "copy",
      src: sources.map(escapeSubstitution),
      dest: escapeSubstitution(dest),
      ...(options.owner ? { owner: options.owner } : {}),
      ...(mode === undefined ? {} : { mode }),
    });
    return this;
  }

  setEnvs(envs: Record<string, string>): this {
    const values = Object.fromEntries(
      Object.entries(envs).map(([name, value]) => [name, escapeSubstitution(value)]),
    );
    this.#steps.push({ type: "env", values });
    return this;
  }

  setWorkdir(path: string): this {
    this.#steps.push({ type: "workdir", path: escapeSubstitution(path) });
    return this;
  }

  setUser(user: RecipeUser): this {
    this.#steps.push({ type: "user", user });
    return this;
  }

  /**
   * Start command run at every boot of a sandbox from the built template, as
   * the guest user. With `ready`, the sandbox becomes READY only once `ready`
   * exits 0 (polled for up to `readyTimeoutMs`, default 60 s).
   */
  setStartCmd(command: string, ready?: string, readyTimeoutMs?: number): this {
    this.#extras.start = {
      command,
      ...(ready === undefined ? {} : { ready }),
      ...(readyTimeoutMs === undefined ? {} : { readyTimeoutMs }),
    };
    return this;
  }

  /** Egress request of the build VM (replaces any earlier one). */
  egress(options: TemplateEgressOptions): this {
    this.#egress = { ...options };
    return this;
  }

  /** Build even when an identical earlier build could be reused. */
  skipCache(): this {
    this.#noCache = true;
    return this;
  }

  get noCache(): boolean {
    return this.#noCache;
  }

  /** The canonical recipe, validated against every recipe bound. */
  toRecipe(options: { buildArgs?: Record<string, string> } = {}): Recipe {
    if (this.#from === null)
      throw invalid(new Error("Set a base with fromTemplate() or fromDockerfile() first."));
    const candidate: Recipe = {
      version: 1,
      from: this.#from,
      steps: [...this.#steps],
      ...this.#extras,
      ...(this.#egress ? { egress: this.#egress } : {}),
    };
    return guard(() => parseRecipe(candidate, options).recipe);
  }
}

/** A new, empty template builder. */
export function Template(): TemplateBuilder {
  return new TemplateBuilder();
}
