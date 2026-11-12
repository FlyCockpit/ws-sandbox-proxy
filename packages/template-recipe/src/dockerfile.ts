import { utf8Bytes } from "./canonical";
import { RecipeError, type RecipeErrorCode, type RecipeWarning, recipeFail } from "./errors";
import { type ParsedRecipe, type ParseRecipeOptions, parseRecipe } from "./recipe";
import {
  RECIPE_LIMITS,
  RECIPE_NAME_PATTERN,
  type Recipe,
  type RecipeStep,
  type RecipeUser,
  TEMPLATE_SLUG_PATTERN,
  TEMPLATE_TAG_PATTERN,
} from "./schema";

/**
 * Dockerfile subset → canonical recipe. Linear, single pass, with
 * 1-based line/column positions on every refusal. Values that support
 * substitution are converted into the recipe substitution language
 * (`substitute.ts`): quoted and escaped characters become literal, unquoted
 * and double-quoted `$` stays live.
 */

export type CompileDockerfileOptions = Pick<ParseRecipeOptions, "buildArgs">;
export type CompiledDockerfile = ParsedRecipe & { warnings: RecipeWarning[] };

type Segment = { start: number; line: number; column: number };
type Logical = { text: string; segments: Segment[] };
type Position = { line: number; column: number };

const UNSUPPORTED = new Set([
  "ADD",
  "ENTRYPOINT",
  "CMD",
  "VOLUME",
  "HEALTHCHECK",
  "ONBUILD",
  "SHELL",
  "STOPSIGNAL",
]);
const IGNORED = new Set(["EXPOSE", "LABEL"]);
const HEREDOC = /<<-?\s*["']?[A-Za-z_][A-Za-z0-9_]*["']?/;

function positionOf(logical: Logical, offset: number): Position {
  let segment = logical.segments[0]!;
  for (const candidate of logical.segments) {
    if (candidate.start > offset) break;
    segment = candidate;
  }
  return { line: segment.line, column: segment.column + (offset - segment.start) };
}

// --- word lexer ------------------------------------------------------------

type LexChar = { ch: string; mode: "u" | "s" | "d"; escaped: boolean };
type Word = { chars: LexChar[]; offset: number };

/** Literal text: everything except an unescaped `$` outside single quotes. */
function toTemplate(chars: LexChar[]): string {
  return chars
    .map(({ ch, mode, escaped }) => {
      const live = ch === "$" && mode !== "s" && !escaped;
      if (live) return "$";
      return ch === "$" || ch === "\\" ? `\\${ch}` : ch;
    })
    .join("");
}

function plain(chars: LexChar[]): string {
  return chars.map(({ ch }) => ch).join("");
}

/**
 * Shell-like lexing (Docker's word rules): whitespace separates words unless
 * `split` is false; single quotes are literal; double quotes allow `\"`, `\\`
 * and `\$`; an unquoted backslash escapes the next character.
 */
function lexWords(
  text: string,
  base: number,
  split: boolean,
  fail: (offset: number, message: string) => never,
): Word[] {
  const words: Word[] = [];
  let current: Word | null = null;
  let i = 0;
  const push = (char: LexChar, at: number) => {
    if (!current) {
      current = { chars: [], offset: base + at };
      words.push(current);
    }
    current.chars.push(char);
  };
  while (i < text.length) {
    const ch = text[i]!;
    if (split && /\s/.test(ch)) {
      current = null;
      i += 1;
      continue;
    }
    if (ch === "'") {
      const close = text.indexOf("'", i + 1);
      if (close < 0) fail(base + i, "Unterminated single quote.");
      if (!current) {
        current = { chars: [], offset: base + i };
        words.push(current);
      }
      for (const inner of text.slice(i + 1, close))
        push({ ch: inner, mode: "s", escaped: false }, i);
      i = close + 1;
      continue;
    }
    if (ch === '"') {
      if (!current) {
        current = { chars: [], offset: base + i };
        words.push(current);
      }
      let j = i + 1;
      for (;;) {
        if (j >= text.length) fail(base + i, "Unterminated double quote.");
        const inner = text[j]!;
        if (inner === '"') break;
        if (inner === "\\" && j + 1 < text.length && '"\\$'.includes(text[j + 1]!)) {
          push({ ch: text[j + 1]!, mode: "d", escaped: true }, i);
          j += 2;
          continue;
        }
        push({ ch: inner, mode: "d", escaped: inner === "\\" }, i);
        j += 1;
      }
      i = j + 1;
      continue;
    }
    if (ch === "\\" && i + 1 < text.length) {
      push({ ch: text[i + 1]!, mode: "u", escaped: true }, i);
      i += 2;
      continue;
    }
    push({ ch, mode: "u", escaped: false }, i);
    i += 1;
  }
  return words;
}

function shellQuote(arg: string): string {
  return `'${arg.replace(/'/g, "'\\''")}'`;
}

/** JSON exec form; null when the text is not a JSON array of strings (shell form then). */
function jsonArray(text: string): string[] | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("[")) return null;
  try {
    const value: unknown = JSON.parse(trimmed);
    if (Array.isArray(value) && value.every((item) => typeof item === "string")) return value;
  } catch {
    return null;
  }
  return null;
}

/** JSON-form strings have no quote processing; `$` stays live, `\` is literal. */
function jsonTemplate(value: string): string {
  return value.replace(/\\/g, "\\\\");
}

// --- compiler --------------------------------------------------------------

export function compileDockerfile(
  text: string,
  options: CompileDockerfileOptions = {},
): CompiledDockerfile {
  if (utf8Bytes(text) > RECIPE_LIMITS.dockerfileBytes)
    recipeFail({
      code: "recipe_too_large",
      message: `The Dockerfile is larger than ${RECIPE_LIMITS.dockerfileBytes} bytes.`,
    });
  const nul = text.indexOf("\0");
  if (nul >= 0) {
    const before = text.slice(0, nul).split("\n");
    recipeFail({
      code: "recipe_syntax",
      message: "The Dockerfile contains a NUL byte.",
      line: before.length,
      column: before.at(-1)!.length + 1,
    });
  }
  const lines = text.split("\n").map((line) => (line.endsWith("\r") ? line.slice(0, -1) : line));
  const warnings: RecipeWarning[] = [];
  const failAt = (code: RecipeErrorCode, at: Position, message: string): never =>
    recipeFail({ code, message, line: at.line, column: at.column });

  // Parser directives: only at the very top, before any other line.
  let index = 0;
  for (; index < lines.length; index += 1) {
    const match = /^#\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(.*?)\s*$/.exec(lines[index]!);
    if (!match) break;
    const key = match[1]!.toLowerCase();
    if (key === "escape")
      failAt(
        "recipe_unsupported_directive",
        { line: index + 1, column: 1 },
        "The escape directive is not supported; wssp parses with the default escape character (\\).",
      );
    if (key !== "syntax") break;
    warnings.push({
      code: "directive_ignored",
      message: "The syntax directive is ignored.",
      line: index + 1,
    });
  }

  let from: Recipe["from"] | null = null;
  const steps: RecipeStep[] = [];
  const stepLines: Position[] = [];
  const egress: NonNullable<Recipe["egress"]> = {};
  const resources: NonNullable<Recipe["resources"]> = {};
  const scrubPaths: string[] = [];
  // Mutated inside the extension handler; a holder keeps TS from narrowing.
  const marks: {
    egress?: Position;
    resources?: Position;
    scrub?: Position;
    start?: { command?: string; ready?: string; at: Position };
  } = {};

  const extension = (raw: string, at: Position) => {
    const match = /^#\s*wssp:([a-z-]+)(?:\s+(.*?))?\s*$/.exec(raw.trim());
    if (!match) failAt("recipe_unknown_extension", at, "Malformed wssp extension comment.");
    const [, name, argText = ""] = match!;
    const args = argText.split(/\s+/).filter(Boolean);
    const need = (count: number) => {
      if (args.length < count)
        failAt(
          "recipe_syntax",
          at,
          `# wssp:${name} needs ${count === 1 ? "an argument" : "arguments"}.`,
        );
    };
    switch (name) {
      case "egress-mode": {
        need(1);
        const mode = args[0];
        if (args.length !== 1 || (mode !== "open" && mode !== "allowlist"))
          failAt("recipe_egress_invalid", at, "# wssp:egress-mode takes open or allowlist.");
        if (egress.mode !== undefined && egress.mode !== mode)
          failAt("recipe_egress_invalid", at, "Conflicting # wssp:egress-mode lines.");
        egress.mode = mode as "open" | "allowlist";
        marks.egress ??= at;
        return;
      }
      case "egress": {
        need(2);
        const [kind, ...values] = args;
        if (kind === "domain") egress.domains = [...(egress.domains ?? []), ...values];
        else if (kind === "cidr") egress.cidrs = [...(egress.cidrs ?? []), ...values];
        else failAt("recipe_egress_invalid", at, "# wssp:egress takes `domain …` or `cidr …`.");
        marks.egress ??= at;
        return;
      }
      case "egress-preset":
        need(1);
        egress.presets = [...(egress.presets ?? []), ...args];
        marks.egress ??= at;
        return;
      case "resources": {
        need(1);
        const keys = { cpu: "cpuCount", memory: "memoryMiB", disk: "diskGiB" } as const;
        for (const arg of args) {
          const pair = /^(cpu|memory|disk)=([0-9]{1,9})$/.exec(arg);
          if (!pair)
            failAt(
              "recipe_resources_invalid",
              at,
              `Unsupported resource "${arg}" (cpu=, memory=, disk=).`,
            );
          resources[keys[pair![1] as keyof typeof keys]] = Number(pair![2]);
        }
        marks.resources ??= at;
        return;
      }
      case "start":
      case "ready": {
        need(1);
        marks.start ??= { at };
        marks.start[name === "start" ? "command" : "ready"] = argText;
        return;
      }
      case "scrub":
        need(1);
        scrubPaths.push(...args);
        marks.scrub ??= at;
        return;
      default:
        failAt("recipe_unknown_extension", at, `Unknown extension # wssp:${name}.`);
    }
  };

  for (; index < lines.length; index += 1) {
    const raw = lines[index]!;
    const trimmed = raw.trimStart();
    const indent = raw.length - trimmed.length;
    if (trimmed === "") continue;
    if (trimmed.startsWith("#")) {
      if (/^#\s*wssp:/.test(trimmed)) extension(trimmed, { line: index + 1, column: indent + 1 });
      continue;
    }

    // Gather one logical instruction across `\` continuations.
    const logical: Logical = { text: "", segments: [] };
    let piece = trimmed;
    let pieceColumn = indent + 1;
    let pieceLine = index + 1;
    for (;;) {
      const continued = /\\[ \t]*$/.exec(piece);
      const body = continued ? piece.slice(0, continued.index) : piece;
      logical.segments.push({ start: logical.text.length, line: pieceLine, column: pieceColumn });
      logical.text += body;
      if (!continued) break;
      let next = index + 1;
      while (next < lines.length) {
        const candidate = lines[next]!.trimStart();
        if (candidate.startsWith("#")) {
          if (/^#\s*wssp:/.test(candidate))
            failAt(
              "recipe_extension_misplaced",
              { line: next + 1, column: lines[next]!.length - candidate.length + 1 },
              "wssp extension comments cannot appear inside a continued instruction.",
            );
          next += 1;
          continue;
        }
        if (candidate === "") {
          next += 1;
          continue;
        }
        break;
      }
      if (next >= lines.length) {
        index = next - 1;
        break;
      }
      index = next;
      piece = lines[index]!;
      pieceColumn = 1;
      pieceLine = index + 1;
    }

    const head = /^([A-Za-z]+)(\s+|$)/.exec(logical.text);
    const at = (offset: number) => positionOf(logical, offset);
    if (!head) failAt("recipe_syntax", at(0), "Expected an instruction.");
    const keyword = head![1]!.toUpperCase();
    const restOffset = head![0].length;
    const rest = logical.text.slice(restOffset).trimEnd();
    const fail = (
      offset: number,
      message: string,
      code: RecipeErrorCode = "recipe_syntax",
    ): never => failAt(code, at(offset), message);
    const words = (split = true) =>
      lexWords(rest, restOffset, split, (offset, message) => fail(offset, message));

    if (UNSUPPORTED.has(keyword))
      fail(0, `${keyword} is not supported in wssp recipes.`, "recipe_unsupported_instruction");
    if (IGNORED.has(keyword)) {
      warnings.push({
        code: "instruction_ignored",
        message: `${keyword} is ignored.`,
        line: at(0).line,
      });
      continue;
    }
    if (keyword !== "FROM" && from === null)
      fail(0, "The first instruction must be FROM.", "recipe_from_missing");
    const addStep = (step: RecipeStep) => {
      steps.push(step);
      stepLines.push(at(0));
    };

    switch (keyword) {
      case "FROM": {
        if (from !== null)
          fail(0, "Only one FROM is supported (no multi-stage builds).", "recipe_multi_stage");
        const parts = words();
        if (parts.some((part) => plain(part.chars).startsWith("--")))
          fail(parts[0]!.offset, "FROM flags are not supported.", "recipe_unsupported_flag");
        if (parts.length === 3 && plain(parts[1]!.chars).toUpperCase() === "AS")
          fail(
            parts[1]!.offset,
            "FROM … AS (build stages) is not supported.",
            "recipe_multi_stage",
          );
        if (parts.length !== 1) fail(0, "FROM takes exactly one template.");
        const selector = plain(parts[0]!.chars);
        const offset = parts[0]!.offset;
        if (selector.startsWith("revision/")) {
          const revisionId = selector.slice("revision/".length);
          if (!/^[A-Za-z0-9_-]{1,64}$/.test(revisionId))
            fail(offset, "Invalid revision id.", "recipe_from_invalid");
          from = { revisionId };
        } else {
          const [template = "", tag, extra] = selector.split(":");
          if (
            extra !== undefined ||
            template.length > 63 ||
            !TEMPLATE_SLUG_PATTERN.test(template) ||
            (tag !== undefined && !TEMPLATE_TAG_PATTERN.test(tag))
          )
            fail(
              offset,
              "FROM takes a template slug with an optional :tag, or revision/<id>.",
              "recipe_from_invalid",
            );
          from = tag === undefined ? { template } : { template, tag };
        }
        break;
      }
      case "RUN": {
        if (rest === "") fail(0, "RUN needs a command.");
        if (/^--[A-Za-z]/.test(rest))
          fail(
            restOffset,
            "RUN flags (--mount, --network, --security) are not supported.",
            "recipe_unsupported_flag",
          );
        const heredoc = HEREDOC.exec(rest);
        if (heredoc)
          fail(
            restOffset + heredoc.index,
            "Heredocs are not supported.",
            "recipe_unsupported_instruction",
          );
        const exec = jsonArray(rest);
        if (exec && exec.length === 0) fail(restOffset, "RUN [] needs a command.");
        addStep({ type: "run", script: exec ? exec.map(shellQuote).join(" ") : rest });
        break;
      }
      case "ENV": {
        const parts = words();
        if (parts.length === 0) fail(0, "ENV needs a name and a value.");
        const values: Record<string, string> = {};
        const firstEq = parts[0]!.chars.findIndex(
          (c) => c.ch === "=" && c.mode === "u" && !c.escaped,
        );
        const nameAt = (name: string, offset: number) => {
          if (!RECIPE_NAME_PATTERN.test(name))
            fail(offset, `Invalid ENV name "${name}".`, "recipe_env_invalid");
          if (Object.hasOwn(values, name))
            fail(offset, `ENV sets "${name}" twice.`, "recipe_env_invalid");
        };
        if (firstEq < 0) {
          // Legacy `ENV name value…`: the rest of the line is one value.
          const name = plain(parts[0]!.chars);
          nameAt(name, parts[0]!.offset);
          if (parts.length < 2) fail(0, "ENV needs a name and a value.");
          const valueStart = parts[1]!.offset - restOffset;
          const [whole] = lexWords(rest.slice(valueStart), parts[1]!.offset, false, (o, m) =>
            fail(o, m),
          );
          values[name] = toTemplate(whole?.chars ?? []);
        } else {
          for (const part of parts) {
            const eq = part.chars.findIndex((c) => c.ch === "=" && c.mode === "u" && !c.escaped);
            if (eq < 0) fail(part.offset, "Mixed ENV forms; use name=value for every pair.");
            const name = plain(part.chars.slice(0, eq));
            nameAt(name, part.offset);
            values[name] = toTemplate(part.chars.slice(eq + 1));
          }
        }
        addStep({ type: "env", values });
        break;
      }
      case "ARG": {
        const parts = words();
        if (parts.length === 0) fail(0, "ARG needs a name.");
        for (const part of parts) {
          const eq = part.chars.findIndex((c) => c.ch === "=" && c.mode === "u" && !c.escaped);
          const name = plain(eq < 0 ? part.chars : part.chars.slice(0, eq));
          if (!RECIPE_NAME_PATTERN.test(name))
            fail(part.offset, `Invalid ARG name "${name}".`, "recipe_env_invalid");
          steps.push(
            eq < 0
              ? { type: "arg", name }
              : { type: "arg", name, default: toTemplate(part.chars.slice(eq + 1)) },
          );
          stepLines.push(at(part.offset));
        }
        break;
      }
      case "WORKDIR": {
        const [whole] = words(false);
        if (!whole || whole.chars.length === 0) fail(0, "WORKDIR needs a path.");
        addStep({ type: "workdir", path: toTemplate(whole!.chars) });
        break;
      }
      case "USER": {
        const parts = words();
        const user = parts.length === 1 ? plain(parts[0]!.chars) : "";
        if (user !== "root" && user !== "user")
          fail(
            parts[0]?.offset ?? 0,
            "USER must be root or user (the base template's guest user).",
            "recipe_user_unsupported",
          );
        addStep({ type: "user", user: user as RecipeUser });
        break;
      }
      case "COPY": {
        const heredoc = HEREDOC.exec(rest);
        if (heredoc)
          fail(
            restOffset + heredoc.index,
            "Heredocs are not supported.",
            "recipe_unsupported_instruction",
          );
        const parts = words();
        let owner: RecipeUser | undefined;
        let mode: string | undefined;
        let first = 0;
        for (; first < parts.length; first += 1) {
          const part = parts[first]!;
          const flag = plain(part.chars);
          if (!flag.startsWith("--") || part.chars[0]!.mode !== "u") break;
          const chown = /^--chown=(root|user)(?::\1)?$/.exec(flag);
          if (chown) {
            owner = chown[1] as RecipeUser;
            continue;
          }
          const chmod = /^--chmod=(0?[0-7]{3})$/.exec(flag);
          if (chmod) {
            mode = chmod[1];
            continue;
          }
          if (flag.startsWith("--from"))
            fail(
              part.offset,
              "COPY --from (build stages) is not supported.",
              "recipe_unsupported_instruction",
            );
          if (flag.startsWith("--chown"))
            fail(part.offset, "COPY --chown takes root or user.", "recipe_user_unsupported");
          fail(
            part.offset,
            `Unsupported COPY flag ${flag.split("=")[0]}.`,
            "recipe_unsupported_flag",
          );
        }
        const tail = parts[first];
        const exec = tail ? jsonArray(rest.slice(tail.offset - restOffset)) : null;
        const args = exec
          ? exec.map(jsonTemplate)
          : parts.slice(first).map((part) => toTemplate(part.chars));
        if (args.length < 2)
          fail(tail?.offset ?? 0, "COPY needs at least one source and a destination.");
        addStep({
          type: "copy",
          src: args.slice(0, -1),
          dest: args.at(-1)!,
          ...(owner === undefined ? {} : { owner }),
          ...(mode === undefined ? {} : { mode }),
        });
        break;
      }
      default:
        fail(0, `Unknown instruction ${keyword}.`, "recipe_unknown_instruction");
    }
  }

  if (from === null)
    recipeFail({ code: "recipe_from_missing", message: "The Dockerfile has no FROM." });
  const startSpec = marks.start;
  if (startSpec && startSpec.command === undefined)
    failAt("recipe_syntax", startSpec.at, "# wssp:ready needs a # wssp:start.");

  const recipe: Recipe = {
    version: 1,
    from: from!,
    steps,
    ...(startSpec
      ? {
          start: {
            command: startSpec.command!,
            ...(startSpec.ready === undefined ? {} : { ready: startSpec.ready }),
          },
        }
      : {}),
    ...(Object.keys(resources).length ? { resources } : {}),
    ...(marks.egress ? { egress } : {}),
    ...(scrubPaths.length ? { scrubPaths } : {}),
  };
  try {
    return { ...parseRecipe(recipe, options), warnings };
  } catch (error) {
    if (!(error instanceof RecipeError) || error.line !== undefined) throw error;
    const where =
      error.stepIndex !== undefined
        ? stepLines[error.stepIndex]
        : error.code === "recipe_egress_invalid" || error.code === "recipe_egress_preset_unknown"
          ? marks.egress
          : error.code === "recipe_scrub_invalid"
            ? marks.scrub
            : error.code === "recipe_resources_invalid"
              ? marks.resources
              : undefined;
    if (!where) throw error;
    throw new RecipeError({ ...error.toJSON(), line: where.line, column: where.column });
  }
}
