import { recipeFail } from "./errors";

/**
 * Variable substitution for the recipe fields that support it (ENV values,
 * ARG defaults, WORKDIR, COPY sources and destination). A Docker subset:
 *
 * - `$NAME`, `${NAME}`: the value, or empty when unset.
 * - `${NAME:-word}`: `word` when NAME is unset or empty.
 * - `${NAME:+word}`: `word` when NAME is set and non-empty, else empty.
 * - `\$` is a literal `$` and `\\` a literal `\`; any other backslash is
 *   literal. `word` is literal text (escapes apply, no nested variables).
 * - A `$` not followed by a name or `{` is literal.
 *
 * RUN scripts are never substituted here: they receive ARG and ENV values as
 * environment variables and the shell expands them.
 */
const NAME_START = /[A-Za-z_]/;
const NAME_CHAR = /[A-Za-z0-9_]/;

/**
 * Shared expansion budget of one planning pass, in UTF-16 code units (each
 * is at least one UTF-8 byte, so it never under-counts the byte limits).
 * `substitute` charges it as it appends, so the total expanded output of a
 * recipe stays bounded however values reference each other.
 */
export type ExpansionBudget = { remaining: number };

export type SubstitutionContext = {
  stepIndex?: number;
  /** Most UTF-8 bytes one expanded value may have. */
  maxBytes?: number;
  budget?: ExpansionBudget;
};

const encoder = new TextEncoder();

export function substitute(
  text: string,
  vars: ReadonlyMap<string, string>,
  context: SubstitutionContext = {},
): string {
  let out = "";
  let i = 0;
  const { stepIndex, maxBytes, budget } = context;
  const invalid = (message: string): never =>
    recipeFail({ code: "recipe_substitution_invalid", message, stepIndex });
  const tooLarge = (message: string): never =>
    recipeFail({ code: "recipe_expansion_too_large", message, stepIndex });
  // Every append is checked before it happens: the output never exceeds the
  // value limit (or the shared budget) by more than the one refused piece.
  const append = (piece: string): void => {
    if (piece.length === 0) return;
    if (maxBytes !== undefined && out.length + piece.length > maxBytes)
      tooLarge(`An expanded value exceeds ${maxBytes} bytes.`);
    if (budget !== undefined) {
      if (piece.length > budget.remaining)
        tooLarge("The recipe's variable expansions exceed the expansion budget.");
      budget.remaining -= piece.length;
    }
    out += piece;
  };
  while (i < text.length) {
    const char = text[i]!;
    if (char === "\\" && (text[i + 1] === "$" || text[i + 1] === "\\")) {
      append(text[i + 1]!);
      i += 2;
      continue;
    }
    if (char !== "$") {
      append(char);
      i += 1;
      continue;
    }
    const next = text[i + 1];
    if (next !== undefined && NAME_START.test(next)) {
      let end = i + 2;
      while (end < text.length && NAME_CHAR.test(text[end]!)) end += 1;
      append(vars.get(text.slice(i + 1, end)) ?? "");
      i = end;
      continue;
    }
    if (next !== "{") {
      append("$");
      i += 1;
      continue;
    }
    const close = text.indexOf("}", i + 2);
    if (close < 0) invalid("Unterminated substitution: missing }.");
    const body = text.slice(i + 2, close);
    const match = /^([A-Za-z_][A-Za-z0-9_]*)(?::([-+])(.*))?$/s.exec(body);
    if (!match) invalid(`Unsupported substitution \${${body}}.`);
    const [, name, operator, word] = match!;
    const value = vars.get(name!);
    const literal = (word ?? "").replace(/\\([$\\])/g, "$1");
    if (operator === "-") append(value ? value : literal);
    else if (operator === "+") append(value ? literal : "");
    else append(value ?? "");
    i = close + 1;
  }
  if (maxBytes !== undefined && encoder.encode(out).byteLength > maxBytes)
    tooLarge(`An expanded value exceeds ${maxBytes} bytes.`);
  return out;
}

/** Escape literal text so `substitute` returns it unchanged. */
export function escapeSubstitution(text: string): string {
  return text.replace(/[\\$]/g, (char) => `\\${char}`);
}
