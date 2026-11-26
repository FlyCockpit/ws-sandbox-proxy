/**
 * The shell and theme rules a static check can see (docs/design/shell-rules.md § Shell rules).
 * Called by check-agent-rules.ts (gate 4, `pnpm policy:checks`); syntax only,
 * no app imports, no I/O beyond reading tracked/non-ignored source.
 *
 *   G8 — full-bleed shell: a `<main>` page scroller reserves no scrollbar
 *        gutter (className or CSS), and no route file renders a site
 *        `<footer>`: a site footer lives once, in the public shell.
 *   G9 — no surface ignores the theme: no literal colour (hex, rgb(), oklch()…)
 *        in a className arbitrary value, an inline style or a CSS declaration,
 *        and no prefers-color-scheme query, outside the token file
 *        packages/ui/src/styles/globals.css. A deliberate fixed colour carries
 *        `theme-exempt: <reason>`.
 *   G10 — text scales and stays at least 12px: no px font size in a class
 *        list anywhere in web source (className, cva() variants, constants),
 *        which does not follow the root viewport scale, no rem size below
 *        0.75, no em size below 1, and no other size expression without a
 *        0.75rem floor (max()/clamp()). See
 *        docs/design/shell-rules.md § Viewport scale
 *
 * Tests: scripts/check-web-conventions.test.ts (run by the check-agent-rules
 * self-test, `pnpm policy:checks:self-test`).
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

const { parse } = createRequire(import.meta.url)("@babel/parser") as typeof import("@babel/parser");

type Node = { type: string; [key: string]: unknown };
type Binding = { value?: Node; ancestors: Node[]; source?: string; imported?: string };
export type Finding = { file: string; line: number; rule: string; message: string };

function node(value: unknown): Node | undefined {
  return value !== null && typeof value === "object" && "type" in value
    ? (value as Node)
    : undefined;
}
function name(value: unknown): string | undefined {
  const n = node(value);
  return n?.type === "Identifier" || n?.type === "JSXIdentifier"
    ? String(n.name)
    : n?.type === "StringLiteral"
      ? String(n.value)
      : undefined;
}
function children(value: unknown): Node[] {
  return Array.isArray(value) ? value.flatMap((item) => node(item) ?? []) : [];
}
function walk(n: Node, ancestors: Node[], visit: (n: Node, ancestors: Node[]) => void): void {
  visit(n, ancestors);
  for (const [key, value] of Object.entries(n)) {
    if (["loc", "tokens", "comments"].includes(key) || key.endsWith("Comments")) continue;
    for (const child of Array.isArray(value) ? children(value) : [node(value)]) {
      if (child) walk(child, [...ancestors, n], visit);
    }
  }
}
function line(n: Node): number {
  return (n.loc as { start: { line: number } } | undefined)?.start.line ?? 1;
}
function offsetLine(source: string, offset: number): number {
  return source.slice(0, offset).split("\n").length;
}
function unwrap(n: Node | undefined): Node | undefined {
  while (
    n &&
    [
      "TSAsExpression",
      "TSSatisfiesExpression",
      "TSNonNullExpression",
      "ParenthesizedExpression",
    ].includes(n.type)
  )
    n = node(n.expression);
  return n;
}
function property(n: Node | undefined): string | undefined {
  return n && (!n.computed || node(n.property)?.type === "StringLiteral")
    ? name(n.property)
    : undefined;
}
function isScope(n: Node): boolean {
  return [
    "Program",
    "BlockStatement",
    "ArrowFunctionExpression",
    "FunctionExpression",
    "FunctionDeclaration",
    "CatchClause",
  ].includes(n.type);
}

/** Local binding provenance prevents aliased imports bypassing rules and shadowed names triggering them. */
function bindings(ast: Node) {
  const scopes = new WeakMap<Node, Map<string, Binding>>();
  function put(scope: Node | undefined, id: unknown, binding: Binding): void {
    if (!scope) return;
    const n = node(id);
    if (n?.type === "Identifier") {
      if (!scopes.has(scope)) scopes.set(scope, new Map());
      scopes.get(scope)?.set(String(n.name), binding);
    } else if (n?.type === "ObjectPattern" || n?.type === "ArrayPattern") {
      for (const part of children(n.properties ?? n.elements))
        put(scope, part.type === "ObjectProperty" ? part.value : part, {
          ancestors: binding.ancestors,
        });
    } else if (n?.type === "AssignmentPattern") put(scope, n.left, binding);
    else if (n?.type === "RestElement") put(scope, n.argument, binding);
  }
  walk(ast, [], (n, ancestors) => {
    const scope = [...ancestors].reverse().find(isScope);
    if (n.type === "VariableDeclarator") {
      const declaration = ancestors.at(-1);
      const owner =
        declaration?.kind === "var"
          ? [...ancestors].reverse().find((item) => isScope(item) && item.type !== "BlockStatement")
          : scope;
      put(owner, n.id, { value: node(n.init), ancestors });
    }
    if (n.type === "FunctionDeclaration") put(scope, n.id, { value: n, ancestors });
    if (["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(n.type)) {
      for (const param of children(n.params)) put(n, param, { ancestors: [...ancestors, n] });
    }
    if (n.type === "CatchClause") put(n, n.param, { ancestors: [...ancestors, n] });
    if (n.type === "ImportDeclaration" && n.importKind !== "type") {
      for (const spec of children(n.specifiers)) {
        if (spec.importKind !== "type")
          put(scope, spec.local, {
            ancestors,
            source: name(n.source),
            imported:
              spec.type === "ImportNamespaceSpecifier" ? "*" : (name(spec.imported) ?? "default"),
          });
      }
    }
  });
  function lookup(id: string, ancestors: Node[]): Binding | undefined {
    for (const ancestor of [...ancestors].reverse()) {
      const found = scopes.get(ancestor)?.get(id);
      if (found) return found;
    }
    return undefined;
  }
  function resolve(
    n: Node | undefined,
    ancestors: Node[],
    seen = new Set<Node>(),
  ): { value?: Node; ancestors: Node[] } {
    n = unwrap(n);
    if (n?.type !== "Identifier" || seen.has(n)) return { value: n, ancestors };
    seen.add(n);
    const binding = lookup(String(n.name), ancestors);
    return binding?.value
      ? resolve(binding.value, binding.ancestors, seen)
      : { value: n, ancestors };
  }
  function imported(
    n: Node | undefined,
    ancestors: Node[],
    source: string,
    symbol: string,
  ): boolean {
    const resolved = resolve(n, ancestors);
    n = resolved.value;
    if (n?.type === "Identifier") {
      const binding = lookup(String(n.name), resolved.ancestors);
      return binding?.source === source && binding.imported === symbol;
    }
    if (
      ["MemberExpression", "OptionalMemberExpression"].includes(n?.type ?? "") &&
      property(n) === symbol
    ) {
      const binding = lookup(name(n?.object) ?? "", resolved.ancestors);
      return binding?.source === source && binding.imported === "*";
    }
    return false;
  }
  return { lookup, resolve, imported };
}

type Context = ReturnType<typeof bindings>;

/**
 * The string values an expression can take, through bindings, template parts, `+` concatenation and
 * both branches of a conditional or logical expression (`dark ? "#fff" : "#000"`, `custom || "#fff"`).
 */
function styleStrings(
  n: Node | undefined,
  ancestors: Node[],
  context: Context,
  depth = 0,
): string[] {
  if (depth > 20) return [];
  const resolved = context.resolve(n, ancestors);
  const value = resolved.value;
  const recur = (child: unknown) =>
    styleStrings(node(child), resolved.ancestors, context, depth + 1);
  if (value?.type === "StringLiteral") return [String(value.value)];
  if (value?.type === "TemplateLiteral")
    return [
      children(value.quasis)
        .map((q) => String((q.value as { raw?: string })?.raw))
        .join(" "),
      ...children(value.expressions).flatMap(recur),
    ];
  if (value?.type === "ConditionalExpression")
    return [...recur(value.consequent), ...recur(value.alternate)];
  if (value?.type === "LogicalExpression") return [...recur(value.left), ...recur(value.right)];
  // `"1px solid " + color`: every combination of the two sides (capped, as it multiplies).
  if (value?.type === "BinaryExpression" && value.operator === "+") {
    const right = recur(value.right);
    return recur(value.left)
      .flatMap((left) => (right.length ? right.map((r) => left + r) : [left]))
      .slice(0, 64);
  }
  return [];
}

/**
 * Every `property: value` a style object can set, following bindings, spreads and both branches of
 * conditional/logical expressions, with the strings each value can take.
 */
function styleEntries(
  n: Node | undefined,
  ancestors: Node[],
  context: Context,
  depth = 0,
): Array<{ key: string; texts: string[]; at: Node }> {
  if (depth > 20) return [];
  const resolved = context.resolve(n, ancestors);
  const value = resolved.value;
  const recur = (child: unknown) =>
    styleEntries(node(child), resolved.ancestors, context, depth + 1);
  // `style={dark ? { color: "#fff" } : undefined}`: every branch is a style the element can get.
  if (value?.type === "ConditionalExpression")
    return [...recur(value.consequent), ...recur(value.alternate)];
  if (value?.type === "LogicalExpression") return [...recur(value.left), ...recur(value.right)];
  if (value?.type !== "ObjectExpression") return [];
  return children(value.properties).flatMap((prop) => {
    if (prop.type === "SpreadElement") return recur(prop.argument);
    if (prop.type !== "ObjectProperty") return [];
    const key = prop.computed
      ? name(context.resolve(node(prop.key), resolved.ancestors).value)
      : name(prop.key);
    // Reported at the property, so a theme-exempt comment above a multiline style's entry applies.
    return [
      {
        key: key ?? "",
        texts: styleStrings(node(prop.value), resolved.ancestors, context),
        at: prop,
      },
    ];
  });
}

/**
 * Every string a cva() call's class definitions can hold (base, variants, compound variants,
 * defaults), through local bindings (`const base = "…"; cva(base)`), spreads, arrays, cn() calls and
 * both branches of conditionals. Returns the literal nodes, so a finding (and its theme-exempt
 * comment) sits where the string is written.
 */
function cvaLiterals(call: Node, ancestors: Node[], context: Context): Node[] {
  const found: Node[] = [];
  const seen = new Set<Node>();
  const visit = (n: Node | undefined, at: Node[], depth: number): void => {
    if (!n || depth > 20) return;
    const resolved = context.resolve(n, at);
    const value = resolved.value;
    if (!value || seen.has(value)) return;
    seen.add(value);
    const recur = (child: unknown) => visit(node(child), resolved.ancestors, depth + 1);
    switch (value.type) {
      case "StringLiteral":
        found.push(value);
        return;
      case "TemplateLiteral":
        found.push(...children(value.quasis));
        for (const part of children(value.expressions)) recur(part);
        return;
      case "ObjectExpression":
        for (const prop of children(value.properties)) {
          // A clsx-style dictionary (`cva({ "bg-[#fff]": on })`) carries its classes in the keys.
          const key = node(prop.key);
          if (prop.type === "ObjectProperty" && !prop.computed && key?.type === "StringLiteral")
            found.push(key);
          recur(prop.type === "SpreadElement" ? prop.argument : prop.value);
        }
        return;
      case "ArrayExpression":
        for (const item of children(value.elements)) recur(item);
        return;
      case "SpreadElement":
        recur(value.argument);
        return;
      case "ConditionalExpression":
        recur(value.consequent);
        recur(value.alternate);
        return;
      case "LogicalExpression":
      case "BinaryExpression":
        recur(value.left);
        recur(value.right);
        return;
      case "CallExpression":
        for (const arg of children(value.arguments)) recur(arg);
        return;
    }
  };
  for (const arg of children(call.arguments)) visit(arg, [...ancestors, call], 0);
  return found;
}

type ClassSet = { tokens: string[]; when: Map<string, boolean> };
const classSet = (tokens: string[] = []): ClassSet => ({ tokens, when: new Map() });
function combine(left: ClassSet[], right: ClassSet[]): ClassSet[] {
  const result: ClassSet[] = [];
  for (const a of left)
    for (const b of right) {
      if ([...b.when].some(([key, value]) => a.when.has(key) && a.when.get(key) !== value))
        continue;
      result.push({ tokens: [...a.tokens, ...b.tokens], when: new Map([...a.when, ...b.when]) });
      if (result.length > 128)
        throw new Error(
          "Too many static class branches to check. Fix: split the conditional classes into fewer branches (docs/design/shell-rules.md § Shell rules).",
        );
    }
  return result;
}
/** Preserve exclusive branches and correlate repeated simple conditions within cn/arrays/templates. */
function classSets(root: Node | undefined, rootAncestors: Node[], context: Context): ClassSet[] {
  const conditionIds = new Map<Binding | string, number>();
  function condition(n: Node | undefined, ancestors: Node[], truthy: boolean): ClassSet[] {
    n = unwrap(n);
    if (n?.type === "UnaryExpression" && n.operator === "!")
      return condition(node(n.argument), ancestors, !truthy);
    const resolved = context.resolve(n, ancestors).value;
    if (resolved?.type === "BooleanLiteral") return resolved.value === truthy ? [classSet()] : [];
    if (n?.type !== "Identifier") return [classSet()]; // complex expressions are not assumed equivalent
    const binding = context.lookup(String(n.name), ancestors) ?? String(n.name);
    if (!conditionIds.has(binding)) conditionIds.set(binding, conditionIds.size);
    return [{ tokens: [], when: new Map([[String(conditionIds.get(binding)), truthy]]) }];
  }
  function collect(n: Node | undefined, ancestors: Node[], depth: number): ClassSet[] {
    if (!n || depth > 20) return [classSet()];
    const resolved = context.resolve(n, ancestors);
    n = resolved.value;
    ancestors = resolved.ancestors;
    const recur = (value: unknown) => collect(node(value), ancestors, depth + 1);
    const branch = (test: unknown, truthy: boolean, choices: ClassSet[]) =>
      combine(condition(node(test), ancestors, truthy), choices);
    if (!n) return [classSet()];
    if (n.type === "JSXExpressionContainer") return recur(n.expression);
    // `cn(...classes)`, `[...base, "p-2"]`: the spread's classes are all applied.
    if (n.type === "SpreadElement") return recur(n.argument);
    if (n.type === "StringLiteral") return [classSet(String(n.value).split(/\s+/).filter(Boolean))];
    if (n.type === "TemplateLiteral") {
      // Literal portions only; dynamically constructed utility names are outside this finite proof.
      return children(n.quasis).reduce(
        (sets, quasi, index) => {
          const raw = (quasi.value as { raw: string }).raw;
          const parts = [classSet(raw.split(/\s+/).filter(Boolean))];
          return combine(combine(sets, parts), recur(children(n?.expressions)[index]));
        },
        [classSet()],
      );
    }
    if (n.type === "ConditionalExpression")
      return [
        ...branch(n.test, true, recur(n.consequent)),
        ...branch(n.test, false, recur(n.alternate)),
      ];
    if (n.type === "LogicalExpression") {
      if (n.operator === "&&")
        return [...branch(n.left, false, [classSet()]), ...branch(n.left, true, recur(n.right))];
      return [...branch(n.left, true, recur(n.left)), ...branch(n.left, false, recur(n.right))];
    }
    if (n.type === "BinaryExpression" && n.operator === "+")
      return combine(recur(n.left), recur(n.right));
    if (n.type === "ArrayExpression")
      return children(n.elements).reduce((sets, item) => combine(sets, recur(item)), [classSet()]);
    if (
      n.type === "CallExpression" &&
      (["cn", "clsx", "classnames"].includes(name(n.callee) ?? "") ||
        context.imported(node(n.callee), ancestors, "@wssp/ui/lib/utils", "cn"))
    ) {
      return children(n.arguments).reduce((sets, item) => combine(sets, recur(item)), [classSet()]);
    }
    // `[...base, "p-2"].join(" ")`: the joined array's classes.
    if (
      n.type === "CallExpression" &&
      ["MemberExpression", "OptionalMemberExpression"].includes(node(n.callee)?.type ?? "") &&
      property(node(n.callee)) === "join"
    )
      return recur(node(n.callee)?.object);
    if (n.type === "ObjectExpression")
      return children(n.properties).reduce(
        (sets, prop) => {
          if (prop.type === "SpreadElement") return combine(sets, recur(prop.argument));
          if (prop.type !== "ObjectProperty" || prop.computed) return sets;
          const tokens = (name(prop.key) ?? "").split(/\s+/).filter(Boolean);
          return combine(sets, [
            ...branch(prop.value, false, [classSet()]),
            ...branch(prop.value, true, [classSet(tokens)]),
          ]);
        },
        [classSet()],
      );
    return [classSet()];
  }
  return collect(root, rootAncestors, 0);
}

/** Split only outside arbitrary Tailwind variants such as [&:hover]:. */
function utility(token: string): { prefix: string; base: string } {
  let bracketDepth = 0;
  let boundary = -1;
  for (let i = 0; i < token.length; i++) {
    if (token[i] === "[") bracketDepth++;
    else if (token[i] === "]") bracketDepth--;
    else if (token[i] === ":" && bracketDepth === 0) boundary = i;
  }
  return {
    prefix: token.slice(0, boundary + 1),
    base: token.slice(boundary + 1).replace(/^!|!$/g, ""),
  };
}
/**
 * Elements whose <footer> is that element's own (author line, citation, card
 * actions), not site chrome: HTML's sectioning content and sectioning roots.
 */
const SECTION_TAGS = new Set([
  "article",
  "aside",
  "nav",
  "section",
  "blockquote",
  "details",
  "dialog",
  "fieldset",
  "figure",
  "td",
]);
/**
 * A selector list split at its top-level commas, with pseudo-class arguments removed
 * (`.pane:not(main, #main-content)` → `.pane:not`): those arguments never name the styled element.
 */
function topLevelSelectors(selectorList: string): string[] {
  let list = selectorList;
  while (/\([^()]*\)/.test(list)) list = list.replace(/\([^()]*\)/g, "");
  return list
    .split(",")
    .map((selector) => selector.trim())
    .filter(Boolean);
}
/** The theme's token file: the one place literal colours and color-scheme queries belong. */
const THEME_TOKENS = "packages/ui/src/styles/globals.css";
const LITERAL_COLOR = /#[0-9a-f]{3,8}(?![\w-])|\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\(/i;
/**
 * A CSS `url(…)` value: `url(#fade)`, `url(/shapes.svg#fade)`, `url("data:…")`. Its `#…` is an element
 * reference (clip path, mask, gradient), not a colour, so the whole value is dropped before the check;
 * a colour next to it (`url(#grad) #fff`) still counts.
 */
const CSS_URL = /\burl\(\s*(?:"[^"]*"|'[^']*'|[^)"']*)\s*\)/gi;
function hasLiteralColor(text: string): boolean {
  return LITERAL_COLOR.test(text.replace(CSS_URL, "url()"));
}
/**
 * The CSS named colours (CSS Color 4, `transparent` and `currentColor` excluded: they carry no fixed
 * colour). Checked only where a value paints (see PAINT_PROPERTY), so `white-space` or an animation
 * named `fade` never match.
 */
const NAMED_COLORS = new Set(
  (
    "aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue blueviolet " +
    "brown burlywood cadetblue chartreuse chocolate coral cornflowerblue cornsilk crimson cyan darkblue " +
    "darkcyan darkgoldenrod darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange " +
    "darkorchid darkred darksalmon darkseagreen darkslateblue darkslategray darkslategrey darkturquoise " +
    "darkviolet deeppink deepskyblue dimgray dimgrey dodgerblue firebrick floralwhite forestgreen fuchsia " +
    "gainsboro ghostwhite gold goldenrod gray green greenyellow grey honeydew hotpink indianred indigo " +
    "ivory khaki lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral lightcyan " +
    "lightgoldenrodyellow lightgray lightgreen lightgrey lightpink lightsalmon lightseagreen lightskyblue " +
    "lightslategray lightslategrey lightsteelblue lightyellow lime limegreen linen magenta maroon " +
    "mediumaquamarine mediumblue mediumorchid mediumpurple mediumseagreen mediumslateblue " +
    "mediumspringgreen mediumturquoise mediumvioletred midnightblue mintcream mistyrose moccasin " +
    "navajowhite navy oldlace olive olivedrab orange orangered orchid palegoldenrod palegreen " +
    "paleturquoise palevioletred papayawhip peachpuff peru pink plum powderblue purple rebeccapurple red " +
    "rosybrown royalblue saddlebrown salmon sandybrown seagreen seashell sienna silver skyblue slateblue " +
    "slategray slategrey snow springgreen steelblue tan teal thistle tomato turquoise violet wheat white " +
    "whitesmoke yellow yellowgreen"
  ).split(" "),
);
/** CSS properties (kebab or camel case) and Tailwind arbitrary values whose value paints a colour. */
const PAINT_PROPERTY =
  /^(?:--.*|color|background(?:-?color|-?image)?|border(?:-?(?:top|right|bottom|left|block|inline)(?:-?(?:start|end))?)?(?:-?color)?|outline(?:-?color)?|fill|stroke|(?:box|text)-?shadow|caret-?color|accent-?color|column-?rule(?:-?color)?|text-?decoration(?:-?color)?|text-?emphasis(?:-?color)?|scrollbar-?color|flood-?color|lighting-?color|stop-?color)$/i;
/** A named colour as a whole word of a value; quoted strings (`content: "white"`) are text, not colour. */
function hasNamedColor(text: string): boolean {
  return text
    .replace(/"[^"]*"|'[^']*'/g, " ")
    .replace(CSS_URL, " ")
    .split(/[^a-z-]+/i)
    .some((word) => NAMED_COLORS.has(word.toLowerCase()));
}
/** A literal or named colour in the value of a CSS/inline-style property. */
function hasPropertyColor(property: string, value: string): boolean {
  return hasLiteralColor(value) || (PAINT_PROPERTY.test(property.trim()) && hasNamedColor(value));
}
/**
 * A Tailwind arbitrary value or property holding a literal colour anywhere in its brackets:
 * `bg-[#fff]`, `text-[oklch(…)]`, `[background-color:#fff]`, `bg-[linear-gradient(#fff,#000)]`,
 * `shadow-[0_0_2px_#fff]`. Underscores are spaces; `url(#id)` stays a reference.
 */
function isArbitraryColor(base: string): boolean {
  const bracket = /\[(.*)\]/.exec(base)?.[1];
  if (bracket === undefined) return false;
  const value = bracket.replaceAll("_", " ");
  if (hasLiteralColor(value)) return true;
  // `[color:white]` names its property; `bg-[white]`, `shadow-[0 0 2px white]` paint whatever the
  // utility paints, and only colour-painting utilities take a bare colour name.
  const property = /^([a-z-]+):(.*)$/i.exec(value);
  if (property) return hasPropertyColor(property[1] ?? "", property[2] ?? "");
  return (
    /^(?:bg|text|border(?:-[trblxyse])?|outline|ring|fill|stroke|shadow|decoration|accent|caret|from|via|to|divide|placeholder)-\[/.test(
      base,
    ) && hasNamedColor(value)
  );
}
const THEME_MESSAGE =
  "follows the OS or a fixed colour instead of the app theme (stored choice > OS, the `.dark` class). Fix: use the theme tokens (bg-popover, text-foreground, var(--state-*)…) and `dark:` variants; new colours become tokens in packages/ui/src/styles/globals.css (docs/design/shell-rules.md § Shell rules).";
/** A number with a CSS length unit or a percentage, as a font size holds. */
const FONT_LENGTH =
  /\d(?:%|(?:r?(?:em|ex|cap|ch|ic|lh)|px|pt|pc|cm|mm|in|q|[dsl]?v(?:w|h|i|b|min|max)|cq(?:w|h|i|b|min|max))(?![a-z]))/i;
/** Colour expressions a `text-[…]` value can hold whose arguments include percentages. */
const COLOR_FUNCTION = /\b(?:color-mix|light-dark|color)\(/i;
/**
 * G10: an arbitrary font size (`text-[…]` or `[font-size:…]`) that is not provably at least 12px and scaling:
 * a px size (`text-[13px]`, `text-[10px]/4`) or any px branch in an expression
 * (`max(100px,0.75rem)`), which does not follow the root viewport scale; rem
 * below 0.75 (12px); em below 1 and % below 100, which drop under 12px inside
 * 12px text; viewport and other units (`2vw`), which have no floor; and any other
 * expression holding a length unless it has a rem floor of at least 0.75:
 * `max(…, 0.75rem)` or `clamp(0.75rem, …, …)` (`text-[length:max(0.9em,0.75rem)]`
 * passes, `calc(0.9em)` doesn't). Values without a length (variables, colours) are
 * not font sizes it can judge.
 */
function fixedOrTinyText(base: string): boolean {
  const match =
    /^text-\[(?:length:)?(.+?)\](?:\/[\w.%[\]()-]+)?$/.exec(base) ??
    /^\[font-size:(.+)\]$/.exec(base);
  const value = match?.[1]?.replaceAll("_", " ").trim();
  if (
    !value ||
    // A type hint other than `length:` (`text-[color:…]`) is not a font size.
    /^[a-z-]+:/i.test(value) ||
    hasLiteralColor(value) ||
    COLOR_FUNCTION.test(value) ||
    !FONT_LENGTH.test(value)
  )
    return false;
  const plain = /^(\d*\.?\d+)([a-z]+|%)$/i.exec(value);
  if (plain) {
    const size = Number(plain[1]);
    const unit = plain[2]?.toLowerCase();
    if (unit === "rem") return size < 0.75;
    if (unit === "em") return size < 1;
    if (unit === "%") return size < 100;
    return true;
  }
  if (/\dpx\b/i.test(value)) return true;
  const fn = /^(max|clamp)\((.*)\)$/.exec(value);
  if (!fn?.[2]) return true;
  const args: string[] = [];
  let depth = 0;
  let current = "";
  for (const char of fn[2]) {
    if (char === "(") depth++;
    else if (char === ")") depth--;
    if (char === "," && depth === 0) {
      args.push(current.trim());
      current = "";
    } else current += char;
  }
  args.push(current.trim());
  const floors = fn[1] === "max" ? args : args.length === 3 ? [args[0] ?? ""] : [];
  return !floors.some((arg) => {
    const rem = /^(\d*\.?\d+)rem$/.exec(arg);
    return rem !== null && Number(rem[1]) >= 0.75;
  });
}
const FIXED_TEXT_MESSAGE =
  "a px size does not grow with the large-screen root scale, and no text is smaller than 12px. Fix: use the type scale, text-xs (12px) at the smallest, or give a relative size a floor (text-[max(0.9em,0.75rem)]); a label that does not fit wraps or ends in an ellipsis (docs/design/shell-rules.md § Viewport scale).";
function isThemeScanned(file: string): boolean {
  return (
    /^(apps\/web|packages\/ui)\/src\//.test(file) &&
    file !== THEME_TOKENS &&
    !/\.test\.[cm]?[jt]sx?$/.test(file)
  );
}
/**
 * A deliberate fixed colour (a QR code that must stay dark-on-white to scan, a chess board, a share
 * image) carries `theme-exempt: <reason>` in a comment on the line above it, on its line, or inside
 * the flagged className/style value; the reason is required. G9 skips that finding and nothing else.
 */
const THEME_EXEMPT = /theme-exempt:\s*\S.{3,}/;
function withoutThemeExemptions(
  source: string,
  findings: Finding[],
  ends: ReadonlyMap<Finding, number> = new Map(),
): Finding[] {
  const lines = source.split("\n");
  const exempt = (finding: Finding) =>
    lines
      .slice(Math.max(0, finding.line - 2), ends.get(finding) ?? finding.line)
      .some((text) => THEME_EXEMPT.test(text));
  return findings.filter((finding) => finding.rule !== "G9" || !exempt(finding));
}
export function scanWebSource(file: string, source: string): Finding[] {
  const findings: Finding[] = [];
  // Where each finding's flagged node ends, so a theme-exempt comment inside a multiline
  // className/style value (above the literal it covers) still applies.
  const ends = new Map<Finding, number>();
  const add = (n: Node, rule: string, message: string) => {
    const finding = { file, line: line(n), rule, message };
    ends.set(finding, (n.loc as { end: { line: number } } | undefined)?.end.line ?? finding.line);
    findings.push(finding);
  };
  let ast: Node;
  try {
    ast = parse(source, {
      sourceType: "unambiguous",
      plugins: /\.[cm]?ts$/.test(file) ? ["typescript"] : ["typescript", "jsx"],
      allowUndeclaredExports: true,
    }) as unknown as Node;
  } catch (error) {
    const location = (error as { loc?: { line?: number } }).loc;
    return [
      {
        file,
        line: location?.line ?? 1,
        rule: "parse",
        message: `Cannot parse source: ${(error as Error).message}. Fix the syntax and rerun pnpm policy:checks.`,
      },
    ];
  }
  const context = bindings(ast);
  walk(ast, [], (n, ancestors) => {
    if (n.type === "JSXOpeningElement") {
      const attrs = children(n.attributes);
      const tag = name(n.name);
      for (const attr of attrs) {
        if (name(attr.name) !== "className") continue;
        let sets: ClassSet[];
        try {
          sets = classSets(node(attr.value), ancestors, context);
        } catch (error) {
          add(attr, "G9", (error as Error).message);
          continue;
        }
        const gutters = new Set<string>();
        const colors = new Set<string>();
        for (const set of sets) {
          for (const u of set.tokens.map(utility)) {
            if (tag === "main" && /scrollbar-gutter:(?!auto\])/.test(u.base)) gutters.add(u.base);
            if (isThemeScanned(file) && isArbitraryColor(u.base)) colors.add(u.base);
          }
        }
        if (gutters.size)
          add(
            attr,
            "G8",
            `The page scroller reserves a scrollbar gutter (${[...gutters].join(", ")}), so every full-bleed rule inside it (footer, sub-nav, banners) stops short of the viewport edge with classic scrollbars. Fix: remove it from <main>; nested panes may keep it (docs/design/shell-rules.md § Shell rules).`,
          );
        if (colors.size)
          add(attr, "G9", `Literal colour class (${[...colors].join(", ")}) ${THEME_MESSAGE}`);
      }
      const style = attrs.find((attr) => name(attr.name) === "style");
      const styleValue = node(style?.value);
      if (style && styleValue?.type === "JSXExpressionContainer") {
        for (const entry of styleEntries(node(styleValue.expression), ancestors, context)) {
          if (isThemeScanned(file))
            for (const text of entry.texts.filter((text) => hasPropertyColor(entry.key, text)))
              add(entry.at, "G9", `A literal colour in an inline style (${text}) ${THEME_MESSAGE}`);
          const gutter = entry.texts.find((text) => !/^\s*auto\s*$/i.test(text));
          if (tag === "main" && entry.key === "scrollbarGutter" && gutter !== undefined)
            add(
              entry.at,
              "G8",
              `The page scroller reserves a scrollbar gutter (scrollbarGutter: ${gutter}), so every full-bleed rule inside it (footer, sub-nav, banners) stops short of the viewport edge with classic scrollbars. Fix: remove it from <main>; nested panes may keep it (docs/design/shell-rules.md § Shell rules).`,
            );
        }
      }
      if (
        tag === "footer" &&
        file.startsWith("apps/web/src/routes/") &&
        !ancestors.some(
          (a) =>
            a.type === "JSXElement" && SECTION_TAGS.has(name(node(a.openingElement)?.name) ?? ""),
        )
      )
        add(
          n,
          "G8",
          "A route renders a site footer, which follows the page content instead of sitting at the bottom of a short page and repeats per page. Fix: render the footer once, as the last box of the public shell's content column (apps/web/src/components/public-shell.tsx); a footer that belongs to an <article>, <section> or similar stays inside that element (docs/design/shell-rules.md § Shell rules).",
        );
    }
    // cva() class definitions (base, variants, compound variants) reach className through a call
    // (`buttonVariants()`), so every class string inside a cva call is checked where it is written.
    if (
      isThemeScanned(file) &&
      n.type === "CallExpression" &&
      (name(n.callee) === "cva" ||
        context.imported(node(n.callee), ancestors, "class-variance-authority", "cva"))
    ) {
      for (const literal of cvaLiterals(n, ancestors, context)) {
        const text =
          literal.type === "StringLiteral"
            ? String(literal.value)
            : String((literal.value as { raw?: string })?.raw);
        const colors = text
          .split(/\s+/)
          .filter(Boolean)
          .map(utility)
          .filter((u) => isArbitraryColor(u.base))
          .map((u) => u.base);
        if (colors.length)
          add(literal, "G9", `Literal colour class (${colors.join(", ")}) ${THEME_MESSAGE}`);
      }
    }
    // G10 looks at every string in web source, not only className values: class
    // lists also live in cva() variants, shared constants and other *ClassName
    // props, and a text-[…] token means the same wherever it is written.
    if (isThemeScanned(file) && (n.type === "StringLiteral" || n.type === "TemplateElement")) {
      const text =
        n.type === "StringLiteral" ? String(n.value) : String((n.value as { raw?: string })?.raw);
      const fixed = text
        .split(/\s+/)
        .filter(Boolean)
        .map((token) => utility(token).base)
        .filter(fixedOrTinyText);
      if (fixed.length)
        add(n, "G10", `Fixed or sub-12px text size (${fixed.join(", ")}): ${FIXED_TEXT_MESSAGE}`);
    }
    if (
      isThemeScanned(file) &&
      ((n.type === "StringLiteral" && /prefers-color-scheme/i.test(String(n.value))) ||
        (n.type === "TemplateElement" &&
          /prefers-color-scheme/i.test(String((n.value as { raw?: string })?.raw))))
    )
      add(n, "G9", `A prefers-color-scheme query ${THEME_MESSAGE}`);
  });
  return withoutThemeExemptions(source, findings, ends);
}

/** CSS lexical blocks: comments and strings are masked before declarations are read. */
export function scanWebCss(file: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const masked = source.replace(/\/\*[\s\S]*?\*\/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, (part) =>
    part.replace(/[^\n]/g, " "),
  );
  const stack: Array<{
    start: number;
    selector: string;
    declarations: Array<{ text: string; offset: number }>;
  }> = [];
  let start = 0;
  const declaration = (end: number) => {
    const text = masked.slice(start, end).trim();
    if (text) stack.at(-1)?.declarations.push({ text, offset: start });
  };
  for (let i = 0; i < masked.length; i++) {
    const char = masked[i];
    if (char === "{") {
      const selector = masked.slice(start, i);
      if (isThemeScanned(file) && /prefers-color-scheme/i.test(selector))
        findings.push({
          file,
          line: offsetLine(masked, start + selector.search(/\S/)),
          rule: "G9",
          message: `A prefers-color-scheme query ${THEME_MESSAGE}`,
        });
      stack.push({ start: i, selector, declarations: [] });
      start = i + 1;
    } else if (char === ";") {
      declaration(i);
      start = i + 1;
    } else if (char === "}") {
      declaration(i);
      const block = stack.pop();
      if (!block)
        findings.push({
          file,
          line: offsetLine(masked, i),
          rule: "parse",
          message: "Unmatched CSS closing brace. Fix the syntax and rerun pnpm policy:checks.",
        });
      for (const d of block?.declarations ?? []) {
        const at = () => offsetLine(masked, d.offset + masked.slice(d.offset).search(/\S/));
        const [, property = "", value = ""] = /^([^:]*):([\s\S]*)$/.exec(d.text) ?? [];
        if (isThemeScanned(file) && hasPropertyColor(property, value))
          findings.push({
            file,
            line: at(),
            rule: "G9",
            message: `A literal colour ${THEME_MESSAGE}`,
          });
        if (
          block &&
          /^scrollbar-gutter\s*:/i.test(d.text) &&
          !/^scrollbar-gutter\s*:\s*auto\s*(?:!\s*important\s*)?$/i.test(d.text) &&
          topLevelSelectors(block.selector).some((selector) => {
            // The element the rule styles is the selector's last compound.
            const target = selector.split(/[\s>+~]+/).at(-1) ?? "";
            return /^main(?![\w-])|#main-content(?![\w-])/.test(target);
          })
        )
          findings.push({
            file,
            line: at(),
            rule: "G8",
            message:
              "The page scroller reserves a scrollbar gutter, so every full-bleed rule inside it stops short of the viewport edge with classic scrollbars. Fix: remove scrollbar-gutter from <main> (docs/design/shell-rules.md § Shell rules).",
          });
      }
      start = i + 1;
    }
  }
  if (stack.length)
    findings.push({
      file,
      line: offsetLine(masked, stack.at(-1)?.start ?? 0),
      rule: "parse",
      message: "Unclosed CSS rule. Fix the syntax and rerun pnpm policy:checks.",
    });
  return withoutThemeExemptions(source, findings);
}

function formatFinding(finding: Finding): string {
  return `${finding.file}:${finding.line} ${finding.rule}: ${finding.message}`;
}

/** Every tracked or non-ignored web source file under apps/web/src and packages/ui/src. */
export function checkWebConventions(root: string): string[] {
  let paths: string[];
  try {
    paths = [
      ...new Set(
        execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], {
          cwd: root,
          encoding: "utf8",
          maxBuffer: 16 * 1024 * 1024,
          stdio: ["ignore", "pipe", "pipe"],
        })
          .split("\0")
          .filter(Boolean),
      ),
    ].sort();
  } catch (error) {
    return [
      `scripts/check-web-conventions.ts:1 Cannot enumerate tracked/non-ignored source. Fix Git access and rerun pnpm policy:checks: ${(error as Error).message}`,
    ];
  }
  const failures: string[] = [];
  for (const file of paths) {
    const sourceFile =
      /^(apps\/web|packages\/ui)\/src\//.test(file) && /\.(?:[cm]?[jt]sx?|css)$/.test(file);
    if (!sourceFile || !existsSync(join(root, file))) continue; // tracked deletions have no working-tree source
    try {
      const source = readFileSync(join(root, file), "utf8");
      failures.push(
        ...(file.endsWith(".css") ? scanWebCss(file, source) : scanWebSource(file, source)).map(
          formatFinding,
        ),
      );
    } catch (error) {
      failures.push(
        `${file}:1 Cannot read/check source. Fix the file and rerun pnpm policy:checks: ${(error as Error).message}`,
      );
    }
  }
  return failures;
}
