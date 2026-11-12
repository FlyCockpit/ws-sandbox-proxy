/**
 * Principal-kind lint. A branch on, or a
 * construction of, a principal kind outside the exhaustive helpers is the
 * "implicit else-branch over an open union" bug class: adding a kind silently
 * falls into whichever branch the site wrote last. The helpers in
 * `principal-kinds.ts` and `stored-principal.ts` end every switch in
 * `assertNever`, so a new kind is a compile error there and nowhere else.
 *
 * Four encodings are refused outside those files:
 *   1. kind comparisons: `.kind === "session"`, `!== "sdkKey"`, `principal === "system"`,
 *      reversed forms and `case "session":` labels;
 *   2. kind literals: `kind: "session"` (constructing a principal or attribution);
 *   3. default-parameter principals: `principal: AuthorizingPrincipal = …`;
 *   4. null-key reconstructions: `keyId ? … : …`, `keyId && …`, `!row.keyId`,
 *      `?? { kind`, `keyId ?? "session"`, and `revalidateSdkKey(` calls.
 *
 * Reviewed exceptions live in `principal-kinds.lint.allow.json` as
 * `path|sha256-of-complete-line|reason`; each entry covers exactly one line,
 * and an edited, duplicated or stale occurrence fails (the pinning style of
 * `scripts/policy-checks.sh`). Do not grow the allowlist to land a branch:
 * add or extend a helper instead.
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const REPO = resolve(import.meta.dirname, "../../../..");
const ALLOWLIST_PATH = resolve(import.meta.dirname, "principal-kinds.lint.allow.json");
const KINDS = "(?:sdkKey|session|system|build)";
const KEY = "(?:authorizingKeyId|keyId)";
const PRINCIPAL_TYPES =
  "(?:AuthorizingPrincipal|Principal|SessionPrincipal|ServicePrincipal|BuildPrincipal)";

type Encoding = "comparison" | "literal" | "default" | "null-key";
const RULES: ReadonlyArray<{ encoding: Encoding; pattern: RegExp }> = [
  { encoding: "comparison", pattern: new RegExp(String.raw`\.kind\s*[!=]==?\s*"${KINDS}"`) },
  {
    encoding: "comparison",
    pattern: new RegExp(String.raw`"${KINDS}"\s*[!=]==?\s*[\w.?]*\.kind\b`),
  },
  { encoding: "comparison", pattern: new RegExp(String.raw`\bprincipal\s*[!=]==?\s*"${KINDS}"`) },
  { encoding: "comparison", pattern: new RegExp(String.raw`\bcase\s+"${KINDS}"\s*:`) },
  { encoding: "null-key", pattern: new RegExp(String.raw`\?\?\s*\{\s*kind:\s*"${KINDS}"`) },
  { encoding: "default", pattern: new RegExp(String.raw`=\s*\{\s*kind:\s*"${KINDS}"`) },
  { encoding: "literal", pattern: new RegExp(String.raw`\bkind:\s*"${KINDS}"`) },
  {
    encoding: "default",
    pattern: new RegExp(
      String.raw`(?<!\b(?:const|let|var)\s+)\b\w+\??\s*:\s*${PRINCIPAL_TYPES}\s*=(?![=>])`,
    ),
  },
  { encoding: "null-key", pattern: new RegExp(String.raw`\b${KEY}\s*\?(?![?.:])`) },
  // A key-identity comparison (`a.keyId === b.keyId &&`) is not a null-key test.
  {
    encoding: "null-key",
    pattern: new RegExp(String.raw`(?<!(?:===|!==)\s*[\w.?]*)\b${KEY}\s*&&`),
  },
  { encoding: "null-key", pattern: new RegExp(String.raw`!(?:\w+\??\.)*${KEY}\b`) },
  { encoding: "null-key", pattern: new RegExp(String.raw`\b${KEY}\s*\?\?\s*"`) },
  { encoding: "null-key", pattern: /\brevalidateSdkKey\s*\(/ },
];

/** Files that may branch on and construct kinds. */
const HELPER_FILES = new Set([
  "packages/api/src/sandbox/principal-kinds.ts",
  "packages/api/src/sandbox/stored-principal.ts",
  "packages/api/src/template-builds/principal.ts",
]);
/** Named declarations that define a kind (types, factories, the strict decoder). */
const EXEMPT_DECLARATIONS: Readonly<Record<string, readonly string[]>> = {
  "packages/api/src/sandbox/contracts.ts": [
    "SessionPrincipal",
    "sessionPrincipal",
    "AuthorizingPrincipal",
  ],
  "packages/api/src/sandbox/outbox.ts": ["decodeOutboxPrincipal"],
  "packages/api/src/lib/sdk-key-access.ts": ["ServicePrincipal", "principalFromRow"],
};
/** The auth core keeps its class switches; each must end in `assertNever`. */
const SWITCH_FILES = new Set(["packages/api/src/lib/sdk-key-access.ts"]);
/** The SDK key is revalidated only by the auth core and the stored-principal resolver. */
const REVALIDATE_FILES = new Set([
  "packages/api/src/lib/sdk-key-access.ts",
  "packages/api/src/sandbox/stored-principal.ts",
]);

export type Finding = { path: string; line: number; encoding: Encoding; text: string };

function braceDelta(text: string): number {
  let delta = 0;
  for (const char of text) {
    if (char === "{") delta += 1;
    else if (char === "}") delta -= 1;
  }
  return delta;
}

/** Line indexes (0-based) of a declaration from its name to its closing `}` / `;`. */
function declarationLines(lines: readonly string[], name: string): Set<number> {
  const out = new Set<number>();
  const start = lines.findIndex((line) =>
    new RegExp(String.raw`\b(?:function|type|const|let)\s+${name}\b`).test(line),
  );
  if (start < 0) throw new Error(`exempt declaration ${name} not found`);
  let depth = 0;
  for (let i = start; i < lines.length; i += 1) {
    out.add(i);
    depth += braceDelta(lines[i]!);
    const trimmed = lines[i]!.trim();
    if (depth === 0 && (trimmed.endsWith(";") || trimmed === "}")) break;
  }
  return out;
}

/** `case` lines inside `switch (….kind)` blocks that end in `assertNever(`. */
function exhaustiveSwitchCaseLines(lines: readonly string[]): {
  allowed: Set<number>;
  open: number[];
} {
  const allowed = new Set<number>();
  const open: number[] = [];
  for (let start = 0; start < lines.length; start += 1) {
    if (!/\bswitch\s*\(\s*[\w.]*\bkind\s*\)\s*\{/.test(lines[start]!)) continue;
    let depth = 0;
    let end = start;
    for (let i = start; i < lines.length; i += 1) {
      depth += braceDelta(lines[i]!);
      end = i;
      if (depth === 0) break;
    }
    const block = lines.slice(start, end + 1).join("\n");
    if (!/\bdefault\s*:[\s\S]*\bassertNever\(/.test(block)) open.push(start + 1);
    for (let i = start; i <= end; i += 1) allowed.add(i);
  }
  return { allowed, open };
}

export function scanSource(path: string, text: string): Finding[] {
  if (HELPER_FILES.has(path)) return [];
  const lines = text.split("\n");
  const exempt = new Set<number>();
  for (const name of EXEMPT_DECLARATIONS[path] ?? [])
    for (const index of declarationLines(lines, name)) exempt.add(index);
  const switches = SWITCH_FILES.has(path)
    ? exhaustiveSwitchCaseLines(lines)
    : { allowed: new Set<number>(), open: [] };
  const findings: Finding[] = switches.open.map((line) => ({
    path,
    line,
    encoding: "comparison" as const,
    text: "switch over a principal kind without a `default: … assertNever(…)`",
  }));
  lines.forEach((line, index) => {
    if (exempt.has(index)) return;
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) return;
    for (const { encoding, pattern } of RULES) {
      if (!pattern.test(line)) continue;
      if (/\bcase\s+"/.test(line) && switches.allowed.has(index)) continue;
      if (/revalidateSdkKey/.test(pattern.source) && REVALIDATE_FILES.has(path)) continue;
      findings.push({ path, line: index + 1, encoding, text: trimmed });
      return;
    }
  });
  return findings;
}

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === "generated") continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...sourceFiles(path));
    else if (/\.(ts|tsx)$/.test(entry) && !/\.test\.tsx?$/.test(entry)) out.push(path);
  }
  return out;
}

function packageSourceRoots(): string[] {
  const roots = ["apps/server/src", "apps/web/src", "apps/worker/src"];
  for (const name of readdirSync(resolve(REPO, "packages"))) {
    const src = resolve(REPO, "packages", name, "src");
    try {
      if (statSync(src).isDirectory()) roots.push(relative(REPO, src));
    } catch {
      // A package without `src/` has no TypeScript sources to lint.
    }
  }
  return roots;
}

const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");

type AllowEntry = { path: string; hash: string; reason: string };
function readAllowlist(): AllowEntry[] {
  const raw = JSON.parse(readFileSync(ALLOWLIST_PATH, "utf8")) as unknown;
  if (!Array.isArray(raw)) throw new Error("allowlist must be a JSON array");
  return raw.map((entry) => {
    if (typeof entry !== "string") throw new Error("allowlist entries are strings");
    const [path, hash, reason, ...rest] = entry.split("|");
    if (!path || !hash || !/^[0-9a-f]{64}$/.test(hash) || !reason?.trim() || rest.length > 0)
      throw new Error(`malformed allowlist entry: ${entry}`);
    return { path, hash, reason };
  });
}

describe("principal-kind lint (scanner self-test)", () => {
  const scan = (text: string, path = "packages/api/src/sandbox/example.ts") =>
    scanSource(path, text).map((finding) => finding.encoding);

  it.each([
    ['if (owner.kind === "session") return;', "comparison"],
    ['if (principal.kind !== "sdkKey") throw forbidden();', "comparison"],
    ['const x = principal?.kind === "system";', "comparison"],
    ['if ("session" === owner.kind) return;', "comparison"],
    ['authorizingKeyId: input.principal === "system" ? null : k,', "comparison"],
    ['    case "build":', "comparison"],
    ['const principal = { kind: "session", ownerId };', "default"],
    ['return { kind: "sdkKey", keyId: owner.keyId };', "literal"],
    ['  kind: "sdkKey" as const,', "literal"],
    ['    principal: AuthorizingPrincipal = { kind: "session" },', "default"],
    ["    principal: AuthorizingPrincipal = SESSION,", "default"],
    ["const owner = row.keyId ? await load(row.keyId) : session;", "null-key"],
    ["keyId && tx.count({ where: { keyId } })", "null-key"],
    ["if (!head.authorizingKeyId) return session;", "null-key"],
    ['principal: principal ?? { kind: "session" as const },', "null-key"],
    ['  context.authorizingKeyId ?? "session",', "null-key"],
    ["const key = await revalidateSdkKey(id, owner, tx);", "null-key"],
  ] as const)("flags %s", (line, encoding) => {
    expect(scan(line)).toEqual([encoding]);
  });

  it.each([
    "  authorizingKeyId?: string | null;",
    "if (operation.authorizingKeyId !== recordedKeyIdOf(principal)) status = 'inactive';",
    "operation.authorizingKeyId === binding?.authorizingKeyId &&",
    'const lease = q.lease ?? { kind: "deadline" as const, ms: 1 };',
    "const owner: Principal = await authorize();",
    '// a comment naming kind === "session" is not a branch',
    'type Wire = { kind: "global" } | { kind: "scoped" };',
  ])("passes %s", (line) => {
    expect(scan(line)).toEqual([]);
  });

  it("exempts the helper files and the named kind declarations only", () => {
    expect(
      scan('if (p.kind === "session") return;', "packages/api/src/sandbox/principal-kinds.ts"),
    ).toEqual([]);
    const contracts = [
      'export type SessionPrincipal = { readonly kind: "session"; readonly ownerId: string };',
      "export function sessionPrincipal(ownerId: string): SessionPrincipal {",
      '  return { kind: "session", ownerId };',
      "}",
      'const stray = { kind: "session" };',
      "export type AuthorizingPrincipal =",
      '  | { kind: "sdkKey"; keyId: string }',
      '  | { kind: "session" };',
    ].join("\n");
    expect(scanSource("packages/api/src/sandbox/contracts.ts", contracts)).toEqual([
      expect.objectContaining({ line: 5, encoding: "default" }),
    ]);
  });

  it("admits auth-core case labels only inside a switch that ends in assertNever", () => {
    const path = "packages/api/src/lib/sdk-key-access.ts";
    const closed = [
      "switch (principal.kind) {",
      '  case "session":',
      "    return owner;",
      '  case "sdkKey":',
      "    break;",
      "  default:",
      "    return assertNever(principal);",
      "}",
    ].join("\n");
    const declarations = [
      'export type ServicePrincipal = { kind: "sdkKey" };',
      "function principalFromRow() {",
      '  return { kind: "sdkKey" };',
      "}",
    ].join("\n");
    expect(scanSource(path, `${declarations}\n${closed}`)).toEqual([]);
    const open = closed.replace("    return assertNever(principal);", "    throw forbidden();");
    expect(scanSource(path, `${declarations}\n${open}`)).toEqual([
      expect.objectContaining({ line: 5 }),
    ]);
    expect(scan(closed)).toEqual(["comparison", "comparison"]);
  });
});

describe("principal-kind lint (repository)", () => {
  const files = packageSourceRoots()
    .flatMap((root) => sourceFiles(resolve(REPO, root)))
    .map((path) => ({
      path: relative(REPO, path).replaceAll("\\", "/"),
      text: readFileSync(path, "utf8"),
    }));
  const findings = files.flatMap((file) => scanSource(file.path, file.text));
  const allowlist = readAllowlist();

  it("scans the server, worker, web and every package", () => {
    expect(files.some((file) => file.path === "packages/api/src/lib/sdk-key-access.ts")).toBe(true);
    expect(files.some((file) => file.path.startsWith("apps/server/src/"))).toBe(true);
  });

  it("finds no principal-kind encoding outside the helpers except reviewed lines", () => {
    const lines = new Map(files.map((file) => [file.path, file.text.split("\n")]));
    const allowed = new Map<string, number>();
    for (const entry of allowlist) {
      const key = `${entry.path}|${entry.hash}`;
      allowed.set(key, (allowed.get(key) ?? 0) + 1);
    }
    const unreviewed: string[] = [];
    for (const finding of findings) {
      const text = lines.get(finding.path)?.[finding.line - 1] ?? "";
      const key = `${finding.path}|${sha256(text)}`;
      const left = allowed.get(key) ?? 0;
      if (left > 0) allowed.set(key, left - 1);
      else
        unreviewed.push(
          `${finding.path}:${finding.line} [${finding.encoding}] ${finding.text} (sha256 ${sha256(text)})`,
        );
    }
    expect(unreviewed).toEqual([]);
    const stale = [...allowed].filter(([, left]) => left > 0).map(([key]) => key);
    expect(stale).toEqual([]);
  });
});
