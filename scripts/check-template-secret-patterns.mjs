/**
 * `pnpm policy:template-secrets`: fail on application secrets, database
 * credentials and private keys in tracked or untracked (not ignored) files.
 * Secrets pass only as the documented semantic placeholders below. A private
 * key passes only in a vendored russh file pinned by hash in
 * `third_party/russh-key-fixtures.sha256` (see `KEY_FIXTURE_PINS` and
 * `third_party/README.md`); there are no path or glob exemptions.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = new URL("..", import.meta.url);
const DOCKER_DEFAULT_SECRET_SHA256 =
  "7b392ad9b78b37bfede6f3c8d35f7a26c4f2641ebff21f7599b7fe2a6387fd9d";
const DATABASE_USERS = new Set(["postgres"]);
const DATABASE_PASSWORDS = new Set(["password", "test", "drill"]);
const DATABASE_PORTS = new Set(["", "5432", "55432"]);

const PATTERNS = [
  {
    kind: "application-secret",
    expression:
      "(^|[[:space:]])(BETTER_AUTH_SECRET|VAPID_PRIVATE_KEY)[[:space:]]*=[[:space:]]*[^[:space:]#]+",
  },
  {
    kind: "database-credential",
    expression:
      "DATABASE_URL[[:space:]]*=[[:space:]]*postgres(ql)?://[^[:space:]]+:[^[:space:]@]+@",
  },
  { kind: "private-key", expression: "-----BEGIN [A-Z ]*PRIVATE KEY-----" },
];

/**
 * The one private-key exception: vendored upstream russh files that hold
 * russh's own test keys. A file is accepted only while its bytes hash to its
 * pin here, the pin being the published crate's copy of that file (proved by
 * `cargo xtask vendored-russh --check`, rewritten by `--update`). Any edit to
 * the file, the same keys at any other path, a missing or malformed pin file,
 * a pin for a copy the root `Cargo.toml` does not patch in, or a vendored
 * patch that touches the file or that `--check` could not apply fails the
 * scan. The scanner trusts the pin hashes as far as `--check` proves them:
 * CI runs it on every change under `third_party/**` (`cli-ci.yml`
 * `docs-drift`); `pnpm verify` does not, so run it after editing a pin.
 */
const KEY_FIXTURE_PINS = "third_party/russh-key-fixtures.sha256";
// Plain path characters only: no `:`, `#`, `?`, `%`, spaces or escapes that
// could make the path git grep reports differ from the file that is hashed.
const KEY_FIXTURE_PATH =
  /^third_party\/russh-(\d+\.\d+\.\d+)\/([A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*)$/;
const ROOT_DIR = fileURLToPath(ROOT);
const PATCH_PATH = "[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*";
const PATCH_DIFF_LINE = new RegExp(`^diff --git a/(${PATCH_PATH}) b/(${PATCH_PATH})$`);
// At most 9 digits: always within xtask's `usize` line numbers.
const PATCH_HUNK_HEADER = /^@@ -[0-9]{1,9}(?:,[0-9]{1,9})? \+[0-9]{1,9}(?:,[0-9]{1,9})? @@/;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function secretAssignments(line) {
  return [...line.matchAll(/\b(BETTER_AUTH_SECRET|VAPID_PRIVATE_KEY)\s*=\s*([^\s#]+)/g)].map(
    (match) => ({ key: match[1], value: match[2] }),
  );
}

function databasePlaceholders(line) {
  const matches = [...line.matchAll(/\bDATABASE_URL\s*=\s*(postgres(?:ql)?:\/\/[^\s`"'\\]+)/g)];
  if (matches.length === 0) return false;
  return matches.every((match) => databasePlaceholder(match[1] ?? ""));
}

function databasePlaceholder(value) {
  if (!value) return false;
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  return (
    (parsed.protocol === "postgres:" || parsed.protocol === "postgresql:") &&
    parsed.hostname === "localhost" &&
    DATABASE_USERS.has(parsed.username) &&
    DATABASE_PASSWORDS.has(parsed.password) &&
    DATABASE_PORTS.has(parsed.port) &&
    // The database name is product identity, not a credential. Permit one
    // ordinary local identifier so a rebrand does not require editing this
    // scanner, while retaining exact disposable host/user/password semantics.
    /^[A-Za-z0-9_-]+$/.test(parsed.pathname.slice(1)) &&
    !parsed.search &&
    !parsed.hash
  );
}

/**
 * These are semantic placeholders, not path/prefix exemptions. A matching
 * detector line is still rejected unless its value itself is one of the small,
 * documented non-credential forms below. The docker default is pinned by hash
 * so changing it requires an intentional review of this allowlist.
 */
function documentedSecretAssignment(file, assignment) {
  if (
    file === ".env.docker.defaults" &&
    assignment.key === "BETTER_AUTH_SECRET" &&
    sha256(assignment.value) === DOCKER_DEFAULT_SECRET_SHA256
  ) {
    return true;
  }
  if (assignment.key === "VAPID_PRIVATE_KEY" && assignment.value === "…") return true;
  if (assignment.key !== "BETTER_AUTH_SECRET") return false;
  return new Set([
    '"your-secret-min-32-chars"',
    "$(openssl",
    "<openssl",
    ["$", "{{server.BETTER_AUTH_SECRET}}"].join(""),
  ]).has(assignment.value);
}

/**
 * Parse the pin file: sorted, unique `<lowercase sha256>  <path>` lines, each
 * naming a plain path below `third_party/russh-<version>/`. Anything else
 * throws, so a damaged pin file fails the scan instead of exempting nothing
 * or something unintended.
 */
function parseKeyFixturePins(text) {
  if (typeof text !== "string") throw new Error(`${KEY_FIXTURE_PINS} is missing`);
  if (text !== "" && !text.endsWith("\n")) {
    throw new Error(`${KEY_FIXTURE_PINS}: the last line has no newline`);
  }
  const pins = new Map();
  let previous = "";
  for (const [index, line] of text.split("\n").slice(0, -1).entries()) {
    const match = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
    const path = KEY_FIXTURE_PATH.exec(match?.[2] ?? "");
    const parts = path?.[2]?.split("/") ?? [];
    if (!match || !path || parts.some((part) => part === "." || part === "..")) {
      throw new Error(`${KEY_FIXTURE_PINS}: line ${index + 1} is not \`<sha256>  <path>\``);
    }
    const file = match[2];
    if (file <= previous) {
      throw new Error(`${KEY_FIXTURE_PINS}: line ${index + 1} is out of order or repeated`);
    }
    previous = file;
    pins.set(file, { digest: match[1], version: path[1], relative: path[2] });
  }
  return pins;
}

/**
 * The files a vendored patch edits, or null unless every line is one
 * `cargo xtask vendored-russh` applies: `diff --git a/P b/P` (plain P),
 * `index`, `--- a/P` + `+++ b/P`, `@@ -l,c +l,c @@` headers and ` `/`-`/`+`
 * hunk lines.
 * A quoted or escaped path, a mode, rename, copy or binary header, or stray
 * text gives null, so the exception fails closed on any patch it cannot read.
 * This is a fail-closed subset of what xtask parses, not a re-run of
 * `--check`: whether the hunks apply needs the published crate, which only
 * `--check` (CI) has. The bytes the exception covers never depend on the
 * patch; they are the pinned upstream bytes.
 */
function patchedFiles(patch) {
  if (!patch.endsWith("\n")) return null;
  const lines = patch.split("\n").slice(0, -1);
  const files = new Set();
  let state = "top";
  let path = "";
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const diff = PATCH_DIFF_LINE.exec(line);
    if (diff) {
      if ((state !== "top" && state !== "hunk") || diff[1] !== diff[2]) return null;
      path = diff[1];
      files.add(path);
      state = "header";
    } else if (state === "header" && line.startsWith("index ")) {
      // The blob ids; the bytes themselves are checked by `--check`.
    } else if (
      state === "header" &&
      line === `--- a/${path}` &&
      lines[index + 1] === `+++ b/${path}`
    ) {
      index += 1;
      state = "file";
    } else if ((state === "file" || state === "hunk") && PATCH_HUNK_HEADER.test(line)) {
      state = "hunk";
    } else if (state === "hunk" && /^[ +-]/.test(line)) {
      // A hunk line.
    } else {
      return null;
    }
  }
  return state === "hunk" ? files : null;
}

/**
 * Whether a private-key finding is in a pinned file whose current bytes are
 * exactly the pinned upstream bytes and which the vendored patch leaves alone
 * (no patch line names the file at all: hunks, mode, rename and copy headers
 * all carry its path, so any of them fails closed).
 * `io.readFile(path)` returns the file's bytes (null if it is not a regular
 * file); `io.readPatch(version)` returns the vendored patch text (or null);
 * `io.vendoredVersion()` returns the version the root `Cargo.toml` patches in.
 */
function isPinnedKeyFixture(finding, pins, io) {
  if (finding.kind !== "private-key") return false;
  const pin = pins.get(finding.file);
  if (!pin) return false;
  const bytes = io.readFile(finding.file);
  if (!bytes || sha256(bytes) !== pin.digest) return false;
  const patch = io.readPatch(pin.version);
  if (typeof patch !== "string") return false;
  // Only the copy the build uses (root `[patch.crates-io]`), the one
  // `vendored-russh --check` proves; never a second `third_party/russh-*`.
  if (pin.version !== io.vendoredVersion()) return false;
  const edited = patchedFiles(patch);
  if (!edited || edited.has(pin.relative)) return false;
  // Case-insensitively too: on a case-insensitive file system `src/Keys.rs`
  // is the pinned file.
  const named = pin.relative.toLowerCase();
  return !patch.split("\n").some((line) => line.toLowerCase().includes(named));
}

const repositoryIo = {
  // The literal path below the repository root (never URL-parsed), and only
  // if no component of it is a symlink.
  readFile(path) {
    const file = join(ROOT_DIR, path);
    try {
      if (!lstatSync(file).isFile() || realpathSync(file) !== join(realpathSync(ROOT_DIR), path)) {
        return null;
      }
      return readFileSync(file);
    } catch {
      return null;
    }
  },
  readPatch(version) {
    try {
      return readFileSync(join(ROOT_DIR, "third_party", `russh-${version}.patch`), "utf8");
    } catch {
      return null;
    }
  },
  vendoredVersion() {
    try {
      const manifest = readFileSync(join(ROOT_DIR, "Cargo.toml"), "utf8");
      const found = [
        ...manifest.matchAll(/^russh = \{ path = "third_party\/russh-(\d+\.\d+\.\d+)" \}$/gm),
      ];
      return found.length === 1 ? found[0][1] : null;
    } catch {
      return null;
    }
  },
};

export function isDocumentedPlaceholder(finding) {
  if (finding.kind === "database-credential") return databasePlaceholders(finding.text);
  if (finding.kind === "private-key") return false;
  const assignments = secretAssignments(finding.text);
  return (
    assignments.length > 0 &&
    assignments.every((assignment) => documentedSecretAssignment(finding.file, assignment))
  );
}

/**
 * `git grep -z -n` output: `<path>\0<line>\0<text>\n` per match, the path
 * verbatim (it may contain `:`, so only NUL delimits it). Anything else,
 * such as a "Binary file … matches" line or a path with a newline, throws.
 */
function parseGitGrep(output) {
  const findings = [];
  let at = 0;
  while (at < output.length) {
    const pathEnd = output.indexOf("\0", at);
    const lineEnd = pathEnd < 0 ? -1 : output.indexOf("\0", pathEnd + 1);
    const textEnd = lineEnd < 0 ? -1 : output.indexOf("\n", lineEnd + 1);
    if (textEnd < 0) throw new Error("git grep returned an unreadable finding");
    const file = output.slice(at, pathEnd);
    const lineText = output.slice(pathEnd + 1, lineEnd);
    if (!file || file.includes("\n") || !/^[1-9][0-9]*$/.test(lineText)) {
      throw new Error("git grep returned an unreadable finding");
    }
    findings.push({ file, line: Number(lineText), text: output.slice(lineEnd + 1, textEnd) });
    at = textEnd + 1;
  }
  return findings;
}

function scanPattern(pattern) {
  // `--untracked`: a check run before `git add` (new files are untracked
  // until the commit) must see the files it is about to commit. Ignored
  // files stay out (`.gitignore`); they are never committed.
  const args = ["grep", "--untracked", "-z", "-n", "-E", "-e", pattern.expression, "--", "."];
  const result = spawnSync("git", args, {
    cwd: ROOT,
    encoding: "utf8",
  });
  if (result.error || (result.status !== 0 && result.status !== 1)) {
    throw new Error(
      `could not run the template secret scan (${result.error?.code ?? result.status ?? "unknown"})`,
    );
  }
  return parseGitGrep(result.stdout).map((finding) => ({ ...finding, kind: pattern.kind }));
}

export function collectResidualFindings(findings, pins = new Map(), io = repositoryIo) {
  return findings.filter(
    (finding) => !isDocumentedPlaceholder(finding) && !isPinnedKeyFixture(finding, pins, io),
  );
}

function readPins() {
  let text;
  try {
    text = readFileSync(new URL(KEY_FIXTURE_PINS, ROOT), "utf8");
  } catch {
    text = undefined;
  }
  return parseKeyFixturePins(text);
}

const SAMPLE_PATCH =
  "diff --git a/src/lib.rs b/src/lib.rs\nindex 1..2 100644\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,2 @@\n a\n-b\n+c\n";

function keyFixtureSelfTest() {
  const repositoryPins = readPins();
  const [first] = [...repositoryPins.keys()];
  // The real pinned file and patch; if an upgrade left no pin, a synthetic
  // one, so the exception's tests still run.
  const file = first ?? "third_party/russh-0.0.0/src/keys.rs";
  const real = first
    ? repositoryIo.readFile(first)
    : Buffer.from(`${"-".repeat(5)}BEGIN PRIVATE KEY${"-".repeat(5)}\n`);
  if (!real) throw new Error(`${file} is not a regular file`);
  const pins = first
    ? repositoryPins
    : new Map([[file, { digest: sha256(real), version: "0.0.0", relative: "src/keys.rs" }]]);
  const baseIo = first
    ? repositoryIo
    : {
        readFile: (path) => (path === file ? real : null),
        readPatch: () => SAMPLE_PATCH,
        vendoredVersion: () => "0.0.0",
      };
  const finding = { file, line: 1, text: "", kind: "private-key" };
  const residual = (findings, overrides = {}, pinMap = pins) =>
    collectResidualFindings(findings, pinMap, { ...baseIo, ...overrides }).length;
  if (residual([finding]) !== 0) {
    throw new Error("the pinned upstream key fixture should be accepted as it is");
  }
  for (const offset of [0, Math.floor(real.length / 2), real.length - 1]) {
    const changed = Buffer.from(real);
    changed[offset] = changed[offset] ^ 1;
    if (residual([finding], { readFile: () => changed }) !== 1) {
      throw new Error("a one-byte change to the pinned file must fail the scan");
    }
  }
  if (residual([finding], { readFile: () => Buffer.concat([real, Buffer.from("\n")]) }) !== 1) {
    throw new Error("an appended byte must fail the scan");
  }
  const copies = [
    "apps/cli/src/keys.rs",
    file.replace(/\.rs$/, ".copy.rs"),
    `./${file}`,
    file.toUpperCase(),
  ];
  for (const copy of copies) {
    if (residual([{ ...finding, file: copy }], { readFile: () => real }) !== 1) {
      throw new Error(`the pinned content at another path (${copy}) must fail the scan`);
    }
  }
  // A path git grep reports verbatim that only looks like the pinned one.
  const colon = `${file}:1:evil.rs`;
  const parsed = parseGitGrep(`${colon}\u00001\u0000x\n${file}\u00002\u0000y\n`);
  if (parsed.length !== 2 || parsed[0].file !== colon || parsed[1].file !== file) {
    throw new Error("git grep paths must be split on NUL only");
  }
  if (residual([parsed[0]], { readFile: () => real }) !== 1) {
    throw new Error("a path containing the pinned path must fail the scan");
  }
  for (const output of [
    "Binary file x matches\n",
    `${file}:1:x\n`,
    `${file}\u00000\u0000x\n`,
    `${file}\u00001\u0000x`,
    `a\nb\u00001\u0000x\n`,
  ]) {
    let threw = false;
    try {
      parseGitGrep(output);
    } catch {
      threw = true;
    }
    if (!threw) throw new Error(`unreadable git grep output must fail: ${JSON.stringify(output)}`);
  }
  // The hashed file is the literal path, never a URL-parsed one.
  if (
    !repositoryIo.readFile("package.json") ||
    repositoryIo.readFile("package.json#x") ||
    repositoryIo.readFile("package.json?x") ||
    repositoryIo.readFile("package%2ejson")
  ) {
    throw new Error("only the literal path may be read");
  }
  const without = new Map(pins);
  without.delete(file);
  if (residual([finding], {}, without) !== 1) {
    throw new Error("a file without a pin must fail the scan");
  }
  if (residual([{ ...finding, kind: "application-secret" }]) !== 1) {
    throw new Error("a pin covers private-key findings only");
  }
  const relative = pins.get(file).relative;
  for (const vendoredVersion of [() => "9.9.9", () => null]) {
    if (residual([finding], { vendoredVersion }) !== 1) {
      throw new Error("a pin for a copy the build does not use must fail the scan");
    }
  }
  if (residual([finding], { readPatch: () => SAMPLE_PATCH }) !== 0) {
    throw new Error("a patch that edits another file leaves the pin in force");
  }
  const escaped = relative.replace(/^./, (char) => `\\${char.charCodeAt(0).toString(8)}`);
  for (const patch of [
    `--- a/${relative}\n+++ b/${relative}\n`,
    SAMPLE_PATCH.replaceAll("src/lib.rs", relative),
    SAMPLE_PATCH.replaceAll("src/lib.rs", relative.toUpperCase()),
    `diff --git a/${relative} b/${relative}\nold mode 100644\nnew mode 100755\n`,
    `${SAMPLE_PATCH}diff --git a/x b/${relative}\nrename from x\nrename to ${relative}\n`,
    `${SAMPLE_PATCH}diff --git "a/${escaped}" "b/${escaped}"\nold mode 100644\nnew mode 100755\n`,
    `${SAMPLE_PATCH}diff --git a/x b/x\nold mode 100644\nnew mode 100755\n`,
    `${SAMPLE_PATCH}GIT binary patch\n`,
    SAMPLE_PATCH.replace("@@ -1,2 +1,2 @@", "@@ -garbage"),
    SAMPLE_PATCH.replace("@@ -1,2 +1,2 @@", "@@ -1,2 +1,2"),
    SAMPLE_PATCH.replace("@@ -1,2 +1,2 @@", "@@ - 1 +1 @@"),
    SAMPLE_PATCH.replace("@@ -1,2 +1,2 @@", "@@ -18446744073709551616,2 +1,2 @@"),
    `${SAMPLE_PATCH}\\ No newline at end of file\n`,
    SAMPLE_PATCH.trimEnd(),
    "",
    null,
  ]) {
    if (residual([finding], { readPatch: () => patch }) !== 1) {
      throw new Error(
        `a patch that touches the pinned file, or one it cannot read, must fail: ${JSON.stringify(patch)}`,
      );
    }
  }
  if (residual([finding], { readFile: () => null }) !== 1) {
    throw new Error("a pinned path that is not a regular file must fail the scan");
  }
  const digest = "a".repeat(64);
  const line = (path) => `${digest}  third_party/russh-1.2.3/${path}\n`;
  if (parseKeyFixturePins(line("a.rs") + line("b/c.rs")).size !== 2) {
    throw new Error("well-formed pins should parse");
  }
  const malformed = [
    undefined,
    line("a.rs").trimEnd(),
    line("a.rs").replace("  ", " "),
    line("a.rs").replace(digest, "A".repeat(64)),
    line("a.rs").replace(digest, "a".repeat(63)),
    `${digest}  apps/cli/a.rs\n`,
    `${digest}  third_party/other-1.2.3/a.rs\n`,
    line("../a.rs"),
    line("src//a.rs"),
    line("src/./a.rs"),
    line(""),
    line("a b.rs"),
    line("a:1:b.rs"),
    line("a#b.rs"),
    line("a?b.rs"),
    line("a%2fb.rs"),
    line("b.rs") + line("a.rs"),
    line("a.rs") + line("a.rs"),
    `\n${line("a.rs")}`,
    `# pins\n${line("a.rs")}`,
  ];
  for (const text of malformed) {
    let threw = false;
    try {
      parseKeyFixturePins(text);
    } catch {
      threw = true;
    }
    if (!threw) throw new Error(`a malformed pin file must fail the scan: ${JSON.stringify(text)}`);
  }
}

function selfTest() {
  const database = ["post", "gresql://postgres:password@localhost:5432/wssp"].join("");
  const authKey = ["BETTER_AUTH", "_SECRET"].join("");
  const vapidKey = ["VAPID_PRIVATE", "_KEY"].join("");
  const assignment = (key, value) => [key, "=", value].join("");
  const safe = [
    {
      file: ".env.example",
      line: 1,
      text: `DATABASE_URL=${database}`,
      kind: "database-credential",
    },
    {
      file: ".env.example",
      line: 2,
      text: `DATABASE_URL=${database.replace("wssp", "renamed_app")}`,
      kind: "database-credential",
    },
    {
      file: ".env.docker.defaults",
      line: 1,
      text: assignment(
        authKey,
        ["docker_dev_placeholder_do_not_use_in_production_", "1234567890abcdef"].join(""),
      ),
      kind: "application-secret",
    },
    {
      file: "README.md",
      line: 1,
      text: assignment(authKey, '"your-secret-min-32-chars"'),
      kind: "application-secret",
    },
    { file: "README.md", line: 1, text: assignment(vapidKey, "…"), kind: "application-secret" },
  ];
  if (collectResidualFindings(safe).length !== 0) {
    throw new Error("documented semantic placeholders should be accepted");
  }
  const unsafe = safe.concat([
    {
      file: "example.example",
      line: 2,
      text: `DATABASE_URL=${database.replace("password", "not-a-placeholder")}`,
      kind: "database-credential",
    },
    {
      file: "example.example",
      line: 3,
      text: `${`DATABASE_URL=${database.replace("wssp", "renamed_app?sslmode=require")}`}`,
      kind: "database-credential",
    },
    {
      file: ".env.docker.defaults",
      line: 2,
      text: assignment(authKey, "changed-value"),
      kind: "application-secret",
    },
    {
      file: "README.md",
      line: 2,
      text: assignment(vapidKey, "not-a-placeholder"),
      kind: "application-secret",
    },
    {
      file: "README.md",
      line: 3,
      text: `DATABASE_URL=${database} ${assignment(authKey, "not-a-placeholder")}`,
      kind: "application-secret",
    },
    {
      file: "README.md",
      line: 4,
      text: `DATABASE_URL=${database} ${["-----BE", "GIN PRIVATE KEY-----"].join("")}`,
      kind: "private-key",
    },
    {
      file: "README.md",
      line: 5,
      text: `${assignment(authKey, '"your-secret-min-32-chars"')} ${assignment(authKey, "not-a-placeholder")}`,
      kind: "application-secret",
    },
    {
      file: "README.md",
      line: 6,
      text: `DATABASE_URL=${database} DATABASE_URL=${database.replace("password", "not-a-placeholder")}`,
      kind: "database-credential",
    },
  ]);
  if (collectResidualFindings(unsafe).length !== 8) {
    throw new Error(
      "each matched credential occurrence must satisfy its own semantic placeholder check",
    );
  }
  keyFixtureSelfTest();
  console.log("template secret-pattern self-test OK");
}

function main() {
  const pins = readPins();
  const findings = PATTERNS.flatMap(scanPattern);
  const residual = collectResidualFindings(findings, pins);
  if (residual.length > 0) {
    for (const finding of residual) {
      console.error(`::error file=${finding.file},line=${finding.line}::Potential ${finding.kind}`);
    }
    console.error(
      "::error::Potential private secret committed. Rotate the secret and remove it from git history if it was real.",
    );
    process.exit(1);
  }
}

try {
  if (process.argv.includes("--self-test")) {
    selfTest();
  } else {
    main();
  }
} catch (error) {
  console.error(`::error::${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
