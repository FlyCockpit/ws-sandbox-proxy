/**
 * Newline-safe upsert of KEY=value lines in a local `.env` file.
 *
 * `upsertEnvContents` is pure (unit-tested in `env-file.test.mjs`);
 * `upsertEnvFile` owns the I/O: it refuses a symlink, writes a 0600 temporary
 * file next to the target and renames it into place, so a crash never leaves
 * a half-written `.env`. Neither ever returns or logs a value, only key names.
 *
 * An existing assignment is replaced in place (the first one; later
 * duplicates are removed so the result is unambiguous). A quoted value that
 * spans several lines is replaced as a whole. Other lines, comments and
 * blank lines are kept byte for byte. Missing keys are appended.
 */
import { lstatSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import process from "node:process";

const KEY = /^[A-Z_][A-Z0-9_]*$/;

/**
 * Encode a value the way `scripts/generate-secrets.ts` does: bare when it is
 * plain, single-quoted (fully literal) otherwise. Refuses newlines, NUL and
 * quotes, which no caller needs and which would make the file ambiguous.
 */
function encodeEnvValue(key, value) {
  if (typeof value !== "string") throw new TypeError(`${key} must be a string.`);
  if (/[\r\n\0'"`\\]/.test(value))
    throw new Error(`${key} contains a character not allowed in .env.`);
  if (value === "" || /^[A-Za-z0-9_./:@%+,=-]+$/.test(value)) return value;
  return `'${value}'`;
}

function assignmentKey(line) {
  const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
  return match ? { key: match[1], rest: line.slice(match[0].length) } : null;
}

/** Index of the last line of an assignment whose quoted value may span lines. */
function assignmentEnd(lines, start, rest) {
  const value = rest.trimStart();
  const quote = value[0];
  if (quote !== "'" && quote !== '"' && quote !== "`") return start;
  if (value.indexOf(quote, 1) !== -1) return start;
  for (let i = start + 1; i < lines.length; i++) if (lines[i].includes(quote)) return i;
  return start;
}

/**
 * @param {string} contents existing file contents ("" when absent)
 * @param {Record<string, string>} entries keys to set
 * @returns {{ contents: string, replaced: string[], appended: string[] }}
 */
export function upsertEnvContents(contents, entries) {
  const encoded = new Map();
  for (const [key, value] of Object.entries(entries)) {
    if (!KEY.test(key)) throw new Error(`invalid env key: ${key}`);
    encoded.set(key, `${key}=${encodeEnvValue(key, value)}`);
  }
  const lines = contents.length === 0 ? [] : contents.split("\n");
  const trailingNewline = contents.endsWith("\n");
  if (trailingNewline) lines.pop();
  const out = [];
  const replaced = new Set();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const parsed = line.trimStart().startsWith("#") ? null : assignmentKey(line);
    if (!parsed || !encoded.has(parsed.key)) {
      out.push(line);
      continue;
    }
    i = assignmentEnd(lines, i, parsed.rest);
    if (replaced.has(parsed.key)) continue;
    replaced.add(parsed.key);
    out.push(encoded.get(parsed.key));
  }
  const appended = [...encoded.keys()].filter((key) => !replaced.has(key));
  for (const key of appended) out.push(encoded.get(key));
  return {
    contents: out.length === 0 ? "" : `${out.join("\n")}\n`,
    replaced: [...replaced],
    appended,
  };
}

/** Upsert `entries` into the env file at `path` (created 0600 if absent). */
export function upsertEnvFile(path, entries) {
  const target = resolve(path);
  let existing = "";
  try {
    const stat = lstatSync(target);
    if (!stat.isFile())
      throw new Error(`${basename(target)} is not a regular file; refusing to write it.`);
    existing = readFileSync(target, "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const result = upsertEnvContents(existing, entries);
  const temporary = resolve(dirname(target), `.${basename(target)}.${process.pid}.tmp`);
  try {
    writeFileSync(temporary, result.contents, { mode: 0o600, flag: "wx" });
    renameSync(temporary, target);
  } finally {
    rmSync(temporary, { force: true });
  }
  return { replaced: result.replaced, appended: result.appended };
}
