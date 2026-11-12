/**
 * Guards `<file>.md § <section>` citations — in shipped code and in the docs
 * themselves — against the actual section anchors in those docs, and every
 * relative doc-to-doc markdown link against the files on disk.
 *
 *   pnpm docs:check-citations   — verify without writing (CI gate; non-zero exit on drift)
 *
 * Why this exists: code comments across `apps/`, `packages/`, and `scripts/`
 * point readers at a specific section of a product doc, e.g.
 *
 *     // see docs/infra.md § The APPLY_SCHEMA contract.
 *
 * When a doc is restructured — a heading renamed, a section merged away — those
 * citations silently rot: the file still exists, so nothing errors, but the
 * "§ <section>" now names a heading that is gone. This script makes a stale
 * citation a fast, CI-visible error.
 *
 * What counts as a valid citation target (a doc "anchor"):
 *   1. A Markdown heading — any `#`..`######` line.
 *   2. A bold lead-in label — a line that starts (optionally after a list
 *      marker) with `**Label.**` / `**Label:**`.
 *
 * Matching is deliberately lenient about trailing text: a citation captures the
 * rest of the source line after `§`, which can run into continuing prose
 * (`… § The CI gate has the full …`). A citation passes if some anchor equals
 * the captured text or is a whole-word prefix of it — so "The CI gate has the
 * full" still resolves to the "The CI gate" heading. Both sides are normalized
 * (lowercased, backticks/asterisks removed, trailing punctuation stripped,
 * whitespace collapsed) before comparison.
 *
 * Scope: citations are read from shipped code (`apps/`, `packages/`, `scripts/`)
 * AND from the docs themselves (`docs/**.md` plus the root docs in ROOT_DOCS).
 * Docs cite each other several times more often than code cites them, and a
 * restructured file rots those references identically — so scanning only code
 * would miss most of the drift this check exists to catch. Doc-to-doc citations
 * are usually markdown links, `[docs/infra.md § Health](../infra.md#health)`,
 * which is why the citation regex stops at `]` and why a cited path is resolved
 * relative to the citing file before falling back to the repo root.
 *
 * A citation whose doc is missing is judged by its DIRECTORY:
 *
 *   - Directory gone too → warning. Deleting a whole docs tree must not turn
 *     CI red across a dozen source files that still mention it.
 *   - Directory still there, file missing → error. That is a typo or a rename,
 *     not a teardown. Warning on both was a real coverage hole: it meant a
 *     misspelled filename (`docs/infranotes.md § Foo`) passed CI silently,
 *     since nothing else validates the path.
 *
 * A renamed or deleted *heading* in a doc that still exists is always fatal.
 *
 * This file itself is skipped: its docstring quotes example citations and
 * heading names to explain the rules, and scanning it would let an unrelated
 * heading rename fail CI via prose that only documents the checker.
 *
 * Repo-relative links (C56) — markdown links, images and HTML href/src to
 * any file or directory, outside code — are validated in `docs/**.md`, the
 * CLI docs, package READMEs and the root docs that link into them (the
 * generated AGENTS.md mirrors inherit the result). A plain "see [x](./x.md)"
 * carries no `§`, so nothing else noticed when its target was renamed or
 * deleted. A missing link target is always fatal, and a `#anchor` on a
 * markdown target (or a bare `#anchor`) must name one of that file's GitHub
 * heading slugs. Absolute URLs and site paths (`/v1/…`) are out of scope.
 * The helpers live in `scripts/lib/doc-links.ts` (tested by
 * `scripts/lib/doc-links.test.ts`).
 *
 * Dependency-free by design (node:fs only) — no new packages, safe to run in the
 * CI `lint` job alongside `pnpm env:check` / `pnpm docker:check-copy`.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

import { extractDocLinks, markdownAnchors } from "./lib/doc-links.ts";

const ROOT = resolve(import.meta.dirname!, "..");

// Where to scan for citations. Shipped code, plus the docs themselves — docs
// cite each other roughly 4x as often as code cites them, and a restructured
// pattern file rots those references exactly the same way.
const CODE_DIRS = ["apps", "packages", "scripts", "docs"];
const CODE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs", ".md"]);
// Root-level docs that also carry citations (the walk covers directories only).
const ROOT_DOCS = ["AGENTS.md", "CLAUDE.md", "README.md", "SECURITY.md"];
// Directories never worth scanning (build output, deps, generated caches).
const SKIP_DIRS = new Set([
  "node_modules",
  "dist",
  "build",
  "out",
  "coverage",
  ".turbo",
  ".next",
  ".expo",
  "target",
  ".git",
  // Generated, git-ignored Prisma client (packages/db/prisma/generated). Its
  // class.ts embeds a single token of several hundred KB that makes the
  // citation regex quadratic; with a larger schema the scan never finished.
  "generated",
]);

// A citation: `<path>.md § <rest of line>`. Any markdown doc counts — code also
// cites root docs (`docs/infra.md § The APPLY_SCHEMA contract`, `AGENTS.md §
// Dockerfiles — keep server and worker in sync`), and those headings rot
// exactly the same way.
// The section text stops at a newline or a `]`. The `]` bound matters now that
// docs are scanned: they cite each other as markdown links,
// `[docs/infra.md § Health](../infra.md#health)`, and without it the capture
// swallows `](../infra.md#health)` and never matches any heading.
const CITATION_RE = /([\w./-]+\.md)\s*§\s*([^\n\]]+)/g;

// The OTHER, more common spelling: a markdown link whose label carries the `§`
// but not the filename, with the doc named only in the target —
// `[infra § Health](../infra.md#health)`.
// `CITATION_RE` requires a literal `.md` before the `§`, so it cannot see these
// at all; that blind spot hid roughly 40% of the citations in this repo,
// including several in AGENTS.md. The path comes from the link target (group 3),
// which is more reliable than the label anyway.
const LINK_CITATION_RE = /\[([^\]\n]*?)§\s*([^\]\n]+)\]\(\s*([^)\s#]+\.md)(?:#[^)\s]*)?\s*\)/g;

// Repo-relative links in the product docs (C56): every markdown link, image
// and HTML href/src that is not an absolute URL or a site path, to ANY file
// or directory (`LICENSE`, `examples/wssp-host.service`, `../infra.md`), with
// its `#anchor` resolved against the target's GitHub heading slugs. A `§`
// citation only reaches the file-existence check when the author happened to
// name a section; a plain "see [x](./x.md)" link, a renamed heading behind a
// `#anchor`, or a moved example file rots invisibly otherwise. A missing
// target or anchor is always an error: these are the user-facing docs, and a
// dead link there is a defect (see scripts/lib/doc-links.ts).
//
// Where links are validated: product docs plus the root docs that link into
// them. CLAUDE.md / .cursorrules / copilot-instructions.md are generated
// mirrors of AGENTS.md, so checking AGENTS.md covers them.
const DOC_LINK_ROOT_DOCS = new Set([
  "AGENTS.md",
  "README.md",
  "SECURITY.md",
  "apps/cli/AGENTS.md",
  "apps/cli/CONTRIBUTING.md",
  "apps/cli/README.md",
  "apps/cli/SECURITY.md",
]);
function isDocLinkFile(rel: string): boolean {
  if (DOC_LINK_ROOT_DOCS.has(rel)) return true;
  if (!rel.endsWith(".md")) return false;
  return (
    rel.startsWith("docs/") ||
    rel.startsWith("apps/cli/docs/") ||
    /^packages\/[^/]+\/README\.md$/.test(rel)
  );
}
const linkAnchorCache = new Map<string, Set<string>>();
function anchorsOf(path: string): Set<string> {
  let anchors = linkAnchorCache.get(path);
  if (!anchors) {
    anchors = markdownAnchors(readFileSync(path, "utf8"));
    linkAnchorCache.set(path, anchors);
  }
  return anchors;
}

// This file's own docstring uses `docs/infra.md § …` as the
// worked example of what a citation looks like, and quotes heading names while
// explaining the matching rules. Scanning it would make renaming an unrelated
// heading fail CI via prose that merely documents the checker.
const SELF = resolve(ROOT, "scripts/check-doc-citations.ts");

/** Recursively collect code files under a directory, skipping build/vendor dirs. */
function walk(dir: string, acc: string[]): void {
  let entries: import("node:fs").Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      // Hidden directories hold tool state, not shipped source (.claude/,
      // .vscode/, .turbo/). Citations there are notes, not code comments.
      if (entry.name.startsWith(".") || SKIP_DIRS.has(entry.name)) continue;
      walk(full, acc);
    } else if (entry.isFile()) {
      const dot = entry.name.lastIndexOf(".");
      if (dot !== -1 && CODE_EXTENSIONS.has(entry.name.slice(dot))) acc.push(full);
    }
  }
}

/**
 * Lowercase, strip markdown emphasis/code and quotes, drop trailing
 * punctuation, collapse spaces.
 *
 * Quotes are stripped everywhere, not just at the ends: a citation may wrap the
 * section name in quotes mid-string (`§ "Who email verification gates" for the
 * …`), and an interior quote would otherwise survive and break the whole-word
 * prefix test in `anchorMatches`.
 */
function normalize(text: string): string {
  return (
    text
      .replace(/[`*_"'“”‘’]/g, "")
      .replace(/\s+/g, " ")
      .trim()
      // `|` is in the class because docs cite sections from inside table cells
      // (`… § 1 — Rate Limiting` |`), where the trailing pipe would otherwise
      // survive normalization and defeat the prefix match.
      .replace(/[\s.,;:)\]}"'*/|-]+$/g, "")
      .trim()
      .toLowerCase()
  );
}

/** Collect the set of citable anchors (headings + bold lead-in labels) for a doc. */
function collectAnchors(docPath: string): Set<string> {
  const anchors = new Set<string>();
  const text = readFileSync(docPath, "utf8");
  const headingRe = /^#{1,6}\s+(.+?)\s*$/;
  const boldLabelRe = /^\s*(?:[-*+]|\d+\.)?\s*\*\*([^*]+?)\*\*/;
  for (const rawLine of text.split("\n")) {
    const heading = headingRe.exec(rawLine);
    if (heading) {
      const a = normalize(heading[1] ?? "");
      if (a) anchors.add(a);
      continue;
    }
    const bold = boldLabelRe.exec(rawLine);
    if (bold) {
      const a = normalize(bold[1] ?? "");
      if (a) anchors.add(a);
    }
  }
  return anchors;
}

/**
 * Does `cite` resolve to some anchor? A match is an exact equality or a
 * whole-word prefix in either direction: the citation may over-capture trailing
 * prose (`"The CI gate has the full …"` → heading `"The CI gate"`), or it may
 * name only the leading part of a longer heading (`"Component-level dynamic
 * import"` → heading `"Component-level dynamic import (React.lazy)"`).
 */
function anchorMatches(cite: string, anchors: Set<string>): boolean {
  if (anchors.has(cite)) return true;
  for (const a of anchors) {
    if (cite.startsWith(`${a} `)) return true;
    if (a.startsWith(`${cite} `)) return true;
  }
  return false;
}

const errors: string[] = [];
const warnings: string[] = [];
const anchorCache = new Map<string, Set<string> | null>();
let citationCount = 0;
let docLinkCount = 0;

const codeFiles: string[] = [];
for (const dir of CODE_DIRS) walk(resolve(ROOT, dir), codeFiles);
for (const doc of ROOT_DOCS) codeFiles.push(resolve(ROOT, doc));

for (const file of codeFiles) {
  if (file === SELF) continue;
  const source = readFileSync(file, "utf8");
  const where = relative(ROOT, file).replaceAll("\\", "/");

  // Link-form citations first, recording the span each one occupies. A link
  // whose label happens to include the filename
  // (`[docs/infra.md § Health](../infra.md#health)`) matches BOTH
  // patterns, so the bare-form pass below skips anything already covered —
  // otherwise it double-counts and reports the same problem twice.
  const found: Array<{ docRel: string; cite: string }> = [];
  const linkSpans: Array<[number, number]> = [];
  for (const match of source.matchAll(LINK_CITATION_RE)) {
    linkSpans.push([match.index, match.index + match[0].length]);
    found.push({ docRel: match[3] ?? "", cite: match[2] ?? "" });
  }
  for (const match of source.matchAll(CITATION_RE)) {
    if (linkSpans.some(([start, end]) => match.index >= start && match.index < end)) continue;
    found.push({ docRel: match[1] ?? "", cite: match[2] ?? "" });
  }

  for (const raw of found) {
    citationCount++;
    const docRel = raw.docRel;
    const cite = normalize(raw.cite);

    if (cite.length === 0) {
      errors.push(`${where}: citation "${docRel} §" has no section text.`);
      continue;
    }

    // A doc citing a sibling writes a path relative to itself
    // (`backup-and-restore.md` from inside `docs/operations/`), while code
    // cites repo-relative (`docs/infra.md`). Try the citing file's own
    // directory first, then the repo root.
    const cacheKey = `${dirname(file)} ${docRel}`;
    let anchors = anchorCache.get(cacheKey);
    if (anchors === undefined) {
      anchors = null;
      for (const candidate of [resolve(dirname(file), docRel), resolve(ROOT, docRel)]) {
        try {
          anchors = collectAnchors(candidate);
          break;
        } catch {
          // try the next candidate
        }
      }
      anchorCache.set(cacheKey, anchors);
    }

    if (anchors === null) {
      // Deleting a whole docs tree must not turn CI red across a dozen source
      // files that still mention it.
      //
      // But "the whole directory is gone" and "someone typo'd or renamed a
      // filename" are different events, and collapsing both into a warning threw
      // away the filename check entirely: `docs/infranotes.md § Foo`
      // would sail through. Distinguish them by the DIRECTORY. Directory gone →
      // deliberate teardown, warn. Directory present but file missing → real
      // drift, and fatal like a renamed heading.
      const dirExists = [
        dirname(resolve(dirname(file), docRel)),
        dirname(resolve(ROOT, docRel)),
      ].some((dir) => existsSync(dir));
      if (dirExists) {
        errors.push(
          `${where}: cited doc "${docRel}" does not exist, though its directory does — ` +
            `renamed or misspelled? (If the doc was deliberately removed, drop the citation.)`,
        );
      } else {
        warnings.push(`${where}: cited doc "${docRel}" does not exist on disk (citation skipped).`);
      }
      continue;
    }

    if (!anchorMatches(cite, anchors)) {
      errors.push(
        `${where}: "${docRel} § ${raw.cite.trim()}" — no matching section heading in ${docRel}.`,
      );
    }
  }

  // Repo-relative links (any target) and their anchors.
  if (!isDocLinkFile(where)) continue;
  for (const link of extractDocLinks(source)) {
    docLinkCount++;
    const shown = `${link.target}${link.anchor === null ? "" : `#${link.anchor}`}`;
    const absolute = link.target === "" ? file : resolve(dirname(file), link.target);
    if (!existsSync(absolute)) {
      errors.push(
        `${where}:${link.line}: link target "${link.target}" does not exist — renamed, ` +
          `moved or misspelled? (If it was deliberately removed, drop the link.)`,
      );
      continue;
    }
    if (link.anchor !== null && link.anchor !== "" && absolute.endsWith(".md")) {
      if (!anchorsOf(absolute).has(link.anchor)) {
        errors.push(
          `${where}:${link.line}: link "${shown}" names no heading anchor in ` +
            `${relative(ROOT, absolute).replaceAll("\\", "/")}.`,
        );
      }
    }
  }
}

if (warnings.length > 0) {
  console.warn("Doc citations pointing at missing files (not fatal):\n");
  for (const w of warnings) console.warn(`  ! ${w}`);
  console.warn("");
}

if (errors.length > 0) {
  console.error("Doc-citation drift detected:\n");
  for (const e of errors) console.error(`  • ${e}`);
  console.error(
    "\nEither fix the `<file>.md § <section>` citation in the code to name a real\n" +
      "heading, or restore/rename the heading in the cited doc so the two agree. For a link\n" +
      "target, point it at the file's new path, or drop the link if the doc is gone for good.",
  );
  process.exit(1);
}

console.log(
  `Doc citations OK — ${citationCount} \`<doc>.md § <section>\` reference(s) ` +
    `across ${codeFiles.length} code and doc file(s) all resolve to a real section, ` +
    `and ${docLinkCount} repo-relative link(s) all resolve to a file (and heading anchor) on disk` +
    `${warnings.length > 0 ? ` (${warnings.length} skipped: target absent)` : ""}.`,
);
