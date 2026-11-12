/**
 * Repository-relative link checking for the product docs (C56).
 *
 * Pure helpers used by `scripts/check-doc-citations.ts`: extract every
 * repo-relative link target from a markdown file (markdown links, images and
 * HTML `href`/`src` attributes, outside code), and compute the GitHub heading
 * anchors of a markdown file so `file.md#section` and `#section` links can be
 * resolved. Absolute URLs (`https:`, `mailto:` …) and site paths (`/v1/…`)
 * are out of scope: they are not files in this repository.
 */

export type DocLink = { target: string; anchor: string | null; line: number };

/**
 * Blank fenced blocks and inline code spans, preserving offsets and newlines,
 * so quoted links inside code are never treated as links.
 */
function maskMarkdownCode(source: string): string {
  let fenced = false;
  return source
    .split("\n")
    .map((line) => {
      if (/^\s*(?:```|~~~)/.test(line)) {
        fenced = !fenced;
        return " ".repeat(line.length);
      }
      if (fenced) return " ".repeat(line.length);
      return line.replace(/(`+)(.+?)\1/g, (match) => " ".repeat(match.length));
    })
    .join("\n");
}

const MARKDOWN_LINK_RE = /\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g;
const HTML_LINK_RE = /\b(?:href|src)="([^"]+)"/g;

/** True for targets that name a file or anchor in this repository. */
export function isRepoRelative(target: string): boolean {
  if (target.length === 0) return false;
  if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return false; // https:, mailto:, data: …
  if (target.startsWith("//") || target.startsWith("/")) return false; // site paths
  return true;
}

/** Repo-relative links in a markdown source, code masked out. */
export function extractDocLinks(source: string): DocLink[] {
  const masked = maskMarkdownCode(source);
  const links: DocLink[] = [];
  const lineOf = (index: number) => masked.slice(0, index).split("\n").length;
  for (const re of [MARKDOWN_LINK_RE, HTML_LINK_RE]) {
    for (const match of masked.matchAll(re)) {
      const raw = match[1] ?? "";
      if (!isRepoRelative(raw)) continue;
      const hash = raw.indexOf("#");
      const target = hash === -1 ? raw : raw.slice(0, hash);
      const anchor = hash === -1 ? null : decodeURIComponent(raw.slice(hash + 1));
      links.push({ target: decodeURIComponent(target), anchor, line: lineOf(match.index) });
    }
  }
  return links.sort((a, b) => a.line - b.line);
}

/**
 * GitHub's heading slug: inline markup removed, lowercased, every character
 * that is not a letter, number, space, `-` or `_` dropped, spaces to `-`.
 */
export function githubSlug(heading: string): string {
  return heading
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1") // links and images keep their text
    .replace(/<[^>]+>/g, "")
    .replace(/[`*]/g, "")
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\p{M} _-]/gu, "")
    .replace(/ /g, "-");
}

/** Every anchor a markdown file defines: heading slugs (deduplicated GitHub-style) and HTML ids. */
export function markdownAnchors(source: string): Set<string> {
  const anchors = new Set<string>();
  const seen = new Map<string, number>();
  let fenced = false;
  for (const line of source.split("\n")) {
    if (/^\s*(?:```|~~~)/.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    const heading = /^#{1,6}\s+(.+?)\s*#*\s*$/.exec(line);
    if (heading) {
      const base = githubSlug(heading[1] ?? "");
      const count = seen.get(base) ?? 0;
      seen.set(base, count + 1);
      anchors.add(count === 0 ? base : `${base}-${count}`);
    }
    for (const id of line.matchAll(/<a\s+(?:id|name)="([^"]+)"/g)) anchors.add(id[1] ?? "");
  }
  return anchors;
}
