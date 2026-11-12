import { utf8Length } from "./text";

/**
 * Home-relative credential paths. Returns `null` when `path` is acceptable or
 * a short reason. Rules (identical in Rust, `paths.rs`):
 * relative, `/`-separated, no empty, `.` or `..` segment, no `\`, `:`, NUL or
 * ASCII control byte, at most `maxBytes` UTF-8 bytes, and the first segment
 * never starts with `.wssp` (daemon-owned state). No segment may start with
 * `.wssp-cred-` (credential restore staging).
 */
export function pathProblem(path: string, maxBytes: number): string | null {
  if (path.length === 0) return "path is empty";
  if (utf8Length(path) > maxBytes) return `path exceeds ${maxBytes} bytes`;
  for (let i = 0; i < path.length; i++) {
    const unit = path.charCodeAt(i);
    if (unit < 0x20 || unit === 0x7f) return "path contains a control byte";
    if (unit === 0x5c) return "path contains a backslash";
    if (unit === 0x3a) return "path contains a colon";
  }
  if (path.startsWith("/")) return "path must be relative to the home directory";
  const segments = path.split("/");
  for (const segment of segments) {
    if (segment === "") return "path has an empty segment";
    if (segment === "." || segment === "..") return "path has a dot segment";
    if (segment.startsWith(".wssp-cred-")) return "credential staging paths are reserved";
  }
  if ((segments[0] ?? "").startsWith(".wssp")) return "paths under .wssp* are reserved";
  return null;
}

/** `path` equals `ancestor` or lies below it. */
export function pathWithin(path: string, ancestor: string): boolean {
  return path === ancestor || path.startsWith(`${ancestor}/`);
}

/** `path` lies strictly below `ancestor`. */
export function pathBelow(path: string, ancestor: string): boolean {
  return path.startsWith(`${ancestor}/`);
}

/** Two paths overlap when one equals or contains the other. */
export function pathsOverlap(a: string, b: string): boolean {
  return pathWithin(a, b) || pathWithin(b, a);
}
