/**
 * Minimal POSIX ustar writer for build contexts (no dependency). Output is
 * deterministic: callers pass entries in their final order, and every header
 * has mtime 0, uid/gid 0 and empty owner names. Only directories, regular
 * files and contained symlinks are written; anything a guest extractor could
 * be tricked by (absolute names, `..`, control characters, escaping link
 * targets) is refused here, before any byte is produced.
 */

export const USTAR_BLOCK = 512;
/** 11 octal digits in the size field. */
const USTAR_MAX_FILE_BYTES = 0o77777777777;

export type UstarEntry =
  | { type: "directory"; path: string; mode: number }
  | { type: "file"; path: string; mode: number; size: number }
  | { type: "symlink"; path: string; target: string };

export class UstarPathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UstarPathError";
  }
}

const encoder = new TextEncoder();

/**
 * A context-relative entry name: non-empty segments, no `.`/`..`, no
 * leading `/`, no NUL or control characters. Returns the segments.
 */
export function ustarPathSegments(path: string): string[] {
  if (path.length === 0) throw new UstarPathError("Empty archive path.");
  if (path.startsWith("/")) throw new UstarPathError(`Absolute archive path "${path}".`);
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control bytes are refused, not matched away
  if (/[\x00-\x1f\x7f]/.test(path))
    throw new UstarPathError(`Archive path ${JSON.stringify(path)} has control characters.`);
  const segments = path.split("/");
  for (const segment of segments) {
    if (segment === "" || segment === "." || segment === "..")
      throw new UstarPathError(`Archive path "${path}" is not normalized.`);
  }
  return segments;
}

/**
 * A symlink target must be relative and stay inside the archive root when
 * resolved from the link's own directory.
 */
export function assertContainedLinkTarget(path: string, target: string): void {
  if (target.length === 0 || target.startsWith("/"))
    throw new UstarPathError(`Symlink "${path}" must point inside the context.`);
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control bytes are refused, not matched away
  if (/[\x00-\x1f\x7f]/.test(target))
    throw new UstarPathError(`Symlink "${path}" target has control characters.`);
  const stack = ustarPathSegments(path).slice(0, -1);
  for (const segment of target.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (stack.length === 0)
        throw new UstarPathError(`Symlink "${path}" must point inside the context.`);
      stack.pop();
    } else stack.push(segment);
  }
}

function writeField(header: Uint8Array, offset: number, length: number, bytes: Uint8Array) {
  if (bytes.length > length) throw new UstarPathError("Archive header field overflow.");
  header.set(bytes, offset);
}

function octal(value: number, length: number): Uint8Array {
  // length-1 digits, NUL terminated.
  const text = value.toString(8).padStart(length - 1, "0");
  if (text.length > length - 1) throw new UstarPathError("Archive numeric field overflow.");
  return encoder.encode(`${text}\0`);
}

/** Split a name over `prefix` (155) and `name` (100) at a `/`. */
function splitName(name: string): { prefix: Uint8Array; name: Uint8Array } {
  const bytes = encoder.encode(name);
  if (bytes.length <= 100) return { prefix: new Uint8Array(), name: bytes };
  for (let i = bytes.length - 1; i > 0; i -= 1) {
    if (bytes[i] !== 0x2f) continue;
    const prefix = bytes.subarray(0, i);
    const rest = bytes.subarray(i + 1);
    if (prefix.length <= 155 && rest.length > 0 && rest.length <= 100)
      return { prefix, name: rest };
  }
  throw new UstarPathError(`Archive path "${name}" is too long for ustar.`);
}

/** One 512-byte header block. */
export function ustarHeader(entry: UstarEntry): Uint8Array {
  ustarPathSegments(entry.path);
  const header = new Uint8Array(USTAR_BLOCK);
  const stored = entry.type === "directory" ? `${entry.path}/` : entry.path;
  const { prefix, name } = splitName(stored);
  writeField(header, 0, 100, name);
  const mode = entry.type === "symlink" ? 0o777 : entry.mode & 0o777;
  writeField(header, 100, 8, octal(mode, 8));
  writeField(header, 108, 8, octal(0, 8));
  writeField(header, 116, 8, octal(0, 8));
  const size = entry.type === "file" ? entry.size : 0;
  if (!Number.isSafeInteger(size) || size < 0 || size > USTAR_MAX_FILE_BYTES)
    throw new UstarPathError(`File "${entry.path}" is too large for ustar.`);
  writeField(header, 124, 12, octal(size, 12));
  writeField(header, 136, 12, octal(0, 12));
  header.fill(0x20, 148, 156); // checksum placeholder: spaces
  header[156] = entry.type === "file" ? 0x30 : entry.type === "symlink" ? 0x32 : 0x35;
  if (entry.type === "symlink") {
    assertContainedLinkTarget(entry.path, entry.target);
    const target = encoder.encode(entry.target);
    if (target.length > 100)
      throw new UstarPathError(`Symlink "${entry.path}" target is too long for ustar.`);
    writeField(header, 157, 100, target);
  }
  writeField(header, 257, 6, encoder.encode("ustar\0"));
  writeField(header, 263, 2, encoder.encode("00"));
  writeField(header, 329, 8, octal(0, 8));
  writeField(header, 337, 8, octal(0, 8));
  writeField(header, 345, 155, prefix);
  let sum = 0;
  for (const byte of header) sum += byte;
  writeField(header, 148, 8, encoder.encode(`${sum.toString(8).padStart(6, "0")}\0 `));
  return header;
}

/** Zero padding after `size` bytes of file data. */
export function ustarPadding(size: number): Uint8Array {
  const remainder = size % USTAR_BLOCK;
  return new Uint8Array(remainder === 0 ? 0 : USTAR_BLOCK - remainder);
}

/** End-of-archive marker: two zero blocks. */
export function ustarTrailer(): Uint8Array {
  return new Uint8Array(USTAR_BLOCK * 2);
}
