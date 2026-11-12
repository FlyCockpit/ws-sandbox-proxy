import { LOGIN_DEFINITION_LIMITS } from "./limits";
import { compareCodePoints, isWellFormed, toHex, utf8, utf8Length } from "./text";

/**
 * Canonical JSON v1, shared byte for byte with `crates/login-definition`:
 *
 * - object keys sorted by Unicode code point (UTF-8 byte order), no whitespace;
 * - strings escaped exactly as ECMAScript `JSON.stringify` escapes them (`\"`,
 *   `\\`, `\b \f \n \r \t`, other C0 controls as lowercase `\u00xx`, nothing
 *   else), encoded as UTF-8; a lone surrogate is refused;
 * - numbers are integers in the IEEE-754 safe range written in plain decimal
 *   (`-0` is `0`); any fractional or unsafe number is refused;
 * - at most `documentMaxDepth` nested arrays/objects;
 * - at most `documentMaxBytes` bytes of output. The budget is enforced while
 *   writing (and before sorting an object's keys or escaping a string), so an
 *   oversized document is refused after at most that much work.
 */
export class CanonicalJsonError extends Error {
  constructor(
    readonly detail: string,
    readonly path: string,
  ) {
    super(`${path || "(document)"}: ${detail}`);
    this.name = "CanonicalJsonError";
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function joinPath(path: string, key: string | number): string {
  return typeof key === "number" ? `${path}[${key}]` : path ? `${path}.${key}` : key;
}

export type CanonicalJsonLimits = { maxDepth?: number; maxBytes?: number };

export function canonicalJson(
  value: unknown,
  {
    maxDepth = LOGIN_DEFINITION_LIMITS.documentMaxDepth,
    maxBytes = LOGIN_DEFINITION_LIMITS.documentMaxBytes,
  }: CanonicalJsonLimits = {},
): string {
  const out: string[] = [];
  let size = 0;
  /** Refuses before work whose output would need at least `bytes` more bytes. */
  const reserve = (bytes: number) => {
    if (size + bytes > maxBytes) {
      throw new CanonicalJsonError(`canonical JSON exceeds ${maxBytes} bytes`, "");
    }
  };
  const emit = (text: string, bytes: number) => {
    reserve(bytes);
    size += bytes;
    out.push(text);
  };
  const ascii = (text: string) => emit(text, text.length);
  const writeString = (text: string, path: string) => {
    // UTF-8 bytes >= UTF-16 units, and escaping only grows the text.
    reserve(text.length + 2);
    if (!isWellFormed(text)) throw new CanonicalJsonError("string has a lone surrogate", path);
    const quoted = JSON.stringify(text);
    emit(quoted, utf8Length(quoted));
  };
  const write = (node: unknown, path: string, depth: number): void => {
    if (node === null) {
      ascii("null");
    } else if (typeof node === "boolean") {
      ascii(node ? "true" : "false");
    } else if (typeof node === "number") {
      if (!Number.isSafeInteger(node)) {
        throw new CanonicalJsonError("numbers must be safe integers", path);
      }
      ascii(Object.is(node, -0) ? "0" : String(node));
    } else if (typeof node === "string") {
      writeString(node, path);
    } else if (Array.isArray(node)) {
      if (depth + 1 > maxDepth) throw new CanonicalJsonError("nesting is too deep", path);
      // `[` + n values of at least one byte + n - 1 commas + `]`.
      reserve(2 * node.length + 1);
      ascii("[");
      for (let i = 0; i < node.length; i++) {
        if (i > 0) ascii(",");
        if (!(i in node)) throw new CanonicalJsonError("array has a hole", joinPath(path, i));
        write(node[i], joinPath(path, i), depth + 1);
      }
      ascii("]");
    } else if (isPlainObject(node)) {
      if (depth + 1 > maxDepth) throw new CanonicalJsonError("nesting is too deep", path);
      const keys = Object.keys(node);
      // `{` + n members of at least `"":0` (4 bytes) + n - 1 commas + `}`.
      reserve(5 * keys.length + 1);
      keys.sort(compareCodePoints);
      ascii("{");
      keys.forEach((key, i) => {
        if (i > 0) ascii(",");
        writeString(key, joinPath(path, key));
        ascii(":");
        write(node[key], joinPath(path, key), depth + 1);
      });
      ascii("}");
    } else {
      throw new CanonicalJsonError(`unsupported JSON value (${typeof node})`, path);
    }
  };
  write(value, "", 0);
  return out.join("");
}

export function canonicalJsonBytes(value: unknown, limits?: CanonicalJsonLimits): Uint8Array {
  return utf8(canonicalJson(value, limits));
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>);
  return new Uint8Array(digest);
}

/**
 * Definition digest: lowercase hex SHA-256 of the canonical JSON of the stored
 * document exactly as submitted (`x-*` extensions included, defaults not
 * filled in). Throws `CanonicalJsonError` past the document bounds.
 */
export async function definitionDigestHex(document: unknown): Promise<string> {
  return canonicalDigestHex(canonicalJsonBytes(document));
}

/** The digest of canonical bytes already produced (e.g. `ParsedDefinition.canonical`). */
export async function canonicalDigestHex(canonical: Uint8Array): Promise<string> {
  return toHex(await sha256(canonical));
}
