/**
 * Canonical JSON in the RFC 8785 style for the values a recipe can hold:
 * object keys sorted by UTF-16 code units, no insignificant whitespace,
 * strings escaped by `JSON.stringify`, integers only, `undefined` members
 * omitted. Anything else (floats, non-plain objects) is refused so a digest
 * can never depend on an engine's number formatting.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value)) throw new TypeError("canonical JSON allows integers only");
      return String(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
      const prototype: unknown = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null)
        throw new TypeError("canonical JSON allows plain objects only");
      const record = value as Record<string, unknown>;
      const members = Object.keys(record)
        .filter((key) => record[key] !== undefined)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
      return `{${members.join(",")}}`;
    }
    default:
      throw new TypeError(`canonical JSON cannot encode ${typeof value}`);
  }
}

const encoder = new TextEncoder();

export function utf8Bytes(text: string): number {
  return encoder.encode(text).byteLength;
}

/** Lowercase hex SHA-256 of the UTF-8 text (Web Crypto: Node 20+ and browsers). */
export async function sha256Hex(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", encoder.encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
