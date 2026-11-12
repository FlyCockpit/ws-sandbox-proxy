/**
 * True when `source`'s UTF-8 encoding (as TextEncoder produces it: a lone
 * surrogate becomes U+FFFD, three bytes) is longer than `maxBytes`. No copy:
 * a string whose every code unit could take three bytes and still fit skips
 * the walk, and the walk stops at the first byte past the bound.
 */
function utf8LengthExceeds(source: string, maxBytes: number): boolean {
  if (source.length > maxBytes) return true;
  if (source.length * 3 <= maxBytes) return false;
  let bytes = 0;
  for (let i = 0; i < source.length; i++) {
    const unit = source.charCodeAt(i);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = source.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i++;
      } else bytes += 3;
    } else bytes += 3;
    if (bytes > maxBytes) return true;
  }
  return false;
}

/**
 * Scan bounded raw JSON before object construction. Only decoded property names
 * are retained; value tokens are skipped. This also walks RPC batch envelopes.
 * Normal JSON decoding remains responsible for syntax/type validation.
 */
function assertUniqueMapKeys(
  source: string,
  maxBytes: number,
  field: string,
  rootMap = false,
): void {
  const invalid = () => new Error(`sandbox.${field === "envs" ? "env" : "metadata"}_invalid`);
  if (utf8LengthExceeds(source, maxBytes)) throw invalid();
  let at = 0;
  const space = () => {
    while (at < source.length && " \r\n\t".includes(source[at]!)) at++;
  };
  const string = (decode: boolean): string => {
    const start = at++;
    while (at < source.length) {
      const ch = source[at++];
      if (ch === "\\") at++;
      else if (ch === '"') {
        if (!decode) return "";
        try {
          const key: unknown = JSON.parse(source.slice(start, at));
          if (typeof key === "string") return key;
        } catch {}
        throw invalid();
      }
    }
    throw invalid();
  };
  const value = (depth: number, mapObject = false): void => {
    if (depth > 128) throw invalid();
    space();
    const ch = source[at];
    if (ch === '"') {
      string(false);
      return;
    }
    if (ch === "{") {
      at++;
      space();
      const keys = mapObject ? new Set<string>() : undefined;
      // Duplicate map containers must not conceal a duplicate-bearing map.
      let sawMap = false;
      if (source[at] === "}") {
        at++;
        return;
      }
      for (;;) {
        space();
        if (source[at] !== '"') throw invalid();
        const key = string(true);
        if (keys?.has(key) || (key === field && sawMap)) throw invalid();
        keys?.add(key);
        if (key === field) sawMap = true;
        space();
        if (source[at++] !== ":") throw invalid();
        value(depth + 1, key === field);
        space();
        const separator = source[at++];
        if (separator === "}") return;
        if (separator !== ",") throw invalid();
      }
    }
    if (ch === "[") {
      at++;
      space();
      if (source[at] === "]") {
        at++;
        return;
      }
      for (;;) {
        value(depth + 1);
        space();
        const separator = source[at++];
        if (separator === "]") return;
        if (separator !== ",") throw invalid();
      }
    }
    const start = at;
    while (at < source.length && !",]} \r\n\t".includes(source[at]!)) at++;
    if (at === start) throw invalid();
  };
  value(0, rootMap);
  space();
  if (at !== source.length) throw invalid();
}

export function assertUniqueEnvKeys(source: string, maxBytes: number): void {
  assertUniqueMapKeys(source, maxBytes, "envs");
}

/** Reject duplicate decoded keys before JSON.parse can discard them. */
export function assertUniqueMetadataKeys(source: string, maxBytes: number, rootMap = false): void {
  assertUniqueMapKeys(source, maxBytes, "metadata", rootMap);
}

/** Shared raw HTTP/RPC chokepoint; scan before either public map loses duplicate keys. */
export function assertUniqueInputMapKeys(source: string, maxBytes: number): void {
  assertUniqueEnvKeys(source, maxBytes);
  assertUniqueMetadataKeys(source, maxBytes);
}
