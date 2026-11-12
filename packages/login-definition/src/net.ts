import { LOGIN_DEFINITION_LIMITS as L } from "./limits";
import { utf8, utf8Length } from "./text";

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * An exact, lowercase ASCII DNS name with at least two labels whose last label
 * starts with a letter (so no IPv4 literal or numeric look-alike such as
 * `0x7f.1` passes). Internationalized names are written in punycode.
 */
export function dnsNameProblem(name: string): string | null {
  if (name.length === 0) return "name is empty";
  if (utf8Length(name) > L.dnsNameMaxBytes) return `name exceeds ${L.dnsNameMaxBytes} bytes`;
  const labels = name.split(".");
  if (labels.length < 2) return "name needs at least two labels";
  for (const label of labels) {
    if (!LABEL.test(label)) return "name must be lowercase ASCII letters, digits and hyphens";
  }
  if (!/^[a-z]/.test(labels[labels.length - 1] ?? "")) {
    return "the last label must start with a letter (IP literals are not allowed)";
  }
  return null;
}

const UNRESERVED = /^[A-Za-z0-9\-._~]$/;
const SEGMENT_CHAR = /^[A-Za-z0-9\-._~!$&'()*+,;=]$/;

function segmentProblem(segment: string): string | null {
  if (segment === "") return "basepath has an empty segment";
  if (segment === "." || segment === "..") return "basepath has a dot segment";
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i] ?? "";
    if (ch === "%") {
      const hex = segment.slice(i + 1, i + 3);
      if (!/^[0-9A-F]{2}$/.test(hex)) {
        return "basepath percent-escapes must be two uppercase hex digits";
      }
      const byte = Number.parseInt(hex, 16);
      if (UNRESERVED.test(String.fromCharCode(byte))) {
        return "basepath must not percent-encode an unreserved character";
      }
      if (byte === 0x2f || byte === 0x5c || byte < 0x20 || byte === 0x7f) {
        return "basepath must not percent-encode a slash, backslash or control byte";
      }
      i += 2;
    } else if (!SEGMENT_CHAR.test(ch)) {
      return "basepath contains a character outside the allowed set";
    }
  }
  return null;
}

export type Upstream = { host: string; port: number | null; basepath: string };

/**
 * Parses a proxy upstream written in its one normalized form:
 * `https://host[:port][/basepath]`, lowercase scheme and host, no userinfo,
 * query or fragment, no trailing slash, port without leading zeros.
 */
export function parseUpstream(text: string): Upstream | string {
  if (utf8Length(text) > L.proxyUpstreamMaxBytes) {
    return `upstream exceeds ${L.proxyUpstreamMaxBytes} bytes`;
  }
  const scheme = "https://";
  if (!text.startsWith(scheme)) return "upstream must start with https://";
  if (text.includes("?") || text.includes("#")) return "upstream must not have a query or fragment";
  const rest = text.slice(scheme.length);
  const slash = rest.indexOf("/");
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  const basepath = slash === -1 ? "" : rest.slice(slash);
  if (authority.includes("@")) return "upstream must not have userinfo";
  if (authority.includes("[")) return "upstream must be a DNS name, not an IP literal";
  const parts = authority.split(":");
  if (parts.length > 2) return "upstream authority is malformed";
  const host = parts[0] ?? "";
  const hostProblem = dnsNameProblem(host);
  if (hostProblem) return `upstream host: ${hostProblem}`;
  let port: number | null = null;
  if (parts.length === 2) {
    const raw = parts[1] ?? "";
    if (!/^[1-9][0-9]{0,4}$/.test(raw) || Number(raw) > 65535) {
      return "upstream port must be 1-65535 without leading zeros";
    }
    port = Number(raw);
  }
  if (basepath !== "") {
    if (utf8Length(basepath) > L.proxyBasepathMaxBytes) {
      return `upstream basepath exceeds ${L.proxyBasepathMaxBytes} bytes`;
    }
    if (basepath.endsWith("/")) return "upstream basepath must not end with a slash";
    for (const segment of basepath.slice(1).split("/")) {
      const problem = segmentProblem(segment);
      if (problem) return problem;
    }
  }
  return { host, port, basepath };
}

const TCHAR = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const FORBIDDEN_HEADERS = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "upgrade",
  "te",
  "trailer",
  "keep-alive",
  "expect",
  "forwarded",
  "via",
]);
const FORBIDDEN_HEADER_PREFIXES = ["proxy-", "x-forwarded-"];

export function headerNameProblem(name: string): string | null {
  if (name.length === 0) return "header is empty";
  if (utf8Length(name) > L.proxyHeaderMaxBytes) {
    return `header exceeds ${L.proxyHeaderMaxBytes} bytes`;
  }
  if (!TCHAR.test(name)) return "header must be an HTTP token";
  const lower = name.toLowerCase();
  if (FORBIDDEN_HEADERS.has(lower) || FORBIDDEN_HEADER_PREFIXES.some((p) => lower.startsWith(p))) {
    return "header is reserved for the proxy";
  }
  return null;
}

const VALUE_PLACEHOLDER = "{value}";

/** RFC 9110 field-value byte: visible ASCII, obs-text, SP or HTAB. */
function isFieldValueByte(byte: number): boolean {
  return (byte >= 0x21 && byte <= 0x7e) || byte >= 0x80 || byte === 0x20 || byte === 0x09;
}

const isWhitespace = (byte: number | undefined) => byte === 0x20 || byte === 0x09;

export function formatProblem(format: string): string | null {
  if (utf8Length(format) > L.proxyFormatMaxBytes) {
    return `format exceeds ${L.proxyFormatMaxBytes} bytes`;
  }
  if (format.split(VALUE_PLACEHOLDER).length !== 2) {
    return "format must contain {value} exactly once";
  }
  const bytes = utf8(format);
  if (isWhitespace(bytes[0]) || isWhitespace(bytes[bytes.length - 1])) {
    return "format must not start or end with whitespace";
  }
  for (const byte of utf8(format.replace(VALUE_PLACEHOLDER, ""))) {
    if (!isFieldValueByte(byte)) return "format contains a byte that is not allowed in a header";
  }
  return null;
}

/**
 * Checks that `format(value)` is an RFC 9110 §5.5 field-value: 1 to
 * `headerValueMaxBytes` bytes of visible ASCII, obs-text, SP or HTAB, with no
 * leading or trailing whitespace. `format` must already be valid. The value is
 * inspected in place, never concatenated into a new buffer; callers report the
 * entry name on failure, never the value.
 */
export function headerValueAcceptable(format: string, value: Uint8Array): boolean {
  const [prefix = "", suffix = ""] = format.split(VALUE_PLACEHOLDER);
  const head = utf8(prefix);
  const tail = utf8(suffix);
  const total = head.length + value.length + tail.length;
  if (total === 0 || total > L.headerValueMaxBytes) return false;
  const byteAt = (i: number) =>
    i < head.length
      ? head[i]
      : i < head.length + value.length
        ? value[i - head.length]
        : tail[i - head.length - value.length];
  if (isWhitespace(byteAt(0)) || isWhitespace(byteAt(total - 1))) return false;
  for (const part of [head, value, tail]) {
    for (const byte of part) if (!isFieldValueByte(byte)) return false;
  }
  return true;
}

/** Env values for every delivery: at most `envValueMaxBytes` bytes, no NUL. */
export function envValueAcceptable(value: Uint8Array): boolean {
  return value.length <= L.envValueMaxBytes && !value.includes(0);
}
