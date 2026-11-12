/**
 * Strict IPv4/IPv6/CIDR parsing shared by the egress policy and the webhook
 * destination policy. Moved out of `egress.ts` without behaviour change: the
 * egress tests still exercise every path through `normalizeEgressPolicy`.
 *
 * Only canonical dotted-quad IPv4 (no leading zeros, no shorthand) and RFC 4291
 * IPv6 text (no zone id) parse. Hostnames that merely look numeric must be
 * canonicalized by WHATWG URL first.
 */

/** Thrown by `parseCidr`; callers map it to their own typed error. */
export class IpParseError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "IpParseError";
  }
}

function fail(reason: string): never {
  throw new IpParseError(reason);
}

// --- IPv4 -----------------------------------------------------------------

export function parseIpv4(input: string): number[] | null {
  const parts = input.split(".");
  if (parts.length !== 4) return null;
  const bytes: number[] = [];
  for (const part of parts) {
    // No leading zeros: "01" is an ambiguous (octal historical) octet.
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    bytes.push(value);
  }
  return bytes;
}

// --- IPv6 -----------------------------------------------------------------

export function parseIpv6(input: string): number[] | null {
  if (input.length === 0 || input.includes("%")) return null;
  let s = input;
  if (s.includes(".")) {
    const at = s.lastIndexOf(":");
    if (at < 0) return null;
    const bytes = parseIpv4(s.slice(at + 1));
    if (!bytes) return null;
    const hi = (((bytes[0] as number) << 8) | (bytes[1] as number)).toString(16);
    const lo = (((bytes[2] as number) << 8) | (bytes[3] as number)).toString(16);
    s = `${s.slice(0, at)}:${hi}:${lo}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const groupOk = (group: string) => /^[0-9a-fA-F]{1,4}$/.test(group);
  const left = halves[0] === "" ? [] : (halves[0] as string).split(":");
  if (halves.length === 1) {
    if (left.length !== 8 || !left.every(groupOk)) return null;
    return left.map((group) => Number.parseInt(group, 16));
  }
  const right = halves[1] === "" ? [] : (halves[1] as string).split(":");
  if (![...left, ...right].every(groupOk)) return null;
  // "::" must compress at least one zero group.
  if (left.length + right.length > 7) return null;
  const missing = 8 - left.length - right.length;
  return [
    ...left.map((group) => Number.parseInt(group, 16)),
    ...Array.from({ length: missing }, () => 0),
    ...right.map((group) => Number.parseInt(group, 16)),
  ];
}

/** RFC 5952: lowercase, no leading zeros, longest (first) zero run ≥ 2 as "::". */
export function formatIpv6(groups: number[]): string {
  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  let runLength = 0;
  for (let i = 0; i <= 8; i += 1) {
    if (i < 8 && groups[i] === 0) {
      if (runStart < 0) {
        runStart = i;
        runLength = 0;
      }
      runLength += 1;
      if (runLength > bestLength) {
        bestStart = runStart;
        bestLength = runLength;
      }
    } else {
      runStart = -1;
    }
  }
  if (bestLength < 2) {
    bestStart = -1;
    bestLength = 0;
  }
  const parts: string[] = [];
  let i = 0;
  while (i < 8) {
    if (i === bestStart) {
      if (i === 0) parts.push("");
      parts.push("");
      i += bestLength;
      if (i >= 8) parts.push("");
      continue;
    }
    parts.push((groups[i] as number).toString(16));
    i += 1;
  }
  return parts.join(":");
}

// --- CIDRs ----------------------------------------------------------------

export type ParsedCidr = {
  family: 4 | 6;
  /** 16-bit groups: two for IPv4 (32 bits), eight for IPv6 (128 bits). */
  groups: number[];
  prefix: number;
  text: string;
};

export function maskBits(groups: number[], prefix: number): number[] {
  const masked = [...groups];
  for (let bit = prefix; bit < groups.length * 16; bit += 1) {
    const index = Math.floor(bit / 16);
    masked[index] = (masked[index] as number) & ~(0x8000 >> (bit % 16));
  }
  return masked;
}

export function cidrFromV4(bytes: number[], prefix: number): ParsedCidr {
  const asGroups = [
    ((bytes[0] as number) << 8) | (bytes[1] as number),
    ((bytes[2] as number) << 8) | (bytes[3] as number),
  ];
  const masked = maskBits(asGroups, prefix);
  const text = `${(masked[0] as number) >> 8}.${(masked[0] as number) & 0xff}.${(masked[1] as number) >> 8}.${(masked[1] as number) & 0xff}/${prefix}`;
  return { family: 4, groups: masked, prefix, text };
}

export function cidrFromV6(groups: number[], prefix: number): ParsedCidr {
  const masked = maskBits(groups, prefix);
  return { family: 6, groups: masked, prefix, text: `${formatIpv6(masked)}/${prefix}` };
}

/** Strict CIDR parse. Throws `IpParseError` with a human-readable reason. */
export function parseCidr(raw: string): ParsedCidr {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control bytes must be rejected, not matched away
  if (/[\x00-\x20\x7f]/.test(raw)) fail("CIDR contains whitespace or control characters.");
  const parts = raw.split("/");
  if (parts.length !== 2) fail("CIDR must be address/prefix.");
  const [address, prefixText] = parts as [string, string];
  if (!/^(?:0|[1-9][0-9]*)$/.test(prefixText)) fail("CIDR prefix is not a canonical integer.");
  const prefix = Number(prefixText);
  const v4 = parseIpv4(address);
  if (v4) {
    if (prefix > 32) fail("IPv4 CIDR prefix exceeds 32.");
    return cidrFromV4(v4, prefix);
  }
  if (address.includes(":")) {
    const v6 = parseIpv6(address);
    if (!v6) fail("IPv6 CIDR address is malformed.");
    if (prefix > 128) fail("IPv6 CIDR prefix exceeds 128.");
    return cidrFromV6(v6, prefix);
  }
  fail("CIDR address is neither IPv4 nor IPv6.");
}

export function cidrsIntersect(a: ParsedCidr, b: ParsedCidr): boolean {
  if (a.family !== b.family) return false;
  const prefix = Math.min(a.prefix, b.prefix);
  const am = maskBits(a.groups, prefix);
  const bm = maskBits(b.groups, prefix);
  return am.every((group, index) => group === bm[index]);
}

/** A single parsed address as a host-length CIDR (/32 or /128), or null. */
export function parseIpAddress(input: string): ParsedCidr | null {
  const v4 = parseIpv4(input);
  if (v4) return cidrFromV4(v4, 32);
  if (!input.includes(":")) return null;
  const v6 = parseIpv6(input);
  return v6 ? cidrFromV6(v6, 128) : null;
}

/** True when `address` (a host-length CIDR) lies inside `range`. */
export function cidrContains(range: ParsedCidr, address: ParsedCidr): boolean {
  if (range.family !== address.family || address.prefix < range.prefix) return false;
  return cidrsIntersect(range, address);
}
