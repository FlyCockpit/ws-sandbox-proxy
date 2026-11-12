import { isIP } from "node:net";
import {
  cidrContains,
  cidrsIntersect,
  GLOBAL_UNICAST_V6,
  HARD_DENIED,
  IpParseError,
  type ParsedCidr,
  parseCidr,
  parseIpAddress,
  SPECIAL_PURPOSE_V4,
  SPECIAL_PURPOSE_V6_IN_GLOBAL,
  WEBHOOK_URL_MAX_LENGTH,
} from "@wssp/sandbox-contracts";

/**
 * Webhook destination policy (SSRF). Every rule here runs at create/update for
 * a fast answer and again on every delivery attempt against the addresses the
 * attempt actually connects to. Public unicast only, unless the operator
 * allowlists a private destination for an eligible owner; some addresses are
 * hard-denied even then.
 */

export type DestinationRefusal = { ok: false; code: "invalid" | "blocked"; reason: string };

export type ParsedDestination = {
  url: URL;
  scheme: "https" | "http";
  /** Hostname without IPv6 brackets or a trailing dot. */
  hostname: string;
  /** `host[:port]` exactly as sent in the Host header. */
  authority: string;
  port: number;
  /** Set when the hostname is an IP literal: no DNS for it. */
  literal: ParsedCidr | null;
};

export type WebhookAllowlist = {
  cidrs: readonly ParsedCidr[];
  hosts: ReadonlySet<string>;
  allowPlaintext: boolean;
  /** Non-production only: an explicitly allowlisted 127/8 is permitted (loopback dev). */
  allowLoopback: boolean;
  /**
   * Network-specific IPv6 translation prefixes (RFC 6052) on the worker's
   * network (`WEBHOOK_TRANSLATION_PREFIXES`). Hard-denied like 64:ff9b::/96.
   */
  translationPrefixes?: readonly ParsedCidr[];
};

export const EMPTY_ALLOWLIST: WebhookAllowlist = {
  cidrs: [],
  hosts: new Set(),
  allowPlaintext: false,
  allowLoopback: false,
};

// The special-purpose and hard-denied tables live in
// `@wssp/sandbox-contracts` (`special-ranges.ts`), shared with sandbox egress,
// whose protected set is their computed union. Classification here is
// unchanged: `special_purpose` vs `hard_denied`.
const BLOCKED_V4 = SPECIAL_PURPOSE_V4;
const BLOCKED_V6_INSIDE_GLOBAL = SPECIAL_PURPOSE_V6_IN_GLOBAL;
const LOOPBACK_V4 = parseCidr("127.0.0.0/8");

export type AddressClass =
  | { allowed: true }
  | { allowed: false; hard: boolean; reason: "special_purpose" | "hard_denied" };

function within(address: ParsedCidr, ranges: readonly ParsedCidr[]): boolean {
  return ranges.some((range) => cidrContains(range, address));
}

/** RFC 6052 §2.2: the prefix lengths a NAT64 translator may use. */
const RFC6052_PREFIX_LENGTHS = new Set([32, 40, 48, 56, 64, 96]);

/**
 * The IPv4 address embedded in `address` under an RFC 6052 prefix of length
 * 32-96: four octets starting right after the prefix, skipping octet 8 (bits
 * 64-71, the reserved "u" octet). Null for a non-RFC 6052 length.
 */
export function embeddedIpv4(address: ParsedCidr, prefixLength: number): ParsedCidr | null {
  if (address.family !== 6 || !RFC6052_PREFIX_LENGTHS.has(prefixLength)) return null;
  const bytes = address.groups.flatMap((group) => [group >> 8, group & 0xff]);
  const octets: number[] = [];
  for (let index = prefixLength / 8; octets.length < 4; index++)
    if (index !== 8) octets.push(bytes[index] as number);
  return parseIpAddress(octets.join("."));
}

/**
 * Classify one address with no allowlist applied. An address inside a
 * configured translation prefix is hard-denied outright (it reaches an IPv4
 * host through the translator); its embedded IPv4 is also classified, so the
 * refusal names the real target class.
 */
export function classifyAddress(
  address: ParsedCidr,
  allowLoopback = false,
  translationPrefixes: readonly ParsedCidr[] = [],
): AddressClass {
  const loopback = address.family === 4 && cidrContains(LOOPBACK_V4, address);
  if (within(address, HARD_DENIED) || (loopback && !allowLoopback))
    return { allowed: false, hard: true, reason: "hard_denied" };
  for (const prefix of translationPrefixes)
    if (cidrContains(prefix, address)) {
      // The whole prefix is refused; the embedded IPv4 (exported for tests and
      // logs) would only ever narrow that, never widen it.
      return { allowed: false, hard: true, reason: "hard_denied" };
    }
  if (address.family === 4)
    return within(address, BLOCKED_V4)
      ? { allowed: false, hard: false, reason: "special_purpose" }
      : { allowed: true };
  if (!cidrContains(GLOBAL_UNICAST_V6, address) || within(address, BLOCKED_V6_INSIDE_GLOBAL))
    return { allowed: false, hard: false, reason: "special_purpose" };
  return { allowed: true };
}

/**
 * Parse `WEBHOOK_ALLOWED_PRIVATE_CIDRS` (CSV). A CIDR overlapping a hard-denied
 * range is refused at boot (loopback only outside production); a broader range
 * that merely covers a single hard-denied host is accepted because every
 * address is still classified, so no allowlist can open metadata, link-local,
 * multicast or mapped addresses.
 */
export function parseAllowedCidrs(
  csv: string | undefined,
  production: boolean,
  translationPrefixes: readonly ParsedCidr[] = [],
): ParsedCidr[] {
  const out: ParsedCidr[] = [];
  for (const raw of (csv ?? "").split(",")) {
    const text = raw.trim();
    if (!text) continue;
    let cidr: ParsedCidr;
    try {
      cidr = parseCidr(text);
    } catch (error) {
      if (error instanceof IpParseError)
        throw new Error(`WEBHOOK_ALLOWED_PRIVATE_CIDRS: ${error.message}`);
      throw error;
    }
    for (const denied of HARD_DENIED) {
      // A broad range may cover a single hard-denied host (100.64.0.0/10 holds
      // the Tailscale resolver): classification still refuses that host. Any
      // other overlap with a hard-denied range is refused outright.
      const coversSingleHost =
        denied.prefix === (denied.family === 4 ? 32 : 128) && cidr.prefix < denied.prefix;
      if (cidrsIntersect(cidr, denied) && !coversSingleHost)
        throw new Error(
          `WEBHOOK_ALLOWED_PRIVATE_CIDRS: ${cidr.text} intersects a hard-denied range.`,
        );
    }
    for (const prefix of translationPrefixes)
      if (cidrsIntersect(cidr, prefix))
        throw new Error(
          `WEBHOOK_ALLOWED_PRIVATE_CIDRS: ${cidr.text} intersects translation prefix ${prefix.text}.`,
        );
    if (production && cidrsIntersect(cidr, LOOPBACK_V4))
      throw new Error(`WEBHOOK_ALLOWED_PRIVATE_CIDRS: ${cidr.text} allows loopback in production.`);
    out.push(cidr);
  }
  return out;
}

/**
 * Parse `WEBHOOK_TRANSLATION_PREFIXES` (CSV of IPv6 prefixes with an RFC 6052
 * length: /32, /40, /48, /56, /64 or /96). Anything else fails boot.
 */
export function parseTranslationPrefixes(csv: string | undefined): ParsedCidr[] {
  const out: ParsedCidr[] = [];
  for (const raw of (csv ?? "").split(",")) {
    const text = raw.trim();
    if (!text) continue;
    let prefix: ParsedCidr;
    try {
      prefix = parseCidr(text);
    } catch (error) {
      if (error instanceof IpParseError)
        throw new Error(`WEBHOOK_TRANSLATION_PREFIXES: ${error.message}`);
      throw error;
    }
    if (prefix.family !== 6 || !RFC6052_PREFIX_LENGTHS.has(prefix.prefix))
      throw new Error(
        `WEBHOOK_TRANSLATION_PREFIXES: ${prefix.text} is not an IPv6 prefix of length 32, 40, 48, 56, 64 or 96.`,
      );
    out.push(prefix);
  }
  return out;
}

/** Parse `WEBHOOK_ALLOWED_PRIVATE_HOSTS` (CSV of exact, canonical hostnames). */
export function parseAllowedHosts(csv: string | undefined): Set<string> {
  const out = new Set<string>();
  for (const raw of (csv ?? "").split(",")) {
    const text = raw.trim();
    if (!text) continue;
    let host: string;
    try {
      host = new URL(`https://${text}`).hostname;
    } catch {
      throw new Error("WEBHOOK_ALLOWED_PRIVATE_HOSTS: an entry is not a hostname.");
    }
    if (host !== text.toLowerCase().replace(/\.$/, "") || isIP(stripBrackets(host)))
      throw new Error("WEBHOOK_ALLOWED_PRIVATE_HOSTS: entries must be exact DNS names.");
    out.add(host.replace(/\.$/, ""));
  }
  return out;
}

function stripBrackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

const refuse = (code: "invalid" | "blocked", reason: string): DestinationRefusal => ({
  ok: false,
  code,
  reason,
});

/**
 * URL rules (create/update and every attempt). WHATWG URL canonicalizes
 * `0x7f.1`, `2130706433`, `127.1` and IDNA before any check runs.
 */
export function parseDestination(
  raw: string,
  allowlist: WebhookAllowlist,
): ({ ok: true } & ParsedDestination) | DestinationRefusal {
  if (raw.length > WEBHOOK_URL_MAX_LENGTH) return refuse("invalid", "too_long");
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control bytes must be rejected
  if (/[\x00-\x20\x7f]/.test(raw)) return refuse("invalid", "whitespace");
  if (raw.includes("#")) return refuse("invalid", "fragment");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return refuse("invalid", "unparseable");
  }
  if (url.href.length > WEBHOOK_URL_MAX_LENGTH) return refuse("invalid", "too_long");
  if (url.username || url.password) return refuse("invalid", "userinfo");
  const scheme = url.protocol === "https:" ? "https" : url.protocol === "http:" ? "http" : null;
  if (!scheme) return refuse("invalid", "scheme");
  if (scheme === "http" && !allowlist.allowPlaintext) return refuse("invalid", "plaintext");
  const port = url.port ? Number(url.port) : scheme === "https" ? 443 : 80;
  if (!(port === 443 || (port === 80 && scheme === "http") || (port >= 1024 && port <= 65535)))
    return refuse("invalid", "port");
  const bare = stripBrackets(url.hostname);
  const hostname = bare.endsWith(".") ? bare.slice(0, -1) : bare;
  if (!hostname) return refuse("invalid", "host");
  const literal = isIP(hostname) ? parseIpAddress(hostname) : null;
  if (isIP(hostname) && !literal) return refuse("invalid", "host");
  if (!literal) {
    if (hostname === "localhost" || hostname.endsWith(".localhost"))
      return refuse("blocked", "local_name");
    if (
      (hostname.endsWith(".local") || hostname.endsWith(".internal")) &&
      !allowlist.hosts.has(hostname)
    )
      return refuse("blocked", "local_name");
  }
  return { ok: true, url, scheme, hostname, authority: url.host, port, literal };
}

/**
 * The address decision for one attempt: EVERY resolved address must pass, or
 * the attempt is refused (a mixed public/private answer cannot win a race).
 * A blocked, not hard-denied address passes only for an eligible owner and
 * only through the operator allowlist: inside a configured CIDR, or, when no
 * CIDRs are configured, through an exact hostname match.
 */
export function checkAddresses(input: {
  destination: Pick<ParsedDestination, "hostname" | "scheme">;
  addresses: readonly ParsedCidr[];
  allowlist: WebhookAllowlist;
  ownerMayUsePrivate: boolean;
}): { ok: true; private: boolean } | DestinationRefusal {
  const { destination, addresses, allowlist } = input;
  if (addresses.length === 0) return refuse("blocked", "no_address");
  let anyPublic = false;
  let anyPrivate = false;
  for (const address of addresses) {
    const verdict = classifyAddress(
      address,
      allowlist.allowLoopback && inCidrs(address, allowlist),
      allowlist.translationPrefixes,
    );
    if (verdict.allowed) {
      anyPublic = true;
      continue;
    }
    if (verdict.hard) return refuse("blocked", "hard_denied");
    if (!input.ownerMayUsePrivate) return refuse("blocked", "private");
    const allowed =
      allowlist.cidrs.length > 0
        ? inCidrs(address, allowlist)
        : allowlist.hosts.has(destination.hostname);
    if (!allowed) return refuse("blocked", "private");
    anyPrivate = true;
  }
  // Plaintext only to allowlisted private destinations, never mixed with public.
  if (destination.scheme === "http" && (anyPublic || !anyPrivate || !allowlist.allowPlaintext))
    return refuse("blocked", "plaintext");
  return { ok: true, private: anyPrivate };
}

function inCidrs(address: ParsedCidr, allowlist: WebhookAllowlist): boolean {
  return allowlist.cidrs.some((range) => cidrContains(range, address));
}

/** Host only, for logs and admin views: never path, query or credentials. */
export function destinationHost(raw: string): string {
  try {
    return new URL(raw).hostname;
  } catch {
    return "invalid";
  }
}
