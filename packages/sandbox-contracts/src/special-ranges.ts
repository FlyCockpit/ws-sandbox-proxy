import { cidrContains, cidrFromV4, cidrsIntersect, type ParsedCidr, parseCidr } from "./ip";

/**
 * The one table of special-purpose and hard-denied address ranges, shared by
 * the webhook destination policy (SSRF) and sandbox egress (grant refusal,
 * the host's protected set, the open-mode public complement and the egress
 * guard's static set). The tables were moved verbatim from the webhook
 * policy; the sandbox protected set is COMPUTED from them, so a new
 * hard-denied entry joins the sandbox set without a second edit.
 *
 * Stable exports (template-recipe, webhooks, the shared fixture
 * `crates/sandbox-protocol/fixtures/egress_policy_cases.json` and the Rust
 * peers read these): `SPECIAL_PURPOSE_V4`, `GLOBAL_UNICAST_V6`,
 * `SPECIAL_PURPOSE_V6_IN_GLOBAL`, `HARD_DENIED`, `SANDBOX_PROTECTED_V4`,
 * `SANDBOX_PUBLIC_V4`, `intersectsSandboxProtectedV4`,
 * `sandboxProtectedV4Address`, `normalizeCidrSetV4`, `subtractCidrsV4`.
 */

const v4 = (a: number, b: number, c: number, d: number, prefix: number) =>
  parseCidr(`${a}.${b}.${c}.${d}/${prefix}`);
const v6 = (text: string) => parseCidr(text);

/** Special-purpose IPv4 ranges: never a public destination (webhooks: `special_purpose`). */
export const SPECIAL_PURPOSE_V4: readonly ParsedCidr[] = Object.freeze([
  v4(0, 0, 0, 0, 8),
  v4(10, 0, 0, 0, 8),
  v4(100, 64, 0, 0, 10), // CGNAT, tailnets, Alibaba metadata
  v4(127, 0, 0, 0, 8),
  v4(169, 254, 0, 0, 16),
  v4(172, 16, 0, 0, 12),
  v4(192, 0, 0, 0, 24),
  v4(192, 0, 2, 0, 24),
  v4(192, 88, 99, 0, 24),
  v4(192, 168, 0, 0, 16),
  v4(198, 18, 0, 0, 15),
  v4(198, 51, 100, 0, 24),
  v4(203, 0, 113, 0, 24),
  v4(224, 0, 0, 0, 4),
  v4(240, 0, 0, 0, 4),
]);

/** IPv6 global unicast; everything outside it is special-purpose. */
export const GLOBAL_UNICAST_V6: ParsedCidr = v6("2000::/3");

/** Special-purpose blocks inside 2000::/3. */
export const SPECIAL_PURPOSE_V6_IN_GLOBAL: readonly ParsedCidr[] = Object.freeze([
  v6("2001::/23"), // Teredo (2001::/32), ORCHID and other IETF assignments
  v6("2001:db8::/32"), // documentation
  v6("2002::/16"), // 6to4: embeds an IPv4 address
  v6("3fff::/20"), // documentation (RFC 9637)
  v6("5f00::/16"), // SRv6 SIDs
]);

/**
 * Refused even when an operator allowlists private space (webhooks:
 * `hard_denied`): loopback-adjacent, link-local, multicast, cloud metadata and
 * platform endpoints, and every IPv6 form that embeds or translates to IPv4.
 * Note `168.63.129.16/32` (Azure wireserver) is PUBLIC space, so it is the one
 * entry that widens the sandbox protected set beyond `SPECIAL_PURPOSE_V4`.
 */
export const HARD_DENIED: readonly ParsedCidr[] = Object.freeze([
  v4(0, 0, 0, 0, 8),
  v4(169, 254, 0, 0, 16),
  v4(224, 0, 0, 0, 4),
  v4(240, 0, 0, 0, 4), // includes 255.255.255.255
  v4(100, 100, 100, 100, 32), // Tailscale MagicDNS resolver
  v4(100, 100, 100, 200, 32), // Alibaba Cloud metadata
  v4(168, 63, 129, 16, 32), // Azure platform (wireserver)
  v6("fe80::/10"),
  v6("ff00::/8"),
  v6("fd00:ec2::254/128"), // AWS IMDS over IPv6
  // Every IPv6 form that embeds or translates to an IPv4 address is refused
  // outright, before any allowlist: otherwise an allowlisted name answering
  // 64:ff9b::a9fe:a9fe would reach 169.254.169.254 through a translator.
  // IPv4 destinations belong in IPv4 form, where the IPv4 rules apply.
  v6("::/96"), // IPv4-compatible (includes :: and ::1)
  v6("::ffff:0:0/96"), // IPv4-mapped: never unwrapped
  v6("::ffff:0:0:0/96"), // IPv4-translated (SIIT)
  v6("64:ff9b::/96"), // NAT64 well-known prefix
  v6("64:ff9b:1::/48"), // NAT64 local-use prefix
  v6("2002::/16"), // 6to4
  v6("2001::/32"), // Teredo
]);

// --- IPv4 set arithmetic ----------------------------------------------------

const V4_SIZE = 2 ** 32;

function v4Start(cidr: ParsedCidr): number {
  return (cidr.groups[0] as number) * 0x10000 + (cidr.groups[1] as number);
}
function v4End(cidr: ParsedCidr): number {
  return v4Start(cidr) + 2 ** (32 - cidr.prefix) - 1;
}
function v4FromInt(value: number, prefix: number): ParsedCidr {
  return cidrFromV4(
    [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff],
    prefix,
  );
}
function assertV4(cidrs: readonly ParsedCidr[]): void {
  for (const cidr of cidrs)
    if (cidr.family !== 4) throw new Error(`IPv4 set arithmetic got ${cidr.text}.`);
}

/**
 * Canonical IPv4 set: drops every entry covered by another and sorts by
 * address then prefix. Sibling prefixes are NOT merged, so the table keeps
 * the familiar special-purpose names (224/4 and 240/4 stay two entries).
 */
export function normalizeCidrSetV4(cidrs: readonly ParsedCidr[]): ParsedCidr[] {
  assertV4(cidrs);
  const sorted = [...cidrs].sort((a, b) => v4Start(a) - v4Start(b) || a.prefix - b.prefix);
  const out: ParsedCidr[] = [];
  for (const cidr of sorted) {
    const last = out[out.length - 1];
    if (last && cidrContains(last, cidr)) continue;
    out.push(cidr);
  }
  return out;
}

/** Minimal CIDR cover of the inclusive integer range [start, end]. */
function rangeToCidrs(start: number, end: number): ParsedCidr[] {
  const out: ParsedCidr[] = [];
  let cursor = start;
  while (cursor <= end) {
    // Largest aligned block starting at `cursor` that fits in the range.
    let size = alignment(cursor);
    while (cursor + size - 1 > end) size /= 2;
    out.push(v4FromInt(cursor, 32 - Math.log2(size)));
    cursor += size;
  }
  return out;
}
/** Largest power of two dividing `value` (JS bit ops are 32-bit signed, so no `& -x`). */
function alignment(value: number): number {
  if (value === 0) return V4_SIZE;
  let size = 1;
  while (size < V4_SIZE && value % (size * 2) === 0) size *= 2;
  return size;
}

/**
 * `cidr` minus every range in `remove`, as a sorted minimal CIDR list. Used
 * for the open-mode public complement and the partial-overlap cases in the
 * shared fixture.
 */
export function subtractCidrsV4(cidr: ParsedCidr, remove: readonly ParsedCidr[]): ParsedCidr[] {
  assertV4([cidr, ...remove]);
  const holes = normalizeCidrSetV4(remove.filter((range) => cidrsIntersect(range, cidr)));
  const out: ParsedCidr[] = [];
  let cursor = v4Start(cidr);
  const end = v4End(cidr);
  for (const hole of holes) {
    const holeStart = Math.max(v4Start(hole), v4Start(cidr));
    const holeEnd = Math.min(v4End(hole), end);
    if (holeStart > cursor) out.push(...rangeToCidrs(cursor, holeStart - 1));
    cursor = Math.max(cursor, holeEnd + 1);
  }
  if (cursor <= end) out.push(...rangeToCidrs(cursor, end));
  return out;
}

// --- Sandbox egress sets ----------------------------------------------------

/**
 * Every IPv4 destination a sandbox guest may never reach, whatever its
 * policy: `normalize(SPECIAL_PURPOSE_V4 ∪ HARD_DENIED ∩ IPv4)`. Today this is
 * the special-purpose list plus `168.63.129.16/32`.
 */
export const SANDBOX_PROTECTED_V4: readonly ParsedCidr[] = Object.freeze(
  normalizeCidrSetV4([...SPECIAL_PURPOSE_V4, ...HARD_DENIED.filter((cidr) => cidr.family === 4)]),
);

/**
 * The open-mode destination set: the minimal CIDR complement of
 * `SANDBOX_PROTECTED_V4` within `0.0.0.0/0` (golden in the shared fixture).
 */
export const SANDBOX_PUBLIC_V4: readonly ParsedCidr[] = Object.freeze(
  subtractCidrsV4(parseCidr("0.0.0.0/0"), SANDBOX_PROTECTED_V4),
);

/** True when an IPv4 CIDR overlaps the sandbox protected set (grant refusal). */
export function intersectsSandboxProtectedV4(cidr: ParsedCidr): boolean {
  return cidr.family === 4 && SANDBOX_PROTECTED_V4.some((range) => cidrsIntersect(range, cidr));
}

/** True when one IPv4 address lies in the sandbox protected set (DNS-answer filter). */
export function sandboxProtectedV4Address(address: ParsedCidr): boolean {
  return address.family === 4 && SANDBOX_PROTECTED_V4.some((range) => cidrContains(range, address));
}
