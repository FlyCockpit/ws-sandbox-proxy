import { z } from "zod";
import { IpParseError, type ParsedCidr, parseCidr as parseIpCidr, parseIpv4 } from "./ip";
import { intersectsSandboxProtectedV4 } from "./special-ranges";

/**
 * Sandbox egress policy. Two modes:
 *
 * - `open`: the guest reaches the public IPv4 internet (`SANDBOX_PUBLIC_V4`).
 *   Any `domains`/`cidrs` are FALLBACK grants: inert while the effective mode
 *   is open, and the allowlist when a host forces allowlist mode.
 * - `allowlist`: deny-default; only the listed exact DNS names
 *   (IDNA-canonicalized, no wildcards, URLs or IP literals) and IPv4 CIDRs.
 *
 * Inference (fail-safe, `inferEgressMode`): `egress` omitted, `null` or `{}`
 * means `open`; `mode` absent with ANY `domains` or `cidrs` key, even an empty
 * array, means `allowlist`, so `{domains:[],cidrs:[]}` and every older client
 * asking for a restricted sandbox stay restricted. Explicit deny-all is
 * `{mode:"allowlist"}`.
 *
 * Grants are refused (never carved out) when they intersect
 * `SANDBOX_PROTECTED_V4` (private, loopback, link-local, CGNAT/tailnet,
 * metadata, Azure wireserver, documentation, multicast, reserved). IPv6
 * grants are refused: sandboxes have IPv4 egress only.
 *
 * Stable exports (template-recipe and the server import these):
 * `EGRESS_MODES`, `EgressMode`, `egressModeSchema`, `egressPolicyInputSchema`,
 * `EgressPolicyInput`, `normalizedEgressPolicySchema`, `NormalizedEgressPolicy`,
 * `egressPolicyWireSchema`, `EgressPolicyWire`, `DENY_ALL_EGRESS_POLICY`,
 * `OPEN_EGRESS_POLICY`, `inferEgressMode`, `normalizeEgressPolicy`,
 * `canonicalEgressPolicyJson`, `isNormalizedEgressPolicy`,
 * `toEgressPolicyWire`, `egressPolicyFromWire`, `isCanonicalEgressPolicyWire`,
 * `EgressPolicyValidationError`.
 */
export const EGRESS_POLICY_MAX_DOMAINS = 128;
export const EGRESS_POLICY_MAX_CIDRS = 128;
export const EGRESS_DOMAIN_MAX_LENGTH = 253;
const EGRESS_CIDR_MAX_LENGTH = 64;

export const EGRESS_MODES = ["open", "allowlist"] as const;
export const egressModeSchema = z.enum(EGRESS_MODES);
export type EgressMode = z.infer<typeof egressModeSchema>;

/** Rejection is always this type; callers map it to the typed catalog error. */
export class EgressPolicyValidationError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "EgressPolicyValidationError";
  }
}

function fail(reason: string): never {
  throw new EgressPolicyValidationError(reason);
}

const domainsSchema = z
  .array(z.string().min(1).max(EGRESS_DOMAIN_MAX_LENGTH))
  .max(EGRESS_POLICY_MAX_DOMAINS);
const cidrsSchema = z
  .array(z.string().min(1).max(EGRESS_CIDR_MAX_LENGTH))
  .max(EGRESS_POLICY_MAX_CIDRS);

/** Request shape. No `presets` key: template builds expand presets first. */
export const egressPolicyInputSchema = z
  .object({
    mode: egressModeSchema.optional(),
    domains: domainsSchema.optional(),
    cidrs: cidrsSchema.optional(),
  })
  .strict();
export type EgressPolicyInput = z.infer<typeof egressPolicyInputSchema>;

/** Normalized form (DTOs, in-memory): canonical, sorted, deduplicated, explicit mode. */
export const normalizedEgressPolicySchema = z
  .object({ mode: egressModeSchema, domains: domainsSchema, cidrs: cidrsSchema })
  .strict();
export type NormalizedEgressPolicy = z.infer<typeof normalizedEgressPolicySchema>;

/**
 * Stored and relay form: `mode` is omitted for `allowlist` and present only
 * as `"open"`, exactly like the canonical JSON and the Rust `EgressPolicy`
 * serialization. This compact allowlist representation is canonical.
 */
export const egressPolicyWireSchema = z
  .object({ mode: z.literal("open").optional(), domains: domainsSchema, cidrs: cidrsSchema })
  .strict();
export type EgressPolicyWire = z.infer<typeof egressPolicyWireSchema>;

/** Explicit deny-all: allowlist mode with no grants. */
export const DENY_ALL_EGRESS_POLICY: NormalizedEgressPolicy = Object.freeze({
  mode: "allowlist",
  domains: [],
  cidrs: [],
}) as NormalizedEgressPolicy;

/** The effective open policy (fallback grants are dropped once open is granted). */
export const OPEN_EGRESS_POLICY: NormalizedEgressPolicy = Object.freeze({
  mode: "open",
  domains: [],
  cidrs: [],
}) as NormalizedEgressPolicy;

/**
 * Deterministic canonical serialization; the persisted hash covers this text.
 * `{"cidrs":[…],"domains":[…]}` for allowlist (unchanged from before modes,
 * so every allowlist hash is byte-identical) and
 * `{"cidrs":[…],"domains":[…],"mode":"open"}` for open. Accepts the normalized
 * or the wire form (absent mode = allowlist).
 */
export function canonicalEgressPolicyJson(policy: {
  mode?: EgressMode | undefined;
  domains: readonly string[];
  cidrs: readonly string[];
}): string {
  const base = { cidrs: [...policy.cidrs].sort(), domains: [...policy.domains].sort() };
  return JSON.stringify(policy.mode === "open" ? { ...base, mode: "open" } : base);
}

// --- CIDRs ----------------------------------------------------------------

function parseCidr(raw: string): ParsedCidr {
  try {
    return parseIpCidr(raw);
  } catch (error) {
    if (error instanceof IpParseError) fail(error.message);
    throw error;
  }
}

function assertGrantableCidr(cidr: ParsedCidr) {
  if (cidr.family === 6) {
    fail(`CIDR ${cidr.text} is IPv6; sandbox egress is IPv4 only.`);
  }
  if (intersectsSandboxProtectedV4(cidr)) {
    fail(`CIDR ${cidr.text} intersects a protected destination range.`);
  }
}

// --- Domains ---------------------------------------------------------------

const ASCII_DOMAIN_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

function normalizeDomain(raw: string): string {
  // Header injection and ambiguity guards run before any canonicalization.
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control bytes must be rejected, not matched away
  if (/[\x00-\x20\x7f]/.test(raw)) fail("Domain contains whitespace or control characters.");
  if (/[/\\@:?#[\]|]/.test(raw) || raw.includes("*") || raw.includes("%")) {
    fail("Domain must be an exact DNS name: no wildcards, URLs, ports or userinfo.");
  }
  // One optional trailing dot denotes an absolute name; canonical form drops it.
  const name = raw.endsWith(".") ? raw.slice(0, -1) : raw;
  if (name.length === 0) fail("Domain is empty.");
  let ascii: string;
  try {
    // WHATWG URL applies IDNA ToASCII and lowercases; it also normalizes
    // IPv4-in-disguise ("0x7f.1", "2130706433") to dotted quad, caught below.
    ascii = new URL(`http://${name}`).hostname;
  } catch {
    fail("Domain is not a parseable DNS name.");
  }
  if (parseIpv4(ascii) || ascii.includes(":")) {
    fail("IP literals belong in cidrs, not domains.");
  }
  if (ascii.length > EGRESS_DOMAIN_MAX_LENGTH || !ASCII_DOMAIN_PATTERN.test(ascii)) {
    fail("Domain is not a valid exact DNS name.");
  }
  return ascii;
}

// --- Policy ----------------------------------------------------------------

/**
 * The requested mode under the fail-safe inference rule: explicit `mode`
 * wins; otherwise any `domains` or `cidrs` key (even an empty array) means
 * `allowlist`; nothing at all (`undefined`, `null`, `{}`) means `open`.
 */
export function inferEgressMode(input: EgressPolicyInput | null | undefined): EgressMode {
  if (input == null) return "open";
  if (input.mode !== undefined) return input.mode;
  return input.domains !== undefined || input.cidrs !== undefined ? "allowlist" : "open";
}

/**
 * Validate, infer the mode and canonicalize. Throws EgressPolicyValidationError
 * on any defect. Grants are validated identically in both modes.
 */
export function normalizeEgressPolicy(
  input: EgressPolicyInput | null | undefined,
): NormalizedEgressPolicy {
  const parsed = egressPolicyInputSchema.safeParse(input ?? {});
  if (!parsed.success) fail("Egress policy exceeds the allowed shape or size.");
  const mode = inferEgressMode(parsed.data);
  const domains = [
    ...new Set((parsed.data.domains ?? []).map((domain) => normalizeDomain(domain))),
  ].sort();
  const cidrs = (parsed.data.cidrs ?? []).map((cidr) => parseCidr(cidr));
  for (const cidr of cidrs) assertGrantableCidr(cidr);
  const cidrsText = [...new Set(cidrs.map((cidr) => cidr.text))].sort();
  return { mode, domains, cidrs: cidrsText };
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}

/** `value` re-normalizes to itself (fixed point), so it is canonical. */
function isFixedPoint(value: NormalizedEgressPolicy): boolean {
  let roundTrip: NormalizedEgressPolicy;
  try {
    roundTrip = normalizeEgressPolicy(value);
  } catch {
    return false;
  }
  return (
    roundTrip.mode === value.mode &&
    sameList(roundTrip.domains, value.domains) &&
    sameList(roundTrip.cidrs, value.cidrs)
  );
}

/**
 * True only when `value` is already in canonical normalized form (explicit
 * `mode`): it parses, and re-normalizing is a fixed point.
 */
export function isNormalizedEgressPolicy(value: unknown): value is NormalizedEgressPolicy {
  const parsed = normalizedEgressPolicySchema.safeParse(value);
  return parsed.success && isFixedPoint(parsed.data);
}

/** The stored/relay form of a normalized policy (`mode` only when open). */
export function toEgressPolicyWire(policy: NormalizedEgressPolicy): EgressPolicyWire {
  return policy.mode === "open"
    ? { mode: "open", domains: [...policy.domains], cidrs: [...policy.cidrs] }
    : { domains: [...policy.domains], cidrs: [...policy.cidrs] };
}

/**
 * Parse a stored or relayed policy. Returns null unless `value` is the
 * canonical wire form: strict shape, `mode` absent (allowlist) or `"open"`
 * (an explicit `"allowlist"` is a second spelling and refused), and a
 * normalization fixed point. Relay dispatch validation uses this so a
 * non-canonical durable payload fails closed instead of reaching a daemon.
 */
export function egressPolicyFromWire(value: unknown): NormalizedEgressPolicy | null {
  const parsed = egressPolicyWireSchema.safeParse(value);
  if (!parsed.success) return null;
  const policy: NormalizedEgressPolicy = {
    mode: parsed.data.mode ?? "allowlist",
    domains: parsed.data.domains,
    cidrs: parsed.data.cidrs,
  };
  return isFixedPoint(policy) ? policy : null;
}

export function isCanonicalEgressPolicyWire(value: unknown): value is EgressPolicyWire {
  return egressPolicyFromWire(value) !== null;
}
