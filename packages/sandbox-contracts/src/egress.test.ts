import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import cases from "../../../crates/sandbox-protocol/fixtures/egress_policy_cases.json";
import {
  canonicalEgressPolicyJson,
  DENY_ALL_EGRESS_POLICY,
  EGRESS_POLICY_MAX_CIDRS,
  EGRESS_POLICY_MAX_DOMAINS,
  EgressPolicyValidationError,
  type EgressPolicyWire,
  egressPolicyFromWire,
  inferEgressMode,
  isCanonicalEgressPolicyWire,
  isNormalizedEgressPolicy,
  normalizedEgressPolicySchema,
  normalizeEgressPolicy,
  OPEN_EGRESS_POLICY,
  toEgressPolicyWire,
} from "./egress";

const ok = (input: Parameters<typeof normalizeEgressPolicy>[0]) => normalizeEgressPolicy(input);
const bad = (input: Parameters<typeof normalizeEgressPolicy>[0]) =>
  expect(() => normalizeEgressPolicy(input)).toThrow(EgressPolicyValidationError);

describe("egress policy domains", () => {
  it("canonicalizes case, trailing dot and IDNA", () => {
    expect(ok({ domains: ["Example.COM."] }).domains).toEqual(["example.com"]);
    expect(ok({ domains: ["bücher.example"] }).domains).toEqual(["xn--bcher-kva.example"]);
    expect(ok({ domains: ["xn--bcher-kva.example"] }).domains).toEqual(["xn--bcher-kva.example"]);
  });

  it("deduplicates and sorts", () => {
    expect(ok({ domains: ["b.example.com", "a.example.com", "B.example.com"] }).domains).toEqual([
      "a.example.com",
      "b.example.com",
    ]);
  });

  it.each([
    ["wildcard", "*.example.com"],
    ["prefix wildcard", "*example.com"],
    ["URL", "https://example.com"],
    ["path", "example.com/path"],
    ["port", "example.com:443"],
    ["userinfo", "u@example.com"],
    ["header injection", "example.com\r\nX-Evil: 1"],
    ["embedded space", "exa mple.com"],
    ["NUL", "example.com\0"],
    ["single label", "localhost"],
    ["empty label", "a..b.com"],
    ["underscore label", "bad_name.example.com"],
    ["IPv4 literal", "169.254.169.254"],
    ["IPv4 in disguise", "0xa9.0xfe.0xa9.0xfe"],
    ["IPv4 single integer", "2852039166"],
    ["bracketed IPv6", "[fe80::1]"],
    ["label too long", `${"a".repeat(64)}.example.com`],
    ["double trailing dot", "example.com.."],
    ["percent-encoded", "example%2ecom"],
  ])("rejects malformed or ambiguous name: %s", (_label, domain) => {
    bad({ domains: [domain] });
  });
});

describe("egress policy CIDRs", () => {
  it("normalizes IPv4 host bits and rejects ambiguous octets", () => {
    expect(ok({ cidrs: ["128.66.1.2/24"] }).cidrs).toEqual(["128.66.1.0/24"]);
    bad({ cidrs: ["010.0.0.0/8"] });
    bad({ cidrs: ["256.0.0.0/8"] });
    bad({ cidrs: ["8.0.0.0/33"] });
    bad({ cidrs: ["8.0.0.0/08"] });
    bad({ cidrs: ["8.0.0.0"] });
    bad({ cidrs: ["8.0.0.0/8/1"] });
  });

  it("enforces the 128-entry caps", () => {
    const domains = Array.from(
      { length: EGRESS_POLICY_MAX_DOMAINS + 1 },
      (_, i) => `d${i}.example.com`,
    );
    bad({ domains });
    const cidrs = Array.from(
      { length: EGRESS_POLICY_MAX_CIDRS + 1 },
      (_, i) => `128.${i >> 1}.${(i & 1) * 128}.0/25`,
    );
    bad({ cidrs });
    expect(ok({ domains: domains.slice(0, EGRESS_POLICY_MAX_DOMAINS) }).domains).toHaveLength(128);
    expect(ok({ cidrs: cidrs.slice(0, EGRESS_POLICY_MAX_CIDRS) }).cidrs).toHaveLength(128);
  });

  it("sorts and dedupes after normalization", () => {
    expect(ok({ cidrs: ["8.8.8.8/24", "1.1.0.0/16", "1.1.1.1/16"] }).cidrs).toEqual([
      "1.1.0.0/16",
      "8.8.8.0/24",
    ]);
  });

  it.each([
    ["global unicast", "2001:4860::/32"],
    ["documentation", "2001:db8::/32"],
    ["default", "::/0"],
    ["unique-local", "fd00:1::/32"],
    ["link-local", "fe80::/10"],
    ["IPv4-mapped metadata", "::ffff:169.254.169.254/128"],
    ["IPv4-mapped public", "::ffff:8.8.8.8/128"],
    ["NAT64", "64:ff9b::/96"],
  ])("refuses every IPv6 grant (IPv4-only egress): %s", (_label, cidr) => {
    bad({ cidrs: [cidr] });
    bad({ mode: "open", cidrs: [cidr] });
  });
});

describe("protected destination ranges", () => {
  it.each([
    ["IETF protocol assignments", "192.0.0.0/24"],
    ["IETF protocol assignment exact", "192.0.0.9/32"],
    ["IETF protocol assignment supernet", "192.0.0.0/23"],
    ["deprecated 6to4 anycast", "192.88.99.0/24"],
    ["deprecated 6to4 anycast supernet", "192.88.98.0/23"],
    ["TEST-NET-1", "192.0.2.0/24"],
    ["TEST-NET-2 exact", "198.51.100.7/32"],
    ["TEST-NET-3 supernet", "203.0.112.0/23"],
    ["metadata exact", "169.254.169.254/32"],
    ["link-local supernet", "169.254.0.0/15"],
    ["broad IPv4 default", "0.0.0.0/0"],
    ["Alibaba metadata exact", "100.100.100.200/32"],
    ["Tailscale MagicDNS", "100.100.100.100/32"],
    ["CGNAT / tailnet", "100.64.0.0/10"],
    ["Azure wireserver exact", "168.63.129.16/32"],
    ["Azure wireserver supernet", "168.63.0.0/16"],
    ["RFC1918 10/8", "10.1.2.3/8"],
    ["RFC1918 172.16/12 inner", "172.20.0.0/16"],
    ["RFC1918 192.168/16 exact", "192.168.1.1/32"],
    ["loopback", "127.0.0.1/32"],
    ["this network", "0.0.0.0/8"],
    ["benchmarking", "198.18.0.0/15"],
    ["multicast", "224.0.0.251/32"],
    ["reserved and broadcast", "255.255.255.255/32"],
  ])("refuses a CIDR intersecting the sandbox protected set: %s", (_label, cidr) => {
    bad({ cidrs: [cidr] });
    // Fallback grants on an open request pass the same refusal.
    bad({ mode: "open", cidrs: [cidr] });
  });

  it("accepts public CIDRs adjacent to protected ranges", () => {
    expect(
      ok({
        cidrs: ["169.253.0.0/16", "169.255.1.0/24", "168.63.129.17/32", "172.32.0.0/11"],
      }).cidrs,
    ).toEqual(["168.63.129.17/32", "169.253.0.0/16", "169.255.1.0/24", "172.32.0.0/11"]);
  });
});

describe("egress mode inference (fail-safe)", () => {
  it("nothing requested means open; any grant key means allowlist", () => {
    expect(inferEgressMode(undefined)).toBe("open");
    expect(inferEgressMode(null)).toBe("open");
    expect(inferEgressMode({})).toBe("open");
    expect(inferEgressMode({ domains: [] })).toBe("allowlist");
    expect(inferEgressMode({ cidrs: [] })).toBe("allowlist");
    expect(inferEgressMode({ domains: [], cidrs: [] })).toBe("allowlist");
    expect(inferEgressMode({ mode: "open", domains: ["example.com"] })).toBe("open");
    expect(inferEgressMode({ mode: "allowlist" })).toBe("allowlist");
  });

  it("deny-all and open constants", () => {
    expect(ok({ domains: [], cidrs: [] })).toEqual(DENY_ALL_EGRESS_POLICY);
    expect(ok({ mode: "allowlist" })).toEqual(DENY_ALL_EGRESS_POLICY);
    expect(ok({})).toEqual(OPEN_EGRESS_POLICY);
    expect(ok(undefined)).toEqual(OPEN_EGRESS_POLICY);
  });

  it("open keeps validated fallback grants", () => {
    expect(ok({ mode: "open", domains: ["B.example.com"], cidrs: ["8.8.8.8/32"] })).toEqual({
      mode: "open",
      domains: ["b.example.com"],
      cidrs: ["8.8.8.8/32"],
    });
  });

  it("refuses presets and unknown modes (presets are expanded by template builds)", () => {
    bad({ presets: ["pypi"] } as never);
    bad({ mode: "closed" } as never);
    bad({ mode: null } as never);
  });
});

describe("canonical JSON and wire form", () => {
  it("allowlist hashes are byte-identical to the pre-mode canonical JSON", () => {
    expect(canonicalEgressPolicyJson(DENY_ALL_EGRESS_POLICY)).toBe('{"cidrs":[],"domains":[]}');
    expect(canonicalEgressPolicyJson({ domains: [], cidrs: [] })).toBe('{"cidrs":[],"domains":[]}');
    expect(canonicalEgressPolicyJson(OPEN_EGRESS_POLICY)).toBe(
      '{"cidrs":[],"domains":[],"mode":"open"}',
    );
  });

  it("the wire form omits mode for allowlist and refuses a second spelling", () => {
    expect(toEgressPolicyWire(DENY_ALL_EGRESS_POLICY)).toEqual({ domains: [], cidrs: [] });
    expect(toEgressPolicyWire(OPEN_EGRESS_POLICY)).toEqual({
      mode: "open",
      domains: [],
      cidrs: [],
    });
    expect(egressPolicyFromWire({ domains: [], cidrs: [] })).toEqual(DENY_ALL_EGRESS_POLICY);
    expect(egressPolicyFromWire({ mode: "allowlist", domains: [], cidrs: [] })).toBeNull();
    // Non-canonical (unsorted, uppercase, host bits) and refused grants fail closed.
    expect(egressPolicyFromWire({ domains: ["b.com", "a.com"], cidrs: [] })).toBeNull();
    expect(egressPolicyFromWire({ domains: ["A.com"], cidrs: [] })).toBeNull();
    expect(egressPolicyFromWire({ domains: [], cidrs: ["8.8.8.8/24"] })).toBeNull();
    expect(egressPolicyFromWire({ domains: [], cidrs: ["10.0.0.0/8"] })).toBeNull();
    expect(isNormalizedEgressPolicy({ domains: [], cidrs: [] })).toBe(false);
    expect(isNormalizedEgressPolicy(DENY_ALL_EGRESS_POLICY)).toBe(true);
  });
});

describe("shared fixture (crates/sandbox-protocol/fixtures/egress_policy_cases.json)", () => {
  const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

  it.each(cases.normalize.map((c) => [c.name, c] as const))("normalizes: %s", (_name, c) => {
    const normalized = normalizeEgressPolicy(c.input as never);
    expect(normalized).toEqual(c.normalized);
    expect(isNormalizedEgressPolicy(normalized)).toBe(true);
    expect(toEgressPolicyWire(normalized)).toEqual(c.wire);
    expect(isCanonicalEgressPolicyWire(c.wire)).toBe(true);
    expect(egressPolicyFromWire(c.wire)).toEqual(c.normalized);
    expect(canonicalEgressPolicyJson(normalized)).toBe(c.canonicalJson);
    expect(canonicalEgressPolicyJson(c.wire as EgressPolicyWire)).toBe(c.canonicalJson);
    expect(sha256(c.canonicalJson)).toBe(c.hash);
  });

  it.each(cases.invalid.map((c) => [c.name, c] as const))("refuses: %s", (_name, c) => {
    bad(c.input as never);
  });

  it.each(cases.wireInvalid.map((c) => [c.name, c] as const))("wire refuses: %s", (_n, c) => {
    expect(egressPolicyFromWire(c.wire)).toBeNull();
  });

  it("the legacy deny-all golden hash is unchanged", () => {
    const legacy = cases.normalize.find((c) => c.name.startsWith("empty arrays"));
    expect(legacy?.hash).toBe("cd54f076503987212abf92b598f837d67f1e70de63317600961cf181ef0f7caa");
  });
});

describe("egress policy shape", () => {
  it("rejects unsupported fields", () => {
    bad({ domains: ["example.com"], wildcard: true } as never);
    bad({ headers: ["X: 1"] } as never);
  });

  it("normalized output parses its own schema and hashes deterministically", () => {
    const a = ok({ domains: ["B.example.com", "a.example.com"], cidrs: ["128.66.1.2/24"] });
    const b = ok({ domains: ["a.example.com", "b.example.com"], cidrs: ["128.66.1.0/24"] });
    expect(a).toEqual(b);
    expect(normalizedEgressPolicySchema.parse(a)).toEqual(a);
    expect(canonicalEgressPolicyJson(a)).toBe(canonicalEgressPolicyJson(b));
  });
});
