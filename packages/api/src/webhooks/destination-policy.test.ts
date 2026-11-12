import { parseIpAddress } from "@wssp/sandbox-contracts";
import { describe, expect, it } from "vitest";
import {
  checkAddresses,
  classifyAddress,
  EMPTY_ALLOWLIST,
  embeddedIpv4,
  parseAllowedCidrs,
  parseAllowedHosts,
  parseDestination,
  parseTranslationPrefixes,
  type WebhookAllowlist,
} from "./destination-policy";

/** URL → the single address a literal destination connects to, through the full policy. */
function literalVerdict(
  url: string,
  allowlist: WebhookAllowlist = EMPTY_ALLOWLIST,
  eligible = true,
) {
  const destination = parseDestination(url, allowlist);
  if (!destination.ok) return destination.code;
  if (!destination.literal) return "name";
  const verdict = checkAddresses({
    destination,
    addresses: [destination.literal],
    allowlist,
    ownerMayUsePrivate: eligible,
  });
  return verdict.ok ? "allowed" : verdict.code;
}

describe("webhook SSRF matrix: IPv4 URL forms", () => {
  it.each([
    "https://127.0.0.1/",
    "https://127.1/",
    "https://2130706433/",
    "https://0x7f.0.0.1/",
    "https://0177.0.0.1/",
    "https://10.0.0.1/",
    "https://100.64.0.1/",
    "https://100.100.100.100/",
    "https://100.100.100.200/",
    "https://169.254.169.254/",
    "https://172.31.255.255/",
    "https://192.168.1.1/",
    "https://198.18.0.1/",
    "https://224.0.0.1/",
    "https://255.255.255.255/",
    "https://0.0.0.0/",
    "https://192.0.2.1/",
    "https://203.0.113.9/",
    "https://240.0.0.1/",
  ])("%s is refused", (url) => {
    expect(literalVerdict(url)).toBe("blocked");
  });

  it("canonicalizes numeric spellings before classifying", () => {
    for (const url of ["https://127.1/", "https://2130706433/", "https://0x7f.0.0.1/"]) {
      const parsed = parseDestination(url, EMPTY_ALLOWLIST);
      expect(parsed.ok && parsed.hostname).toBe("127.0.0.1");
    }
  });

  it("allows public unicast", () => {
    expect(literalVerdict("https://8.8.8.8/")).toBe("allowed");
    expect(literalVerdict("https://1.1.1.1:8443/hook")).toBe("allowed");
  });
});

describe("webhook SSRF matrix: IPv6 URL forms", () => {
  it.each([
    "https://[::1]/",
    "https://[::]/",
    "https://[::ffff:127.0.0.1]/",
    "https://[::ffff:7f00:1]/",
    "https://[::127.0.0.1]/",
    "https://[0:0:0:0:0:ffff:a9fe:a9fe]/",
    "https://[fd00:ec2::254]/",
    "https://[fc00::1]/",
    "https://[fe80::1]/",
    "https://[fec0::1]/",
    "https://[ff02::1]/",
    "https://[64:ff9b::a9fe:a9fe]/",
    "https://[64:ff9b:1::1]/",
    "https://[100::1]/",
    "https://[2002:a9fe:a9fe::1]/",
    "https://[2001:0:4136:e378::1]/",
    "https://[2001:db8::1]/",
    "https://[3fff::1]/",
    "https://[5f00::1]/",
    "https://[FE80::1]/",
    "https://[0000:0000:0000:0000:0000:0000:0000:0001]/",
    "https://[FD00:EC2:0:0:0:0:0:254]/",
  ])("%s is refused", (url) => {
    expect(literalVerdict(url)).toBe("blocked");
  });

  it("rejects zone ids in the URL parser", () => {
    expect(literalVerdict("https://[fe80::1%25eth0]/")).toBe("invalid");
  });

  it("strips brackets: the literal skips DNS and is classified", () => {
    const parsed = parseDestination("https://[2606:4700::1111]/", EMPTY_ALLOWLIST);
    expect(parsed.ok && parsed.hostname).toBe("2606:4700::1111");
    expect(parsed.ok && parsed.literal?.family).toBe(6);
    expect(literalVerdict("https://[2606:4700::1111]/")).toBe("allowed");
  });
});

describe("webhook URL rules", () => {
  it.each([
    ["https://localhost/", "blocked"],
    ["https://localhost./", "blocked"],
    ["https://foo.localhost/", "blocked"],
    ["https://x.internal/", "blocked"],
    ["https://printer.local/", "blocked"],
    ["https://user:pass@hooks.example.com/", "invalid"],
    ["https://hooks.example.com/#frag", "invalid"],
    ["https://hooks.example.com/#", "invalid"],
    ["ftp://hooks.example.com/", "invalid"],
    ["http://hooks.example.com/", "invalid"],
    ["https://hooks.example.com:22/", "invalid"],
    ["https://hooks.example.com:80/", "invalid"],
    ["https://hooks.example.com:1023/", "invalid"],
    ["https://hooks.example.com/ x", "invalid"],
    [`https://hooks.example.com/${"a".repeat(2050)}`, "invalid"],
    ["not a url", "invalid"],
  ])("%s → %s", (url, expected) => {
    const parsed = parseDestination(url, EMPTY_ALLOWLIST);
    expect(parsed.ok ? "ok" : parsed.code).toBe(expected);
  });

  it("accepts public names on 443 and 1024-65535, normalizing IDN", () => {
    for (const url of ["https://hooks.example.com/x?y=1", "https://hooks.example.com:8443/"])
      expect(parseDestination(url, EMPTY_ALLOWLIST).ok).toBe(true);
    const idn = parseDestination("https://bücher.example/", EMPTY_ALLOWLIST);
    expect(idn.ok && idn.hostname).toBe("xn--bcher-kva.example");
  });
});

describe("operator allowlist", () => {
  const tailnet: WebhookAllowlist = {
    cidrs: parseAllowedCidrs("100.64.0.0/10,192.168.1.0/24", true),
    hosts: new Set(),
    allowPlaintext: false,
    allowLoopback: false,
  };

  it("allows an allowlisted CIDR hit for an eligible owner only", () => {
    expect(literalVerdict("https://100.101.102.103/", tailnet)).toBe("allowed");
    expect(literalVerdict("https://100.101.102.103/", tailnet, false)).toBe("blocked");
    expect(literalVerdict("https://10.0.0.1/", tailnet)).toBe("blocked");
  });

  it("never opens metadata or IPv4-mapped addresses, even under a covering CIDR", () => {
    expect(literalVerdict("https://100.100.100.200/", tailnet)).toBe("blocked");
    expect(literalVerdict("https://100.100.100.100/", tailnet)).toBe("blocked");
    expect(literalVerdict("https://[::ffff:192.168.1.5]/", tailnet)).toBe("blocked");
  });

  it("a host match allows a private name only when no CIDRs are configured", () => {
    const hosts: WebhookAllowlist = {
      ...EMPTY_ALLOWLIST,
      hosts: parseAllowedHosts("box.tail1234.ts.net"),
    };
    const destination = { hostname: "box.tail1234.ts.net", scheme: "https" as const };
    const address = parseIpAddress("100.88.1.2")!;
    expect(
      checkAddresses({
        destination,
        addresses: [address],
        allowlist: hosts,
        ownerMayUsePrivate: true,
      }).ok,
    ).toBe(true);
    // With CIDRs set, the resolved address must also be inside one (review minor 10).
    const both: WebhookAllowlist = {
      ...hosts,
      cidrs: parseAllowedCidrs("192.168.1.0/24", true),
    };
    expect(
      checkAddresses({
        destination,
        addresses: [address],
        allowlist: both,
        ownerMayUsePrivate: true,
      }).ok,
    ).toBe(false);
  });

  it("refuses a mixed public/private answer set outright", () => {
    const destination = { hostname: "hooks.example.com", scheme: "https" as const };
    const verdict = checkAddresses({
      destination,
      addresses: [parseIpAddress("8.8.8.8")!, parseIpAddress("10.0.0.1")!],
      allowlist: EMPTY_ALLOWLIST,
      ownerMayUsePrivate: true,
    });
    expect(verdict.ok).toBe(false);
  });

  it("plaintext needs the flag AND an allowlisted private destination", () => {
    expect(literalVerdict("http://192.168.1.10:8080/", tailnet)).toBe("invalid");
    const plain = { ...tailnet, allowPlaintext: true };
    expect(literalVerdict("http://192.168.1.10:8080/", plain)).toBe("allowed");
    expect(literalVerdict("http://8.8.8.8/", plain)).toBe("blocked");
    expect(literalVerdict("http://10.0.0.5/", plain)).toBe("blocked");
    expect(literalVerdict("http://192.168.1.10:8080/", plain, false)).toBe("blocked");
  });

  it("validates CIDRs at boot against hard-denied ranges", () => {
    for (const bad of [
      "0.0.0.0/0",
      "169.254.0.0/16",
      "100.100.100.200/32",
      "::/0",
      "fd00:ec2::254/128",
      "::ffff:0:0/96",
      "fe80::/10",
      "10.0.0.1/33",
      "10.0.0.1",
    ])
      expect(() => parseAllowedCidrs(bad, false), bad).toThrow(/WEBHOOK_ALLOWED_PRIVATE_CIDRS/);
    expect(() => parseAllowedCidrs("127.0.0.1/32", true)).toThrow(/loopback/);
    expect(parseAllowedCidrs("127.0.0.1/32", false)).toHaveLength(1);
    expect(parseAllowedCidrs(" 10.1.0.0/16 , ", true).map((c) => c.text)).toEqual(["10.1.0.0/16"]);
  });

  it("permits explicitly allowlisted loopback outside production only", () => {
    const dev: WebhookAllowlist = {
      ...EMPTY_ALLOWLIST,
      cidrs: parseAllowedCidrs("127.0.0.1/32", false),
      allowLoopback: true,
    };
    expect(literalVerdict("https://127.0.0.1:8443/", dev)).toBe("allowed");
    expect(literalVerdict("https://127.0.0.2:8443/", dev)).toBe("blocked");
    expect(literalVerdict("https://127.0.0.1:8443/", { ...dev, allowLoopback: false })).toBe(
      "blocked",
    );
  });

  it("host allowlist entries must be exact DNS names", () => {
    expect(() => parseAllowedHosts("10.0.0.1")).toThrow();
    expect(() => parseAllowedHosts("https://x.example")).toThrow();
    expect([...parseAllowedHosts("A.Example.COM")]).toEqual(["a.example.com"]);
  });
});

describe("classifyAddress", () => {
  it("treats only 2000::/3 minus special blocks as public IPv6", () => {
    expect(classifyAddress(parseIpAddress("2606:4700::1111")!).allowed).toBe(true);
    expect(classifyAddress(parseIpAddress("2001:db8::1")!).allowed).toBe(false);
    expect(classifyAddress(parseIpAddress("4000::1")!).allowed).toBe(false);
  });
});

describe("IPv6 translation and embedding ranges (review finding 1)", () => {
  const everything: WebhookAllowlist = {
    cidrs: parseAllowedCidrs("10.0.0.0/8,fc00::/7,2001:db8::/32", true),
    hosts: new Set(["box.example.test"]),
    allowPlaintext: true,
    allowLoopback: false,
  };
  it.each([
    ["64:ff9b::a9fe:a9fe", "NAT64 of 169.254.169.254"],
    ["64:ff9b::a00:1", "NAT64 of 10.0.0.1"],
    ["64:ff9b:1::a9fe:a9fe", "NAT64 local-use"],
    ["::a9fe:a9fe", "IPv4-compatible metadata"],
    ["::ffff:a9fe:a9fe", "IPv4-mapped metadata"],
    ["::ffff:0:a9fe:a9fe", "IPv4-translated metadata"],
    ["2002:a9fe:a9fe::1", "6to4 of metadata"],
    ["2001:0:4136:e378:8000:63bf:3fff:fdd2", "Teredo"],
  ])("%s (%s) is hard-denied even for an eligible owner with an allowlisted host", (ip) => {
    const address = parseIpAddress(ip)!;
    expect(classifyAddress(address)).toMatchObject({ allowed: false, hard: true });
    for (const scheme of ["https", "http"] as const)
      expect(
        checkAddresses({
          destination: { hostname: "box.example.test", scheme },
          addresses: [address],
          allowlist: { ...everything, cidrs: [] },
          ownerMayUsePrivate: true,
        }),
      ).toMatchObject({ ok: false, reason: "hard_denied" });
  });

  it("refuses an allowlist CIDR that overlaps a translation range at boot", () => {
    for (const bad of ["64:ff9b::/96", "2002::/16", "2001::/32", "::/96", "2000::/3"])
      expect(() => parseAllowedCidrs(bad, true), bad).toThrow(/hard-denied/);
  });
});

describe("network-specific NAT64 prefixes (review round 2, finding 1)", () => {
  const prefixes = parseTranslationPrefixes("fd12:3456:789a:bcde::/64, 2001:db8:122::/48");
  const allowlist: WebhookAllowlist = {
    // An operator allowlist that would otherwise cover the translated range.
    cidrs: parseAllowedCidrs("fd00::/16", true),
    hosts: new Set(["box.example.test"]),
    allowPlaintext: true,
    allowLoopback: false,
    translationPrefixes: prefixes,
  };

  it("extracts the embedded IPv4 at the RFC 6052 positions (u octet skipped)", () => {
    const cases: [string, number, string][] = [
      ["fd12:3456:789a:bcde:a9:fea9:fe00:0", 64, "169.254.169.254/32"],
      ["2001:db8:c000:221::", 32, "192.0.2.33/32"],
      ["2001:db8:1c0:2:21::", 40, "192.0.2.33/32"],
      ["2001:db8:122:c000:2:2100::", 48, "192.0.2.33/32"],
      ["2001:db8:122:3c0:0:221::", 56, "192.0.2.33/32"],
      ["2001:db8:122:344:c0:2:2100:0", 64, "192.0.2.33/32"],
      ["2001:db8:122:344::192.0.2.33", 96, "192.0.2.33/32"],
    ];
    for (const [ip, length, ipv4] of cases)
      expect(embeddedIpv4(parseIpAddress(ip)!, length)?.text, `${ip}/${length}`).toBe(ipv4);
    expect(embeddedIpv4(parseIpAddress("2001:db8::1")!, 72)).toBeNull();
  });

  it("hard-denies metadata embedded under a configured prefix, even for an eligible owner over plaintext", () => {
    const metadata = parseIpAddress("fd12:3456:789a:bcde:a9:fea9:fe00:0")!;
    expect(classifyAddress(metadata, false, prefixes)).toMatchObject({
      allowed: false,
      hard: true,
    });
    expect(
      checkAddresses({
        destination: { hostname: "box.example.test", scheme: "http" },
        addresses: [metadata],
        allowlist: { ...allowlist, cidrs: [] },
        ownerMayUsePrivate: true,
      }),
    ).toMatchObject({ ok: false, reason: "hard_denied" });
    // Any address in the prefix is refused, not only embedded protected ones.
    const anyTranslated = parseIpAddress("fd12:3456:789a:bcde:8:808:800:0")!; // 8.8.8.8
    expect(classifyAddress(anyTranslated, false, prefixes)).toMatchObject({ hard: true });
    // Without the prefix configured the same ULA address is merely private.
    expect(classifyAddress(metadata)).toMatchObject({ allowed: false, hard: false });
  });

  it("refuses allowlist CIDRs overlapping a translation prefix and malformed prefixes at boot", () => {
    expect(() => parseAllowedCidrs("fd00::/8", true, prefixes)).toThrow(/translation prefix/);
    expect(() => parseAllowedCidrs("fd12:3456:789a:bcde::1/128", true, prefixes)).toThrow(
      /translation prefix/,
    );
    expect(parseAllowedCidrs("fd99::/16", true, prefixes)).toHaveLength(1);
    for (const bad of ["fd12::/72", "10.0.0.0/8", "fd12::", "nonsense"])
      expect(() => parseTranslationPrefixes(bad), bad).toThrow(/WEBHOOK_TRANSLATION_PREFIXES/);
  });
});
