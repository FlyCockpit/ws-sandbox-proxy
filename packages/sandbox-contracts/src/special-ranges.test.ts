import { describe, expect, it } from "vitest";
import cases from "../../../crates/sandbox-protocol/fixtures/egress_policy_cases.json";
import { cidrContains, cidrsIntersect, type ParsedCidr, parseCidr, parseIpAddress } from "./ip";
import {
  HARD_DENIED,
  intersectsSandboxProtectedV4,
  normalizeCidrSetV4,
  SANDBOX_PROTECTED_V4,
  SANDBOX_PUBLIC_V4,
  SPECIAL_PURPOSE_V4,
  sandboxProtectedV4Address,
  subtractCidrsV4,
} from "./special-ranges";

const texts = (cidrs: readonly ParsedCidr[]) => cidrs.map((cidr) => cidr.text);
const start = (c: ParsedCidr) => (c.groups[0] as number) * 0x10000 + (c.groups[1] as number);
const size = (c: ParsedCidr) => 2 ** (32 - c.prefix);

describe("sandbox protected set", () => {
  it("is the computed union of the webhook special-purpose and hard-denied IPv4 tables", () => {
    const hardV4 = HARD_DENIED.filter((cidr) => cidr.family === 4);
    expect(texts(SANDBOX_PROTECTED_V4)).toEqual(
      texts(normalizeCidrSetV4([...SPECIAL_PURPOSE_V4, ...hardV4])),
    );
    // Every member of either table is covered; nothing else is added.
    for (const cidr of [...SPECIAL_PURPOSE_V4, ...hardV4])
      expect(SANDBOX_PROTECTED_V4.some((range) => cidrContains(range, cidr))).toBe(true);
    for (const range of SANDBOX_PROTECTED_V4)
      expect([...SPECIAL_PURPOSE_V4, ...hardV4].some((c) => c.text === range.text)).toBe(true);
  });

  it("today the union adds exactly the Azure wireserver to the special-purpose list", () => {
    const added = texts(SANDBOX_PROTECTED_V4).filter(
      (text) => !texts(SPECIAL_PURPOSE_V4).includes(text),
    );
    expect(added).toEqual(["168.63.129.16/32"]);
    expect(SANDBOX_PROTECTED_V4).toHaveLength(SPECIAL_PURPOSE_V4.length + 1);
  });

  it("matches the shared fixture tables", () => {
    expect(texts(SPECIAL_PURPOSE_V4)).toEqual(cases.specialPurposeV4);
    expect(texts(HARD_DENIED.filter((c) => c.family === 4))).toEqual(cases.hardDeniedV4);
    expect(texts(SANDBOX_PROTECTED_V4)).toEqual(cases.sandboxProtectedV4);
    expect(texts(SANDBOX_PUBLIC_V4)).toEqual(cases.sandboxPublicV4);
  });

  it.each(cases.protectedVerdicts.map((v) => [v.address, v.protected] as const))(
    "address verdict %s → %s",
    (address, isProtected) => {
      const parsed = parseIpAddress(address);
      if (!parsed) throw new Error(address);
      expect(sandboxProtectedV4Address(parsed)).toBe(isProtected);
      expect(intersectsSandboxProtectedV4(parsed)).toBe(isProtected);
    },
  );

  it("never classifies IPv6 as protected-v4 (IPv6 grants are refused separately)", () => {
    expect(intersectsSandboxProtectedV4(parseCidr("::/0"))).toBe(false);
  });
});

describe("public complement", () => {
  it("partitions 0.0.0.0/0 exactly with the protected set", () => {
    const all = [...SANDBOX_PUBLIC_V4, ...SANDBOX_PROTECTED_V4].sort((a, b) => start(a) - start(b));
    let cursor = 0;
    for (const cidr of all) {
      expect(start(cidr)).toBe(cursor);
      cursor += size(cidr);
    }
    expect(cursor).toBe(2 ** 32);
    for (const pub of SANDBOX_PUBLIC_V4)
      for (const prot of SANDBOX_PROTECTED_V4) expect(cidrsIntersect(pub, prot)).toBe(false);
  });

  it("is minimal: no two public prefixes are mergeable siblings", () => {
    const sorted = [...SANDBOX_PUBLIC_V4].sort((a, b) => start(a) - start(b));
    for (let i = 1; i < sorted.length; i += 1) {
      const a = sorted[i - 1] as ParsedCidr;
      const b = sorted[i] as ParsedCidr;
      const siblings =
        a.prefix === b.prefix && start(a) % (2 * size(a)) === 0 && start(b) === start(a) + size(a);
      expect(siblings).toBe(false);
    }
  });
});

describe("subtraction", () => {
  it.each(cases.subtractions.map((s) => [s.cidr, s] as const))("%s minus fixture", (_c, s) => {
    expect(
      texts(
        subtractCidrsV4(
          parseCidr(s.cidr),
          s.remove.map((r) => parseCidr(r)),
        ),
      ),
    ).toEqual(s.result);
  });

  it("refuses IPv6 operands", () => {
    expect(() => subtractCidrsV4(parseCidr("::/0"), [])).toThrow();
    expect(() => normalizeCidrSetV4([parseCidr("::/0")])).toThrow();
  });
});
