import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "test-better-auth-secret" },
}));

const {
  CREDENTIAL_HMAC_CONTEXTS,
  PRODUCT_CREDENTIAL_PREFIXES,
  PRODUCT_CREDENTIAL_SECRET_BYTES,
  PRODUCT_CREDENTIAL_SUFFIX_LENGTH,
  credentialLookupPrefix,
  generateProductCredentialSecret,
  hmacDigestForProductPurpose,
  parseDeviceCredentialSecret,
  parseHostTokenCredential,
  parseSdkKeyCredentialSecret,
  resolveProductCredentialPurpose,
  verifyProductCredentialDigest,
} = await import("./credential-security");

const PURPOSE_PARSERS = {
  hostToken: parseHostTokenCredential,
  deviceCredential: parseDeviceCredentialSecret,
  sdkKey: parseSdkKeyCredentialSecret,
} as const;

describe("credentialSecurity", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("generates purpose-prefixed secrets with 32 bytes of entropy", () => {
    for (const purpose of Object.keys(PRODUCT_CREDENTIAL_PREFIXES) as Array<
      keyof typeof PRODUCT_CREDENTIAL_PREFIXES
    >) {
      const credential = generateProductCredentialSecret(purpose);
      expect(credential.raw.startsWith(PRODUCT_CREDENTIAL_PREFIXES[purpose])).toBe(true);
      const randomPart = credential.raw.slice(PRODUCT_CREDENTIAL_PREFIXES[purpose].length);
      expect(randomPart).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(randomPart).toHaveLength(PRODUCT_CREDENTIAL_SUFFIX_LENGTH);
      expect(Buffer.from(randomPart, "base64url")).toHaveLength(PRODUCT_CREDENTIAL_SECRET_BYTES);
    }
  });

  it("derives lookup prefixes only from parsed credentials", () => {
    const credential = generateProductCredentialSecret("hostToken");
    expect(credentialLookupPrefix(credential)).toBe(
      credential.raw.slice(0, PRODUCT_CREDENTIAL_PREFIXES.hostToken.length + 12),
    );
  });

  it("uses distinct purpose-derived HMAC keys so cross-purpose verification fails", () => {
    const credential = generateProductCredentialSecret("hostToken");
    const hostDigest = hmacDigestForProductPurpose({
      purpose: "hostToken",
      value: credential.raw,
    });
    expect(
      verifyProductCredentialDigest({
        purpose: "hostToken",
        value: credential.raw,
        digest: hostDigest,
      }),
    ).toBe(true);
    expect(
      verifyProductCredentialDigest({
        purpose: "deviceCredential",
        value: credential.raw,
        digest: hostDigest,
      }),
    ).toBe(false);
    expect(
      verifyProductCredentialDigest({
        purpose: "sdkKey",
        value: credential.raw,
        digest: hostDigest,
      }),
    ).toBe(false);
  });

  it("rejects malformed digests with constant-time length guard", () => {
    const credential = generateProductCredentialSecret("sdkKey");
    const digest = hmacDigestForProductPurpose({ purpose: "sdkKey", value: credential.raw });
    expect(
      verifyProductCredentialDigest({
        purpose: "sdkKey",
        value: credential.raw,
        digest: digest.slice(0, -1),
      }),
    ).toBe(false);
  });

  it("invalidates all digests when BETTER_AUTH_SECRET changes", () => {
    const credential = generateProductCredentialSecret("deviceCredential");
    const digest = hmacDigestForProductPurpose({
      purpose: "deviceCredential",
      value: credential.raw,
      betterAuthSecret: "original-secret",
    });
    expect(
      verifyProductCredentialDigest({
        purpose: "deviceCredential",
        value: credential.raw,
        digest,
        betterAuthSecret: "rotated-secret",
      }),
    ).toBe(false);
  });

  it("snapshots HMAC context strings for host, device, and SDK purposes", () => {
    expect(CREDENTIAL_HMAC_CONTEXTS).toMatchInlineSnapshot(`
      {
        "deviceCredential": "wssp:device-credential:v1",
        "hostToken": "wssp:host-token:v1",
        "sdkKey": "wssp:sdk-key:v1",
      }
    `);
    expect(PRODUCT_CREDENTIAL_PREFIXES).toMatchInlineSnapshot(`
      {
        "deviceCredential": "wssp_device_",
        "hostToken": "wssp_host_",
        "sdkKey": "wssp_sdk_",
      }
    `);
  });

  it("resolves product credential purposes only for fully valid secrets", () => {
    const host = generateProductCredentialSecret("hostToken");
    expect(resolveProductCredentialPurpose(host.raw)).toBe("hostToken");
    expect(resolveProductCredentialPurpose("wsmp_cli_legacy")).toBeNull();
    expect(resolveProductCredentialPurpose(PRODUCT_CREDENTIAL_PREFIXES.hostToken)).toBeNull();
  });

  describe.each(Object.keys(PURPOSE_PARSERS) as Array<keyof typeof PURPOSE_PARSERS>)(
    "parseProductCredential (%s)",
    (purpose) => {
      const prefix = PRODUCT_CREDENTIAL_PREFIXES[purpose];
      const parse = PURPOSE_PARSERS[purpose];
      const validSuffix = "A".repeat(PRODUCT_CREDENTIAL_SUFFIX_LENGTH);

      it("accepts the exact generated format", () => {
        const parsed = parse(`${prefix}${validSuffix}`);
        expect(parsed?.purpose).toBe(purpose);
        expect(parsed?.raw).toBe(`${prefix}${validSuffix}`);
      });

      it("rejects prefix-only, short, long, padded, spaced, unicode, and invalid alphabet input", () => {
        const cases = [
          prefix,
          `${prefix}${"a".repeat(PRODUCT_CREDENTIAL_SUFFIX_LENGTH - 1)}`,
          `${prefix}${"a".repeat(PRODUCT_CREDENTIAL_SUFFIX_LENGTH + 1)}`,
          `${prefix}${"A".repeat(PRODUCT_CREDENTIAL_SUFFIX_LENGTH - 1)}=`,
          `${prefix}${"A".repeat(20)} ${"A".repeat(22)}`,
          `${prefix}${"A".repeat(20)}é${"A".repeat(21)}`,
          `${prefix}${"A".repeat(20)}@${"A".repeat(21)}`,
        ];
        for (const candidate of cases) {
          expect(parse(candidate)).toBeNull();
        }
      });
    },
  );
});
