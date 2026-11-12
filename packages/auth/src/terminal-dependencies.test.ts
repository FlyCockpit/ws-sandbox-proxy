import { createRequire } from "node:module";
import { createOTP } from "@better-auth/utils/otp";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import { describe, expect, it } from "vitest";

describe("T1 approved dependency exports and locked plugin parity", () => {
  it("resolves the same OTP export as Better Auth, with RFC 4226 counters", async () => {
    const require = createRequire(import.meta.url);
    const pluginRequire = createRequire(require.resolve("better-auth"));
    expect(require.resolve("@better-auth/utils/otp")).toBe(
      pluginRequire.resolve("@better-auth/utils/otp"),
    );
    // RFC 4226's public test key, never a product credential.
    const otp = createOTP("12345678901234567890", { digits: 6, period: 30 });
    const expected = [
      "755224",
      "287082",
      "359152",
      "969429",
      "338314",
      "254676",
      "287922",
      "162583",
      "399871",
      "520489",
    ];
    expect(await Promise.all(expected.map((_, counter) => otp.hotp(counter)))).toEqual(expected);
  });
  it("uses the public crypto exports without a package-internal import", async () => {
    const key = "public-test-only-crypto-key-32-chars";
    const data = "public-test-factor";
    expect(await symmetricDecrypt({ key, data: await symmetricEncrypt({ key, data }) })).toBe(data);
  });
});
