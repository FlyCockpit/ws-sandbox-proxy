import { createOTP } from "@better-auth/utils/otp";
import { symmetricEncrypt } from "better-auth/crypto";
import { expect, it, vi } from "vitest";

vi.mock("@better-auth/utils/otp", async (original) => {
  const actual = await original<typeof import("@better-auth/utils/otp")>();
  return { ...actual, createOTP: vi.fn(actual.createOTP) };
});

import { hasSessionCookies, matchedTotpSteps } from "./terminal-proof";

it("RFC/plugin counters and adjacent windows produce ephemeral step evidence only", async () => {
  const key = "public-factor-test-key-at-least-32-characters",
    secret = "12345678901234567890";
  const factor = {
    id: "factor",
    userId: "owner",
    secret: await symmetricEncrypt({ key, data: secret }),
    verified: true,
    lockedUntil: null,
  };
  const otp = createOTP(secret, { digits: 6, period: 30 });
  for (const step of [99, 100, 101]) {
    const code = await otp.hotp(step);
    expect(await matchedTotpSteps(factor, code, key, 100 * 30000)).toContain(step);
    expect(await matchedTotpSteps(factor, code, key, (step + 3) * 30000)).toEqual([]);
  }
  expect(await matchedTotpSteps(factor, "invalid", key, 3000000)).toEqual([]);
});
it("recognizes empty/secure/chunked cookie presence without confusing real challenge cookies", () => {
  for (const cookie of [
    "better-auth.session_token=",
    "__Secure-better-auth.session_data.0=bad",
    "__Host-better-auth.session_token=x",
    "better-auth.session_data=",
  ])
    expect(hasSessionCookies(new Headers({ cookie }))).toBe(true);
  expect(hasSessionCookies(new Headers({ cookie: "better-auth.two_factor=real-challenge" }))).toBe(
    false,
  );
});

it("returns every matching adjacent step, including equal-code collisions", async () => {
  const key = "public-equal-code-factor-key-32-characters";
  const factor = {
    id: "equal-factor",
    userId: "owner",
    secret: await symmetricEncrypt({ key, data: "public-test" }),
    verified: true,
    lockedUntil: null,
  };
  const otp = createOTP("public-test");
  const hotp = vi.fn(async (counter: number) => (counter === 101 ? "654321" : "123456"));
  vi.mocked(createOTP).mockReturnValueOnce({ ...otp, hotp });
  expect(await matchedTotpSteps(factor, "123456", key, 3000000)).toEqual([99, 100]);
  expect(hotp.mock.calls).toEqual([[99], [100], [101]]);
});
