/** Server-only OTP evidence, using exactly the plugin's public crypto/OTP exports. */
import { timingSafeEqual } from "node:crypto";
import { createOTP } from "@better-auth/utils/otp";
import type { TerminalFactor } from "@wssp/db/terminal-proof";
import { type SecretConfig, symmetricDecrypt } from "better-auth/crypto";

export async function matchedTotpSteps(
  factor: TerminalFactor,
  code: string,
  key: string | SecretConfig,
  at: number,
): Promise<number[]> {
  const secret = await symmetricDecrypt({ key, data: factor.secret });
  const otp = createOTP(secret, { digits: 6, period: 30 });
  const k = Math.floor(at / 30_000);
  const counters = [k - 1, k, k + 1].filter((counter) => counter >= 0);
  const codes = await Promise.all(counters.map((counter) => otp.hotp(counter)));
  // Compare EVERY candidate, including the rare equal-code adjacent steps.
  const candidate = Buffer.from(/^\d{6}$/.test(code) ? code : "------");
  return counters.filter((_, i) => timingSafeEqual(candidate, Buffer.from(codes[i]!)));
}

export function hasSessionCookies(headers: Headers): boolean {
  return (headers.get("cookie") ?? "")
    .split(";")
    .some((pair) =>
      /^(?:__Secure-|__Host-)?(?:better-auth|better_auth)\.session_(?:token|data)(?:\.\d+)?$/.test(
        pair.trim().split("=", 1)[0] ?? "",
      ),
    );
}
