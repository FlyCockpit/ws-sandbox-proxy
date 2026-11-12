/** Public, deterministic factor fixtures; never use production secrets. */
import { createOTP } from "@better-auth/utils/otp";
import { symmetricEncrypt } from "better-auth/crypto";
export async function encryptTestFactor(key: string, secret: string) {
  return symmetricEncrypt({ key, data: secret });
}
export async function testTotp(secret: string, step = Math.floor(Date.now() / 30000)) {
  return createOTP(secret, { digits: 6, period: 30 }).hotp(step);
}
