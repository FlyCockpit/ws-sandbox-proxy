import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { env } from "@wssp/env/server";

export const PRODUCT_CREDENTIAL_SECRET_BYTES = 32;

/** Unpadded base64url encoding of exactly 32 bytes (43 characters). */
export const PRODUCT_CREDENTIAL_SUFFIX_LENGTH = 43;

const PRODUCT_CREDENTIAL_SUFFIX_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export const PRODUCT_CREDENTIAL_PREFIXES = {
  hostToken: "wssp_host_",
  deviceCredential: "wssp_device_",
  sdkKey: "wssp_sdk_",
} as const;

export const CREDENTIAL_HMAC_CONTEXTS = {
  hostToken: "wssp:host-token:v1",
  deviceCredential: "wssp:device-credential:v1",
  sdkKey: "wssp:sdk-key:v1",
} as const;

export type ProductCredentialPurpose = keyof typeof PRODUCT_CREDENTIAL_PREFIXES;

const LOOKUP_VISIBLE_RANDOM_CHARS = 12;

declare const parsedProductCredentialBrand: unique symbol;

export type ParsedProductCredential<P extends ProductCredentialPurpose = ProductCredentialPurpose> =
  {
    readonly [parsedProductCredentialBrand]: true;
    readonly purpose: P;
    readonly raw: string;
  };

export type ParsedHostTokenCredential = ParsedProductCredential<"hostToken">;
export type ParsedDeviceCredential = ParsedProductCredential<"deviceCredential">;
export type ParsedSdkKeyCredential = ParsedProductCredential<"sdkKey">;

function parseProductCredentialForPurpose<P extends ProductCredentialPurpose>(
  purpose: P,
  raw: string,
): ParsedProductCredential<P> | null {
  const prefix = PRODUCT_CREDENTIAL_PREFIXES[purpose];
  if (raw.length !== prefix.length + PRODUCT_CREDENTIAL_SUFFIX_LENGTH) {
    return null;
  }
  if (!raw.startsWith(prefix)) {
    return null;
  }
  const suffix = raw.slice(prefix.length);
  if (!PRODUCT_CREDENTIAL_SUFFIX_PATTERN.test(suffix)) {
    return null;
  }
  return { purpose, raw } as ParsedProductCredential<P>;
}

export function parseHostTokenCredential(raw: string): ParsedHostTokenCredential | null {
  return parseProductCredentialForPurpose("hostToken", raw);
}

export function parseDeviceCredentialSecret(raw: string): ParsedDeviceCredential | null {
  return parseProductCredentialForPurpose("deviceCredential", raw);
}

export function parseSdkKeyCredentialSecret(raw: string): ParsedSdkKeyCredential | null {
  return parseProductCredentialForPurpose("sdkKey", raw);
}

export function generateProductCredentialSecret<P extends ProductCredentialPurpose>(
  purpose: P,
): ParsedProductCredential<P> {
  const prefix = PRODUCT_CREDENTIAL_PREFIXES[purpose];
  const raw = `${prefix}${randomBytes(PRODUCT_CREDENTIAL_SECRET_BYTES).toString("base64url")}`;
  const parsed = parseProductCredentialForPurpose(purpose, raw);
  if (!parsed) {
    throw new Error("generated product credential failed format self-check");
  }
  return parsed;
}

export function resolveProductCredentialPurpose(secret: string): ProductCredentialPurpose | null {
  for (const purpose of Object.keys(PRODUCT_CREDENTIAL_PREFIXES) as ProductCredentialPurpose[]) {
    if (parseProductCredentialForPurpose(purpose, secret)) {
      return purpose;
    }
  }
  return null;
}

export function credentialLookupPrefix(credential: ParsedProductCredential): string {
  const prefix = PRODUCT_CREDENTIAL_PREFIXES[credential.purpose];
  return credential.raw.slice(0, prefix.length + LOOKUP_VISIBLE_RANDOM_CHARS);
}

function derivePurposeKey(purpose: ProductCredentialPurpose, betterAuthSecret: string): Buffer {
  return createHmac("sha256", Buffer.from(betterAuthSecret, "utf8"))
    .update(CREDENTIAL_HMAC_CONTEXTS[purpose])
    .digest();
}

export function hmacDigestForProductPurpose({
  purpose,
  value,
  betterAuthSecret = env.BETTER_AUTH_SECRET,
}: {
  purpose: ProductCredentialPurpose;
  value: string;
  betterAuthSecret?: string;
}): string {
  return createHmac("sha256", derivePurposeKey(purpose, betterAuthSecret))
    .update(value)
    .digest("base64url");
}

export function verifyProductCredentialDigest({
  purpose,
  value,
  digest,
  betterAuthSecret = env.BETTER_AUTH_SECRET,
}: {
  purpose: ProductCredentialPurpose;
  value: string;
  digest: string;
  betterAuthSecret?: string;
}): boolean {
  const candidate = hmacDigestForProductPurpose({ purpose, value, betterAuthSecret });
  const candidateBuffer = Buffer.from(candidate, "utf8");
  const digestBuffer = Buffer.from(digest, "utf8");
  return (
    candidateBuffer.length === digestBuffer.length && timingSafeEqual(candidateBuffer, digestBuffer)
  );
}
