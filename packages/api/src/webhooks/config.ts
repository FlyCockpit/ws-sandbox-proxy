import { sharedVars } from "@wssp/env/vars/shared";
import { deriveSubkeys, readDataKeyring } from "../crypto/data-key";
import { WEBHOOK_SECRET_PURPOSE, type WebhookSecretKey } from "./crypto";
import {
  parseAllowedCidrs,
  parseAllowedHosts,
  parseTranslationPrefixes,
  type WebhookAllowlist,
} from "./destination-policy";

/**
 * Webhook runtime configuration, from worker-safe (shared) vars only:
 * the worker validates nothing server-only, so this module must never import
 * `@wssp/env/server`. Without `DATA_ENCRYPTION_KEY` the feature is off: no
 * `/v1/capabilities` feature, `UNSUPPORTED_CAPABILITY` from every entry point,
 * and the worker records `not_configured` instead of counting failures.
 */
export type WebhookConfig = {
  /** Webhook sub-keys of the current root (first; encrypts) and previous root (decrypts). */
  keys: readonly WebhookSecretKey[];
  current: WebhookSecretKey;
  allowlist: WebhookAllowlist;
  privateScope: "admins" | "all";
  deliveryConcurrency: number;
};

let cached: WebhookConfig | null | undefined;

const WEBHOOK_VARS = {
  NODE_ENV: sharedVars.NODE_ENV,
  WEBHOOK_ALLOWED_PRIVATE_CIDRS: sharedVars.WEBHOOK_ALLOWED_PRIVATE_CIDRS,
  WEBHOOK_ALLOWED_PRIVATE_HOSTS: sharedVars.WEBHOOK_ALLOWED_PRIVATE_HOSTS,
  WEBHOOK_TRANSLATION_PREFIXES: sharedVars.WEBHOOK_TRANSLATION_PREFIXES,
  WEBHOOK_PRIVATE_ALLOWLIST_SCOPE: sharedVars.WEBHOOK_PRIVATE_ALLOWLIST_SCOPE,
  WEBHOOK_ALLOW_PLAINTEXT_PRIVATE: sharedVars.WEBHOOK_ALLOW_PLAINTEXT_PRIVATE,
  WEBHOOK_DELIVERY_CONCURRENCY: sharedVars.WEBHOOK_DELIVERY_CONCURRENCY,
};

/**
 * Parsed on first use with the SAME declarations `@wssp/env/shared` validates
 * at process boot (`packages/env/src/vars/shared.ts`), so importing the router
 * graph never triggers env validation (unit tests import it freely). Empty
 * strings are unset, as in `createEnv({ emptyStringAsUndefined: true })`.
 * Values are never logged.
 */
function readWebhookEnv() {
  const value = (name: keyof typeof WEBHOOK_VARS) => {
    const raw = process.env[name];
    return raw === "" ? undefined : raw;
  };
  const out = {} as {
    [K in keyof typeof WEBHOOK_VARS]: ReturnType<(typeof WEBHOOK_VARS)[K]["parse"]>;
  };
  for (const name of Object.keys(WEBHOOK_VARS) as (keyof typeof WEBHOOK_VARS)[]) {
    const parsed = WEBHOOK_VARS[name].safeParse(value(name));
    if (!parsed.success) throw new Error(`${name} is invalid.`);
    (out as Record<string, unknown>)[name] = parsed.data;
  }
  return out;
}

/** Parse and validate once. Throws on an invalid allowlist (boot failure). */
export function loadWebhookConfig(): WebhookConfig | null {
  if (cached !== undefined) return cached;
  const env = readWebhookEnv();
  const production = env.NODE_ENV === "production";
  const translationPrefixes = parseTranslationPrefixes(env.WEBHOOK_TRANSLATION_PREFIXES);
  const allowlist: WebhookAllowlist = {
    cidrs: parseAllowedCidrs(env.WEBHOOK_ALLOWED_PRIVATE_CIDRS, production, translationPrefixes),
    translationPrefixes,
    hosts: parseAllowedHosts(env.WEBHOOK_ALLOWED_PRIVATE_HOSTS),
    allowPlaintext: env.WEBHOOK_ALLOW_PLAINTEXT_PRIVATE,
    allowLoopback: !production,
  };
  const ring = readDataKeyring();
  if (!ring) {
    cached = null;
    return cached;
  }
  const { current, all } = deriveSubkeys(ring, WEBHOOK_SECRET_PURPOSE);
  cached = {
    current,
    keys: all,
    allowlist,
    privateScope: env.WEBHOOK_PRIVATE_ALLOWLIST_SCOPE,
    deliveryConcurrency: env.WEBHOOK_DELIVERY_CONCURRENCY,
  };
  return cached;
}

export function webhooksConfigured(): boolean {
  return loadWebhookConfig() !== null;
}

/** Test seam only. */
export function resetWebhookConfigForTests(): void {
  cached = undefined;
}
