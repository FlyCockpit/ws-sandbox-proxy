import {
  FORCE_2FA_SETTING_KEYS,
  type ForceTwoFactorSettingKey,
  forcedTwoFactorSettingKeyForRole,
  isForcedTwoFactorEnabled,
  isTwoFactorRequirementSatisfied,
  type TwoFactorPolicyUser,
} from "@wssp/auth/two-factor-policy";
import prisma, { type Prisma } from "@wssp/db";

// The keys, the absent-row defaults, and the grace window live in
// `@wssp/auth/two-factor-policy` so the browser mirror
// (`apps/web/src/utils/two-factor-policy.ts`) reads the same literals. This
// module adds only the database read and its cache.
export { FORCE_2FA_SETTING_KEYS } from "@wssp/auth/two-factor-policy";

// In-process TTL cache for the force-2FA settings. `requireAdminOr404` /
// `requireRequiredTwoFactor` consult this on nearly every protected call, so
// hitting Postgres each time is pure overhead for a value that changes only
// when an admin flips the setting. The settings write path bumps
// `forceTwoFactorCacheGeneration` and clears the published entry; reads record
// the generation at start and publish only when it is unchanged so an older
// read cannot repopulate after invalidation. Other processes converge within
// the TTL.
const FORCE_2FA_CACHE_TTL_MS = 60_000;

let forceTwoFactorCacheGeneration = 0;
let forceTwoFactorCache: {
  generation: number;
  byKey: Map<string, string>;
  expiresAt: number;
} | null = null;

async function readForceTwoFactorSettings(db: Pick<Prisma.TransactionClient, "appSetting">) {
  return db.appSetting.findMany({
    where: {
      key: {
        in: [...FORCE_2FA_SETTING_KEYS],
      },
    },
    select: { key: true, value: true },
    // pagination:audited — bounded by the compile-time settings key list
    take: FORCE_2FA_SETTING_KEYS.length,
  });
}

async function loadForceTwoFactorSettings(): Promise<Map<string, string>> {
  const now = Date.now();
  if (forceTwoFactorCache && forceTwoFactorCache.expiresAt > now) {
    return forceTwoFactorCache.byKey;
  }
  const readGeneration = forceTwoFactorCacheGeneration;
  const settings = await readForceTwoFactorSettings(prisma);
  if (readGeneration !== forceTwoFactorCacheGeneration) {
    return loadForceTwoFactorSettings();
  }
  const byKey = new Map(settings.map((setting) => [setting.key, setting.value]));
  forceTwoFactorCache = {
    generation: readGeneration,
    byKey,
    expiresAt: now + FORCE_2FA_CACHE_TTL_MS,
  };
  return byKey;
}

/** Drop the cached settings — call after any AppSetting write to these keys (and from test setup). */
export function invalidateForceTwoFactorSettingsCache(): void {
  forceTwoFactorCacheGeneration += 1;
  forceTwoFactorCache = null;
}

export type ForcedTwoFactorSettingsRecord = Partial<
  Record<ForceTwoFactorSettingKey, string | undefined>
>;

/** Production settings load for route gates and other server-side policy mirrors. */
export async function getForcedTwoFactorSettingsRecord(
  db?: Pick<Prisma.TransactionClient, "appSetting">,
): Promise<ForcedTwoFactorSettingsRecord> {
  // Interactive transactions must use their own connection, bypassing the global cache/client.
  if (db)
    return Object.fromEntries(
      (await readForceTwoFactorSettings(db)).map(({ key, value }) => [key, value]),
    );
  const byKey = await loadForceTwoFactorSettings();
  return Object.fromEntries(byKey) as ForcedTwoFactorSettingsRecord;
}

/**
 * Is forced 2FA on for this role? An absent AppSetting row resolves to
 * `FORCE_2FA_DEFAULTS` — which means **on** for internal (admin) users.
 */
export async function isForcedTwoFactorEnabledForRole(role: unknown): Promise<boolean> {
  const targetKey = forcedTwoFactorSettingKeyForRole(role);
  const byKey = await loadForceTwoFactorSettings();

  return isForcedTwoFactorEnabled(targetKey, byKey.get(targetKey));
}

/**
 * The gate every server-side caller uses. Pass the whole session user — the
 * `createdAt` field is load-bearing, because an unenrolled user inside the
 * enrollment grace window still satisfies the policy. A missing or unreadable
 * `createdAt` means no grace (fail closed).
 */
export async function isTwoFactorPolicySatisfied(
  user: TwoFactorPolicyUser & { role?: unknown },
): Promise<boolean> {
  if (user.twoFactorEnabled) return true;
  const forced = await isForcedTwoFactorEnabledForRole(user.role);
  return isTwoFactorRequirementSatisfied(user, forced);
}
