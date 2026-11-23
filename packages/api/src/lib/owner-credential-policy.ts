import { isUserBanned } from "@wssp/auth/ban";
import {
  forcedTwoFactorSettingKeyForRole,
  isForcedTwoFactorEnabled,
  isTwoFactorRequirementSatisfied,
  type TwoFactorPolicyUser,
} from "@wssp/auth/two-factor-policy";
import type { Prisma } from "@wssp/db";

import {
  type ForcedTwoFactorSettingsRecord,
  isTwoFactorPolicySatisfied,
} from "./two-factor-policy";

/** Owner fields required for SDK keys, host tokens, and any future product credential plane. */
export const ownerCredentialPolicyUserSelect = {
  deletionRequestedAt: true,
  banned: true,
  banExpires: true,
  twoFactorEnabled: true,
  createdAt: true,
  role: true,
  mustChangePassword: true,
} satisfies Prisma.UserSelect;

export type OwnerCredentialPolicyUser = Prisma.UserGetPayload<{
  select: typeof ownerCredentialPolicyUserSelect;
}>;

/**
 * Shared owner boundary for product credential authentication: active (not
 * banned under ban-expiry semantics) and satisfying applicable enrollment policy.
 */
export async function isOwnerCredentialPolicySatisfied(
  user: OwnerCredentialPolicyUser,
  now = new Date(),
  settings?: ForcedTwoFactorSettingsRecord,
): Promise<boolean> {
  if (user.deletionRequestedAt || isUserBanned(user, now)) {
    return false;
  }
  // An admin-set temporary password is replaced before anything else.
  if (user.mustChangePassword) return false;
  if (settings) {
    const key = forcedTwoFactorSettingKeyForRole(user.role);
    return isTwoFactorRequirementSatisfied(
      user,
      isForcedTwoFactorEnabled(key, settings[key]),
      now.getTime(),
    );
  }
  return isTwoFactorPolicySatisfied(user satisfies TwoFactorPolicyUser & { role?: unknown });
}
