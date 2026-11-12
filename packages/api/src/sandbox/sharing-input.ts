import { z } from "zod";
import { entityId } from "../lib/schemas";
import { leaseMaxInput, memberPercentInput, shareCapsInput } from "./pool-input";

export const inviteTokenInput = z.string().regex(/^wssp_inv_[A-Za-z0-9_-]{43}$/);
export const shareSettingsInput = shareCapsInput.extend({
  canUse: z.boolean().default(true),
  canContribute: z.boolean().default(true),
});
export const grantPoolShareInput = shareSettingsInput
  .extend({
    poolId: entityId,
    email: z
      .string()
      .trim()
      .toLowerCase()
      .pipe(z.email().max(320))
      .refine((email) => new TextEncoder().encode(email).byteLength <= 320),
    signupAllowed: z.boolean().default(false),
  })
  .strict();
export const updatePoolShareInput = shareSettingsInput
  .extend({ poolId: entityId, granteeUserId: entityId })
  .strict();
export const revokePoolShareInput = z
  .object({ poolId: entityId, granteeUserId: entityId })
  .strict();
export const leavePoolInput = z.object({ poolId: entityId }).strict();
export const poolInviteInput = z.object({ poolId: entityId, inviteId: entityId }).strict();
export const acceptPoolInviteInput = z
  .object({ token: z.string().max(256), mode: z.enum(["bearer", "email"]) })
  .strict();
export const contributePoolHostInput = z
  .object({
    poolId: entityId,
    sandboxHostId: entityId,
    enabled: z.boolean().default(true),
    memoryCapPercent: memberPercentInput.default(null),
    vcpuCapPercent: memberPercentInput.default(null),
    /** Host owner's lease maximum for this membership; omitted = unchanged. */
    maxLeaseMs: leaseMaxInput.optional(),
  })
  .strict();
