import { z } from "zod";
import { publicProcedure } from "../index";
import { consumeDeviceExchangeBudget } from "../lib/device-exchange-budget";
import { mintUserLoginFromApprovedDeviceCode } from "../lib/user-login-credential-access";

export const userLoginsRouter = {
  /**
   * `wssp login`: redeem an approved `user-login` device code for the `/v1`
   * key the approver chose. Public like the host exchange (the device code is
   * the credential) and charged to the same per-IP exchange budget.
   */
  exchangeDeviceCode: publicProcedure
    .input(z.object({ deviceCode: z.string().trim().min(1).max(512) }))
    .handler(async ({ input, context }) => {
      await consumeDeviceExchangeBudget(context.clientIp);
      const minted = await mintUserLoginFromApprovedDeviceCode({ deviceCode: input.deviceCode });
      return {
        keyId: minted.keyId,
        secret: minted.secret,
        name: minted.name,
        userId: minted.userId,
        email: minted.email,
        scopes: minted.scopes,
        poolMode: minted.poolMode,
        poolIds: minted.poolIds,
        ownSandboxesOnly: minted.ownSandboxesOnly,
        expiresAt: minted.expiresAt,
        maxLiveSandboxes: minted.maxLiveSandboxes,
      };
    }),
};
