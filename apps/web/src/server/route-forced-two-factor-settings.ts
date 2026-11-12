import { createServerFn } from "@tanstack/react-start";

import type { ForcedTwoFactorSettings } from "@/utils/two-factor-policy";

/**
 * Loads force-2FA AppSetting rows through the same server helper the oRPC
 * admin gates use (`getForcedTwoFactorSettingsRecord`), for route `beforeLoad`
 * decisions that must match procedure enforcement.
 */
export const getRouteForcedTwoFactorSettings = createServerFn({ method: "GET" }).handler(
  async (): Promise<ForcedTwoFactorSettings> => {
    const { getForcedTwoFactorSettingsRecord } = await import("@wssp/api/lib/two-factor-policy");
    return getForcedTwoFactorSettingsRecord();
  },
);
