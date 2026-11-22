import { ORPCError } from "@orpc/server";
import { getSignupEnabled, SIGNUP_SETTING_KEY } from "@wssp/auth/signup-policy";
import { FORCE_2FA_DEFAULTS } from "@wssp/auth/two-factor-policy";
import prisma from "@wssp/db";
import { env } from "@wssp/env/server";
import { isEmailConfigured } from "@wssp/mailer";
import { OUTPUT_HEAD_BYTES, OUTPUT_RETENTION_MS, OUTPUT_TAIL_BYTES } from "@wssp/sandbox-contracts";
import { z } from "zod";
import {
  adminOr404Procedure,
  adminWriteProcedure,
  authenticatedProcedure,
  protectedProcedure,
} from "../index";
import { ADMIN_ERROR_CODES } from "../lib/admin-error-codes";
import { loadSensitiveSessionGateUser } from "../lib/sensitive-session-two-factor-gate";
import { FORCE_2FA_SETTING_KEYS } from "../lib/two-factor-policy";
import { sessionPrincipal } from "../sandbox";
import { SANDBOX_COMMAND_PAYLOAD_MAX_BYTES } from "../sandbox/command-payload";
import {
  SANDBOX_COMMAND_TIMEOUT_DEFAULT_MS,
  SANDBOX_COMMAND_TIMEOUT_MAX_MS,
} from "../sandbox/contracts";
import {
  CONSUMED_GRACE_SETTING_KEY,
  consumedGraceSeconds,
  consumedGraceValueSchema,
} from "../sandbox/disk-offload/settings";
import { imageDistributionMode } from "../sandbox/image-store/config";
import {
  getAccountImagePolicy,
  setAccountImagePolicy,
  setImagePolicyInput,
} from "../sandbox/image-store/settings";
import { deploymentLeaseMaxMs } from "../sandbox/lease-policy";

// Leak-prevention boundary: only keys listed here are exposed to clients via getAll; future settings must be explicitly opted in.
const CLIENT_READABLE_SETTING_KEYS: readonly string[] = FORCE_2FA_SETTING_KEYS;
const booleanSettingKeySchema = z.enum([SIGNUP_SETTING_KEY, ...FORCE_2FA_SETTING_KEYS]);
/**
 * Per-key value schema: the boolean keys take "true" | "false"; the offload
 * consumed grace takes a decimal integer string of seconds
 * in [0, 604800], validated again on read (`consumedGraceSeconds`). It is
 * admin-only and never client-readable.
 */
const settingUpdateInput = z.union([
  z.object({ key: booleanSettingKeySchema, value: z.enum(["true", "false"]) }),
  z.object({ key: z.literal(CONSUMED_GRACE_SETTING_KEY), value: consumedGraceValueSchema }),
]);

export const settingsRouter = {
  adminGet: adminOr404Procedure.handler(async () => {
    // Read and range-checked through its own reader (default + warning).
    const offloadConsumedGraceSeconds = await consumedGraceSeconds(prisma);
    const rows = await prisma.appSetting.findMany({
      where: { key: { in: [...FORCE_2FA_SETTING_KEYS] } },
      take: FORCE_2FA_SETTING_KEYS.length, // pagination:audited — fixed key set
      select: { key: true, value: true },
    });
    const values = new Map(rows.map((row) => [row.key, row.value]));
    return {
      signupEnabled: await getSignupEnabled(),
      force2faPublicUsers:
        (values.get("force2faPublicUsers") ?? String(FORCE_2FA_DEFAULTS.force2faPublicUsers)) ===
        "true",
      force2faInternalUsers:
        (values.get("force2faInternalUsers") ??
          String(FORCE_2FA_DEFAULTS.force2faInternalUsers)) === "true",
      offloadConsumedGraceSeconds,
      // Where template images and offloaded disks live ("off" | "peer" | "s3"),
      // for the overview's deployment setup card. The mode only: no bucket,
      // endpoint or key ever leaves the server.
      imageStoreMode: imageDistributionMode(),
      limits: {
        commandPayloadMaxBytes: SANDBOX_COMMAND_PAYLOAD_MAX_BYTES,
        commandTimeoutDefaultMs: SANDBOX_COMMAND_TIMEOUT_DEFAULT_MS,
        commandTimeoutMaxMs: SANDBOX_COMMAND_TIMEOUT_MAX_MS,
        outputMaxBytes: OUTPUT_HEAD_BYTES + OUTPUT_TAIL_BYTES,
        outputRetentionMs: OUTPUT_RETENTION_MS,
        transferMaxBytes: env.TRANSFER_MAX_BYTES,
        transferDiskBytes: env.TRANSFER_DISK_BYTES,
        transferOwnerActive: env.TRANSFER_OWNER_ACTIVE,
        transferGlobalActive: env.TRANSFER_GLOBAL_ACTIVE,
        transferIdleSeconds: env.TRANSFER_IDLE_SECONDS,
        transferAbsoluteSeconds: env.TRANSFER_ABSOLUTE_SECONDS,
        // Deployment layer of the lease policy; null = unlimited (operator env).
        sandboxLeaseMaxMs: deploymentLeaseMaxMs(),
      },
    };
  }),
  getAll: authenticatedProcedure.handler(async () => {
    const settings = await prisma.appSetting.findMany({
      where: { key: { in: [...CLIENT_READABLE_SETTING_KEYS] } },
      // pagination:audited — bounded by the compile-time settings key list
      take: CLIENT_READABLE_SETTING_KEYS.length,
      select: { key: true, value: true },
    });
    return Object.fromEntries(settings.map((s) => [s.key, s.value]));
  }),

  /** Account image placement default, store quotas and usage. */
  imagePolicy: protectedProcedure.handler(({ context }) =>
    getAccountImagePolicy(sessionPrincipal(context.session.user.id), undefined),
  ),
  setImagePolicy: protectedProcedure
    .input(setImagePolicyInput)
    .handler(({ input, context }) =>
      setAccountImagePolicy(sessionPrincipal(context.session.user.id), input),
    ),

  myNotificationPreferences: authenticatedProcedure.handler(async ({ context }) => {
    const user = await prisma.user.findUnique({
      where: { id: context.session.user.id },
      select: { operationalAlerts: true },
    });
    return {
      operationalAlerts: user?.operationalAlerts ?? true,
    };
  }),

  updateMyNotificationPreferences: authenticatedProcedure
    .input(
      z.object({
        operationalAlerts: z.boolean(),
      }),
    )
    .handler(async ({ input, context }) => {
      await prisma.user.update({
        where: { id: context.session.user.id },
        data: { operationalAlerts: input.operationalAlerts },
      });
      return { success: true };
    }),

  update: adminWriteProcedure.input(settingUpdateInput).handler(async ({ input, context }) => {
    // Strict by design: an admin must secure their own account before
    // requiring 2FA for either public users or internal/admin users.
    if (input.key !== SIGNUP_SETTING_KEY && input.value === "true") {
      const owner = await loadSensitiveSessionGateUser(context.session.user.id, context.adminTx);
      if (!owner?.twoFactorEnabled) {
        throw new ORPCError("FORBIDDEN", {
          message: "You must enable 2FA for your own account before requiring it for others",
          data: { code: ADMIN_ERROR_CODES.ownTwoFactorRequired },
        });
      }
    }

    if (input.key === SIGNUP_SETTING_KEY && input.value === "true" && !isEmailConfigured()) {
      throw new ORPCError("PRECONDITION_FAILED", {
        message: "Sign-up requires email delivery (SMTP) to send verification email.",
        data: { code: ADMIN_ERROR_CODES.signupEmailRequired },
      });
    }

    await context.adminTx.appSetting.upsert({
      where: { key: input.key },
      update: { value: input.value },
      create: { key: input.key, value: input.value },
    });

    return { success: true };
  }),
};
