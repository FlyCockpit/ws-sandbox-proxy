import { ORPCError } from "@orpc/server";
import { hostSlugFromDeviceLoginScope, isValidHostSlug } from "@wssp/config/host-device-login";
import prisma from "@wssp/db";
import { z } from "zod";
import { ownerDeviceProcedure, publicProcedure } from "../index";
import { deviceRequestKind, userCodeCandidates } from "../lib/device-code-transitions";
import { consumeDeviceExchangeBudget } from "../lib/device-exchange-budget";
import { mintHostDeviceCredentialFromApprovedDeviceCode } from "../lib/host-device-credential-access";

const hostSlugSchema = z
  .string()
  .min(1)
  .max(63)
  .refine((value) => isValidHostSlug(value), {
    message: "Host slug must use lowercase letters, numbers, and hyphens only.",
  });

export const hostCredentialsRouter = {
  exchangeDeviceCode: publicProcedure
    .input(
      z.object({
        deviceCode: z.string().trim().min(1).max(512),
        hostSlug: hostSlugSchema,
      }),
    )
    .handler(async ({ input, context }) => {
      await consumeDeviceExchangeBudget(context.clientIp);
      const minted = await mintHostDeviceCredentialFromApprovedDeviceCode({
        deviceCode: input.deviceCode,
        hostSlug: input.hostSlug,
      });
      return {
        credentialId: minted.credentialId,
        userId: minted.userId,
        hostId: minted.hostId,
        secret: minted.secret,
      };
    }),

  deviceLoginRequest: ownerDeviceProcedure
    .input(z.object({ userCode: z.string().trim().min(1).max(191) }))
    .handler(async ({ input, context }) => {
      const userId = context.session.user.id;
      const row = await prisma.deviceCode.findFirst({
        where: { userCode: { in: userCodeCandidates(input.userCode) }, userId },
        select: { id: true, status: true, expiresAt: true, scope: true },
      });
      if (!row || row.expiresAt <= new Date()) {
        throw new ORPCError("NOT_FOUND", { message: "Device login request not found." });
      }
      // The stored scope decides what the page shows. A user login carries
      // nothing the CLI chose: the approver picks the whole grant on the page.
      const kind = deviceRequestKind(row.scope);
      if (kind === "user") return { kind, requestId: row.id, status: row.status } as const;
      const slug = hostSlugFromDeviceLoginScope(row.scope);
      if (kind !== "host" || slug === null) {
        throw new ORPCError("BAD_REQUEST", {
          message: "This device login request does not name a host slug; upgrade wssp.",
        });
      }
      const host = await prisma.sandboxHost.findUnique({
        where: { userId_slug: { userId, slug } },
        select: { id: true, slug: true, label: true },
      });
      return {
        kind,
        requestId: row.id,
        status: row.status,
        slug,
        existingHost: host ? { id: host.id, slug: host.slug, label: host.label } : null,
      };
    }),
};
