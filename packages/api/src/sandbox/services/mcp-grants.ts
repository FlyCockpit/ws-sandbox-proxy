import { ORPCError } from "@orpc/server";
import prisma from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { withAuthorityChange } from "@wssp/db/authority";
import { z } from "zod";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../../lib/pagination";
import { entityId } from "../../lib/schemas";
import { serviceProcedure } from "../../lib/sdk-key-access";
import { notifyCapacityChanged } from "../capacity-queue-wake";
import type { Principal } from "../contracts";

export const listMcpGrantsInput = cursorPageInput.extend({
  includeRevoked: z.boolean().default(false),
});
export const revokeMcpGrantInput = z.object({ id: entityId });
/** Auth binds refresh-token revocation here; the grant and key are already inactive. */
let revokeTokens: (userId: string, clientId: string) => Promise<void> = async () => {};
export function bindMcpGrantTokenRevocation(hook: typeof revokeTokens): void {
  revokeTokens = hook;
}
export const listMcpGrants = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof listMcpGrantsInput>) => {
    const result = listMcpGrantsInput.safeParse(input);
    if (!result.success)
      throw new ORPCError("BAD_REQUEST", { message: "Invalid OAuth grant list input." });
    const parsed = result.data;
    const rows = await prisma.mcpGrant.findMany({
      where: withCursor(
        { userId: owner.ownerId, ...(parsed.includeRevoked ? {} : { revokedAt: null }) },
        "createdAt",
        parsed.cursor,
        "desc",
      ),
      take: pageTake(parsed.limit),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      select: {
        id: true,
        clientId: true,
        createdAt: true,
        revokedAt: true,
        SdkKey: {
          select: {
            id: true,
            name: true,
            scopes: true,
            resourceMode: true,
            poolMode: true,
            ownSandboxesOnly: true,
            expiresAt: true,
            lastUsedAt: true,
          },
        },
      },
    });
    return cursorPage(rows, parsed.limit, "createdAt");
  },
);
export const revokeMcpGrant = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof revokeMcpGrantInput>) => {
    const grant = await prisma.mcpGrant.findFirst({
      where: { id: input.id, userId: owner.ownerId },
      select: { sdkKeyId: true, clientId: true },
    });
    if (!grant) throw new ORPCError("NOT_FOUND");
    await withAuthorityChange({ ownerId: owner.ownerId, credentialId: grant.sdkKeyId }, () =>
      prisma.$transaction(async (tx) => {
        await lockOwnerForAdmission(tx, owner.ownerId);
        const now = new Date();
        await tx.mcpGrant.updateMany({
          where: { id: input.id, userId: owner.ownerId, revokedAt: null },
          data: { revokedAt: now },
        });
        await tx.sdkKey.updateMany({
          where: {
            id: grant.sdkKeyId,
            userId: owner.ownerId,
            kind: "OAUTH_GRANT",
            revokedAt: null,
          },
          data: { revokedAt: now },
        });
      }),
    );
    notifyCapacityChanged("all");
    await revokeTokens(owner.ownerId, grant.clientId);
    return { ok: true as const };
  },
);
