import { ORPCError } from "@orpc/server";
import type { Prisma } from "@wssp/db";

/**
 * Community templates are wssp-managed (community-base D-G): only the
 * community create, retry and refresh paths write revisions, builds or tags
 * into them. Every other writer (a user build, a capture, a registration, a
 * tag move) is refused with `template.community_managed`. Retire and archive
 * stay available to the owner (D-L).
 */
export function communityManaged(): ORPCError<"CONFLICT", { code: "template.community_managed" }> {
  return new ORPCError("CONFLICT", {
    message: "This community template is managed by wssp.",
    data: { code: "template.community_managed" },
  });
}

/** Refuse a user write into `templateId` when it is a community template. */
export async function refuseCommunityWrite(
  tx: Pick<Prisma.TransactionClient, "sandboxTemplate">,
  ownerId: string,
  templateId: string,
): Promise<void> {
  const row = await tx.sandboxTemplate.findFirst({
    where: { id: templateId, userId: ownerId },
    select: { communitySource: true },
  });
  if (row?.communitySource) throw communityManaged();
}
