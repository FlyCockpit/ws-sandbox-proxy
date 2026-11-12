import prisma, { type Prisma } from "@wssp/db";
import type {
  CommunityTemplateCreateBody,
  CommunityTemplateCreatedDto,
} from "@wssp/sandbox-contracts";
import type { Principal } from "../../sandbox/contracts";
import { toTemplateDto } from "../../sandbox/sdk-reads";
import { toTemplateBuildDto } from "../views";
import { createCommunityTemplateService } from "./procedures";

/** The template DTO fields of the `/v1` community answer (a disclosure boundary). */
const communityTemplateSelect = {
  id: true,
  slug: true,
  label: true,
  archivedAt: true,
  createdAt: true,
  updatedAt: true,
  imagePlacement: true,
  captureKeep: true,
  pruneAfterDays: true,
  communitySource: true,
  communityRefresh: true,
} satisfies Prisma.SandboxTemplateSelect;

/**
 * `POST /v1/templates/community` (S11): the shared create service, then the
 * created (or joined) template as its public DTO. The service already
 * authorized the key (`templates:build` + `templates:write`, no allowlist),
 * so the template is read by owner and id, not through `templates:read`.
 */
export async function createCommunityTemplateForSdk(
  principal: Principal,
  body: CommunityTemplateCreateBody,
  idempotencyKey: string,
): Promise<CommunityTemplateCreatedDto> {
  const target =
    body.sandboxHostId !== undefined
      ? { sandboxHostId: body.sandboxHostId }
      : { poolId: body.poolId ?? "" };
  const result = await createCommunityTemplateService(principal, {
    source: body.source,
    idempotencyKey,
    target,
    ...(body.label === undefined ? {} : { label: body.label }),
  });
  const row = await prisma.sandboxTemplate.findFirstOrThrow({
    where: { id: result.template.id, userId: principal.ownerId },
    select: communityTemplateSelect,
  });
  return {
    template: toTemplateDto(row),
    build: result.build ? toTemplateBuildDto(result.build) : null,
    existing: result.existing,
  };
}
