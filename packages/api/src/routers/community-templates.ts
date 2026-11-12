import { z } from "zod";
import { protectedProcedure } from "../index";
import { sessionPrincipal } from "../sandbox";
import { idempotencyKey } from "../sandbox/contracts";
import {
  createCommunityTemplateService,
  refreshCommunityTemplateService,
  retryCommunityTemplateService,
  setCommunityRefreshService,
} from "../template-builds/community/procedures";
import { listCommunityImages } from "../template-builds/community/service";
import { toTemplateBuildDto, withTemplateNames } from "../template-builds/views";

const entityId = z.string().min(1).max(128);
const targetInput = z.union([
  z.strictObject({ poolId: entityId }),
  z.strictObject({ sandboxHostId: entityId }),
]);

/** A community result with its build as the dashboard DTO (template name added). */
async function present(
  ownerId: string,
  result: Awaited<ReturnType<typeof createCommunityTemplateService>>,
) {
  const build = result.build
    ? (await withTemplateNames(ownerId, [toTemplateBuildDto(result.build)]))[0]
    : null;
  return { template: result.template, build: build ?? null, existing: result.existing };
}

/**
 * Browser plane for community base templates (community-base S8, S12). Every
 * entry calls the shared service procedures with the session principal; the
 * services spend the owner's "build" budget (the switch: "template").
 */
export const communityTemplatesRouter = {
  /** The tested catalog entries and why creation is disabled, if it is. */
  images: protectedProcedure.handler(() => listCommunityImages()),
  create: protectedProcedure
    .input(
      z.strictObject({
        source: z.string().min(1).max(64),
        idempotencyKey,
        target: targetInput,
        label: z.string().trim().min(1).max(100).optional(),
      }),
    )
    .handler(async ({ input, context }) =>
      present(
        context.session.user.id,
        await createCommunityTemplateService(sessionPrincipal(context.session.user.id), input),
      ),
    ),
  /** "Try again" after a failed or cancelled prep build. */
  retry: protectedProcedure
    .input(z.strictObject({ templateId: entityId, idempotencyKey, target: targetInput.optional() }))
    .handler(async ({ input, context }) =>
      present(
        context.session.user.id,
        await retryCommunityTemplateService(sessionPrincipal(context.session.user.id), input),
      ),
    ),
  /** "Refresh now": always available; bypasses the 7-day minimum. */
  refresh: protectedProcedure
    .input(z.strictObject({ templateId: entityId, idempotencyKey }))
    .handler(async ({ input, context }) => {
      const outcome = await refreshCommunityTemplateService(
        sessionPrincipal(context.session.user.id),
        input,
      );
      if ("template" in outcome)
        return { kind: "started" as const, ...(await present(context.session.user.id, outcome)) };
      return outcome;
    }),
  setRefresh: protectedProcedure
    .input(z.strictObject({ templateId: entityId, refresh: z.boolean() }))
    .handler(({ input, context }) =>
      setCommunityRefreshService(sessionPrincipal(context.session.user.id), input),
    ),
};
