import { templateBuildCreateFieldsSchema, validTemplateBuildCreate } from "@wssp/sandbox-contracts";
import { TEMPLATE_TAG_PATTERN } from "@wssp/template-recipe";
import { z } from "zod";
import { protectedProcedure } from "../index";
import { sessionPrincipal } from "../sandbox";
import { idempotencyKey } from "../sandbox/contracts";
import {
  cancelTemplateBuild,
  createTemplateBuild,
  getTemplateBuild,
  getTemplateBuildFailureTail,
  getTemplateBuildLogs,
  getTemplateBuildUsage,
  listTemplateBuilds,
  listTemplateBuildsInput,
  templateBuildIdInput,
  templateBuildInputFromBody,
  templateBuildLogsInput,
  toTemplateBuildDto,
  withTemplateNames,
} from "../template-builds/views";

/** One build with its template's display name (browser pages show names). */
async function named<
  T extends { templateId: string; revisionId?: string | null; cacheHitRevisionId?: string | null },
>(ownerId: string, build: T) {
  const [out] = await withTemplateNames(ownerId, [build]);
  return out as T & {
    templateName: string | null;
    templateSlug: string | null;
    revisionNumber: number | null;
  };
}

/** The browser create: the `/v1` body, plus any tag (sessions may name one, I5). */
const createTemplateBuildSessionInput = templateBuildCreateFieldsSchema
  .extend({
    idempotencyKey,
    tag: z.string().max(63).regex(TEMPLATE_TAG_PATTERN).optional(),
  })
  .refine(validTemplateBuildCreate, "Send one recipe source and one placement target.");

/**
 * Browser plane for template builds. Every entry
 * calls the shared `serviceProcedure` services with the session principal;
 * acceptance and cancel spend the owner's "build" budget inside the service.
 * A COPY build's context is uploaded through the dashboard context routes
 * (`/api/dashboard/template-builds/:id/context…`), which re-open the staged
 * upload idempotently, so `create` returns `needsContext` instead of a handle.
 */
export const templateBuildsRouter = {
  create: protectedProcedure
    .input(createTemplateBuildSessionInput)
    .handler(async ({ input, context }) => {
      const { idempotencyKey: key, ...body } = input;
      const accepted = await createTemplateBuild(
        sessionPrincipal(context.session.user.id),
        templateBuildInputFromBody(body, key),
      );
      return {
        build: await named(context.session.user.id, toTemplateBuildDto(accepted.build)),
        joined: accepted.joined,
        cacheHit: accepted.cacheHit,
        needsContext: accepted.needsContext,
      };
    }),
  get: protectedProcedure
    .input(templateBuildIdInput)
    .handler(async ({ input, context }) =>
      named(
        context.session.user.id,
        await getTemplateBuild(sessionPrincipal(context.session.user.id), input),
      ),
    ),
  list: protectedProcedure.input(listTemplateBuildsInput).handler(async ({ input, context }) => {
    const page = await listTemplateBuilds(sessionPrincipal(context.session.user.id), input);
    return {
      ...page,
      items: await withTemplateNames(context.session.user.id, page.items),
    };
  }),
  cancel: protectedProcedure
    .input(templateBuildIdInput)
    .handler(async ({ input, context }) =>
      named(
        context.session.user.id,
        toTemplateBuildDto(
          await cancelTemplateBuild(sessionPrincipal(context.session.user.id), input),
        ),
      ),
    ),
  logs: protectedProcedure
    .input(templateBuildLogsInput)
    .handler(({ input, context }) =>
      getTemplateBuildLogs(sessionPrincipal(context.session.user.id), input),
    ),
  /** Owner-only output tail of a failed step (kept beyond output retention). */
  failureTail: protectedProcedure
    .input(templateBuildIdInput)
    .handler(({ input, context }) =>
      getTemplateBuildFailureTail(sessionPrincipal(context.session.user.id), input),
    ),
  /** Availability, quotas and usage for the dashboard (build button, settings card). */
  usage: protectedProcedure.handler(({ context }) =>
    getTemplateBuildUsage(sessionPrincipal(context.session.user.id), undefined),
  ),
};
