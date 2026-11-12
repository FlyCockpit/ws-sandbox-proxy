import { protectedProcedure } from "../index";
import { sessionPrincipal } from "../sandbox";
import { consumeSandboxWriteBudget } from "../sandbox/budgets";
import {
  createTemplateInput,
  listTemplatesInput,
  sandboxIdInput,
  templateIdInput,
} from "../sandbox/contracts";
import {
  getTemplateImageSettings,
  pruneNowInput,
  pruneTemplateNow,
  publishRevisionInput,
  publishTemplateRevision,
  updateImageSettingsInput,
  updateTemplateImageSettings,
} from "../sandbox/image-store/settings";
import {
  appendTemplateRevision,
  associateTemplateAvailability,
  createTemplate,
  getTemplate,
  getTemplateRevision,
  listRevisionChoices,
  listTemplateAvailability,
  listTemplateRevisions,
  listTemplates,
  retireTemplate,
  retireTemplateRevision,
  setTemplateTag,
} from "../sandbox/services/templates";
import {
  appendRevisionInput,
  associateAvailabilityInput,
  listAvailabilityInput,
  listRevisionsInput,
  revisionChoicesInput,
  setTemplateTagInput,
} from "../sandbox/template-input";
import { rethrowLaunchInputValidationError } from "../sandbox/vm-size-input";

export const sandboxTemplatesRouter = {
  getImageSettings: protectedProcedure
    .input(pruneNowInput)
    .handler(({ input, context }) =>
      getTemplateImageSettings(sessionPrincipal(context.session.user.id), input),
    ),
  /** Placement, captureKeep, pruneAfterDays, extra scrub paths ("image" budget). */
  updateImageSettings: protectedProcedure
    .input(updateImageSettingsInput)
    .handler(({ input, context }) =>
      updateTemplateImageSettings(sessionPrincipal(context.session.user.id), input),
    ),
  /** Publish to the image store now (S3 mode; "image" budget). */
  publishRevision: protectedProcedure
    .input(publishRevisionInput)
    .handler(({ input, context }) =>
      publishTemplateRevision(sessionPrincipal(context.session.user.id), input),
    ),
  /** Retire untagged revisions outside retention now ("image" budget). */
  pruneNow: protectedProcedure
    .input(pruneNowInput)
    .handler(({ input, context }) =>
      pruneTemplateNow(sessionPrincipal(context.session.user.id), input),
    ),
  retireRevision: protectedProcedure
    .input(templateIdInput)
    .handler(({ input, context }) =>
      retireTemplateRevision(sessionPrincipal(context.session.user.id), input),
    ),
  listRevisionChoices: protectedProcedure
    .input(revisionChoicesInput)
    .handler(({ input, context }) =>
      listRevisionChoices(sessionPrincipal(context.session.user.id), input),
    ),
  getTemplateRevision: protectedProcedure
    .input(templateIdInput)
    .handler(({ input, context }) =>
      getTemplateRevision(sessionPrincipal(context.session.user.id), input),
    ),
  listRevisions: protectedProcedure
    .input(listRevisionsInput)
    .handler(({ input, context }) =>
      listTemplateRevisions(sessionPrincipal(context.session.user.id), input),
    ),
  listAvailability: protectedProcedure
    .input(listAvailabilityInput)
    .handler(({ input, context }) =>
      listTemplateAvailability(sessionPrincipal(context.session.user.id), input),
    ),
  appendRevision: protectedProcedure
    .use(async ({ next }) => {
      try {
        return await next();
      } catch (error) {
        rethrowLaunchInputValidationError(error);
        throw error;
      }
    })
    .input(appendRevisionInput)
    .handler(async ({ input, context }) => {
      await consumeSandboxWriteBudget(context.session.user.id, "template");
      return appendTemplateRevision(sessionPrincipal(context.session.user.id), input);
    }),
  associateAvailability: protectedProcedure
    .input(associateAvailabilityInput)
    .handler(async ({ input, context }) => {
      await consumeSandboxWriteBudget(context.session.user.id, "template");
      return associateTemplateAvailability(sessionPrincipal(context.session.user.id), input);
    }),
  setTag: protectedProcedure
    .input(setTemplateTagInput)
    .handler(({ input, context }) =>
      setTemplateTag(sessionPrincipal(context.session.user.id), input),
    ),

  retireTemplate: protectedProcedure.input(sandboxIdInput).handler(async ({ input, context }) => {
    return retireTemplate(sessionPrincipal(context.session.user.id), input);
  }),
  listTemplates: protectedProcedure
    .input(listTemplatesInput)
    .handler(async ({ input, context }) => {
      return listTemplates(sessionPrincipal(context.session.user.id), input);
    }),
  getTemplate: protectedProcedure.input(templateIdInput).handler(async ({ input, context }) => {
    return getTemplate(sessionPrincipal(context.session.user.id), input);
  }),

  createTemplate: protectedProcedure
    .use(async ({ next }) => {
      try {
        return await next();
      } catch (error) {
        rethrowLaunchInputValidationError(error);
        throw error;
      }
    })
    .input(createTemplateInput)
    .handler(async ({ input, context }) => {
      await consumeSandboxWriteBudget(context.session.user.id, "template");
      return createTemplate(sessionPrincipal(context.session.user.id), input);
    }),
};
