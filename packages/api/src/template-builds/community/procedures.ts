import { serviceProcedure } from "../../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../../sandbox/budgets";
import type { Principal } from "../../sandbox/contracts";
import { budgetSubjectOf } from "../../sandbox/principal-kinds";
import {
  createCommunityTemplate,
  refreshCommunityTemplate,
  retryCommunityTemplate,
  setCommunityRefresh,
} from "./service";

/**
 * The community entry points of both planes (session, or an SDK key with
 * `templates:build` and `templates:write`). Kept apart from the service so
 * the build modules that call the service (rebuild on miss) never load the
 * rate limiter.
 */
/** The owner's "build" budget (acceptance-class requests, §7). */
async function consumeBuild(principal: Principal) {
  const subject = budgetSubjectOf(principal);
  if (subject) await consumeSandboxWriteBudget(subject.ownerId, "build");
}

/** Entry points for both planes (session, or a key with `templates:build`
 * plus `templates:write`); each spends one "build" budget point. */
export const createCommunityTemplateService = serviceProcedure(
  { action: "templates.build" },
  async (principal: Principal, input: Parameters<typeof createCommunityTemplate>[1]) => {
    await consumeBuild(principal);
    return createCommunityTemplate(principal, input);
  },
);
export const retryCommunityTemplateService = serviceProcedure(
  { action: "templates.build" },
  async (principal: Principal, input: Parameters<typeof retryCommunityTemplate>[1]) => {
    await consumeBuild(principal);
    return retryCommunityTemplate(principal, input);
  },
);
export const refreshCommunityTemplateService = serviceProcedure(
  { action: "templates.build" },
  async (principal: Principal, input: Parameters<typeof refreshCommunityTemplate>[1]) => {
    await consumeBuild(principal);
    return refreshCommunityTemplate(principal, input);
  },
);
/** The refresh switch spends the "template" budget (a settings write). */
export const setCommunityRefreshService = serviceProcedure(
  { action: "templates.build" },
  async (principal: Principal, input: Parameters<typeof setCommunityRefresh>[1]) => {
    const subject = budgetSubjectOf(principal);
    if (subject) await consumeSandboxWriteBudget(subject.ownerId, "template");
    return setCommunityRefresh(principal, input);
  },
);
