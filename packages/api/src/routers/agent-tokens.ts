import { env } from "@wssp/env/server";
import { liveOwnerSessionProcedure, protectedProcedure } from "../index";
import { sessionPrincipal } from "../sandbox/contracts";
import {
  createAgentToken,
  createAgentTokenInput,
  listAgentTokens,
  listAgentTokensInput,
  revokeAgentToken,
  revokeAgentTokenInput,
} from "../sandbox/services/agent-tokens";

export const agentTokensRouter = {
  expiryPolicy: protectedProcedure.handler(() => ({
    allowNoExpiry: env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY,
    maxLifetimeDays: env.WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS,
  })),
  create: liveOwnerSessionProcedure
    .input(createAgentTokenInput)
    .handler(({ input, context }) =>
      createAgentToken(sessionPrincipal(context.session.user.id), input),
    ),
  list: protectedProcedure
    .input(listAgentTokensInput)
    .handler(({ input, context }) =>
      listAgentTokens(sessionPrincipal(context.session.user.id), input),
    ),
  revoke: protectedProcedure
    .input(revokeAgentTokenInput)
    .handler(({ input, context }) =>
      revokeAgentToken(sessionPrincipal(context.session.user.id), input),
    ),
};
