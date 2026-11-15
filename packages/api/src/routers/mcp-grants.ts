import { protectedProcedure } from "../index";
import { sessionPrincipal } from "../sandbox/contracts";
import {
  listMcpGrants,
  listMcpGrantsInput,
  revokeMcpGrant,
  revokeMcpGrantInput,
} from "../sandbox/services/mcp-grants";
export const mcpGrantsRouter = {
  list: protectedProcedure
    .input(listMcpGrantsInput)
    .handler(({ input, context }) =>
      listMcpGrants(sessionPrincipal(context.session.user.id), input),
    ),
  revoke: protectedProcedure
    .input(revokeMcpGrantInput)
    .handler(({ input, context }) =>
      revokeMcpGrant(sessionPrincipal(context.session.user.id), input),
    ),
};
