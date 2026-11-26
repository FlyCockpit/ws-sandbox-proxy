import { ORPCError } from "@orpc/server";
import { z } from "zod";
import { liveOwnerSessionProcedure } from "../index";
import { endLiveTerminal, listHostTargets, listLiveTerminals } from "../sandbox/live-terminals";
import { consumeTerminalEndBudget } from "../sandbox/terminal-budgets";

const liveTerminalIdInput = z.object({ id: z.string().regex(/^bt_[0-9a-f]{32}$/) }).strict();

/**
 * The Terminals page: the caller's own live browser terminals, on their
 * sandboxes and hosts. Cookie session only, never SDK/MCP (person-only).
 * Owner-scoped for everyone, admins included: no cross-owner listing.
 */
export const terminalsRouter = {
  list: liveOwnerSessionProcedure.handler(async ({ context }) =>
    listLiveTerminals({
      userId: context.session.user.id,
      sessionId: context.session.session.id,
    }),
  ),
  /** The picker's hosts: the caller's own, with whether a host terminal can open now. */
  hostTargets: liveOwnerSessionProcedure.handler(async ({ context }) =>
    listHostTargets({ userId: context.session.user.id }),
  ),
  /** End one live terminal (its PTY closes; the other tab is told why). */
  end: liveOwnerSessionProcedure.input(liveTerminalIdInput).handler(async ({ input, context }) => {
    // Per user and per procedure: one /rpc request can batch many ends.
    await consumeTerminalEndBudget(`uid:${context.session.user.id}`);
    // One answer for "gone" and "not yours": it reveals nothing about others.
    if (!(await endLiveTerminal({ userId: context.session.user.id }, input.id)))
      throw new ORPCError("NOT_FOUND", {
        message: "This terminal is no longer open.",
        data: { code: "terminal.not_found" },
      });
    return { ended: true as const };
  }),
};
