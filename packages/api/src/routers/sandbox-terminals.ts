import {
  BROWSER_TERMINAL_SUBPROTOCOL,
  BROWSER_TERMINAL_SUBPROTOCOL_V2,
  BROWSER_TERMINAL_TICKET_PROTOCOL_PREFIX,
  browserTerminalPath,
} from "@wssp/config/browser-terminal";
import { liveOwnerSessionProcedure } from "../index";
import { consumeTerminalMintBudget } from "../sandbox/terminal-budgets";
import { createTerminalSessionInput, mintTerminalTicket } from "../sandbox/terminal-tickets";

/**
 * Browser terminal sessions (C53). Cookie session only: the oRPC surface strips
 * `Authorization`, so SDK and host credentials never reach this procedure.
 */
export const sandboxTerminalsRouter = {
  /**
   * Mint a one-use upgrade ticket for the caller's own READY sandbox. With
   * `resume` (v2 only) the ticket reattaches a detached terminal; the same
   * mint budget applies (each reattach attempt costs one point, WP8).
   */
  createSession: liveOwnerSessionProcedure
    .input(createTerminalSessionInput)
    .handler(async ({ input, context }) => {
      await consumeTerminalMintBudget(`uid:${context.session.user.id}`);
      const { ticket, expiresAt } = await mintTerminalTicket(
        { userId: context.session.user.id, sessionId: context.session.session.id },
        input,
      );
      return {
        path: browserTerminalPath(input.sandboxId),
        // Offer both, in this order: `new WebSocket(url, protocols)`. The
        // server selects only the first; the ticket is never echoed.
        protocols: [
          input.version === 2 ? BROWSER_TERMINAL_SUBPROTOCOL_V2 : BROWSER_TERMINAL_SUBPROTOCOL,
          `${BROWSER_TERMINAL_TICKET_PROTOCOL_PREFIX}${ticket}`,
        ],
        expiresAt,
      };
    }),
};
