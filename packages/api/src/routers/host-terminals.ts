import {
  BROWSER_TERMINAL_SUBPROTOCOL,
  HOST_TERMINAL_TICKET_PROTOCOL_PREFIX,
  hostTerminalPath,
} from "@wssp/config/browser-terminal";
import { liveOwnerSessionProcedure } from "../index";
import { hostIdInput } from "../sandbox/contracts";
import {
  createHostTerminalSessionInput,
  mintHostTerminalTicket,
  raiseHostTerminalTotp,
} from "../sandbox/host-terminal-tickets";

export const hostTerminalsRouter = {
  createSession: liveOwnerSessionProcedure
    .input(createHostTerminalSessionInput)
    .handler(async ({ input, context }) => {
      const { ticket, expiresAt } = await mintHostTerminalTicket(
        {
          userId: context.session.user.id,
          sessionId: context.session.session.id,
        },
        input,
      );
      return {
        path: hostTerminalPath(input.hostId),
        protocols: [
          BROWSER_TERMINAL_SUBPROTOCOL,
          `${HOST_TERMINAL_TICKET_PROTOCOL_PREFIX}${ticket}`,
        ],
        expiresAt,
      };
    }),
  raiseHostTerminalTotp: liveOwnerSessionProcedure
    .input(hostIdInput)
    .handler(async ({ input, context }) => {
      return raiseHostTerminalTotp(
        { userId: context.session.user.id, sessionId: context.session.session.id },
        input,
      );
    }),
};
