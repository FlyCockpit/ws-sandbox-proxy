import { liveOwnerSessionProcedure, protectedProcedure } from "../index";
import { sessionPrincipal } from "../sandbox/contracts";
import {
  dismissQueuedHostCommand,
  listQueuedHostCommands,
  listQueuedHostCommandsInput,
  queuedHostCommandIdInput,
  runQueuedHostCommand,
} from "../sandbox/services/host-queued";
export const hostQueuedCommandsRouter = {
  list: protectedProcedure
    .input(listQueuedHostCommandsInput)
    .handler(({ input, context }) =>
      listQueuedHostCommands(sessionPrincipal(context.session.user.id), input),
    ),
  run: liveOwnerSessionProcedure
    .input(queuedHostCommandIdInput)
    .handler(({ input, context }) =>
      runQueuedHostCommand(sessionPrincipal(context.session.user.id), input),
    ),
  dismiss: liveOwnerSessionProcedure
    .input(queuedHostCommandIdInput)
    .handler(({ input, context }) =>
      dismissQueuedHostCommand(sessionPrincipal(context.session.user.id), input),
    ),
};
