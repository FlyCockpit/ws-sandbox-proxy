import { liveOwnerSessionProcedure, protectedProcedure } from "../index";
import { sessionPrincipal } from "../sandbox";
import {
  commandOutputInput,
  connectProcessInput,
  createSandboxInput,
  createSnapshotInput,
  forkSandboxInput,
  killProcessInput,
  killSandboxInput,
  listDirInput,
  listOperationsInput,
  listProcessesInput,
  listSandboxesInput,
  mkdirInput,
  movePathInput,
  operationIdInput,
  readFileInput,
  reconnectSandboxInput,
  removePathInput,
  restoreSnapshotInput,
  runCommandInput,
  sandboxIdInput,
  sendProcessStdinInput,
  setSandboxOffloadPinInput,
  setSandboxTimeoutInput,
  signalProcessInput,
  statPathInput,
  stopSandboxInput,
  updateSandboxInput,
  writeStdinInput,
} from "../sandbox/contracts";
import { setSandboxOffloadPin } from "../sandbox/disk-offload/pin";
import { captureSandbox, captureSessionInput } from "../sandbox/image-store/captures";
import { getOperationResult } from "../sandbox/operation-results";
import { connectProcess } from "../sandbox/process-connect";
import { cancelAction, writeStdinAction } from "../sandbox/process-controls";
import { getSandboxCapabilities, getSandboxLimits } from "../sandbox/services/capabilities";
import { getOperationView, listOperationViews } from "../sandbox/services/operation-views";
import { getSandboxView, listSandboxViews } from "../sandbox/services/sandbox-views";
import {
  cancelOperation,
  createSandbox,
  createSnapshot,
  forkSandbox,
  getCommandOutput,
  getOperation,
  killSandbox,
  listDir,
  listProcesses,
  mkdir,
  movePath,
  probeSandbox,
  readFile,
  reconnectSandbox,
  removePath,
  restoreSnapshot,
  retryRestoreCleanup,
  runCommand,
  setSandboxTimeout,
  signalProcess,
  statPath,
  stopSandbox,
  updateSandbox,
  writeStdin,
} from "../sandbox/services/sandboxes";
import { rethrowLaunchInputValidationError } from "../sandbox/vm-size-input";

export const sandboxesRouter = {
  getOperationResult: liveOwnerSessionProcedure
    .input(operationIdInput)
    .handler(({ input, context }) =>
      getOperationResult(sessionPrincipal(context.session.user.id), input),
    ),
  getSandboxCapabilities: liveOwnerSessionProcedure
    .input(sandboxIdInput)
    .handler(({ input, context }) =>
      getSandboxCapabilities(sessionPrincipal(context.session.user.id), input),
    ),
  connectProcess: liveOwnerSessionProcedure
    .input(connectProcessInput)
    .handler(({ input, context }) =>
      connectProcess(sessionPrincipal(context.session.user.id), input),
    ),
  killProcess: liveOwnerSessionProcedure
    .input(killProcessInput)
    .handler(({ input, context }) =>
      cancelAction(sessionPrincipal(context.session.user.id), input),
    ),
  sendProcessStdin: liveOwnerSessionProcedure
    .input(sendProcessStdinInput)
    .handler(({ input, context }) =>
      writeStdinAction(sessionPrincipal(context.session.user.id), input),
    ),
  getLimits: protectedProcedure.handler(({ context }) =>
    getSandboxLimits(sessionPrincipal(context.session.user.id), undefined),
  ),
  probeSandbox: protectedProcedure.input(sandboxIdInput).handler(async ({ input, context }) => {
    return probeSandbox(sessionPrincipal(context.session.user.id), input);
  }),
  /** Dashboard projection (C47): host summary, template revision, latest lifecycle receipt. */
  list: protectedProcedure.input(listSandboxesInput).handler(async ({ input, context }) => {
    return listSandboxViews(sessionPrincipal(context.session.user.id), input);
  }),

  getSandbox: protectedProcedure.input(sandboxIdInput).handler(async ({ input, context }) => {
    return getSandboxView(sessionPrincipal(context.session.user.id), input);
  }),

  /** Dashboard operation list (C48): status metadata only, filtered by sandbox/state/kind. */
  listOperations: protectedProcedure
    .input(listOperationsInput)
    .handler(async ({ input, context }) => {
      return listOperationViews(sessionPrincipal(context.session.user.id), input);
    }),

  /** Dashboard operation detail (C48): status, typed error, exit code, sandbox/host summary. */
  getOperationView: protectedProcedure
    .input(operationIdInput)
    .handler(async ({ input, context }) => {
      return getOperationView(sessionPrincipal(context.session.user.id), input);
    }),

  getOperation: liveOwnerSessionProcedure
    .input(operationIdInput)
    .handler(async ({ input, context }) => {
      return getOperation(sessionPrincipal(context.session.user.id), input);
    }),

  /** Incremental durable command output: one ≤ 64 KiB page per call (C26). */
  getCommandOutput: liveOwnerSessionProcedure
    .input(commandOutputInput)
    .handler(async ({ input, context }) => {
      return getCommandOutput(sessionPrincipal(context.session.user.id), input);
    }),

  createSandbox: protectedProcedure
    // Input validation runs before the service's policy resolver, so a
    // malformed `egress` shape would otherwise surface as a generic
    // BAD_REQUEST instead of the stable sandbox.egress_policy_invalid code.
    .use(async ({ next }) => {
      try {
        return await next();
      } catch (error) {
        rethrowLaunchInputValidationError(error, { sandboxName: true });
        throw error;
      }
    })
    .input(createSandboxInput)
    .handler(async ({ input, context }) => {
      return createSandbox(sessionPrincipal(context.session.user.id), input);
    }),

  killSandbox: protectedProcedure.input(killSandboxInput).handler(async ({ input, context }) => {
    return killSandbox(sessionPrincipal(context.session.user.id), input);
  }),

  runCommand: liveOwnerSessionProcedure
    .input(runCommandInput)
    .handler(async ({ input, context }) => {
      return runCommand(sessionPrincipal(context.session.user.id), input);
    }),

  /** Queue a GET_FILE capture; poll getOperation, then stream the bytes from
   * `GET /api/dashboard/operations/{id}/content` (C30: no base64 file RPC). */
  readFile: liveOwnerSessionProcedure.input(readFileInput).handler(async ({ input, context }) => {
    return readFile(sessionPrincipal(context.session.user.id), input);
  }),

  reconnectSandbox: protectedProcedure
    .input(reconnectSandboxInput)
    .handler(async ({ input, context }) => {
      return reconnectSandbox(sessionPrincipal(context.session.user.id), input);
    }),

  /** Save as template: any tag over a session (I6); the service spends the "image" budget. */
  captureSandbox: protectedProcedure
    .input(captureSessionInput)
    .handler(({ input, context }) =>
      captureSandbox(sessionPrincipal(context.session.user.id), input),
    ),
  stopSandbox: protectedProcedure.input(stopSandboxInput).handler(async ({ input, context }) => {
    return stopSandbox(sessionPrincipal(context.session.user.id), input);
  }),

  listDir: liveOwnerSessionProcedure.input(listDirInput).handler(async ({ input, context }) => {
    return listDir(sessionPrincipal(context.session.user.id), input);
  }),

  statPath: liveOwnerSessionProcedure.input(statPathInput).handler(async ({ input, context }) => {
    return statPath(sessionPrincipal(context.session.user.id), input);
  }),

  mkdir: liveOwnerSessionProcedure.input(mkdirInput).handler(async ({ input, context }) => {
    return mkdir(sessionPrincipal(context.session.user.id), input);
  }),

  removePath: liveOwnerSessionProcedure
    .input(removePathInput)
    .handler(async ({ input, context }) => {
      return removePath(sessionPrincipal(context.session.user.id), input);
    }),

  movePath: liveOwnerSessionProcedure.input(movePathInput).handler(async ({ input, context }) => {
    return movePath(sessionPrincipal(context.session.user.id), input);
  }),

  createSnapshot: protectedProcedure
    .input(createSnapshotInput)
    .handler(async ({ input, context }) => {
      return createSnapshot(sessionPrincipal(context.session.user.id), input);
    }),

  restoreSnapshot: protectedProcedure
    .input(restoreSnapshotInput)
    .handler(async ({ input, context }) => {
      return restoreSnapshot(sessionPrincipal(context.session.user.id), input);
    }),

  forkSandbox: protectedProcedure.input(forkSandboxInput).handler(async ({ input, context }) => {
    return forkSandbox(sessionPrincipal(context.session.user.id), input);
  }),

  listProcesses: liveOwnerSessionProcedure
    .input(listProcessesInput)
    .handler(async ({ input, context }) => {
      return listProcesses(sessionPrincipal(context.session.user.id), input);
    }),

  signalProcess: liveOwnerSessionProcedure
    .input(signalProcessInput)
    .handler(async ({ input, context }) => {
      return signalProcess(sessionPrincipal(context.session.user.id), input);
    }),

  writeStdin: liveOwnerSessionProcedure
    .input(writeStdinInput)
    .handler(async ({ input, context }) => {
      return writeStdin(sessionPrincipal(context.session.user.id), input);
    }),

  setSandboxTimeout: protectedProcedure
    .input(setSandboxTimeoutInput)
    .handler(async ({ input, context }) => {
      return setSandboxTimeout(sessionPrincipal(context.session.user.id), input);
    }),

  /** Rename. The service charges the ordinary budget and checks the name. */
  updateSandbox: protectedProcedure
    .input(updateSandboxInput)
    .handler(async ({ input, context }) => {
      return updateSandbox(sessionPrincipal(context.session.user.id), input);
    }),

  /** re-queue a pending restore cleanup. Session only. */
  retryCleanup: protectedProcedure.input(sandboxIdInput).handler(async ({ input, context }) => {
    return retryRestoreCleanup(sessionPrincipal(context.session.user.id), input);
  }),
  /** Restore pin: owner session only, charged like rename. */
  setOffloadPin: protectedProcedure
    .input(setSandboxOffloadPinInput)
    .handler(async ({ input, context }) => {
      return setSandboxOffloadPin(sessionPrincipal(context.session.user.id), input);
    }),

  cancelOperation: liveOwnerSessionProcedure
    .input(operationIdInput)
    .handler(async ({ input, context }) => {
      return cancelOperation(sessionPrincipal(context.session.user.id), input);
    }),
};
