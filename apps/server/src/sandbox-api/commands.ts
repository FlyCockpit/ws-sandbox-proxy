import { listProcessesInput, runCommandInput, writeStdinInput } from "@wssp/api/sandbox/contracts";
import { cancelAction, writeStdinAction } from "@wssp/api/sandbox/process-controls";
import { signalProcessAction } from "@wssp/api/sandbox/process-signals";
import { cancelOperationReceipt, writeStdinReceipt } from "@wssp/api/sandbox/sdk-mutations";
import { listProcesses, runCommand } from "@wssp/api/sandbox/services/sandboxes";
import type { RouteHandlers } from "./reads.js";

export const commandMutationHandlers = {
  listProcesses: (owner, { params, body, idempotencyKey }) =>
    listProcesses(owner, listProcessesInput.parse({ ...body, id: params.id, idempotencyKey })),
  signalProcess: (owner, { params, body, idempotencyKey }) => {
    const { signal, ...qualifiers } = body;
    return signalProcessAction(owner, {
      process: { sandboxId: params.id, pid: params.pid, ...qualifiers },
      signal,
      idempotencyKey,
    });
  },
  killProcess: (owner, { params, body, idempotencyKey }) =>
    cancelAction(owner, {
      process: { sandboxId: params.id, pid: params.pid, ...body },
      idempotencyKey,
    }),
  sendProcessStdin: (owner, { params, body, idempotencyKey }) => {
    const { contentBase64, eof, ...qualifiers } = body;
    return writeStdinAction(owner, {
      process: { sandboxId: params.id, pid: params.pid, ...qualifiers },
      contentBase64,
      eof,
      idempotencyKey,
    });
  },
  startCommand: (owner, { params, body, idempotencyKey }) =>
    runCommand(owner, runCommandInput.parse({ ...body, id: params.id, idempotencyKey })),
  writeStdin: (owner, { params, body, idempotencyKey }) =>
    writeStdinReceipt(owner, {
      ...writeStdinInput.parse({ ...body, operationId: params.id }),
      idempotencyKey,
    }),
  cancelOperation: (owner, { params, idempotencyKey }) =>
    cancelOperationReceipt(owner, { operationId: params.id, idempotencyKey }),
} satisfies Pick<
  RouteHandlers,
  | "startCommand"
  | "writeStdin"
  | "cancelOperation"
  | "listProcesses"
  | "signalProcess"
  | "killProcess"
  | "sendProcessStdin"
>;
