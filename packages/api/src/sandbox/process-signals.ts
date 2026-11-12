import { ORPCError } from "@orpc/server";
import prisma from "@wssp/db";
import { type ProcessRef, processSignalSchema } from "@wssp/sandbox-contracts";
import { authorizeServiceAction, serviceProcedure } from "../lib/sdk-key-access";
import type { Principal } from "./contracts";
import { operationDigestContext } from "./digest-context";
import { requestDigestMetadata } from "./idempotency";
import { initialResultFields } from "./operation-results";
import { operationTransaction } from "./operation-transaction";
import { createSandboxOutboxEvent } from "./outbox";
import { attributionOf, recordedKeyIdOf } from "./principal-kinds";
import {
  cancelAction,
  locateControlTarget,
  requireLiveControl,
  resolveLockedControl,
  validateControlRef,
} from "./process-controls";

/** SIGKILL has exactly cancel's identity space and state machine. This staged
 * entry is shared by the native/browser adapters at the 6C route cutover. */
export const signalProcessAction = serviceProcedure(
  { action: "processes.signal", intentOnly: true },
  async (
    owner: Principal,
    input: {
      process: ProcessRef;
      signal: "SIGTERM" | "SIGINT" | "SIGHUP" | "SIGKILL";
      idempotencyKey: string;
    },
  ) => {
    if (!processSignalSchema.safeParse(input.signal).success) throw new ORPCError("BAD_REQUEST");
    if (input.signal === "SIGKILL") return cancelAction(owner, input);
    const target = await locateControlTarget(prisma, owner, input);
    await authorizeServiceAction(owner, "processes.signal", { operationId: target.id });
    validateControlRef(target, input.process);
    return operationTransaction(
      owner,
      {
        key: input.idempotencyKey,
        intent: { targetOperationId: target.id, process: input.process, signal: input.signal },
        kind: "SIGNAL_PROCESS",
        action: "processes.signal",
        target: { sandboxId: target.sandboxId },
        fsProcess: {},
      },
      async (tx, digest) => {
        const resolved = await resolveLockedControl(tx, owner, "processes.signal", input);
        await requireLiveControl(tx, owner, resolved);
        const { row, sandbox, now } = resolved;
        const control = await tx.sandboxOperation.create({
          data: {
            userId: owner.ownerId,
            sandboxId: sandbox.id,
            generation: sandbox.generation,
            kind: "SIGNAL_PROCESS",
            idempotencyKey: input.idempotencyKey,
            requestBodyHash: digest(),
            digestContext: operationDigestContext(tx),
            authorizingKeyId: recordedKeyIdOf(owner),
            ...initialResultFields("SIGNAL_PROCESS", true),
            createdAt: now,
            ...requestDigestMetadata(),
          },
        });
        await createSandboxOutboxEvent(tx, {
          userId: owner.ownerId,
          aggregateId: sandbox.id,
          eventType: "sandbox.process_signal_requested",
          authorizingPrincipal: attributionOf(owner),
          payload: {
            sandboxId: sandbox.id,
            sandboxHostId: row.dispatchedHostId,
            operationId: control.id,
            dispatchAttempt: 0,
            generation: row.generation,
            kind: "process.signal",
            idempotencyKey: input.idempotencyKey,
            process: input.process,
            targetOperationId: row.id,
            signal: input.signal,
            resultVersion: 1,
            connectionEpoch: row.dispatchedConnectionEpoch,
          },
        });
        return { operationId: control.id, state: control.state };
      },
      async (_tx, prior) => ({ operationId: prior.id, state: prior.state }),
    );
  },
);
