import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import {
  type ProcessConnection,
  type ProcessRef,
  processConnectionSchema,
  resultBodySchema,
  SDK_ERRORS,
} from "@wssp/sandbox-contracts";
import { serviceProcedure } from "../lib/sdk-key-access";
import { encodeOutputCursor, isCommandOutputExpired, outputExpired } from "./command-output";
import type { Principal } from "./contracts";
import { resolveLockedControl } from "./process-controls";

const connectionSelect = {
  processStartedAt: true,
  resultObservedAt: true,
  processDescription: true,
  processDescriptionExpiresAt: true,
  completedAt: true,
  scalarResult: true,
} satisfies Prisma.SandboxOperationSelect;

/** A server snapshot, serialized with output writers by O. No guest IO or receipt. */
export const connectProcess = serviceProcedure(
  { action: "processes.connect", intentOnly: true },
  async (owner: Principal, input: { process: ProcessRef }): Promise<ProcessConnection> =>
    prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, owner.ownerId);
      const { row, sandbox, now } = await resolveLockedControl(
        tx,
        owner,
        "processes.connect",
        input,
      );
      const refuse = (
        code:
          | "sandbox.process_unknown_outcome"
          | "sandbox.process_not_started"
          | "sandbox.process_unavailable",
      ): never => {
        throw new ORPCError("CONFLICT", { data: { code }, message: SDK_ERRORS[code][1] });
      };
      if (row.state === "UNKNOWN_OUTCOME") refuse("sandbox.process_unknown_outcome");
      const terminal = ["SUCCEEDED", "FAILED", "CANCELLED"].includes(row.state);
      if (!terminal) {
        const host = row.dispatchedHostId
          ? await tx.sandboxHost.findFirst({
              where: { id: row.dispatchedHostId, userId: owner.ownerId },
              select: { connectionEpoch: true, status: true },
            })
          : null;
        if (!host || host.connectionEpoch !== row.dispatchedConnectionEpoch)
          refuse("sandbox.process_unknown_outcome");
        if (
          row.state !== "CANCEL_REQUESTED" &&
          (host?.status !== "CONNECTED" ||
            sandbox.sandboxHostId !== row.dispatchedHostId ||
            sandbox.state !== "READY")
        )
          refuse("sandbox.process_unavailable");
      }
      const facts = await tx.sandboxOperation.findFirst({
        where: { id: row.id, userId: owner.ownerId },
        select: connectionSelect,
      });
      if (!facts?.processStartedAt) return refuse("sandbox.process_not_started");
      if (
        isCommandOutputExpired(facts.completedAt, now) ||
        (facts.processDescriptionExpiresAt !== null && facts.processDescriptionExpiresAt <= now) ||
        !facts.processDescription
      )
        throw outputExpired();
      const header = await tx.sandboxCommandOutput.findUnique({
        where: { id: row.id },
        select: { attempt: true, receivedEnd: true },
      });
      // Identity and watermark must belong to the same immutable dispatch attempt.
      if (header && header.attempt !== row.dispatchAttempt)
        return refuse("sandbox.process_unknown_outcome");
      const scalar = resultBodySchema.safeParse(facts.scalarResult);
      const description = facts.processDescription;
      if (typeof description !== "object" || Array.isArray(description))
        throw new ORPCError("INTERNAL_SERVER_ERROR");
      const checked = processConnectionSchema.safeParse({
        info: {
          ...description,
          process: input.process,
          operationId: row.id,
          kind: "command",
          startedAt: facts.processStartedAt.toISOString(),
          observedAt: (facts.resultObservedAt ?? facts.processStartedAt).toISOString(),
        },
        state: row.state,
        exitCode: scalar.success && scalar.data.type === "command" ? scalar.data.exitCode : null,
        outputOperationId: row.id,
        attempt: row.dispatchAttempt,
        attachmentCursor: encodeOutputCursor(row.dispatchAttempt, Number(header?.receivedEnd ?? 0)),
      });
      if (!checked.success) throw new ORPCError("INTERNAL_SERVER_ERROR");
      return checked.data;
    }),
);
