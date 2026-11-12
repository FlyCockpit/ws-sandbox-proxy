import type { SandboxOperation } from "@wssp/db";

/** A current host command result with stable process birth evidence. */
export function commandResultFixture(
  operation: Pick<
    SandboxOperation,
    "id" | "sandboxId" | "generation" | "processId" | "dispatchAttempt"
  >,
  metadata: { exitCode: number | null; outputBytes?: number },
) {
  if (!operation.processId) throw new Error("Command fixture needs a process identity.");
  const process = {
    sandboxId: operation.sandboxId,
    generation: operation.generation,
    attempt: operation.dispatchAttempt,
    processId: operation.processId,
    pid: 42,
  };
  const startedAt = "2026-10-27T00:00:00.000Z";
  return {
    version: 1,
    observedAt: startedAt,
    payload: { type: "command", process, startedAt, exitCode: metadata.exitCode },
    continuation: null,
    birth: {
      type: "process.started",
      ...process,
      operationId: operation.id,
      bootId: "12345678-1234-4234-8234-123456789abc",
      startTicks: "123",
      startedAt,
      observedAt: startedAt,
    },
    failure: null,
    ...(metadata.outputBytes === undefined ? {} : { outputBytes: metadata.outputBytes }),
  };
}
