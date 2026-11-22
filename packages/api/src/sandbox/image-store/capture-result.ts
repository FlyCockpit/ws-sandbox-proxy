import type { Prisma } from "@wssp/db";

/** Host result for a capture (stored, never finalized here: H→S→O only). */
export async function recordCaptureResult(
  tx: Prisma.TransactionClient,
  input: {
    operationId: string;
    hostId: string;
    epoch: number;
    result: Record<string, unknown> | undefined;
  },
): Promise<boolean> {
  const result = input.result ?? {};
  const fingerprint = typeof result.fingerprint === "string" ? result.fingerprint : null;
  const size = typeof result.sizeBytes === "number" ? result.sizeBytes : null;
  const architecture = typeof result.architecture === "string" ? result.architecture : null;
  if (
    !fingerprint ||
    !/^sha256:[0-9a-f]{64}$/.test(fingerprint) ||
    !size ||
    size <= 0 ||
    !architecture
  )
    return false;
  const symlinked = Array.isArray(result.symlinkedPaths)
    ? result.symlinkedPaths.filter((p): p is string => typeof p === "string").slice(0, 80)
    : [];
  const written = await tx.sandboxTemplateCapture.updateMany({
    where: { operationId: input.operationId, hostId: input.hostId, state: "PENDING" },
    data: {
      state: "CAPTURED",
      fingerprint,
      sizeBytes: BigInt(size),
      unpackedBytes: typeof result.unpackedBytes === "number" ? BigInt(result.unpackedBytes) : null,
      architecture,
      resultEpoch: input.epoch,
      symlinkedPaths: symlinked,
      capturedAt: new Date(),
    },
  });
  await tx.sandboxOperation.updateMany({
    where: { id: input.operationId, state: { in: ["DISPATCHED", "ACCEPTED", "RUNNING"] } },
    data: { state: "RUNNING", progressPhase: "finalizing", progressAt: new Date() },
  });
  return written.count === 1;
}
