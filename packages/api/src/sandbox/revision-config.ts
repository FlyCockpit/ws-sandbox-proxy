import type { Prisma } from "@wssp/db";
import { digestKeyChanged } from "./errors";
import { executionEnvPairs } from "./execution-config";
import { hashRevisionDefaultsBody, requestDigestMetadata } from "./idempotency";
import { rethrowSensitiveSandboxError } from "./sensitive-errors";

function checksum(ownerId: string, revisionId: string, env: [string, string][]) {
  return hashRevisionDefaultsBody({ revisionId, env }, ownerId);
}

export async function writeRevisionDefaults(
  tx: Prisma.TransactionClient,
  ownerId: string,
  revisionId: string,
  value: unknown,
) {
  const env = executionEnvPairs(value);
  const meta = requestDigestMetadata();
  await tx.sandboxRevisionConfig.create({
    data: {
      userId: ownerId,
      revisionId,
      defaultEnvs: Object.fromEntries(env),
      checksum: checksum(ownerId, revisionId, env),
      digestScheme: meta.requestDigestScheme,
      digestKeyId: meta.requestDigestKeyId,
    },
  });
}

/** Private projection only. Never return the row or caught driver details. */
export async function loadRevisionDefaults(
  tx: Prisma.TransactionClient,
  revisionId: string,
  ownerId: string,
) {
  try {
    const row = await tx.sandboxRevisionConfig.findFirst({
      where: { revisionId, userId: ownerId, Revision: { userId: ownerId } },
      select: { defaultEnvs: true, checksum: true, digestScheme: true, digestKeyId: true },
    });
    if (!row) throw new Error("Private revision config missing.");
    const env = executionEnvPairs(row.defaultEnvs);
    const meta = requestDigestMetadata();
    if (
      row.digestScheme !== meta.requestDigestScheme ||
      row.digestKeyId !== meta.requestDigestKeyId
    )
      throw digestKeyChanged();
    if (row.checksum !== checksum(ownerId, revisionId, env))
      throw new Error("Private revision config invalid.");
    return env;
  } catch (error) {
    return rethrowSensitiveSandboxError(error);
  }
}
