import type { Prisma } from "@wssp/db";
import { loadVerifiedDefinition } from "@wssp/login-definition";
import type { VerifiedLogin } from "./vault/store";

type Tx = Prisma.TransactionClient;

export type LoadedLogin = VerifiedLogin & {
  copyBack: boolean;
  exclusive: boolean;
  checkpointIntervalMin: number | null;
  foreignAllowed: boolean;
};

/**
 * Loads a login for relay use: the pinned definition's digest is recomputed
 * from the stored document (`credential.definition_corrupt` otherwise), and
 * policy-bearing fields (copy-back, delivery, opt-in) are re-read inside the
 * caller's transaction. Null when the login is gone or corrupt.
 */
export async function loadVerifiedLogin(tx: Tx, credentialId: string): Promise<LoadedLogin | null> {
  const row = await tx.credential.findUnique({
    where: { id: credentialId },
    select: {
      userId: true,
      mode: true,
      delivery: true,
      copyBack: true,
      checkpointIntervalMin: true,
      foreignAllowed: true,
      definitionDigest: true,
      Definition: { select: { document: true, digest: true } },
    },
  });
  if (!row || row.Definition.digest !== row.definitionDigest) return null;
  const verified = await loadVerifiedDefinition(row.Definition.document, row.definitionDigest);
  if (!verified.success) return null;
  return {
    userId: row.userId,
    credentialId,
    definition: verified.definition,
    definitionDigest: row.definitionDigest,
    delivery: row.delivery,
    copyBack: row.copyBack,
    exclusive: row.mode === "EXCLUSIVE",
    checkpointIntervalMin: row.checkpointIntervalMin,
    foreignAllowed: row.foreignAllowed,
  };
}
