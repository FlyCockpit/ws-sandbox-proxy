import { createHash } from "node:crypto";
import prisma from "@wssp/db";
import { decryptImageStream, type ImageStore, imageStore } from "../image-store/s3";
import { isTerminalImageVerificationError } from "../image-store/verification-errors";
import { DiskKeyError, loadDiskObjectKey } from "./keys";
import { failLiveOffload, finishEndedOffload, markStored } from "./store";

/**
 * Disk verify: re-read the completed object, decrypt it with the offload
 * wrap (AAD rebuilt from `completedSessionId`), and check the SHA-256 against
 * the declared fingerprint and the plaintext size. Pass → `markStored`
 * after verification; definite corruption → FAILED(corrupt) with a shred and
 * the object deleted. Store, stream and database outages rethrow for retry
 * without changing VERIFYING or shredding the wrap.
 */
export type DiskVerifyOutcome = "stored" | "superseded" | "login_unsettled" | "corrupt" | "skipped";

export async function verifyDiskOffload(
  offloadId: string,
  store: ImageStore | null = imageStore(),
): Promise<DiskVerifyOutcome> {
  if (!store) return "skipped";
  const row = await prisma.sandboxDiskOffload.findFirst({
    where: { id: offloadId, state: "VERIFYING" },
    select: {
      id: true,
      objectKey: true,
      completedSessionId: true,
      fingerprint: true,
      sizeBytes: true,
    },
  });
  if (!row?.objectKey || !row.completedSessionId || !row.fingerprint || !row.sizeBytes)
    return "skipped";
  let ok = false;
  let key: Buffer | undefined;
  try {
    key = await loadDiskObjectKey(prisma, row.id);
    const body = await store.getObjectStream(row.objectKey);
    const hash = createHash("sha256");
    let size = 0n;
    for await (const chunk of decryptImageStream(key, Number(row.sizeBytes), body)) {
      hash.update(chunk);
      size += BigInt(chunk.length);
    }
    ok = size === row.sizeBytes && `sha256:${hash.digest("hex")}` === row.fingerprint;
  } catch (error) {
    if (
      !isTerminalImageVerificationError(error) &&
      !(
        error instanceof DiskKeyError &&
        ["authentication_failed", "malformed", "not_stored"].includes(error.code)
      )
    )
      throw error;
    // A malformed/missing wrap, a missing object, a tamper or a truncation: never STORED.
    ok = false;
  } finally {
    key?.fill(0);
  }
  if (ok) {
    const outcome = await markStored(row.id, {
      completedSessionId: row.completedSessionId,
      objectKey: row.objectKey,
    });
    if (outcome.kind === "noop") return "skipped";
    if (outcome.kind === "stored") return "stored";
    await finishEndedOffload(store, outcome.ended);
    return outcome.kind;
  }
  const ended = await prisma.$transaction(async (tx) => {
    const head = await tx.sandboxDiskOffload.findUnique({
      where: { id: row.id },
      select: { sandboxId: true },
    });
    if (!head) return null;
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${head.sandboxId} FOR UPDATE`;
    return failLiveOffload(tx, row.id, "corrupt");
  });
  await finishEndedOffload(store, ended);
  return ended ? "corrupt" : "skipped";
}
