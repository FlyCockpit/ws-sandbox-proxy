import { ACTIVE_OPERATION_STATES } from "@wssp/api/sandbox/state-transitions";
import type { Prisma } from "@wssp/db";
import {
  cloudInitInstanceIdSchema,
  type DispatchExpectDiskV11,
  type DispatchImageV11,
  type DispatchRestoreV11,
  dispatchExpectDiskV11Schema,
  imageFingerprintSchema,
  type LaunchMode,
} from "@wssp/sandbox-contracts";

/**
 * The disk offload fields of one dispatch, built in the
 * dispatch transaction under H/S/O from rows only:
 *
 * - `restore`, `launchMode: "new_root"` and the `fetch` image of the stored
 *   disk for a restore attempt, known from the operation row
 *   (`restoreOffloadOf`, U9.1), never from the outbox payload. The
 *   fingerprint is the worker-verified `SandboxDiskOffload.fingerprint` (S4).
 * - `expectDisk` for a cached cold reconnect: written by the accepting
 *   transaction (§8.1) into the server-produced payload, forwarded verbatim.
 * - `diskBaseFingerprint` on every binding dispatch: the attempt's offload
 *   fingerprint while a restore attempt is active (`currentlyRestoring`),
 *   else `Sandbox.diskBaseFingerprint` (set by a restore's READY). Sent only
 * to a host advertising stopped-disk offload support. Without that runtime
 * feature, binding requires the template base.
 *
 * `restore_unavailable`: the restore's offload is no longer the sandbox's
 * STORED disk (a producer bug or a concurrent destroy); never dispatched.
 */
export type DispatchDiskFields = {
  restore?: DispatchRestoreV11;
  launchMode?: LaunchMode;
  image?: DispatchImageV11;
  expectDisk?: DispatchExpectDiskV11;
  diskBaseFingerprint?: string;
};

/** Kinds that never bind an instance (no base needed) or are controls. */
const UNBOUND_KINDS = new Set(["sandbox.create", "operation.cancel", "process.stdin"]);

export async function dispatchDiskFields(
  tx: Prisma.TransactionClient,
  input: {
    kind: string;
    restoreOffloadId: string | null;
    payload: Record<string, unknown>;
    sandbox: {
      id: string;
      userId: string;
      generation: number;
      diskOffloadId: string | null;
      diskBaseFingerprint: string | null;
      cloudInitInstanceId: string | null;
    };
    /** The host's current hello advertised `diskOffload` (read under H). */
    diskCapable: boolean;
  },
): Promise<DispatchDiskFields | "restore_unavailable"> {
  const { sandbox } = input;
  if (input.restoreOffloadId !== null) {
    if (input.kind !== "sandbox.reconnect" || sandbox.diskOffloadId !== input.restoreOffloadId)
      return "restore_unavailable";
    const offload = await tx.sandboxDiskOffload.findFirst({
      where: {
        id: input.restoreOffloadId,
        sandboxId: sandbox.id,
        userId: sandbox.userId,
        state: "STORED",
      },
      select: { id: true, seq: true, fingerprint: true, sizeBytes: true },
    });
    const fingerprint = imageFingerprintSchema.safeParse(offload?.fingerprint).data;
    if (!offload || !fingerprint || !offload.sizeBytes || offload.sizeBytes <= 0n)
      return "restore_unavailable";
    const cloudInitInstanceId = cloudInitInstanceIdSchema.safeParse(
      sandbox.cloudInitInstanceId,
    ).data;
    return {
      restore: {
        offloadId: offload.id,
        seq: offload.seq,
        fingerprint,
        ...(cloudInitInstanceId ? { cloudInitInstanceId } : {}),
      },
      launchMode: "new_root",
      image: {
        fingerprint,
        sizeBytes: Number(offload.sizeBytes),
        format: "unified",
        source: "fetch",
      },
      diskBaseFingerprint: fingerprint,
    };
  }
  const fields: DispatchDiskFields = {};
  if (input.kind === "sandbox.reconnect" && input.payload.expectDisk !== undefined) {
    const expect = dispatchExpectDiskV11Schema.safeParse(input.payload.expectDisk);
    if (!expect.success) return "restore_unavailable";
    fields.expectDisk = expect.data;
  }
  if (!UNBOUND_KINDS.has(input.kind) && input.diskCapable) {
    const base = await bindingDiskBase(tx, sandbox);
    if (base) fields.diskBaseFingerprint = base;
  }
  return fields;
}

/** §7 "Server anchor (S4)": the base image a binding dispatch names. */
async function bindingDiskBase(
  tx: Prisma.TransactionClient,
  sandbox: {
    id: string;
    userId: string;
    generation: number;
    diskOffloadId: string | null;
    diskBaseFingerprint: string | null;
  },
): Promise<string | null> {
  if (sandbox.diskOffloadId !== null) {
    // currentlyRestoring (§8.4): the offload pointer plus an active restore
    // attempt of the current generation; its offload is the lineage's base.
    const attempt = await tx.sandboxOperation.findFirst({
      where: {
        sandboxId: sandbox.id,
        userId: sandbox.userId,
        kind: "RECONNECT_SANDBOX",
        launchMode: "NEW_ROOT",
        generation: sandbox.generation,
        state: { in: [...ACTIVE_OPERATION_STATES] },
        restoreOffloadId: { not: null },
      },
      select: { restoreOffloadId: true },
    });
    if (attempt?.restoreOffloadId) {
      const offload = await tx.sandboxDiskOffload.findFirst({
        where: { id: attempt.restoreOffloadId, sandboxId: sandbox.id, userId: sandbox.userId },
        select: { fingerprint: true },
      });
      return imageFingerprintSchema.safeParse(offload?.fingerprint).data ?? null;
    }
  }
  return imageFingerprintSchema.safeParse(sandbox.diskBaseFingerprint).data ?? null;
}
