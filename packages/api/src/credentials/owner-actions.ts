import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { z } from "zod";
import { DataKeyStaleWriter, staleWriterError } from "../crypto/data-key-epoch";
import { cursorPage, cursorPageInput, decodeCursor, pageTake, withCursor } from "../lib/pagination";
import { entityId } from "../lib/schemas";
import { authorizeServiceAction, serviceProcedure } from "../lib/sdk-key-access";
import type { Principal } from "../sandbox/contracts";
import { credentialAccessFilter, requireCredentials } from "./access";
import { consumeCredentialDiscard, consumeCredentialForceRelease } from "./budgets";
import { credentialError } from "./errors";
import { deliverCredentialFrame } from "./frame-sink";
import { discardQuarantined, forceReleaseLease, type QuarantineDiscard } from "./leases";
import {
  CredentialValueInvalid,
  CredentialVaultUnavailable,
  promotableCheckpoints,
  promoteLeaseCheckpoint,
} from "./vault/store";
import { loadVerifiedLogin } from "./verified-login";

/**
 * Owner recovery actions on a login instance: force-release a lease (optionally promoting its newest
 * checkpoint), discard the instance's rejected (quarantined) captures, and
 * the two reads the dashboard needs for them. Everything is owner-scoped and
 * metadata only: no value, path or envelope byte is ever returned.
 *
 * Force-release follows the capture-commit lock order (§7.3): S → credential
 * FOR SHARE → instance FOR UPDATE → lease → binding → residue; visibility is
 * checked first without locks. Frames (`credential.revoke`,
 * `credential.quarantine.discard`) go out after commit, best-effort: a host
 * that misses them learns DISCARDED{force_released} on its next capture, and
 * a census still listing a discarded envelope gets the discard again.
 */

type Tx = Prisma.TransactionClient;

const NON_TERMINAL = [
  "RESERVED",
  "INSTALLING",
  "ACTIVE",
  "RELEASING",
  "RECOVERY_REQUIRED",
  "RECOVERING",
] as const;

function parse<T extends z.ZodType>(schema: T, input: unknown): z.output<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new ORPCError("BAD_REQUEST", { message: "Invalid login input." });
  return parsed.data;
}

const iso = (date: Date) => date.toISOString();

export const forceReleaseInput = z.object({
  credentialId: entityId,
  instanceId: entityId,
  leaseId: entityId,
  /** Promote the lease's newest checkpoint newer than the current value. */
  promoteCheckpoint: z.boolean().default(false),
});
export const instanceScopedPageInput = cursorPageInput.extend({
  credentialId: entityId,
  instanceId: entityId,
});
export const discardRejectedInput = z.object({ credentialId: entityId, instanceId: entityId });

export type ForceReleaseResultDto = {
  leaseId: string;
  /** False when the lease was already terminal (idempotent). */
  released: boolean;
  /** The promoted checkpoint, when one was requested and existed. */
  promoted: { storageSeq: number; fromSeq: number } | null;
};

export type InstanceLeaseDto = {
  id: string;
  kind: "WORKLOAD" | "LOGIN";
  state: (typeof NON_TERMINAL)[number];
  sandboxId: string | null;
  createdAt: string;
  /** The newest checkpoint of this lease newer than the current value. */
  checkpoint: { storageSeq: number; at: string } | null;
};

export type RejectedCaptureDto = {
  captureId: string;
  leaseId: string | null;
  reason: string;
  at: string;
};

/** The visible instance or NOT_FOUND, without row locks. */
async function visibleInstance(
  client: Tx | typeof prisma,
  principal: Principal,
  credentialId: string,
  instanceId: string,
) {
  const login = await client.credential.findFirst({
    where: { AND: [credentialAccessFilter(principal), { id: credentialId }] },
    select: { id: true },
  });
  if (!login) throw credentialError("credential.not_found");
  const instance = await client.credentialInstance.findFirst({
    where: { id: instanceId, credentialId, userId: principal.ownerId },
    select: { id: true, accountId: true },
  });
  if (!instance) throw credentialError("credential.instance_not_found");
  return instance;
}

function sendDiscards(discards: QuarantineDiscard[], reason: "force_released" | "owner_discard") {
  for (const discard of discards)
    deliverCredentialFrame(discard.hostId, {
      type: "credential.quarantine.discard",
      captureIds: discard.captureIds,
      reason,
    });
}

/**
 * Force-release (§7.1 non-terminal → FORCE_RELEASED): all the lease's
 * bindings close, its residue becomes non-recoverable (scrubbed at the next
 * start), its quarantined captures are discarded and its unresolved
 * envelopes become authorized discards. With `promoteCheckpoint`, the
 * newest checkpoint this lease committed that is newer than the current
 * value becomes current (PROMOTED, fresh DEK) in the same transaction.
 * Without it the guest's newest rotation may be lost. Allowed in drain mode.
 */
export const forceRelease = serviceProcedure(
  { action: "credentialInstances.forceRelease" },
  async (
    principal: Principal,
    input: z.input<typeof forceReleaseInput>,
  ): Promise<ForceReleaseResultDto> => {
    requireCredentials("settle");
    const body = parse(forceReleaseInput, input);
    await consumeCredentialForceRelease(principal.ownerId);
    let frames: {
      revoke: { hostId: string; leaseId: string } | null;
      discards: QuarantineDiscard[];
    };
    let result: ForceReleaseResultDto;
    try {
      [result, frames] = await prisma.$transaction(
        async (tx) => {
          await authorizeServiceAction(principal, "credentialInstances.forceRelease", {}, tx);
          const instance = await visibleInstance(tx, principal, body.credentialId, body.instanceId);
          const lease = await tx.credentialLease.findFirst({
            where: {
              id: body.leaseId,
              userId: principal.ownerId,
              credentialId: body.credentialId,
              instanceId: instance.id,
            },
            select: { id: true, sandboxId: true },
          });
          // E3-B-05: the instance exists; it is the lease that does not.
          if (!lease) throw credentialError("credential.lease_not_found");
          const released = await forceReleaseLease(tx, {
            ownerId: principal.ownerId,
            leaseId: lease.id,
          });
          let promoted: ForceReleaseResultDto["promoted"] = null;
          if (released.released && body.promoteCheckpoint) {
            const login = await loadVerifiedLogin(tx, body.credentialId);
            if (!login) throw credentialError("credential.definition_corrupt");
            const written = await promoteLeaseCheckpoint(tx, login, instance.id, lease.id);
            if (written) promoted = { storageSeq: written.storageSeq, fromSeq: written.fromSeq };
          }
          if (released.released) {
            await recordEvent(tx, principal, {
              credentialId: body.credentialId,
              accountId: instance.accountId,
              instanceId: instance.id,
              leaseId: lease.id,
              sandboxId: lease.sandboxId,
              type: "force_released",
              reason: "force_released",
            });
            if (promoted)
              await recordEvent(tx, principal, {
                credentialId: body.credentialId,
                accountId: instance.accountId,
                instanceId: instance.id,
                leaseId: lease.id,
                sandboxId: lease.sandboxId,
                type: "checkpoint_promoted",
                storageSeq: promoted.storageSeq,
              });
          }
          return [
            { leaseId: lease.id, released: released.released, promoted },
            { revoke: released.revoke, discards: released.discards },
          ] as const;
        },
        { timeout: 30_000 },
      );
    } catch (error) {
      if (error instanceof CredentialValueInvalid)
        throw credentialError("credential.value_invalid", {
          entry: error.entry,
          ...(error.path === undefined ? {} : { path: error.path }),
        });
      if (error instanceof CredentialVaultUnavailable)
        throw credentialError("credential.unavailable");
      if (error instanceof DataKeyStaleWriter) throw staleWriterError();
      throw error;
    }
    if (frames.revoke)
      deliverCredentialFrame(frames.revoke.hostId, {
        type: "credential.revoke",
        leaseId: frames.revoke.leaseId,
        reason: "force_released",
      });
    sendDiscards(frames.discards, "force_released");
    return result;
  },
);

/**
 * Owner "Discard rejected captures" (§7.4.2 P3-1): marks every live
 * rejection row of the instance's leases discarded and tells each host to
 * delete those quarantined envelopes. A rejected envelope can never commit,
 * so nothing recoverable is lost. Session only (no SDK action).
 */
export const discardRejectedCaptures = serviceProcedure(
  { sessionOnly: true },
  async (
    principal: Principal,
    input: z.input<typeof discardRejectedInput>,
  ): Promise<{ discarded: number }> => {
    requireCredentials("settle");
    const body = parse(discardRejectedInput, input);
    await consumeCredentialDiscard(principal.ownerId);
    const discards = await prisma.$transaction(async (tx) => {
      const instance = await visibleInstance(tx, principal, body.credentialId, body.instanceId);
      // credential FOR SHARE → instance FOR UPDATE (value-write order, §7.3).
      await tx.$queryRaw`SELECT id FROM credential WHERE id = ${body.credentialId} FOR SHARE`;
      await tx.$queryRaw`SELECT id FROM credential_instance WHERE id = ${instance.id} FOR UPDATE`;
      const discarded = await discardQuarantined(tx, { instanceId: instance.id });
      const count = discarded.reduce((sum, d) => sum + d.captureIds.length, 0);
      if (count > 0)
        await recordEvent(tx, principal, {
          credentialId: body.credentialId,
          accountId: instance.accountId,
          instanceId: instance.id,
          type: "rejected_discarded",
          reason: "owner_discard",
        });
      return discarded;
    });
    sendDiscards(discards, "owner_discard");
    return { discarded: discards.reduce((sum, d) => sum + d.captureIds.length, 0) };
  },
);

/**
 * The instance's non-terminal leases (holders), each with its promotable
 * checkpoint: the ids force-release needs. Dashboard and `/v1`
 * (`credentials:read`, the per-login allowlist via the visibility check).
 */
export const listInstanceLeases = serviceProcedure(
  { action: "credentialInstances.listLeases" },
  async (principal: Principal, input: z.input<typeof instanceScopedPageInput>) => {
    requireCredentials("read");
    const page = parse(instanceScopedPageInput, input);
    const instance = await visibleInstance(prisma, principal, page.credentialId, page.instanceId);
    const rows = await prisma.credentialLease.findMany({
      where: withCursor(
        { userId: principal.ownerId, instanceId: instance.id, state: { in: [...NON_TERMINAL] } },
        "createdAt",
        page.cursor,
        "asc",
      ),
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      take: pageTake(page.limit),
      select: { id: true, kind: true, state: true, sandboxId: true, createdAt: true },
    });
    const result = cursorPage(rows, page.limit, "createdAt");
    const checkpoints = await promotableCheckpoints(
      prisma,
      instance.id,
      result.items.map((row) => row.id),
    );
    return {
      items: result.items.map((row): InstanceLeaseDto => {
        const checkpoint = checkpoints.get(row.id);
        return {
          id: row.id,
          kind: row.kind,
          state: row.state as InstanceLeaseDto["state"],
          sandboxId: row.sandboxId,
          createdAt: iso(row.createdAt),
          checkpoint: checkpoint
            ? { storageSeq: checkpoint.storageSeq, at: iso(checkpoint.createdAt) }
            : null,
        };
      }),
      nextCursor: result.nextCursor,
    };
  },
);

/** The instance's quarantined (rejected, not yet discarded) captures, newest first. */
export const listRejectedCaptures = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, input: z.input<typeof instanceScopedPageInput>) => {
    requireCredentials("read");
    const page = parse(instanceScopedPageInput, input);
    const instance = await visibleInstance(prisma, principal, page.credentialId, page.instanceId);
    const cursor = page.cursor ? decodeCursor(page.cursor) : null;
    const take = pageTake(page.limit);
    type Row = { id: string; leaseId: string | null; reason: string; at: Date };
    const rows = cursor
      ? await prisma.$queryRaw<Row[]>`SELECT r."captureId" AS id, r."leaseId", r.reason, r.at
          FROM credential_capture_rejection r
          JOIN credential_lease l ON l.id = r."leaseId"
          WHERE l."instanceId" = ${instance.id} AND l."userId" = ${principal.ownerId}
            AND r."discardedAt" IS NULL
            AND (r.at, r."captureId") < (${cursor.sortValue}, ${cursor.id})
          ORDER BY r.at DESC, r."captureId" DESC
          LIMIT ${take}`
      : await prisma.$queryRaw<Row[]>`SELECT r."captureId" AS id, r."leaseId", r.reason, r.at
          FROM credential_capture_rejection r
          JOIN credential_lease l ON l.id = r."leaseId"
          WHERE l."instanceId" = ${instance.id} AND l."userId" = ${principal.ownerId}
            AND r."discardedAt" IS NULL
          ORDER BY r.at DESC, r."captureId" DESC
          LIMIT ${take}`;
    const result = cursorPage(rows, page.limit, "at");
    return {
      items: result.items.map(
        (row): RejectedCaptureDto => ({
          captureId: row.id,
          leaseId: row.leaseId,
          reason: row.reason,
          at: iso(row.at),
        }),
      ),
      nextCursor: result.nextCursor,
    };
  },
);

async function recordEvent(
  tx: Tx,
  principal: Principal,
  event: Omit<Prisma.CredentialEventUncheckedCreateInput, "userId" | "id" | "at">,
) {
  await tx.credentialEvent.create({
    data: { ...event, userId: principal.ownerId },
    select: { id: true },
  });
}
