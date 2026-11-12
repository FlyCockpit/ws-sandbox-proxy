import { ORPCError } from "@orpc/server";
import prisma from "@wssp/db";
import { redisConnection } from "@wssp/queue";
import { z } from "zod";

import {
  declareHostReturnKeyLost,
  destroyReturnKey,
  listReturnKeyBlockers,
  listReturnKeys,
  rotateReturnKey,
} from "../credentials/return-keys";
import { CredentialVaultUnavailable } from "../credentials/vault/store";
import { type DataKeyring, readDataKeyring } from "../crypto/data-key";
import { DataKeyStaleWriter, promoteDataKey, staleWriterError } from "../crypto/data-key-epoch";
import { readDataKeyStatus } from "../crypto/data-key-status";
import { adminOr404Procedure, adminWriteProcedure } from "../index";
import { ADMIN_ERROR_CODES, type DataKeyRefusal } from "../lib/admin-error-codes";
import { entityId } from "../lib/schemas";

/**
 * Admin data-key card: rotation status, the
 * promote switch, return-key rotation, destruction and declare-lost. Hidden
 * (404) for non-admins. Metadata only: kids, epochs, counts and timestamps;
 * never key material, public keys or wrap columns. Writes run in the locked
 * admin write transaction and are audited (structured log) after commit.
 */

const kid = z.string().regex(/^[0-9a-f]{16}$/);
const pageLimit = z.number().int().min(1).max(50).default(20);

function refuse(reason: DataKeyRefusal): never {
  throw new ORPCError("CONFLICT", {
    message: "The key action was refused.",
    data: { code: ADMIN_ERROR_CODES.dataKeyRefused, reason },
  });
}

/** Null when unset; an invalid value is "not configured" here (boot reports it). */
function keyring(): DataKeyring | null {
  try {
    return readDataKeyring();
  } catch {
    return null;
  }
}

function audit(event: string, actor: string, fields: Record<string, string | number | boolean>) {
  // Committed control-plane metadata only: ids, kids and epochs, never key material.
  console.info(JSON.stringify({ event, actor, ...fields }));
}

function mapKeyErrors(error: unknown): never {
  if (error instanceof DataKeyStaleWriter) throw staleWriterError();
  if (error instanceof CredentialVaultUnavailable) refuse("not_configured");
  throw error;
}

export const adminDataKeysRouter = {
  status: adminOr404Procedure.handler(async () => {
    const ring = keyring();
    const [status, state] = await Promise.all([
      readDataKeyStatus({ ring, redis: redisConnection }),
      prisma.credentialReturnKeyState.findUnique({
        where: { id: 1 },
        select: { currentKidR: true, currentEpoch: true },
      }),
    ]);
    return {
      configured: ring !== null,
      ...status,
      returnKey: state
        ? { currentKidR: state.currentKidR, currentEpoch: state.currentEpoch.toString() }
        : null,
    };
  }),

  listReturnKeys: adminOr404Procedure
    .input(
      z
        .object({
          cursor: z
            .string()
            .regex(/^[1-9][0-9]{0,17}$/)
            .optional(),
          limit: pageLimit,
        })
        .optional(),
    )
    .handler(({ input }) =>
      listReturnKeys({
        afterEpoch: input?.cursor ? BigInt(input.cursor) : null,
        limit: input?.limit ?? 20,
      }),
    ),

  listReturnKeyBlockers: adminOr404Procedure
    .input(
      z.object({
        kidR: kid,
        cursor: entityId.regex(/^[A-Za-z0-9_-]+$/).optional(),
        limit: pageLimit,
      }),
    )
    .handler(({ input }) =>
      listReturnKeyBlockers({
        kidR: input.kidR,
        afterHostId: input.cursor ?? null,
        limit: input.limit,
      }),
    ),

  promote: adminWriteProcedure
    .input(z.object({ kid: z.string().max(64) }))
    .handler(async ({ input, context }) => {
      const ring = keyring();
      if (!ring) refuse("not_configured");
      const result = await promoteDataKey(ring, input.kid, context.adminTx);
      if (!result.ok) refuse(result.reason);
      const actor = context.session.user.id;
      if (result.changed)
        context.afterCommit(async () =>
          audit("data_key.promoted", actor, {
            currentKid: result.currentKid,
            previousKid: result.previousKid ?? "",
            epoch: result.epoch.toString(),
          }),
        );
      return {
        changed: result.changed,
        currentKid: result.currentKid,
        previousKid: result.previousKid,
        epoch: result.epoch.toString(),
      };
    }),

  rotateReturnKey: adminWriteProcedure.handler(async ({ context }) => {
    const rotated = await rotateReturnKey(context.adminTx).catch(mapKeyErrors);
    if (!rotated) refuse("not_initialized");
    const actor = context.session.user.id;
    context.afterCommit(async () =>
      audit("credential.return_key_rotated", actor, {
        kidR: rotated.kidR,
        epoch: rotated.epoch.toString(),
      }),
    );
    return { kidR: rotated.kidR, epoch: rotated.epoch.toString() };
  }),

  /**
   * Destroys a retired private key (§4.3 step 4). The admin types the kid to
   * confirm; live quarantined envelopes under it also need
   * `destroyQuarantined` (audited with their count). Time never authorizes it.
   */
  destroyReturnKey: adminWriteProcedure
    .input(
      z.object({ kidR: kid, confirmKidR: z.string().max(64), destroyQuarantined: z.boolean() }),
    )
    .handler(async ({ input, context }) => {
      if (input.confirmKidR !== input.kidR) refuse("confirmation_mismatch");
      const result = await destroyReturnKey(
        { kidR: input.kidR, destroyQuarantined: input.destroyQuarantined },
        context.adminTx,
      );
      if (!result.ok) refuse(result.reason);
      const actor = context.session.user.id;
      context.afterCommit(async () =>
        audit("credential.return_key_destroyed", actor, {
          kidR: input.kidR,
          destroyQuarantined: input.destroyQuarantined,
          quarantined: result.quarantined,
        }),
      );
      return { kidR: input.kidR, destroyed: true as const };
    }),

  /** The host will never return: its issuance row stops blocking destruction. Irreversible. */
  declareHostLost: adminWriteProcedure
    .input(z.object({ kidR: kid, hostId: entityId.regex(/^[A-Za-z0-9_-]+$/) }))
    .handler(async ({ input, context }) => {
      const result = await declareHostReturnKeyLost(input, context.adminTx);
      if (!result.ok) refuse(result.reason);
      const actor = context.session.user.id;
      context.afterCommit(async () =>
        audit("credential.return_key_host_declared_lost", actor, {
          kidR: input.kidR,
          hostId: input.hostId,
        }),
      );
      return { kidR: input.kidR, hostId: input.hostId, declaredLost: true as const };
    }),
};
