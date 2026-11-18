import { ORPCError } from "@orpc/server";
import prisma from "@wssp/db";
import { z } from "zod";
import { DataKeyStaleWriter, fenceWriteKey, staleWriterError } from "../crypto/data-key-epoch";
import { adminOr404Procedure, adminWriteProcedure } from "../index";
import { ADMIN_ERROR_CODES, type TunnelConfigRefusal } from "../lib/admin-error-codes";
import { wakeTunnelController } from "../sandbox/tunnels/bridge";
import {
  credentialSha256,
  mintServerKey,
  normalizeTunnelApiUrl,
  sealCredential,
  TUNNEL_CONFIG_ID,
  tunnelConfigPublicSelect,
  tunnelKeys,
  validServiceCredential,
} from "../sandbox/tunnels/config";
import { recordTunnelEvent, TUNNEL_OWED } from "../sandbox/tunnels/rows";
import { checkCredential, TunServerError } from "../sandbox/tunnels/tun-client";

/**
 * Admin preview-tunnel card (docs/guide/tunnels.md#admin-configure-the-tunnel-server):
 * the optional tunnel server this deployment uses. Hidden (404) for
 * non-admins. The service credential is write-only: reads say whether one is
 * stored, never return it.
 *
 * These procedures never call the tunnel server for cleanup (they run inside
 * the short admin write transaction). Turning off only marks the
 * configuration as turning off: the integration is off for callers at once,
 * the controller deletes every tunnel with the stored credential and then
 * removes the configuration. A configuration never changes its server or
 * credential (only its limit): another one is configured after the turn-off
 * finished, so a tunnel is never stranded on a server wssp no longer holds a
 * credential for. Every tunnel row's remote state carries the identity
 * (`serverKey`) it was made with; remove-now is the one way to forget them.
 */

function refuse(reason: TunnelConfigRefusal): never {
  throw new ORPCError("CONFLICT", {
    message: "The tunnel server setting was refused.",
    data: { code: ADMIN_ERROR_CODES.tunnelConfigRefused, reason },
  });
}

export const adminTunnelRouter = {
  get: adminOr404Procedure.handler(async () => {
    const row = await prisma.tunnelServerConfig.findUnique({
      where: { id: TUNNEL_CONFIG_ID },
      select: tunnelConfigPublicSelect,
    });
    const [total, connected] = await Promise.all([
      // Turning off: what is still to delete (rows are closed as it goes).
      prisma.sandboxTunnel.count({ where: row?.disabledAt ? TUNNEL_OWED : { closedAt: null } }),
      prisma.sandboxTunnel.count({ where: { state: "CONNECTED", closedAt: null } }),
    ]);
    return {
      configured: row !== null && row.disabledAt === null,
      /** Turning off: tunnels are being deleted; the setting disappears after. */
      turningOff: row?.disabledAt != null,
      apiUrl: row?.apiUrl ?? null,
      maxTunnelsPerOwner: row?.maxTunnelsPerOwner ?? 10,
      updatedAt: row?.updatedAt.toISOString() ?? null,
      /** DATA_ENCRYPTION_KEY is set: a credential can be stored. */
      keyAvailable: tunnelKeys() !== null,
      tunnels: { total, connected },
    };
  }),

  set: adminWriteProcedure
    .input(
      z
        .object({
          apiUrl: z.string().max(300),
          /** Write-only; omitted keeps the stored one (same server only). */
          credential: z.string().max(200).optional(),
          maxTunnelsPerOwner: z.number().int().min(1).max(1000).optional(),
        })
        .strict(),
    )
    .handler(async ({ input, context }) => {
      const apiUrl = normalizeTunnelApiUrl(input.apiUrl);
      if (!apiUrl) refuse("url_invalid");
      const keys = tunnelKeys();
      if (!keys) refuse("key_missing");
      const credential = input.credential?.trim() || null;
      if (credential !== null && !validServiceCredential(credential)) refuse("credential_invalid");
      // Serialized with the controller (FOR SHARE) and other admins.
      const [locked] = await context.adminTx.$queryRaw<
        { disabledAt: Date | null; apiUrl: string; credentialSha256: string }[]
      >`SELECT "disabledAt", "apiUrl", "credentialSha256" FROM tunnel_server_config
        WHERE id = ${TUNNEL_CONFIG_ID} FOR UPDATE`;
      const actor = context.session.user.id;
      if (locked) {
        // A configuration keeps its server and credential for its whole life:
        // tunnels made with it are deleted with it. Another server or
        // credential: turn tunnels off, wait until the setting is gone, then
        // configure it.
        if (locked.disabledAt) refuse("turning_off");
        if (
          locked.apiUrl !== apiUrl ||
          (credential !== null && credentialSha256(credential) !== locked.credentialSha256)
        )
          refuse("turn_off_first");
        const maxTunnelsPerOwner = input.maxTunnelsPerOwner;
        if (maxTunnelsPerOwner !== undefined)
          await context.adminTx.tunnelServerConfig.update({
            where: { id: TUNNEL_CONFIG_ID },
            data: { maxTunnelsPerOwner, updatedById: actor },
          });
        return { configured: true, apiUrl, changed: false };
      }
      if (credential === null) refuse("credential_required");
      try {
        await checkCredential({ apiUrl, credential });
      } catch (error) {
        refuse(
          error instanceof TunServerError && error.unauthorized
            ? "credential_rejected"
            : "server_unreachable",
        );
      }
      try {
        const key = await fenceWriteKey(context.adminTx, keys.all);
        const sealed = sealCredential(credential, apiUrl, key);
        const hash = credentialSha256(credential);
        // A plain create: a concurrent first configure fails on the key
        // instead of replacing an identity rows may already carry.
        await context.adminTx.tunnelServerConfig.create({
          data: {
            id: TUNNEL_CONFIG_ID,
            apiUrl,
            credentialCiphertext: new Uint8Array(sealed.ciphertext),
            credentialNonce: new Uint8Array(sealed.nonce),
            credentialKeyId: sealed.keyId,
            credentialSha256: hash,
            serverKey: mintServerKey(apiUrl, hash),
            maxTunnelsPerOwner: input.maxTunnelsPerOwner ?? 10,
            updatedById: actor,
          },
        });
        await recordTunnelEvent(context.adminTx, {
          kind: "config.set",
          actorId: actor,
          detail: apiUrl,
        });
      } catch (error) {
        if (error instanceof DataKeyStaleWriter) throw staleWriterError();
        // Another admin configured one at the same moment.
        if (
          typeof error === "object" &&
          error !== null &&
          "code" in error &&
          error.code === "P2002"
        )
          refuse("turn_off_first");
        throw error;
      }
      context.afterCommit(async () => {
        console.info(JSON.stringify({ event: "tunnel.config_set", actor, apiUrl }));
        wakeTunnelController();
      });
      return { configured: true, apiUrl, changed: true };
    }),

  /** Turn tunnels off: callers are refused at once; the controller deletes
   * every tunnel, then removes the setting. */
  clear: adminWriteProcedure
    .input(
      z
        .object({
          /** Last resort (the tunnel server is gone for good): remove the
           * setting now and close every tunnel record (forgetting what the
           * tunnel server still holds; such tunnels stop when their 7-day
           * TTL ends). Closed rows keep their generation: hosts fence on it. */
          removeNow: z.literal(true).optional(),
        })
        .strict()
        .optional(),
    )
    .handler(async ({ input, context }) => {
      const actor = context.session.user.id;
      if (input?.removeNow) {
        // Serialized with every write that gives a row this configuration's
        // key (FOR SHARE there): no row keeps a key the setting outlived.
        await context.adminTx.$queryRaw`SELECT 1 AS locked FROM tunnel_server_config
          WHERE id = ${TUNNEL_CONFIG_ID} FOR UPDATE`;
        const rows = await context.adminTx.sandboxTunnel.count({ where: TUNNEL_OWED });
        const closedAt = new Date();
        await context.adminTx.sandboxTunnel.updateMany({
          where: TUNNEL_OWED,
          data: {
            closedAt,
            state: "SUSPENDED",
            lastError: null,
            tunTunnelId: null,
            hostTemplate: null,
            hostId: null,
            sweepLabel: false,
            creatingUntil: null,
            serverKey: null,
            generation: { increment: 1 },
          },
        });
        const removed = await context.adminTx.tunnelServerConfig.deleteMany({
          where: { id: TUNNEL_CONFIG_ID },
        });
        await recordTunnelEvent(context.adminTx, {
          kind: "config.removed_now",
          actorId: actor,
          detail: String(rows),
        });
        context.afterCommit(async () =>
          console.info(JSON.stringify({ event: "tunnel.config_removed_now", actor, rows })),
        );
        return { turningOff: removed.count > 0, tunnelsLeft: 0 };
      }
      const turned = await context.adminTx.tunnelServerConfig.updateMany({
        where: { id: TUNNEL_CONFIG_ID, disabledAt: null },
        data: { disabledAt: new Date() },
      });
      if (turned.count > 0)
        await recordTunnelEvent(context.adminTx, { kind: "config.turning_off", actorId: actor });
      context.afterCommit(async () => {
        console.info(JSON.stringify({ event: "tunnel.config_turning_off", actor }));
        wakeTunnelController();
      });
      const pending = await context.adminTx.sandboxTunnel.count({ where: TUNNEL_OWED });
      return { turningOff: turned.count > 0, tunnelsLeft: pending };
    }),
};
