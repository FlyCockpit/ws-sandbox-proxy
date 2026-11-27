import prisma from "@wssp/db";
import { BASE_ERROR_CODES, type BetterAuthOptions } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { APIError } from "better-auth/api";
import {
  type CredentialTransactionClient,
  type CredentialTransactionDatabase,
  withCredentialTransaction,
} from "./credential-revocation.js";
import { withLockSlot, withTransactionSlot } from "./lock-slots.js";
import {
  assertPasswordWriteLocked,
  isResetPasswordWrite,
  passwordWriteLockKey,
} from "./password-write-lock.js";

type Adapter = ReturnType<ReturnType<typeof prismaAdapter>>;
const RESET_PREFIX = "reset-password:";

async function lockOwner(tx: CredentialTransactionClient, userId: string): Promise<void> {
  const owners = await tx.$queryRaw<{ id: string }[]>`
    SELECT id FROM "user" WHERE id = ${userId} FOR NO KEY UPDATE`;
  if (owners.length !== 1 || owners[0]?.id !== userId)
    throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_TOKEN);
}

function deleteResetTokens(tx: CredentialTransactionClient, userId: string) {
  return tx.verification.deleteMany({
    where: { value: userId, identifier: { startsWith: RESET_PREFIX } },
  });
}

/**
 * Only BA's reset transaction is real. Signup's locale/SMTP callbacks remain
 * outside transactions. Verification uses the same PW -> owner order in one
 * short transaction; WSSP has no shown-link metadata or IdP activation path.
 */
export function createPasswordResetAdapter(database: CredentialTransactionDatabase = prisma) {
  return (options: BetterAuthOptions): Adapter => {
    // Keep the caller's extended Prisma client, including session notifications.
    const make = (client: object) =>
      prismaAdapter(client, { provider: "postgresql", transaction: false })(options);
    const transact = <T>(work: (tx: CredentialTransactionClient) => Promise<T>) =>
      withLockSlot(() => withTransactionSlot(() => withCredentialTransaction(database, work)));
    const bind = (
      inner: Adapter,
      tx?: CredentialTransactionClient,
      spent?: { userId?: string },
    ): Adapter => {
      const verificationWrite = async <T>(
        args: Parameters<Adapter["update"]>[0],
        write: (adapter: Adapter) => Promise<T>,
      ): Promise<T> => {
        const selector = args.where[0];
        if (
          args.where.length !== 1 ||
          !selector ||
          !["id", "email"].includes(selector.field) ||
          (selector.operator && selector.operator !== "eq") ||
          selector.mode === "insensitive" ||
          typeof selector.value !== "string"
        )
          throw new Error("Activation requires an exact user selector");
        const target = await inner.findOne<{ id: string }>({ model: "user", where: args.where });
        if (!target) return write(inner);
        const activate = async (client: CredentialTransactionClient, writer: Adapter) => {
          if (tx) assertPasswordWriteLocked(target.id);
          else
            await client.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${passwordWriteLockKey(target.id)}))`;
          await lockOwner(client, target.id);
          const result = await write(writer);
          await deleteResetTokens(client, target.id);
          return result;
        };
        if (tx) return activate(tx, inner);
        return transact((client) => activate(client, make(client)));
      };
      return {
        ...inner,
        options: inner.options && {
          ...inner.options,
          adapterConfig: {
            ...inner.options.adapterConfig,
            // BA checks this after failure; the path marker must survive lapse.
            get transaction() {
              return isResetPasswordWrite() ? inner.transaction : false;
            },
          },
        },
        transaction: async (callback) => {
          if (tx || !isResetPasswordWrite()) return callback(bind(inner, tx, spent));
          return transact(async (client) => {
            const reset: { userId?: string } = {};
            const result = await callback(bind(make(client), client, reset));
            if (reset.userId) {
              // These writes belong to the chosen password, never mailbox proof.
              await deleteResetTokens(client, reset.userId);
              await client.user.updateMany({
                where: { id: reset.userId, mustChangePassword: true },
                data: { mustChangePassword: false },
              });
            }
            return result;
          });
        },
        consumeOne: async <T>(args: Parameters<Adapter["consumeOne"]>[0]): Promise<T | null> => {
          if (args.model.toLowerCase() !== "verification") return inner.consumeOne<T>(args);
          const row = await inner.findOne<{ identifier: string; value: string; expiresAt: Date }>({
            ...args,
          });
          if (!row?.identifier.startsWith(RESET_PREFIX)) return inner.consumeOne<T>(args);
          if (!tx || !spent || !isResetPasswordWrite())
            throw new Error("Reset consumption requires its password transaction");
          assertPasswordWriteLocked(row.value);
          await lockOwner(tx, row.value);
          // A token read before verify-email/another reset is no authority to spend.
          const live = await inner.findOne<typeof row>({ ...args });
          if (
            !live ||
            live.identifier !== row.identifier ||
            live.value !== row.value ||
            live.expiresAt < new Date()
          )
            throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_TOKEN);
          assertPasswordWriteLocked(live.value);
          const consumed = await inner.consumeOne<T>(args);
          if (consumed) spent.userId = live.value;
          return consumed;
        },
        update: async <T>(args: Parameters<Adapter["update"]>[0]): Promise<T | null> => {
          if (args.model.toLowerCase() !== "user" || args.update.emailVerified !== true)
            return inner.update<T>(args);
          return verificationWrite(args, (writer) => writer.update<T>(args));
        },
        updateMany: async (args) => {
          if (args.model.toLowerCase() !== "user" || args.update.emailVerified !== true)
            return inner.updateMany(args);
          return verificationWrite(args, (writer) => writer.updateMany(args));
        },
      };
    };
    return bind(make(database));
  };
}
