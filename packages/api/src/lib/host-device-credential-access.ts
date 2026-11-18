import { ORPCError } from "@orpc/server";
import { hostSlugFromDeviceLoginScope, isValidHostSlug } from "@wssp/config/host-device-login";
import prisma from "@wssp/db";
import { AccountDeletionConflictError, lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { withAuthorityChange } from "@wssp/db/authority";
import {
  credentialLookupPrefix,
  generateProductCredentialSecret,
  hmacDigestForProductPurpose,
} from "@wssp/db/credential-security";
import { prelockHostDeviceCredentials } from "../sandbox/host-admission";
import { assertOwnerHostCapacity } from "../sandbox/owner-host-cap";
import { deviceExpiredError, pollUnapprovedDeviceCode } from "./device-code-exchange";
import { deviceDatabaseNow, rethrowDeviceTransactionError } from "./device-code-transitions";
import {
  isOwnerCredentialPolicySatisfied,
  ownerCredentialPolicyUserSelect,
} from "./owner-credential-policy";
import { isPrismaForeignKeyViolation, isPrismaUniqueViolation } from "./prisma-errors";
import { getForcedTwoFactorSettingsRecord } from "./two-factor-policy";

function digestHostDeviceCredentialSecret(rawSecret: string): string {
  return hmacDigestForProductPurpose({ purpose: "deviceCredential", value: rawSecret });
}

/**
 * Exchanges an approved device code for a host-bound `wssp_device_` credential.
 *
 * The slug comes from the device authorization request itself (`scope =
 * "host-slug:<slug>"`). The exchange `hostSlug` must equal it.
 *
 * One transaction: consume the approved code, create or replace the approved host, mint the
 * credential, revoke prior active credentials for that host.
 */
export async function mintHostDeviceCredentialFromApprovedDeviceCode({
  deviceCode,
  hostSlug,
}: {
  deviceCode: string;
  hostSlug: string;
}): Promise<{
  credentialId: string;
  userId: string;
  hostId: string;
  secret: string;
}> {
  if (!isValidHostSlug(hostSlug)) {
    throw new ORPCError("BAD_REQUEST", {
      message: "Host slug must use lowercase letters, numbers, and hyphens only.",
    });
  }

  const row = await prisma.deviceCode.findUnique({
    where: { deviceCode },
    select: {
      id: true,
      userId: true,
      expiresAt: true,
      status: true,
      lastPolledAt: true,
      pollingInterval: true,
      scope: true,
      enrollmentIntent: true,
      replaceHostId: true,
    },
  });

  if (!row) throw new ORPCError("NOT_FOUND", { message: "Device code not found." });
  // A `user-login` (or any non-host) row is refused before it is polled or consumed.
  const boundSlug = hostSlugFromDeviceLoginScope(row.scope);
  if (boundSlug === null) {
    throw new ORPCError("BAD_REQUEST", {
      message:
        "Device authorization does not name a host slug; upgrade wssp and run `wssp host enroll` again.",
    });
  }
  if (boundSlug !== hostSlug) {
    throw new ORPCError("BAD_REQUEST", {
      message: "Device authorization was requested for a different host slug.",
    });
  }
  if (row.status !== "approved" || !row.userId) throw await pollUnapprovedDeviceCode(row);

  const userId = row.userId;
  const secret = generateProductCredentialSecret("deviceCredential");

  try {
    const mint = () =>
      prisma.$transaction(async (tx) => {
        // C21-13: owner lock first (owner → host → device code), serializing
        // with account finalization; a tombstoned owner is refused here.
        await lockOwnerForAdmission(tx, userId);
        // C19-2: replacement H(owner/id/slug) -> D; creation D -> host INSERT.
        // No User UPDATE lock: existing H -> owner FK KEY SHARE writers must coexist.
        let host: { id: string } | undefined;
        if (row.enrollmentIntent === "replace" && row.replaceHostId) {
          const [existing] = await tx.$queryRaw<{ id: string }[]>`
          SELECT id FROM sandbox_host
          WHERE id = ${row.replaceHostId} AND "userId" = ${userId} AND slug = ${boundSlug} AND "deletionRequestedAt" IS NULL
          FOR UPDATE`;
          if (!existing)
            throw new ORPCError("CONFLICT", {
              message: "The approved host changed or was deleted.",
            });
          host = existing;
        } else if (row.enrollmentIntent !== "create") {
          throw new ORPCError("CONFLICT", {
            message: "Device request has no approved enrollment intent.",
          });
        }
        await tx.$queryRaw`SELECT id FROM device_code WHERE id = ${row.id} FOR UPDATE`;
        // Check consumption before attempting an INSERT that might collide with an earlier mint.
        const current = await tx.deviceCode.findUnique({
          where: { id: row.id },
          select: { id: true },
        });
        if (!current) throw new ORPCError("NOT_FOUND", { message: "Device code not found." });
        if (row.enrollmentIntent === "create") {
          // C52-R2-3: same per-owner cap and lock as `createHost` (owner →
          // cap lock → INSERT). The approved code is not consumed on refusal.
          await assertOwnerHostCapacity(tx, userId);
          host = await tx.sandboxHost.create({
            data: { userId, slug: boundSlug, label: boundSlug },
            select: { id: true },
          });
        }
        if (!host) throw new Error("Missing enrollment host");
        // Validate expiry after host/unique waits, then revalidate after the remaining writes.
        const commitNow = await deviceDatabaseNow(tx);
        if (row.expiresAt <= commitNow) throw deviceExpiredError();
        const consumed = await tx.deviceCode.deleteMany({
          where: {
            id: row.id,
            status: "approved",
            userId,
            expiresAt: { gt: commitNow },
            enrollmentIntent: row.enrollmentIntent,
            replaceHostId: row.replaceHostId,
          },
        });
        if (consumed.count !== 1) {
          throw new ORPCError("NOT_FOUND", {
            message: "Device code consumed, changed or expired.",
          });
        }

        const created = await tx.hostDeviceCredential.create({
          data: {
            userId,
            sandboxHostId: host.id,
            lookupPrefix: credentialLookupPrefix(secret),
            secretDigest: digestHostDeviceCredentialSecret(secret.raw),
          },
          select: { id: true, userId: true },
        });

        await prelockHostDeviceCredentials(tx, host.id);
        // Set-based, owner/host-bounded revocation; no enrollment-history materialization.
        await tx.hostDeviceCredential.updateMany({
          where: { userId, sandboxHostId: host.id, revokedAt: null, id: { not: created.id } },
          data: { revokedAt: commitNow },
        });

        // Last: all row, FK KEY SHARE and unique-index waits have finished. These reads
        // use this transaction's connection; the pure policy uses the final database clock.
        const settings = await getForcedTwoFactorSettingsRecord(tx);
        const owner = await tx.user.findUnique({
          where: { id: userId },
          select: { ...ownerCredentialPolicyUserSelect, emailVerified: true },
        });
        const policyNow = await deviceDatabaseNow(tx);
        if (row.expiresAt <= policyNow) throw deviceExpiredError();
        if (
          !owner?.emailVerified ||
          !(await isOwnerCredentialPolicySatisfied(owner, policyNow, settings))
        ) {
          throw new ORPCError("FORBIDDEN", {
            message: "Owner credential policy is not satisfied.",
          });
        }

        return {
          credentialId: created.id,
          userId: created.userId,
          hostId: host.id,
          secret: secret.raw,
        };
      });
    // Replacement revokes that host's prior credentials: a host-scoped authority
    // change. Create intent revokes nothing, so it must not disturb live sockets (C21-7).
    return row.enrollmentIntent === "replace" && row.replaceHostId
      ? await withAuthorityChange({ ownerId: userId, hostId: row.replaceHostId }, mint)
      : await mint();
  } catch (error) {
    if (error instanceof ORPCError) throw error;
    if (error instanceof AccountDeletionConflictError || isPrismaForeignKeyViolation(error))
      throw new ORPCError("CONFLICT", { message: "The account changed during enrollment." });
    if (isHostSlugConflict(error)) {
      throw new ORPCError("CONFLICT", {
        message: "A host with this slug already exists.",
      });
    }
    rethrowDeviceTransactionError(error);
  }
}

function isHostSlugConflict(error: unknown): boolean {
  if (!isPrismaUniqueViolation(error) || !error || typeof error !== "object" || !("meta" in error))
    return false;
  const meta = error.meta;
  if (!meta || typeof meta !== "object" || !("target" in meta)) return false;
  const target = meta.target;
  return (
    target === "sandbox_host_userId_slug_key" ||
    (Array.isArray(target) &&
      target.length === 2 &&
      target.includes("userId") &&
      target.includes("slug"))
  );
}
