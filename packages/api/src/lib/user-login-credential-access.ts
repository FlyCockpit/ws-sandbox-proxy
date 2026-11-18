import { ORPCError } from "@orpc/server";
import {
  isUserDeviceLoginScope,
  USER_LOGIN_ACTIVE_KEY_LIMIT,
  userLoginGrantSchema,
  userLoginScopes,
} from "@wssp/config/user-device-login";
import prisma from "@wssp/db";
import { AccountDeletionConflictError } from "@wssp/db/account-deletion";
import {
  assertMintableGrant,
  insertSdkKey,
  lockSdkKeyMint,
  rethrowSdkKeyMintError,
  selectedPoolOwnerIds,
} from "../sandbox/sdk-key-mint";
import { deviceExpiredError, pollUnapprovedDeviceCode } from "./device-code-exchange";
import { deviceDatabaseNow, rethrowDeviceTransactionError } from "./device-code-transitions";
import {
  isOwnerCredentialPolicySatisfied,
  ownerCredentialPolicyUserSelect,
} from "./owner-credential-policy";
import { isPrismaForeignKeyViolation } from "./prisma-errors";
import { generateSdkKeySecret } from "./sdk-key-access";
import { parseServiceScopeSet } from "./service-scopes";
import { getForcedTwoFactorSettingsRecord } from "./two-factor-policy";

const DAY_MS = 86_400_000;

export type MintedUserLogin = {
  keyId: string;
  secret: string;
  name: string;
  userId: string;
  email: string;
  scopes: string[];
  poolMode: "ALL_USABLE" | "SELECTED";
  poolIds: string[];
  ownSandboxesOnly: boolean;
  expiresAt: Date;
  maxLiveSandboxes: number | null;
};

function poolNoLongerUsable(error: unknown): boolean {
  if (!(error instanceof ORPCError)) return false;
  const data: unknown = error.data;
  return (
    !!data && typeof data === "object" && "code" in data && data.code === "sandbox.pool_not_found"
  );
}

/**
 * Exchanges an approved `user-login` device code for a `wssp_sdk_` API key with
 * exactly the grant the approver chose on the approval page (`loginGrant`).
 *
 * Same poll contract as the host exchange. A host-enrollment code is refused
 * before it is polled or consumed. One transaction consumes the code and mints
 * the key; lock order:
 *   1. sharing principals: the owner and the selected pools' owners, sorted
 *      (`lockOwnerForAdmission` each, plus a ban check);
 *   2. the owner's placement lock (`lockOwnerPlacement`), under which the
 *      active CLI-login cap is counted;
 *   3. the device code row (FOR UPDATE), then its conditional delete;
 *   4. the selected pools' graph (FOR UPDATE), then `requirePoolUse` per pool;
 *   5. the key INSERT, then the owner-credential policy on the final clock.
 * Any refusal rolls back and leaves the approved code unconsumed.
 */
export async function mintUserLoginFromApprovedDeviceCode({
  deviceCode,
}: {
  deviceCode: string;
}): Promise<MintedUserLogin> {
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
      loginGrant: true,
    },
  });
  if (!row) throw new ORPCError("NOT_FOUND", { message: "Device code not found." });
  if (!isUserDeviceLoginScope(row.scope)) {
    throw new ORPCError("BAD_REQUEST", {
      message: "This device code is a host enrollment; finish it with `wssp host enroll`.",
    });
  }
  if (row.status !== "approved" || !row.userId) throw await pollUnapprovedDeviceCode(row);

  const parsedGrant = userLoginGrantSchema.safeParse(row.loginGrant);
  if (!parsedGrant.success)
    throw new ORPCError("CONFLICT", { message: "Device request has no approved login grant." });
  const grant = parsedGrant.data;
  const userId = row.userId;
  const scopes = parseServiceScopeSet(userLoginScopes(grant.access));
  assertMintableGrant(scopes, {
    resourceMode: "ALL_OWNED",
    poolMode: grant.poolMode,
    hostIds: [],
    poolIds: grant.poolIds,
    credentialIds: [],
  });
  const credential = generateSdkKeySecret();
  const poolOwnerIds = await selectedPoolOwnerIds(grant.poolIds);

  try {
    return await prisma.$transaction(async (tx) => {
      await lockSdkKeyMint(tx, userId, poolOwnerIds);
      await tx.$queryRaw`SELECT id FROM device_code WHERE id = ${row.id} FOR UPDATE`;
      const current = await tx.deviceCode.findUnique({
        where: { id: row.id },
        select: { id: true },
      });
      if (!current) throw new ORPCError("NOT_FOUND", { message: "Device code not found." });
      const now = await deviceDatabaseNow(tx);
      if (row.expiresAt <= now) throw deviceExpiredError();
      // Counted under the owner placement lock: concurrent exchanges serialize.
      const active = await tx.sdkKey.count({
        where: {
          userId,
          kind: "API",
          origin: "CLI_LOGIN",
          revokedAt: null,
          OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
        },
      });
      if (active >= USER_LOGIN_ACTIVE_KEY_LIMIT)
        throw new ORPCError("CONFLICT", {
          message: "Active CLI login limit reached. Revoke an old login first.",
          data: { code: "user_login.limit", limit: USER_LOGIN_ACTIVE_KEY_LIMIT },
        });
      const consumed = await tx.deviceCode.deleteMany({
        where: { id: row.id, status: "approved", userId, expiresAt: { gt: now } },
      });
      if (consumed.count !== 1)
        throw new ORPCError("NOT_FOUND", { message: "Device code consumed, changed or expired." });

      const created = await insertSdkKey(tx, userId, {
        kind: "API",
        origin: "CLI_LOGIN",
        name: grant.name,
        scopes,
        resourceMode: "ALL_OWNED",
        poolMode: grant.poolMode,
        hostIds: [],
        templateRevisionIds: [],
        poolIds: grant.poolIds,
        credentialIds: [],
        ownSandboxesOnly: grant.ownSandboxesOnly,
        expiresAt: new Date(now.getTime() + grant.expiresInDays * DAY_MS),
        maxLiveSandboxes: grant.maxLiveSandboxes,
        credential,
      });

      // Last, as in the host mint: every lock wait is over; the pure policy
      // uses the final database clock.
      const settings = await getForcedTwoFactorSettingsRecord(tx);
      const owner = await tx.user.findUnique({
        where: { id: userId },
        select: { ...ownerCredentialPolicyUserSelect, emailVerified: true, email: true },
      });
      const policyNow = await deviceDatabaseNow(tx);
      if (row.expiresAt <= policyNow) throw deviceExpiredError();
      if (
        !owner?.emailVerified ||
        !(await isOwnerCredentialPolicySatisfied(owner, policyNow, settings))
      ) {
        throw new ORPCError("FORBIDDEN", { message: "Owner credential policy is not satisfied." });
      }
      if (!created.expiresAt) throw new Error("CLI login minted without expiry");
      return {
        keyId: created.id,
        secret: credential.raw,
        name: created.name,
        userId,
        email: owner.email,
        scopes: created.scopes,
        poolMode: created.poolMode,
        poolIds: (created.PoolAllowlist ?? []).map((entry) => entry.poolId),
        ownSandboxesOnly: created.ownSandboxesOnly,
        expiresAt: created.expiresAt,
        maxLiveSandboxes: created.maxLiveSandboxes,
      };
    });
  } catch (error) {
    if (grant.poolIds.length > 0 && poolNoLongerUsable(error))
      throw new ORPCError("FORBIDDEN", {
        message: "A pool this login was approved for is no longer usable; log in again.",
        data: { code: "user_login.pool_unavailable" },
      });
    if (error instanceof ORPCError) throw error;
    if (error instanceof AccountDeletionConflictError || isPrismaForeignKeyViolation(error))
      throw new ORPCError("CONFLICT", { message: "The account changed during login." });
    try {
      rethrowSdkKeyMintError(error);
    } catch (mapped) {
      if (mapped instanceof ORPCError) throw mapped;
      rethrowDeviceTransactionError(mapped);
    }
  }
}
