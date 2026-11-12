import type { Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import limits from "../../../config/src/credential-limits.json";
import { credentialError } from "./errors";

/**
 * Instance selection and lease claims.
 *
 * Deadlock freedom (N3): a multi-login request is processed in sorted
 * `credentialId` order; per login the credential row is locked FOR SHARE and up
 * to 8 candidate ids are read from a partial pick index WITHOUT locking; each
 * candidate is then claimed by ONE conditional UPDATE whose WHERE re-checks
 * readiness, pause and room (EvalPlanQual), so a failed candidate holds no lock
 * and a transaction holds at most one instance row per login. Account rows are
 * never locked by claims: pause takes the account FOR UPDATE and then updates
 * the denormalized `accountPaused` of its instances, which the claim's UPDATE
 * re-evaluates. Lock order: ... S → credential → instance → lease → O.
 *
 * Every function here runs inside the caller's transaction, after the caller's
 * own prefix (User/K/placement/G/H/S) and before the operation row (O).
 */

type Tx = Prisma.TransactionClient;

const SELECTION_CANDIDATES: number = limits.selectionCandidates;

/** One login of a request. Naming an account or instance applies to this claim only. */
export type CredentialClaimRequest = {
  credentialId: string;
  accountId?: string | null;
  instanceId?: string | null;
};

export type ClaimedLease = {
  leaseId: string;
  credentialId: string;
  accountId: string;
  instanceId: string;
  exclusive: boolean;
  baseSeq: number | null;
};

type ClaimRow = {
  id: string;
  accountId: string;
  currentSeq: number | null;
  capacity: number | null;
};

/** Locks the login FOR SHARE (blocks delete, re-pin and settings, which take it FOR UPDATE). */
export async function lockCredentialForClaim(tx: Tx, ownerId: string, credentialId: string) {
  const rows = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM credential
    WHERE id = ${credentialId} AND "userId" = ${ownerId} AND "deletedAt" IS NULL FOR SHARE`;
  if (rows.length !== 1) throw credentialError("credential.not_found");
}

/** Candidate ids from the pick indexes, read without locks. */
async function candidateIds(
  tx: Tx,
  ownerId: string,
  request: CredentialClaimRequest,
): Promise<string[]> {
  if (request.instanceId) {
    const rows = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM credential_instance
      WHERE id = ${request.instanceId} AND "credentialId" = ${request.credentialId} AND "userId" = ${ownerId}
        ${request.accountId ? sqlAccount(request.accountId) : emptySql()}`;
    return rows.map((row) => row.id);
  }
  if (request.accountId) {
    const rows = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM credential_instance
      WHERE "accountId" = ${request.accountId} AND "credentialId" = ${request.credentialId} AND "userId" = ${ownerId}
        AND state = 'READY' AND "loginLeaseId" IS NULL AND (capacity IS NULL OR "activeLeases" < capacity)
      ORDER BY ordinal, id LIMIT ${SELECTION_CANDIDATES}`;
    return rows.map((row) => row.id);
  }
  const rows = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM credential_instance
    WHERE "credentialId" = ${request.credentialId} AND "userId" = ${ownerId}
      AND state = 'READY' AND NOT "accountPaused" AND "loginLeaseId" IS NULL
      AND (capacity IS NULL OR "activeLeases" < capacity)
    ORDER BY "accountOrdinal", ordinal, id LIMIT ${SELECTION_CANDIDATES}`;
  return rows.map((row) => row.id);
}

function sqlAccount(accountId: string) {
  return PrismaValue.sql`AND "accountId" = ${accountId}`;
}
function emptySql() {
  return PrismaValue.empty;
}

/** The one conditional claim statement; a failed re-check locks nothing. */
async function tryClaim(tx: Tx, instanceId: string): Promise<ClaimRow | null> {
  const rows = await tx.$queryRaw<ClaimRow[]>`UPDATE credential_instance
    SET "activeLeases" = "activeLeases" + 1, "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id = ${instanceId} AND state = 'READY' AND "loginLeaseId" IS NULL
      AND NOT "accountPaused" AND (capacity IS NULL OR "activeLeases" < capacity)
    RETURNING id, "accountId", "currentSeq", capacity`;
  return rows[0] ?? null;
}

/** Names the refusal after every candidate failed twice (§7.2 table). */
async function refusal(tx: Tx, ownerId: string, request: CredentialClaimRequest): Promise<never> {
  if (request.instanceId) {
    const rows = await tx.$queryRaw<
      { state: string; accountPaused: boolean; full: boolean; held: boolean }[]
    >`SELECT state::text AS state, "accountPaused",
        (capacity IS NOT NULL AND "activeLeases" >= capacity) AS full, ("loginLeaseId" IS NOT NULL) AS held
      FROM credential_instance WHERE id = ${request.instanceId} AND "credentialId" = ${request.credentialId}
        AND "userId" = ${ownerId}
        ${request.accountId ? sqlAccount(request.accountId) : emptySql()}`;
    const instance = rows[0];
    if (!instance) throw credentialError("credential.instance_not_found");
    if (instance.accountPaused) throw credentialError("credential.account_paused");
    if (instance.state !== "READY") throw credentialError("credential.needs_login");
    throw credentialError("credential.in_use");
  }
  if (request.accountId) {
    const accounts = await tx.$queryRaw<
      { paused: boolean }[]
    >`SELECT ("pausedAt" IS NOT NULL) AS paused
      FROM credential_account WHERE id = ${request.accountId} AND "credentialId" = ${request.credentialId}
        AND "userId" = ${ownerId}`;
    const account = accounts[0];
    if (!account) throw credentialError("credential.account_not_found");
    if (account.paused) throw credentialError("credential.account_paused");
  }
  const counts = await tx.$queryRaw<{ ready: number; readyUnpaused: number }[]>`SELECT
      count(*) FILTER (WHERE state = 'READY')::int AS ready,
      count(*) FILTER (WHERE state = 'READY' AND NOT "accountPaused")::int AS "readyUnpaused"
    FROM credential_instance WHERE "credentialId" = ${request.credentialId} AND "userId" = ${ownerId}
      ${request.accountId ? sqlAccount(request.accountId) : emptySql()}`;
  const { ready = 0, readyUnpaused = 0 } = counts[0] ?? {};
  if (ready === 0) throw credentialError("credential.needs_login");
  if (readyUnpaused === 0) throw credentialError("credential.account_paused");
  throw credentialError("credential.in_use");
}

/**
 * Read-only pre-check before placement (E1-B-05): when no instance the
 * request names could be claimed right now, throw the same refusal the
 * claim would (`credential.in_use`, `account_paused`, `needs_login`, …), so
 * a deterministic login refusal wins over a capacity answer from placement.
 * Takes no lock and claims nothing: the claim after placement stays
 * authoritative (a concurrent free or take is decided there).
 *
 * `slots: false` — a create that may wait for capacity: only the static and
 * READY checks apply (the instance exists, is READY and unpaused). Whether a
 * slot is free (room left, no login holder) is decided when the create is
 * placed, by the claim: a slot held now may be free by then.
 */
export async function refuseUnclaimableLogin(
  tx: Tx,
  ownerId: string,
  request: CredentialClaimRequest,
  options: { slots: boolean } = { slots: true },
): Promise<void> {
  const logins = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM credential
    WHERE id = ${request.credentialId} AND "userId" = ${ownerId} AND "deletedAt" IS NULL`;
  // A missing login keeps its own refusal at the claim (`credential.not_found`).
  if (logins.length === 0) return;
  const rows = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM credential_instance
    WHERE "credentialId" = ${request.credentialId} AND "userId" = ${ownerId}
      ${request.instanceId ? PrismaValue.sql`AND id = ${request.instanceId}` : emptySql()}
      ${request.accountId ? sqlAccount(request.accountId) : emptySql()}
      AND state = 'READY' AND NOT "accountPaused"
      ${
        options.slots
          ? PrismaValue.sql`AND "loginLeaseId" IS NULL AND (capacity IS NULL OR "activeLeases" < capacity)`
          : emptySql()
      }
    LIMIT 1`;
  if (rows.length === 0) await refusal(tx, ownerId, request);
}

async function claimOne(
  tx: Tx,
  ownerId: string,
  request: CredentialClaimRequest,
): Promise<ClaimRow> {
  await lockCredentialForClaim(tx, ownerId, request.credentialId);
  // Read candidates, try each once; then re-read once (§7.2 step 4).
  for (let pass = 0; pass < 2; pass++) {
    for (const id of await candidateIds(tx, ownerId, request)) {
      const claimed = await tryClaim(tx, id);
      if (claimed) return claimed;
    }
  }
  return refusal(tx, ownerId, request);
}

/**
 * Claims one WORKLOAD lease per requested login for `sandboxId`, in sorted
 * `credentialId` order. Leases start RESERVED; the instance's `activeLeases`
 * is incremented in the same statement that admits it. A request naming the
 * same login twice is refused before any claim.
 */
export async function claimWorkloadLeases(
  tx: Tx,
  input: {
    ownerId: string;
    sandboxId: string;
    operationId: string;
    requests: readonly CredentialClaimRequest[];
    /** The placed host, when placement has chosen one (grant fence step 1). */
    hostId?: string | null;
  },
): Promise<ClaimedLease[]> {
  const sorted = [...input.requests].sort((a, b) =>
    a.credentialId < b.credentialId ? -1 : a.credentialId > b.credentialId ? 1 : 0,
  );
  if (sorted.length > limits.attachmentsPerSandbox)
    throw credentialError("credential.limit_reached", { limit: limits.attachmentsPerSandbox });
  for (let i = 1; i < sorted.length; i++)
    if (sorted[i]!.credentialId === sorted[i - 1]!.credentialId)
      throw credentialError("credential.limit_reached", { reason: "duplicate_login" });
  const leases: ClaimedLease[] = [];
  for (const request of sorted) leases.push(await claimWorkloadLease(tx, { ...input, request }));
  return leases;
}

/**
 * One WORKLOAD claim (named rules for whatever the request names). Callers
 * processing several logins call this in sorted `credentialId` order.
 */
export async function claimWorkloadLease(
  tx: Tx,
  input: {
    ownerId: string;
    sandboxId: string;
    operationId: string;
    request: CredentialClaimRequest;
    hostId?: string | null;
  },
): Promise<ClaimedLease> {
  const { request } = input;
  const claimed = await claimOne(tx, input.ownerId, request);
  const exclusive = claimed.capacity === 1;
  const lease = await tx.credentialLease.create({
    data: {
      userId: input.ownerId,
      credentialId: request.credentialId,
      accountId: claimed.accountId,
      instanceId: claimed.id,
      sandboxId: input.sandboxId,
      operationId: input.operationId,
      kind: "WORKLOAD",
      exclusive,
      state: "RESERVED",
      hostId: input.hostId ?? null,
    },
    select: { id: true },
  });
  return {
    leaseId: lease.id,
    credentialId: request.credentialId,
    accountId: claimed.accountId,
    instanceId: claimed.id,
    exclusive,
    baseSeq: claimed.currentSeq,
  };
}

/**
 * Login claim (N9): the instance must have no holder at all; any state, pause
 * ignored. Setting `loginLeaseId` in the same statement keeps every workload
 * claim and value write out until the session ends. The LOGIN lease is
 * exclusive, so the partial unique barrier covers it too.
 */
export async function claimLoginLease(
  tx: Tx,
  input: {
    ownerId: string;
    credentialId: string;
    instanceId: string;
    loginSessionId: string;
    operationId: string;
    sandboxId?: string | null;
  },
): Promise<ClaimedLease> {
  await lockCredentialForClaim(tx, input.ownerId, input.credentialId);
  const leaseId = newLeaseId();
  const rows = await tx.$queryRaw<ClaimRow[]>`UPDATE credential_instance
    SET "activeLeases" = "activeLeases" + 1, "loginLeaseId" = ${leaseId},
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id = ${input.instanceId} AND "credentialId" = ${input.credentialId} AND "userId" = ${input.ownerId}
      AND "activeLeases" = 0 AND "loginLeaseId" IS NULL
    RETURNING id, "accountId", "currentSeq", capacity`;
  const claimed = rows[0];
  if (!claimed) {
    const exists = await tx.credentialInstance.findFirst({
      where: { id: input.instanceId, credentialId: input.credentialId, userId: input.ownerId },
      select: { id: true },
    });
    throw credentialError(exists ? "credential.busy" : "credential.instance_not_found");
  }
  await tx.credentialLease.create({
    data: {
      id: leaseId,
      userId: input.ownerId,
      credentialId: input.credentialId,
      accountId: claimed.accountId,
      instanceId: claimed.id,
      sandboxId: input.sandboxId ?? null,
      loginSessionId: input.loginSessionId,
      operationId: input.operationId,
      kind: "LOGIN",
      exclusive: true,
      state: "RESERVED",
    },
    select: { id: true },
  });
  return {
    leaseId,
    credentialId: input.credentialId,
    accountId: claimed.accountId,
    instanceId: claimed.id,
    exclusive: true,
    baseSeq: claimed.currentSeq,
  };
}

function newLeaseId(): string {
  // cuid2-compatible alphabet and length bound (entity ids ≤ 64).
  return `cl${globalThis.crypto.randomUUID().replaceAll("-", "")}`;
}
