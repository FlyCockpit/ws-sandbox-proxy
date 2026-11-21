import type { Prisma } from "../prisma/generated/client";
import { assertAdminRemains, lockAdminGovernance } from "./admin-governance";
import { withAuthorityChange } from "./authority";
import prisma from "./index";

function isPrismaForeignKeyViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "P2003";
}

/**
 * Live state that refuses account deletion. Logical templates, immutable
 * revisions, availability and private defaults are history, never blockers;
 * the finalizer clears them after live hosts and sandbox work are gone.
 */
export type AccountDeletionBlockerKind =
  | "hosts"
  | "sandboxes"
  | "operations"
  | "outbox"
  | "transfers"
  | "image_jobs"
  | "shared_pool_workloads";

export class AccountDeletionConflictError extends Error {
  readonly kinds: AccountDeletionBlockerKind[];

  constructor(kinds: AccountDeletionBlockerKind[], message?: string) {
    super(
      message ??
        (kinds.length > 0
          ? `Account deletion is blocked while these resources remain: ${kinds.join(", ")}. Remove them first.`
          : "Account deletion is in progress."),
    );
    this.name = "AccountDeletionConflictError";
    this.kinds = kinds;
  }
}

/** Serializes owner-row creation with account finalization; rejects in-progress deletion. */
export async function lockOwnerForAdmission(
  tx: Prisma.TransactionClient,
  ownerId: string,
): Promise<void> {
  await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${ownerId} FOR SHARE`;
  const user = await tx.user.findUnique({
    where: { id: ownerId },
    select: { deletionRequestedAt: true },
  });
  if (!user || user.deletionRequestedAt != null) {
    throw new AccountDeletionConflictError([]);
  }
}

const LIVE_OPERATION_STATES = [
  "QUEUED",
  "DISPATCHED",
  "ACCEPTED",
  "RUNNING",
  "CANCEL_REQUESTED",
  "UNKNOWN_OUTCOME",
] as const;

type Tx = Prisma.TransactionClient;

/**
 * The one classification of every model with a relation to User. Account
 * deletion reads its blockers and its finalizing deletes from this table, and
 * `account-deletion.test.ts` (Prisma schema) and `account-deletion.pg.test.ts` (live FKs) fail
 * when a User-related model (Prisma schema) or FK (live database) is missing
 * from it. Array order is the finalizing delete order (Restrict FKs first).
 *
 * Keyed by (model, FK column): a model with two FKs to User needs one entry
 * per FK, each classified against its own ON DELETE.
 *
 * - `blocker`: live rows refuse deletion; its non-live rows are receipts the
 *   finalizing transaction deletes explicitly.
 * - `receipt`: deleted with the account — by FK `Cascade` from the user row
 *   (`cascade`) or by an explicit delete in the finalizing transaction.
 */
export type AccountDeletionClassification =
  | {
      model: string;
      table: string;
      /** The FK column to User; the inventory key is (model, column). */
      column: string;
      class: "blocker";
      kind: AccountDeletionBlockerKind;
      hasLive: (tx: Tx, ownerId: string) => Promise<boolean>;
      finalize: (tx: Tx, ownerId: string) => Promise<unknown>;
    }
  | {
      model: string;
      table: string;
      /** The FK column to User; the inventory key is (model, column). */
      column: string;
      class: "receipt";
      removedBy: "finalize";
      finalize: (tx: Tx, ownerId: string) => Promise<unknown>;
    }
  | { model: string; table: string; column: string; class: "receipt"; removedBy: "cascade" };

export const ACCOUNT_DELETION_CLASSIFICATION: readonly AccountDeletionClassification[] = [
  {
    // Webhook endpoints are receipts: pending deliveries never block deletion.
    // Endpoints go first (their deliveries and attempts cascade), then the
    // FK-free event rows by owner. This is the delivery claim's own order
    // (endpoint, then delivery), so finalization cannot deadlock with an
    // in-progress claim (webhook-lock-order.pg.test.ts).
    model: "WebhookEndpoint",
    table: "webhook_endpoint",
    column: "userId",
    class: "receipt",
    removedBy: "finalize",
    finalize: async (tx, ownerId) => {
      // Lock every endpoint in id order FIRST (webhook fan-out key-share-locks
      // them in the same order): a bulk DELETE visits rows in physical order,
      // which could invert fan-out's order across two endpoints (40P01).
      await tx.$queryRaw`SELECT id FROM webhook_endpoint WHERE "userId" = ${ownerId} ORDER BY id FOR UPDATE`;
      await tx.webhookEndpoint.deleteMany({ where: { userId: ownerId } });
      return tx.webhookEvent.deleteMany({ where: { userId: ownerId } });
    },
  },
  {
    // CLI logins. Every lease that names a surviving
    // host gets a tombstone first, so an envelope that host still holds acks
    // DISCARDED{account_deleted} instead of REJECTED{unknown_lease}. The
    // owner's own hosts are blockers, so any host still present is foreign.
    // Then every credential row is deleted here, children first, before the
    // sandbox rows they reference: leases (bindings and residue cascade),
    // attachments, login sessions, logins (accounts, instances, versions and
    // SDK allowlist rows cascade), definitions, events.
    model: "CredentialLease",
    table: "credential_lease",
    column: "userId",
    class: "receipt",
    removedBy: "finalize",
    finalize: async (tx, ownerId) => {
      await tx.$executeRaw`INSERT INTO credential_lease_tombstone ("hostId", "leaseId", reason)
        SELECT l."hostId", l.id, 'account_deleted' FROM credential_lease l
        JOIN sandbox_host h ON h.id = l."hostId"
        WHERE l."userId" = ${ownerId}
        ORDER BY l."hostId", l.id
        ON CONFLICT DO NOTHING`;
      await tx.$executeRaw`DELETE FROM credential_residue WHERE "userId" = ${ownerId}`;
      await tx.$executeRaw`DELETE FROM credential_lease WHERE "userId" = ${ownerId}`;
      await tx.$executeRaw`DELETE FROM sandbox_credential WHERE "userId" = ${ownerId}`;
      await tx.$executeRaw`DELETE FROM credential_login_session WHERE "userId" = ${ownerId}`;
      await tx.$executeRaw`DELETE FROM credential WHERE "userId" = ${ownerId}`;
      await tx.$executeRaw`DELETE FROM credential_definition WHERE "userId" = ${ownerId}`;
      return tx.$executeRaw`DELETE FROM credential_event WHERE "userId" = ${ownerId}`;
    },
  },
  ...[
    ["McpGrant", "mcp_grant"],
    ["HostQueuedCommand", "host_queued_command"],
    ["HostFileReceipt", "host_file_receipt"],
    ["OauthClient", "oauth_client"],
    ["OauthRefreshToken", "oauth_refresh_token"],
    ["OauthAccessToken", "oauth_access_token"],
    ["OauthConsent", "oauth_consent"],
    ["CredentialDefinition", "credential_definition"],
    ["Credential", "credential"],
    ["CredentialAccount", "credential_account"],
    ["CredentialInstance", "credential_instance"],
    ["CredentialResidue", "credential_residue"],
    ["SandboxCredential", "sandbox_credential"],
    ["CredentialLoginSession", "credential_login_session"],
    ["CredentialEvent", "credential_event"],
    ["SdkKeyCredentialAllowlist", "sdk_key_credential_allowlist"],
  ].map(([model, table]) => ({
    model: model!,
    table: table!,
    column: "userId",
    class: "receipt" as const,
    removedBy: "cascade" as const,
  })),
  ...[
    ["Share", "share", "ownerUserId"],
    ["Share", "share", "granteeUserId"],
    ["ShareInvite", "share_invite", "ownerUserId"],
    ["HostTerminalTicket", "host_terminal_ticket", "userId"],
  ].map(([model, table, column]) => ({
    model: model!,
    table: table!,
    column: column!,
    class: "receipt" as const,
    removedBy: "cascade" as const,
  })),
  {
    model: "SandboxOperationResult",
    table: "sandbox_operation_result",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    model: "SdkKeyPoolAllowlist",
    table: "sdk_key_pool_allowlist",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    model: "SandboxPoolMember",
    table: "sandbox_pool_member",
    column: "userId",
    class: "receipt",
    removedBy: "finalize",
    finalize: (tx, ownerId) => tx.sandboxPoolMember.deleteMany({ where: { userId: ownerId } }),
  },
  {
    model: "SandboxPool",
    table: "sandbox_pool",
    column: "userId",
    class: "blocker",
    kind: "shared_pool_workloads",
    hasLive: async (tx, ownerId) =>
      (
        await tx.$queryRaw<{ live: boolean }[]>`
      SELECT EXISTS (SELECT 1 FROM sandbox_instance s JOIN sandbox_pool p ON p.id = s."usagePoolId"
        WHERE p."userId" = ${ownerId} AND s.state <> 'DELETED'
          AND (p."deletedAt" IS NULL OR s."accessGraceUntil" IS NULL)) AS live
    `
      )[0]?.live === true,
    finalize: (tx, ownerId) => tx.sandboxPool.deleteMany({ where: { userId: ownerId } }),
  },
  {
    model: "SandboxTransfer",
    table: "sandbox_stream_transfer",
    column: "userId",
    class: "blocker",
    kind: "transfers",
    hasLive: async (tx, ownerId) =>
      (await tx.sandboxTransfer.count({ where: { userId: ownerId, reservationHeld: true } })) > 0,
    finalize: (tx, ownerId) => tx.sandboxTransfer.deleteMany({ where: { userId: ownerId } }),
  },
  {
    // Open image jobs (fetch, publish, capture upload) of this owner or on
    // this owner's hosts, plus captures that have not settled. Objects in the
    // image store are reclaimed by the orphan sweeper once the rows are gone.
    model: "SandboxImageTransfer",
    table: "sandbox_image_transfer",
    column: "userId",
    class: "blocker",
    kind: "image_jobs",
    hasLive: async (tx, ownerId) =>
      (
        await tx.$queryRaw<{ live: boolean }[]>`
      SELECT (EXISTS (SELECT 1 FROM sandbox_image_transfer t WHERE t.state = 'OPEN'
          AND (t."userId" = ${ownerId} OR t."destHostOwnerId" = ${ownerId} OR t."sourceHostOwnerId" = ${ownerId}))
        OR EXISTS (SELECT 1 FROM sandbox_template_capture c
          WHERE c.state::text IN ('PENDING', 'CAPTURED', 'STORING')
            AND (c."userId" = ${ownerId} OR c."hostOwnerId" = ${ownerId}))) AS live
    `
      )[0]?.live === true,
    finalize: (tx, ownerId) => tx.sandboxImageTransfer.deleteMany({ where: { userId: ownerId } }),
  },
  {
    // Template builds that have not ended, owned by this account or running on
    // its hosts: named as image work (a build ends in a template capture).
    // Ended builds are history; their staged contexts and chunks cascade.
    model: "SandboxTemplateBuild",
    table: "sandbox_template_build",
    column: "userId",
    class: "blocker",
    kind: "image_jobs",
    hasLive: async (tx, ownerId) =>
      (
        await tx.$queryRaw<{ live: boolean }[]>`
      SELECT EXISTS (SELECT 1 FROM sandbox_template_build b
        WHERE b.state::text NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
          AND (b."userId" = ${ownerId} OR b."hostOwnerId" = ${ownerId})) AS live
    `
      )[0]?.live === true,
    finalize: (tx, ownerId) => tx.sandboxTemplateBuild.deleteMany({ where: { userId: ownerId } }),
  },
  {
    model: "SandboxImageArtifact",
    table: "sandbox_image_artifact",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    model: "AccountImagePolicy",
    table: "account_image_policy",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    model: "SandboxActionReceipt",
    table: "sandbox_mutation_receipt",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    // C53 one-use terminal upgrade tickets; also cascade from session and sandbox.
    model: "SandboxTerminalTicket",
    table: "sandbox_browser_terminal_ticket",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    // WP8 resumable browser terminals; also cascade from session and sandbox.
    model: "SandboxTerminalSession",
    table: "sandbox_terminal_session",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    // wssp-ssh §10: the CLI connect audit; no FK besides its owner.
    model: "SandboxConnectSession",
    table: "sandbox_connect_session",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    model: "OutboxEvent",
    table: "sandbox_dispatch_outbox",
    column: "userId",
    class: "blocker",
    kind: "outbox",
    hasLive: async (tx, ownerId) =>
      (await tx.outboxEvent.count({ where: { userId: ownerId, processedAt: null } })) > 0,
    finalize: (tx, ownerId) => tx.outboxEvent.deleteMany({ where: { userId: ownerId } }),
  },
  {
    // Capacity waits: WAITING rows by this user or in this user's pools are
    // failed first (`failCapacityWaitsForAccountDeletion`); ended rows are
    // history. The pool/pool owner are plain strings, so a grantee's history
    // never blocks the pool owner's deletion.
    model: "SandboxCapacityWait",
    table: "sandbox_capacity_wait",
    column: "userId",
    class: "receipt",
    removedBy: "finalize",
    finalize: (tx, ownerId) => tx.sandboxCapacityWait.deleteMany({ where: { userId: ownerId } }),
  },
  {
    model: "SandboxPlacement",
    table: "sandbox_placement",
    column: "userId",
    class: "receipt",
    removedBy: "finalize",
    finalize: async (tx, ownerId) => {
      await tx.sandbox.updateMany({
        where: { userId: ownerId },
        data: { currentPlacementId: null },
      });
      return tx.sandboxPlacement.deleteMany({ where: { userId: ownerId } });
    },
  },
  {
    model: "SandboxOperation",
    table: "sandbox_mutation_operation",
    column: "userId",
    class: "blocker",
    kind: "operations",
    hasLive: async (tx, ownerId) =>
      (await tx.sandboxOperation.count({
        where: { userId: ownerId, state: { in: [...LIVE_OPERATION_STATES] } },
      })) > 0,
    finalize: (tx, ownerId) => tx.sandboxOperation.deleteMany({ where: { userId: ownerId } }),
  },
  {
    // Private retained snapshots follow sandbox destruction/history cleanup.
    model: "SandboxExecutionConfig",
    table: "sandbox_execution_config",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    // A detached local disk copy still holds a root
    // reservation on its host (often another owner's): it blocks deletion
    // until the copy is discarded or its host is forgotten, so finalizing
    // never drops a foreign host's root counts without a release. Named as a
    // sandbox resource; rows cascade with their sandbox otherwise.
    model: "SandboxDiskCopy",
    table: "sandbox_disk_copy",
    column: "userId",
    class: "blocker",
    kind: "sandboxes",
    hasLive: async (tx, ownerId) =>
      (await tx.sandboxDiskCopy.count({ where: { userId: ownerId } })) > 0,
    finalize: (tx, ownerId) => tx.sandboxDiskCopy.deleteMany({ where: { userId: ownerId } }),
  },
  {
    // Offload attempts and stored-disk rows: receipts that cascade with the
    // sandbox and the user. An OFFLOADED sandbox is itself a live blocker, and
    // stored objects are reclaimed by the image-store sweeper once rows are gone.
    model: "SandboxDiskOffload",
    table: "sandbox_disk_offload",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    // Queued restore continuations cascade with their operation and the user.
    model: "SandboxRestoreWait",
    table: "sandbox_restore_wait",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    model: "Sandbox",
    table: "sandbox_instance",
    column: "userId",
    class: "blocker",
    kind: "sandboxes",
    hasLive: async (tx, ownerId) =>
      (await tx.sandbox.count({ where: { userId: ownerId, state: { not: "DELETED" } } })) > 0,
    finalize: (tx, ownerId) => tx.sandbox.deleteMany({ where: { userId: ownerId } }),
  },
  {
    // Logical templates and revisions are receipts after live resources settle.
    model: "SandboxTemplate",
    table: "sandbox_logical_template",
    column: "userId",
    class: "receipt",
    removedBy: "finalize",
    finalize: (tx, ownerId) => tx.sandboxTemplate.deleteMany({ where: { userId: ownerId } }),
  },
  ...[
    ["SandboxTemplateRevision", "sandbox_template_revision"],
    ["SandboxTemplateTag", "sandbox_template_tag"],
    // Community pins: metadata of a revision, removed with it.
    ["SandboxUpstreamImage", "sandbox_upstream_image"],
    // Storage rows cascade only after host blockers and retained-root FKs settle.
    ["SandboxHostStoragePool", "sandbox_host_storage_pool"],
    ["SandboxTemplateAvailability", "sandbox_template_availability"],
    ["SandboxRevisionConfig", "sandbox_revision_config"],
    ["SdkKeyRevisionAllowlist", "sdk_key_revision_allowlist"],
  ].map(([model, table]) => ({
    model: model!,
    table: table!,
    column: "userId",
    class: "receipt" as const,
    removedBy: "cascade" as const,
  })),
  {
    model: "SandboxHost",
    table: "sandbox_host",
    column: "userId",
    class: "blocker",
    kind: "hosts",
    hasLive: async (tx, ownerId) =>
      (await tx.sandboxHost.count({ where: { userId: ownerId } })) > 0,
    finalize: (tx, ownerId) => tx.sandboxHost.deleteMany({ where: { userId: ownerId } }),
  },
  {
    // Also FK Cascade; deleted explicitly so sign-out is part of the same tx.
    model: "Session",
    table: "session",
    column: "userId",
    class: "receipt",
    removedBy: "finalize",
    finalize: (tx, ownerId) => tx.session.deleteMany({ where: { userId: ownerId } }),
  },
  { model: "Account", table: "account", column: "userId", class: "receipt", removedBy: "cascade" },
  {
    model: "TwoFactor",
    table: "two_factor",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    model: "DeviceCode",
    table: "device_code",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    model: "PushSubscription",
    table: "push_subscription",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    model: "HostToken",
    table: "host_token",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  {
    model: "HostDeviceCredential",
    table: "host_device_credential",
    column: "userId",
    class: "receipt",
    removedBy: "cascade",
  },
  { model: "SdkKey", table: "sdk_key", column: "userId", class: "receipt", removedBy: "cascade" },
];

const BLOCKER_KIND_ORDER: readonly AccountDeletionBlockerKind[] = [
  "hosts",
  "sandboxes",
  "operations",
  "outbox",
  "transfers",
  "image_jobs",
  "shared_pool_workloads",
];

async function liveDeletionBlockers(
  tx: Tx,
  ownerId: string,
): Promise<AccountDeletionBlockerKind[]> {
  const kinds: AccountDeletionBlockerKind[] = [];
  for (const entry of ACCOUNT_DELETION_CLASSIFICATION)
    if (entry.class === "blocker" && (await entry.hasLive(tx, ownerId))) kinds.push(entry.kind);
  // Stable, human-ordered naming independent of the delete order.
  return kinds.sort((a, b) => BLOCKER_KIND_ORDER.indexOf(a) - BLOCKER_KIND_ORDER.indexOf(b));
}

/**
 * A waiting create holds no host, storage or quota. Account deletion ends
 * every WAITING entry by this user and every entry in this user's pools as
 * FAILED `access_denied`, in the deletion transaction (the caller holds the
 * user row and G). Mirrors the queue's failure exit: sandbox DELETED with
 * `lastErrorCode`, operation FAILED, intent scrubbed. Rolls back with the
 * deletion when another blocker refuses it.
 */
export async function failCapacityWaitsForAccountDeletion(tx: Tx, ownerId: string) {
  return tx.$executeRaw`WITH ended AS (
      UPDATE sandbox_capacity_wait w SET state = 'FAILED', intent = NULL, "endedAt" = (clock_timestamp() AT TIME ZONE 'UTC'),
        "endReason" = 'access_denied', "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
      WHERE w.state = 'WAITING' AND (w."userId" = ${ownerId} OR w."poolOwnerId" = ${ownerId})
      RETURNING w."sandboxId", w."operationId", w."userId"
    ), sandboxes AS (
      UPDATE sandbox_instance s SET state = 'DELETED', "lastErrorCode" = 'access_denied',
        "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
      FROM ended WHERE s.id = ended."sandboxId" AND s."userId" = ended."userId"
        AND s.state = 'WAITING_FOR_CAPACITY'
    )
    UPDATE sandbox_mutation_operation o SET state = 'FAILED', "errorCode" = 'access_denied',
      failure = '{"resource":"sandbox","effect":"none"}'::jsonb, "completedAt" = (clock_timestamp() AT TIME ZONE 'UTC'), "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    FROM ended WHERE o.id = ended."operationId" AND o."userId" = ended."userId" AND o.state = 'QUEUED'`;
}

async function lockAccountPoolGraph(tx: Tx, ownerId: string) {
  // Graph cleanup never enters H. Lock all owned pool G rows in canonical order.
  await tx.$queryRaw`SELECT p.id FROM sandbox_pool p WHERE p."userId" = ${ownerId}
    OR EXISTS (SELECT 1 FROM share s WHERE s."poolId" = p.id AND s."granteeUserId" = ${ownerId})
    ORDER BY p.id FOR UPDATE`;
}

async function finalizeDeletableAccount(tx: Tx, ownerId: string): Promise<void> {
  await lockAccountPoolGraph(tx, ownerId);
  await failCapacityWaitsForAccountDeletion(tx, ownerId);
  const blockers = await liveDeletionBlockers(tx, ownerId);
  if (blockers.length > 0) throw new AccountDeletionConflictError(blockers);

  const owner = await tx.user.findUnique({
    where: { id: ownerId },
    select: { deletionRequestedAt: true },
  });
  if (!owner) return;
  if (!owner.deletionRequestedAt) {
    await tx.user.update({
      where: { id: ownerId },
      data: { deletionRequestedAt: new Date() },
    });
  }

  for (const entry of ACCOUNT_DELETION_CLASSIFICATION)
    if ("finalize" in entry) await entry.finalize(tx, ownerId);
  const deleted = await tx.user.deleteMany({
    where: { id: ownerId, deletionRequestedAt: { not: null } },
  });
  if (deleted.count !== 1)
    throw new AccountDeletionConflictError(await liveDeletionBlockers(tx, ownerId));
}

/** After a failed finalization: name the blockers as seen under the owner lock
 * in a fresh transaction, or say plainly that the set changed. */
export async function accountDeletionConflictAfterForeignKeyRace(
  ownerId: string,
): Promise<AccountDeletionConflictError> {
  const kinds = await prisma.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${ownerId} FOR UPDATE`;
    return liveDeletionBlockers(tx, ownerId);
  });
  return kinds.length > 0
    ? new AccountDeletionConflictError(kinds)
    : new AccountDeletionConflictError(
        [],
        "The account's resources changed while it was being deleted, and no blocker remains now. Retry the deletion.",
      );
}

/** Refuses while live resources exist; otherwise tombstones and deletes receipts with the user. */
export async function requestAccountDeletion(ownerId: string): Promise<boolean> {
  return withAuthorityChange({ ownerId }, async () => {
    try {
      return await prisma.$transaction(async (tx) => {
        await lockAdminGovernance(tx);
        return deleteAccountInTransaction(tx, ownerId);
      });
    } catch (error) {
      if (error instanceof AccountDeletionConflictError) throw error;
      if (isPrismaForeignKeyViolation(error))
        throw await accountDeletionConflictAfterForeignKeyRace(ownerId);
      throw error;
    }
  });
}

/** C49 admin mutations already own the governance transaction and authority fence. */
export async function deleteAccountInTransaction(tx: Tx, ownerId: string): Promise<boolean> {
  await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${ownerId} FOR UPDATE`;
  const existing = await tx.user.findUnique({ where: { id: ownerId }, select: { id: true } });
  if (!existing) return false;
  await assertAdminRemains(tx, ownerId);
  await finalizeDeletableAccount(tx, ownerId);
  return true;
}
