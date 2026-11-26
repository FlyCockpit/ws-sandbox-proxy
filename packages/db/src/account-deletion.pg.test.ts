vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));

import { randomUUID } from "node:crypto";

import { afterAll, describe, expect, it, vi } from "vitest";
import type { PgTestDatabase } from "./testing/pg";
import { pgTestDatabase } from "./testing/pg";
import { CONFDELTYPE, userRelationsFromSchema } from "./testing/user-relations";

vi.mock("./index", async () => {
  const { pgTestDatabase: database } = await import("./testing/pg");
  return { default: (await database()).prisma };
});

const db = await pgTestDatabase();
const { ACCOUNT_DELETION_CLASSIFICATION, AccountDeletionConflictError, requestAccountDeletion } =
  await import("./account-deletion");

afterAll(() => db.close());

const FP = `sha256:${"b".repeat(64)}`;

async function seedUser() {
  const id = `user-${randomUUID()}`;
  await db.inspect.user.create({ data: { id, name: "Owner", email: `${id}@example.test` } });
  await db.inspect.session.create({
    data: { userId: id, token: `tok-${id}`, expiresAt: new Date(Date.now() + 3_600_000) },
  });
  return id;
}

async function seedReceipts(userId: string) {
  // Historical rows only: a retired, unplaced template; a DELETED, detached
  // sandbox; a terminal operation; and a processed outbox event.
  const template = await db.inspect.sandboxTemplateRevision.create({
    data: {
      userId,
      templateId: (
        await db.inspect.sandboxTemplate.create({ data: { userId, slug: "base", label: "Base" } })
      ).id,
      revision: 1,
      incusFingerprint: FP,
      architecture: "x86_64",
      manifestDigest: "b".repeat(64),
      retiredAt: new Date(),
    },
  });
  const sandbox = await db.inspect.sandbox.create({
    data: {
      userId,
      templateId: template.templateId,
      templateRevisionId: template.id,
      originalSelector: `revision/${template.id}`,
      originPoolId: null,
      originHostId: "host-gone",
      state: "DELETED",
    },
  });
  await db.inspect.sandboxExecutionConfig.create({
    data: {
      id: randomUUID(),
      userId,
      sandboxId: sandbox.id,
      generation: 1,
      hostId: "host-gone",
      templateDefaults: {},
      sandboxOverrides: { APP: "synthetic-private-account" },
      mergedDefaults: { APP: "synthetic-private-account" },
      bindingScheme: "hmac-sha256-v1",
      bindingKeyId: "a".repeat(32),
      bindingMac: "b".repeat(64),
    },
  });
  await db.inspect.sandboxOperation.create({
    data: {
      digestContext: {
        version: 1,
        domain: "wssp-request-v1",
        hostId: "",
        hostOwnerId: "",
        generation: null,
        configId: null,
        usagePoolId: null,
        usageMemberId: null,
      },
      requestDigestScheme: "sha256-env-free-v1",

      userId,
      sandboxId: sandbox.id,
      kind: "KILL_SANDBOX",
      state: "SUCCEEDED",
      generation: 1,
      idempotencyKey: `kill-${sandbox.id}`,
      requestBodyHash: "h",
    },
  });
  await db.inspect.outboxEvent.create({
    data: {
      operationId: "fixture-operation",

      userId,
      aggregateType: "sandbox",
      aggregateId: sandbox.id,
      eventType: "sandbox.kill_requested",
      processedAt: new Date(),
    },
  });
}

async function ownedCounts(userId: string) {
  const where = { userId };
  return {
    users: await db.inspect.user.count({ where: { id: userId } }),
    sessions: await db.inspect.session.count({ where }),
    templates: await db.inspect.sandboxTemplate.count({ where }),
    sandboxes: await db.inspect.sandbox.count({ where }),
    operations: await db.inspect.sandboxOperation.count({ where }),
    outbox: await db.inspect.outboxEvent.count({ where }),
    hosts: await db.inspect.sandboxHost.count({ where }),
    configs: await db.inspect.sandboxExecutionConfig.count({ where }),
  };
}

describe("account finalization against real PostgreSQL", () => {
  it("deletes receipts (DELETED sandbox, terminal operation, processed outbox, retired template) with the user", async () => {
    const userId = await seedUser();
    await seedReceipts(userId);

    await expect(requestAccountDeletion(userId)).resolves.toBe(true);

    expect(await ownedCounts(userId)).toEqual({
      users: 0,
      sessions: 0,
      templates: 0,
      sandboxes: 0,
      operations: 0,
      outbox: 0,
      hosts: 0,
      configs: 0,
    });
  });

  it("refuses with CONFLICT naming a live host and deletes nothing", async () => {
    const userId = await seedUser();
    await seedReceipts(userId);
    await db.inspect.sandboxHost.create({
      data: {
        userId,
        slug: "lab",
        label: "Lab",
        daemonMemoryBudgetMiB: 65536,
        daemonMaxCpuCount: 32,
      },
    });

    const refusal = await requestAccountDeletion(userId).catch((error: unknown) => error);

    expect(refusal).toBeInstanceOf(AccountDeletionConflictError);
    expect(refusal).toMatchObject({ kinds: ["hosts"] });
    expect(await ownedCounts(userId)).toMatchObject({ users: 1, sessions: 1, sandboxes: 1 });
  });

  it("refuses with CONFLICT naming image_jobs while an image transfer is OPEN, then finalizes once it ends", async () => {
    const userId = await seedUser();
    await seedReceipts(userId);
    const transfer = await db.inspect.sandboxImageTransfer.create({
      data: {
        userId,
        fingerprint: FP,
        purpose: "FETCH",
        mode: "RELAY",
        sizeBytes: 4096n,
        partSize: 1024,
        partCount: 4,
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    await expect(requestAccountDeletion(userId)).rejects.toMatchObject({ kinds: ["image_jobs"] });
    expect(await ownedCounts(userId)).toMatchObject({ users: 1, sandboxes: 1 });
    await db.inspect.sandboxImageTransfer.update({
      where: { id: transfer.id },
      data: { state: "FAILED", endReason: "test" },
    });
    await expect(requestAccountDeletion(userId)).resolves.toBe(true);
    expect(await db.inspect.sandboxImageTransfer.count({ where: { userId } })).toBe(0);
  });

  it("refuses with CONFLICT naming image_jobs while a template build has not ended (own, or on this account's host)", async () => {
    const userId = await seedUser();
    await seedReceipts(userId);
    const builder = await seedUser();
    await seedReceipts(builder);
    const build = async (owner: string, hostOwnerId: string | null) => {
      const revision = await db.inspect.sandboxTemplateRevision.findFirstOrThrow({
        where: { userId: owner },
      });
      return db.inspect.sandboxTemplateBuild.create({
        data: {
          userId: owner,
          templateId: revision.templateId,
          tag: "latest",
          principalKind: "session",
          idempotencyKey: `build-${randomUUID()}`,
          requestBodyHash: "hash",
          recipe: { v: 1 },
          recipeDigest: "a".repeat(64),
          buildDigest: "b".repeat(64),
          sourceFormat: "RECIPE",
          baseRevisionId: revision.id,
          baseFingerprint: revision.incusFingerprint,
          requestedHostId: "host-x",
          targetKey: "host-x",
          principalKey: "s",
          cpuCount: 1,
          memoryMiB: 1024,
          diskGiB: 32,
          defaultDiskGiB: 32,
          timeoutMinutes: 10,
          reservedMinutes: 10,
          chargeMonth: new Date("2026-11-01T00:00:00Z"),
          state: "RUNNING",
          ...(hostOwnerId ? { hostId: "host-x", hostOwnerId, foreignHost: true } : {}),
        },
      });
    };
    // Another owner's build running on this account's host blocks it too.
    const foreign = await build(builder, userId);
    await expect(requestAccountDeletion(userId)).rejects.toMatchObject({ kinds: ["image_jobs"] });
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: foreign.id },
      data: { state: "FAILED", errorCode: "build_host_lost", completedAt: new Date() },
    });
    const own = await build(userId, null);
    await expect(requestAccountDeletion(userId)).rejects.toMatchObject({ kinds: ["image_jobs"] });
    expect(await ownedCounts(userId)).toMatchObject({ users: 1 });
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: own.id },
      data: { state: "CANCELLED", cancelRequestedAt: new Date(), completedAt: new Date() },
    });
    await expect(requestAccountDeletion(userId)).resolves.toBe(true);
    expect(await db.inspect.sandboxTemplateBuild.count({ where: { userId } })).toBe(0);
  });

  it("maps a real FK violation (P2003) raised by the finalizing DELETE to CONFLICT naming the blocker", async () => {
    const userId = await seedUser();
    const gate = db.pauseAt("finalize", { before: "user.deleteMany" });
    const deletion = db.run("finalize", () => requestAccountDeletion(userId));
    await gate.waitReached();
    // The finalizer holds the owner FOR UPDATE, so every owner-FK insert blocks
    // on its KEY SHARE check; only a writer that bypasses FK triggers can land a
    // restricted child row inside this window. It commits a host row, and the
    // finalizer's own DELETE then fails PostgreSQL's RESTRICT check (23503).
    await db.inspect.$transaction([
      db.inspect.$executeRawUnsafe("SET LOCAL session_replication_role = replica"),
      db.inspect.$executeRawUnsafe(
        `INSERT INTO sandbox_host (id, "userId", slug, label, "updatedAt") VALUES ($1, $2, 'rogue', 'Rogue', now())`,
        `host-${randomUUID()}`,
        userId,
      ),
    ]);
    gate.release();

    const refusal = await deletion.catch((error: unknown) => error);
    expect(refusal).toBeInstanceOf(AccountDeletionConflictError);
    expect(refusal).toMatchObject({ kinds: ["hosts"] });
    // The finalization rolled back as a unit: the user and session remain.
    expect(await ownedCounts(userId)).toMatchObject({ users: 1, sessions: 1, hosts: 1 });
    expect(
      (await db.inspect.user.findUnique({ where: { id: userId } }))?.deletionRequestedAt,
    ).toBeNull();
  });
});

/** Rows the owner still has in `table` (every classified table keys the owner as "userId"). */
async function ownerRows(
  { table, column }: { table: string; column: string },
  userId: string,
): Promise<number> {
  const [row] = await db.inspect.$queryRawUnsafe<{ n: bigint }[]>(
    `SELECT count(*) AS n FROM "${table}" WHERE "${column}" = $1`,
    userId,
  );
  return Number(row!.n);
}

/** One row of every receipt model a finalizable account can hold. */
async function seedAgentAccess(userId: string) {
  // OAuth provider rows and the MCP grant (with its secretless backing key).
  const client = await db.inspect.oauthClient.create({
    data: { id: `oc-${userId}`, clientId: `client-${userId}`, userId, redirectUris: [] },
  });
  const refresh = await db.inspect.oauthRefreshToken.create({
    data: {
      token: `rt-${userId}`,
      clientId: client.clientId,
      userId,
      expiresAt: new Date(Date.now() + 60_000),
    },
  });
  await db.inspect.oauthAccessToken.create({
    data: {
      token: `at-${userId}`,
      clientId: client.clientId,
      userId,
      refreshId: refresh.id,
      expiresAt: new Date(Date.now() + 60_000),
    },
  });
  await db.inspect.oauthConsent.create({
    data: { clientId: client.clientId, userId, scopes: ["sandboxes:read"] },
  });
  const backing = await db.inspect.sdkKey.create({
    data: { userId, name: "oauth", kind: "OAUTH_GRANT", scopes: ["sandboxes:read"] },
  });
  await db.inspect.mcpGrant.create({
    data: { userId, clientId: client.clientId, referenceId: "ref", sdkKeyId: backing.id },
  });
}

async function seedEveryReceipt(userId: string) {
  await seedReceipts(userId);
  await seedAgentAccess(userId);
  await db.inspect.sandboxActionReceipt.create({
    data: {
      digestContext: {
        version: 1,
        domain: "wssp-request-v1",
        hostId: "",
        hostOwnerId: "",
        generation: null,
        configId: null,
        usagePoolId: null,
        usageMemberId: null,
      },
      requestDigestScheme: "hmac-sha256-v1",

      userId,
      idempotencyKey: "retained-action",
      requestBodyHash: "hash",
      action: "templates.create",
      hostId: "retired-host",
      state: "SUCCEEDED",
    },
  });
  const sandbox = await db.inspect.sandbox.findFirstOrThrow({ where: { userId } });
  const resultOperation = await db.inspect.sandboxOperation.create({
    data: {
      digestContext: {
        version: 1,
        domain: "wssp-request-v1",
        hostId: "",
        hostOwnerId: "",
        generation: null,
        configId: null,
        usagePoolId: null,
        usageMemberId: null,
      },
      requestDigestScheme: "hmac-sha256-v1",

      userId,
      sandboxId: sandbox.id,
      kind: "STAT_PATH",
      state: "FAILED",
      generation: 1,
      idempotencyKey: "retained-result",
      requestBodyHash: "hash",
      resultVersion: 1,
      resultExpiresAt: new Date(0),
      completedAt: new Date(0),
    },
  });
  // Disk offload history: a shredded FAILED attempt, and the
  // ended restore wait of a finished restore operation.
  await db.inspect.sandboxDiskOffload.create({
    data: {
      sandboxId: sandbox.id,
      userId,
      seq: 1,
      sourceGeneration: 1,
      sourceHostId: "retired-host",
      sourceHostOwnerId: userId,
      state: "FAILED",
      failureCode: "quota_exceeded",
      shreddedAt: new Date(0),
    },
  });
  const restoreOperation = await db.inspect.sandboxOperation.create({
    data: {
      digestContext: {
        version: 1,
        domain: "wssp-request-v1",
        hostId: "",
        hostOwnerId: "",
        generation: null,
        configId: null,
        usagePoolId: null,
        usageMemberId: null,
      },
      requestDigestScheme: "hmac-sha256-v1",

      userId,
      sandboxId: sandbox.id,
      kind: "RECONNECT_SANDBOX",
      state: "FAILED",
      generation: 1,
      idempotencyKey: "ended-restore",
      requestBodyHash: "hash",
      completedAt: new Date(0),
    },
  });
  await db.inspect.sandboxRestoreWait.create({
    data: {
      operationId: restoreOperation.id,
      sandboxId: sandbox.id,
      userId,
      expectedGeneration: 1,
      state: "TIMED_OUT",
      enqueuedAt: new Date(0),
      deadlineAt: new Date(1),
      endedAt: new Date(1),
      endReason: "restore_no_allowed_host",
    },
  });
  await db.inspect.sandboxOperationResult.create({
    data: {
      operationId: resultOperation.id,
      sandboxId: sandbox.id,
      userId,
      generation: 1,
      attempt: 0,
      version: 1,
      expiresAt: new Date(0),
      reservationState: "RELEASED",
      reservationBytes: 0,
    },
  });

  await db.inspect.sandboxTransfer.create({
    data: {
      id: randomUUID(),
      userId,
      sandboxId: sandbox.id,
      acceptedHostId: "retired-host",
      generation: 1,
      direction: "UPLOAD",
      guestPath: "/file",
      idempotencyKey: "retained-transfer",
      requestBodyHash: "hash",
      totalBytes: 0n,
      state: "ABORTED",
      reservationHeld: false,
      idleExpiresAt: new Date(),
      expiresAt: new Date(),
    },
  });
  const template = await db.inspect.sandboxTemplateRevision.findFirstOrThrow({ where: { userId } });
  await db.inspect.account.create({
    data: { userId, accountId: userId, providerId: "credential", password: "hash" },
  });
  await db.inspect.twoFactor.create({ data: { userId, secret: "s", backupCodes: "b" } });
  await db.inspect.deviceCode.create({
    data: {
      userId,
      deviceCode: `dc-${userId}`,
      userCode: `uc-${userId}`,
      status: "approved",
      expiresAt: new Date(Date.now() + 60_000),
    },
  });
  await db.inspect.pushSubscription.create({
    data: { userId, endpoint: `https://push.example.test/${userId}`, p256dh: "p", auth: "a" },
  });
  await db.inspect.hostToken.create({
    data: {
      userId,
      name: "pairing",
      lookupPrefix: `lp-${userId}`,
      secretDigest: `sd-${userId}`,
    },
  });
  const key = await db.inspect.sdkKey.create({
    data: {
      userId,
      name: "ci",
      scopes: ["sandboxes:read"],
      lookupPrefix: `kp-${userId}`,
      secretDigest: `ks-${userId}`,
    },
  });
  const pool = await db.inspect.sandboxPool.create({
    data: { userId, slug: "retained-pool", label: "Retained pool" },
  });
  const grantee = await seedUser();
  await db.inspect.share.create({
    data: { poolId: pool.id, ownerUserId: userId, granteeUserId: grantee },
  });
  const received = await db.inspect.sandboxPool.create({
    data: { userId: grantee, slug: "received", label: "Received" },
  });
  await db.inspect.share.create({
    data: { poolId: received.id, ownerUserId: grantee, granteeUserId: userId },
  });
  await db.inspect.shareInvite.create({
    data: {
      poolId: pool.id,
      ownerUserId: userId,
      email: "recipient@example.test",
      pendingKey: `${pool.id}:recipient@example.test`,
      tokenDigest: randomUUID().replaceAll("-", "").repeat(2),
      expiresAt: new Date(Date.now() + 3600000),
    },
  });
  await db.inspect.sdkKeyPoolAllowlist.create({
    data: { userId, poolOwnerId: userId, sdkKeyId: key.id, poolId: pool.id },
  });
  // A waiting create of this user's (failed by the deletion) and an ended one.
  await seedCapacityWait(userId, pool, "WAITING");
  await seedCapacityWait(userId, pool, "TIMED_OUT");
  await db.inspect.sdkKeyRevisionAllowlist.create({
    data: { userId, sdkKeyId: key.id, templateRevisionId: template.id },
  });
  await db.inspect.sandboxTemplateTag.create({
    data: { userId, templateId: template.templateId, revisionId: template.id, tag: "latest" },
  });
  // A community pin's upstream facts: revision metadata, removed with it.
  await db.inspect.sandboxUpstreamImage.create({
    data: {
      userId,
      templateId: template.templateId,
      revisionId: template.id,
      source: "ubuntu-26.04",
      product: "ubuntu:resolute:amd64:cloud",
      version: "20261106_07:42",
      fingerprint: template.incusFingerprint,
      architecture: "x86_64",
      metaPath: "images/ubuntu/resolute/amd64/cloud/20261106_07:42/incus.tar.xz",
      metaSha256: "a".repeat(64),
      metaSize: 1208n,
      diskPath: "images/ubuntu/resolute/amd64/cloud/20261106_07:42/disk.qcow2",
      diskSha256: "b".repeat(64),
      diskSize: 495803904n,
    },
  });
  // An ended template build is history, deleted with the account.
  await db.inspect.sandboxTemplateBuild.create({
    data: {
      userId,
      templateId: template.templateId,
      tag: "latest",
      principalKind: "session",
      idempotencyKey: `build-${userId}`,
      requestBodyHash: "hash",
      recipe: { v: 1 },
      recipeDigest: "a".repeat(64),
      buildDigest: "b".repeat(64),
      sourceFormat: "RECIPE",
      baseRevisionId: template.id,
      baseFingerprint: template.incusFingerprint,
      poolId: pool.id,
      targetKey: pool.id,
      principalKey: "s",
      cpuCount: 1,
      memoryMiB: 1024,
      diskGiB: 32,
      defaultDiskGiB: 32,
      timeoutMinutes: 10,
      reservedMinutes: 10,
      chargedMinutes: 3,
      minutesSettled: true,
      chargeMonth: new Date("2026-11-01T00:00:00Z"),
      state: "FAILED",
      errorCode: "build_step_failed",
      completedAt: new Date(),
    },
  });
  await db.inspect.sandboxRevisionConfig.create({
    data: {
      userId,
      revisionId: template.id,
      defaultEnvs: {},
      checksum: "fixture",
      digestScheme: "fixture",
      digestKeyId: "fixture",
    },
  });
  const config = await db.inspect.sandboxExecutionConfig.findUniqueOrThrow({
    where: { sandboxId: sandbox.id },
  });
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { userId, sandboxId: sandbox.id },
  });
  const placement = await db.inspect.sandboxPlacement.create({
    data: {
      userId,
      hostOwnerId: userId,
      sandboxId: sandbox.id,
      generation: sandbox.generation,
      operationId: operation.id,
      kind: "DIRECT",
      originHostId: "host-gone",
      storagePoolId: "retired-pool",
      storageMarker: "retired-marker",
      storagePoolName: "default",
      rootChargeGiB: 33,
      chargedMemoryMiB: 1280,
      chargedVcpu: 1,
      templateId: template.templateId,
      templateRevisionId: template.id,
      artifact: template.incusFingerprint,
      architecture: template.architecture,
      guestUid: template.guestUid,
      guestGid: template.guestGid,
      guestHome: template.guestHome,
      guestShell: template.guestShell,
      configId: config.id,
      acceptedAt: new Date(),
    },
  });
  await db.inspect.sandbox.update({
    where: { id: sandbox.id },
    data: { currentPlacementId: placement.id },
  });
  // C53: an outstanding browser terminal ticket (cascades with the account).
  const session = await db.inspect.session.findFirstOrThrow({ where: { userId } });
  await db.inspect.sandboxTerminalTicket.create({
    data: {
      userId,
      sessionId: session.id,
      sandboxId: sandbox.id,
      sandboxHostId: "host-gone",
      hostOwnerId: userId,
      epoch: 1,
      generation: 1,
      rows: 24,
      cols: 80,
      tokenDigest: `td-${userId}`,
      expiresAt: new Date(Date.now() + 30_000),
    },
  });
  // WP8: a resumable terminal row (cascades with the account).
  await db.inspect.sandboxTerminalSession.create({
    data: {
      id: `t-${userId}`,
      userId,
      sessionId: session.id,
      sandboxId: sandbox.id,
      hostId: "host-gone",
      generation: 1,
    },
  });
  // A CLI connect audit row (cascades with the account).
  await db.inspect.sandboxConnectSession.create({
    data: {
      id: `c-${userId}`,
      userId,
      sandboxId: sandbox.id,
      hostId: "host-gone",
      keyId: "key-gone",
      origin: "CLI_LOGIN",
    },
  });
  // Image store receipts: an artifact, a finished transfer and the policy row.
  await db.inspect.sandboxImageArtifact.create({
    data: {
      userId,
      fingerprint: FP,
      architecture: "x86_64",
      sizeBytes: 1024n,
      storeKind: "PEER",
      state: "LOCAL",
    },
  });
  await db.inspect.sandboxImageTransfer.create({
    data: {
      userId,
      fingerprint: FP,
      purpose: "FETCH",
      mode: "S3",
      state: "COMPLETE",
      sizeBytes: 1024n,
      partSize: 1024,
      partCount: 1,
      expiresAt: new Date(Date.now() + 60_000),
    },
  });
  await db.inspect.accountImagePolicy.create({ data: { userId } });
  // Webhooks: an endpoint with a pending delivery (never a blocker) and its
  // FK-free event, all removed by the finalizer.
  const endpoint = await db.inspect.webhookEndpoint.create({
    data: {
      userId,
      url: "https://hooks.example.com/x",
      events: ["sandbox.ready"],
      secretCiphertext: new Uint8Array(48),
      secretNonce: new Uint8Array(12),
      secretKeyId: "0".repeat(16),
    },
  });
  const eventId = `evt_${randomUUID().replaceAll("-", "")}`;
  await db.inspect.webhookEvent.create({
    data: {
      id: eventId,
      userId,
      type: "sandbox.ready",
      facts: {},
      body: "{}",
      fannedOutAt: new Date(),
    },
  });
  await db.inspect.webhookDelivery.create({
    data: {
      eventId,
      endpointId: endpoint.id,
      userId,
      kind: "event",
      maxAttempts: 11,
      nextAttemptAt: new Date(),
      expiresAt: new Date(Date.now() + 86_400_000),
    },
  });
  // CLI logins: every credential receipt table, history only (terminal lease).
  const definition = await db.inspect.credentialDefinition.create({
    data: {
      userId,
      slug: "cli",
      version: 1,
      document: {},
      digest: "a".repeat(64),
      displayName: "CLI",
    },
  });
  const login = await db.inspect.credential.create({
    data: {
      userId,
      name: "cli",
      definitionId: definition.id,
      definitionDigest: definition.digest,
      mode: "EXCLUSIVE",
      delivery: "GUEST",
      copyBack: true,
    },
  });
  const account = await db.inspect.credentialAccount.create({
    data: { userId, credentialId: login.id, ordinal: 1 },
  });
  const instance = await db.inspect.credentialInstance.create({
    data: {
      userId,
      credentialId: login.id,
      accountId: account.id,
      accountOrdinal: 1,
      ordinal: 1,
      capacity: 1,
    },
  });
  const lease = await db.inspect.credentialLease.create({
    data: {
      userId,
      credentialId: login.id,
      accountId: account.id,
      instanceId: instance.id,
      sandboxId: sandbox.id,
      operationId: "history",
      kind: "WORKLOAD",
      exclusive: true,
      state: "RELEASED",
      releasedAt: new Date(),
    },
  });
  const binding = await db.inspect.credentialBinding.create({
    data: {
      leaseId: lease.id,
      instanceId: instance.id,
      hostId: "retired-host",
      grantGeneration: 1,
      purpose: "INSTALL",
    },
  });
  await db.inspect.credentialResidue.create({
    data: {
      sandboxId: sandbox.id,
      userId,
      credentialId: login.id,
      instanceId: instance.id,
      leaseId: lease.id,
      bindingId: binding.id,
      grantGeneration: 1,
      paths: [],
      recoverable: false,
      clearedAt: new Date(),
    },
  });
  await db.inspect.sandboxCredential.create({
    data: { sandboxId: sandbox.id, userId, credentialId: login.id, detachedAt: new Date() },
  });
  await db.inspect.credentialLoginSession.create({
    data: {
      userId,
      credentialId: login.id,
      accountId: account.id,
      instanceId: instance.id,
      state: "SAVED",
      expiresAt: new Date(),
    },
  });
  await db.inspect.credentialEvent.create({
    data: { userId, credentialId: login.id, type: "value_written" },
  });
  await db.inspect.sdkKeyCredentialAllowlist.create({
    data: { userId, sdkKeyId: key.id, credentialId: login.id },
  });
}

/** A hostless pool create in `state` (WAITING keeps its intent; others ended). */
async function seedCapacityWait(
  userId: string,
  pool: { id: string; userId: string },
  state: "WAITING" | "PLACED" | "TIMED_OUT" | "CANCELLED" | "FAILED",
) {
  const revision = await db.inspect.sandboxTemplateRevision.findFirstOrThrow({ where: { userId } });
  const waiting = state === "WAITING";
  const sandbox = await db.inspect.sandbox.create({
    data: {
      userId,
      templateId: revision.templateId,
      templateRevisionId: revision.id,
      originalSelector: "base",
      originPoolId: pool.id,
      state: waiting ? "WAITING_FOR_CAPACITY" : "DELETED",
    },
  });
  const operation = await db.inspect.sandboxOperation.create({
    data: {
      digestContext: {
        version: 1,
        domain: "wssp-request-v1",
        hostId: "",
        hostOwnerId: "",
        generation: null,
        configId: null,
        usagePoolId: null,
        usageMemberId: null,
      },
      requestDigestScheme: "hmac-sha256-v1",

      userId,
      sandboxId: sandbox.id,
      generation: 1,
      kind: "CREATE_SANDBOX",
      state: waiting ? "QUEUED" : state === "CANCELLED" ? "CANCELLED" : "FAILED",
      idempotencyKey: `wait-${randomUUID()}`,
      requestBodyHash: "hash",
    },
  });
  return db.inspect.sandboxCapacityWait.create({
    data: {
      userId,
      sandboxId: sandbox.id,
      operationId: operation.id,
      poolId: pool.id,
      poolOwnerId: pool.userId,
      templateRevisionId: revision.id,
      cpuCount: 1,
      memoryMiB: 1024,
      diskGiB: 32,
      chargedMemoryMiB: 1280,
      rootChargeGiB: 33,
      leaseTimeoutMs: 300000,
      leaseExpireAction: "DESTROY",
      state,
      intent: waiting ? {} : undefined,
      endedAt: waiting ? null : new Date(),
      deadlineAt: new Date(Date.now() + 3600000),
    },
  });
}

type Queryable = Pick<PgTestDatabase["inspect"], "$queryRaw">;

/** Every live FK to "user", keyed `<table>.<column>` (C21c-cf-2: a table with
 * two FKs to user yields two entries). A multi-column FK is refused. */
async function liveUserForeignKeys(client: Queryable): Promise<Map<string, string>> {
  const fks = await client.$queryRaw<{ table: string; column: string | null; action: string }[]>`
    SELECT c.conrelid::regclass::text AS table,
           CASE WHEN array_length(c.conkey, 1) = 1 THEN a.attname::text END AS column,
           c.confdeltype::text AS action
    FROM pg_constraint c
    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
    WHERE c.contype = 'f' AND c.confrelid = '"user"'::regclass`;
  const live = new Map<string, string>();
  for (const fk of fks) {
    const table = fk.table.replaceAll('"', "");
    if (!fk.column) throw new Error(`multi-column FK to user on ${table}`);
    const key = `${table}.${fk.column}`;
    if (live.has(key)) throw new Error(`two FKs to user on ${key}`);
    live.set(key, fk.action);
  }
  return live;
}

describe("account deletion inventory against the live schema (DECISIONS: Account-deletion blockers)", () => {
  it("C21c-cf-2 the live FK inventory keeps both FKs of a table with two FKs to user", async () => {
    const rollback = new Error("rollback");
    let seen: Map<string, string> | undefined;
    await expect(
      db.inspect.$transaction(async (tx) => {
        await tx.$executeRawUnsafe(
          `CREATE TABLE "cf2_probe" ("authorId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE, "approverId" text REFERENCES "user"(id) ON DELETE RESTRICT)`,
        );
        seen = await liveUserForeignKeys(tx);
        throw rollback;
      }),
    ).rejects.toBe(rollback);
    expect(seen?.get("cf2_probe.authorId")).toBe("c");
    expect(seen?.get("cf2_probe.approverId")).toBe("r");
  });

  it("every foreign key to user is classified, and each ON DELETE matches its classification", async () => {
    const live = await liveUserForeignKeys(db.inspect);
    const classified = new Map(
      ACCOUNT_DELETION_CLASSIFICATION.map((entry) => [`${entry.table}.${entry.column}`, entry]),
    );
    expect([...live.keys()].sort()).toEqual([...classified.keys()].sort());
    // C21b-c2-D: the unit inventory's schema parser must see exactly the live
    // FKs (table, column and ON DELETE), so the two inventories cannot drift apart.
    const parsed = new Map(
      [...userRelationsFromSchema().values()].map(({ table, column, onDelete }) => [
        `${table}.${column}`,
        CONFDELTYPE[onDelete],
      ]),
    );
    expect(parsed.size).toBe(userRelationsFromSchema().size);
    expect(Object.fromEntries([...parsed].sort())).toEqual(Object.fromEntries([...live].sort()));
    for (const [table, action] of live) {
      const entry = classified.get(table)!;
      // r = RESTRICT, c = CASCADE, n = SET NULL (pg_constraint.confdeltype).
      if (entry.class === "blocker") expect({ table, action }).toEqual({ table, action: "r" });
      else if (entry.class === "receipt" && entry.removedBy === "cascade")
        expect({ table, action }).toEqual({ table, action: "c" });
    }
  });

  it("every receipt model's rows vanish with the account", async () => {
    const userId = await seedUser();
    await seedEveryReceipt(userId);
    const receipts = ACCOUNT_DELETION_CLASSIFICATION;
    const seeded = Object.fromEntries(
      await Promise.all(receipts.map(async (e) => [e.table, await ownerRows(e, userId)] as const)),
    );
    // A device credential needs a host, and a host blocks deletion, so none can
    // exist at finalization; its FK Cascade is asserted by the inventory above.
    // sandbox_host rows are live state and never present in a finalizable account.
    for (const [table, count] of Object.entries(seeded))
      if (
        table !== "host_terminal_ticket" &&
        // A queued host command belongs to a host, which blocks deletion.
        table !== "host_queued_command" &&
        // So does a host file receipt.
        table !== "host_file_receipt" &&
        table !== "host_device_credential" &&
        table !== "sandbox_host" &&
        table !== "sandbox_template_availability" &&
        table !== "sandbox_pool_member" &&
        // Like availability/member rows, a storage pool requires a blocking host.
        table !== "sandbox_host_storage_pool" &&
        // A disk copy needs a host and is itself a blocker (offload plan S10).
        table !== "sandbox_disk_copy"
      )
        expect({ table, seeded: count > 0 }).toEqual({ table, seeded: true });

    await expect(requestAccountDeletion(userId)).resolves.toBe(true);

    const after = Object.fromEntries(
      await Promise.all(receipts.map(async (e) => [e.table, await ownerRows(e, userId)] as const)),
    );
    expect(after).toEqual(Object.fromEntries(receipts.map((e) => [e.table, 0])));
    expect(await db.inspect.user.count({ where: { id: userId } })).toBe(0);
    expect(await db.inspect.sdkKeyRevisionAllowlist.count({ where: { SdkKey: { userId } } })).toBe(
      0,
    );
    expect(await db.inspect.webhookEvent.count({ where: { userId } })).toBe(0);
    expect(await db.inspect.webhookDelivery.count({ where: { userId } })).toBe(0);
  });
});

it("shared_pool_workloads refuses both deletion entries before any effects, then allows a pinned deleted pool", async () => {
  const ownerId = await seedUser(),
    creatorId = await seedUser();
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: ownerId, slug: "shared-blocker", label: "Shared" },
  });
  await seedReceipts(creatorId);
  const sandbox = await db.inspect.sandbox.findFirstOrThrow({ where: { userId: creatorId } });
  await db.inspect.sandbox.update({
    where: { id: sandbox.id },
    data: { state: "STOPPED", usagePoolId: pool.id },
  });
  const before = await ownedCounts(ownerId);
  const { deleteAccountInTransaction } = await import("./account-deletion");
  for (const remove of [
    () => requestAccountDeletion(ownerId),
    () => db.prisma.$transaction((tx) => deleteAccountInTransaction(tx, ownerId)),
  ]) {
    await expect(remove()).rejects.toMatchObject({ kinds: ["shared_pool_workloads"] });
    expect(await ownedCounts(ownerId)).toEqual(before);
    expect(await db.inspect.sandboxPool.findUnique({ where: { id: pool.id } })).toMatchObject({
      deletedAt: null,
    });
    expect(await db.inspect.user.findUnique({ where: { id: ownerId } })).toMatchObject({
      deletionRequestedAt: null,
    });
  }
  await db.inspect.sandboxPool.update({ where: { id: pool.id }, data: { deletedAt: new Date() } });
  await expect(requestAccountDeletion(ownerId)).rejects.toMatchObject({
    kinds: ["shared_pool_workloads"],
  });
  await db.inspect.sandbox.update({
    where: { id: sandbox.id },
    data: { accessGraceUntil: new Date(Date.now() + 259200000), accessGraceReason: "access" },
  });
  expect(await requestAccountDeletion(ownerId)).toBe(true);
  expect(await db.inspect.sandbox.findUnique({ where: { id: sandbox.id } })).toMatchObject({
    usagePoolId: pool.id,
    state: "STOPPED",
  });
});

it("owner deletion fails grantee creates waiting in its pools (access_denied) and keeps every grantee wait history, never P2003", async () => {
  const ownerId = await seedUser(),
    granteeId = await seedUser();
  await seedReceipts(granteeId);
  // The grantee's seeded receipts include a DELETED sandbox; no live blocker.
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: ownerId, slug: "queued", label: "Queued" },
  });
  await db.inspect.share.create({
    data: { poolId: pool.id, ownerUserId: ownerId, granteeUserId: granteeId },
  });
  const waiting = await seedCapacityWait(granteeId, pool, "WAITING");
  const ended = await Promise.all(
    (["PLACED", "TIMED_OUT", "CANCELLED", "FAILED"] as const).map((state) =>
      seedCapacityWait(granteeId, pool, state),
    ),
  );
  expect(await requestAccountDeletion(ownerId)).toBe(true);
  expect(await db.inspect.user.count({ where: { id: ownerId } })).toBe(0);
  expect(
    await db.inspect.sandboxCapacityWait.findUniqueOrThrow({ where: { id: waiting.id } }),
  ).toMatchObject({ state: "FAILED", endReason: "access_denied", intent: null });
  expect(
    await db.inspect.sandbox.findUniqueOrThrow({ where: { id: waiting.sandboxId } }),
  ).toMatchObject({ state: "DELETED", lastErrorCode: "access_denied" });
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: waiting.operationId } }),
  ).toMatchObject({ state: "FAILED", errorCode: "access_denied" });
  expect(
    await db.inspect.sandboxCapacityWait.count({ where: { id: { in: ended.map((w) => w.id) } } }),
  ).toBe(4);
});
