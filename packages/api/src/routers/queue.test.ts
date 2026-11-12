import { createRouterClient, ORPCError } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";

const authTokenGetJob = vi.fn();
const deletionGetJob = vi.fn();
const redisGet = vi.fn();
const backupEnabled = vi.fn(() => true);
const backupMisconfiguration = vi.fn((): { state: "misconfigured"; reason: string } | null => null);
const backupSetupMissing = vi.fn((): { state: "setup-missing"; reason: string } | null => null);

vi.mock("@wssp/queue", () => {
  const fakeQueue = { add: vi.fn(), getJob: vi.fn(), getJobs: vi.fn().mockResolvedValue([]) };
  return {
    reapExpiredAuthTokensQueue: { ...fakeQueue, getJob: authTokenGetJob },
    checkBackupFreshnessQueue: fakeQueue,
    imageStoreMaintenanceQueue: fakeQueue,
    webhookDeliveryQueue: fakeQueue,
    reapWebhookLogQueue: fakeQueue,
    notifyDataDeletionsQueue: { ...fakeQueue, getJob: deletionGetJob },
    QUEUE_NAMES: {
      reapExpiredAuthTokens: "reap-expired-auth-tokens",
      checkBackupFreshness: "check-backup-freshness",
      imageStoreMaintenance: "image-store-maintenance",
      webhookDelivery: "webhook-delivery",
      reapWebhookLog: "reap-webhook-log",
      notifyDataDeletions: "notify-data-deletions",
    },
    redisConnection: { get: redisGet },
  };
});

vi.mock("../lib/backup-freshness", () => ({
  backupFreshnessEnabled: () => backupEnabled(),
  misconfiguredBackupFreshness: () => backupMisconfiguration(),
  setupMissingBackupFreshness: () => backupSetupMissing(),
  readBackupFreshness: async (redis: { get: (key: string) => Promise<string | null> }) => {
    const raw = await redis.get("backup:freshness");
    return raw ? JSON.parse(raw) : null;
  },
}));

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

vi.mock("@wssp/env/server", () => ({
  env: {},
  ADMIN_EMAILS: new Set<string>(),
}));

const { queueRouter } = await import("./queue");
const { default: prisma } = await import("@wssp/db");
const { wireSensitiveSessionGateUser } = await import("@wssp/api/test/mock-prisma");

function buildContext(role: "admin" | "user"): Context {
  const ctx: Context = {
    session: {
      user: {
        id: "admin-user-id",
        email: "admin@example.com",
        name: "Admin",
        emailVerified: true,
        role,
        // Forced admin 2FA is the shipped default (FORCE_2FA_DEFAULTS), so an
        // unenrolled admin would 404 here before the router ever ran.
        twoFactorEnabled: true,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
      },
      session: {
        id: "test-session-id",
        userId: "admin-user-id",
        token: "test-token",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: "127.0.0.1",
        userAgent: "vitest",
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
      },
    } as Session,
  };
  wireSensitiveSessionGateUser(prisma as never, {
    role: ctx.session!.user.role,
    emailVerified: ctx.session!.user.emailVerified,
    twoFactorEnabled: ctx.session!.user.twoFactorEnabled,
    createdAt: ctx.session!.user.createdAt,
    banned: ctx.session!.user.banned,
    banExpires: ctx.session!.user.banExpires,
  });
  return ctx;
}

describe("queueRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    backupEnabled.mockReturnValue(true);
    backupMisconfiguration.mockReturnValue(null);
    backupSetupMissing.mockReturnValue(null);
  });

  it("includes reapExpiredAuthTokens in the admin queue map", async () => {
    authTokenGetJob.mockResolvedValue(null);
    const client = createRouterClient(queueRouter, { context: buildContext("admin") });

    await expect(
      client.getJob({ jobId: "job-1", queue: "reap-expired-auth-tokens" }),
    ).resolves.toBeNull();
    expect(authTokenGetJob).toHaveBeenCalledWith("job-1");
  });

  it("reports backups as not configured without touching Redis", async () => {
    backupEnabled.mockReturnValue(false);
    const client = createRouterClient(queueRouter, { context: buildContext("admin") });

    await expect(client.backupStatus()).resolves.toEqual({ configured: false, status: null });
    expect(redisGet).not.toHaveBeenCalled();
  });

  it("returns the recorded freshness verdict when backups are configured", async () => {
    backupEnabled.mockReturnValue(true);
    const verdict = {
      state: "stale",
      checkedAt: "2026-09-08T00:00:00.000Z",
      latestKey: "database/backup-1.dump",
      latestAt: "2026-09-05T03:00:00.000Z",
      ageHours: 69,
      maxAgeHours: 36,
    };
    redisGet.mockResolvedValue(JSON.stringify(verdict));
    const client = createRouterClient(queueRouter, { context: buildContext("admin") });

    await expect(client.backupStatus()).resolves.toEqual({ configured: true, status: verdict });
    expect(redisGet).toHaveBeenCalledWith("backup:freshness");
  });

  it('reports enabled backups without a bucket as setup-missing rather than as "off"', async () => {
    backupEnabled.mockReturnValue(true);
    backupSetupMissing.mockReturnValue({
      state: "setup-missing",
      checkedAt: "2026-09-08T00:00:00.000Z",
      maxAgeHours: 36,
      reason: "BACKUP_S3_BUCKET is not set.",
    });
    const client = createRouterClient(queueRouter, { context: buildContext("admin") });

    await expect(client.backupStatus()).resolves.toEqual({
      configured: true,
      status: {
        state: "setup-missing",
        checkedAt: "2026-09-08T00:00:00.000Z",
        maxAgeHours: 36,
        reason: "BACKUP_S3_BUCKET is not set.",
      },
    });
    expect(redisGet).not.toHaveBeenCalled();
  });

  it('reports a set-but-unusable bucket as misconfigured rather than as "off"', async () => {
    // Hiding this behind `configured: false` means the admin card disappears
    // and the operator never learns that no backups are being taken.
    backupEnabled.mockReturnValue(true);
    backupMisconfiguration.mockReturnValue({
      state: "misconfigured",
      reason: "BACKUP_S3_REGION must be a real AWS region.",
    });
    const client = createRouterClient(queueRouter, { context: buildContext("admin") });

    await expect(client.backupStatus()).resolves.toEqual({
      configured: true,
      status: { state: "misconfigured", reason: "BACKUP_S3_REGION must be a real AWS region." },
    });
    expect(redisGet).not.toHaveBeenCalled();
  });

  it("hides backup status from non-admins", async () => {
    const client = createRouterClient(queueRouter, { context: buildContext("user") });
    await expect(client.backupStatus()).rejects.toBeInstanceOf(ORPCError);
  });

  it("rejects an unknown queue name", async () => {
    const client = createRouterClient(queueRouter, { context: buildContext("admin") });
    await expect(client.getJob({ jobId: "job-1", queue: "not-a-queue" })).rejects.toBeInstanceOf(
      ORPCError,
    );
  });
});

it("returns only job metadata even when payload, result and error contain secrets", async () => {
  authTokenGetJob.mockResolvedValue({
    id: "job-1",
    getState: async () => "failed",
    attemptsMade: 1,
    timestamp: 100,
    data: { token: "secret-token" },
    returnvalue: { output: "secret-output" },
    failedReason: "secret-error",
    stacktrace: ["secret-stack"],
  });
  const client = createRouterClient(queueRouter, { context: buildContext("admin") });
  expect(await client.getJob({ jobId: "job-1", queue: "reap-expired-auth-tokens" })).toEqual({
    id: "job-1",
    state: "failed",
    attemptsMade: 1,
    timestamp: 100,
    finishedOn: null,
  });
});

it("redacts raw backup-service errors from administrative status", async () => {
  redisGet.mockResolvedValue(
    JSON.stringify({
      state: "error",
      checkedAt: "2026-09-26T00:00:00.000Z",
      maxAgeHours: 36,
      message: "private-service-response",
    }),
  );
  const client = createRouterClient(queueRouter, { context: buildContext("admin") });
  expect(await client.backupStatus()).toEqual({
    configured: true,
    status: {
      state: "error",
      checkedAt: "2026-09-26T00:00:00.000Z",
      maxAgeHours: 36,
      message: "Backup status unavailable",
    },
  });
});

it("includes deletion notice jobs in authenticated metadata-only observability", async () => {
  deletionGetJob.mockResolvedValue({
    id: "notice-job",
    getState: async () => "completed",
    attemptsMade: 1,
    timestamp: 100,
    data: { secret: "wssp_sdk_private-notice-data" },
    returnvalue: { notified: 1 },
  });
  const admin = createRouterClient(queueRouter, { context: buildContext("admin") });
  expect(await admin.getJob({ jobId: "notice-job", queue: "notify-data-deletions" })).toEqual({
    id: "notice-job",
    state: "completed",
    attemptsMade: 1,
    timestamp: 100,
    finishedOn: null,
  });
  const user = createRouterClient(queueRouter, { context: buildContext("user") });
  await expect(
    user.getJob({ jobId: "notice-job", queue: "notify-data-deletions" }),
  ).rejects.toBeInstanceOf(ORPCError);
  expect(deletionGetJob).toHaveBeenCalledOnce();
});
