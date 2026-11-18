-- wssp:transactional
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
-- wssp:history-capture (records the history table for the commit marker; keep it here)
DO $wssp$ BEGIN PERFORM set_config('wssp.history', coalesce(to_regclass('_prisma_migrations')::oid::text, ''), true); END $wssp$;

-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateExtension
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- CreateEnum
CREATE TYPE "SdkKeyKind" AS ENUM ('API', 'AGENT_TOKEN', 'OAUTH_GRANT');

-- CreateEnum
CREATE TYPE "HostQueuedCommandState" AS ENUM ('QUEUED', 'RUN', 'DISMISSED', 'EXPIRED', 'REFUSED');

-- CreateEnum
CREATE TYPE "HostFileReceiptState" AS ENUM ('PENDING', 'SUCCEEDED', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "HostAuditKind" AS ENUM ('COMMAND', 'COMMAND_QUEUED', 'QUEUED_RUN', 'QUEUED_DISMISSED', 'FILE_READ', 'FILE_LIST', 'FILE_WRITE', 'FILE_EDIT', 'POLICY_LOWER', 'POLICY_VETO_LIFT');

-- CreateEnum
CREATE TYPE "HostAuditActor" AS ENUM ('AGENT', 'PERSON');

-- CreateEnum
CREATE TYPE "TemplateBuildState" AS ENUM ('AWAITING_CONTEXT', 'QUEUED', 'PLACING', 'RUNNING', 'STOPPING', 'CAPTURING', 'CANCELLING', 'SUCCEEDED', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "TemplateBuildPrincipalKind" AS ENUM ('session', 'sdkKey', 'system');

-- CreateEnum
CREATE TYPE "TemplateBuildOrigin" AS ENUM ('USER', 'COMMUNITY_PREP');

-- CreateEnum
CREATE TYPE "TemplateBuildSourceFormat" AS ENUM ('RECIPE', 'DOCKERFILE');

-- CreateEnum
CREATE TYPE "TemplateBuildCleanupState" AS ENUM ('PENDING', 'DONE');

-- CreateEnum
CREATE TYPE "BuildContextState" AS ENUM ('OPEN', 'SEALED', 'ADOPTED', 'ABORTED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "CredentialMode" AS ENUM ('EXCLUSIVE', 'SHAREABLE');

-- CreateEnum
CREATE TYPE "CredentialDelivery" AS ENUM ('GUEST', 'PROXY');

-- CreateEnum
CREATE TYPE "CredentialInstanceState" AS ENUM ('EMPTY', 'READY', 'NEEDS_LOGIN');

-- CreateEnum
CREATE TYPE "CredentialSecretKind" AS ENUM ('UPLOAD', 'LOGIN', 'CAPTURE', 'CHECKPOINT', 'RECOVERY', 'PROMOTED', 'REPIN');

-- CreateEnum
CREATE TYPE "CredentialLeaseKind" AS ENUM ('WORKLOAD', 'LOGIN');

-- CreateEnum
CREATE TYPE "CredentialLeaseState" AS ENUM ('RESERVED', 'INSTALLING', 'ACTIVE', 'RELEASING', 'RELEASED', 'RECOVERY_REQUIRED', 'RECOVERING', 'FORCE_RELEASED', 'ABANDONED');

-- CreateEnum
CREATE TYPE "CredentialBindingPurpose" AS ENUM ('INSTALL', 'RECOVER', 'LOGIN');

-- CreateEnum
CREATE TYPE "CredentialCaptureOutcome" AS ENUM ('COMMITTED', 'UNCHANGED', 'DISCARDED', 'REJECTED');

-- CreateEnum
CREATE TYPE "CredentialLoginSessionState" AS ENUM ('PROVISIONING', 'READY', 'SAVING', 'SAVED', 'CANCELLED', 'FAILED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "SandboxState" AS ENUM ('REQUESTED', 'SCHEDULED', 'PROVISIONING', 'READY', 'STOPPING', 'STOPPED', 'RECLAIMING', 'DELETED', 'UNREACHABLE', 'RECOVERED', 'HOST_LOST', 'ERROR', 'WAITING_FOR_CAPACITY', 'OFFLOADED');

-- CreateEnum
CREATE TYPE "SandboxDiskOffloadState" AS ENUM ('PENDING', 'EXPORTING', 'UPLOADING', 'VERIFYING', 'STORED', 'EVICTING', 'CONSUMED', 'SUPERSEDED', 'FAILED', 'DELETING', 'DELETED');

-- CreateEnum
CREATE TYPE "SandboxDiskCopyState" AS ENUM ('STALE', 'DISCARDING');

-- CreateEnum
CREATE TYPE "SandboxOffloadPin" AS ENUM ('ANY', 'OWN_HOSTS');

-- CreateEnum
CREATE TYPE "SandboxOffloadMode" AS ENUM ('ON_STOP', 'AFTER', 'ON_PRESSURE');

-- CreateEnum
CREATE TYPE "SandboxTeardownIntent" AS ENUM ('OWNER_DESTROY', 'SYSTEM_DETACH');

-- CreateEnum
CREATE TYPE "SandboxLaunchMode" AS ENUM ('NEW_ROOT', 'COLD', 'WARM');

-- CreateEnum
CREATE TYPE "CapacityWaitState" AS ENUM ('WAITING', 'PLACED', 'TIMED_OUT', 'CANCELLED', 'FAILED');

-- CreateEnum
CREATE TYPE "OperationState" AS ENUM ('QUEUED', 'DISPATCHED', 'ACCEPTED', 'RUNNING', 'CANCEL_REQUESTED', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'UNKNOWN_OUTCOME');

-- CreateEnum
CREATE TYPE "HostConnectionStatus" AS ENUM ('DISCONNECTED', 'CONNECTED', 'STALE', 'REVOKED');

-- CreateEnum
CREATE TYPE "NodeDaemonRuntime" AS ENUM ('FAKE', 'INCUS_KVM', 'UNSUPPORTED');

-- CreateEnum
CREATE TYPE "SandboxEgressModeReason" AS ENUM ('NODE_POLICY', 'HOST_UNSUPPORTED');

-- CreateEnum
CREATE TYPE "SandboxGuestSudoReason" AS ENUM ('NODE_POLICY', 'HOST_UNSUPPORTED');

-- CreateEnum
CREATE TYPE "SandboxLeaseExpireAction" AS ENUM ('STOP', 'DESTROY');

-- CreateEnum
CREATE TYPE "SandboxOperationKind" AS ENUM ('CREATE_SANDBOX', 'KILL_SANDBOX', 'RUN_COMMAND', 'GET_FILE', 'PUT_FILE', 'RECONNECT_SANDBOX', 'STOP_SANDBOX', 'RENEW_SANDBOX_LEASE', 'LIST_DIR', 'STAT_PATH', 'MKDIR', 'REMOVE_PATH', 'MOVE_PATH', 'LIST_PROCESSES', 'SIGNAL_PROCESS', 'CAPTURE_TEMPLATE', 'CREDENTIAL_ATTACH', 'CREDENTIAL_FREE');

-- CreateEnum
CREATE TYPE "SandboxPurpose" AS ENUM ('WORKLOAD', 'CREDENTIAL_LOGIN', 'TEMPLATE_BUILD', 'TEMPLATE_VERIFY');

-- CreateEnum
CREATE TYPE "SdkKeyResourceMode" AS ENUM ('ALL_OWNED', 'ALLOWLIST');

-- CreateEnum
CREATE TYPE "SdkKeyPoolMode" AS ENUM ('ALL_USABLE', 'SELECTED');

-- CreateEnum
CREATE TYPE "TemplateAvailabilityStatus" AS ENUM ('PENDING', 'AVAILABLE', 'MISSING', 'REJECTED');

-- CreateEnum
CREATE TYPE "SandboxTransferState" AS ENUM ('ALLOCATING', 'OPEN', 'SEALED', 'ABORTED', 'EXPIRED', 'FAILED');

-- CreateEnum
CREATE TYPE "SandboxTransferDirection" AS ENUM ('UPLOAD', 'DOWNLOAD');

-- CreateEnum
CREATE TYPE "OperationResultReservationState" AS ENUM ('RESERVED', 'PUBLISHED', 'RELEASED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "TemplateRevisionSource" AS ENUM ('MANUAL', 'CAPTURE', 'BUILD', 'UPSTREAM');

-- CreateEnum
CREATE TYPE "ImagePlacementPolicy" AS ENUM ('ANY_NODE', 'OWNED_NODES_ONLY');

-- CreateEnum
CREATE TYPE "TemplateImagePlacement" AS ENUM ('INHERIT', 'ANY_NODE', 'OWNED_NODES_ONLY');

-- CreateEnum
CREATE TYPE "ImageArtifactState" AS ENUM ('LOCAL', 'UPLOADING', 'VERIFYING', 'STORED', 'CORRUPT', 'FAILED', 'DELETING', 'DELETED');

-- CreateEnum
CREATE TYPE "ImageStoreKind" AS ENUM ('S3', 'PEER');

-- CreateEnum
CREATE TYPE "ImageTransferPurpose" AS ENUM ('FETCH', 'REPLICATE', 'PUBLISH', 'CAPTURE_UPLOAD', 'OFFLOAD_UPLOAD', 'RESTORE_FETCH');

-- CreateEnum
CREATE TYPE "ImageTransferState" AS ENUM ('OPEN', 'COMPLETE', 'FAILED', 'EXPIRED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "TemplateCaptureState" AS ENUM ('PENDING', 'CAPTURED', 'STORING', 'FINALIZED', 'FAILED');

-- CreateEnum
CREATE TYPE "ImageUploadSessionState" AS ENUM ('OPEN', 'COMPLETE', 'ABORTED');

-- CreateEnum
CREATE TYPE "SandboxTunnelState" AS ENUM ('PENDING', 'CONNECTING', 'CONNECTED', 'SUSPENDED', 'ERROR');

-- CreateEnum
CREATE TYPE "WebhookDeliveryState" AS ENUM ('PENDING', 'IN_FLIGHT', 'SUCCEEDED', 'FAILED', 'CANCELLED');

-- CreateTable
CREATE TABLE "mcp_grant" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "referenceId" TEXT NOT NULL,
    "sdkKeyId" TEXT NOT NULL,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "mcp_grant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "host_queued_command" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "sandboxHostId" TEXT NOT NULL,
    "sdkKeyId" TEXT,
    "command" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "state" "HostQueuedCommandState" NOT NULL DEFAULT 'QUEUED',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "decidedAt" TIMESTAMP(3),
    "decidedBy" TEXT,

    CONSTRAINT "host_queued_command_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "host_file_receipt" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "userId" TEXT NOT NULL,
    "sandboxHostId" TEXT NOT NULL,
    "sdkKeyId" TEXT NOT NULL,
    "idempotencyKey" TEXT NOT NULL,
    "requestHmac" TEXT NOT NULL,
    "state" "HostFileReceiptState" NOT NULL DEFAULT 'PENDING',
    "result" JSONB,

    CONSTRAINT "host_file_receipt_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "host_audit_event" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "sandboxHostId" TEXT NOT NULL,
    "sdkKeyId" TEXT,
    "actor" "HostAuditActor" NOT NULL,
    "kind" "HostAuditKind" NOT NULL,
    "program" TEXT,
    "subjectHmac" TEXT,
    "commandId" TEXT,
    "state" TEXT,
    "reason" TEXT,
    "exitCode" INTEGER,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),

    CONSTRAINT "host_audit_event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "emailVerified" BOOLEAN NOT NULL DEFAULT false,
    "image" TEXT,
    "role" TEXT NOT NULL DEFAULT 'user',
    "locale" TEXT NOT NULL DEFAULT 'en-US',
    "deletionRequestedAt" TIMESTAMP(3),
    "banned" BOOLEAN,
    "banReason" TEXT,
    "banExpires" TIMESTAMP(3),
    "twoFactorEnabled" BOOLEAN,
    "hostTerminalFailedAttempts" INTEGER NOT NULL DEFAULT 0,
    "hostTerminalLockedUntil" TIMESTAMP(3),
    "hostTerminalLastTotpStep" BIGINT,
    "hostTerminalFactorFingerprint" TEXT,
    "hostTerminalFactorObservedAt" TIMESTAMP(3),
    "createdViaPoolInviteBy" TEXT,
    "createdViaPoolInviteId" TEXT,
    "operationalAlerts" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "user_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "session" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "token" TEXT NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "userId" TEXT NOT NULL,
    "impersonatedBy" TEXT,

    CONSTRAINT "session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "account" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "accountId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "accessToken" TEXT,
    "refreshToken" TEXT,
    "idToken" TEXT,
    "accessTokenExpiresAt" TIMESTAMP(3),
    "refreshTokenExpiresAt" TIMESTAMP(3),
    "scope" TEXT,
    "password" TEXT,
    "issuer" TEXT NOT NULL DEFAULT 'local:credential',

    CONSTRAINT "account_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "verification" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "identifier" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "verification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "two_factor" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "secret" TEXT NOT NULL,
    "backupCodes" TEXT NOT NULL,
    "verified" BOOLEAN NOT NULL DEFAULT true,
    "failedVerificationCount" INTEGER DEFAULT 0,
    "lockedUntil" TIMESTAMP(3),
    "userId" TEXT NOT NULL,

    CONSTRAINT "two_factor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "app_setting" (
    "key" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "value" TEXT NOT NULL,

    CONSTRAINT "app_setting_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "device_code" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deviceCode" TEXT NOT NULL,
    "userCode" TEXT NOT NULL,
    "userId" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "status" TEXT NOT NULL,
    "lastPolledAt" TIMESTAMP(3),
    "pollingInterval" INTEGER,
    "clientId" TEXT,
    "scope" TEXT,
    "enrollmentIntent" TEXT,
    "replaceHostId" TEXT,

    CONSTRAINT "device_code_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "push_subscription" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endpoint" TEXT NOT NULL,
    "p256dh" TEXT NOT NULL,
    "auth" TEXT NOT NULL,
    "userId" TEXT NOT NULL,

    CONSTRAINT "push_subscription_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "account_image_policy" (
    "userId" TEXT NOT NULL,
    "imagePlacement" "ImagePlacementPolicy" NOT NULL DEFAULT 'ANY_NODE',
    "adminStoredGiBMax" INTEGER,
    "adminDownloadsPerHourMax" INTEGER,
    "allowForeignBuilds" BOOLEAN NOT NULL DEFAULT false,
    "adminConcurrentBuildsMax" INTEGER,
    "adminBuildMinutesPerMonthMax" INTEGER,
    "adminOffloadGiBMax" INTEGER,
    "adminUpdatedAt" TIMESTAMP(3),
    "adminUpdatedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "account_image_policy_pkey" PRIMARY KEY ("userId")
);

-- CreateTable
CREATE TABLE "oauth_client" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientSecret" TEXT,
    "clientDiscoveryId" TEXT,
    "disabled" BOOLEAN DEFAULT false,
    "skipConsent" BOOLEAN,
    "enableEndSession" BOOLEAN,
    "subjectType" TEXT,
    "scopes" TEXT[],
    "clientCredentialsScopes" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "userId" TEXT,
    "createdAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "name" TEXT,
    "uri" TEXT,
    "icon" TEXT,
    "contacts" TEXT[],
    "tos" TEXT,
    "policy" TEXT,
    "softwareId" TEXT,
    "softwareVersion" TEXT,
    "softwareStatement" TEXT,
    "redirectUris" TEXT[],
    "postLogoutRedirectUris" TEXT[],
    "backchannelLogoutUri" TEXT,
    "backchannelLogoutSessionRequired" BOOLEAN,
    "tokenEndpointAuthMethod" TEXT,
    "applicationType" TEXT,
    "jwks" TEXT,
    "jwksUri" TEXT,
    "grantTypes" TEXT[],
    "responseTypes" TEXT[],
    "requirePKCE" BOOLEAN,
    "dpopBoundAccessTokens" BOOLEAN DEFAULT false,
    "referenceId" TEXT,
    "metadata" JSONB,

    CONSTRAINT "oauth_client_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oauth_resource" (
    "id" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "accessTokenTtl" INTEGER,
    "refreshTokenTtl" INTEGER,
    "signingAlgorithm" TEXT,
    "signingKeyId" TEXT,
    "allowedScopes" JSONB,
    "customClaims" JSONB,
    "dpopBoundAccessTokensRequired" BOOLEAN DEFAULT false,
    "disabled" BOOLEAN DEFAULT false,
    "createdAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    "policyVersion" INTEGER DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "oauth_resource_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oauth_client_resource" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "resourceId" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "oauth_client_resource_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oauth_refresh_token" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "sessionId" TEXT,
    "userId" TEXT NOT NULL,
    "referenceId" TEXT,
    "authorizationCodeId" TEXT,
    "resources" TEXT[],
    "requestedUserInfoClaims" TEXT[],
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revoked" TIMESTAMP(3),
    "rotatedAt" TIMESTAMP(3),
    "rotationReplayResponse" TEXT,
    "rotationReplayExpiresAt" TIMESTAMP(3),
    "authTime" TIMESTAMP(3),
    "confirmation" JSONB,
    "scopes" TEXT[],

    CONSTRAINT "oauth_refresh_token_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oauth_access_token" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "sessionId" TEXT,
    "userId" TEXT,
    "referenceId" TEXT,
    "authorizationCodeId" TEXT,
    "resources" TEXT[],
    "requestedUserInfoClaims" TEXT[],
    "refreshId" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revoked" TIMESTAMP(3),
    "confirmation" JSONB,
    "scopes" TEXT[],

    CONSTRAINT "oauth_access_token_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oauth_consent" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "userId" TEXT,
    "referenceId" TEXT,
    "resources" TEXT[],
    "requestedUserInfoClaims" TEXT[],
    "scopes" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "oauth_consent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oauth_client_assertion" (
    "id" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "oauth_client_assertion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "jwks" (
    "id" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "privateKey" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "alg" TEXT,
    "crv" TEXT,

    CONSTRAINT "jwks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_template_build" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "templateId" TEXT NOT NULL,
    "tag" TEXT NOT NULL,
    "principalKind" "TemplateBuildPrincipalKind" NOT NULL,
    "authorizingKeyId" TEXT,
    "triggeredByRevisionId" TEXT,
    "idempotencyKey" TEXT NOT NULL,
    "requestBodyHash" TEXT NOT NULL,
    "recipe" JSONB NOT NULL,
    "recipeDigest" TEXT NOT NULL,
    "buildDigest" TEXT NOT NULL,
    "sourceFormat" "TemplateBuildSourceFormat" NOT NULL,
    "dockerfileText" TEXT,
    "baseRevisionId" TEXT NOT NULL,
    "baseFingerprint" TEXT NOT NULL,
    "buildArgs" JSONB NOT NULL DEFAULT '{}',
    "contextSha256" TEXT,
    "contextBytes" BIGINT,
    "poolId" TEXT,
    "requestedHostId" TEXT,
    "targetKey" TEXT NOT NULL,
    "principalKey" TEXT NOT NULL,
    "cpuCount" INTEGER NOT NULL,
    "memoryMiB" INTEGER NOT NULL,
    "diskGiB" INTEGER NOT NULL,
    "defaultDiskGiB" INTEGER NOT NULL,
    "egressRequest" JSONB,
    "egressPresets" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "timeoutMinutes" INTEGER NOT NULL,
    "waitForCapacityMs" INTEGER,
    "reservedMinutes" INTEGER NOT NULL,
    "chargedMinutes" INTEGER,
    "minutesSettled" BOOLEAN NOT NULL DEFAULT false,
    "chargeMonth" DATE NOT NULL,
    "state" "TemplateBuildState" NOT NULL,
    "phase" TEXT,
    "stepIndex" INTEGER NOT NULL DEFAULT -1,
    "steps" JSONB NOT NULL DEFAULT '[]',
    "egressHints" JSONB NOT NULL DEFAULT '[]',
    "pendingAction" JSONB,
    "nextAttemptAt" TIMESTAMP(3),
    "buildSandboxId" TEXT,
    "currentOperationId" TEXT,
    "captureOperationId" TEXT,
    "captureAttempt" INTEGER NOT NULL DEFAULT 0,
    "revisionId" TEXT,
    "cacheHitRevisionId" TEXT,
    "hostId" TEXT,
    "hostOwnerId" TEXT,
    "foreignHost" BOOLEAN NOT NULL DEFAULT false,
    "noCache" BOOLEAN NOT NULL DEFAULT false,
    "cancelRequestedAt" TIMESTAMP(3),
    "deadlineAt" TIMESTAMP(3),
    "captureDeadlineAt" TIMESTAMP(3),
    "readyAt" TIMESTAMP(3),
    "stoppedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "errorCode" TEXT,
    "errorDetail" TEXT,
    "failureStepIndex" INTEGER,
    "failureExitCode" INTEGER,
    "failureTail" BYTEA,
    "origin" "TemplateBuildOrigin" NOT NULL DEFAULT 'USER',
    "verifyRequired" BOOLEAN NOT NULL DEFAULT false,
    "verifySandboxId" TEXT,
    "verifyDeadlineAt" TIMESTAMP(3),
    "cleanupState" "TemplateBuildCleanupState" NOT NULL DEFAULT 'PENDING',
    "cleanupDoneAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_template_build_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_build_context" (
    "id" TEXT NOT NULL,
    "buildId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "keyId" TEXT,
    "state" "BuildContextState" NOT NULL DEFAULT 'OPEN',
    "totalBytes" BIGINT NOT NULL,
    "receivedBytes" BIGINT NOT NULL DEFAULT 0,
    "expectedSha256" TEXT NOT NULL,
    "idleExpiresAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "importAttempt" INTEGER NOT NULL DEFAULT 0,
    "reservationHeld" BOOLEAN NOT NULL DEFAULT true,
    "errorCode" TEXT,
    "transferId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_build_context_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_build_context_chunk" (
    "contextId" TEXT NOT NULL,
    "offset" BIGINT NOT NULL,
    "length" INTEGER NOT NULL,
    "digest" TEXT NOT NULL,

    CONSTRAINT "sandbox_build_context_chunk_pkey" PRIMARY KEY ("contextId","offset")
);

-- CreateTable
CREATE TABLE "credential_definition" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "document" JSONB NOT NULL,
    "digest" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "archivedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_definition_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credential" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "definitionId" TEXT NOT NULL,
    "definitionDigest" TEXT NOT NULL,
    "mode" "CredentialMode" NOT NULL,
    "delivery" "CredentialDelivery" NOT NULL,
    "copyBack" BOOLEAN NOT NULL,
    "checkpointIntervalMin" INTEGER,
    "foreignAllowed" BOOLEAN NOT NULL DEFAULT false,
    "foreignAllowedAt" TIMESTAMP(3),
    "foreignAllowedBy" TEXT,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credential_account" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "ordinal" INTEGER NOT NULL,
    "name" TEXT,
    "pausedAt" TIMESTAMP(3),
    "pausedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_account_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credential_instance" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "accountOrdinal" INTEGER NOT NULL,
    "ordinal" INTEGER NOT NULL,
    "name" TEXT,
    "accountPaused" BOOLEAN NOT NULL DEFAULT false,
    "capacity" INTEGER,
    "activeLeases" INTEGER NOT NULL DEFAULT 0,
    "loginLeaseId" TEXT,
    "currentSeq" INTEGER,
    "nextStorageSeq" INTEGER NOT NULL DEFAULT 1,
    "state" "CredentialInstanceState" NOT NULL DEFAULT 'EMPTY',
    "needsLoginReason" TEXT,
    "lastCapturedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_instance_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credential_secret_version" (
    "instanceId" TEXT NOT NULL,
    "storageSeq" INTEGER NOT NULL,
    "kind" "CredentialSecretKind" NOT NULL,
    "ciphertext" BYTEA NOT NULL,
    "nonce" BYTEA NOT NULL,
    "wrappedDek" BYTEA NOT NULL,
    "wrapSalt" BYTEA NOT NULL,
    "wrapNonce" BYTEA NOT NULL,
    "rootKid" TEXT NOT NULL,
    "policyDigest" TEXT NOT NULL,
    "sizeBytes" INTEGER NOT NULL,
    "sourceLeaseId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_secret_version_pkey" PRIMARY KEY ("instanceId","storageSeq")
);

-- CreateTable
CREATE TABLE "credential_lease" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "instanceId" TEXT NOT NULL,
    "sandboxId" TEXT,
    "loginSessionId" TEXT,
    "operationId" TEXT NOT NULL,
    "kind" "CredentialLeaseKind" NOT NULL,
    "exclusive" BOOLEAN NOT NULL,
    "state" "CredentialLeaseState" NOT NULL DEFAULT 'RESERVED',
    "baseSeq" INTEGER,
    "hostId" TEXT,
    "currentBindingId" TEXT,
    "teardownOperationId" TEXT,
    "captureSeqAccepted" INTEGER NOT NULL DEFAULT 0,
    "endReason" TEXT,
    "releasedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_lease_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credential_binding" (
    "id" TEXT NOT NULL,
    "leaseId" TEXT NOT NULL,
    "instanceId" TEXT NOT NULL,
    "sandboxId" TEXT,
    "hostId" TEXT NOT NULL,
    "grantGeneration" INTEGER NOT NULL,
    "operationId" TEXT,
    "requestId" TEXT,
    "baseSeq" INTEGER,
    "purpose" "CredentialBindingPurpose" NOT NULL,
    "recoveryOfBindingId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "closedAt" TIMESTAMP(3),
    "closeReason" TEXT,

    CONSTRAINT "credential_binding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credential_residue" (
    "id" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "instanceId" TEXT NOT NULL,
    "leaseId" TEXT NOT NULL,
    "bindingId" TEXT NOT NULL,
    "grantGeneration" INTEGER NOT NULL,
    "paths" JSONB NOT NULL,
    "recoverable" BOOLEAN NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "clearedAt" TIMESTAMP(3),
    "clearReason" TEXT,

    CONSTRAINT "credential_residue_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credential_capture" (
    "captureId" TEXT NOT NULL,
    "leaseId" TEXT NOT NULL,
    "bindingId" TEXT NOT NULL,
    "captureSeq" INTEGER NOT NULL,
    "kind" TEXT NOT NULL,
    "kidR" TEXT NOT NULL,
    "envelopeDigest" BYTEA NOT NULL,
    "outcome" "CredentialCaptureOutcome" NOT NULL,
    "reason" TEXT,
    "storageSeq" INTEGER,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_capture_pkey" PRIMARY KEY ("captureId")
);

-- CreateTable
CREATE TABLE "credential_pending_capture" (
    "hostId" TEXT NOT NULL,
    "captureId" TEXT NOT NULL,
    "leaseId" TEXT NOT NULL,
    "bindingId" TEXT NOT NULL,
    "kidR" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "reportedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_pending_capture_pkey" PRIMARY KEY ("hostId","captureId")
);

-- CreateTable
CREATE TABLE "credential_host_census" (
    "hostId" TEXT NOT NULL,
    "connectionEpoch" BIGINT NOT NULL,
    "keyEpoch" BIGINT NOT NULL,
    "quarantinedCount" INTEGER NOT NULL DEFAULT 0,
    "completedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "credential_host_census_pkey" PRIMARY KEY ("hostId")
);

-- CreateTable
CREATE TABLE "credential_lease_tombstone" (
    "hostId" TEXT NOT NULL,
    "leaseId" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_lease_tombstone_pkey" PRIMARY KEY ("hostId","leaseId")
);

-- CreateTable
CREATE TABLE "credential_return_key" (
    "kidR" TEXT NOT NULL,
    "epoch" BIGINT NOT NULL,
    "publicKey" BYTEA NOT NULL,
    "wrappedPrivate" BYTEA NOT NULL,
    "rwrapSalt" BYTEA NOT NULL,
    "wrapNonce" BYTEA NOT NULL,
    "rootKid" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "retiredAt" TIMESTAMP(3),
    "destroyedAt" TIMESTAMP(3),

    CONSTRAINT "credential_return_key_pkey" PRIMARY KEY ("kidR")
);

-- CreateTable
CREATE TABLE "credential_return_key_state" (
    "id" INTEGER NOT NULL,
    "currentKidR" TEXT NOT NULL,
    "currentEpoch" BIGINT NOT NULL,

    CONSTRAINT "credential_return_key_state_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credential_host_return_key" (
    "hostId" TEXT NOT NULL,
    "kidR" TEXT NOT NULL,
    "epoch" BIGINT NOT NULL,
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ackedAt" TIMESTAMP(3),
    "drainedAt" TIMESTAMP(3),
    "declaredLostAt" TIMESTAMP(3),

    CONSTRAINT "credential_host_return_key_pkey" PRIMARY KEY ("hostId","kidR")
);

-- CreateTable
CREATE TABLE "credential_capture_rejection" (
    "hostId" TEXT NOT NULL,
    "captureId" TEXT NOT NULL,
    "envelopeDigest" BYTEA NOT NULL,
    "leaseId" TEXT,
    "bindingId" TEXT,
    "kidR" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "discardedAt" TIMESTAMP(3),

    CONSTRAINT "credential_capture_rejection_pkey" PRIMARY KEY ("hostId","captureId","envelopeDigest")
);

-- CreateTable
CREATE TABLE "sandbox_credential" (
    "id" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "requestedAccountId" TEXT,
    "requestedInstanceId" TEXT,
    "accountId" TEXT,
    "instanceId" TEXT,
    "attachedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "detachedAt" TIMESTAMP(3),

    CONSTRAINT "sandbox_credential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credential_operation_spec" (
    "operationId" TEXT NOT NULL,
    "digest" BYTEA NOT NULL,
    "bytes" BYTEA NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_operation_spec_pkey" PRIMARY KEY ("operationId")
);

-- CreateTable
CREATE TABLE "credential_login_session" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "instanceId" TEXT NOT NULL,
    "sandboxId" TEXT,
    "state" "CredentialLoginSessionState" NOT NULL DEFAULT 'PROVISIONING',
    "foreignConsentAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_login_session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credential_event" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "accountId" TEXT,
    "instanceId" TEXT,
    "leaseId" TEXT,
    "sandboxId" TEXT,
    "type" TEXT NOT NULL,
    "storageSeq" INTEGER,
    "hostId" TEXT,
    "sizeBytes" INTEGER,
    "reason" TEXT,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credential_event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sdk_key_credential_allowlist" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "sdkKeyId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,

    CONSTRAINT "sdk_key_credential_allowlist_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "data_key_epoch" (
    "id" INTEGER NOT NULL,
    "currentKid" TEXT NOT NULL,
    "previousKid" TEXT,
    "epoch" BIGINT NOT NULL,
    "switchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "data_key_epoch_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_host" (
    "agentHostCommandsVetoedAt" TIMESTAMP(3),
    "hostTerminalVetoedAt" TIMESTAMP(3),
    "relayProtocolVersion" TEXT,
    "relayProtocolEpoch" INTEGER,
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "status" "HostConnectionStatus" NOT NULL DEFAULT 'DISCONNECTED',
    "lastConnectedAt" TIMESTAMP(3),
    "lastDisconnectedAt" TIMESTAMP(3),
    "lastHeartbeatAt" TIMESTAMP(3),
    "deletionRequestedAt" TIMESTAMP(3),
    "connectionCount" INTEGER NOT NULL DEFAULT 0,
    "connectionEpoch" INTEGER NOT NULL DEFAULT 0,
    "inventorySeq" INTEGER NOT NULL DEFAULT 0,
    "inventoryDigest" TEXT,
    "inventoryAcknowledgedEpoch" INTEGER,
    "journalKeyVersion" INTEGER,
    "journalKeyId" TEXT,
    "journalKeyAcknowledgedEpoch" INTEGER,
    "lastPlacedAt" TIMESTAMP(3),
    "admissionRuntime" "NodeDaemonRuntime",
    "admissionEpoch" INTEGER,
    "admissionReportedAt" TIMESTAMP(3),
    "daemonSchedulable" BOOLEAN,
    "daemonFeatures" JSONB,
    "availabilityEpoch" INTEGER,
    "availabilityCensusComplete" BOOLEAN NOT NULL DEFAULT false,
    "inventoryAcknowledgedAt" TIMESTAMP(3),
    "quarantinedAt" TIMESTAMP(3),
    "quarantineReason" TEXT,
    "liveCount" INTEGER NOT NULL DEFAULT 0,
    "memoryReservedMiB" INTEGER NOT NULL DEFAULT 0,
    "daemonMemoryBudgetMiB" INTEGER,
    "daemonMaxCpuCount" INTEGER,
    "capacityReport" JSONB,
    "daemonVcpuBudget" INTEGER,
    "vcpuReserved" INTEGER NOT NULL DEFAULT 0,
    "rootCount" INTEGER NOT NULL DEFAULT 0,
    "draining" BOOLEAN NOT NULL DEFAULT false,
    "drainOffload" BOOLEAN NOT NULL DEFAULT false,
    "quiescingSince" TIMESTAMP(3),
    "daemonRuntime" "NodeDaemonRuntime",
    "daemonVersion" TEXT,
    "policyReconcilerHealth" JSONB,
    "egressEnforcement" BOOLEAN NOT NULL DEFAULT false,
    "daemonMaxLeaseMs" INTEGER DEFAULT 86400000,
    "daemonLeasePolicy" BOOLEAN NOT NULL DEFAULT false,
    "daemonOpenEgressForOthers" BOOLEAN NOT NULL DEFAULT false,
    "daemonGuestSudoForOthers" BOOLEAN NOT NULL DEFAULT true,
    "daemonEgressGuardOk" BOOLEAN NOT NULL DEFAULT false,
    "daemonEgressGuardReason" TEXT,
    "daemonEgressGuardEpoch" INTEGER,
    "daemonEgressGuardLeaseUntil" TIMESTAMP(3),
    "daemonEgressGuardInstanceId" TEXT,
    "daemonEgressGuardGeneration" BIGINT,
    "daemonEgressStateSequence" BIGINT,
    "imageCacheCapBytes" BIGINT,
    "imageCacheUsedBytes" BIGINT,
    "imageCacheForeignBytes" BIGINT,
    "imageCacheEpoch" INTEGER,
    "daemonDiskOffload" BOOLEAN NOT NULL DEFAULT false,
    "daemonTunnel" JSONB,
    "daemonTunnelPorts" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "sandbox_host_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "host_token" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "sandboxHostId" TEXT,
    "name" TEXT NOT NULL,
    "lookupPrefix" TEXT NOT NULL,
    "secretDigest" TEXT NOT NULL,
    "lastUsedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),

    CONSTRAINT "host_token_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "host_device_credential" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "sandboxHostId" TEXT NOT NULL,
    "lookupPrefix" TEXT NOT NULL,
    "secretDigest" TEXT NOT NULL,
    "lastUsedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "host_device_credential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sdk_key" (
    "kind" "SdkKeyKind" NOT NULL DEFAULT 'API',
    "ownSandboxesOnly" BOOLEAN NOT NULL DEFAULT false,
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "poolMode" "SdkKeyPoolMode" NOT NULL DEFAULT 'SELECTED',
    "resourceMode" "SdkKeyResourceMode" NOT NULL DEFAULT 'ALLOWLIST',
    "scopes" TEXT[],
    "lookupPrefix" TEXT,
    "secretDigest" TEXT,
    "lastUsedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),

    CONSTRAINT "sdk_key_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sdk_key_host_allowlist" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sdkKeyId" TEXT NOT NULL,
    "sandboxHostId" TEXT NOT NULL,

    CONSTRAINT "sdk_key_host_allowlist_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sdk_key_revision_allowlist" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "sdkKeyId" TEXT NOT NULL,
    "templateRevisionId" TEXT NOT NULL,

    CONSTRAINT "sdk_key_revision_allowlist_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_logical_template" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "archivedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "imagePlacement" "TemplateImagePlacement" NOT NULL DEFAULT 'INHERIT',
    "captureKeep" INTEGER NOT NULL DEFAULT 3,
    "pruneAfterDays" INTEGER,
    "captureScrubPaths" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "communitySource" TEXT,
    "communityRefresh" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "sandbox_logical_template_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_template_revision" (
    "defaultDiskGiB" INTEGER NOT NULL DEFAULT 32,
    "minDiskGiB" INTEGER NOT NULL DEFAULT 32,
    "cpuCount" INTEGER NOT NULL DEFAULT 1,
    "memoryMiB" INTEGER NOT NULL DEFAULT 1024,
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "templateId" TEXT NOT NULL,
    "revision" INTEGER NOT NULL,
    "incusFingerprint" TEXT NOT NULL,
    "architecture" TEXT NOT NULL,
    "guestUid" INTEGER NOT NULL DEFAULT 1000,
    "guestGid" INTEGER NOT NULL DEFAULT 1000,
    "guestHome" TEXT NOT NULL DEFAULT '/home/user',
    "guestShell" TEXT NOT NULL DEFAULT '/bin/bash',
    "guestVersion" TEXT,
    "manifestDigest" TEXT NOT NULL,
    "retiredAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sourceKind" "TemplateRevisionSource" NOT NULL DEFAULT 'MANUAL',
    "parentRevisionId" TEXT,
    "capturedFromSandboxId" TEXT,
    "captureTag" TEXT,
    "retiredReason" TEXT,
    "buildId" TEXT,
    "recipeDigest" TEXT,
    "defaultCwd" TEXT,
    "startCmd" TEXT,
    "readyCmd" TEXT,
    "readyTimeoutMs" INTEGER,
    "builtOnForeignHost" BOOLEAN NOT NULL DEFAULT false,
    "builtWithRoot" BOOLEAN NOT NULL DEFAULT false,
    "capturedWithGuestRoot" BOOLEAN NOT NULL DEFAULT false,
    "builtWithWsspRecipe" BOOLEAN NOT NULL DEFAULT false,
    "pendingVerifyBuildId" TEXT,

    CONSTRAINT "sandbox_template_revision_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_upstream_image" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "templateId" TEXT NOT NULL,
    "revisionId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "product" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "architecture" TEXT NOT NULL,
    "metaPath" TEXT NOT NULL,
    "metaSha256" TEXT NOT NULL,
    "metaSize" BIGINT NOT NULL,
    "diskPath" TEXT NOT NULL,
    "diskSha256" TEXT NOT NULL,
    "diskSize" BIGINT NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_upstream_image_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_template_tag" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "templateId" TEXT NOT NULL,
    "tag" TEXT NOT NULL,
    "revisionId" TEXT NOT NULL,

    CONSTRAINT "sandbox_template_tag_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_template_availability" (
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "revisionId" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "hostOwnerId" TEXT NOT NULL,
    "localFingerprint" TEXT NOT NULL,
    "architecture" TEXT NOT NULL,
    "manifestDigest" TEXT NOT NULL,
    "status" "TemplateAvailabilityStatus" NOT NULL DEFAULT 'PENDING',
    "verifiedConnectionEpoch" INTEGER,
    "observedAt" TIMESTAMP(3),
    "sizeBytes" BIGINT,
    "imageFormat" TEXT,

    CONSTRAINT "sandbox_template_availability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_revision_config" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "revisionId" TEXT NOT NULL,
    "defaultEnvs" JSONB NOT NULL,
    "checksum" TEXT NOT NULL,
    "digestScheme" TEXT NOT NULL,
    "digestKeyId" TEXT NOT NULL,

    CONSTRAINT "sandbox_revision_config_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_placement" (
    "storagePoolId" TEXT NOT NULL,
    "storageMarker" TEXT NOT NULL,
    "storagePoolName" TEXT NOT NULL,
    "rootChargeGiB" INTEGER NOT NULL,
    "chargedMemoryMiB" INTEGER NOT NULL,
    "chargedVcpu" INTEGER NOT NULL,
    "diskGiB" INTEGER NOT NULL DEFAULT 32,
    "cpuCount" INTEGER NOT NULL DEFAULT 1,
    "memoryMiB" INTEGER NOT NULL DEFAULT 1024,
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "generation" INTEGER NOT NULL,
    "operationId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "originHostId" TEXT NOT NULL,
    "originPoolId" TEXT,
    "hostOwnerId" TEXT NOT NULL,
    "originShareId" TEXT,
    "acceptedGraceSeconds" INTEGER NOT NULL DEFAULT 259200,
    "originMemberId" TEXT,
    "imageFetchBytes" BIGINT,
    "templateId" TEXT NOT NULL,
    "templateRevisionId" TEXT NOT NULL,
    "artifact" TEXT NOT NULL,
    "architecture" TEXT NOT NULL,
    "guestUid" INTEGER NOT NULL,
    "guestGid" INTEGER NOT NULL,
    "guestHome" TEXT NOT NULL,
    "guestShell" TEXT NOT NULL,
    "configId" TEXT NOT NULL,
    "acceptedAt" TIMESTAMP(3) NOT NULL,
    "startedAt" TIMESTAMP(3),
    "readyAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "endReason" TEXT,
    "restoreOffloadId" TEXT,

    CONSTRAINT "sandbox_placement_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_instance" (
    "storagePoolId" TEXT,
    "storageMarker" TEXT,
    "storagePoolName" TEXT,
    "rootChargeGiB" INTEGER,
    "diskReservationHeld" BOOLEAN NOT NULL DEFAULT false,
    "diskGiB" INTEGER NOT NULL DEFAULT 32,
    "cpuCount" INTEGER NOT NULL DEFAULT 1,
    "memoryMiB" INTEGER NOT NULL DEFAULT 1024,
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "sandboxHostId" TEXT,
    "hostOwnerId" TEXT,
    "usagePoolId" TEXT,
    "usageMemberId" TEXT,
    "accessGraceUntil" TIMESTAMP(3),
    "accessGraceReason" TEXT,
    "templateRevisionId" TEXT NOT NULL,
    "originPoolId" TEXT,
    "originalSelector" TEXT NOT NULL,
    "currentPlacementId" TEXT,
    "templateId" TEXT NOT NULL,
    "originHostId" TEXT,
    "state" "SandboxState" NOT NULL DEFAULT 'REQUESTED',
    "generation" INTEGER NOT NULL DEFAULT 1,
    "incusName" TEXT,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "leaseRevision" INTEGER NOT NULL DEFAULT 1,
    "leaseExpiresAt" TIMESTAMP(3),
    "leaseExpireAction" "SandboxLeaseExpireAction" NOT NULL DEFAULT 'DESTROY',
    "leaseExpiresAtRequested" TIMESTAMP(3),
    "leaseExpireActionRequested" "SandboxLeaseExpireAction",
    "leaseRevisionEffective" INTEGER,
    "leaseExpiresAtEffective" TIMESTAMP(3),
    "leaseExpireActionEffective" "SandboxLeaseExpireAction",
    "leasePendingReady" BOOLEAN NOT NULL DEFAULT false,
    "startedAt" TIMESTAMP(3),
    "readyAt" TIMESTAMP(3),
    "lastErrorCode" TEXT,
    "lastErrorDetail" TEXT,
    "hostExpiryConfirmedAt" TIMESTAMP(3),
    "hostExpiryRevision" INTEGER,
    "hostExpiryAction" "SandboxLeaseExpireAction",
    "liveResourcesHeld" BOOLEAN NOT NULL DEFAULT false,
    "egressPolicy" JSONB,
    "egressPolicyHash" TEXT,
    "purpose" "SandboxPurpose" NOT NULL DEFAULT 'WORKLOAD',
    "buildId" TEXT,
    "verifyBuildId" TEXT,
    "credentialProxyEnabled" BOOLEAN NOT NULL DEFAULT false,
    "credentialPathHistory" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "egressRequest" JSONB,
    "egressModeReason" "SandboxEgressModeReason",
    "guestSudoRequested" BOOLEAN NOT NULL DEFAULT false,
    "guestSudo" BOOLEAN NOT NULL DEFAULT false,
    "tunnelPorts" INTEGER[] DEFAULT ARRAY[]::INTEGER[],
    "guestSudoReason" "SandboxGuestSudoReason",
    "guestRoot" BOOLEAN NOT NULL DEFAULT false,
    "egressDeniedGrants" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "guestGroupSignals" BOOLEAN,
    "name" TEXT NOT NULL DEFAULT ('sandbox-'::text || substr(md5((random())::text), 1, 12)),
    "offloadSeq" INTEGER NOT NULL DEFAULT 0,
    "diskOffloadId" TEXT,
    "cachedOffloadSeq" INTEGER,
    "diskBaseFingerprint" TEXT,
    "cloudInitInstanceId" TEXT,
    "offloadPin" "SandboxOffloadPin" NOT NULL DEFAULT 'ANY',
    "offloadMode" "SandboxOffloadMode" NOT NULL DEFAULT 'ON_STOP',
    "offloadAfterMs" INTEGER,
    "credentialFilesEver" BOOLEAN NOT NULL DEFAULT false,
    "lastStoppedAt" TIMESTAMP(3),

    CONSTRAINT "sandbox_instance_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_execution_config" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "generation" INTEGER NOT NULL,
    "hostId" TEXT NOT NULL,
    "authorizingKeyId" TEXT,
    "templateDefaults" JSONB NOT NULL,
    "sandboxOverrides" JSONB NOT NULL,
    "mergedDefaults" JSONB NOT NULL,
    "bindingScheme" TEXT NOT NULL,
    "bindingKeyId" TEXT NOT NULL,
    "bindingMac" TEXT NOT NULL,
    "acknowledgedEpoch" INTEGER,
    "acknowledgedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_execution_config_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_mutation_operation" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "kind" "SandboxOperationKind" NOT NULL,
    "state" "OperationState" NOT NULL DEFAULT 'QUEUED',
    "generation" INTEGER NOT NULL,
    "teardownPriorState" "SandboxState",
    "dispatchedConnectionEpoch" INTEGER,
    "nextStdinSequence" INTEGER NOT NULL DEFAULT 0,
    "stdinClosed" BOOLEAN NOT NULL DEFAULT false,
    "dispatchAttempt" INTEGER NOT NULL DEFAULT 0,
    "acceptedAttempt" INTEGER,
    "authorizingKeyId" TEXT,
    "dispatchedHostId" TEXT,
    "idempotencyKey" TEXT NOT NULL,
    "requestBodyHash" TEXT NOT NULL,
    "requestDigestScheme" TEXT NOT NULL,
    "requestDigestKeyId" TEXT,
    "leaseAcceptedAt" TIMESTAMP(3),
    "leaseTimeoutMs" INTEGER,
    "leaseRevisionAccepted" INTEGER,
    "leaseExpiresAtAccepted" TIMESTAMP(3),
    "leaseExpireActionAccepted" "SandboxLeaseExpireAction",
    "leaseAcknowledgedAt" TIMESTAMP(3),
    "leaseAcknowledgedAttempt" INTEGER,
    "leaseAcknowledgedEpoch" INTEGER,
    "leaseFromReady" BOOLEAN NOT NULL DEFAULT false,
    "progressPhase" TEXT,
    "progressBytesDone" BIGINT,
    "progressBytesTotal" BIGINT,
    "progressAt" TIMESTAMP(3),
    "processId" TEXT,
    "processPid" INTEGER,
    "processStartedAt" TIMESTAMP(3),
    "processBootId" TEXT,
    "processStartTicks" TEXT,
    "processDescription" JSONB,
    "processDescriptionExpiresAt" TIMESTAMP(3),
    "resultVersion" INTEGER,
    "resultExpiresAt" TIMESTAMP(3),
    "resultObservedAt" TIMESTAMP(3),
    "scalarResult" JSONB,
    "failure" JSONB,
    "result" JSONB,
    "errorCode" TEXT,
    "errorDetail" TEXT,
    "dispatchedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "teardownIntent" "SandboxTeardownIntent",
    "launchMode" "SandboxLaunchMode",
    "restoreOffloadId" TEXT,
    "digestContext" JSONB NOT NULL,
    "attemptOperationId" TEXT,
    "attemptGeneration" INTEGER,

    CONSTRAINT "sandbox_mutation_operation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_command_stream" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "attempt" INTEGER NOT NULL,
    "nextSequence" INTEGER NOT NULL DEFAULT 0,
    "receivedEnd" BIGINT NOT NULL DEFAULT 0,
    "totalBytes" BIGINT,
    "headBytes" INTEGER NOT NULL DEFAULT 0,
    "tailBytes" INTEGER NOT NULL DEFAULT 0,
    "headSegments" INTEGER NOT NULL DEFAULT 0,
    "tailSegments" INTEGER NOT NULL DEFAULT 0,
    "recent" JSONB NOT NULL DEFAULT '[]',

    CONSTRAINT "sandbox_command_stream_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_command_stream_segment" (
    "id" TEXT NOT NULL,
    "outputId" TEXT NOT NULL,
    "tail" BOOLEAN NOT NULL,
    "startOffset" BIGINT NOT NULL,
    "endOffset" BIGINT NOT NULL,
    "bytes" BYTEA NOT NULL,
    "stderrMask" BYTEA NOT NULL,

    CONSTRAINT "sandbox_command_stream_segment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_dispatch_outbox" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "aggregateType" TEXT NOT NULL,
    "aggregateId" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "payload" JSONB NOT NULL DEFAULT '{}',
    "operationId" TEXT NOT NULL,
    "sentAt" TIMESTAMP(3),
    "sentConnectionEpoch" INTEGER,
    "claimToken" TEXT,
    "claimedAt" TIMESTAMP(3),
    "processedAt" TIMESTAMP(3),

    CONSTRAINT "sandbox_dispatch_outbox_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_mutation_receipt" (
    "authorizingKeyId" TEXT,
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "idempotencyKey" TEXT NOT NULL,
    "requestBodyHash" TEXT NOT NULL,
    "requestDigestScheme" TEXT NOT NULL,
    "requestDigestKeyId" TEXT,
    "action" TEXT NOT NULL,
    "sandboxId" TEXT,
    "hostId" TEXT NOT NULL,
    "verificationConnectionEpoch" INTEGER,
    "logicalTemplateId" TEXT,
    "templateRevisionId" TEXT,
    "originPoolId" TEXT,
    "targetOperationId" TEXT,
    "generation" INTEGER,
    "state" "OperationState" NOT NULL DEFAULT 'UNKNOWN_OUTCOME',
    "errorCode" TEXT,
    "probeState" TEXT,
    "resourceId" TEXT,
    "digestContext" JSONB NOT NULL,

    CONSTRAINT "sandbox_mutation_receipt_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_stream_transfer" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "keyId" TEXT,
    "sandboxId" TEXT NOT NULL,
    "generation" INTEGER NOT NULL,
    "direction" "SandboxTransferDirection" NOT NULL,
    "guestPath" TEXT NOT NULL,
    "idempotencyKey" TEXT NOT NULL,
    "requestBodyHash" TEXT NOT NULL,
    "totalBytes" BIGINT NOT NULL,
    "receivedBytes" BIGINT NOT NULL DEFAULT 0,
    "reservationHeld" BOOLEAN NOT NULL DEFAULT true,
    "state" "SandboxTransferState" NOT NULL DEFAULT 'ALLOCATING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "idleExpiresAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "sha256" TEXT,
    "operationId" TEXT,
    "operationAttempt" INTEGER,
    "acceptedHostId" TEXT NOT NULL,

    CONSTRAINT "sandbox_stream_transfer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_stream_transfer_chunk" (
    "transferId" TEXT NOT NULL,
    "offset" BIGINT NOT NULL,
    "length" INTEGER NOT NULL,
    "digest" TEXT NOT NULL,

    CONSTRAINT "sandbox_stream_transfer_chunk_pkey" PRIMARY KEY ("transferId","offset")
);

-- CreateTable
CREATE TABLE "sandbox_browser_terminal_ticket" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "tokenDigest" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "sandboxHostId" TEXT NOT NULL,
    "hostOwnerId" TEXT NOT NULL,
    "epoch" INTEGER NOT NULL,
    "generation" INTEGER NOT NULL,
    "rows" INTEGER NOT NULL,
    "cols" INTEGER NOT NULL,
    "resumeTerminalId" TEXT,
    "resumeOutputSeq" INTEGER,

    CONSTRAINT "sandbox_browser_terminal_ticket_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_terminal_session" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "generation" INTEGER NOT NULL,
    "hostId" TEXT NOT NULL,
    "openedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "closedAt" TIMESTAMP(3),

    CONSTRAINT "sandbox_terminal_session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_pool" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deletedAt" TIMESTAMP(3),
    "ownHostsOnly" BOOLEAN NOT NULL DEFAULT false,
    "disconnectGraceSeconds" INTEGER NOT NULL DEFAULT 259200,
    "maxLeaseMs" INTEGER,
    "capacityWaitMaxMs" INTEGER,
    "capacityQueuePerKeyMax" INTEGER,
    "capacityQueuePerOwnerMax" INTEGER,
    "unlimitedLeaseForShares" BOOLEAN NOT NULL DEFAULT false,
    "preferOwnHosts" BOOLEAN NOT NULL DEFAULT true,
    "memberImageCacheMaxGiB" INTEGER,

    CONSTRAINT "sandbox_pool_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_pool_member" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "poolId" TEXT NOT NULL,
    "sandboxHostId" TEXT NOT NULL,
    "hostOwnerId" TEXT NOT NULL,
    "shareId" TEXT,
    "contributeWitness" BOOLEAN,
    "ownHostsOnlyWitness" BOOLEAN,
    "memoryCapPercent" INTEGER,
    "vcpuCapPercent" INTEGER,
    "maxLeaseMs" INTEGER,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "removedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_pool_member_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sdk_key_pool_allowlist" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sdkKeyId" TEXT NOT NULL,
    "poolId" TEXT NOT NULL,
    "poolOwnerId" TEXT NOT NULL,
    "shareId" TEXT,
    "useWitness" BOOLEAN,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sdk_key_pool_allowlist_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "share" (
    "id" TEXT NOT NULL,
    "poolId" TEXT NOT NULL,
    "ownerUserId" TEXT NOT NULL,
    "granteeUserId" TEXT NOT NULL,
    "canUse" BOOLEAN NOT NULL DEFAULT true,
    "canContribute" BOOLEAN NOT NULL DEFAULT true,
    "maxMemoryMiB" INTEGER,
    "maxVcpu" INTEGER,
    "maxDiskGiB" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "share_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "share_invite" (
    "id" TEXT NOT NULL,
    "poolId" TEXT NOT NULL,
    "ownerUserId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "tokenDigest" TEXT NOT NULL,
    "pendingKey" TEXT,
    "canUse" BOOLEAN NOT NULL DEFAULT true,
    "canContribute" BOOLEAN NOT NULL DEFAULT true,
    "maxMemoryMiB" INTEGER,
    "maxVcpu" INTEGER,
    "maxDiskGiB" INTEGER,
    "signupAllowed" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "sentAt" TIMESTAMP(3),
    "acceptedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "expiredAt" TIMESTAMP(3),
    "acceptedByUserId" TEXT,
    "acceptedShareId" TEXT,

    CONSTRAINT "share_invite_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "host_terminal_ticket" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "tokenDigest" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "sandboxHostId" TEXT NOT NULL,
    "hostOwnerId" TEXT NOT NULL,
    "epoch" INTEGER NOT NULL,
    "rows" INTEGER NOT NULL,
    "cols" INTEGER NOT NULL,
    "policyRevision" BIGINT NOT NULL,
    "proofRequired" BOOLEAN NOT NULL,
    "verifiedAt" TIMESTAMP(3),
    "factorFingerprint" TEXT,
    "observedAt" TIMESTAMP(3),

    CONSTRAINT "host_terminal_ticket_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_operation_result" (
    "operationId" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "generation" INTEGER NOT NULL,
    "attempt" INTEGER NOT NULL,
    "version" INTEGER NOT NULL,
    "payload" JSONB,
    "continuation" JSONB,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "reservationBytes" INTEGER NOT NULL,
    "reservationState" "OperationResultReservationState" NOT NULL DEFAULT 'RESERVED',

    CONSTRAINT "sandbox_operation_result_pkey" PRIMARY KEY ("operationId")
);

-- CreateTable
CREATE TABLE "sandbox_host_storage_pool" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sandboxHostId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "marker" TEXT NOT NULL,
    "capacityGiB" INTEGER NOT NULL,
    "totalBasedCapacityGiB" INTEGER,
    "derivationTotalBytes" BIGINT,
    "derivationFreeBytes" BIGINT,
    "derivationCommittedBytes" BIGINT,
    "derivationActualBytes" BIGINT,
    "derivationHeadroomBytes" BIGINT,
    "implicitCeilingGiB" INTEGER,
    "capacitySource" TEXT NOT NULL,
    "newRootsAllowed" BOOLEAN NOT NULL DEFAULT false,
    "configured" BOOLEAN NOT NULL DEFAULT false,
    "draining" BOOLEAN NOT NULL DEFAULT false,
    "health" TEXT NOT NULL,
    "healthReason" TEXT,
    "connectionEpoch" INTEGER NOT NULL,
    "observationSequence" BIGINT NOT NULL,
    "reportedAt" TIMESTAMP(3) NOT NULL,
    "diskReservedGiB" INTEGER NOT NULL DEFAULT 0,
    "totalBytes" BIGINT,
    "usedBytes" BIGINT,
    "freeBytes" BIGINT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_host_storage_pool_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_image_artifact" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "architecture" TEXT NOT NULL,
    "format" TEXT NOT NULL DEFAULT 'unified',
    "sizeBytes" BIGINT NOT NULL,
    "unpackedBytes" BIGINT,
    "storeKind" "ImageStoreKind" NOT NULL,
    "state" "ImageArtifactState" NOT NULL,
    "objectKey" TEXT,
    "partSize" INTEGER,
    "encryption" TEXT,
    "wrappedKey" BYTEA,
    "wrappedKeyNonce" BYTEA,
    "keyId" TEXT,
    "uploadedByHostId" TEXT,
    "storedAt" TIMESTAMP(3),
    "verifiedAt" TIMESTAMP(3),
    "unreferencedSince" TIMESTAMP(3),
    "deleteAfter" TIMESTAMP(3),
    "lastFetchedAt" TIMESTAMP(3),
    "lastProgressAt" TIMESTAMP(3),
    "corruptReports" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_image_artifact_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_image_upload_session" (
    "id" TEXT NOT NULL,
    "transferId" TEXT NOT NULL,
    "artifactId" TEXT,
    "liveArtifactId" TEXT,
    "diskOffloadId" TEXT,
    "liveDiskOffloadId" TEXT,
    "userId" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "hostEpoch" INTEGER NOT NULL,
    "dispatchAttempt" INTEGER,
    "requestId" TEXT,
    "state" "ImageUploadSessionState" NOT NULL DEFAULT 'OPEN',
    "objectKey" TEXT NOT NULL,
    "uploadId" TEXT,
    "sizeBytes" BIGINT NOT NULL,
    "storedBytes" BIGINT NOT NULL,
    "partSize" INTEGER NOT NULL,
    "encryption" TEXT,
    "wrappedKey" BYTEA,
    "wrappedKeyNonce" BYTEA,
    "keyId" TEXT,
    "wrapSalt" BYTEA,
    "endReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_image_upload_session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_image_upload_part" (
    "sessionId" TEXT NOT NULL,
    "partNumber" INTEGER NOT NULL,
    "etag" TEXT NOT NULL,
    "sizeBytes" INTEGER NOT NULL,

    CONSTRAINT "sandbox_image_upload_part_pkey" PRIMARY KEY ("sessionId","partNumber")
);

-- CreateTable
CREATE TABLE "sandbox_host_image_cache" (
    "id" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "hostOwnerId" TEXT NOT NULL,
    "imageOwnerId" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "compressedBytes" BIGINT NOT NULL,
    "unpackedBytes" BIGINT,
    "origin" TEXT NOT NULL,
    "pinned" BOOLEAN NOT NULL DEFAULT false,
    "connectionEpoch" INTEGER NOT NULL,
    "reportedAt" TIMESTAMP(3) NOT NULL,
    "accessLostAt" TIMESTAMP(3),
    "releaseSentAt" TIMESTAMP(3),

    CONSTRAINT "sandbox_host_image_cache_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_image_transfer" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "artifactId" TEXT,
    "purpose" "ImageTransferPurpose" NOT NULL,
    "mode" TEXT NOT NULL,
    "sourceHostId" TEXT,
    "sourceHostOwnerId" TEXT,
    "destHostId" TEXT,
    "destHostOwnerId" TEXT,
    "operationId" TEXT,
    "state" "ImageTransferState" NOT NULL DEFAULT 'OPEN',
    "sizeBytes" BIGINT NOT NULL,
    "partSize" INTEGER NOT NULL,
    "partCount" INTEGER NOT NULL,
    "bytesDone" BIGINT NOT NULL DEFAULT 0,
    "sourceEpoch" INTEGER,
    "destEpoch" INTEGER,
    "dispatchAttempt" INTEGER,
    "countedDownload" BOOLEAN NOT NULL DEFAULT false,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "lastProgressAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "diskOffloadId" TEXT,

    CONSTRAINT "sandbox_image_transfer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_image_link" (
    "id" TEXT NOT NULL,
    "transferId" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "hostEpoch" INTEGER NOT NULL,
    "role" TEXT NOT NULL,
    "partNumber" INTEGER NOT NULL,
    "tokenDigest" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sandbox_image_link_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_template_capture" (
    "operationId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "templateId" TEXT NOT NULL,
    "tag" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "hostOwnerId" TEXT NOT NULL,
    "scrubPaths" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "state" "TemplateCaptureState" NOT NULL DEFAULT 'PENDING',
    "stoppedCapture" BOOLEAN NOT NULL DEFAULT false,
    "fingerprint" TEXT,
    "sizeBytes" BIGINT,
    "unpackedBytes" BIGINT,
    "architecture" TEXT,
    "resultEpoch" INTEGER,
    "revisionId" TEXT,
    "resourcesHeld" BOOLEAN NOT NULL DEFAULT false,
    "chargedMemoryMiB" INTEGER NOT NULL DEFAULT 0,
    "chargedVcpu" INTEGER NOT NULL DEFAULT 0,
    "diskChargeGiB" INTEGER NOT NULL DEFAULT 0,
    "defaultDiskGiB" INTEGER,
    "storagePoolId" TEXT,
    "errorCode" TEXT,
    "symlinkedPaths" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "buildId" TEXT,
    "buildAttempt" INTEGER NOT NULL DEFAULT 0,
    "buildCancelledAt" TIMESTAMP(3),
    "finalizedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_template_capture_pkey" PRIMARY KEY ("operationId")
);

-- CreateTable
CREATE TABLE "sandbox_capacity_wait" (
    "id" TEXT NOT NULL,
    "seq" BIGSERIAL NOT NULL,
    "userId" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "operationId" TEXT NOT NULL,
    "poolId" TEXT NOT NULL,
    "poolOwnerId" TEXT NOT NULL,
    "authorizingKeyId" TEXT,
    "templateRevisionId" TEXT NOT NULL,
    "cpuCount" INTEGER NOT NULL,
    "memoryMiB" INTEGER NOT NULL,
    "diskGiB" INTEGER NOT NULL,
    "chargedMemoryMiB" INTEGER NOT NULL,
    "rootChargeGiB" INTEGER NOT NULL,
    "leaseTimeoutMs" INTEGER NOT NULL,
    "leaseExpireAction" "SandboxLeaseExpireAction" NOT NULL,
    "intent" JSONB,
    "state" "CapacityWaitState" NOT NULL DEFAULT 'WAITING',
    "enqueuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deadlineAt" TIMESTAMP(3),
    "bypassCount" INTEGER NOT NULL DEFAULT 0,
    "lastBlocker" TEXT,
    "lastEvaluatedAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "endReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_capacity_wait_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_disk_offload" (
    "id" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "seq" INTEGER NOT NULL,
    "sourceGeneration" INTEGER NOT NULL,
    "sourceHostId" TEXT NOT NULL,
    "sourceHostOwnerId" TEXT NOT NULL,
    "state" "SandboxDiskOffloadState" NOT NULL DEFAULT 'PENDING',
    "liveSandboxId" TEXT,
    "fingerprint" TEXT,
    "sizeBytes" BIGINT,
    "storedBytes" BIGINT,
    "objectKey" TEXT,
    "partSize" INTEGER,
    "encryption" TEXT,
    "wrappedKey" BYTEA,
    "wrapSalt" BYTEA,
    "wrapNonce" BYTEA,
    "rootKid" TEXT,
    "completedSessionId" TEXT,
    "verifiedAt" TIMESTAMP(3),
    "storedAt" TIMESTAMP(3),
    "sourceReleasedAt" TIMESTAMP(3),
    "evictGrantId" TEXT,
    "evictHostId" TEXT,
    "evictGrantEpoch" INTEGER,
    "evictGrantedAt" TIMESTAMP(3),
    "evictGrantExpiresAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),
    "deleteAfter" TIMESTAMP(3),
    "destroyOperationId" TEXT,
    "shredAfter" TIMESTAMP(3),
    "shreddedAt" TIMESTAMP(3),
    "failureCode" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_disk_offload_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_disk_copy" (
    "id" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "hostOwnerId" TEXT NOT NULL,
    "usagePoolId" TEXT,
    "usageMemberId" TEXT,
    "storagePoolId" TEXT NOT NULL,
    "storageMarker" TEXT NOT NULL,
    "storagePoolName" TEXT NOT NULL,
    "rootChargeGiB" INTEGER NOT NULL,
    "offloadSeq" INTEGER NOT NULL,
    "createKey" TEXT NOT NULL,
    "baseFingerprint" TEXT NOT NULL,
    "state" "SandboxDiskCopyState" NOT NULL DEFAULT 'STALE',
    "diskReservationHeld" BOOLEAN NOT NULL DEFAULT true,
    "discardSentAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sandbox_disk_copy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_restore_wait" (
    "operationId" TEXT NOT NULL,
    "sandboxId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "authorizingKeyId" TEXT,
    "expectedGeneration" INTEGER NOT NULL,
    "intent" JSONB,
    "state" "CapacityWaitState" NOT NULL DEFAULT 'WAITING',
    "enqueuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deadlineAt" TIMESTAMP(3) NOT NULL,
    "lastAttemptAt" TIMESTAMP(3),
    "endedAt" TIMESTAMP(3),
    "endReason" TEXT,
    "lastLoginRefusal" TEXT,

    CONSTRAINT "sandbox_restore_wait_pkey" PRIMARY KEY ("operationId")
);

-- CreateTable
CREATE TABLE "tunnel_server_config" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "apiUrl" TEXT NOT NULL,
    "credentialCiphertext" BYTEA NOT NULL,
    "credentialNonce" BYTEA NOT NULL,
    "credentialKeyId" TEXT NOT NULL,
    "credentialSha256" TEXT NOT NULL,
    "serverKey" TEXT NOT NULL,
    "maxTunnelsPerOwner" INTEGER NOT NULL DEFAULT 10,
    "disabledAt" TIMESTAMP(3),
    "updatedById" TEXT,

    CONSTRAINT "tunnel_server_config_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sandbox_tunnel" (
    "sandboxId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ports" INTEGER[],
    "state" "SandboxTunnelState" NOT NULL DEFAULT 'PENDING',
    "lastError" TEXT,
    "tunTunnelId" TEXT,
    "hostTemplate" TEXT,
    "hostId" TEXT,
    "generation" INTEGER NOT NULL DEFAULT 0,
    "appliedAt" TIMESTAMP(3),
    "connectedAt" TIMESTAMP(3),
    "closedAt" TIMESTAMP(3),
    "sweepLabel" BOOLEAN NOT NULL DEFAULT false,
    "creatingUntil" TIMESTAMP(3),
    "serverKey" TEXT,

    CONSTRAINT "sandbox_tunnel_pkey" PRIMARY KEY ("sandboxId")
);

-- CreateTable
CREATE TABLE "sandbox_tunnel_event" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "kind" TEXT NOT NULL,
    "userId" TEXT,
    "sandboxId" TEXT,
    "actorId" TEXT,
    "actorKeyId" TEXT,
    "port" INTEGER,
    "detail" TEXT,

    CONSTRAINT "sandbox_tunnel_event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_endpoint" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "createdByKeyId" TEXT,
    "url" TEXT NOT NULL,
    "description" TEXT,
    "events" TEXT[],
    "operationKinds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "payloadVersion" INTEGER NOT NULL DEFAULT 1,
    "secretCiphertext" BYTEA NOT NULL,
    "secretNonce" BYTEA NOT NULL,
    "secretKeyId" TEXT NOT NULL,
    "secretVersion" INTEGER NOT NULL DEFAULT 1,
    "previousSecretCiphertext" BYTEA,
    "previousSecretNonce" BYTEA,
    "previousSecretKeyId" TEXT,
    "previousSecretVersion" INTEGER,
    "previousSecretExpiresAt" TIMESTAMP(3),
    "disabledAt" TIMESTAMP(3),
    "disabledReason" TEXT,
    "disabledNotifiedAt" TIMESTAMP(3),
    "consecutiveFailures" INTEGER NOT NULL DEFAULT 0,
    "failingSince" TIMESTAMP(3),
    "lastSuccessAt" TIMESTAMP(3),
    "lastFailureAt" TIMESTAMP(3),
    "lastFailureClass" TEXT,

    CONSTRAINT "webhook_endpoint_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_event" (
    "id" TEXT NOT NULL,
    "seq" BIGSERIAL NOT NULL,
    "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "sandboxId" TEXT,
    "operationId" TEXT,
    "facts" JSONB NOT NULL,
    "body" TEXT,
    "fannedOutAt" TIMESTAMP(3),

    CONSTRAINT "webhook_event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_delivery" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "eventId" TEXT NOT NULL,
    "endpointId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "state" "WebhookDeliveryState" NOT NULL DEFAULT 'PENDING',
    "attemptCount" INTEGER NOT NULL DEFAULT 0,
    "maxAttempts" INTEGER NOT NULL,
    "nextAttemptAt" TIMESTAMP(3),
    "leaseUntil" TIMESTAMP(3),
    "enqueuedAt" TIMESTAMP(3),
    "enqueueSeq" INTEGER NOT NULL DEFAULT 0,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "lastStatusCode" INTEGER,
    "lastErrorClass" TEXT,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "webhook_delivery_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_delivery_attempt" (
    "id" TEXT NOT NULL,
    "deliveryId" TEXT NOT NULL,
    "attempt" INTEGER NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL,
    "durationMs" INTEGER NOT NULL,
    "resolvedAddress" TEXT,
    "statusCode" INTEGER,
    "errorClass" TEXT,
    "responseExcerpt" TEXT,

    CONSTRAINT "webhook_delivery_attempt_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "mcp_grant_sdkKeyId_key" ON "mcp_grant"("sdkKeyId");

-- CreateIndex
CREATE UNIQUE INDEX "mcp_grant_sdkKeyId_userId_key" ON "mcp_grant"("sdkKeyId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "mcp_grant_userId_clientId_referenceId_key" ON "mcp_grant"("userId", "clientId", "referenceId");

-- CreateIndex
CREATE INDEX "host_queued_command_userId_state_createdAt_idx" ON "host_queued_command"("userId", "state", "createdAt");

-- CreateIndex
CREATE INDEX "host_queued_command_sandboxHostId_state_idx" ON "host_queued_command"("sandboxHostId", "state");

-- CreateIndex
CREATE INDEX "host_file_receipt_expiresAt_idx" ON "host_file_receipt"("expiresAt");

-- CreateIndex
CREATE INDEX "host_file_receipt_sandboxHostId_idx" ON "host_file_receipt"("sandboxHostId");

-- CreateIndex
CREATE INDEX "host_file_receipt_userId_idx" ON "host_file_receipt"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "host_file_receipt_sdkKeyId_idempotencyKey_key" ON "host_file_receipt"("sdkKeyId", "idempotencyKey");

-- CreateIndex
CREATE UNIQUE INDEX "host_audit_event_commandId_key" ON "host_audit_event"("commandId");

-- CreateIndex
CREATE INDEX "host_audit_event_userId_createdAt_idx" ON "host_audit_event"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "host_audit_event_sandboxHostId_createdAt_idx" ON "host_audit_event"("sandboxHostId", "createdAt");

-- CreateIndex
CREATE INDEX "user_role_idx" ON "user"("role");

-- CreateIndex
CREATE INDEX "user_email_idx" ON "user" USING GIN ("email" gin_trgm_ops);

-- CreateIndex
CREATE INDEX "user_name_idx" ON "user" USING GIN ("name" gin_trgm_ops);

-- CreateIndex
CREATE UNIQUE INDEX "user_email_key" ON "user"("email");

-- CreateIndex
CREATE INDEX "session_userId_idx" ON "session"("userId");

-- CreateIndex
CREATE INDEX "session_expiresAt_idx" ON "session"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "session_token_key" ON "session"("token");

-- CreateIndex
CREATE UNIQUE INDEX "session_id_userId_key" ON "session"("id", "userId");

-- CreateIndex
CREATE INDEX "account_userId_idx" ON "account"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "account_issuer_accountId_key" ON "account"("issuer", "accountId");

-- CreateIndex
CREATE INDEX "verification_identifier_idx" ON "verification"("identifier");

-- CreateIndex
CREATE INDEX "verification_expiresAt_idx" ON "verification"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "two_factor_userId_key" ON "two_factor"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "device_code_deviceCode_key" ON "device_code"("deviceCode");

-- CreateIndex
CREATE UNIQUE INDEX "device_code_userCode_key" ON "device_code"("userCode");

-- CreateIndex
CREATE INDEX "device_code_userId_idx" ON "device_code"("userId");

-- CreateIndex
CREATE INDEX "device_code_expiresAt_idx" ON "device_code"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "push_subscription_endpoint_key" ON "push_subscription"("endpoint");

-- CreateIndex
CREATE INDEX "push_subscription_userId_idx" ON "push_subscription"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "oauth_client_clientId_key" ON "oauth_client"("clientId");

-- CreateIndex
CREATE INDEX "oauth_client_userId_idx" ON "oauth_client"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "oauth_resource_identifier_key" ON "oauth_resource"("identifier");

-- CreateIndex
CREATE INDEX "oauth_client_resource_clientId_idx" ON "oauth_client_resource"("clientId");

-- CreateIndex
CREATE INDEX "oauth_client_resource_resourceId_idx" ON "oauth_client_resource"("resourceId");

-- CreateIndex
CREATE UNIQUE INDEX "oauth_client_resource_clientId_resourceId_key" ON "oauth_client_resource"("clientId", "resourceId");

-- CreateIndex
CREATE UNIQUE INDEX "oauth_refresh_token_token_key" ON "oauth_refresh_token"("token");

-- CreateIndex
CREATE INDEX "oauth_refresh_token_clientId_idx" ON "oauth_refresh_token"("clientId");

-- CreateIndex
CREATE INDEX "oauth_refresh_token_sessionId_idx" ON "oauth_refresh_token"("sessionId");

-- CreateIndex
CREATE INDEX "oauth_refresh_token_userId_idx" ON "oauth_refresh_token"("userId");

-- CreateIndex
CREATE INDEX "oauth_refresh_token_authorizationCodeId_idx" ON "oauth_refresh_token"("authorizationCodeId");

-- CreateIndex
CREATE UNIQUE INDEX "oauth_access_token_token_key" ON "oauth_access_token"("token");

-- CreateIndex
CREATE INDEX "oauth_access_token_clientId_idx" ON "oauth_access_token"("clientId");

-- CreateIndex
CREATE INDEX "oauth_access_token_sessionId_idx" ON "oauth_access_token"("sessionId");

-- CreateIndex
CREATE INDEX "oauth_access_token_userId_idx" ON "oauth_access_token"("userId");

-- CreateIndex
CREATE INDEX "oauth_access_token_authorizationCodeId_idx" ON "oauth_access_token"("authorizationCodeId");

-- CreateIndex
CREATE INDEX "oauth_access_token_refreshId_idx" ON "oauth_access_token"("refreshId");

-- CreateIndex
CREATE INDEX "oauth_consent_clientId_idx" ON "oauth_consent"("clientId");

-- CreateIndex
CREATE INDEX "oauth_consent_userId_idx" ON "oauth_consent"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_build_buildSandboxId_key" ON "sandbox_template_build"("buildSandboxId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_build_captureOperationId_key" ON "sandbox_template_build"("captureOperationId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_build_verifySandboxId_key" ON "sandbox_template_build"("verifySandboxId");

-- CreateIndex
CREATE INDEX "sandbox_template_build_userId_state_idx" ON "sandbox_template_build"("userId", "state");

-- CreateIndex
CREATE INDEX "sandbox_template_build_state_nextAttemptAt_idx" ON "sandbox_template_build"("state", "nextAttemptAt");

-- CreateIndex
CREATE INDEX "sandbox_template_build_templateId_createdAt_idx" ON "sandbox_template_build"("templateId", "createdAt");

-- CreateIndex
CREATE INDEX "sandbox_template_build_userId_chargeMonth_idx" ON "sandbox_template_build"("userId", "chargeMonth");

-- CreateIndex
CREATE INDEX "sandbox_template_build_hostOwnerId_state_idx" ON "sandbox_template_build"("hostOwnerId", "state");

-- CreateIndex
CREATE INDEX "sandbox_template_build_cleanup_pending_idx" ON "sandbox_template_build"("id") WHERE ("cleanupState" = 'PENDING'::"TemplateBuildCleanupState");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_build_id_userId_key" ON "sandbox_template_build"("id", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_build_userId_idempotencyKey_key" ON "sandbox_template_build"("userId", "idempotencyKey");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_build_active_dedupe" ON "sandbox_template_build"("userId", "templateId", "tag", "buildDigest", "targetKey", "principalKey") WHERE ((state = ANY (ARRAY['AWAITING_CONTEXT'::"TemplateBuildState", 'QUEUED'::"TemplateBuildState", 'PLACING'::"TemplateBuildState", 'RUNNING'::"TemplateBuildState", 'STOPPING'::"TemplateBuildState", 'CAPTURING'::"TemplateBuildState"])) AND (NOT "noCache"));

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_build_context_buildId_key" ON "sandbox_build_context"("buildId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_build_context_transferId_key" ON "sandbox_build_context"("transferId");

-- CreateIndex
CREATE INDEX "sandbox_build_context_state_idleExpiresAt_idx" ON "sandbox_build_context"("state", "idleExpiresAt");

-- CreateIndex
CREATE INDEX "sandbox_build_context_state_expiresAt_idx" ON "sandbox_build_context"("state", "expiresAt");

-- CreateIndex
CREATE INDEX "sandbox_build_context_userId_state_idx" ON "sandbox_build_context"("userId", "state");

-- CreateIndex
CREATE INDEX "sandbox_build_context_reservationHeld_id_idx" ON "sandbox_build_context"("reservationHeld", "id");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_build_context_buildId_userId_key" ON "sandbox_build_context"("buildId", "userId");

-- CreateIndex
CREATE INDEX "credential_definition_userId_slug_createdAt_idx" ON "credential_definition"("userId", "slug", "createdAt");

-- CreateIndex
CREATE INDEX "credential_definition_userId_createdAt_idx" ON "credential_definition"("userId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "credential_definition_userId_slug_version_key" ON "credential_definition"("userId", "slug", "version");

-- CreateIndex
CREATE UNIQUE INDEX "credential_definition_id_userId_key" ON "credential_definition"("id", "userId");

-- CreateIndex
CREATE INDEX "credential_userId_createdAt_idx" ON "credential"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "credential_definitionId_idx" ON "credential"("definitionId");

-- CreateIndex
CREATE UNIQUE INDEX "credential_userId_name_key" ON "credential"("userId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "credential_id_userId_key" ON "credential"("id", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "credential_account_credentialId_ordinal_key" ON "credential_account"("credentialId", "ordinal");

-- CreateIndex
CREATE UNIQUE INDEX "credential_account_credentialId_name_key" ON "credential_account"("credentialId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "credential_account_id_credentialId_userId_key" ON "credential_account"("id", "credentialId", "userId");

-- CreateIndex
CREATE INDEX "credential_instance_pick_any" ON "credential_instance"("credentialId", "accountOrdinal", "ordinal") WHERE (state = 'READY' AND NOT "accountPaused" AND "loginLeaseId" IS NULL AND (capacity IS NULL OR "activeLeases" < capacity));

-- CreateIndex
CREATE INDEX "credential_instance_pick_account" ON "credential_instance"("accountId", "ordinal") WHERE (state = 'READY' AND "loginLeaseId" IS NULL AND (capacity IS NULL OR "activeLeases" < capacity));

-- CreateIndex
CREATE INDEX "credential_instance_credentialId_accountId_ordinal_idx" ON "credential_instance"("credentialId", "accountId", "ordinal");

-- CreateIndex
CREATE UNIQUE INDEX "credential_instance_accountId_ordinal_key" ON "credential_instance"("accountId", "ordinal");

-- CreateIndex
CREATE UNIQUE INDEX "credential_instance_accountId_name_key" ON "credential_instance"("accountId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "credential_instance_id_credentialId_userId_key" ON "credential_instance"("id", "credentialId", "userId");

-- CreateIndex
CREATE INDEX "credential_secret_version_rootKid_idx" ON "credential_secret_version"("rootKid");

-- CreateIndex
CREATE INDEX "credential_lease_sandboxId_state_idx" ON "credential_lease"("sandboxId", "state");

-- CreateIndex
CREATE INDEX "credential_lease_instanceId_state_idx" ON "credential_lease"("instanceId", "state");

-- CreateIndex
CREATE INDEX "credential_lease_credentialId_state_idx" ON "credential_lease"("credentialId", "state");

-- CreateIndex
CREATE INDEX "credential_lease_userId_createdAt_idx" ON "credential_lease"("userId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "credential_lease_exclusive_live" ON "credential_lease"("instanceId") WHERE (exclusive AND (state = ANY (ARRAY['RESERVED'::"CredentialLeaseState", 'INSTALLING'::"CredentialLeaseState", 'ACTIVE'::"CredentialLeaseState", 'RELEASING'::"CredentialLeaseState", 'RECOVERY_REQUIRED'::"CredentialLeaseState", 'RECOVERING'::"CredentialLeaseState"])));

-- CreateIndex
CREATE INDEX "credential_binding_leaseId_idx" ON "credential_binding"("leaseId");

-- CreateIndex
CREATE UNIQUE INDEX "credential_binding_leaseId_requestId_key" ON "credential_binding"("leaseId", "requestId");

-- CreateIndex
CREATE UNIQUE INDEX "credential_residue_bindingId_key" ON "credential_residue"("bindingId");

-- CreateIndex
CREATE INDEX "credential_residue_uncleared" ON "credential_residue"("sandboxId") WHERE ("clearedAt" IS NULL);

-- CreateIndex
CREATE UNIQUE INDEX "credential_capture_leaseId_captureSeq_key" ON "credential_capture"("leaseId", "captureSeq");

-- CreateIndex
CREATE INDEX "credential_pending_capture_leaseId_idx" ON "credential_pending_capture"("leaseId");

-- CreateIndex
CREATE UNIQUE INDEX "credential_return_key_epoch_key" ON "credential_return_key"("epoch");

-- CreateIndex
CREATE INDEX "credential_return_key_rootKid_idx" ON "credential_return_key"("rootKid");

-- CreateIndex
CREATE UNIQUE INDEX "credential_return_key_current" ON "credential_return_key"("retiredAt") WHERE ("retiredAt" IS NULL);

-- CreateIndex
CREATE INDEX "credential_host_return_key_kidR_idx" ON "credential_host_return_key"("kidR");

-- CreateIndex
CREATE INDEX "credential_capture_rejection_live" ON "credential_capture_rejection"("leaseId") WHERE ("discardedAt" IS NULL);

-- CreateIndex
CREATE INDEX "sandbox_credential_credentialId_detachedAt_idx" ON "sandbox_credential"("credentialId", "detachedAt");

-- CreateIndex
CREATE INDEX "sandbox_credential_sandboxId_attachedAt_idx" ON "sandbox_credential"("sandboxId", "attachedAt");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_credential_active" ON "sandbox_credential"("sandboxId", "credentialId") WHERE ("detachedAt" IS NULL);

-- CreateIndex
CREATE INDEX "credential_login_session_userId_state_idx" ON "credential_login_session"("userId", "state");

-- CreateIndex
CREATE INDEX "credential_event_userId_credentialId_at_idx" ON "credential_event"("userId", "credentialId", "at");

-- CreateIndex
CREATE INDEX "sdk_key_credential_allowlist_credentialId_userId_idx" ON "sdk_key_credential_allowlist"("credentialId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sdk_key_credential_allowlist_sdkKeyId_credentialId_key" ON "sdk_key_credential_allowlist"("sdkKeyId", "credentialId");

-- CreateIndex
CREATE INDEX "sandbox_host_userId_status_idx" ON "sandbox_host"("userId", "status");

-- CreateIndex
CREATE INDEX "sandbox_host_lastHeartbeatAt_idx" ON "sandbox_host"("lastHeartbeatAt");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_host_userId_slug_key" ON "sandbox_host"("userId", "slug");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_host_id_userId_key" ON "sandbox_host"("id", "userId");

-- CreateIndex
CREATE INDEX "host_token_userId_revokedAt_idx" ON "host_token"("userId", "revokedAt");

-- CreateIndex
CREATE INDEX "host_token_sandboxHostId_idx" ON "host_token"("sandboxHostId");

-- CreateIndex
CREATE INDEX "host_token_expiresAt_idx" ON "host_token"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "host_token_lookupPrefix_key" ON "host_token"("lookupPrefix");

-- CreateIndex
CREATE UNIQUE INDEX "host_token_secretDigest_key" ON "host_token"("secretDigest");

-- CreateIndex
CREATE INDEX "host_device_credential_userId_revokedAt_idx" ON "host_device_credential"("userId", "revokedAt");

-- CreateIndex
CREATE INDEX "host_device_credential_sandboxHostId_idx" ON "host_device_credential"("sandboxHostId");

-- CreateIndex
CREATE UNIQUE INDEX "host_device_credential_lookupPrefix_key" ON "host_device_credential"("lookupPrefix");

-- CreateIndex
CREATE UNIQUE INDEX "host_device_credential_secretDigest_key" ON "host_device_credential"("secretDigest");

-- CreateIndex
CREATE INDEX "sdk_key_userId_kind_revokedAt_idx" ON "sdk_key"("userId", "kind", "revokedAt");

-- CreateIndex
CREATE INDEX "sdk_key_userId_revokedAt_idx" ON "sdk_key"("userId", "revokedAt");

-- CreateIndex
CREATE INDEX "sdk_key_expiresAt_idx" ON "sdk_key"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "sdk_key_lookupPrefix_key" ON "sdk_key"("lookupPrefix");

-- CreateIndex
CREATE UNIQUE INDEX "sdk_key_secretDigest_key" ON "sdk_key"("secretDigest");

-- CreateIndex
CREATE UNIQUE INDEX "sdk_key_id_userId_key" ON "sdk_key"("id", "userId");

-- CreateIndex
CREATE INDEX "sdk_key_host_allowlist_sandboxHostId_idx" ON "sdk_key_host_allowlist"("sandboxHostId");

-- CreateIndex
CREATE UNIQUE INDEX "sdk_key_host_allowlist_sdkKeyId_sandboxHostId_key" ON "sdk_key_host_allowlist"("sdkKeyId", "sandboxHostId");

-- CreateIndex
CREATE INDEX "sdk_key_revision_allowlist_templateRevisionId_userId_idx" ON "sdk_key_revision_allowlist"("templateRevisionId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sdk_key_revision_allowlist_sdkKeyId_templateRevisionId_key" ON "sdk_key_revision_allowlist"("sdkKeyId", "templateRevisionId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_logical_template_userId_slug_key" ON "sandbox_logical_template"("userId", "slug");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_logical_template_id_userId_key" ON "sandbox_logical_template"("id", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_logical_template_userId_communitySource_key" ON "sandbox_logical_template"("userId", "communitySource");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_revision_buildId_key" ON "sandbox_template_revision"("buildId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_revision_pendingVerifyBuildId_key" ON "sandbox_template_revision"("pendingVerifyBuildId");

-- CreateIndex
CREATE INDEX "sandbox_template_revision_templateId_captureTag_revision_idx" ON "sandbox_template_revision"("templateId", "captureTag", "revision");

-- CreateIndex
CREATE INDEX "sandbox_template_revision_parentRevisionId_userId_idx" ON "sandbox_template_revision"("parentRevisionId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_revision_id_userId_key" ON "sandbox_template_revision"("id", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_revision_id_templateId_userId_key" ON "sandbox_template_revision"("id", "templateId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_revision_templateId_revision_key" ON "sandbox_template_revision"("templateId", "revision");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_upstream_image_revisionId_key" ON "sandbox_upstream_image"("revisionId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_upstream_image_templateId_fingerprint_key" ON "sandbox_upstream_image"("templateId", "fingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_upstream_image_revisionId_templateId_userId_key" ON "sandbox_upstream_image"("revisionId", "templateId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_tag_templateId_tag_key" ON "sandbox_template_tag"("templateId", "tag");

-- CreateIndex
CREATE INDEX "sandbox_template_availability_hostId_revisionId_idx" ON "sandbox_template_availability"("hostId", "revisionId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_availability_revisionId_hostId_key" ON "sandbox_template_availability"("revisionId", "hostId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_revision_config_revisionId_key" ON "sandbox_revision_config"("revisionId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_revision_config_revisionId_userId_key" ON "sandbox_revision_config"("revisionId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_placement_operationId_key" ON "sandbox_placement"("operationId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_placement_sandboxId_generation_key" ON "sandbox_placement"("sandboxId", "generation");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_placement_id_sandboxId_userId_key" ON "sandbox_placement"("id", "sandboxId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_placement_operationId_sandboxId_userId_key" ON "sandbox_placement"("operationId", "sandboxId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_instance_currentPlacementId_key" ON "sandbox_instance"("currentPlacementId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_instance_buildId_key" ON "sandbox_instance"("buildId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_instance_verifyBuildId_key" ON "sandbox_instance"("verifyBuildId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_instance_diskOffloadId_key" ON "sandbox_instance"("diskOffloadId");

-- CreateIndex
CREATE INDEX "sandbox_instance_userId_state_createdAt_id_idx" ON "sandbox_instance"("userId", "state", "createdAt", "id");

-- CreateIndex
CREATE INDEX "sandbox_instance_sandboxHostId_state_idx" ON "sandbox_instance"("sandboxHostId", "state");

-- CreateIndex
CREATE INDEX "sandbox_instance_usagePoolId_idx" ON "sandbox_instance"("usagePoolId");

-- CreateIndex
CREATE INDEX "sandbox_instance_accessGraceUntil_idx" ON "sandbox_instance"("accessGraceUntil");

-- CreateIndex
CREATE INDEX "sandbox_instance_leaseExpiresAt_idx" ON "sandbox_instance"("leaseExpiresAt");

-- CreateIndex
CREATE INDEX "sandbox_instance_build_cleanup_idx" ON "sandbox_instance"("state") WHERE ("buildId" IS NOT NULL);

-- CreateIndex
CREATE INDEX "sandbox_instance_verify_cleanup_idx" ON "sandbox_instance"("state") WHERE ("verifyBuildId" IS NOT NULL);

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_instance_id_userId_key" ON "sandbox_instance"("id", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_instance_currentPlacementId_id_userId_key" ON "sandbox_instance"("currentPlacementId", "id", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_instance_owner_live_name" ON "sandbox_instance"("userId", "name") WHERE ((state <> 'DELETED'::"SandboxState") AND (purpose = 'WORKLOAD'::"SandboxPurpose"));

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_instance_diskOffloadId_id_userId_key" ON "sandbox_instance"("diskOffloadId", "id", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_execution_config_sandboxId_key" ON "sandbox_execution_config"("sandboxId");

-- CreateIndex
CREATE INDEX "sandbox_execution_config_userId_idx" ON "sandbox_execution_config"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_execution_config_id_sandboxId_userId_key" ON "sandbox_execution_config"("id", "sandboxId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_execution_config_sandboxId_userId_key" ON "sandbox_execution_config"("sandboxId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_mutation_operation_processId_key" ON "sandbox_mutation_operation"("processId");

-- CreateIndex
CREATE INDEX "sandbox_mutation_operation_userId_processDescriptionExpires_idx" ON "sandbox_mutation_operation"("userId", "processDescriptionExpiresAt");

-- CreateIndex
CREATE INDEX "sandbox_mutation_operation_processDescriptionExpiresAt_user_idx" ON "sandbox_mutation_operation"("processDescriptionExpiresAt", "userId");

-- CreateIndex
CREATE INDEX "sandbox_mutation_operation_sandboxId_state_idx" ON "sandbox_mutation_operation"("sandboxId", "state");

-- CreateIndex
CREATE INDEX "sandbox_mutation_operation_userId_kind_state_idx" ON "sandbox_mutation_operation"("userId", "kind", "state");

-- CreateIndex
CREATE INDEX "sandbox_mutation_operation_dispatchedHostId_state_idx" ON "sandbox_mutation_operation"("dispatchedHostId", "state");

-- CreateIndex
CREATE INDEX "sandbox_mutation_operation_userId_createdAt_idx" ON "sandbox_mutation_operation"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "sandbox_mutation_operation_sandboxId_createdAt_idx" ON "sandbox_mutation_operation"("sandboxId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_mutation_operation_userId_idempotencyKey_key" ON "sandbox_mutation_operation"("userId", "idempotencyKey");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_mutation_operation_id_sandboxId_userId_key" ON "sandbox_mutation_operation"("id", "sandboxId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_mutation_operation_id_userId_key" ON "sandbox_mutation_operation"("id", "userId");

-- CreateIndex
CREATE INDEX "sandbox_command_stream_segment_outputId_tail_startOffset_idx" ON "sandbox_command_stream_segment"("outputId", "tail", "startOffset");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_command_stream_segment_outputId_startOffset_key" ON "sandbox_command_stream_segment"("outputId", "startOffset");

-- CreateIndex
CREATE INDEX "sandbox_dispatch_outbox_aggregateType_processedAt_sentAt_id_idx" ON "sandbox_dispatch_outbox"("aggregateType", "processedAt", "sentAt", "id");

-- CreateIndex
CREATE INDEX "sandbox_dispatch_outbox_operation_idx" ON "sandbox_dispatch_outbox"("userId", "aggregateType", "aggregateId", "operationId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_mutation_receipt_userId_idempotencyKey_key" ON "sandbox_mutation_receipt"("userId", "idempotencyKey");

-- CreateIndex
CREATE INDEX "sandbox_stream_transfer_reservationHeld_id_idx" ON "sandbox_stream_transfer"("reservationHeld", "id");

-- CreateIndex
CREATE INDEX "sandbox_stream_transfer_sandboxId_reservationHeld_idx" ON "sandbox_stream_transfer"("sandboxId", "reservationHeld");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_stream_transfer_operationId_operationAttempt_key" ON "sandbox_stream_transfer"("operationId", "operationAttempt");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_stream_transfer_userId_idempotencyKey_key" ON "sandbox_stream_transfer"("userId", "idempotencyKey");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_browser_terminal_ticket_tokenDigest_key" ON "sandbox_browser_terminal_ticket"("tokenDigest");

-- CreateIndex
CREATE INDEX "sandbox_browser_terminal_ticket_userId_expiresAt_idx" ON "sandbox_browser_terminal_ticket"("userId", "expiresAt");

-- CreateIndex
CREATE INDEX "sandbox_browser_terminal_ticket_sessionId_idx" ON "sandbox_browser_terminal_ticket"("sessionId");

-- CreateIndex
CREATE INDEX "sandbox_browser_terminal_ticket_sandboxId_idx" ON "sandbox_browser_terminal_ticket"("sandboxId");

-- CreateIndex
CREATE INDEX "sandbox_browser_terminal_ticket_expiresAt_idx" ON "sandbox_browser_terminal_ticket"("expiresAt");

-- CreateIndex
CREATE INDEX "sandbox_terminal_session_userId_sandboxId_idx" ON "sandbox_terminal_session"("userId", "sandboxId");

-- CreateIndex
CREATE INDEX "sandbox_terminal_session_sessionId_idx" ON "sandbox_terminal_session"("sessionId");

-- CreateIndex
CREATE INDEX "sandbox_terminal_session_sandboxId_idx" ON "sandbox_terminal_session"("sandboxId");

-- CreateIndex
CREATE INDEX "sandbox_terminal_session_closedAt_idx" ON "sandbox_terminal_session"("closedAt");

-- CreateIndex
CREATE INDEX "sandbox_terminal_session_openedAt_idx" ON "sandbox_terminal_session"("openedAt");

-- CreateIndex
CREATE INDEX "sandbox_pool_userId_createdAt_idx" ON "sandbox_pool"("userId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_pool_userId_slug_key" ON "sandbox_pool"("userId", "slug");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_pool_id_userId_key" ON "sandbox_pool"("id", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_pool_id_userId_ownHostsOnly_key" ON "sandbox_pool"("id", "userId", "ownHostsOnly");

-- CreateIndex
CREATE INDEX "sandbox_pool_member_sandboxHostId_userId_idx" ON "sandbox_pool_member"("sandboxHostId", "userId");

-- CreateIndex
CREATE INDEX "sandbox_pool_member_poolId_createdAt_idx" ON "sandbox_pool_member"("poolId", "createdAt");

-- CreateIndex
CREATE INDEX "sandbox_pool_member_shareId_idx" ON "sandbox_pool_member"("shareId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_pool_member_poolId_sandboxHostId_key" ON "sandbox_pool_member"("poolId", "sandboxHostId");

-- CreateIndex
CREATE INDEX "sdk_key_pool_allowlist_poolId_userId_idx" ON "sdk_key_pool_allowlist"("poolId", "userId");

-- CreateIndex
CREATE INDEX "sdk_key_pool_allowlist_shareId_idx" ON "sdk_key_pool_allowlist"("shareId");

-- CreateIndex
CREATE UNIQUE INDEX "sdk_key_pool_allowlist_sdkKeyId_poolId_key" ON "sdk_key_pool_allowlist"("sdkKeyId", "poolId");

-- CreateIndex
CREATE INDEX "share_granteeUserId_createdAt_idx" ON "share"("granteeUserId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "share_poolId_granteeUserId_key" ON "share"("poolId", "granteeUserId");

-- CreateIndex
CREATE UNIQUE INDEX "share_use_witness_key" ON "share"("id", "poolId", "ownerUserId", "granteeUserId", "canUse");

-- CreateIndex
CREATE UNIQUE INDEX "share_contribute_witness_key" ON "share"("id", "poolId", "ownerUserId", "granteeUserId", "canContribute");

-- CreateIndex
CREATE UNIQUE INDEX "share_invite_tokenDigest_key" ON "share_invite"("tokenDigest");

-- CreateIndex
CREATE UNIQUE INDEX "share_invite_pendingKey_key" ON "share_invite"("pendingKey");

-- CreateIndex
CREATE INDEX "share_invite_poolId_createdAt_idx" ON "share_invite"("poolId", "createdAt");

-- CreateIndex
CREATE INDEX "share_invite_ownerUserId_createdAt_idx" ON "share_invite"("ownerUserId", "createdAt");

-- CreateIndex
CREATE INDEX "share_invite_expiresAt_idx" ON "share_invite"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "host_terminal_ticket_tokenDigest_key" ON "host_terminal_ticket"("tokenDigest");

-- CreateIndex
CREATE INDEX "host_terminal_ticket_userId_expiresAt_idx" ON "host_terminal_ticket"("userId", "expiresAt");

-- CreateIndex
CREATE INDEX "host_terminal_ticket_sessionId_idx" ON "host_terminal_ticket"("sessionId");

-- CreateIndex
CREATE INDEX "host_terminal_ticket_sandboxHostId_idx" ON "host_terminal_ticket"("sandboxHostId");

-- CreateIndex
CREATE INDEX "host_terminal_ticket_expiresAt_idx" ON "host_terminal_ticket"("expiresAt");

-- CreateIndex
CREATE INDEX "sandbox_operation_result_userId_expiresAt_idx" ON "sandbox_operation_result"("userId", "expiresAt");

-- CreateIndex
CREATE INDEX "sandbox_operation_result_expiresAt_userId_idx" ON "sandbox_operation_result"("expiresAt", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_operation_result_operationId_sandboxId_userId_key" ON "sandbox_operation_result"("operationId", "sandboxId", "userId");

-- CreateIndex
CREATE INDEX "sandbox_host_storage_pool_userId_sandboxHostId_id_idx" ON "sandbox_host_storage_pool"("userId", "sandboxHostId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_host_storage_pool_id_userId_key" ON "sandbox_host_storage_pool"("id", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_host_storage_pool_id_sandboxHostId_userId_marker_na_key" ON "sandbox_host_storage_pool"("id", "sandboxHostId", "userId", "marker", "name");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_host_storage_pool_sandboxHostId_marker_key" ON "sandbox_host_storage_pool"("sandboxHostId", "marker");

-- CreateIndex
CREATE INDEX "sandbox_image_artifact_state_deleteAfter_idx" ON "sandbox_image_artifact"("state", "deleteAfter");

-- CreateIndex
CREATE INDEX "sandbox_image_artifact_userId_state_idx" ON "sandbox_image_artifact"("userId", "state");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_image_artifact_userId_fingerprint_key" ON "sandbox_image_artifact"("userId", "fingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_image_artifact_id_userId_key" ON "sandbox_image_artifact"("id", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_image_upload_session_transferId_key" ON "sandbox_image_upload_session"("transferId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_image_upload_session_liveArtifactId_key" ON "sandbox_image_upload_session"("liveArtifactId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_image_upload_session_liveDiskOffloadId_key" ON "sandbox_image_upload_session"("liveDiskOffloadId");

-- CreateIndex
CREATE INDEX "sandbox_image_upload_session_artifactId_idx" ON "sandbox_image_upload_session"("artifactId");

-- CreateIndex
CREATE INDEX "sandbox_image_upload_session_diskOffloadId_idx" ON "sandbox_image_upload_session"("diskOffloadId");

-- CreateIndex
CREATE INDEX "sandbox_image_upload_session_state_updatedAt_idx" ON "sandbox_image_upload_session"("state", "updatedAt");

-- CreateIndex
CREATE INDEX "sandbox_host_image_cache_imageOwnerId_fingerprint_idx" ON "sandbox_host_image_cache"("imageOwnerId", "fingerprint");

-- CreateIndex
CREATE INDEX "sandbox_host_image_cache_accessLostAt_releaseSentAt_idx" ON "sandbox_host_image_cache"("accessLostAt", "releaseSentAt");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_host_image_cache_hostId_fingerprint_imageOwnerId_key" ON "sandbox_host_image_cache"("hostId", "fingerprint", "imageOwnerId");

-- CreateIndex
CREATE INDEX "sandbox_image_transfer_state_expiresAt_idx" ON "sandbox_image_transfer"("state", "expiresAt");

-- CreateIndex
CREATE INDEX "sandbox_image_transfer_destHostId_state_idx" ON "sandbox_image_transfer"("destHostId", "state");

-- CreateIndex
CREATE INDEX "sandbox_image_transfer_sourceHostId_state_idx" ON "sandbox_image_transfer"("sourceHostId", "state");

-- CreateIndex
CREATE INDEX "sandbox_image_transfer_userId_createdAt_idx" ON "sandbox_image_transfer"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "sandbox_image_transfer_operationId_idx" ON "sandbox_image_transfer"("operationId");

-- CreateIndex
CREATE INDEX "sandbox_image_transfer_diskOffloadId_idx" ON "sandbox_image_transfer"("diskOffloadId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_image_link_tokenDigest_key" ON "sandbox_image_link"("tokenDigest");

-- CreateIndex
CREATE INDEX "sandbox_image_link_expiresAt_idx" ON "sandbox_image_link"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_image_link_transferId_role_partNumber_key" ON "sandbox_image_link"("transferId", "role", "partNumber");

-- CreateIndex
CREATE INDEX "sandbox_template_capture_hostId_state_idx" ON "sandbox_template_capture"("hostId", "state");

-- CreateIndex
CREATE INDEX "sandbox_template_capture_sandboxId_state_idx" ON "sandbox_template_capture"("sandboxId", "state");

-- CreateIndex
CREATE INDEX "sandbox_template_capture_state_updatedAt_idx" ON "sandbox_template_capture"("state", "updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_capture_operationId_sandboxId_userId_key" ON "sandbox_template_capture"("operationId", "sandboxId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_template_capture_buildId_buildAttempt_key" ON "sandbox_template_capture"("buildId", "buildAttempt");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_capacity_wait_seq_key" ON "sandbox_capacity_wait"("seq");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_capacity_wait_sandboxId_key" ON "sandbox_capacity_wait"("sandboxId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_capacity_wait_operationId_key" ON "sandbox_capacity_wait"("operationId");

-- CreateIndex
CREATE INDEX "sandbox_capacity_wait_poolId_state_seq_idx" ON "sandbox_capacity_wait"("poolId", "state", "seq");

-- CreateIndex
CREATE INDEX "sandbox_capacity_wait_userId_state_idx" ON "sandbox_capacity_wait"("userId", "state");

-- CreateIndex
CREATE INDEX "sandbox_capacity_wait_authorizingKeyId_state_idx" ON "sandbox_capacity_wait"("authorizingKeyId", "state");

-- CreateIndex
CREATE INDEX "sandbox_capacity_wait_state_deadlineAt_idx" ON "sandbox_capacity_wait"("state", "deadlineAt");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_capacity_wait_sandboxId_userId_key" ON "sandbox_capacity_wait"("sandboxId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_capacity_wait_operationId_userId_key" ON "sandbox_capacity_wait"("operationId", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_disk_offload_liveSandboxId_key" ON "sandbox_disk_offload"("liveSandboxId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_disk_offload_objectKey_key" ON "sandbox_disk_offload"("objectKey");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_disk_offload_completedSessionId_key" ON "sandbox_disk_offload"("completedSessionId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_disk_offload_evictGrantId_key" ON "sandbox_disk_offload"("evictGrantId");

-- CreateIndex
CREATE INDEX "sandbox_disk_offload_userId_state_idx" ON "sandbox_disk_offload"("userId", "state");

-- CreateIndex
CREATE INDEX "sandbox_disk_offload_state_updatedAt_idx" ON "sandbox_disk_offload"("state", "updatedAt");

-- CreateIndex
CREATE INDEX "sandbox_disk_offload_shredAfter_idx" ON "sandbox_disk_offload"("shredAfter");

-- CreateIndex
CREATE INDEX "sandbox_disk_offload_state_shreddedAt_idx" ON "sandbox_disk_offload"("state", "shreddedAt");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_disk_offload_sandboxId_seq_key" ON "sandbox_disk_offload"("sandboxId", "seq");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_disk_offload_id_sandboxId_userId_key" ON "sandbox_disk_offload"("id", "sandboxId", "userId");

-- CreateIndex
CREATE INDEX "sandbox_disk_copy_hostId_state_idx" ON "sandbox_disk_copy"("hostId", "state");

-- CreateIndex
CREATE INDEX "sandbox_disk_copy_userId_idx" ON "sandbox_disk_copy"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_disk_copy_sandboxId_hostId_key" ON "sandbox_disk_copy"("sandboxId", "hostId");

-- CreateIndex
CREATE INDEX "sandbox_restore_wait_state_deadlineAt_idx" ON "sandbox_restore_wait"("state", "deadlineAt");

-- CreateIndex
CREATE INDEX "sandbox_restore_wait_sandboxId_state_idx" ON "sandbox_restore_wait"("sandboxId", "state");

-- CreateIndex
CREATE INDEX "sandbox_restore_wait_userId_idx" ON "sandbox_restore_wait"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_restore_wait_operationId_sandboxId_userId_key" ON "sandbox_restore_wait"("operationId", "sandboxId", "userId");

-- CreateIndex
CREATE INDEX "sandbox_tunnel_userId_idx" ON "sandbox_tunnel"("userId");

-- CreateIndex
CREATE INDEX "sandbox_tunnel_tunTunnelId_idx" ON "sandbox_tunnel"("tunTunnelId");

-- CreateIndex
CREATE INDEX "sandbox_tunnel_serverKey_idx" ON "sandbox_tunnel"("serverKey");

-- CreateIndex
CREATE UNIQUE INDEX "sandbox_tunnel_sandboxId_userId_key" ON "sandbox_tunnel"("sandboxId", "userId");

-- CreateIndex
CREATE INDEX "sandbox_tunnel_event_createdAt_idx" ON "sandbox_tunnel_event"("createdAt");

-- CreateIndex
CREATE INDEX "sandbox_tunnel_event_sandboxId_createdAt_idx" ON "sandbox_tunnel_event"("sandboxId", "createdAt");

-- CreateIndex
CREATE INDEX "webhook_endpoint_userId_createdAt_idx" ON "webhook_endpoint"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "webhook_endpoint_userId_disabledAt_idx" ON "webhook_endpoint"("userId", "disabledAt");

-- CreateIndex
CREATE UNIQUE INDEX "webhook_endpoint_id_userId_key" ON "webhook_endpoint"("id", "userId");

-- CreateIndex
CREATE UNIQUE INDEX "webhook_event_seq_key" ON "webhook_event"("seq");

-- CreateIndex
CREATE INDEX "webhook_event_fannedOutAt_seq_idx" ON "webhook_event"("fannedOutAt", "seq");

-- CreateIndex
CREATE INDEX "webhook_event_userId_occurredAt_idx" ON "webhook_event"("userId", "occurredAt");

-- CreateIndex
CREATE INDEX "webhook_event_occurredAt_idx" ON "webhook_event"("occurredAt");

-- CreateIndex
CREATE INDEX "webhook_delivery_state_nextAttemptAt_idx" ON "webhook_delivery"("state", "nextAttemptAt");

-- CreateIndex
CREATE INDEX "webhook_delivery_state_leaseUntil_idx" ON "webhook_delivery"("state", "leaseUntil");

-- CreateIndex
CREATE INDEX "webhook_delivery_state_endpointId_nextAttemptAt_idx" ON "webhook_delivery"("state", "endpointId", "nextAttemptAt");

-- CreateIndex
CREATE INDEX "webhook_delivery_manual_due_idx" ON "webhook_delivery"("endpointId", "nextAttemptAt") WHERE ((state = 'PENDING'::"WebhookDeliveryState") AND (kind <> 'event'::text));

-- CreateIndex
CREATE INDEX "webhook_delivery_endpointId_state_idx" ON "webhook_delivery"("endpointId", "state");

-- CreateIndex
CREATE INDEX "webhook_delivery_endpointId_createdAt_idx" ON "webhook_delivery"("endpointId", "createdAt");

-- CreateIndex
CREATE INDEX "webhook_delivery_userId_createdAt_idx" ON "webhook_delivery"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "webhook_delivery_eventId_idx" ON "webhook_delivery"("eventId");

-- CreateIndex
CREATE UNIQUE INDEX "webhook_delivery_attempt_deliveryId_attempt_key" ON "webhook_delivery_attempt"("deliveryId", "attempt");

-- AddForeignKey
ALTER TABLE "mcp_grant" ADD CONSTRAINT "mcp_grant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mcp_grant" ADD CONSTRAINT "mcp_grant_sdkKeyId_userId_fkey" FOREIGN KEY ("sdkKeyId", "userId") REFERENCES "sdk_key"("id", "userId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_queued_command" ADD CONSTRAINT "host_queued_command_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_queued_command" ADD CONSTRAINT "host_queued_command_sandboxHostId_userId_fkey" FOREIGN KEY ("sandboxHostId", "userId") REFERENCES "sandbox_host"("id", "userId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_queued_command" ADD CONSTRAINT "host_queued_command_sdkKeyId_fkey" FOREIGN KEY ("sdkKeyId") REFERENCES "sdk_key"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_file_receipt" ADD CONSTRAINT "host_file_receipt_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_file_receipt" ADD CONSTRAINT "host_file_receipt_sandboxHostId_userId_fkey" FOREIGN KEY ("sandboxHostId", "userId") REFERENCES "sandbox_host"("id", "userId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_file_receipt" ADD CONSTRAINT "host_file_receipt_sdkKeyId_userId_fkey" FOREIGN KEY ("sdkKeyId", "userId") REFERENCES "sdk_key"("id", "userId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "session" ADD CONSTRAINT "session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account" ADD CONSTRAINT "account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "two_factor" ADD CONSTRAINT "two_factor_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_code" ADD CONSTRAINT "device_code_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_subscription" ADD CONSTRAINT "push_subscription_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_image_policy" ADD CONSTRAINT "account_image_policy_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_client" ADD CONSTRAINT "oauth_client_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_client_resource" ADD CONSTRAINT "oauth_client_resource_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "oauth_client"("clientId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_client_resource" ADD CONSTRAINT "oauth_client_resource_resourceId_fkey" FOREIGN KEY ("resourceId") REFERENCES "oauth_resource"("identifier") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_refresh_token" ADD CONSTRAINT "oauth_refresh_token_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "oauth_client"("clientId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_refresh_token" ADD CONSTRAINT "oauth_refresh_token_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "session"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_refresh_token" ADD CONSTRAINT "oauth_refresh_token_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_access_token" ADD CONSTRAINT "oauth_access_token_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "oauth_client"("clientId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_access_token" ADD CONSTRAINT "oauth_access_token_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "session"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_access_token" ADD CONSTRAINT "oauth_access_token_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_access_token" ADD CONSTRAINT "oauth_access_token_refreshId_fkey" FOREIGN KEY ("refreshId") REFERENCES "oauth_refresh_token"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_consent" ADD CONSTRAINT "oauth_consent_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "oauth_client"("clientId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oauth_consent" ADD CONSTRAINT "oauth_consent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "sandbox_template_build_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "sandbox_template_build_templateId_userId_fkey" FOREIGN KEY ("templateId", "userId") REFERENCES "sandbox_logical_template"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_build_context" ADD CONSTRAINT "sandbox_build_context_buildId_userId_fkey" FOREIGN KEY ("buildId", "userId") REFERENCES "sandbox_template_build"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_build_context_chunk" ADD CONSTRAINT "sandbox_build_context_chunk_contextId_fkey" FOREIGN KEY ("contextId") REFERENCES "sandbox_build_context"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_definition" ADD CONSTRAINT "credential_definition_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential" ADD CONSTRAINT "credential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential" ADD CONSTRAINT "credential_definitionId_userId_fkey" FOREIGN KEY ("definitionId", "userId") REFERENCES "credential_definition"("id", "userId") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_account" ADD CONSTRAINT "credential_account_credentialId_userId_fkey" FOREIGN KEY ("credentialId", "userId") REFERENCES "credential"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_account" ADD CONSTRAINT "credential_account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_instance" ADD CONSTRAINT "credential_instance_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_instance" ADD CONSTRAINT "credential_instance_credentialId_userId_fkey" FOREIGN KEY ("credentialId", "userId") REFERENCES "credential"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_instance" ADD CONSTRAINT "credential_instance_accountId_credentialId_userId_fkey" FOREIGN KEY ("accountId", "credentialId", "userId") REFERENCES "credential_account"("id", "credentialId", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_secret_version" ADD CONSTRAINT "credential_secret_version_instanceId_fkey" FOREIGN KEY ("instanceId") REFERENCES "credential_instance"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_lease" ADD CONSTRAINT "credential_lease_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_lease" ADD CONSTRAINT "credential_lease_credentialId_userId_fkey" FOREIGN KEY ("credentialId", "userId") REFERENCES "credential"("id", "userId") ON DELETE NO ACTION ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_lease" ADD CONSTRAINT "credential_lease_instanceId_credentialId_userId_fkey" FOREIGN KEY ("instanceId", "credentialId", "userId") REFERENCES "credential_instance"("id", "credentialId", "userId") ON DELETE NO ACTION ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_lease" ADD CONSTRAINT "credential_lease_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_binding" ADD CONSTRAINT "credential_binding_leaseId_fkey" FOREIGN KEY ("leaseId") REFERENCES "credential_lease"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_residue" ADD CONSTRAINT "credential_residue_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_residue" ADD CONSTRAINT "credential_residue_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_residue" ADD CONSTRAINT "credential_residue_bindingId_fkey" FOREIGN KEY ("bindingId") REFERENCES "credential_binding"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_pending_capture" ADD CONSTRAINT "credential_pending_capture_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "sandbox_host"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_host_census" ADD CONSTRAINT "credential_host_census_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "sandbox_host"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_lease_tombstone" ADD CONSTRAINT "credential_lease_tombstone_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "sandbox_host"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_host_return_key" ADD CONSTRAINT "credential_host_return_key_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "sandbox_host"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_credential" ADD CONSTRAINT "sandbox_credential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_credential" ADD CONSTRAINT "sandbox_credential_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_credential" ADD CONSTRAINT "sandbox_credential_credentialId_userId_fkey" FOREIGN KEY ("credentialId", "userId") REFERENCES "credential"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_operation_spec" ADD CONSTRAINT "credential_operation_spec_operationId_fkey" FOREIGN KEY ("operationId") REFERENCES "sandbox_mutation_operation"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_login_session" ADD CONSTRAINT "credential_login_session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_login_session" ADD CONSTRAINT "credential_login_session_credentialId_userId_fkey" FOREIGN KEY ("credentialId", "userId") REFERENCES "credential"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "credential_event" ADD CONSTRAINT "credential_event_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sdk_key_credential_allowlist" ADD CONSTRAINT "sdk_key_credential_allowlist_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sdk_key_credential_allowlist" ADD CONSTRAINT "sdk_key_credential_allowlist_sdkKeyId_userId_fkey" FOREIGN KEY ("sdkKeyId", "userId") REFERENCES "sdk_key"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sdk_key_credential_allowlist" ADD CONSTRAINT "sdk_key_credential_allowlist_credentialId_userId_fkey" FOREIGN KEY ("credentialId", "userId") REFERENCES "credential"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_host" ADD CONSTRAINT "sandbox_host_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_token" ADD CONSTRAINT "host_token_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_token" ADD CONSTRAINT "host_token_sandboxHostId_fkey" FOREIGN KEY ("sandboxHostId") REFERENCES "sandbox_host"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_device_credential" ADD CONSTRAINT "host_device_credential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_device_credential" ADD CONSTRAINT "host_device_credential_sandboxHostId_fkey" FOREIGN KEY ("sandboxHostId") REFERENCES "sandbox_host"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sdk_key" ADD CONSTRAINT "sdk_key_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sdk_key_host_allowlist" ADD CONSTRAINT "sdk_key_host_allowlist_sdkKeyId_fkey" FOREIGN KEY ("sdkKeyId") REFERENCES "sdk_key"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sdk_key_host_allowlist" ADD CONSTRAINT "sdk_key_host_allowlist_sandboxHostId_fkey" FOREIGN KEY ("sandboxHostId") REFERENCES "sandbox_host"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sdk_key_revision_allowlist" ADD CONSTRAINT "sdk_key_revision_allowlist_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sdk_key_revision_allowlist" ADD CONSTRAINT "sdk_key_revision_allowlist_sdkKeyId_userId_fkey" FOREIGN KEY ("sdkKeyId", "userId") REFERENCES "sdk_key"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sdk_key_revision_allowlist" ADD CONSTRAINT "sdk_key_revision_allowlist_templateRevisionId_userId_fkey" FOREIGN KEY ("templateRevisionId", "userId") REFERENCES "sandbox_template_revision"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_logical_template" ADD CONSTRAINT "sandbox_logical_template_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_template_revision" ADD CONSTRAINT "sandbox_template_revision_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_template_revision" ADD CONSTRAINT "sandbox_template_revision_templateId_userId_fkey" FOREIGN KEY ("templateId", "userId") REFERENCES "sandbox_logical_template"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_upstream_image" ADD CONSTRAINT "sandbox_upstream_image_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_upstream_image" ADD CONSTRAINT "sandbox_upstream_image_templateId_userId_fkey" FOREIGN KEY ("templateId", "userId") REFERENCES "sandbox_logical_template"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_upstream_image" ADD CONSTRAINT "sandbox_upstream_image_revisionId_templateId_userId_fkey" FOREIGN KEY ("revisionId", "templateId", "userId") REFERENCES "sandbox_template_revision"("id", "templateId", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_template_tag" ADD CONSTRAINT "sandbox_template_tag_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_template_tag" ADD CONSTRAINT "sandbox_template_tag_templateId_userId_fkey" FOREIGN KEY ("templateId", "userId") REFERENCES "sandbox_logical_template"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_template_tag" ADD CONSTRAINT "sandbox_template_tag_revisionId_templateId_userId_fkey" FOREIGN KEY ("revisionId", "templateId", "userId") REFERENCES "sandbox_template_revision"("id", "templateId", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_template_availability" ADD CONSTRAINT "sandbox_template_availability_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_template_availability" ADD CONSTRAINT "sandbox_template_availability_revisionId_userId_fkey" FOREIGN KEY ("revisionId", "userId") REFERENCES "sandbox_template_revision"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_template_availability" ADD CONSTRAINT "sandbox_template_availability_hostId_userId_fkey" FOREIGN KEY ("hostId", "hostOwnerId") REFERENCES "sandbox_host"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_revision_config" ADD CONSTRAINT "sandbox_revision_config_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_revision_config" ADD CONSTRAINT "sandbox_revision_config_revisionId_userId_fkey" FOREIGN KEY ("revisionId", "userId") REFERENCES "sandbox_template_revision"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_operationId_sandboxId_userId_fkey" FOREIGN KEY ("operationId", "sandboxId", "userId") REFERENCES "sandbox_mutation_operation"("id", "sandboxId", "userId") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_templateRevisionId_templateId_userId_fkey" FOREIGN KEY ("templateRevisionId", "templateId", "userId") REFERENCES "sandbox_template_revision"("id", "templateId", "userId") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_configId_sandboxId_userId_fkey" FOREIGN KEY ("configId", "sandboxId", "userId") REFERENCES "sandbox_execution_config"("id", "sandboxId", "userId") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_storagePoolId_sandboxHostId_userId_storag_fkey" FOREIGN KEY ("storagePoolId", "sandboxHostId", "hostOwnerId", "storageMarker", "storagePoolName") REFERENCES "sandbox_host_storage_pool"("id", "sandboxHostId", "userId", "marker", "name") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_sandboxHostId_userId_fkey" FOREIGN KEY ("sandboxHostId", "hostOwnerId") REFERENCES "sandbox_host"("id", "userId") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_templateRevisionId_templateId_userId_fkey" FOREIGN KEY ("templateRevisionId", "templateId", "userId") REFERENCES "sandbox_template_revision"("id", "templateId", "userId") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_currentPlacementId_id_userId_fkey" FOREIGN KEY ("currentPlacementId", "id", "userId") REFERENCES "sandbox_placement"("id", "sandboxId", "userId") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_diskOffloadId_id_userId_fkey" FOREIGN KEY ("diskOffloadId", "id", "userId") REFERENCES "sandbox_disk_offload"("id", "sandboxId", "userId") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_execution_config" ADD CONSTRAINT "sandbox_execution_config_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_execution_config" ADD CONSTRAINT "sandbox_execution_config_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_mutation_operation" ADD CONSTRAINT "sandbox_mutation_operation_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_mutation_operation" ADD CONSTRAINT "sandbox_mutation_operation_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_command_stream" ADD CONSTRAINT "sandbox_command_stream_id_fkey" FOREIGN KEY ("id") REFERENCES "sandbox_mutation_operation"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_command_stream_segment" ADD CONSTRAINT "sandbox_command_stream_segment_outputId_fkey" FOREIGN KEY ("outputId") REFERENCES "sandbox_command_stream"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_dispatch_outbox" ADD CONSTRAINT "sandbox_dispatch_outbox_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_dispatch_outbox" ADD CONSTRAINT "sandbox_dispatch_outbox_aggregateId_userId_fkey" FOREIGN KEY ("aggregateId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_mutation_receipt" ADD CONSTRAINT "sandbox_mutation_receipt_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_mutation_receipt" ADD CONSTRAINT "sandbox_mutation_receipt_logicalTemplateId_userId_fkey" FOREIGN KEY ("logicalTemplateId", "userId") REFERENCES "sandbox_logical_template"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_stream_transfer" ADD CONSTRAINT "sandbox_stream_transfer_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_stream_transfer" ADD CONSTRAINT "sandbox_stream_transfer_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_stream_transfer_chunk" ADD CONSTRAINT "sandbox_stream_transfer_chunk_transferId_fkey" FOREIGN KEY ("transferId") REFERENCES "sandbox_stream_transfer"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_browser_terminal_ticket" ADD CONSTRAINT "sandbox_browser_terminal_ticket_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_browser_terminal_ticket" ADD CONSTRAINT "sandbox_browser_terminal_ticket_sessionId_userId_fkey" FOREIGN KEY ("sessionId", "userId") REFERENCES "session"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_browser_terminal_ticket" ADD CONSTRAINT "sandbox_browser_terminal_ticket_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_terminal_session" ADD CONSTRAINT "sandbox_terminal_session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_terminal_session" ADD CONSTRAINT "sandbox_terminal_session_sessionId_userId_fkey" FOREIGN KEY ("sessionId", "userId") REFERENCES "session"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_terminal_session" ADD CONSTRAINT "sandbox_terminal_session_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_pool" ADD CONSTRAINT "sandbox_pool_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_pool_member" ADD CONSTRAINT "sandbox_pool_member_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_pool_member" ADD CONSTRAINT "sandbox_pool_member_poolId_userId_fkey" FOREIGN KEY ("poolId", "userId") REFERENCES "sandbox_pool"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_pool_member" ADD CONSTRAINT "sandbox_pool_member_sandboxHostId_userId_fkey" FOREIGN KEY ("sandboxHostId", "hostOwnerId") REFERENCES "sandbox_host"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_pool_member" ADD CONSTRAINT "sandbox_pool_member_shareId_poolId_userId_hostOwnerId_cont_fkey" FOREIGN KEY ("shareId", "poolId", "userId", "hostOwnerId", "contributeWitness") REFERENCES "share"("id", "poolId", "ownerUserId", "granteeUserId", "canContribute") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_pool_member" ADD CONSTRAINT "sandbox_pool_member_poolId_userId_ownHostsOnlyWitness_fkey" FOREIGN KEY ("poolId", "userId", "ownHostsOnlyWitness") REFERENCES "sandbox_pool"("id", "userId", "ownHostsOnly") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sdk_key_pool_allowlist" ADD CONSTRAINT "sdk_key_pool_allowlist_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sdk_key_pool_allowlist" ADD CONSTRAINT "sdk_key_pool_allowlist_sdkKeyId_userId_fkey" FOREIGN KEY ("sdkKeyId", "userId") REFERENCES "sdk_key"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sdk_key_pool_allowlist" ADD CONSTRAINT "sdk_key_pool_allowlist_poolId_userId_fkey" FOREIGN KEY ("poolId", "poolOwnerId") REFERENCES "sandbox_pool"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sdk_key_pool_allowlist" ADD CONSTRAINT "sdk_key_pool_allowlist_shareId_poolId_poolOwnerId_userId_u_fkey" FOREIGN KEY ("shareId", "poolId", "poolOwnerId", "userId", "useWitness") REFERENCES "share"("id", "poolId", "ownerUserId", "granteeUserId", "canUse") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "share" ADD CONSTRAINT "share_ownerUserId_fkey" FOREIGN KEY ("ownerUserId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "share" ADD CONSTRAINT "share_granteeUserId_fkey" FOREIGN KEY ("granteeUserId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "share" ADD CONSTRAINT "share_poolId_ownerUserId_fkey" FOREIGN KEY ("poolId", "ownerUserId") REFERENCES "sandbox_pool"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "share_invite" ADD CONSTRAINT "share_invite_ownerUserId_fkey" FOREIGN KEY ("ownerUserId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "share_invite" ADD CONSTRAINT "share_invite_poolId_ownerUserId_fkey" FOREIGN KEY ("poolId", "ownerUserId") REFERENCES "sandbox_pool"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "host_terminal_ticket" ADD CONSTRAINT "host_terminal_ticket_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "host_terminal_ticket" ADD CONSTRAINT "host_terminal_ticket_sessionId_userId_fkey" FOREIGN KEY ("sessionId", "userId") REFERENCES "session"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "host_terminal_ticket" ADD CONSTRAINT "host_terminal_ticket_sandboxHostId_hostOwnerId_fkey" FOREIGN KEY ("sandboxHostId", "hostOwnerId") REFERENCES "sandbox_host"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_operation_result" ADD CONSTRAINT "sandbox_operation_result_operationId_sandboxId_userId_fkey" FOREIGN KEY ("operationId", "sandboxId", "userId") REFERENCES "sandbox_mutation_operation"("id", "sandboxId", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_operation_result" ADD CONSTRAINT "sandbox_operation_result_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_host_storage_pool" ADD CONSTRAINT "sandbox_host_storage_pool_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_host_storage_pool" ADD CONSTRAINT "sandbox_host_storage_pool_sandboxHostId_userId_fkey" FOREIGN KEY ("sandboxHostId", "userId") REFERENCES "sandbox_host"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_image_artifact" ADD CONSTRAINT "sandbox_image_artifact_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_image_upload_session" ADD CONSTRAINT "sandbox_image_upload_session_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "sandbox_image_artifact"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_image_upload_session" ADD CONSTRAINT "sandbox_image_upload_session_diskOffloadId_fkey" FOREIGN KEY ("diskOffloadId") REFERENCES "sandbox_disk_offload"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_image_upload_session" ADD CONSTRAINT "sandbox_image_upload_session_transferId_fkey" FOREIGN KEY ("transferId") REFERENCES "sandbox_image_transfer"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_image_upload_part" ADD CONSTRAINT "sandbox_image_upload_part_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "sandbox_image_upload_session"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_host_image_cache" ADD CONSTRAINT "sandbox_host_image_cache_hostId_hostOwnerId_fkey" FOREIGN KEY ("hostId", "hostOwnerId") REFERENCES "sandbox_host"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_image_transfer" ADD CONSTRAINT "sandbox_image_transfer_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_image_transfer" ADD CONSTRAINT "sandbox_image_transfer_diskOffloadId_fkey" FOREIGN KEY ("diskOffloadId") REFERENCES "sandbox_disk_offload"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_image_link" ADD CONSTRAINT "sandbox_image_link_transferId_fkey" FOREIGN KEY ("transferId") REFERENCES "sandbox_image_transfer"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_template_capture" ADD CONSTRAINT "sandbox_template_capture_operationId_sandboxId_userId_fkey" FOREIGN KEY ("operationId", "sandboxId", "userId") REFERENCES "sandbox_mutation_operation"("id", "sandboxId", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_template_capture" ADD CONSTRAINT "sandbox_template_capture_templateId_userId_fkey" FOREIGN KEY ("templateId", "userId") REFERENCES "sandbox_logical_template"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_capacity_wait" ADD CONSTRAINT "sandbox_capacity_wait_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_capacity_wait" ADD CONSTRAINT "sandbox_capacity_wait_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_capacity_wait" ADD CONSTRAINT "sandbox_capacity_wait_operationId_userId_fkey" FOREIGN KEY ("operationId", "userId") REFERENCES "sandbox_mutation_operation"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_disk_offload" ADD CONSTRAINT "sandbox_disk_offload_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_disk_offload" ADD CONSTRAINT "sandbox_disk_offload_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_disk_copy" ADD CONSTRAINT "sandbox_disk_copy_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_disk_copy" ADD CONSTRAINT "sandbox_disk_copy_sandboxId_userId_fkey" FOREIGN KEY ("sandboxId", "userId") REFERENCES "sandbox_instance"("id", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_disk_copy" ADD CONSTRAINT "sandbox_disk_copy_hostId_hostOwnerId_fkey" FOREIGN KEY ("hostId", "hostOwnerId") REFERENCES "sandbox_host"("id", "userId") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_restore_wait" ADD CONSTRAINT "sandbox_restore_wait_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "sandbox_restore_wait" ADD CONSTRAINT "sandbox_restore_wait_operationId_sandboxId_userId_fkey" FOREIGN KEY ("operationId", "sandboxId", "userId") REFERENCES "sandbox_mutation_operation"("id", "sandboxId", "userId") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "webhook_endpoint" ADD CONSTRAINT "webhook_endpoint_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "webhook_delivery" ADD CONSTRAINT "webhook_delivery_eventId_fkey" FOREIGN KEY ("eventId") REFERENCES "webhook_event"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "webhook_delivery" ADD CONSTRAINT "webhook_delivery_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "webhook_endpoint"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "webhook_delivery_attempt" ADD CONSTRAINT "webhook_delivery_attempt_deliveryId_fkey" FOREIGN KEY ("deliveryId") REFERENCES "webhook_delivery"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- wssp:initial-backfill-begin
-- Deterministic data updates needed by future schema changes run here before CHECK constraints.
-- Keep updates idempotent so repeated schema applies are safe.
-- wssp:initial-backfill-end

-- wssp:initial-checks-begin
ALTER TABLE "account_image_policy" ADD CONSTRAINT "account_image_policy_admin_ck6f4ebae4" CHECK (("adminStoredGiBMax" IS NULL OR "adminStoredGiBMax" >= 0) AND ("adminDownloadsPerHourMax" IS NULL OR "adminDownloadsPerHourMax" >= 0) AND ("adminConcurrentBuildsMax" IS NULL OR "adminConcurrentBuildsMax" >= 0) AND ("adminBuildMinutesPerMonthMax" IS NULL OR "adminBuildMinutesPerMonthMax" >= 0) AND ("adminOffloadGiBMax" IS NULL OR "adminOffloadGiBMax" >= 0));
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_principal_ck9d51b3b8" CHECK (("principalKind"::text = 'sdkKey') = ("authorizingKeyId" IS NOT NULL) AND ("principalKind"::text = 'system') = ("triggeredByRevisionId" IS NOT NULL) AND "principalKey" = CASE "principalKind"::text WHEN 'sdkKey' THEN 'k:' || "authorizingKeyId" WHEN 'session' THEN 's' ELSE 'sys' END);
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_target_ckc3626963" CHECK (("poolId" IS NULL) <> ("requestedHostId" IS NULL) AND "targetKey" = coalesce("poolId", "requestedHostId"));
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_minutes_ckaff9aed0" CHECK ("timeoutMinutes" BETWEEN 1 AND 1440 AND "reservedMinutes" BETWEEN 0 AND "timeoutMinutes" AND ("chargedMinutes" IS NULL OR "chargedMinutes" BETWEEN 0 AND "reservedMinutes") AND (NOT "minutesSettled" OR "chargedMinutes" IS NOT NULL) AND extract(day FROM "chargeMonth") = 1);
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_vm_size_ck1ee6588b" CHECK ("cpuCount" >= 1 AND "cpuCount" <= 32 AND "memoryMiB" >= 512 AND "memoryMiB" <= 65536 AND "memoryMiB" % 256 = 0 AND "diskGiB" >= 1 AND "diskGiB" <= 2048 AND "defaultDiskGiB" >= "diskGiB" AND "defaultDiskGiB" <= 2048);
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_recipe_ck85034c96" CHECK (octet_length("recipe"::text) <= 65536 AND "recipeDigest" ~ '^[0-9a-f]{64}$' AND "buildDigest" ~ '^[0-9a-f]{64}$' AND ("sourceFormat"::text = 'DOCKERFILE') = ("dockerfileText" IS NOT NULL) AND ("dockerfileText" IS NULL OR octet_length("dockerfileText") <= 65536) AND jsonb_typeof("buildArgs") = 'object' AND cardinality("egressPresets") <= 16);
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_context_ckac6d057c" CHECK (("contextSha256" IS NULL) = ("contextBytes" IS NULL) AND ("contextSha256" IS NULL OR "contextSha256" ~ '^[0-9a-f]{64}$') AND ("contextBytes" IS NULL OR "contextBytes" > 0));
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_progress_ck8540d445" CHECK ("stepIndex" >= -1 AND jsonb_typeof("steps") = 'array' AND jsonb_array_length("steps") <= 256 AND ("phase" IS NULL OR length("phase") <= 64) AND ("failureStepIndex" IS NULL OR "failureStepIndex" >= 0) AND ("failureTail" IS NULL OR octet_length("failureTail") <= 8192));
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_capture_attempt_ckb0da2bb7" CHECK ("captureAttempt" BETWEEN 0 AND 16);
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_egress_hints_ckd5c6d545" CHECK (jsonb_typeof("egressHints") = 'array' AND jsonb_array_length("egressHints") <= 64);
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_host_ckc9dd883c" CHECK (("hostId" IS NULL) = ("hostOwnerId" IS NULL) AND (NOT "foreignHost" OR ("hostOwnerId" IS NOT NULL AND "hostOwnerId" <> "userId")));
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_outcome_ck736f0852" CHECK ((state::text IN ('SUCCEEDED', 'FAILED', 'CANCELLED')) = ("completedAt" IS NOT NULL) AND (state::text <> 'SUCCEEDED' OR "revisionId" IS NOT NULL OR "cacheHitRevisionId" IS NOT NULL) AND (state::text <> 'FAILED' OR "errorCode" IS NOT NULL) AND (state::text NOT IN ('CANCELLING', 'CANCELLED') OR "cancelRequestedAt" IS NOT NULL) AND (("cleanupState"::text = 'DONE') = ("cleanupDoneAt" IS NOT NULL)) AND ("cleanupState"::text = 'PENDING' OR state::text IN ('SUCCEEDED', 'FAILED', 'CANCELLED')));
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_wait_ckbf6848aa" CHECK (("waitForCapacityMs" IS NULL OR "waitForCapacityMs" BETWEEN 1000 AND 2073600000) AND ("waitForCapacityMs" IS NULL OR "poolId" IS NOT NULL) AND ("errorDetail" IS NULL OR ("errorCode" IS NOT NULL AND "errorDetail" ~ '^[a-z0-9_.]{1,64}$')));
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_error_code_cka31ed2c8" CHECK ("errorCode" IS NULL OR "errorCode" IN ('build_step_failed', 'build_step_unknown', 'build_step_timeout', 'build_step_host_disconnected', 'build_timeout', 'build_context_timeout', 'build_context_mismatch', 'build_context_expired', 'build_context_failed', 'build_placement_failed', 'build_capture_failed', 'build_capture_lease_expired', 'build_store_failed', 'build_authority_lost', 'build_host_lost', 'build_internal', 'build_cancelled', 'build_verify_failed', 'build_upstream_unavailable'));
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_verify_ck423d125a" CHECK ((NOT "verifyRequired" AND "verifySandboxId" IS NULL AND "verifyDeadlineAt" IS NULL) OR ("verifyRequired" AND "noCache"));
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_origin_ck651c67d2" CHECK ("origin"::text = 'USER' OR ("verifyRequired" AND "recipeDigest" = 'eb8a190977a1665adb2f14dcbe7f60eede39ea3ef72f8646652f4919d6802c59' AND "sourceFormat"::text = 'RECIPE' AND "contextSha256" IS NULL));
ALTER TABLE "sandbox_build_context" ADD CONSTRAINT "sandbox_build_context_shape_ck4f029215" CHECK ("totalBytes" > 0 AND "receivedBytes" BETWEEN 0 AND "totalBytes" AND "expectedSha256" ~ '^[0-9a-f]{64}$' AND "importAttempt" >= 0 AND (state::text = 'ADOPTED') = ("transferId" IS NOT NULL) AND (state::text NOT IN ('SEALED', 'ADOPTED') OR "receivedBytes" = "totalBytes") AND ("errorCode" IS NULL OR (state::text IN ('ABORTED', 'EXPIRED') AND "errorCode" IN ('build_context_timeout', 'build_context_expired', 'build_context_mismatch', 'build_context_failed'))) AND (state::text NOT IN ('OPEN', 'SEALED') OR "reservationHeld"));
ALTER TABLE "sandbox_build_context_chunk" ADD CONSTRAINT "sandbox_build_context_chunk_shape_ck629ad63f" CHECK ("offset" >= 0 AND "length" > 0);
ALTER TABLE "credential_definition" ADD CONSTRAINT "credential_definition_version_cke7b16127" CHECK ("version" >= 1);
ALTER TABLE "credential_definition" ADD CONSTRAINT "credential_definition_digest_ckff554ec0" CHECK ("digest" ~ '^[0-9a-f]{64}$');
ALTER TABLE "credential" ADD CONSTRAINT "credential_proxy_copy_back_ck80f3c2ae" CHECK ("delivery"::text <> 'PROXY' OR NOT "copyBack");
ALTER TABLE "credential" ADD CONSTRAINT "credential_checkpoint_interval_ckcb70f641" CHECK ("checkpointIntervalMin" IS NULL OR ("checkpointIntervalMin" >= 5 AND "checkpointIntervalMin" <= 240));
ALTER TABLE "credential" ADD CONSTRAINT "credential_foreign_allowed_ck1d692dac" CHECK (NOT "foreignAllowed" OR "foreignAllowedAt" IS NOT NULL);
ALTER TABLE "credential" ADD CONSTRAINT "credential_pinned_digest_ckacc9fc32" CHECK ("definitionDigest" ~ '^[0-9a-f]{64}$');
ALTER TABLE "credential_account" ADD CONSTRAINT "credential_account_ordinal_ck87678fb4" CHECK ("ordinal" >= 1);
ALTER TABLE "credential_account" ADD CONSTRAINT "credential_account_name_ck4e729995" CHECK ("name" IS NULL OR (length("name") >= 1 AND length("name") <= 80));
ALTER TABLE "credential_instance" ADD CONSTRAINT "credential_instance_active_leases_ckb60cd8cd" CHECK ("activeLeases" >= 0);
ALTER TABLE "credential_instance" ADD CONSTRAINT "credential_instance_capacity_ck4264151e" CHECK ("capacity" IS NULL OR "capacity" >= 1);
ALTER TABLE "credential_instance" ADD CONSTRAINT "credential_instance_ordinal_ck03ac794a" CHECK ("ordinal" >= 1 AND "accountOrdinal" >= 1 AND "nextStorageSeq" >= 1);
ALTER TABLE "credential_instance" ADD CONSTRAINT "credential_instance_name_ck4e729995" CHECK ("name" IS NULL OR (length("name") >= 1 AND length("name") <= 80));
ALTER TABLE "credential_instance" ADD CONSTRAINT "credential_instance_ready_ck7944c74b" CHECK (state::text <> 'READY' OR "currentSeq" IS NOT NULL);
ALTER TABLE "credential_instance" ADD CONSTRAINT "credential_instance_seq_ck5098c8ec" CHECK ("currentSeq" IS NULL OR ("currentSeq" >= 1 AND "currentSeq" < "nextStorageSeq"));
ALTER TABLE "credential_secret_version" ADD CONSTRAINT "credential_secret_version_shape_ck86b90824" CHECK ("storageSeq" >= 1 AND "sizeBytes" >= 0 AND octet_length("nonce") = 12 AND octet_length("wrappedDek") = 48 AND octet_length("wrapSalt") = 32 AND octet_length("wrapNonce") = 12 AND "rootKid" ~ '^[0-9a-f]{16}$' AND "policyDigest" ~ '^[0-9a-f]{64}$');
ALTER TABLE "credential_lease" ADD CONSTRAINT "credential_lease_subject_ckcd370e4f" CHECK (("kind"::text = 'WORKLOAD' AND "sandboxId" IS NOT NULL AND "loginSessionId" IS NULL) OR ("kind"::text = 'LOGIN' AND "loginSessionId" IS NOT NULL));
ALTER TABLE "credential_lease" ADD CONSTRAINT "credential_lease_terminal_ck053a88fa" CHECK (("state"::text IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED')) = ("releasedAt" IS NOT NULL));
ALTER TABLE "credential_lease" ADD CONSTRAINT "credential_lease_capture_seq_ckcf03fede" CHECK ("captureSeqAccepted" >= 0);
ALTER TABLE "credential_capture" ADD CONSTRAINT "credential_capture_digest_ck9faf8b6a" CHECK (octet_length("envelopeDigest") = 32);
ALTER TABLE "credential_return_key" ADD CONSTRAINT "credential_return_key_shape_ckb3d043d0" CHECK ("kidR" ~ '^[0-9a-f]{16}$' AND "epoch" >= 1 AND octet_length("publicKey") = 32 AND octet_length("rwrapSalt") = 32 AND octet_length("wrapNonce") = 12 AND "rootKid" ~ '^[0-9a-f]{16}$');
ALTER TABLE "credential_return_key_state" ADD CONSTRAINT "credential_return_key_state_singleton_ck2254cda8" CHECK ("id" = 1 AND "currentEpoch" >= 1);
ALTER TABLE "credential_capture_rejection" ADD CONSTRAINT "credential_capture_rejection_digest_ck9faf8b6a" CHECK (octet_length("envelopeDigest") = 32);
ALTER TABLE "credential_operation_spec" ADD CONSTRAINT "credential_operation_spec_size_ck0b3642f6" CHECK (octet_length("digest") = 32 AND octet_length("bytes") <= 1179648);
ALTER TABLE "data_key_epoch" ADD CONSTRAINT "data_key_epoch_singleton_ckf9e2aa00" CHECK ("id" = 1 AND "epoch" >= 1 AND "currentKid" ~ '^[0-9a-f]{16}$' AND ("previousKid" IS NULL OR "previousKid" ~ '^[0-9a-f]{16}$'));
ALTER TABLE "sandbox_host" ADD CONSTRAINT "sandbox_host_vcpu_budget_ckcdd5e443" CHECK ("daemonVcpuBudget" IS NULL OR ("daemonVcpuBudget" >= 1 AND "daemonVcpuBudget" <= 8192));
ALTER TABLE "sandbox_host" ADD CONSTRAINT "sandbox_host_vcpu_reserved_ck8ebfea9f" CHECK ("vcpuReserved" >= 0 AND "vcpuReserved" <= 8000);
ALTER TABLE "sandbox_host" ADD CONSTRAINT "sandbox_host_counts_cke9a634c9" CHECK ("liveCount" >= 0 AND "liveCount" <= 250 AND "rootCount" >= 0 AND "rootCount" <= 250);
ALTER TABLE "sandbox_host" ADD CONSTRAINT "sandbox_host_memory_reserved_ckb4b09bbf" CHECK ("memoryReservedMiB" >= 0 AND "memoryReservedMiB" <= 2147483647);
ALTER TABLE "sandbox_host" ADD CONSTRAINT "sandbox_host_memory_budget_ckc1c3edeb" CHECK ("daemonMemoryBudgetMiB" IS NULL OR ("daemonMemoryBudgetMiB" >= 512 AND "daemonMemoryBudgetMiB" <= 16777216 AND "daemonMemoryBudgetMiB" % 256 = 0));
ALTER TABLE "sandbox_host" ADD CONSTRAINT "sandbox_host_cpu_cap_ckee537a76" CHECK ("daemonMaxCpuCount" IS NULL OR ("daemonMaxCpuCount" >= 1 AND "daemonMaxCpuCount" <= 32));
ALTER TABLE "sandbox_host" ADD CONSTRAINT "sandbox_host_max_lease_ck7dac77c4" CHECK ("daemonMaxLeaseMs" IS NULL OR "daemonMaxLeaseMs" BETWEEN 300000 AND 2073600000);
ALTER TABLE "sandbox_host" ADD CONSTRAINT "sandbox_host_egress_guard_reason_ck65752f63" CHECK ("daemonEgressGuardReason" IS NULL OR length("daemonEgressGuardReason") <= 64);
ALTER TABLE "sandbox_host" ADD CONSTRAINT "sandbox_host_image_cache_ckaf508d7d" CHECK (("imageCacheCapBytes" IS NULL OR "imageCacheCapBytes" >= 0) AND ("imageCacheUsedBytes" IS NULL OR "imageCacheUsedBytes" >= 0) AND ("imageCacheForeignBytes" IS NULL OR "imageCacheForeignBytes" >= 0));
ALTER TABLE "sdk_key" ADD CONSTRAINT "sdk_key_kind_secret_ckd067d5ec" CHECK (("kind" = 'OAUTH_GRANT' AND "lookupPrefix" IS NULL AND "secretDigest" IS NULL) OR ("kind" <> 'OAUTH_GRANT' AND "lookupPrefix" IS NOT NULL AND "secretDigest" IS NOT NULL));
ALTER TABLE "sandbox_logical_template" ADD CONSTRAINT "sandbox_template_community_ckec7c7d96" CHECK ("communitySource" IS NULL OR "communitySource" IN ('ubuntu-26.04'));
ALTER TABLE "sandbox_logical_template" ADD CONSTRAINT "sandbox_template_capture_keep_ck827f58be" CHECK ("captureKeep" BETWEEN 1 AND 50 AND ("pruneAfterDays" IS NULL OR "pruneAfterDays" BETWEEN 1 AND 3650) AND cardinality("captureScrubPaths") <= 64);
ALTER TABLE "sandbox_template_revision" ADD CONSTRAINT "sandbox_revision_vm_size_ckece5d0b1" CHECK ("cpuCount" >= 1 AND "cpuCount" <= 32 AND "memoryMiB" >= 512 AND "memoryMiB" <= 65536 AND "memoryMiB" % 256 = 0);
ALTER TABLE "sandbox_template_revision" ADD CONSTRAINT "sandbox_revision_root_disk_ck093d92a5" CHECK ("minDiskGiB" >= 1 AND "minDiskGiB" <= "defaultDiskGiB" AND "defaultDiskGiB" <= 2048);
ALTER TABLE "sandbox_template_revision" ADD CONSTRAINT "sandbox_revision_number_ckd4d6dbf3" CHECK ("revision" > 0 AND "guestUid" > 0 AND "guestGid" > 0);
ALTER TABLE "sandbox_template_revision" ADD CONSTRAINT "sandbox_revision_template_build_ck51f21c23" CHECK (("sourceKind"::text = 'BUILD') = ("buildId" IS NOT NULL) AND ("buildId" IS NULL OR "recipeDigest" ~ '^[0-9a-f]{64}$') AND ("defaultCwd" IS NULL OR ("defaultCwd" LIKE '/%' AND octet_length("defaultCwd") <= 4096)) AND ("startCmd" IS NULL OR octet_length("startCmd") <= 4096) AND ("readyCmd" IS NULL OR octet_length("readyCmd") <= 4096) AND ("readyTimeoutMs" IS NULL OR "readyTimeoutMs" BETWEEN 1000 AND 600000));
ALTER TABLE "sandbox_template_revision" ADD CONSTRAINT "sandbox_revision_retired_reason_ck8496a093" CHECK ("retiredReason" IS NULL OR "retiredReason" IN ('manual', 'retention', 'auto_prune', 'verify_failed', 'superseded'));
ALTER TABLE "sandbox_template_revision" ADD CONSTRAINT "sandbox_revision_upstream_ck893d07c9" CHECK ("sourceKind"::text <> 'UPSTREAM' OR ("parentRevisionId" IS NULL AND "buildId" IS NULL AND "pendingVerifyBuildId" IS NULL AND "captureTag" IS NULL));
ALTER TABLE "sandbox_template_revision" ADD CONSTRAINT "sandbox_revision_wssp_recipe_ck3b3bbca3" CHECK (NOT "builtWithWsspRecipe" OR ("sourceKind"::text = 'BUILD' AND "builtWithRoot" AND NOT "capturedWithGuestRoot" AND NOT "builtOnForeignHost"));
ALTER TABLE "sandbox_upstream_image" ADD CONSTRAINT "sandbox_upstream_image_bounds_ck63167d2e" CHECK ("metaSize" > 0 AND "metaSize" <= 1048576 AND "diskSize" > 0 AND "diskSize" <= 4294967296 AND "fingerprint" ~ '^sha256:[0-9a-f]{64}$' AND "metaSha256" ~ '^[0-9a-f]{64}$' AND "diskSha256" ~ '^[0-9a-f]{64}$' AND octet_length("metaPath") <= 512 AND octet_length("diskPath") <= 512 AND length("version") <= 64);
ALTER TABLE "sandbox_template_availability" ADD CONSTRAINT "sandbox_availability_host_owner_ck99fc7735" CHECK ("hostOwnerId" IS NOT NULL);
ALTER TABLE "sandbox_template_availability" ADD CONSTRAINT "sandbox_availability_image_facts_ckb5ee3538" CHECK (("sizeBytes" IS NULL OR "sizeBytes" > 0) AND ("imageFormat" IS NULL OR "imageFormat" IN ('unified', 'split')));
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_vm_size_ckece5d0b1" CHECK ("cpuCount" >= 1 AND "cpuCount" <= 32 AND "memoryMiB" >= 512 AND "memoryMiB" <= 65536 AND "memoryMiB" % 256 = 0);
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_charges_ckae0feaad" CHECK (("chargedMemoryMiB" IS NULL AND "chargedVcpu" IS NULL) OR ("chargedMemoryMiB" IS NOT NULL AND "chargedMemoryMiB" >= "memoryMiB" AND "chargedMemoryMiB" <= 2147483647 AND "chargedVcpu" IS NOT NULL AND "chargedVcpu" = "cpuCount"));
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_disk_size_ck6734e9b5" CHECK ("diskGiB" >= 1 AND "diskGiB" <= 2048);
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_root_charge_ck2d37e5f8" CHECK ("rootChargeGiB" IS NULL OR ("rootChargeGiB" >= "diskGiB" AND "rootChargeGiB" <= 2147483647));
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_host_owner_ck99fc7735" CHECK ("hostOwnerId" IS NOT NULL);
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_grace_ck8a83bc39" CHECK ("acceptedGraceSeconds" >= 0 AND "acceptedGraceSeconds" <= 2592000);
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_image_fetch_ck59490dce" CHECK ("imageFetchBytes" IS NULL OR "imageFetchBytes" > 0);
ALTER TABLE "sandbox_placement" ADD CONSTRAINT "sandbox_placement_direct_ck8d2ac733" CHECK ("generation" > 0 AND (("kind" = 'DIRECT' AND "originPoolId" IS NULL AND "originMemberId" IS NULL) OR ("kind" = 'POOL' AND "originPoolId" IS NOT NULL AND "originMemberId" IS NOT NULL)));
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_waiting_ck826cd28c" CHECK (state::text <> 'WAITING_FOR_CAPACITY' OR ("sandboxHostId" IS NULL AND "hostOwnerId" IS NULL AND "originHostId" IS NULL AND "currentPlacementId" IS NULL AND "usagePoolId" IS NULL AND "usageMemberId" IS NULL AND "storagePoolId" IS NULL AND NOT "liveResourcesHeld" AND NOT "diskReservationHeld" AND "leaseExpiresAt" IS NULL AND "leaseExpiresAtRequested" IS NULL AND "leaseExpiresAtEffective" IS NULL));
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_origin_host_ckca04d942" CHECK ("originHostId" IS NOT NULL OR "currentPlacementId" IS NULL);
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_host_owner_ckd5a787fc" CHECK ("sandboxHostId" IS NULL OR "hostOwnerId" IS NOT NULL);
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_lease_bound_ckad685b46" CHECK ("leaseExpiresAt" IS NULL OR "leaseExpiresAt" <= '9999-12-31 23:59:59.999');
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_access_reason_ck9c129d71" CHECK (("accessGraceUntil" IS NULL AND "accessGraceReason" IS NULL) OR ("accessGraceUntil" IS NOT NULL AND "accessGraceReason" IS NOT NULL AND "accessGraceReason" = 'access'));
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_origin_pool_ckd7232f90" CHECK ("originPoolId" IS NULL OR length("originPoolId") > 0);
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_generation_ck8b8a1c5b" CHECK ("generation" > 0 AND "leaseRevision" > 0);
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_vm_size_ckece5d0b1" CHECK ("cpuCount" >= 1 AND "cpuCount" <= 32 AND "memoryMiB" >= 512 AND "memoryMiB" <= 65536 AND "memoryMiB" % 256 = 0);
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_disk_hold_ck7d2fa087" CHECK (NOT "diskReservationHeld" OR ("sandboxHostId" IS NOT NULL AND "storagePoolId" IS NOT NULL AND "storageMarker" IS NOT NULL AND "storagePoolName" IS NOT NULL AND "rootChargeGiB" IS NOT NULL));
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_build_ck8a5ee703" CHECK ((purpose::text = 'TEMPLATE_BUILD') = ("buildId" IS NOT NULL));
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_verify_ck159b7032" CHECK ((purpose::text = 'TEMPLATE_VERIFY') = ("verifyBuildId" IS NOT NULL) AND ("verifyBuildId" IS NULL OR "buildId" IS NULL));
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_guest_sudo_ck9a7b7ba1" CHECK (NOT "guestSudo" OR ("purpose"::text = 'WORKLOAD' AND "guestRoot" AND "guestSudoRequested"));
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_guest_sudo_reason_ck3f92eb02" CHECK ("guestSudoReason" IS NULL OR ("guestSudoRequested" AND NOT "guestSudo"));
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_egress_denied_ckb77d0662" CHECK (cardinality("egressDeniedGrants") <= 128);
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_disk_size_ck6734e9b5" CHECK ("diskGiB" >= 1 AND "diskGiB" <= 2048);
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_root_charge_ck2d37e5f8" CHECK ("rootChargeGiB" IS NULL OR ("rootChargeGiB" >= "diskGiB" AND "rootChargeGiB" <= 2147483647));
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_name_ck8561035c" CHECK (length("name") BETWEEN 1 AND 63 AND "name" ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$');
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_offloaded_ck2e0c6813" CHECK (state::text <> 'OFFLOADED' OR ("sandboxHostId" IS NULL AND "hostOwnerId" IS NULL AND "currentPlacementId" IS NULL AND "usagePoolId" IS NULL AND "usageMemberId" IS NULL AND "storagePoolId" IS NULL AND NOT "liveResourcesHeld" AND NOT "diskReservationHeld" AND "leaseExpiresAt" IS NULL AND "leaseExpiresAtRequested" IS NULL AND "leaseExpiresAtEffective" IS NULL AND "accessGraceUntil" IS NULL AND "accessGraceReason" IS NULL AND "diskOffloadId" IS NOT NULL));
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_deleted_offload_ck63856e1a" CHECK (state::text <> 'DELETED' OR "diskOffloadId" IS NULL);
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_offload_parked_cka27fab46" CHECK ("diskOffloadId" IS NULL OR state::text IN ('STOPPED', 'STOPPING', 'PROVISIONING', 'ERROR', 'OFFLOADED'));
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_offload_seq_ck8f49bca7" CHECK ("offloadSeq" >= 0);
ALTER TABLE "sandbox_instance" ADD CONSTRAINT "sandbox_instance_offload_policy_ckcecbf3c8" CHECK (("offloadMode"::text = 'AFTER') = ("offloadAfterMs" IS NOT NULL) AND ("offloadAfterMs" IS NULL OR "offloadAfterMs" BETWEEN 60000 AND 2073600000));
ALTER TABLE "sandbox_mutation_operation" ADD CONSTRAINT "sandbox_operation_progress_ckb9dcf07b" CHECK (("progressPhase" IS NULL OR "progressPhase" IN ('fetching_image', 'importing_image', 'freezing', 'snapshotting', 'copying', 'scrubbing', 'publishing', 'uploading', 'finalizing', 'exporting_disk', 'uploading_disk', 'fetching_disk', 'importing_disk')) AND ("progressBytesDone" IS NULL OR "progressBytesDone" >= 0) AND ("progressBytesTotal" IS NULL OR "progressBytesTotal" >= 0));
ALTER TABLE "sandbox_mutation_operation" ADD CONSTRAINT "sandbox_operation_launch_mode_ck238adc20" CHECK ("restoreOffloadId" IS NULL OR ("kind"::text = 'RECONNECT_SANDBOX' AND "launchMode"::text = 'NEW_ROOT'));
ALTER TABLE "sandbox_browser_terminal_ticket" ADD CONSTRAINT "sandbox_terminal_resume_target_ckd2f5f081" CHECK (("resumeTerminalId" IS NULL AND "resumeOutputSeq" IS NULL) OR ("resumeTerminalId" IS NOT NULL AND "resumeOutputSeq" IS NOT NULL AND "resumeOutputSeq" >= 0));
ALTER TABLE "sandbox_browser_terminal_ticket" ADD CONSTRAINT "sandbox_terminal_transport_ck936a2b29" CHECK (("hostOwnerId" IS NULL AND "epoch" IS NULL) OR ("hostOwnerId" IS NOT NULL AND "epoch" IS NOT NULL AND "epoch" >= 0));
ALTER TABLE "sandbox_pool" ADD CONSTRAINT "sandbox_pool_grace_ckca7681d2" CHECK ("disconnectGraceSeconds" >= 0 AND "disconnectGraceSeconds" <= 2592000);
ALTER TABLE "sandbox_pool" ADD CONSTRAINT "sandbox_pool_max_lease_ck8d9ee741" CHECK ("maxLeaseMs" IS NULL OR "maxLeaseMs" BETWEEN 300000 AND 2073600000);
ALTER TABLE "sandbox_pool" ADD CONSTRAINT "sandbox_pool_capacity_wait_ck5990dd80" CHECK (("capacityWaitMaxMs" IS NULL OR "capacityWaitMaxMs" BETWEEN 0 AND 2073600000) AND ("capacityQueuePerKeyMax" IS NULL OR "capacityQueuePerKeyMax" BETWEEN 0 AND 100000) AND ("capacityQueuePerOwnerMax" IS NULL OR "capacityQueuePerOwnerMax" BETWEEN 0 AND 100000));
ALTER TABLE "sandbox_pool" ADD CONSTRAINT "sandbox_pool_image_cache_ck1e148397" CHECK ("memberImageCacheMaxGiB" IS NULL OR "memberImageCacheMaxGiB" BETWEEN 0 AND 1048576);
ALTER TABLE "sandbox_pool_member" ADD CONSTRAINT "sandbox_member_identity_ck15fd45a6" CHECK ("hostOwnerId" IS NOT NULL AND (("hostOwnerId" = "userId" AND "shareId" IS NULL AND "contributeWitness" IS NULL AND "ownHostsOnlyWitness" IS NULL AND "memoryCapPercent" IS NULL AND "vcpuCapPercent" IS NULL) OR ("hostOwnerId" <> "userId" AND (("removedAt" IS NOT NULL AND "shareId" IS NULL AND "contributeWitness" IS NULL AND "ownHostsOnlyWitness" IS NULL) OR ("removedAt" IS NULL AND "shareId" IS NOT NULL AND "contributeWitness" IS TRUE AND "ownHostsOnlyWitness" IS FALSE)))));
ALTER TABLE "sandbox_pool_member" ADD CONSTRAINT "sandbox_member_caps_ck967df8a0" CHECK (("memoryCapPercent" IS NULL OR "memoryCapPercent" BETWEEN 1 AND 100) AND ("vcpuCapPercent" IS NULL OR "vcpuCapPercent" BETWEEN 1 AND 100));
ALTER TABLE "sandbox_pool_member" ADD CONSTRAINT "sandbox_member_max_lease_ck8d9ee741" CHECK ("maxLeaseMs" IS NULL OR "maxLeaseMs" BETWEEN 300000 AND 2073600000);
ALTER TABLE "sdk_key_pool_allowlist" ADD CONSTRAINT "sdk_pool_grant_identity_ck0f63d7ed" CHECK ("poolOwnerId" IS NOT NULL AND (("poolOwnerId" = "userId" AND "shareId" IS NULL AND "useWitness" IS NULL) OR ("poolOwnerId" <> "userId" AND "shareId" IS NOT NULL AND "useWitness" IS TRUE)));
ALTER TABLE "share" ADD CONSTRAINT "share_identity_ck9d52e4e1" CHECK ("ownerUserId" <> "granteeUserId" AND ("canUse" OR "canContribute"));
ALTER TABLE "share" ADD CONSTRAINT "share_caps_ck66da48f1" CHECK (("maxMemoryMiB" IS NULL OR "maxMemoryMiB" BETWEEN 1 AND 16777216) AND ("maxVcpu" IS NULL OR "maxVcpu" BETWEEN 1 AND 8192) AND ("maxDiskGiB" IS NULL OR "maxDiskGiB" BETWEEN 1 AND 268435456));
ALTER TABLE "share_invite" ADD CONSTRAINT "share_invite_permissions_ck09659a5a" CHECK ("canUse" OR "canContribute");
ALTER TABLE "share_invite" ADD CONSTRAINT "share_invite_caps_ck66da48f1" CHECK (("maxMemoryMiB" IS NULL OR "maxMemoryMiB" BETWEEN 1 AND 16777216) AND ("maxVcpu" IS NULL OR "maxVcpu" BETWEEN 1 AND 8192) AND ("maxDiskGiB" IS NULL OR "maxDiskGiB" BETWEEN 1 AND 268435456));
ALTER TABLE "share_invite" ADD CONSTRAINT "share_invite_email_cka1dab136" CHECK ("email" = lower(btrim("email")) AND length("email") BETWEEN 3 AND 320 AND position('@' in "email") > 1);
ALTER TABLE "share_invite" ADD CONSTRAINT "share_invite_digest_ck4de4417c" CHECK ("tokenDigest" ~ '^[0-9a-f]{64}$');
ALTER TABLE "share_invite" ADD CONSTRAINT "share_invite_state_cka40f7951" CHECK ("expiresAt" > "createdAt" AND (("acceptedAt" IS NULL AND "revokedAt" IS NULL AND "expiredAt" IS NULL AND "pendingKey" IS NOT NULL AND "acceptedByUserId" IS NULL AND "acceptedShareId" IS NULL) OR ("pendingKey" IS NULL AND (("acceptedAt" IS NOT NULL AND "revokedAt" IS NULL AND "expiredAt" IS NULL AND "acceptedByUserId" IS NOT NULL AND "acceptedShareId" IS NOT NULL) OR ("acceptedAt" IS NULL AND "acceptedByUserId" IS NULL AND "acceptedShareId" IS NULL AND num_nonnulls("revokedAt", "expiredAt") = 1)))));
ALTER TABLE "host_terminal_ticket" ADD CONSTRAINT "host_terminal_ticket_binding_ck17919674" CHECK ("userId" = "hostOwnerId" AND "epoch" >= 0 AND "rows" BETWEEN 1 AND 512 AND "cols" BETWEEN 1 AND 1024 AND "policyRevision" >= 0 AND "tokenDigest" ~ '^[0-9a-f]{64}$' AND "expiresAt" > "createdAt");
ALTER TABLE "host_terminal_ticket" ADD CONSTRAINT "host_terminal_ticket_proof_ck6b28210c" CHECK (("proofRequired" AND "verifiedAt" IS NOT NULL AND "factorFingerprint" IS NOT NULL AND "observedAt" IS NOT NULL) OR (NOT "proofRequired" AND "verifiedAt" IS NULL AND "factorFingerprint" IS NULL AND "observedAt" IS NULL));
ALTER TABLE "sandbox_host_storage_pool" ADD CONSTRAINT "sandbox_storage_capacity_ckff014cf9" CHECK ("capacityGiB" >= 0 AND "capacityGiB" <= 1048576 AND "diskReservedGiB" >= 0 AND "diskReservedGiB" <= 2147483647 AND ("totalBasedCapacityGiB" IS NULL OR "totalBasedCapacityGiB" >= 0) AND ("implicitCeilingGiB" IS NULL OR "implicitCeilingGiB" >= 0));
ALTER TABLE "sandbox_host_storage_pool" ADD CONSTRAINT "sandbox_storage_identity_ck5b3a51b4" CHECK (length("name") >= 1 AND length("name") <= 63 AND length("marker") >= 1 AND length("marker") <= 128);
ALTER TABLE "sandbox_host_storage_pool" ADD CONSTRAINT "sandbox_storage_report_ck25ed76cd" CHECK ("connectionEpoch" > 0 AND "observationSequence" >= 0 AND "observationSequence" <= 9007199254740991 AND "health" IN ('healthy', 'unavailable') AND ("healthReason" IS NULL OR "healthReason" IN ('missing', 'identity', 'permission', 'unsupported', 'io', 'incomplete')));
ALTER TABLE "sandbox_host_storage_pool" ADD CONSTRAINT "sandbox_storage_usage_ckcb1f54d7" CHECK (("totalBytes" IS NULL AND "usedBytes" IS NULL AND "freeBytes" IS NULL) OR ("totalBytes" IS NOT NULL AND "usedBytes" IS NOT NULL AND "freeBytes" IS NOT NULL AND "totalBytes" > 0 AND "usedBytes" >= 0 AND "usedBytes" <= "totalBytes" AND "freeBytes" = "totalBytes" - "usedBytes"));
ALTER TABLE "sandbox_host_storage_pool" ADD CONSTRAINT "sandbox_storage_derivation_ckf08da31a" CHECK (("capacitySource" = 'explicit' AND "capacityGiB" > 0 AND "totalBasedCapacityGiB" IS NULL AND "derivationTotalBytes" IS NULL AND "derivationFreeBytes" IS NULL AND "derivationCommittedBytes" IS NULL AND "derivationActualBytes" IS NULL AND "derivationHeadroomBytes" IS NULL AND "implicitCeilingGiB" IS NULL) OR ("capacitySource" = 'implicit' AND "totalBasedCapacityGiB" IS NOT NULL AND "derivationTotalBytes" IS NOT NULL AND "derivationFreeBytes" IS NOT NULL AND "derivationCommittedBytes" IS NOT NULL AND "derivationActualBytes" IS NOT NULL AND "derivationHeadroomBytes" IS NOT NULL AND "implicitCeilingGiB" IS NOT NULL AND "derivationTotalBytes" > 0 AND "derivationFreeBytes" >= 0 AND "derivationFreeBytes" <= "derivationTotalBytes" AND "derivationCommittedBytes" >= 0 AND "derivationActualBytes" >= 0 AND "derivationActualBytes" <= "derivationCommittedBytes" AND "derivationHeadroomBytes" >= 0 AND "derivationHeadroomBytes" <= "derivationTotalBytes" AND "capacityGiB" <= "totalBasedCapacityGiB" AND "capacityGiB" <= "implicitCeilingGiB"));
ALTER TABLE "sandbox_image_artifact" ADD CONSTRAINT "sandbox_image_artifact_fingerprint_ck87b816aa" CHECK ("fingerprint" ~ '^sha256:[0-9a-f]{64}$' AND "format" = 'unified');
ALTER TABLE "sandbox_image_artifact" ADD CONSTRAINT "sandbox_image_artifact_stored_ck65a022ef" CHECK ("state"::text <> 'STORED' OR ("objectKey" IS NOT NULL AND "verifiedAt" IS NOT NULL AND "storeKind"::text = 'S3'));
ALTER TABLE "sandbox_image_artifact" ADD CONSTRAINT "sandbox_image_artifact_encryption_ckbce1a6c5" CHECK (("encryption" IS NULL AND "wrappedKey" IS NULL AND "wrappedKeyNonce" IS NULL AND "keyId" IS NULL) OR ("encryption" = 'aes256gcm-r1' AND "wrappedKey" IS NOT NULL AND "wrappedKeyNonce" IS NOT NULL AND "keyId" IS NOT NULL));
ALTER TABLE "sandbox_image_artifact" ADD CONSTRAINT "sandbox_image_artifact_sizes_ckbfeccfee" CHECK ("sizeBytes" > 0 AND ("unpackedBytes" IS NULL OR "unpackedBytes" > 0) AND ("partSize" IS NULL OR "partSize" > 0) AND "corruptReports" >= 0);
ALTER TABLE "sandbox_image_upload_session" ADD CONSTRAINT "sandbox_image_upload_session_target_ck06e72383" CHECK (("artifactId" IS NULL) <> ("diskOffloadId" IS NULL));
ALTER TABLE "sandbox_image_upload_session" ADD CONSTRAINT "sandbox_image_upload_session_live_ck89aac608" CHECK (("state"::text = 'OPEN') = (COALESCE("liveArtifactId", "liveDiskOffloadId") IS NOT NULL) AND ("liveArtifactId" IS NULL OR "liveArtifactId" = "artifactId") AND ("liveDiskOffloadId" IS NULL OR "liveDiskOffloadId" = "diskOffloadId"));
ALTER TABLE "sandbox_image_upload_session" ADD CONSTRAINT "sandbox_image_upload_session_disk_key_ck443cfa00" CHECK (CASE WHEN "diskOffloadId" IS NULL THEN "wrapSalt" IS NULL ELSE ("state"::text = 'OPEN') = ("wrappedKey" IS NOT NULL) AND ("wrappedKey" IS NULL) = ("wrapSalt" IS NULL) AND ("wrappedKey" IS NULL OR "encryption" = 'aes256gcm-r1') END);
ALTER TABLE "sandbox_image_upload_session" ADD CONSTRAINT "sandbox_image_upload_session_encryption_ckbce1a6c5" CHECK (("encryption" IS NULL AND "wrappedKey" IS NULL AND "wrappedKeyNonce" IS NULL AND "keyId" IS NULL) OR ("encryption" = 'aes256gcm-r1' AND "wrappedKey" IS NOT NULL AND "wrappedKeyNonce" IS NOT NULL AND "keyId" IS NOT NULL));
ALTER TABLE "sandbox_image_upload_session" ADD CONSTRAINT "sandbox_image_upload_session_sizes_cka6bb2748" CHECK ("sizeBytes" > 0 AND "storedBytes" >= "sizeBytes" AND "partSize" > 0 AND "hostEpoch" > 0);
ALTER TABLE "sandbox_image_upload_part" ADD CONSTRAINT "sandbox_image_upload_part_ckb0317c8b" CHECK ("partNumber" BETWEEN 1 AND 10000 AND "sizeBytes" > 0 AND length("etag") BETWEEN 1 AND 256);
ALTER TABLE "sandbox_host_image_cache" ADD CONSTRAINT "sandbox_host_image_cache_entry_cka237c952" CHECK ("fingerprint" ~ '^sha256:[0-9a-f]{64}$' AND "compressedBytes" >= 0 AND ("unpackedBytes" IS NULL OR "unpackedBytes" >= 0) AND "origin" IN ('fetched', 'captured', 'replica') AND "connectionEpoch" > 0);
ALTER TABLE "sandbox_image_transfer" ADD CONSTRAINT "sandbox_image_transfer_shape_ck01776d3f" CHECK ("fingerprint" ~ '^sha256:[0-9a-f]{64}$' AND "mode" IN ('S3', 'RELAY') AND "sizeBytes" > 0 AND "partSize" > 0 AND "partCount" BETWEEN 1 AND 10000 AND "bytesDone" >= 0 AND "bytesDone" <= "sizeBytes");
ALTER TABLE "sandbox_image_link" ADD CONSTRAINT "sandbox_image_link_shape_ck9e5a0d60" CHECK ("role" IN ('SOURCE', 'DEST') AND "partNumber" BETWEEN 1 AND 10000 AND "tokenDigest" ~ '^[0-9a-f]{64}$' AND "expiresAt" > "createdAt" AND "hostEpoch" > 0);
ALTER TABLE "sandbox_template_capture" ADD CONSTRAINT "sandbox_template_capture_shape_ckbb831d5d" CHECK (cardinality("scrubPaths") <= 80 AND "chargedMemoryMiB" >= 0 AND "chargedVcpu" >= 0 AND "diskChargeGiB" >= 0 AND ("fingerprint" IS NULL OR "fingerprint" ~ '^sha256:[0-9a-f]{64}$') AND (NOT "resourcesHeld" OR "storagePoolId" IS NOT NULL OR "diskChargeGiB" = 0));
ALTER TABLE "sandbox_template_capture" ADD CONSTRAINT "sandbox_template_capture_build_attempt_ck67c06fdb" CHECK ("buildAttempt" >= 0 AND ("buildId" IS NOT NULL OR "buildAttempt" = 0));
ALTER TABLE "sandbox_template_capture" ADD CONSTRAINT "sandbox_template_capture_default_disk_ckca9d5ce0" CHECK ("defaultDiskGiB" IS NULL OR ("defaultDiskGiB" >= 1 AND "defaultDiskGiB" <= 2048));
ALTER TABLE "sandbox_capacity_wait" ADD CONSTRAINT "sandbox_capacity_wait_intent_ck3be86db2" CHECK ((state::text = 'WAITING' AND "intent" IS NOT NULL AND "endedAt" IS NULL) OR (state::text <> 'WAITING' AND "intent" IS NULL AND "endedAt" IS NOT NULL));
ALTER TABLE "sandbox_capacity_wait" ADD CONSTRAINT "sandbox_capacity_wait_bypass_ck70dd6c14" CHECK ("bypassCount" >= 0);
ALTER TABLE "sandbox_capacity_wait" ADD CONSTRAINT "sandbox_capacity_wait_deadline_cka867a222" CHECK ("deadlineAt" IS NULL OR "deadlineAt" > "enqueuedAt");
ALTER TABLE "sandbox_capacity_wait" ADD CONSTRAINT "sandbox_capacity_wait_blocker_ckae9d1643" CHECK ("lastBlocker" IS NULL OR "lastBlocker" IN ('ram', 'vcpu', 'disk', 'storage', 'ceiling', 'reserved', 'member_quota', 'share_quota', 'unavailable', 'image_rebuilding'));
ALTER TABLE "sandbox_disk_offload" ADD CONSTRAINT "sandbox_disk_offload_stored_cke2a557ff" CHECK ("state"::text NOT IN ('STORED', 'EVICTING') OR ("objectKey" IS NOT NULL AND "verifiedAt" IS NOT NULL AND "encryption" = 'aes256gcm-r1' AND "wrappedKey" IS NOT NULL AND "wrapSalt" IS NOT NULL AND "wrapNonce" IS NOT NULL AND "rootKid" IS NOT NULL AND "fingerprint" ~ '^sha256:[0-9a-f]{64}$'));
ALTER TABLE "sandbox_disk_offload" ADD CONSTRAINT "sandbox_disk_offload_evict_ck8ec7d190" CHECK (("state"::text = 'EVICTING') = ("evictGrantId" IS NOT NULL) AND ("evictGrantId" IS NULL OR ("evictHostId" IS NOT NULL AND "evictGrantEpoch" > 0 AND "evictGrantExpiresAt" IS NOT NULL)));
ALTER TABLE "sandbox_disk_offload" ADD CONSTRAINT "sandbox_disk_offload_live_cke6cf7213" CHECK (("liveSandboxId" IS NULL) = ("state"::text IN ('CONSUMED', 'SUPERSEDED', 'FAILED', 'DELETING', 'DELETED')) AND ("liveSandboxId" IS NULL OR "liveSandboxId" = "sandboxId"));
ALTER TABLE "sandbox_disk_offload" ADD CONSTRAINT "sandbox_disk_offload_shredded_ck76fcd57f" CHECK ("shreddedAt" IS NULL OR ("wrappedKey" IS NULL AND "wrapSalt" IS NULL AND "wrapNonce" IS NULL));
ALTER TABLE "sandbox_disk_offload" ADD CONSTRAINT "sandbox_disk_offload_wrap_all_ck1a592c76" CHECK (("wrappedKey" IS NULL) = ("wrapSalt" IS NULL) AND ("wrappedKey" IS NULL) = ("wrapNonce" IS NULL) AND ("wrappedKey" IS NULL OR "completedSessionId" IS NOT NULL));
ALTER TABLE "sandbox_restore_wait" ADD CONSTRAINT "sandbox_restore_wait_intent_ck3be86db2" CHECK ((state::text = 'WAITING' AND "intent" IS NOT NULL AND "endedAt" IS NULL) OR (state::text <> 'WAITING' AND "intent" IS NULL AND "endedAt" IS NOT NULL));
ALTER TABLE "sandbox_restore_wait" ADD CONSTRAINT "sandbox_restore_wait_deadline_ckb6bfa91a" CHECK ("deadlineAt" > "enqueuedAt");
ALTER TABLE "tunnel_server_config" ADD CONSTRAINT "tunnel_server_config_singleton_ckea4e5f4a" CHECK (id = 'default');
ALTER TABLE "tunnel_server_config" ADD CONSTRAINT "tunnel_server_config_max_per_owner_ckc5447fae" CHECK ("maxTunnelsPerOwner" >= 1 AND "maxTunnelsPerOwner" <= 1000);
ALTER TABLE "sandbox_tunnel" ADD CONSTRAINT "sandbox_tunnel_ports_ckd13c90d1" CHECK (cardinality(ports) >= 1 AND cardinality(ports) <= 8);
ALTER TABLE "sandbox_tunnel" ADD CONSTRAINT "sandbox_tunnel_generation_ck8313aadc" CHECK (generation >= 0);
ALTER TABLE "sandbox_tunnel" ADD CONSTRAINT "sandbox_tunnel_server_key_ckc4e7c91e" CHECK ("serverKey" IS NOT NULL OR ("tunTunnelId" IS NULL AND NOT "sweepLabel" AND "creatingUntil" IS NULL));
-- wssp:initial-checks-end

-- wssp:initial-hardening-begin
-- Row triggers run after PostgreSQL has locked the source row. NOWAIT on earlier
-- G refuses raw writers that would otherwise invert G -> permission/member RI locks.
-- Service writers already hold their sorted G prefix and reuse it here.
-- Reviewed cross-row enforcement, installed once by this committed migration.
-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE OR REPLACE FUNCTION public.wssp_share_guard() RETURNS trigger LANGUAGE plpgsql AS $wssp$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM id FROM sandbox_pool WHERE id = NEW."poolId" AND "userId" = NEW."ownerUserId" AND "deletedAt" IS NULL FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'share pool unavailable'; END IF;
    RETURN NEW;
  END IF;
  PERFORM id FROM sandbox_pool WHERE id = OLD."poolId" FOR UPDATE NOWAIT;
  IF TG_OP = 'UPDATE' AND (NEW.id, NEW."poolId", NEW."ownerUserId", NEW."granteeUserId") IS DISTINCT FROM (OLD.id, OLD."poolId", OLD."ownerUserId", OLD."granteeUserId") THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'share identity is immutable';
  END IF;
  IF TG_OP = 'DELETE' OR NOT NEW."canContribute" THEN
    UPDATE sandbox_pool_member SET "removedAt" = COALESCE("removedAt", clock_timestamp()), enabled = false,
      "shareId" = NULL, "contributeWitness" = NULL, "ownHostsOnlyWitness" = NULL
      WHERE "shareId" = OLD.id;
  END IF;
  IF TG_OP = 'DELETE' OR NOT NEW."canUse" THEN
    DELETE FROM sdk_key_pool_allowlist WHERE "shareId" = OLD.id;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $wssp$;

-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE OR REPLACE FUNCTION public.wssp_pool_guard() RETURNS trigger LANGUAGE plpgsql AS $wssp$
BEGIN
  IF TG_OP = 'UPDATE' AND (NEW.id, NEW."userId") IS DISTINCT FROM (OLD.id, OLD."userId") THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'pool identity is immutable';
  END IF;
  IF TG_OP = 'DELETE' OR NEW."ownHostsOnly" OR NEW."deletedAt" IS NOT NULL THEN
    UPDATE sandbox_pool_member SET "removedAt" = COALESCE("removedAt", clock_timestamp()), enabled = false,
      "shareId" = NULL, "contributeWitness" = NULL, "ownHostsOnlyWitness" = NULL
      WHERE "poolId" = OLD.id AND "hostOwnerId" <> "userId" AND "removedAt" IS NULL;
  END IF;
  IF TG_OP = 'DELETE' OR NEW."deletedAt" IS NOT NULL THEN
    DELETE FROM sdk_key_pool_allowlist WHERE "poolId" = OLD.id;
    UPDATE share_invite SET "revokedAt" = clock_timestamp(), "pendingKey" = NULL
      WHERE "poolId" = OLD.id AND "pendingKey" IS NOT NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $wssp$;

-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE OR REPLACE FUNCTION public.wssp_invite_guard() RETURNS trigger LANGUAGE plpgsql AS $wssp$
BEGIN
  PERFORM id FROM sandbox_pool WHERE id = NEW."poolId" AND "userId" = NEW."ownerUserId" AND "deletedAt" IS NULL FOR UPDATE NOWAIT;
  IF NOT FOUND AND NEW."pendingKey" IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invite pool unavailable';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.id, NEW."poolId", NEW."ownerUserId", NEW.email, NEW."signupAllowed") IS DISTINCT FROM (OLD.id, OLD."poolId", OLD."ownerUserId", OLD.email, OLD."signupAllowed") THEN
      RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invite identity is immutable';
    END IF;
    IF OLD."pendingKey" IS NULL AND NEW IS DISTINCT FROM OLD THEN
      RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'terminal invite is immutable';
    END IF;
  END IF;
  IF NEW."pendingKey" IS NOT NULL AND NEW."pendingKey" <> NEW."poolId" || ':' || NEW.email THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid invite pending key';
  END IF;
  IF NEW."acceptedAt" IS NOT NULL AND (TG_OP = 'INSERT' OR OLD."acceptedAt" IS NULL) THEN
    IF TG_OP = 'INSERT' OR OLD."expiresAt" <= clock_timestamp() OR NOT EXISTS (
      SELECT 1 FROM share s WHERE s.id = NEW."acceptedShareId" AND s."poolId" = NEW."poolId"
      AND s."ownerUserId" = NEW."ownerUserId" AND s."granteeUserId" = NEW."acceptedByUserId"
      AND s."canUse" = OLD."canUse" AND s."canContribute" = OLD."canContribute"
      AND s."maxMemoryMiB" IS NOT DISTINCT FROM OLD."maxMemoryMiB"
      AND s."maxVcpu" IS NOT DISTINCT FROM OLD."maxVcpu" AND s."maxDiskGiB" IS NOT DISTINCT FROM OLD."maxDiskGiB"
    ) THEN RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid invite acceptance'; END IF;
  END IF;
  RETURN NEW;
END $wssp$;

-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE OR REPLACE FUNCTION public.wssp_member_guard() RETURNS trigger LANGUAGE plpgsql AS $wssp$
BEGIN
  IF TG_OP = 'UPDATE' AND (NEW.id, NEW."poolId", NEW."userId", NEW."sandboxHostId", NEW."hostOwnerId") IS DISTINCT FROM (OLD.id, OLD."poolId", OLD."userId", OLD."sandboxHostId", OLD."hostOwnerId") THEN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'member identity is immutable';
  END IF;
  IF NEW."removedAt" IS NOT NULL THEN
    NEW."shareId" := NULL; NEW."contributeWitness" := NULL; NEW."ownHostsOnlyWitness" := NULL;
  END IF;
  RETURN NEW;
END $wssp$;

-- Webhook emission (docs/design/webhooks-contract.md). AFTER row triggers on the
-- two state columns insert one webhook_event per subscribed type inside the
-- writer's transaction: a rollback emits nothing and every writer (including raw
-- SQL) is covered. webhook_event has no foreign keys and the endpoint probe is a
-- plain SELECT, so these triggers take no row locks beyond the event insert and
-- leave the H -> S -> O and owner lock order untouched. If the webhook tables are
-- ever dropped the functions return early instead of breaking sandbox writes;
-- removing the feature needs explicit trigger/function removal in a migration.
--
-- The pre-READY state list lives only here. It is text, not enum literals, so it
-- may name states a later schema adds (WAITING_FOR_CAPACITY, capacity queue).
-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE OR REPLACE FUNCTION public.wssp_webhook_pre_ready_states() RETURNS text[] LANGUAGE sql IMMUTABLE AS $wssp$
  SELECT ARRAY['REQUESTED', 'SCHEDULED', 'PROVISIONING', 'WAITING_FOR_CAPACITY']::text[]
$wssp$;

-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE OR REPLACE FUNCTION public.wssp_webhook_sandbox_event() RETURNS trigger LANGUAGE plpgsql AS $wssp$
DECLARE
  from_state text := CASE WHEN TG_OP = 'UPDATE' THEN OLD.state::text END;
  to_state text := NEW.state::text;
  t text;
  types text[] := '{}';
BEGIN
  IF to_regclass('public.webhook_endpoint') IS NULL OR to_regclass('public.webhook_event') IS NULL THEN RETURN NULL; END IF;
  IF from_state IS NOT DISTINCT FROM to_state THEN RETURN NULL; END IF;
  -- Managed sandboxes (CREDENTIAL_LOGIN, TEMPLATE_BUILD, TEMPLATE_VERIFY) emit no webhooks (MS0).
  IF NEW.purpose::text <> 'WORKLOAD' THEN RETURN NULL; END IF;
  IF to_state = 'READY' THEN types := types || 'sandbox.ready'::text; END IF;
  IF to_state = 'STOPPED' THEN types := types || 'sandbox.stopped'::text; END IF;
  IF NEW."readyAt" IS NULL AND from_state = ANY(public.wssp_webhook_pre_ready_states())
     AND (to_state = 'ERROR' OR (to_state = 'DELETED' AND NEW."lastErrorCode" IS NOT NULL)) THEN
    types := types || 'sandbox.create_failed'::text;
  END IF;
  IF to_state = 'DELETED' THEN types := types || 'sandbox.destroyed'::text; END IF;
  -- Disk offload (R6, T15): only the detach of a stopped sandbox to its store copy.
  IF from_state = 'STOPPED' AND to_state = 'OFFLOADED' THEN types := types || 'sandbox.offloaded'::text; END IF;
  FOREACH t IN ARRAY types LOOP
    IF EXISTS (SELECT 1 FROM webhook_endpoint e WHERE e."userId" = NEW."userId" AND e."disabledAt" IS NULL AND t = ANY(e.events)) THEN
      INSERT INTO webhook_event (id, "userId", type, "sandboxId", "occurredAt", facts)
      VALUES ('evt_' || replace(gen_random_uuid()::text, '-', ''), NEW."userId", t, NEW.id, clock_timestamp() AT TIME ZONE 'UTC',
        jsonb_build_object('from', from_state, 'to', to_state, 'generation', NEW.generation, 'errorCode', NEW."lastErrorCode"));
    END IF;
  END LOOP;
  RETURN NULL;
END $wssp$;

-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE OR REPLACE FUNCTION public.wssp_webhook_operation_event() RETURNS trigger LANGUAGE plpgsql AS $wssp$
DECLARE
  from_state text := CASE WHEN TG_OP = 'UPDATE' THEN OLD.state::text END;
  to_state text := NEW.state::text;
BEGIN
  IF to_regclass('public.webhook_endpoint') IS NULL OR to_regclass('public.webhook_event') IS NULL THEN RETURN NULL; END IF;
  IF from_state IS NOT DISTINCT FROM to_state THEN RETURN NULL; END IF;
  IF to_state NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'UNKNOWN_OUTCOME') THEN RETURN NULL; END IF;
  IF EXISTS (SELECT 1 FROM webhook_endpoint e WHERE e."userId" = NEW."userId" AND e."disabledAt" IS NULL
      AND 'operation.completed' = ANY(e.events)
      AND (cardinality(e."operationKinds") = 0 OR NEW.kind::text = ANY(e."operationKinds"))) THEN
    -- Purpose lookup only after the endpoint probe: the no-endpoint path costs nothing extra.
    IF EXISTS (SELECT 1 FROM sandbox_instance s WHERE s.id = NEW."sandboxId" AND s.purpose::text <> 'WORKLOAD') THEN
      RETURN NULL;
    END IF;
    INSERT INTO webhook_event (id, "userId", type, "sandboxId", "operationId", "occurredAt", facts)
    VALUES ('evt_' || replace(gen_random_uuid()::text, '-', ''), NEW."userId", 'operation.completed', NEW."sandboxId", NEW.id, clock_timestamp() AT TIME ZONE 'UTC',
      jsonb_build_object('from', from_state, 'to', to_state, 'kind', NEW.kind::text, 'generation', NEW.generation, 'errorCode', NEW."errorCode"));
  END IF;
  RETURN NULL;
END $wssp$;

-- CLI-login credential events (the CLI-logins plan §12 N10): one webhook_event
-- per subscribed `credential.<type>` for the four lease outcomes an owner acts
-- on. The facts carry only the event row id; the renderer re-reads that row
-- through a fixed projection (ids and a reason code), so no value, path or
-- host ever reaches a payload. Same lock profile as the triggers above.
-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE OR REPLACE FUNCTION public.wssp_webhook_credential_event() RETURNS trigger LANGUAGE plpgsql AS $wssp$
DECLARE
  t text;
BEGIN
  IF to_regclass('public.webhook_endpoint') IS NULL OR to_regclass('public.webhook_event') IS NULL THEN RETURN NULL; END IF;
  IF NEW.type NOT IN ('capture_failed', 'capture_lost', 'recovery_required', 'needs_login') THEN RETURN NULL; END IF;
  t := 'credential.' || NEW.type;
  IF EXISTS (SELECT 1 FROM webhook_endpoint e WHERE e."userId" = NEW."userId" AND e."disabledAt" IS NULL AND t = ANY(e.events)) THEN
    INSERT INTO webhook_event (id, "userId", type, "sandboxId", "occurredAt", facts)
    VALUES ('evt_' || replace(gen_random_uuid()::text, '-', ''), NEW."userId", t, NEW."sandboxId", clock_timestamp() AT TIME ZONE 'UTC',
      jsonb_build_object('credentialEventId', NEW.id));
  END IF;
  RETURN NULL;
END $wssp$;

-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE OR REPLACE FUNCTION public.wssp_sandbox_stopped_at() RETURNS trigger LANGUAGE plpgsql AS $wssp$
BEGIN
  -- Every entry into STOPPED stamps when the disk went cold: the offload
  -- policy's AFTER clock and the LRU order of exports and evictions.
  IF NEW.state::text = 'STOPPED' AND OLD.state::text IS DISTINCT FROM 'STOPPED' THEN
    NEW."lastStoppedAt" := clock_timestamp() AT TIME ZONE 'UTC';
  END IF;
  RETURN NEW;
END $wssp$;

-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE TRIGGER wssp_share_guard BEFORE INSERT OR UPDATE OR DELETE ON share FOR EACH ROW EXECUTE FUNCTION public.wssp_share_guard();
-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE TRIGGER wssp_pool_guard BEFORE UPDATE OR DELETE ON sandbox_pool FOR EACH ROW EXECUTE FUNCTION public.wssp_pool_guard();
-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE TRIGGER wssp_invite_guard BEFORE INSERT OR UPDATE ON share_invite FOR EACH ROW EXECUTE FUNCTION public.wssp_invite_guard();
-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE TRIGGER wssp_member_guard BEFORE INSERT OR UPDATE ON sandbox_pool_member FOR EACH ROW EXECUTE FUNCTION public.wssp_member_guard();
-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE TRIGGER wssp_webhook_sandbox_event AFTER INSERT OR UPDATE OF state ON sandbox_instance FOR EACH ROW EXECUTE FUNCTION public.wssp_webhook_sandbox_event();
-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE TRIGGER wssp_webhook_operation_event AFTER INSERT OR UPDATE OF state ON sandbox_mutation_operation FOR EACH ROW EXECUTE FUNCTION public.wssp_webhook_operation_event();
-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE TRIGGER wssp_webhook_credential_event AFTER INSERT ON credential_event FOR EACH ROW EXECUTE FUNCTION public.wssp_webhook_credential_event();
-- wssp:reviewed preserve existing sharing and webhook enforcement in the fresh baseline
CREATE TRIGGER wssp_sandbox_stopped_at BEFORE UPDATE OF state ON sandbox_instance FOR EACH ROW EXECUTE FUNCTION public.wssp_sandbox_stopped_at();
-- wssp:initial-hardening-end

-- wssp:commit-marker (lets the runner prove this transaction committed; keep it last)
DO $wssp$ DECLARE history text := current_setting('wssp.history', true); BEGIN IF history <> '' THEN EXECUTE format('UPDATE %s SET "logs" = %L WHERE "id" = (SELECT "id" FROM %s WHERE "finished_at" IS NULL AND "rolled_back_at" IS NULL ORDER BY "started_at" DESC LIMIT 1)', history::oid::regclass, 'wssp:committed', history::oid::regclass); END IF; END $wssp$;
COMMIT;
