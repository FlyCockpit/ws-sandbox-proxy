-- Synthetic migration fixtures. These are not seeds or usable credentials.

BEGIN;

INSERT INTO "user" ("id", "name", "email", "emailVerified", "role", "locale", "hostTerminalLastTotpStep", "createdAt", "updatedAt")
VALUES ('fx_user_admin', 'Álvaro Fixture', 'owner-one@example.test', true, 'user', 'es-MX', 9007199254740991, '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "user" ("id", "name", "email", "emailVerified", "role", "locale", "createdAt", "updatedAt")
VALUES ('fx_user_plain', 'Owner Two', 'owner-two@example.test', false, 'user', 'en-US', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "app_setting" ("key", "value", "createdAt", "updatedAt")
VALUES ('fx.synthetic', '{"empty":"","unicode":"México"}', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "verification" ("id", "identifier", "value", "expiresAt", "createdAt", "updatedAt")
VALUES ('fx_verification', 'fx-expired', 'synthetic-not-a-verification-token', '2020-01-01', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "session" ("id", "userId", "token", "expiresAt", "createdAt", "updatedAt")
VALUES ('fx_session', 'fx_user_admin', 'synthetic-not-a-session-token', '2099-11-12 12:00:00', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "account" ("id", "accountId", "providerId", "userId", "createdAt", "updatedAt")
VALUES ('fx_account', 'fx-account', 'credential', 'fx_user_admin', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "two_factor" ("id", "userId", "secret", "backupCodes", "verified", "createdAt", "updatedAt")
VALUES ('fx_two_factor', 'fx_user_admin', 'synthetic-not-a-totp-secret', '[]', false, '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "device_code" ("id", "deviceCode", "userCode", "userId", "status", "expiresAt", "createdAt", "updatedAt")
VALUES ('fx_device', 'synthetic-device', 'FX-CODE', 'fx_user_admin', 'pending', '2099-11-12 12:00:00', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "push_subscription" ("id", "userId", "endpoint", "p256dh", "auth", "createdAt", "updatedAt")
VALUES ('fx_push', 'fx_user_admin', 'https://push.example.test/fx', 'synthetic-not-a-public-key', 'synthetic-not-an-auth-key', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "account_image_policy" ("userId", "adminStoredGiBMax", "createdAt", "updatedAt")
VALUES ('fx_user_admin', 0, '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sandbox_host" ("id", "userId", "slug", "label", "createdAt", "updatedAt")
VALUES ('fx_host', 'fx_user_plain', 'fixture-host', 'Synthetic host', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "host_token" ("id", "userId", "sandboxHostId", "name", "lookupPrefix", "secretDigest", "createdAt", "updatedAt")
VALUES ('fx_host_token', 'fx_user_admin', 'fx_host', 'Fixture token', 'synthetic-host-prefix', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "host_device_credential" ("id", "userId", "sandboxHostId", "lookupPrefix", "secretDigest", "createdAt", "updatedAt")
VALUES ('fx_host_device', 'fx_user_admin', 'fx_host', 'synthetic-device-prefix', 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sdk_key" ("id", "userId", "name", "scopes", "lookupPrefix", "secretDigest", "createdAt", "updatedAt")
VALUES ('fx_sdk', 'fx_user_plain', 'Fixture SDK', ARRAY['sandbox:read']::text[], 'synthetic-sdk-prefix', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sandbox_logical_template" ("id", "userId", "slug", "label", "createdAt", "updatedAt")
VALUES ('fx_template', 'fx_user_plain', 'fixture-template', 'Fixture template', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sandbox_template_revision" ("id", "userId", "templateId", "revision", "incusFingerprint", "architecture", "manifestDigest", "sourceKind", "createdAt")
VALUES ('fx_revision', 'fx_user_plain', 'fx_template', 1, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'x86_64', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'MANUAL', '2026-11-12 12:00:00');

INSERT INTO "sandbox_template_tag" ("id", "userId", "templateId", "tag", "revisionId")
VALUES ('fx_tag', 'fx_user_plain', 'fx_template', 'fixture', 'fx_revision');

INSERT INTO "sandbox_revision_config" ("id", "userId", "revisionId", "defaultEnvs", "checksum", "digestScheme", "digestKeyId")
VALUES ('fx_revision_config', 'fx_user_plain', 'fx_revision', '{"FIXTURE":"México","EMPTY":""}', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'sha256-v1', 'synthetic');

INSERT INTO "sandbox_pool" ("id", "userId", "slug", "label", "createdAt", "updatedAt")
VALUES ('fx_pool', 'fx_user_admin', 'fixture-pool', 'Shared fixture pool', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "share" ("id", "poolId", "ownerUserId", "granteeUserId", "canUse", "canContribute", "createdAt", "updatedAt")
VALUES ('fx_share', 'fx_pool', 'fx_user_admin', 'fx_user_plain', true, true, '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sandbox_pool_member" ("id", "userId", "poolId", "sandboxHostId", "hostOwnerId", "shareId", "contributeWitness", "ownHostsOnlyWitness", "createdAt", "updatedAt")
VALUES ('fx_member', 'fx_user_admin', 'fx_pool', 'fx_host', 'fx_user_plain', 'fx_share', true, false, '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sdk_key_pool_allowlist" ("id", "userId", "sdkKeyId", "poolId", "poolOwnerId", "shareId", "useWitness", "createdAt")
VALUES ('fx_pool_grant', 'fx_user_plain', 'fx_sdk', 'fx_pool', 'fx_user_admin', 'fx_share', true, '2026-11-12 12:00:00');

INSERT INTO "sdk_key_host_allowlist" ("id", "sdkKeyId", "sandboxHostId", "createdAt")
VALUES ('fx_host_grant', 'fx_sdk', 'fx_host', '2026-11-12 12:00:00');

INSERT INTO "host_file_receipt" ("id", "userId", "sandboxHostId", "sdkKeyId", "idempotencyKey", "requestHmac", "state", "result", "expiresAt", "createdAt", "updatedAt")
VALUES ('fx_host_file_receipt', 'fx_user_plain', 'fx_host', 'fx_sdk', 'fx-write-key', 'hmac-sha256:synthetic-not-a-request-digest', 'SUCCEEDED', '{"etag":"h:AAAAAAAAAAAAAAAAAAAAAA","size":2,"created":true}', '2026-11-19 12:00:00', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sdk_key_revision_allowlist" ("id", "userId", "sdkKeyId", "templateRevisionId", "createdAt")
VALUES ('fx_revision_grant', 'fx_user_plain', 'fx_sdk', 'fx_revision', '2026-11-12 12:00:00');

INSERT INTO "share_invite" ("id", "poolId", "ownerUserId", "email", "tokenDigest", "pendingKey", "expiresAt", "createdAt")
VALUES ('fx_invite', 'fx_pool', 'fx_user_admin', 'invite@example.test', 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 'fx_pool:invite@example.test', '2099-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sandbox_instance" ("id", "userId", "templateRevisionId", "templateId", "originalSelector", "state", "name", "metadata", "createdAt", "updatedAt")
VALUES ('fx_sandbox', 'fx_user_plain', 'fx_revision', 'fx_template', 'fixture-template:fixture', 'STOPPED', 'fixture-workload', '{"fixture":"México","empty":""}', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sandbox_mutation_operation" ("id", "userId", "sandboxId", "kind", "state", "generation", "idempotencyKey", "requestBodyHash", "requestDigestScheme", "digestContext", "completedAt", "result", "createdAt", "updatedAt")
VALUES ('fx_operation', 'fx_user_plain', 'fx_sandbox', 'RUN_COMMAND', 'SUCCEEDED', 1, 'fx-command', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'sha256-v1', '{"fixture":true}', '2026-11-12 12:00:00', '{"exitCode":0}', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sandbox_command_stream" ("id", "attempt", "nextSequence", "receivedEnd", "totalBytes", "headBytes", "headSegments", "recent", "createdAt", "updatedAt")
VALUES ('fx_operation', 1, 1, 4, 4, 4, 1, '[{"sequence":0,"end":4}]', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sandbox_command_stream_segment" ("id", "outputId", "tail", "startOffset", "endOffset", "bytes", "stderrMask")
VALUES ('fx_output_segment', 'fx_operation', false, 0, 4, decode('68690a00','hex'), decode('00','hex'));

INSERT INTO "sandbox_template_build" ("id", "userId", "templateId", "tag", "principalKind", "principalKey", "idempotencyKey", "requestBodyHash", "recipe", "recipeDigest", "buildDigest", "sourceFormat", "baseRevisionId", "baseFingerprint", "requestedHostId", "targetKey", "cpuCount", "memoryMiB", "diskGiB", "defaultDiskGiB", "timeoutMinutes", "reservedMinutes", "chargeMonth", "state", "buildArgs", "steps", "egressPresets", "createdAt", "updatedAt")
VALUES ('fx_build', 'fx_user_plain', 'fx_template', 'built', 'session', 's', 'fx-build', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '{"version":1,"steps":[]}', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'RECIPE', 'fx_revision', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'fx_host', 'fx_host', 1, 1024, 32, 32, 10, 10, '2026-11-01', 'QUEUED', '{}', '[]', ARRAY[]::text[], '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sandbox_build_context" ("id", "buildId", "userId", "totalBytes", "expectedSha256", "idleExpiresAt", "expiresAt", "createdAt", "updatedAt")
VALUES ('fx_context', 'fx_build', 'fx_user_plain', 4, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '2099-11-12 11:00:00', '2099-11-12 12:00:00', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sandbox_instance" ("id", "userId", "templateRevisionId", "templateId", "originalSelector", "state", "name", "metadata", "createdAt", "updatedAt")
VALUES ('fx_offloaded_sandbox', 'fx_user_plain', 'fx_revision', 'fx_template', 'fixture-template:fixture', 'STOPPED', 'fixture-offloaded', '{"fixture":"México","empty":""}', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "sandbox_disk_offload" ("id", "sandboxId", "userId", "seq", "sourceGeneration", "sourceHostId", "sourceHostOwnerId", "state", "liveSandboxId", "fingerprint", "sizeBytes", "storedBytes", "objectKey", "encryption", "wrappedKey", "wrapSalt", "wrapNonce", "rootKid", "completedSessionId", "verifiedAt", "storedAt", "createdAt", "updatedAt")
VALUES ('fx_offload', 'fx_offloaded_sandbox', 'fx_user_plain', 1, 1, 'fx_host', 'fx_user_plain', 'STORED', 'fx_offloaded_sandbox', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 4, 4, 'synthetic/fx-disk', 'aes256gcm-r1', decode(repeat('11',48),'hex'), decode(repeat('22',32),'hex'), decode(repeat('33',12),'hex'), '0123456789abcdef', 'fx-historical-upload', '2026-11-12 12:00:00', '2026-11-12 12:00:00', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

UPDATE sandbox_instance SET state='OFFLOADED', "offloadSeq"=1, "diskOffloadId"='fx_offload' WHERE id='fx_offloaded_sandbox';

INSERT INTO "credential_definition" ("id", "userId", "slug", "version", "document", "digest", "displayName", "createdAt")
VALUES ('fx_definition', 'fx_user_plain', 'synthetic-cli', 1, '{"version":1,"synthetic":true}', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'Synthetic CLI', '2026-11-12 12:00:00');

INSERT INTO "credential" ("id", "userId", "name", "definitionId", "definitionDigest", "mode", "delivery", "copyBack", "createdAt", "updatedAt")
VALUES ('fx_credential', 'fx_user_plain', 'Synthetic login', 'fx_definition', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'EXCLUSIVE', 'GUEST', false, '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "credential_account" ("id", "userId", "credentialId", "ordinal", "name", "createdAt", "updatedAt")
VALUES ('fx_credential_account', 'fx_user_plain', 'fx_credential', 1, 'Fixture account', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "credential_instance" ("id", "userId", "credentialId", "accountId", "accountOrdinal", "ordinal", "capacity", "state", "createdAt", "updatedAt")
VALUES ('fx_credential_instance', 'fx_user_plain', 'fx_credential', 'fx_credential_account', 1, 1, 1, 'EMPTY', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "credential_lease" ("id", "userId", "credentialId", "accountId", "instanceId", "sandboxId", "operationId", "kind", "exclusive", "state", "releasedAt", "createdAt", "updatedAt")
VALUES ('fx_lease', 'fx_user_plain', 'fx_credential', 'fx_credential_account', 'fx_credential_instance', 'fx_sandbox', 'fx_operation', 'WORKLOAD', true, 'RELEASED', '2026-11-12 12:00:00', '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "webhook_endpoint" ("id", "userId", "url", "secretCiphertext", "secretNonce", "secretKeyId", "events", "operationKinds", "createdAt", "updatedAt")
VALUES ('fx_endpoint', 'fx_user_plain', 'https://hooks.example.test/fx', decode(repeat('44',48),'hex'), decode(repeat('55',12),'hex'), 'synthetic', ARRAY['sandbox.ready']::text[], ARRAY[]::text[], '2026-11-12 12:00:00', '2026-11-12 12:00:00');

INSERT INTO "webhook_event" ("seq", "id", "userId", "type", "sandboxId", "facts", "occurredAt")
VALUES (100, 'fx_event', 'fx_user_plain', 'sandbox.stopped', 'fx_sandbox', '{"from":"READY","to":"STOPPED","fixture":true}', '2026-11-12 12:00:00');

INSERT INTO "webhook_delivery" ("id", "eventId", "endpointId", "userId", "kind", "state", "attemptCount", "maxAttempts", "expiresAt", "completedAt", "lastStatusCode", "createdAt")
VALUES ('fx_delivery', 'fx_event', 'fx_endpoint', 'fx_user_plain', 'event', 'SUCCEEDED', 1, 5, '2099-11-12 12:00:00', '2026-11-12 12:00:00', 204, '2026-11-12 12:00:00');

INSERT INTO "webhook_delivery_attempt" ("id", "deliveryId", "attempt", "startedAt", "durationMs", "resolvedAddress", "statusCode", "responseExcerpt")
VALUES ('fx_delivery_attempt', 'fx_delivery', 1, '2026-11-12 12:00:00', 7, '192.0.2.1', 204, '');

UPDATE sandbox_instance SET state='READY', "readyAt"='2026-11-12 12:00:00' WHERE id='fx_sandbox';

COMMIT;
