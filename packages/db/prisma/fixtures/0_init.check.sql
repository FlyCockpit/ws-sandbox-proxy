-- Each assertion returns zero rows on success. Synthetic fixtures only.

SELECT 'user:fx_user_admin' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "user" WHERE "id" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "name" IS NOT DISTINCT FROM 'Álvaro Fixture'
    AND "email" IS NOT DISTINCT FROM 'owner-one@example.test'
    AND "emailVerified" IS NOT DISTINCT FROM true
    AND "role" IS NOT DISTINCT FROM 'user'
    AND "locale" IS NOT DISTINCT FROM 'es-MX'
    AND "hostTerminalLastTotpStep" IS NOT DISTINCT FROM 9007199254740991
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'user:fx_user_plain' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "user" WHERE "id" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "name" IS NOT DISTINCT FROM 'Owner Two'
    AND "email" IS NOT DISTINCT FROM 'owner-two@example.test'
    AND "emailVerified" IS NOT DISTINCT FROM false
    AND "role" IS NOT DISTINCT FROM 'user'
    AND "locale" IS NOT DISTINCT FROM 'en-US'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'app_setting:fx.synthetic' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "app_setting" WHERE "key" IS NOT DISTINCT FROM 'fx.synthetic'
    AND "value" IS NOT DISTINCT FROM '{"empty":"","unicode":"México"}'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'verification:fx_verification' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "verification" WHERE "id" IS NOT DISTINCT FROM 'fx_verification'
    AND "identifier" IS NOT DISTINCT FROM 'fx-expired'
    AND "value" IS NOT DISTINCT FROM 'synthetic-not-a-verification-token'
    AND "expiresAt" IS NOT DISTINCT FROM '2020-01-01'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'session:fx_session' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "session" WHERE "id" IS NOT DISTINCT FROM 'fx_session'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "token" IS NOT DISTINCT FROM 'synthetic-not-a-session-token'
    AND "expiresAt" IS NOT DISTINCT FROM '2099-11-12 12:00:00'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'account:fx_account' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "account" WHERE "id" IS NOT DISTINCT FROM 'fx_account'
    AND "accountId" IS NOT DISTINCT FROM 'fx-account'
    AND "providerId" IS NOT DISTINCT FROM 'credential'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'two_factor:fx_two_factor' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "two_factor" WHERE "id" IS NOT DISTINCT FROM 'fx_two_factor'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "secret" IS NOT DISTINCT FROM 'synthetic-not-a-totp-secret'
    AND "backupCodes" IS NOT DISTINCT FROM '[]'
    AND "verified" IS NOT DISTINCT FROM false
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'device_code:fx_device' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "device_code" WHERE "id" IS NOT DISTINCT FROM 'fx_device'
    AND "deviceCode" IS NOT DISTINCT FROM 'synthetic-device'
    AND "userCode" IS NOT DISTINCT FROM 'FX-CODE'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "status" IS NOT DISTINCT FROM 'pending'
    AND "expiresAt" IS NOT DISTINCT FROM '2099-11-12 12:00:00'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'push_subscription:fx_push' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "push_subscription" WHERE "id" IS NOT DISTINCT FROM 'fx_push'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "endpoint" IS NOT DISTINCT FROM 'https://push.example.test/fx'
    AND "p256dh" IS NOT DISTINCT FROM 'synthetic-not-a-public-key'
    AND "auth" IS NOT DISTINCT FROM 'synthetic-not-an-auth-key'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'account_image_policy:fx_user_admin' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "account_image_policy" WHERE "userId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "adminStoredGiBMax" IS NOT DISTINCT FROM 0
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sandbox_host:fx_host' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_host" WHERE "id" IS NOT DISTINCT FROM 'fx_host'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "slug" IS NOT DISTINCT FROM 'fixture-host'
    AND "label" IS NOT DISTINCT FROM 'Synthetic host'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'host_token:fx_host_token' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "host_token" WHERE "id" IS NOT DISTINCT FROM 'fx_host_token'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "sandboxHostId" IS NOT DISTINCT FROM 'fx_host'
    AND "name" IS NOT DISTINCT FROM 'Fixture token'
    AND "lookupPrefix" IS NOT DISTINCT FROM 'synthetic-host-prefix'
    AND "secretDigest" IS NOT DISTINCT FROM 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'host_device_credential:fx_host_device' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "host_device_credential" WHERE "id" IS NOT DISTINCT FROM 'fx_host_device'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "sandboxHostId" IS NOT DISTINCT FROM 'fx_host'
    AND "lookupPrefix" IS NOT DISTINCT FROM 'synthetic-device-prefix'
    AND "secretDigest" IS NOT DISTINCT FROM 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sdk_key:fx_sdk' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sdk_key" WHERE "id" IS NOT DISTINCT FROM 'fx_sdk'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "name" IS NOT DISTINCT FROM 'Fixture SDK'
    AND "scopes" IS NOT DISTINCT FROM ARRAY['sandbox:read']::text[]
    AND "lookupPrefix" IS NOT DISTINCT FROM 'synthetic-sdk-prefix'
    AND "secretDigest" IS NOT DISTINCT FROM 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sandbox_logical_template:fx_template' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_logical_template" WHERE "id" IS NOT DISTINCT FROM 'fx_template'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "slug" IS NOT DISTINCT FROM 'fixture-template'
    AND "label" IS NOT DISTINCT FROM 'Fixture template'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sandbox_template_revision:fx_revision' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_template_revision" WHERE "id" IS NOT DISTINCT FROM 'fx_revision'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "templateId" IS NOT DISTINCT FROM 'fx_template'
    AND "revision" IS NOT DISTINCT FROM 1
    AND "incusFingerprint" IS NOT DISTINCT FROM 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "architecture" IS NOT DISTINCT FROM 'x86_64'
    AND "manifestDigest" IS NOT DISTINCT FROM 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "sourceKind" IS NOT DISTINCT FROM 'MANUAL'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sandbox_template_tag:fx_tag' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_template_tag" WHERE "id" IS NOT DISTINCT FROM 'fx_tag'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "templateId" IS NOT DISTINCT FROM 'fx_template'
    AND "tag" IS NOT DISTINCT FROM 'fixture'
    AND "revisionId" IS NOT DISTINCT FROM 'fx_revision'
);

SELECT 'sandbox_revision_config:fx_revision_config' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_revision_config" WHERE "id" IS NOT DISTINCT FROM 'fx_revision_config'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "revisionId" IS NOT DISTINCT FROM 'fx_revision'
    AND "defaultEnvs" IS NOT DISTINCT FROM '{"FIXTURE":"México","EMPTY":""}'
    AND "checksum" IS NOT DISTINCT FROM 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "digestScheme" IS NOT DISTINCT FROM 'sha256-v1'
    AND "digestKeyId" IS NOT DISTINCT FROM 'synthetic'
);

SELECT 'sandbox_pool:fx_pool' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_pool" WHERE "id" IS NOT DISTINCT FROM 'fx_pool'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "slug" IS NOT DISTINCT FROM 'fixture-pool'
    AND "label" IS NOT DISTINCT FROM 'Shared fixture pool'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'share:fx_share' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "share" WHERE "id" IS NOT DISTINCT FROM 'fx_share'
    AND "poolId" IS NOT DISTINCT FROM 'fx_pool'
    AND "ownerUserId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "granteeUserId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "canUse" IS NOT DISTINCT FROM true
    AND "canContribute" IS NOT DISTINCT FROM true
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sandbox_pool_member:fx_member' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_pool_member" WHERE "id" IS NOT DISTINCT FROM 'fx_member'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "poolId" IS NOT DISTINCT FROM 'fx_pool'
    AND "sandboxHostId" IS NOT DISTINCT FROM 'fx_host'
    AND "hostOwnerId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "shareId" IS NOT DISTINCT FROM 'fx_share'
    AND "contributeWitness" IS NOT DISTINCT FROM true
    AND "ownHostsOnlyWitness" IS NOT DISTINCT FROM false
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sdk_key_pool_allowlist:fx_pool_grant' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sdk_key_pool_allowlist" WHERE "id" IS NOT DISTINCT FROM 'fx_pool_grant'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "sdkKeyId" IS NOT DISTINCT FROM 'fx_sdk'
    AND "poolId" IS NOT DISTINCT FROM 'fx_pool'
    AND "poolOwnerId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "shareId" IS NOT DISTINCT FROM 'fx_share'
    AND "useWitness" IS NOT DISTINCT FROM true
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sdk_key_host_allowlist:fx_host_grant' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sdk_key_host_allowlist" WHERE "id" IS NOT DISTINCT FROM 'fx_host_grant'
    AND "sdkKeyId" IS NOT DISTINCT FROM 'fx_sdk'
    AND "sandboxHostId" IS NOT DISTINCT FROM 'fx_host'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'host_file_receipt:fx_host_file_receipt' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "host_file_receipt" WHERE "id" IS NOT DISTINCT FROM 'fx_host_file_receipt'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "sandboxHostId" IS NOT DISTINCT FROM 'fx_host'
    AND "sdkKeyId" IS NOT DISTINCT FROM 'fx_sdk'
    AND "idempotencyKey" IS NOT DISTINCT FROM 'fx-write-key'
    AND "requestHmac" IS NOT DISTINCT FROM 'hmac-sha256:synthetic-not-a-request-digest'
    AND "state" IS NOT DISTINCT FROM 'SUCCEEDED'
    AND "result" IS NOT DISTINCT FROM '{"etag":"h:AAAAAAAAAAAAAAAAAAAAAA","size":2,"created":true}'
    AND "expiresAt" IS NOT DISTINCT FROM '2026-11-19 12:00:00'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sdk_key_revision_allowlist:fx_revision_grant' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sdk_key_revision_allowlist" WHERE "id" IS NOT DISTINCT FROM 'fx_revision_grant'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "sdkKeyId" IS NOT DISTINCT FROM 'fx_sdk'
    AND "templateRevisionId" IS NOT DISTINCT FROM 'fx_revision'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'share_invite:fx_invite' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "share_invite" WHERE "id" IS NOT DISTINCT FROM 'fx_invite'
    AND "poolId" IS NOT DISTINCT FROM 'fx_pool'
    AND "ownerUserId" IS NOT DISTINCT FROM 'fx_user_admin'
    AND "email" IS NOT DISTINCT FROM 'invite@example.test'
    AND "tokenDigest" IS NOT DISTINCT FROM 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
    AND "pendingKey" IS NOT DISTINCT FROM 'fx_pool:invite@example.test'
    AND "expiresAt" IS NOT DISTINCT FROM '2099-11-12 12:00:00'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sandbox_instance:fx_sandbox' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_instance" WHERE "id" IS NOT DISTINCT FROM 'fx_sandbox'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "templateRevisionId" IS NOT DISTINCT FROM 'fx_revision'
    AND "templateId" IS NOT DISTINCT FROM 'fx_template'
    AND "originalSelector" IS NOT DISTINCT FROM 'fixture-template:fixture'
    AND "state" IS NOT DISTINCT FROM 'READY'
    AND "name" IS NOT DISTINCT FROM 'fixture-workload'
    AND "metadata" IS NOT DISTINCT FROM '{"fixture":"México","empty":""}'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "readyAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sandbox_mutation_operation:fx_operation' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_mutation_operation" WHERE "id" IS NOT DISTINCT FROM 'fx_operation'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "sandboxId" IS NOT DISTINCT FROM 'fx_sandbox'
    AND "kind" IS NOT DISTINCT FROM 'RUN_COMMAND'
    AND "state" IS NOT DISTINCT FROM 'SUCCEEDED'
    AND "generation" IS NOT DISTINCT FROM 1
    AND "idempotencyKey" IS NOT DISTINCT FROM 'fx-command'
    AND "requestBodyHash" IS NOT DISTINCT FROM 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "requestDigestScheme" IS NOT DISTINCT FROM 'sha256-v1'
    AND "digestContext" IS NOT DISTINCT FROM '{"fixture":true}'
    AND "completedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "result" IS NOT DISTINCT FROM '{"exitCode":0}'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sandbox_command_stream:fx_operation' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_command_stream" WHERE "id" IS NOT DISTINCT FROM 'fx_operation'
    AND "attempt" IS NOT DISTINCT FROM 1
    AND "nextSequence" IS NOT DISTINCT FROM 1
    AND "receivedEnd" IS NOT DISTINCT FROM 4
    AND "totalBytes" IS NOT DISTINCT FROM 4
    AND "headBytes" IS NOT DISTINCT FROM 4
    AND "headSegments" IS NOT DISTINCT FROM 1
    AND "recent" IS NOT DISTINCT FROM '[{"sequence":0,"end":4}]'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sandbox_command_stream_segment:fx_output_segment' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_command_stream_segment" WHERE "id" IS NOT DISTINCT FROM 'fx_output_segment'
    AND "outputId" IS NOT DISTINCT FROM 'fx_operation'
    AND "tail" IS NOT DISTINCT FROM false
    AND "startOffset" IS NOT DISTINCT FROM 0
    AND "endOffset" IS NOT DISTINCT FROM 4
    AND "bytes" IS NOT DISTINCT FROM decode('68690a00','hex')
    AND "stderrMask" IS NOT DISTINCT FROM decode('00','hex')
);

SELECT 'sandbox_template_build:fx_build' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_template_build" WHERE "id" IS NOT DISTINCT FROM 'fx_build'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "templateId" IS NOT DISTINCT FROM 'fx_template'
    AND "tag" IS NOT DISTINCT FROM 'built'
    AND "principalKind" IS NOT DISTINCT FROM 'session'
    AND "principalKey" IS NOT DISTINCT FROM 's'
    AND "idempotencyKey" IS NOT DISTINCT FROM 'fx-build'
    AND "requestBodyHash" IS NOT DISTINCT FROM 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "recipe" IS NOT DISTINCT FROM '{"version":1,"steps":[]}'
    AND "recipeDigest" IS NOT DISTINCT FROM 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "buildDigest" IS NOT DISTINCT FROM 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "sourceFormat" IS NOT DISTINCT FROM 'RECIPE'
    AND "baseRevisionId" IS NOT DISTINCT FROM 'fx_revision'
    AND "baseFingerprint" IS NOT DISTINCT FROM 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "requestedHostId" IS NOT DISTINCT FROM 'fx_host'
    AND "targetKey" IS NOT DISTINCT FROM 'fx_host'
    AND "cpuCount" IS NOT DISTINCT FROM 1
    AND "memoryMiB" IS NOT DISTINCT FROM 1024
    AND "diskGiB" IS NOT DISTINCT FROM 32
    AND "defaultDiskGiB" IS NOT DISTINCT FROM 32
    AND "timeoutMinutes" IS NOT DISTINCT FROM 10
    AND "reservedMinutes" IS NOT DISTINCT FROM 10
    AND "chargeMonth" IS NOT DISTINCT FROM '2026-11-01'
    AND "state" IS NOT DISTINCT FROM 'QUEUED'
    AND "buildArgs" IS NOT DISTINCT FROM '{}'
    AND "steps" IS NOT DISTINCT FROM '[]'
    AND "egressPresets" IS NOT DISTINCT FROM ARRAY[]::text[]
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sandbox_build_context:fx_context' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_build_context" WHERE "id" IS NOT DISTINCT FROM 'fx_context'
    AND "buildId" IS NOT DISTINCT FROM 'fx_build'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "totalBytes" IS NOT DISTINCT FROM 4
    AND "expectedSha256" IS NOT DISTINCT FROM 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "idleExpiresAt" IS NOT DISTINCT FROM '2099-11-12 11:00:00'
    AND "expiresAt" IS NOT DISTINCT FROM '2099-11-12 12:00:00'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'sandbox_instance:fx_offloaded_sandbox' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_instance" WHERE "id" IS NOT DISTINCT FROM 'fx_offloaded_sandbox'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "templateRevisionId" IS NOT DISTINCT FROM 'fx_revision'
    AND "templateId" IS NOT DISTINCT FROM 'fx_template'
    AND "originalSelector" IS NOT DISTINCT FROM 'fixture-template:fixture'
    AND "state" IS NOT DISTINCT FROM 'OFFLOADED'
    AND "name" IS NOT DISTINCT FROM 'fixture-offloaded'
    AND "metadata" IS NOT DISTINCT FROM '{"fixture":"México","empty":""}'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "offloadSeq" IS NOT DISTINCT FROM 1
    AND "diskOffloadId" IS NOT DISTINCT FROM 'fx_offload'
);

SELECT 'sandbox_disk_offload:fx_offload' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "sandbox_disk_offload" WHERE "id" IS NOT DISTINCT FROM 'fx_offload'
    AND "sandboxId" IS NOT DISTINCT FROM 'fx_offloaded_sandbox'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "seq" IS NOT DISTINCT FROM 1
    AND "sourceGeneration" IS NOT DISTINCT FROM 1
    AND "sourceHostId" IS NOT DISTINCT FROM 'fx_host'
    AND "sourceHostOwnerId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "state" IS NOT DISTINCT FROM 'STORED'
    AND "liveSandboxId" IS NOT DISTINCT FROM 'fx_offloaded_sandbox'
    AND "fingerprint" IS NOT DISTINCT FROM 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "sizeBytes" IS NOT DISTINCT FROM 4
    AND "storedBytes" IS NOT DISTINCT FROM 4
    AND "objectKey" IS NOT DISTINCT FROM 'synthetic/fx-disk'
    AND "encryption" IS NOT DISTINCT FROM 'aes256gcm-r1'
    AND "wrappedKey" IS NOT DISTINCT FROM decode(repeat('11',48),'hex')
    AND "wrapSalt" IS NOT DISTINCT FROM decode(repeat('22',32),'hex')
    AND "wrapNonce" IS NOT DISTINCT FROM decode(repeat('33',12),'hex')
    AND "rootKid" IS NOT DISTINCT FROM '0123456789abcdef'
    AND "completedSessionId" IS NOT DISTINCT FROM 'fx-historical-upload'
    AND "verifiedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "storedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'credential_definition:fx_definition' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "credential_definition" WHERE "id" IS NOT DISTINCT FROM 'fx_definition'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "slug" IS NOT DISTINCT FROM 'synthetic-cli'
    AND "version" IS NOT DISTINCT FROM 1
    AND "document" IS NOT DISTINCT FROM '{"version":1,"synthetic":true}'
    AND "digest" IS NOT DISTINCT FROM 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "displayName" IS NOT DISTINCT FROM 'Synthetic CLI'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'credential:fx_credential' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "credential" WHERE "id" IS NOT DISTINCT FROM 'fx_credential'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "name" IS NOT DISTINCT FROM 'Synthetic login'
    AND "definitionId" IS NOT DISTINCT FROM 'fx_definition'
    AND "definitionDigest" IS NOT DISTINCT FROM 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    AND "mode" IS NOT DISTINCT FROM 'EXCLUSIVE'
    AND "delivery" IS NOT DISTINCT FROM 'GUEST'
    AND "copyBack" IS NOT DISTINCT FROM false
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'credential_account:fx_credential_account' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "credential_account" WHERE "id" IS NOT DISTINCT FROM 'fx_credential_account'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "credentialId" IS NOT DISTINCT FROM 'fx_credential'
    AND "ordinal" IS NOT DISTINCT FROM 1
    AND "name" IS NOT DISTINCT FROM 'Fixture account'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'credential_instance:fx_credential_instance' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "credential_instance" WHERE "id" IS NOT DISTINCT FROM 'fx_credential_instance'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "credentialId" IS NOT DISTINCT FROM 'fx_credential'
    AND "accountId" IS NOT DISTINCT FROM 'fx_credential_account'
    AND "accountOrdinal" IS NOT DISTINCT FROM 1
    AND "ordinal" IS NOT DISTINCT FROM 1
    AND "capacity" IS NOT DISTINCT FROM 1
    AND "state" IS NOT DISTINCT FROM 'EMPTY'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'credential_lease:fx_lease' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "credential_lease" WHERE "id" IS NOT DISTINCT FROM 'fx_lease'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "credentialId" IS NOT DISTINCT FROM 'fx_credential'
    AND "accountId" IS NOT DISTINCT FROM 'fx_credential_account'
    AND "instanceId" IS NOT DISTINCT FROM 'fx_credential_instance'
    AND "sandboxId" IS NOT DISTINCT FROM 'fx_sandbox'
    AND "operationId" IS NOT DISTINCT FROM 'fx_operation'
    AND "kind" IS NOT DISTINCT FROM 'WORKLOAD'
    AND "exclusive" IS NOT DISTINCT FROM true
    AND "state" IS NOT DISTINCT FROM 'RELEASED'
    AND "releasedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'webhook_endpoint:fx_endpoint' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "webhook_endpoint" WHERE "id" IS NOT DISTINCT FROM 'fx_endpoint'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "url" IS NOT DISTINCT FROM 'https://hooks.example.test/fx'
    AND "secretCiphertext" IS NOT DISTINCT FROM decode(repeat('44',48),'hex')
    AND "secretNonce" IS NOT DISTINCT FROM decode(repeat('55',12),'hex')
    AND "secretKeyId" IS NOT DISTINCT FROM 'synthetic'
    AND "events" IS NOT DISTINCT FROM ARRAY['sandbox.ready']::text[]
    AND "operationKinds" IS NOT DISTINCT FROM ARRAY[]::text[]
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "updatedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'webhook_event:fx_event' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "webhook_event" WHERE "seq" IS NOT DISTINCT FROM 100
    AND "id" IS NOT DISTINCT FROM 'fx_event'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "type" IS NOT DISTINCT FROM 'sandbox.stopped'
    AND "sandboxId" IS NOT DISTINCT FROM 'fx_sandbox'
    AND "facts" IS NOT DISTINCT FROM '{"from":"READY","to":"STOPPED","fixture":true}'
    AND "occurredAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'webhook_delivery:fx_delivery' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "webhook_delivery" WHERE "id" IS NOT DISTINCT FROM 'fx_delivery'
    AND "eventId" IS NOT DISTINCT FROM 'fx_event'
    AND "endpointId" IS NOT DISTINCT FROM 'fx_endpoint'
    AND "userId" IS NOT DISTINCT FROM 'fx_user_plain'
    AND "kind" IS NOT DISTINCT FROM 'event'
    AND "state" IS NOT DISTINCT FROM 'SUCCEEDED'
    AND "attemptCount" IS NOT DISTINCT FROM 1
    AND "maxAttempts" IS NOT DISTINCT FROM 5
    AND "expiresAt" IS NOT DISTINCT FROM '2099-11-12 12:00:00'
    AND "completedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "lastStatusCode" IS NOT DISTINCT FROM 204
    AND "createdAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
);

SELECT 'webhook_delivery_attempt:fx_delivery_attempt' AS violation WHERE NOT EXISTS (
  SELECT 1 FROM "webhook_delivery_attempt" WHERE "id" IS NOT DISTINCT FROM 'fx_delivery_attempt'
    AND "deliveryId" IS NOT DISTINCT FROM 'fx_delivery'
    AND "attempt" IS NOT DISTINCT FROM 1
    AND "startedAt" IS NOT DISTINCT FROM '2026-11-12 12:00:00'
    AND "durationMs" IS NOT DISTINCT FROM 7
    AND "resolvedAddress" IS NOT DISTINCT FROM '192.0.2.1'
    AND "statusCode" IS NOT DISTINCT FROM 204
    AND "responseExcerpt" IS NOT DISTINCT FROM ''
);

SELECT 'user count' AS violation WHERE (SELECT count(*) FROM "user") <> 2;

SELECT 'app_setting count' AS violation WHERE (SELECT count(*) FROM "app_setting") <> 1;

SELECT 'verification count' AS violation WHERE (SELECT count(*) FROM "verification") <> 1;

SELECT 'session count' AS violation WHERE (SELECT count(*) FROM "session") <> 1;

SELECT 'account count' AS violation WHERE (SELECT count(*) FROM "account") <> 1;

SELECT 'two_factor count' AS violation WHERE (SELECT count(*) FROM "two_factor") <> 1;

SELECT 'device_code count' AS violation WHERE (SELECT count(*) FROM "device_code") <> 1;

SELECT 'push_subscription count' AS violation WHERE (SELECT count(*) FROM "push_subscription") <> 1;

SELECT 'account_image_policy count' AS violation WHERE (SELECT count(*) FROM "account_image_policy") <> 1;

SELECT 'sandbox_host count' AS violation WHERE (SELECT count(*) FROM "sandbox_host") <> 1;

SELECT 'host_token count' AS violation WHERE (SELECT count(*) FROM "host_token") <> 1;

SELECT 'host_device_credential count' AS violation WHERE (SELECT count(*) FROM "host_device_credential") <> 1;

SELECT 'sdk_key count' AS violation WHERE (SELECT count(*) FROM "sdk_key") <> 1;

SELECT 'sandbox_logical_template count' AS violation WHERE (SELECT count(*) FROM "sandbox_logical_template") <> 1;

SELECT 'sandbox_template_revision count' AS violation WHERE (SELECT count(*) FROM "sandbox_template_revision") <> 1;

SELECT 'sandbox_template_tag count' AS violation WHERE (SELECT count(*) FROM "sandbox_template_tag") <> 1;

SELECT 'sandbox_revision_config count' AS violation WHERE (SELECT count(*) FROM "sandbox_revision_config") <> 1;

SELECT 'sandbox_pool count' AS violation WHERE (SELECT count(*) FROM "sandbox_pool") <> 1;

SELECT 'share count' AS violation WHERE (SELECT count(*) FROM "share") <> 1;

SELECT 'sandbox_pool_member count' AS violation WHERE (SELECT count(*) FROM "sandbox_pool_member") <> 1;

SELECT 'sdk_key_pool_allowlist count' AS violation WHERE (SELECT count(*) FROM "sdk_key_pool_allowlist") <> 1;

SELECT 'sdk_key_host_allowlist count' AS violation WHERE (SELECT count(*) FROM "sdk_key_host_allowlist") <> 1;

SELECT 'sdk_key_revision_allowlist count' AS violation WHERE (SELECT count(*) FROM "sdk_key_revision_allowlist") <> 1;

SELECT 'host_file_receipt count' AS violation WHERE (SELECT count(*) FROM "host_file_receipt") <> 1;

SELECT 'share_invite count' AS violation WHERE (SELECT count(*) FROM "share_invite") <> 1;

SELECT 'sandbox_instance count' AS violation WHERE (SELECT count(*) FROM "sandbox_instance") <> 2;

SELECT 'sandbox_mutation_operation count' AS violation WHERE (SELECT count(*) FROM "sandbox_mutation_operation") <> 1;

SELECT 'sandbox_command_stream count' AS violation WHERE (SELECT count(*) FROM "sandbox_command_stream") <> 1;

SELECT 'sandbox_command_stream_segment count' AS violation WHERE (SELECT count(*) FROM "sandbox_command_stream_segment") <> 1;

SELECT 'sandbox_template_build count' AS violation WHERE (SELECT count(*) FROM "sandbox_template_build") <> 1;

SELECT 'sandbox_build_context count' AS violation WHERE (SELECT count(*) FROM "sandbox_build_context") <> 1;

SELECT 'sandbox_disk_offload count' AS violation WHERE (SELECT count(*) FROM "sandbox_disk_offload") <> 1;

SELECT 'credential_definition count' AS violation WHERE (SELECT count(*) FROM "credential_definition") <> 1;

SELECT 'credential count' AS violation WHERE (SELECT count(*) FROM "credential") <> 1;

SELECT 'credential_account count' AS violation WHERE (SELECT count(*) FROM "credential_account") <> 1;

SELECT 'credential_instance count' AS violation WHERE (SELECT count(*) FROM "credential_instance") <> 1;

SELECT 'credential_lease count' AS violation WHERE (SELECT count(*) FROM "credential_lease") <> 1;

SELECT 'webhook_endpoint count' AS violation WHERE (SELECT count(*) FROM "webhook_endpoint") <> 1;

SELECT 'webhook_event count' AS violation WHERE (SELECT count(*) FROM "webhook_event") <> 2;

SELECT 'webhook_delivery count' AS violation WHERE (SELECT count(*) FROM "webhook_delivery") <> 1;

SELECT 'webhook_delivery_attempt count' AS violation WHERE (SELECT count(*) FROM "webhook_delivery_attempt") <> 1;

SELECT 'composite owner links' AS violation WHERE NOT EXISTS (
 SELECT 1 FROM sandbox_instance s
 JOIN sandbox_template_revision r ON (r.id,r."templateId",r."userId")=(s."templateRevisionId",s."templateId",s."userId")
 JOIN sandbox_mutation_operation o ON (o."sandboxId",o."userId")=(s.id,s."userId")
 JOIN credential_lease l ON (l."sandboxId",l."operationId",l."userId")=(s.id,o.id,s."userId")
 JOIN credential_instance i ON (i.id,i."credentialId",i."userId")=(l."instanceId",l."credentialId",l."userId")
 WHERE s.id='fx_sandbox' AND l.state='RELEASED' AND l."releasedAt" IS NOT NULL AND i.state='EMPTY'
 AND i."currentSeq" IS NULL AND i."activeLeases"=0 AND i."nextStorageSeq"=1
);

SELECT 'offloaded disk cycle and key shape' AS violation WHERE NOT EXISTS (
 SELECT 1 FROM sandbox_instance s JOIN sandbox_disk_offload d ON (d.id,d."sandboxId",d."userId")=(s."diskOffloadId",s.id,s."userId")
 WHERE s.id='fx_offloaded_sandbox' AND s.state='OFFLOADED' AND d.state='STORED'
 AND d."liveSandboxId"=s.id AND d."sourceGeneration"=s.generation AND d.seq=s."offloadSeq"
 AND octet_length(d."wrappedKey")=48 AND octet_length(d."wrapSalt")=32 AND octet_length(d."wrapNonce")=12
 AND d."completedSessionId"='fx-historical-upload' AND d."shreddedAt" IS NULL
 AND s."sandboxHostId" IS NULL AND NOT s."liveResourcesHeld" AND NOT s."diskReservationHeld"
);

SELECT 'output offsets, counters and bytes' AS violation WHERE NOT EXISTS (
 SELECT 1 FROM sandbox_command_stream o JOIN sandbox_command_stream_segment s ON s."outputId"=o.id
 WHERE o.id='fx_operation' AND o."nextSequence"=1 AND o."receivedEnd"=4 AND o."totalBytes"=4
 AND o."headBytes"=octet_length(s.bytes) AND o."headSegments"=1 AND o."tailBytes"=0 AND o."tailSegments"=0
 AND s."startOffset"=0 AND s."endOffset"=4 AND s.bytes=decode('68690a00','hex') AND s."stderrMask"=decode('00','hex')
);

SELECT 'build context owner and state' AS violation WHERE NOT EXISTS (
 SELECT 1 FROM sandbox_template_build b JOIN sandbox_build_context c ON (c."buildId",c."userId")=(b.id,b."userId")
 WHERE b.id='fx_build' AND b.state='QUEUED' AND b."cleanupState"='PENDING' AND b."completedAt" IS NULL
 AND b."principalKey"='s' AND b."targetKey"='fx_host' AND b."chargeMonth"='2026-11-01'
 AND c.state='OPEN' AND c."totalBytes"=4 AND c."receivedBytes"=0 AND c."expiresAt">c."idleExpiresAt"
);

SELECT 'contribution and use witnesses' AS violation WHERE NOT EXISTS (
 SELECT 1 FROM share s JOIN sandbox_pool_member m ON (m."shareId",m."poolId",m."userId",m."hostOwnerId",m."contributeWitness")=(s.id,s."poolId",s."ownerUserId",s."granteeUserId",s."canContribute")
 JOIN sdk_key_pool_allowlist g ON (g."shareId",g."poolId",g."poolOwnerId",g."userId",g."useWitness")=(s.id,s."poolId",s."ownerUserId",s."granteeUserId",s."canUse")
 WHERE s.id='fx_share' AND NOT m."ownHostsOnlyWitness" AND m."removedAt" IS NULL
);

SELECT 'webhook trigger fact' AS violation WHERE (
 SELECT count(*) FROM webhook_event WHERE "sandboxId"='fx_sandbox' AND "userId"='fx_user_plain' AND type='sandbox.ready'
 AND facts=jsonb_build_object('from','STOPPED','to','READY','generation',1,'errorCode',NULL)
)<>1;
