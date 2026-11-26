-- wssp:transactional
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
-- wssp:history-capture (records the history table for the commit marker; keep it here)
DO $wssp$ BEGIN PERFORM set_config('wssp.history', coalesce(to_regclass('_prisma_migrations')::oid::text, ''), true); END $wssp$;

-- DropIndex
DROP INDEX "sandbox_operation_remembered_lease_idx";

-- CreateIndex
CREATE INDEX "sandbox_operation_remembered_lease_idx" ON "sandbox_mutation_operation"("sandboxId", "leaseRevisionAccepted" DESC) WHERE ((kind = ANY (ARRAY['CREATE_SANDBOX'::"SandboxOperationKind", 'RECONNECT_SANDBOX'::"SandboxOperationKind", 'RENEW_SANDBOX_LEASE'::"SandboxOperationKind"])) AND ("leaseRevisionAccepted" IS NOT NULL) AND ("leaseTimeoutMs" IS NOT NULL));

-- wssp:commit-marker (lets the runner prove this transaction committed; keep it last)
DO $wssp$ DECLARE history text := current_setting('wssp.history', true); BEGIN IF history <> '' THEN EXECUTE format('UPDATE %s SET "logs" = %L WHERE "id" = (SELECT "id" FROM %s WHERE "finished_at" IS NULL AND "rolled_back_at" IS NULL ORDER BY "started_at" DESC LIMIT 1)', history::oid::regclass, 'wssp:committed', history::oid::regclass); END IF; END $wssp$;
COMMIT;
