-- wssp:transactional
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
-- wssp:history-capture (records the history table for the commit marker; keep it here)
DO $wssp$ BEGIN PERFORM set_config('wssp.history', coalesce(to_regclass('_prisma_migrations')::oid::text, ''), true); END $wssp$;

-- AlterTable
ALTER TABLE "sandbox_image_artifact" ADD COLUMN     "failureDetail" TEXT;

-- AlterTable
ALTER TABLE "sandbox_template_capture" ADD COLUMN     "capturedAt" TIMESTAMP(3);

ALTER TABLE "sandbox_template_capture" ADD COLUMN     "errorDetail" TEXT;

ALTER TABLE "sandbox_image_artifact" ADD CONSTRAINT "sandbox_image_artifact_failure_detail_ck10f9628d" CHECK ("failureDetail" IS NULL OR "failureDetail" ~ '^[a-z0-9_.]{1,64}$');

ALTER TABLE "sandbox_template_capture" ADD CONSTRAINT "sandbox_template_capture_error_detail_ck7943ec85" CHECK ("errorDetail" IS NULL OR "errorDetail" ~ '^[a-z0-9_.]{1,64}$');

-- wssp:commit-marker (lets the runner prove this transaction committed; keep it last)
DO $wssp$ DECLARE history text := current_setting('wssp.history', true); BEGIN IF history <> '' THEN EXECUTE format('UPDATE %s SET "logs" = %L WHERE "id" = (SELECT "id" FROM %s WHERE "finished_at" IS NULL AND "rolled_back_at" IS NULL ORDER BY "started_at" DESC LIMIT 1)', history::oid::regclass, 'wssp:committed', history::oid::regclass); END IF; END $wssp$;
COMMIT;
