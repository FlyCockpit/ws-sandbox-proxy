-- wssp:transactional
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
-- wssp:history-capture (records the history table for the commit marker; keep it here)
DO $wssp$ BEGIN PERFORM set_config('wssp.history', coalesce(to_regclass('_prisma_migrations')::oid::text, ''), true); END $wssp$;

-- AlterTable
ALTER TABLE "sandbox_image_transfer" ADD COLUMN     "wireBytes" BIGINT NOT NULL DEFAULT 0;

ALTER TABLE "sandbox_image_transfer" ADD CONSTRAINT "sandbox_image_transfer_wire_bytes_ck2cb9f9a8" CHECK ("wireBytes" >= 0 AND "wireBytes" <= 17592186044416);

-- wssp:commit-marker (lets the runner prove this transaction committed; keep it last)
DO $wssp$ DECLARE history text := current_setting('wssp.history', true); BEGIN IF history <> '' THEN EXECUTE format('UPDATE %s SET "logs" = %L WHERE "id" = (SELECT "id" FROM %s WHERE "finished_at" IS NULL AND "rolled_back_at" IS NULL ORDER BY "started_at" DESC LIMIT 1)', history::oid::regclass, 'wssp:committed', history::oid::regclass); END IF; END $wssp$;
COMMIT;
