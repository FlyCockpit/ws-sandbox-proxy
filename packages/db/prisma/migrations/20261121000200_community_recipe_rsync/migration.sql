-- wssp:transactional
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
-- wssp:history-capture (records the history table for the commit marker; keep it here)
DO $wssp$ BEGIN PERFORM set_config('wssp.history', coalesce(to_regclass('_prisma_migrations')::oid::text, ''), true); END $wssp$;

-- The community prep recipe (UBUNTU_CLOUD_PREP_V1) now also installs rsync, so its digest
-- changed again. Widen template_build_origin to accept the new digest and keep both earlier ones:
-- existing COMMUNITY_PREP builds carry them, and the release still running during this deploy
-- writes the previous one. Adding the wider CHECK validates every existing row; it can only fail
-- on a row the old CHECK already refused.
ALTER TABLE "sandbox_template_build" ADD CONSTRAINT "template_build_origin_ck4c786b2f" CHECK ("origin"::text = 'USER' OR ("verifyRequired" AND "recipeDigest" IN ('28ddd19b6c16efce199908628d342179eb933ccead39625b640d567fd22a98be', '76e4e99b8c48671d3f2ea5ba282479e413f91fb15d0f736e6481cec5b9e7af9b', 'eb8a190977a1665adb2f14dcbe7f60eede39ea3ef72f8646652f4919d6802c59') AND "sourceFormat"::text = 'RECIPE' AND "contextSha256" IS NULL));
ALTER TABLE "sandbox_template_build" DROP CONSTRAINT "template_build_origin_ckb5e863b8";

-- wssp:commit-marker (lets the runner prove this transaction committed; keep it last)
DO $wssp$ DECLARE history text := current_setting('wssp.history', true); BEGIN IF history <> '' THEN EXECUTE format('UPDATE %s SET "logs" = %L WHERE "id" = (SELECT "id" FROM %s WHERE "finished_at" IS NULL AND "rolled_back_at" IS NULL ORDER BY "started_at" DESC LIMIT 1)', history::oid::regclass, 'wssp:committed', history::oid::regclass); END IF; END $wssp$;
COMMIT;
