import type { TestProject } from "vitest/node";

declare module "vitest" {
  export interface ProvidedContext {
    wsspPgAdminUrl: string;
    wsspPgTemplateDb: string;
    wsspPgContainer: string;
  }
}

/**
 * The container, schema apply and template belong to `scripts/test-pg.mjs`
 * (one container per `pnpm test:pg` run, removed on exit or signal). A direct
 * `vitest --config vitest.pg.config.ts` has no database and fails loudly here
 * instead of silently skipping every real-PostgreSQL test.
 */
export default function setup(project: TestProject): void {
  const adminUrl = process.env.WSSP_PG_ADMIN_URL;
  const templateDb = process.env.WSSP_PG_TEMPLATE_DB;
  const container = process.env.WSSP_PG_CONTAINER;
  if (!adminUrl || !templateDb || !container) {
    throw new Error(
      "Real-PostgreSQL tests need the disposable database owned by `pnpm test:pg` (run it from the repo root).",
    );
  }
  project.provide("wsspPgAdminUrl", adminUrl);
  project.provide("wsspPgTemplateDb", templateDb);
  project.provide("wsspPgContainer", container);
}
