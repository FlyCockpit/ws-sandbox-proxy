import { createEnv } from "@t3-oss/env-core";
import { z } from "zod";
import { backupCommonConfigWarnings } from "./backup-config.js";
import { imageStoreConfigProblems } from "./image-store-config.js";
import { sharedVars } from "./vars/shared.js";

// ---------------------------------------------------------------------------
// Worker-safe environment — validation only.
//
// This module validates ONLY the variables that the BullMQ worker (and the
// packages it shares with the server: @wssp/db, @wssp/queue,
// @wssp/i18n-translate, @wssp/mailer) actually
// read. It is the import target for every worker-reachable module.
//
// The server's full surface lives in ./server.ts, which `extends` this module
// and adds the server-only variables (Better-Auth, CORS, VAPID,
// rate limits, admin emails, image proxy, …). Importing `@wssp/env/server`
// from worker-graph code would force the worker to set BETTER_AUTH_URL,
// BETTER_AUTH_SECRET, etc. — variables the worker never uses. SMTP is included
// here because the worker can send operational-alert emails without needing
// Better-Auth URL/secret validation.
//
// The strict-boolean helper lives in ./vars/shared.ts.
//
// Do NOT load `.env` here. This file is imported by auth/db and by the web SSR
// graph; a dotenv side effect left `dotenv` as a Vite SSR runtime external and
// broke production containers. Process entrypoints load the root `.env` first,
// via `@wssp/env/load-dotenv` or `loadRootDotenv()` — see that file for the
// full rule, and `pnpm env:check-entrypoints` for the gate that enforces it.
//
// The variable declarations themselves live in ./vars/shared.ts — a
// side-effect-free module, so `pnpm env:check` can read the key set without
// triggering validation. Declare new variables there, never inline in the
// `createEnv` call.
// ---------------------------------------------------------------------------

export {
  type BackupConfig,
  backupCommonConfigWarnings,
  backupMonitorConfigWarnings,
} from "./backup-config.js";
export { imageStoreConfigProblems, imageStoreMode } from "./image-store-config.js";

export const env = createEnv({
  server: sharedVars,
  runtimeEnv: process.env,
  emptyStringAsUndefined: true,
  createFinalSchema: (shape) =>
    z.object(shape).superRefine((value, ctx) => {
      for (const message of imageStoreConfigProblems(value))
        ctx.addIssue({ code: "custom", message });
      // These are shared backup-location warnings only. Writer and freshness
      // credentials intentionally have different grants, so their validators
      // run at their respective consumers rather than making a monitor-only
      // worker look misconfigured for lacking the dump key.
      for (const warning of backupCommonConfigWarnings(value)) {
        console.warn(`WARNING: ${warning}`);
      }
    }),
});
