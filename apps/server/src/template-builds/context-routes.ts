import { ORPCError } from "@orpc/server";
import { consumeSandboxWriteBudget } from "@wssp/api/sandbox/budgets";
import type { Principal } from "@wssp/api/sandbox/contracts";
import { budgetSubjectOf, isBrowserSession } from "@wssp/api/sandbox/principal-kinds";
import { TRANSFER_CHUNK_BYTES } from "@wssp/sandbox-contracts";
import type { Context, Hono } from "hono";
import type { SandboxApiEnv } from "../sandbox-api/auth.js";
import { admitted } from "../sandbox-transfers/http-admission.js";
import { checkChunk } from "../sandbox-transfers/limits.js";
import { readBody } from "../sandbox-transfers/upload-routes.js";
import type { BuildContextStore } from "./context-store.js";

/**
 * Build-context routes, shared by
 * both credential planes like the transfer upload routes:
 *   POST /template-builds/:id/context                 open or re-open (idempotent)
 *   PUT  /template-builds/:id/context/chunks/:offset  one fixed-grid chunk
 *   POST /template-builds/:id/context/seal            hash and seal
 * The build is found by id, the caller's owner and the accepting principal;
 * anything else is NOT_FOUND. Same body limits and HTTP admission as transfer
 * uploads; an (re)open also spends the owner's "build" budget (§7). The plane
 * supplies `authorize`: `/v1` checks the `templates:build` scope on the key,
 * the dashboard transfer app the live owner session.
 */
export function registerBuildContextRoutes<E extends SandboxApiEnv>(
  app: Hono<E>,
  store: () => BuildContextStore,
  authorize: (c: Context) => Promise<Principal>,
  checkNow: (c: Context) => Promise<void> = async (c) => {
    await authorize(c);
  },
) {
  const handle = async (
    c: Context,
    action: (owner: Principal, recheck: () => Promise<void>) => Promise<unknown>,
  ) => {
    const owner = await authorize(c);
    const recheck = async () => {
      if (isBrowserSession(owner)) await checkNow(c);
    };
    return admitted(owner, async () => {
      let result: unknown;
      try {
        if (new URL(c.req.url).search) throw new ORPCError("BAD_REQUEST");
        result = await action(owner, recheck);
      } finally {
        // Disclosure-only after acceptance (as transfer uploads).
        await recheck();
      }
      return c.json(result as object, 200);
    });
  };
  // No body, or the empty JSON object (SDK clients send `{}` on keyless POSTs).
  const emptyBody = async (c: Context, recheck: () => Promise<void>) => {
    const bytes = await readBody(c, false, recheck);
    if (bytes.length && new TextDecoder().decode(bytes).trim() !== "{}")
      throw new ORPCError("BAD_REQUEST");
  };

  app.post("/template-builds/:id/context", (c) =>
    handle(c, async (owner, recheck) => {
      await emptyBody(c, recheck);
      await authorize(c);
      const subject = budgetSubjectOf(owner);
      if (subject) await consumeSandboxWriteBudget(subject.ownerId, "build");
      return store().open(owner, c.req.param("id") ?? "");
    }),
  );
  app.put("/template-builds/:id/context/chunks/:offset", (c) =>
    handle(c, async (owner, recheck) => {
      const buildId = c.req.param("id") ?? "";
      const raw = c.req.param("offset") ?? "";
      if (!/^\d{1,16}$/.test(raw)) throw new ORPCError("BAD_REQUEST");
      const offset = Number(raw);
      // Authorize the resource before consuming bytes; the store rechecks after IO.
      const prior = await store().status(owner, buildId);
      checkChunk(
        prior.totalBytes,
        offset,
        Math.min(TRANSFER_CHUNK_BYTES, prior.totalBytes - offset),
      );
      const bytes = await readBody(c, true, recheck);
      await authorize(c);
      return store().write(owner, buildId, offset, bytes);
    }),
  );
  app.post("/template-builds/:id/context/seal", (c) =>
    handle(c, async (owner, recheck) => {
      await emptyBody(c, recheck);
      await authorize(c);
      return store().seal(owner, c.req.param("id") ?? "");
    }),
  );
}
