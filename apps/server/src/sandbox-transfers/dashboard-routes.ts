import { randomUUID } from "node:crypto";
import { call, ORPCError } from "@orpc/server";
import { checkLiveOwnerSession, liveOwnerSessionProcedure } from "@wssp/api";
import { sessionPrincipal } from "@wssp/api/sandbox/contracts";
import type { Session } from "@wssp/auth";
import { env } from "@wssp/env/server";
import { type Context, Hono } from "hono";
import { expectedIdentity } from "../expected-identity.js";
import { createRateLimiterMiddleware, rpcLimiter } from "../rate-limit.js";
import type { SandboxApiEnv } from "../sandbox-api/auth.js";
import { sdkErrorResponse } from "../sandbox-api/errors.js";
import { sessionMiddleware } from "../session-middleware.js";
import { registerBuildContextRoutes } from "../template-builds/context-routes.js";
import { buildContextStore } from "../template-builds/runtime.js";
import { registerDownloadRoutes } from "./download-routes.js";
import { registerUploadRoutes } from "./upload-routes.js";

const browserPrincipal = liveOwnerSessionProcedure.handler(({ context }) =>
  sessionPrincipal(context.session.user.id),
);
export function createDashboardTransferApi() {
  const app = new Hono<SandboxApiEnv>();
  app.onError((error, c) => sdkErrorResponse(c, error));
  app.use("*", async (c, next) => {
    c.set("requestId", randomUUID());
    c.header("X-Request-Id", c.var.requestId);
    c.header("Cache-Control", "no-store");
    const site = c.req.header("sec-fetch-site");
    if (["GET", "HEAD"].includes(c.req.method)) {
      // Downloads are cookie-authenticated reads: refuse cross-site fetches,
      // embeds and navigations (no CORS grant; responses are attachments).
      if (site && site !== "same-origin" && site !== "none") throw new ORPCError("FORBIDDEN");
    } else {
      // Configured public origin works behind a TLS-terminating proxy. Missing,
      // null, sibling-site and cross-origin requests fail closed (no CORS grant).
      if (
        c.req.header("origin") !== new URL(env.BETTER_AUTH_URL).origin ||
        (site && site !== "same-origin")
      )
        throw new ORPCError("FORBIDDEN");
    }
    await next();
  });
  app.use("*", sessionMiddleware);
  app.use("*", createRateLimiterMiddleware(rpcLimiter));
  app.use("*", expectedIdentity);
  const authorize = (c: Context) =>
    call(browserPrincipal, undefined, {
      context: { session: c.get("session") as Session | null, clientIp: undefined },
    });
  const checkNow = (c: Context) => checkLiveOwnerSession(c.get("session") as Session | null);
  registerUploadRoutes(app, authorize, checkNow);
  registerDownloadRoutes(app, authorize, checkNow);
  // Session-build context uploads (template builds §3.6): the dashboard creates
  // the build over oRPC, then opens and fills its staged context here.
  registerBuildContextRoutes(app, buildContextStore, authorize, checkNow);
  return app;
}
