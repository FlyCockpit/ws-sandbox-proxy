import { createHash } from "node:crypto";
import { OpenAPIHandler } from "@orpc/openapi/fetch";
import { OpenAPIReferencePlugin } from "@orpc/openapi/plugins";
import { ORPCError, onError } from "@orpc/server";
import { RPCHandler } from "@orpc/server/fetch";
import { BatchHandlerPlugin, SimpleCsrfProtectionHandlerPlugin } from "@orpc/server/plugins";
import type { StandardHandlerPlugin } from "@orpc/server/standard";
import { ZodToJsonSchemaConverter } from "@orpc/zod/zod4";
import { createContext } from "@wssp/api/context";
import {
  pushSubscriptionInputSchema,
  upsertPushSubscription,
} from "@wssp/api/lib/push-subscription";
import { isSensitiveSessionTwoFactorPolicySatisfied } from "@wssp/api/lib/sensitive-session-two-factor-gate";
import { appRouter } from "@wssp/api/routers/index";
import { safeErrorLog } from "@wssp/api/sandbox/sensitive-errors";
import {
  activeMcpConsent,
  recordMcpConsent,
  revokedMcpConsent,
  revokeMcpOAuthTokens,
} from "@wssp/api/sandbox/services/mcp-consent";
import { bindMcpGrantTokenRevocation } from "@wssp/api/sandbox/services/mcp-grants";
import { auth, type Session } from "@wssp/auth";
import { bindMcpGrantServices } from "@wssp/auth/mcp-grant";
import { handlePasswordAuthRequest } from "@wssp/auth/password-auth-handler";
import { TWO_FACTOR_REQUIRED_ERROR_CODE } from "@wssp/auth/two-factor-policy";
import { ORPC_BATCH_MAX_SIZE } from "@wssp/config/orpc-batch";
import { THEME_INIT_SCRIPT } from "@wssp/config/theme-init";
import prisma from "@wssp/db";
import { ADMIN_EMAILS, env } from "@wssp/env/server";
import { QUEUE_NAMES, redisConnection } from "@wssp/queue";
import { hasExternalConsumer } from "@wssp/queue/consumer-health";
import { assertUniqueInputMapKeys } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import { apiReferenceAdminGate } from "./api-reference-admin-gate.js";
import { betterAuthAdminGate } from "./better-auth-admin-gate.js";
import { resolveClientIp } from "./client-ip.js";
import { CORS_ALLOW_HEADERS, CORS_EXPOSE_HEADERS } from "./cors-headers.js";
import { deviceDecisionHandler, deviceOwnerGate } from "./device-owner-gate.js";
import {
  EMAIL_RECIPIENT_PATHS,
  emailRecipientLimit,
  FORM_OR_JSON_MEDIA_TYPES,
  SIGNIN_RECIPIENT_PATH,
  SIGNUP_RECIPIENT_PATH,
  signinSentMail,
} from "./email-recipient-limit.js";
import { expectedIdentity } from "./expected-identity.js";
import { registerInstallRoutes } from "./install-script.js";
import type { createServerLifecycle } from "./lifecycle.js";
import { withTimeout } from "./lifecycle.js";
import {
  LOCALE_MODULEPRELOAD_HEADER,
  loadLocaleModulePreloads,
  resolveLocaleModulePreload,
} from "./locale-modulepreload.js";
import { createMcpApi } from "./mcp/endpoint.js";
import { mcpAuthorizeScopeGuard } from "./mcp-authorize-scope-guard.js";
import { createMcpDiscoveryForwarder, MCP_WELL_KNOWN_PATHS } from "./mcp-discovery.js";
import { mcpOauthRateLimits } from "./mcp-oauth-rate-limit.js";
import { createMcpOauthFlagGate, isMcpOauthRawPath } from "./mcp-oauth-route-match.js";
import { cloneRequestOntoPublicOrigin } from "./public-request-url.js";
import {
  authLimiter,
  createRateLimiterMiddleware,
  credentialBurstLimiter,
  credentialLimiter,
  readyLimiter,
  rpcLimiter,
  signinRecipientLimiter,
  signupLimiter,
  signupRecipientLimiter,
  ssrLimiter,
} from "./rate-limit.js";
import { createPathOnlyRequestLogger, requestLogMethod, requestLogPath } from "./request-logger.js";
import { validateSameSiteJsonRequest } from "./request-origin.js";
import { createHostControlApi } from "./sandbox-api/hosts.js";
import { createSandboxApi } from "./sandbox-api/middleware.js";
import { imageRelaySpool } from "./sandbox-image-relay/index.js";
import { createImageRelayApi, IMAGE_RELAY_ROUTE } from "./sandbox-image-relay/routes.js";
import {
  BROWSER_TERMINAL_ROUTE,
  browserTerminalUpgradeHandler,
  createBrowserTerminalUpgradeMiddleware,
  HOST_TERMINAL_ROUTE,
} from "./sandbox-relay/browser-terminal-upgrade.js";
import {
  createSandboxRelayWebsocketMiddleware,
  sandboxConnectManager,
  sandboxRelayUpgradeHandler,
} from "./sandbox-relay/websocket.js";
import { createDashboardTransferApi } from "./sandbox-transfers/dashboard-routes.js";
import { mountSecurityHeaders } from "./security-headers.js";
import { registerSeoRoutes } from "./seo.js";
import { sessionMiddleware } from "./session-middleware.js";
import { mountSetupRoutes } from "./setup-routes.js";
import { SIGNIN_FAILURE_PATH, signinFailureLimit } from "./signin-failure-limit.js";
import { adminBootstrapMarker } from "./signup-gate.js";
import { handleSsrRequest } from "./ssr-cache.js";
import { loadSsrHandler } from "./ssr-handler.js";
import { TWO_FACTOR_OTP_PATH, twoFactorOtpLimit } from "./two-factor-otp-limit.js";

export async function createApp(
  lifecycle: Pick<ReturnType<typeof createServerLifecycle>, "isShuttingDown" | "isWorkerReady">,
) {
  // ---------------------------------------------------------------------------
  // Startup guards
  // ---------------------------------------------------------------------------

  // Reject wildcard CORS origin — it disables credential support and effectively
  // opens the API to any website. Fail hard at startup so the misconfiguration
  // is caught immediately in staging/CI, not silently in production.
  if (env.CORS_ORIGIN === "*") {
    console.error(
      "[server] FATAL: CORS_ORIGIN must not be '*'. Set it to the exact origin of your frontend (e.g. https://app.example.com).",
    );
    throw new Error("Invalid CORS_ORIGIN");
  }

  // Non-production banner. NODE_ENV defaults to "development" (see
  // packages/env/src/vars/shared.ts), which silently weakens several guards for
  // anyone running the server by hand outside Docker — where NODE_ENV is often
  // simply unset. Say so loudly at boot, naming what is weaker.
  if (process.env.NODE_ENV !== "production") {
    console.warn(
      "[server] ══════════════════════════════════════════════════════════════\n" +
        `[server] NON-PRODUCTION MODE (NODE_ENV=${process.env.NODE_ENV ?? "unset → development"}) — guards weakened:\n` +
        "[server] cookies not Secure · /api-reference public · weak secrets warn-only · http:// URLs allowed\n" +
        "[server] Never expose this process publicly or use production data.\n" +
        "[server] ══════════════════════════════════════════════════════════════",
    );
  }

  // ---------------------------------------------------------------------------
  // App + global middleware
  // ---------------------------------------------------------------------------

  type AppVariables = {
    requestId: string;
    session: Session | null;
  };

  const app = new Hono<{ Variables: AppVariables }>();

  // Secure-headers — sets a battery of security headers (X-Content-Type-Options,
  // X-Frame-Options, Strict-Transport-Security, etc.) on every response. The
  // policy lives in mountSecurityHeaders (see its doc comment +
  // security-headers.test.ts). CSP: tighten per route if third-party
  // scripts/analytics are needed.
  const cspConnectSrc = ["'self'", ...(env.CORS_ORIGIN ? [env.CORS_ORIGIN] : [])];
  // CSP hash authorizing the inlined anti-FOUC theme bootstrap (THEME_INIT_SCRIPT,
  // injected into <head> by apps/web/src/routes/__root.tsx). Computed from the
  // shared string at startup, so it can never drift from the inlined content. An
  // inline script needs a nonce or hash to run under `script-src 'self' 'nonce-…'`;
  // this static bootstrap can't carry a per-request nonce, so it uses a hash.
  const themeInitCspHash = `'sha256-${createHash("sha256").update(THEME_INIT_SCRIPT).digest("base64")}'`;
  mountSecurityHeaders(app, { cspConnectSrc, themeInitCspHash });

  bindMcpGrantServices({
    record: recordMcpConsent,
    active: activeMcpConsent,
    revoked: revokedMcpConsent,
  });
  bindMcpGrantTokenRevocation(revokeMcpOAuthTokens);
  // Credential-only MCP and discovery own every method before browser CORS.
  app.route("/", createMcpApi(auth));
  app.use("/api/auth/*", createMcpOauthFlagGate({ enabled: () => env.MCP_ENABLED !== false }));
  app.use("/api/auth/*", mcpOauthRateLimits);
  for (const path of MCP_WELL_KNOWN_PATHS) {
    app.all(
      path,
      createMcpDiscoveryForwarder({
        enabled: env.MCP_ENABLED !== false,
        handler: (request) => auth.handler(request),
      }),
    );
  }

  // This terminal subapp must precede every browser middleware and catch-all.
  app.route(
    "/v1",
    createSandboxApi({
      isShuttingDown: lifecycle.isShuttingDown,
      connects: sandboxConnectManager,
    }),
  );
  app.route("/api/sandbox-host", createHostControlApi());
  // Relayed peer image parts: host credential + one-time link, own 33 MiB
  // body limit and per-host bucket, mounted before the global 10 MB limit.
  app.route(IMAGE_RELAY_ROUTE, createImageRelayApi(imageRelaySpool));

  // Browser terminal plane (C53): cookie session + one-use ticket + exact
  // Origin. Registered BEFORE the dashboard transfer subapp so only its own
  // middleware runs for the upgrade (no SDK/host credential path).
  app.use(
    BROWSER_TERMINAL_ROUTE,
    createBrowserTerminalUpgradeMiddleware({ isShuttingDown: lifecycle.isShuttingDown }),
  );
  app.get(BROWSER_TERMINAL_ROUTE, browserTerminalUpgradeHandler());
  app.use(
    HOST_TERMINAL_ROUTE,
    createBrowserTerminalUpgradeMiddleware({ isShuttingDown: lifecycle.isShuttingDown }),
  );
  app.get(HOST_TERMINAL_ROUTE, browserTerminalUpgradeHandler());

  app.route("/api/dashboard", createDashboardTransferApi());

  // Body-limit — reject oversized payloads early (before JSON parsing) to
  // prevent memory exhaustion. 10 MB covers large form payloads; individual routes can override with a tighter limit if needed.
  app.use(
    "/*",
    bodyLimit({
      maxSize: 10 * 1024 * 1024, // 10 MB
      onError: (c) => c.json({ error: "Request is too large. Try uploading a smaller file." }, 413),
    }),
  );

  // Request-ID — attach a short random ID to every request for log correlation.
  // The ID is stored in `c.var.requestId` and included in the logger output.
  app.use("/*", async (c, next) => {
    const id = crypto.randomUUID().slice(0, 8);
    c.set("requestId", id);
    await next();
  });

  // Logger — path only (no query string); prepends the request ID for correlation.
  app.use("/*", async (c, next) => {
    const logFn = (message: string, ...rest: string[]) => {
      const reqId = c.get("requestId") ?? "-";
      console.log(`[${reqId}] ${message}`, ...rest);
    };
    return createPathOnlyRequestLogger(logFn)(c, next);
  });

  // Last-resort values-free logging for a producer that bypassed its boundary.
  app.onError((err, c) => {
    const reqId = c.get("requestId") ?? "-";
    console.error(
      `[server] [${reqId}] Unhandled error on ${requestLogMethod(c.req.method)} ${requestLogPath(c.req.path)}:`,
      safeErrorLog(err),
    );
    return c.json({ error: "Something didn't work on our end. Try again in a moment." }, 500);
  });

  // SETUP_KEY first-admin bootstrap (`pnpm deploy:generate-admin`). 404 unless
  // SETUP_KEY is set; refuses once an administrator exists; the key is the
  // only credential it reads. Mounted here — after request id + logging,
  // before CORS — so CORS cannot answer for it: an unset key 404s every
  // method (preflights included), and every request is limited and audited
  // by the route itself. See setup-routes.ts.
  mountSetupRoutes(app, { setupKey: env.SETUP_KEY });

  // Shared oRPC error logger: client errors log at warn; every server error
  // (including upstream failures) and unexpected exception logs at error.
  function logOrpcError(error: unknown) {
    const isServerError = !(error instanceof ORPCError) || error.status >= 500;
    const log = isServerError ? console.error : console.warn;
    log("[orpc] Request failed", safeErrorLog(error));
  }
  if (env.CORS_ORIGIN) {
    app.use(
      "/*",
      cors({
        origin: env.CORS_ORIGIN,
        allowMethods: ["GET", "POST", "OPTIONS"],
        // Adding a header the client sets? It must go in CORS_ALLOW_HEADERS or
        // the preflight fails and the request never leaves the browser — a
        // failure mode invisible in local dev. See cors-headers.ts.
        allowHeaders: [...CORS_ALLOW_HEADERS],
        exposeHeaders: [...CORS_EXPOSE_HEADERS],
        credentials: true,
      }),
    );
  }

  // Liveness probe — answers whether this Node process can serve HTTP. Keep this
  // independent of external services so orchestrators do not restart healthy app
  // containers during a transient Postgres/Redis failover.
  app.get("/health", (c) => c.json({ ok: true }));

  // Readiness probe — checks dependencies for deploy gates and manual diagnosis.
  // Rate-limited (unlike /health) because it touches Postgres and Redis on every
  // call, so an unthrottled public probe is a cheap way to load the datastores.
  // Fail-open: an orchestrator must still be able to read readiness during a
  // Redis blip, which is exactly when it matters most.
  //
  // Its OWN bucket, not a remount of `rpcLimiter`: readiness and app traffic are
  // exactly the two things that must stay independent during an incident.

  // The drain answer comes BEFORE the limiter, and must stay there. During a
  // rolling deploy the load balancer polls readiness about once a second and the
  // only correct reply is 503 "draining" — but a limiter placed first will start
  // answering 429 partway through the drain window, which an orchestrator reads
  // as "probe failed for an unknown reason", not as "stop sending me traffic".
  // The check is a boolean read of process state: it touches neither Postgres nor
  // Redis, so it costs nothing to serve unthrottled and there is nothing here for
  // a limiter to protect. Everything past this point does hit the datastores, and
  // that is what `readyLimiter` still guards.
  const buildVersion = process.env.BUILD_VERSION;
  const commit =
    buildVersion && /^[a-f0-9]{40}$/i.test(buildVersion) ? buildVersion.toLowerCase() : null;
  app.use("/ready", async (c, next) => {
    if (lifecycle.isShuttingDown()) {
      return c.json({ ok: false, commit, checks: { shuttingDown: true } }, 503);
    }
    await next();
  });
  app.use("/ready", createRateLimiterMiddleware(readyLimiter));
  app.get("/ready", async (c) => {
    const checks = {
      postgres: false,
      redis: false,
      workers: false,
    };
    try {
      await withTimeout(prisma.$queryRaw`SELECT 1`, 3000, "postgres readiness check");
      checks.postgres = true;

      await withTimeout(redisConnection.ping(), 3000, "redis readiness check");
      checks.redis = true;
      checks.workers =
        env.WORKER_MODE === "embedded"
          ? lifecycle.isWorkerReady()
          : await withTimeout(
              hasExternalConsumer(redisConnection, Object.values(QUEUE_NAMES)),
              3000,
              "consumer readiness check",
            );
      if (!checks.workers) return c.json({ ok: false, commit, checks }, 503);

      return c.json({ ok: true, commit, checks });
    } catch {
      return c.json({ ok: false, commit, checks }, 503);
    }
  });

  // SEO / discoverability: /robots.txt, /sitemap.xml, /llms.txt. Registered here
  // — before the static-asset middleware and the SSR catch-all below — so the
  // `/$lang/...` router never swallows them and returns the SPA HTML shell.
  registerSeoRoutes(app);
  // The CLI installer (/install.sh, /install.ps1): static text, same placement and reasons.
  registerInstallRoutes(app, { commit });

  // ADMIN_EMAILS bootstrap marker (see signup-gate.ts). Pass-through by design:
  // it marks member requests for admin promotion but NEVER rejects, so member
  // and non-member addresses are indistinguishable at this layer.
  //
  // SIGNUP_ENABLED=false is enforced SOLELY by the auth database hook
  // (packages/auth/src/index.ts), which throws for every user creation outside
  // an allowed mode. An earlier revision additionally rejected non-members here
  // with an immediate 403 while members proceeded into Better-Auth — the
  // immediate-403 vs Better-Auth-processing split (shape + timing) revealed
  // which emails are admins, so it was removed. Do NOT re-add an email-based
  // early reject here.
  app.use("/api/auth/sign-up/email", adminBootstrapMarker(ADMIN_EMAILS));

  // Signup-specific rate limiter — stricter than the general auth limiter.
  // Must be mounted BEFORE the general authLimiter so signup traffic is throttled
  // at the tighter limit first.
  app.use("/api/auth/sign-up/*", createRateLimiterMiddleware(signupLimiter, { failClosed: true }));

  // `get-session` is a benign, cookie-authenticated read that the SPA polls on
  // navigation/focus — many calls per minute under normal use. It must NOT be
  // subject to the strict credential-stuffing limiter below: at 10/60s with a
  // 15-minute block, normal polling locks legitimate users out, and because
  // sign-in/sign-up share the /api/auth/* bucket, it blocks those too (a fresh
  // user hits "Too many attempts" on their very first signup). Give it the
  // general RPC ceiling instead. Mounted BEFORE the strict limiter.
  app.use("/api/auth/get-session", createRateLimiterMiddleware(rpcLimiter));

  // Credential endpoints — the tight bucket. Sign-in and 2FA verification are
  // the only routes where an attacker's guess is worth something, so they get a
  // much smaller budget than the rest of the auth surface. Mounted BEFORE the
  // general limiter, which still applies as a second layer.
  //
  // Keeping this separate is what lets the general limiter below be generous:
  // these limiters key on client IP, and an office or mobile carrier shares one,
  // so a single tight limit across all of /api/auth/* would lock a shared
  // network out of password reset and email verification — exactly what a user
  // who just failed to sign in needs next.
  // TWO windows on the same routes. The 60-second bucket bounds sustained
  // guessing; the 10-second one bounds a burst, which is the shape credential
  // stuffing actually has — 10/60s on its own happily permits ten guesses inside
  // one second. Better-Auth's built-in limiter carried a 3-per-10s rule and we
  // disable it (its key degenerates to one shared bucket behind a two-hop proxy;
  // see packages/auth/src/index.ts), so this is what replaces that rule rather
  // than dropping it.
  for (const path of ["/api/auth/sign-in/*", "/api/auth/two-factor/*"]) {
    app.use(path, createRateLimiterMiddleware(credentialBurstLimiter, { failClosed: true }));
    app.use(path, createRateLimiterMiddleware(credentialLimiter, { failClosed: true }));
  }

  // Two-factor OTP resends, capped per CHALLENGE. Mounted here so it runs after
  // the fail-closed IP-keyed pair above — its own key is a cookie, i.e.
  // caller-supplied, and must sit behind something coarser. See
  // `twoFactorOtpLimiter` for why Better-Auth leaves this endpoint uncapped and
  // why the key is the challenge rather than the recipient.
  app.use(TWO_FACTOR_OTP_PATH, twoFactorOtpLimit());

  // Rate limit the remaining auth endpoints, EXCEPT get-session (handled above).
  // Must be mounted BEFORE the auth handler so every auth request is throttled.
  app.use("/api/auth/*", async (c, next) => {
    if (c.req.path.endsWith("/get-session")) return next();
    return createRateLimiterMiddleware(authLimiter, { failClosed: true })(c, next);
  });

  // Per-RECIPIENT cap on the anonymous endpoints that mail a caller-supplied
  // address. Mounted AFTER the IP limiter above (which is the fail-closed
  // security control) because this is the anti-abuse layer on top: the IP
  // limiter bounds one caller, this bounds one mailbox, and rotating IPs defeat
  // only the former. See email-recipient-limit.ts.
  for (const path of EMAIL_RECIPIENT_PATHS) {
    app.use(path, emailRecipientLimit());
  }
  // Signup mails a caller-supplied address too, and `signupLimiter` above is
  // IP-keyed — the exact control rotating IPs defeat. Its own bucket and budget:
  // see signupRecipientLimiter. Mounted here, so it runs AFTER the ADMIN_EMAILS
  // bootstrap marker and signupLimiter: a request rejected by those never
  // reaches this limiter and so never spends a point from the recipient's
  // budget. (SIGNUP_ENABLED=false rejections happen downstream in the auth
  // database hook, so blocked signups DO reach this limiter — same as any other
  // request Better-Auth itself rejects.)
  // `/sign-up/email` is the one route that widens Better-Auth's global
  // JSON-only `allowedMediaTypes` to also accept form-urlencoded, so the limiter
  // has to accept exactly that pair here — see FORM_OR_JSON_MEDIA_TYPES.
  app.use(
    SIGNUP_RECIPIENT_PATH,
    emailRecipientLimit(signupRecipientLimiter, FORM_OR_JSON_MEDIA_TYPES),
  );
  // Sign-in mails too, but only against an unverified account and only because
  // `requireEmailVerification` + `sendOnSignIn` are both on — see
  // SIGNIN_RECIPIENT_PATH. Mounted after the fail-closed credentialBurstLimiter /
  // credentialLimiter pair above, which stays the primary control here: the
  // password is checked before any mail is sent, so this bucket is a backstop
  // against a leaked-credential mail loop, not an anti-spam gate.
  //
  // DEFERRED metering (`signinSentMail`) — this must not charge a point for every
  // sign-in attempt. The bucket keys on the caller-supplied address, so a
  // per-attempt charge would let anyone who knows your email 429 you out of your
  // own login. See the `ConsumeWhen` doc comment.
  //
  // Form-urlencoded as well as JSON: `/sign-in/email` widens the global media
  // types exactly as `/sign-up/email` does (`sign-in.mjs:155`), and declaring
  // JSON-only here would 415 legitimate form posts before Better-Auth sees them.
  app.use(
    SIGNIN_RECIPIENT_PATH,
    emailRecipientLimit(signinRecipientLimiter, FORM_OR_JSON_MEDIA_TYPES, signinSentMail),
  );

  // Per-EMAIL cap on FAILED password sign-ins — the layer the IP-keyed pair
  // above cannot provide: a rotating-IP stuffing campaign against ONE account
  // gets a fresh 10/60s budget from every address it holds, and only this
  // counter bounds it per account. Charged ONLY on 401 responses (see
  // `signinFailedCredentials`), reserve-then-refund so successes never
  // accumulate, 10 failures / 15 min → 10-minute block, keyed on a SHA-256 of
  // the normalized email so no address ever sits in a Redis key, and fail-OPEN
  // with in-memory insurance — the fail-closed IP pair stays the security floor
  // on this route. Sign-in ONLY: signup/forgot-password stay IP-keyed, where a
  // per-email counter would be a pure lockout lever. Full rationale:
  // `signinFailureLimiter` in rate-limit.ts and signin-failure-limit.ts.
  app.use(SIGNIN_FAILURE_PATH, signinFailureLimit());

  // No parallel management/impersonation API: admin actions use hidden oRPC.
  app.use("/api/auth/admin/*", betterAuthAdminGate);

  // Owner enrollment gate for deviceAuthorization claim/approve/deny (verified
  // email + forced 2FA). Mounted before the Better Auth handler.
  app.use("/api/auth/oauth2/authorize", mcpAuthorizeScopeGuard);
  app.use("/api/auth/*", deviceOwnerGate);
  app.post("/api/auth/device", deviceDecisionHandler);
  app.post("/api/auth/device/approve", deviceDecisionHandler);
  app.post("/api/auth/device/deny", deviceDecisionHandler);

  app.on(["POST", "GET"], "/api/auth/*", (c) => {
    if (!isMcpOauthRawPath(new URL(c.req.raw.url).pathname))
      return handlePasswordAuthRequest(auth, c.req.raw);
    try {
      return auth.handler(cloneRequestOntoPublicOrigin(c.req.raw));
    } catch {
      return c.newResponse(null, 400);
    }
  });

  // Resolve the Better-Auth session once per request on paths that need it.
  // Mounted BEFORE the rate limiters so they can key on the user id without
  // each making their own getSession() call. Not mounted on /api/auth/*
  // (Better-Auth does its own lookup) or /health / SSR / dev-only routes.
  app.use("/rpc/*", sessionMiddleware);
  app.use("/sw/*", sessionMiddleware);

  // Rate limit RPC endpoint — general API traffic.
  // Uses Redis-backed limiter with in-memory insurance fallback (fail-open).
  app.use("/rpc/*", createRateLimiterMiddleware(rpcLimiter));
  app.use("/api-reference/*", createRateLimiterMiddleware(rpcLimiter));
  app.use("/rpc/*", expectedIdentity);
  app.use("/sw/*", expectedIdentity);

  // In production the OpenAPI reference is admin-only: it documents every
  // procedure and shouldn't be a public surface. Non-admins get a 404 (not
  // 401/403) so the page isn't enumerable, matching the adminOr404 convention.
  // Mounted after the rate limiter so brute-forcing the gate is throttled first.
  // In development it stays open for local API exploration.
  if (env.NODE_ENV === "production") {
    app.use("/api-reference/*", apiReferenceAdminGate);
  }

  // Sandbox host relay — outbound WSS from trusted node daemons (`/ws/sandbox-host`).
  // While draining it answers 503 + Retry-After, so daemons register only
  // with the next process (one relay drop per restart).
  app.use(
    "/ws/sandbox-host",
    createSandboxRelayWebsocketMiddleware({ isShuttingDown: lifecycle.isShuttingDown }),
  );
  app.get(
    "/ws/sandbox-host",
    sandboxRelayUpgradeHandler({ isShuttingDown: lifecycle.isShuttingDown }),
  );

  // ---------------------------------------------------------------------------
  // Service-worker push-subscription renewal
  // ---------------------------------------------------------------------------
  // Dedicated HTTP endpoint for the `pushsubscriptionchange` handler in
  // `apps/web/src/sw.ts`. The service worker runs in a separate execution
  // context that cannot easily import the oRPC client, so it needs a plain
  // HTTP route. Narrow blast radius: authenticated via Better-Auth session
  // cookie, accepts only a push-subscription body, rate-limited the same way
  // as `push.subscribe` (same underlying `upsertPushSubscription` helper).
  //
  // CSRF: the oRPC handlers attach `SimpleCsrfProtectionHandlerPlugin` to
  // themselves (not to the Hono app), so this route uses a plain HTTP guard
  // instead: JSON-only body, same-site fetch metadata, and Origin allowlist.
  app.use("/sw/*", createRateLimiterMiddleware(rpcLimiter));
  app.post("/sw/push-renew", async (c) => {
    const rejected = validateSameSiteJsonRequest(c);
    if (rejected) return rejected;

    const session = c.get("session");
    if (!session?.user) {
      return c.json({ error: "You're not signed in. Please sign in and try again." }, 401);
    }
    // The same required-2FA gate as `push.subscribe` (a protectedProcedure).
    if (!(await isSensitiveSessionTwoFactorPolicySatisfied(session.user.id))) {
      return c.json(
        {
          error: "Two-factor authentication setup is required.",
          code: TWO_FACTOR_REQUIRED_ERROR_CODE,
        },
        403,
      );
    }

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Request must be valid JSON." }, 400);
    }

    const parsed = pushSubscriptionInputSchema.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: "Request contains missing or invalid fields." }, 400);
    }

    try {
      await upsertPushSubscription(session.user.id, parsed.data);
    } catch (error) {
      // An endpoint registered to another user, or one that changed mid-renewal,
      // is a client conflict like on `push.subscribe`, not a server error.
      if (error instanceof ORPCError && error.code === "CONFLICT")
        return c.json({ error: error.message }, 409);
      throw error;
    }
    return c.json({ success: true });
  });

  // Require the client's x-csrf-token header in every deployment. Simple form
  // posts from sibling origins need no preflight, even without CORS_ORIGIN.
  const csrfPlugins = [new SimpleCsrfProtectionHandlerPlugin()];

  // BatchHandlerPlugin calls the remaining root chain for each subrequest.
  // Scan query JSON there too, including GET data embedded in a batch URL.
  // FormData's serialized `data` stays a string until the RPC codec runs.
  const envJsonPlugin: StandardHandlerPlugin<Awaited<ReturnType<typeof createContext>>> = {
    init(options) {
      options.rootInterceptors ??= [];
      options.rootInterceptors.push(async ({ request, next }) => {
        if (
          !request.url.pathname.startsWith("/rpc/") &&
          !request.url.pathname.startsWith("/api-reference/")
        )
          return next();
        try {
          for (const name of ["data", "batch"]) {
            const source = request.url.searchParams.getAll(name).at(-1);
            if (source?.trim()) assertUniqueInputMapKeys(source, 10 * 1024 * 1024);
          }
          if (request.method !== "GET") {
            const body = await request.body();
            if (body instanceof FormData) {
              const source = body.get("data");
              if (typeof source === "string") assertUniqueInputMapKeys(source, 10 * 1024 * 1024);
            }
          }
        } catch (error) {
          return {
            matched: true,
            response: {
              status: 400,
              headers: {},
              body: {
                json: {
                  defined: false,
                  code: "BAD_REQUEST",
                  status: 400,
                  message:
                    error instanceof Error && error.message === "sandbox.metadata_invalid"
                      ? "sandbox.metadata_invalid"
                      : "sandbox.env_invalid",
                },
              },
            },
          };
        }
        return next();
      });
    },
  };

  const apiHandler = new OpenAPIHandler(appRouter, {
    plugins: [
      envJsonPlugin,
      new OpenAPIReferencePlugin({
        schemaConverters: [new ZodToJsonSchemaConverter()],
      }),
      ...csrfPlugins,
    ],
    interceptors: [onError(logOrpcError)],
  });

  // `BatchHandlerPlugin` matches the client's `BatchLinkPlugin` (see
  // `apps/web/src/utils/orpc.ts`). Without it, any time the SPA fires multiple
  // concurrent queries with a shared router prefix the client wraps them into
  // a single `/rpc/<prefix>/__batch__` POST that the server otherwise 404s.
  //
  // `maxSize` must stay in sync with the client — both read the shared
  // `ORPC_BATCH_MAX_SIZE`, never a literal. If this drops below the client's
  // value, the server rejects the entire batch with HTTP 413 ("Batch request
  // size exceeds the maximum allowed size") and every query in it fails. That
  // 413 is a *procedure count* limit, not `bodyLimit` and not a proxy payload
  // limit. See `packages/config/src/orpc-batch.ts`.
  const rpcHandler = new RPCHandler(appRouter, {
    plugins: [
      new BatchHandlerPlugin({ maxSize: ORPC_BATCH_MAX_SIZE }),
      envJsonPlugin,
      ...csrfPlugins,
    ],
    interceptors: [onError(logOrpcError)],
  });

  app.use("/*", async (c, next) => {
    // Only the two oRPC surfaces need a context (and its session lookup);
    // assets and pages fall straight through to static/SSR.
    const path = c.req.path;
    if (
      path !== "/rpc" &&
      !path.startsWith("/rpc/") &&
      path !== "/api-reference" &&
      !path.startsWith("/api-reference/")
    )
      return next();
    const context = await createContext({ context: c, clientIp: resolveClientIp(c) });

    // The global body limiter has already bounded this stream. Scan before
    // either adapter constructs JSON objects, including batch subrequests.
    if (c.req.path.startsWith("/rpc/") || c.req.path.startsWith("/api-reference/")) {
      try {
        // GET batches are parsed by the batch plugin before its subrequest chain.
        const url = new URL(c.req.url);
        for (const name of ["data", "batch"]) {
          const source = url.searchParams.getAll(name).at(-1);
          if (source?.trim()) assertUniqueInputMapKeys(source, 10 * 1024 * 1024);
        }
        const contentType = c.req.header("content-type")?.toLowerCase();
        if (
          c.req.raw.body !== null &&
          (!contentType || contentType.startsWith("application/json"))
        ) {
          const bytes = await c.req.raw.clone().arrayBuffer();
          const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
          if (source.trim()) assertUniqueInputMapKeys(source, 10 * 1024 * 1024);
        }
      } catch (error) {
        const code =
          error instanceof Error && error.message === "sandbox.metadata_invalid"
            ? "sandbox.metadata_invalid"
            : "sandbox.env_invalid";
        return c.json({ error: code }, 400);
      }
    }

    const rpcResult = await rpcHandler.handle(c.req.raw, {
      prefix: "/rpc",
      context: context,
    });

    if (rpcResult.matched) {
      return c.newResponse(rpcResult.response.body, rpcResult.response);
    }

    // No procedure at this /rpc path. Answer here with oRPC's own NOT_FOUND
    // body instead of falling through to the OpenAPI/static/SSR chain, which
    // would re-read the already-consumed request and end in a generic 500.
    // Every caller (signed in or not) gets the same 404, so it reveals no
    // more than the old 500 did.
    if (c.req.path === "/rpc" || c.req.path.startsWith("/rpc/")) {
      return c.json({ json: new ORPCError("NOT_FOUND").toJSON() }, 404);
    }

    const apiResult = await apiHandler.handle(c.req.raw, {
      prefix: "/api-reference",
      context: context,
    });

    if (apiResult.matched) {
      return c.newResponse(apiResult.response.body, apiResult.response);
    }

    await next();
  });

  if (env.NODE_ENV === "production") {
    const { fileURLToPath, pathToFileURL } = await import("node:url");
    const { dirname, join } = await import("node:path");

    // The built web assets live at apps/web/dist — a sibling of apps/server.
    // Resolve them from THIS module's location, not the process CWD: the bundle
    // runs as /app/apps/server/dist/index.mjs with CWD=/app, so a CWD- or
    // module-relative "../web/dist" lands in the wrong place. `serveStatic`
    // (CWD-relative) and dynamic import (module-relative) disagree on the base,
    // so we hand both an absolute path computed from import.meta.url.
    const webDist = join(dirname(fileURLToPath(import.meta.url)), "../../web/dist");

    // Static client routes (hashed /assets with a plain 404 for a missing file,
    // the .vite manifest denied, then the catch-all static root) ahead of SSR.
    const { mountStaticClient } = await import("./static-client.js");
    mountStaticClient(app, join(webDist, "client"));

    // Mount TanStack Start for SSR — handles all non-static requests. The bundle
    // is produced by `apps/web` at build time and doesn't exist when this file is
    // type-checked, so the specifier is computed at runtime (a non-literal import
    // is left external by rolldown automatically).
    const startHandlerUrl = pathToFileURL(join(webDist, "server/server.js")).href;
    const startHandler = await loadSsrHandler(startHandlerUrl);

    // Content-hashed locale aggregate chunks for SSR modulepreload. Built from
    // the client Vite manifest (apps/web `build.manifest: true`). Missing in
    // incomplete builds is non-fatal — visitors still load the locale on demand.
    loadLocaleModulePreloads(join(webDist, "client"));

    // Throttle the SSR catch-all. Everything above this line is either a static
    // file or an already-limited API route; everything reaching here renders
    // React on the server. Public pages are cached for SSR_CACHE_TTL_SECONDS,
    // but that cache is in-memory, per-replica, and keyed by URL — so a loop
    // appending a junk query string misses it every time and renders on each
    // request. Generous and fail-open on purpose: this is CPU protection, not a
    // security control, and it must never be why a real visitor can't load the
    // site. Mounted only in production, matching the SSR handler itself.
    app.use("/*", createRateLimiterMiddleware(ssrLimiter));

    app.all("/*", async (c) => {
      // Forward the per-request CSP nonce (from secureHeaders) to the SSR
      // renderer via a request header. getRouter() reads it server-side and sets
      // router.options.ssr.nonce, so TanStack Start stamps the matching nonce on
      // every inline script it injects — otherwise script-src would block them.
      //
      // Also forward the active non-default locale's aggregate chunk URL so the
      // SSR root can emit `<link rel="modulepreload">`. Both headers are
      // server-controlled: strip any client-supplied values first.
      const nonce = c.get("secureHeadersNonce");
      const headers = new Headers(c.req.raw.headers);
      headers.delete("x-csp-nonce");
      headers.delete(LOCALE_MODULEPRELOAD_HEADER);
      if (typeof nonce === "string") {
        headers.set("x-csp-nonce", nonce);
      }
      const localePreload = resolveLocaleModulePreload(new URL(c.req.raw.url).pathname);
      if (localePreload) {
        headers.set(LOCALE_MODULEPRELOAD_HEADER, localePreload);
      }
      const request = new Request(c.req.raw, { headers });
      // Public, anonymous GETs are served from a bounded in-memory HTML cache
      // (TTL via SSR_CACHE_TTL_SECONDS); everything else falls straight through
      // to the renderer. The nonce is swapped per request inside the cache.
      return handleSsrRequest({
        request,
        nonce: typeof nonce === "string" ? nonce : undefined,
        render: (req) => startHandler.fetch(req),
      });
    });
  } else {
    app.get("/", (c) => {
      return c.text("OK");
    });
  }
  return app;
}
