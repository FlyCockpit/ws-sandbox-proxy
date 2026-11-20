import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import { createProcedureBudget } from "@wssp/api/lib/procedure-budget";
import { authorizeServiceIntent } from "@wssp/api/lib/sdk-key-access";
import { env } from "@wssp/env/server";
import { assertUniqueInputMapKeys, JSON_BODY_MAX_BYTES } from "@wssp/sandbox-contracts";
import { Hono, type MiddlewareHandler } from "hono";
import { resolveClientIp } from "../client-ip.js";
import { createPathOnlyRequestLogger } from "../request-logger.js";
import type { ConnectManager } from "../sandbox-relay/connect-manager.js";
import { registerDownloadRoutes } from "../sandbox-transfers/download-routes.js";
import { registerUploadRoutes } from "../sandbox-transfers/upload-routes.js";
import { registerBuildContextRoutes } from "../template-builds/context-routes.js";
import { buildContextStore } from "../template-builds/runtime.js";
import { type SandboxApiEnv, sdkAuthentication } from "./auth.js";
import { CONNECT_ROUTE, connectPreAuthentication, registerConnectRoute } from "./connect.js";
import { sdkErrorResponse } from "./errors.js";
import { serveSdkOpenApiDocument } from "./openapi.js";
import { createSandboxApiRoutes } from "./routes.js";

export const SDK_JSON_MAX_BYTES = JSON_BODY_MAX_BYTES;

/** Every /v1 budget counts over this fixed window (DECISIONS: "per 60 s"). */
const SDK_BUDGET_WINDOW_SECONDS = 60;

/**
 * One fail-closed /v1 budget. Each dimension takes its own absolute points
 * from `RATE_LIMIT_SDK_{IP,KEY,OWNER}_POINTS` (defaults 300 / 100 / 300); /v1
 * deliberately does not follow the RPC family (`RATE_LIMIT_RPC_*`) scaling.
 */
function budget(dimension: "ip" | "key" | "owner", points: number) {
  // The env schema enforces this; a mocked or hand-built env must not yield a
  // limiter with NaN/0 points (0 would lock /v1 out, NaN would never count).
  if (!Number.isSafeInteger(points) || points <= 0) {
    throw new TypeError(
      `[sandbox-api] RATE_LIMIT_SDK_${dimension.toUpperCase()}_POINTS must be a positive integer, got ${points}.`,
    );
  }
  return createProcedureBudget({
    keyPrefix: `sdk-http:${dimension}`,
    points,
    durationSeconds: SDK_BUDGET_WINDOW_SECONDS,
    failClosed: true,
    overBudgetMessage: () => "Request budget exceeded.",
    unavailableMessage: "Service temporarily unavailable.",
    unavailableLog: "[sandbox-api] budget unavailable",
    redactErrors: true,
  });
}

/** Absolute deadline for one JSON body read; a stalled sender loses its slot. */
const JSON_BODY_READ_DEADLINE_MS = 60_000;
/** Bounded concurrent JSON body readers; each can hold a 1 MiB buffer. */
const JSON_BODY_GLOBAL_READERS = 64;
const JSON_BODY_OWNER_READERS = 8;

/** Count bytes independently of Content-Length. Bounded JSON buffering only;
 * future binary transfer routes must install their own counting reader here.
 * Admission (per-owner + global reader slots) is acquired BEFORE the 1 MiB
 * buffer exists, and an absolute deadline cancels a body that never completes;
 * request-rate budgets alone cannot bound simultaneous stalled readers (C22).
 * Exported as a factory so tests can drive tight budgets and deadlines. */
export function createJsonBodyLimit(options: {
  deadlineMs: number;
  globalReaders: number;
  ownerReaders: number;
}): MiddlewareHandler<SandboxApiEnv> {
  let jsonBodyReaders = 0;
  const jsonBodyReadersByOwner = new Map<string, number>();
  /** Acquire one reader slot or throw 429. The returned release is idempotent. */
  const acquireJsonBodyReader = (ownerId: string): (() => void) => {
    const owned = jsonBodyReadersByOwner.get(ownerId) ?? 0;
    if (jsonBodyReaders >= options.globalReaders || owned >= options.ownerReaders)
      throw new ORPCError("TOO_MANY_REQUESTS");
    jsonBodyReaders++;
    jsonBodyReadersByOwner.set(ownerId, owned + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      jsonBodyReaders--;
      const left = (jsonBodyReadersByOwner.get(ownerId) ?? 1) - 1;
      if (left) jsonBodyReadersByOwner.set(ownerId, left);
      else jsonBodyReadersByOwner.delete(ownerId);
    };
  };
  return async (c, next) => {
    const encoding = c.req.header("content-encoding");
    if (encoding && encoding.toLowerCase() !== "identity")
      throw new ORPCError("UNSUPPORTED_MEDIA_TYPE");
    if (c.req.raw.signal.aborted) throw new ORPCError("BAD_REQUEST");
    const body = c.req.raw.body;
    if (!body) return next();
    const declared = c.req.header("content-length");
    if (declared && (!/^\d+$/.test(declared) || Number(declared) > SDK_JSON_MAX_BYTES)) {
      throw new ORPCError(/^\d+$/.test(declared) ? "PAYLOAD_TOO_LARGE" : "BAD_REQUEST");
    }
    const release = acquireJsonBodyReader(c.get("principal").ownerId);
    const reader = body.getReader();
    // One fixed buffer also bounds overhead for tiny or zero-length chunks.
    // A declared length sizes it exactly; a body past that length is refused
    // as too large, like any body past the cap.
    const limit = declared ? Number(declared) : SDK_JSON_MAX_BYTES;
    const buffer = new Uint8Array(limit);
    let bytes = 0;
    let timedOut = false;
    const deadline = setTimeout(() => {
      timedOut = true;
      void reader.cancel().catch(() => {});
    }, options.deadlineMs);
    deadline.unref?.();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (timedOut || c.req.raw.signal.aborted) throw new ORPCError("BAD_REQUEST");
        if (done) break;
        bytes += value.byteLength;
        if (bytes > limit) throw new ORPCError("PAYLOAD_TOO_LARGE");
        buffer.set(value, bytes - value.byteLength);
      }
    } catch (error) {
      void reader.cancel().catch(() => {});
      throw error instanceof ORPCError ? error : new ORPCError("BAD_REQUEST");
    } finally {
      clearTimeout(deadline);
      reader.releaseLock();
      release();
    }
    if (
      bytes > 0 &&
      !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(c.req.header("content-type") ?? "")
    ) {
      throw new ORPCError("UNSUPPORTED_MEDIA_TYPE");
    }
    c.req.raw = new Request(c.req.raw, { body: buffer.subarray(0, bytes) });
    if (bytes > 0) {
      try {
        // Fetch JSON decoding replaces invalid UTF-8; reject it before parsing.
        const source = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, bytes));
        assertUniqueInputMapKeys(source, SDK_JSON_MAX_BYTES);
        await c.req.json();
      } catch (error) {
        if (error instanceof Error && error.message === "sandbox.metadata_invalid")
          throw new ORPCError("BAD_REQUEST", { data: { code: "sandbox.metadata_invalid" } });
        throw new ORPCError("BAD_REQUEST");
      }
    }
    await next();
  };
}

const jsonBodyLimit = createJsonBodyLimit({
  deadlineMs: JSON_BODY_READ_DEADLINE_MS,
  globalReaders: JSON_BODY_GLOBAL_READERS,
  ownerReaders: JSON_BODY_OWNER_READERS,
});

export function createSandboxApi(
  options: {
    isShuttingDown?: () => boolean;
    /** CLI shells; absent (tests, tools): every connect upgrade answers 503. */
    connects?: () => ConnectManager;
  } = {},
) {
  const app = new Hono<SandboxApiEnv>();
  const ipBudget = budget("ip", env.RATE_LIMIT_SDK_IP_POINTS);
  const keyBudget = budget("key", env.RATE_LIMIT_SDK_KEY_POINTS);
  const ownerBudget = budget("owner", env.RATE_LIMIT_SDK_OWNER_POINTS);
  app.onError((error, c) => sdkErrorResponse(c, error));
  app.use("*", async (c, next) => {
    const id = randomUUID();
    c.set("requestId", id);
    c.header("X-Request-Id", id);
    c.header("Cache-Control", "no-store");
    return createPathOnlyRequestLogger((message) => console.log(`[${id}] ${message}`))(c, next);
  });
  app.use("*", async (c, next) => {
    await ipBudget(resolveClientIp(c));
    await next();
  });
  // The static public spec is the only anonymous /v1 route; it is IP-budgeted.
  app.get("/openapi.json", serveSdkOpenApiDocument);
  // CLI shells: the credential-free refusals (Origin, cookies, subprotocol,
  // upgrade, shutdown) come before any key is looked up.
  const connects = options.connects;
  app.use(
    CONNECT_ROUTE,
    connectPreAuthentication({
      manager: () => connects?.() ?? { shuttingDown: true },
      ...(options.isShuttingDown ? { isShuttingDown: options.isShuttingDown } : {}),
    }),
  );
  app.use("*", sdkAuthentication);
  app.use("*", async (c, next) => {
    await keyBudget(c.var.principal.keyId);
    await ownerBudget(c.var.principal.ownerId);
    await next();
  });
  app.options("*", () => {
    throw new ORPCError("METHOD_NOT_SUPPORTED");
  });
  registerUploadRoutes(app, async (c) => c.get("principal"));
  registerDownloadRoutes(app, async (c) => c.get("principal"));
  // Binary context chunks bypass the JSON body limit, like transfer uploads.
  // Every call re-checks the key and its `templates:build` scope.
  registerBuildContextRoutes(app, buildContextStore, async (c) => {
    const principal = c.get("principal");
    await authorizeServiceIntent(principal, "templates.build");
    return principal;
  });
  // The connect upgrade has no body; it is mounted before the JSON body limit.
  if (connects) registerConnectRoute(app, { manager: connects });
  app.use("*", jsonBodyLimit);
  app.route("/", createSandboxApiRoutes());
  // Terminal for root, unknown paths and methods: no browser/SSR fallthrough.
  app.all("*", () => {
    throw new ORPCError("NOT_FOUND");
  });
  return app;
}
