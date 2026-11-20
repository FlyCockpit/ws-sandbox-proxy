/**
 * `GET /v1/sandboxes/{id}/connect` (wssp-ssh 1b): the CLI shell plane. A
 * WebSocket upgrade with subprotocol `wssp.connect.v1`, authenticated only by
 * `Authorization: Bearer wssp_sdk_…` of kind `API` holding
 * `sandboxes:connect`. Every refusal is an HTTP answer in the /v1 error
 * catalog, before any WebSocket or channel exists:
 *
 * - before authentication (`connectPreAuthentication`): shutdown → 503; no
 *   `Upgrade: websocket` → 426; any `Origin` → 403 (no browser use, so no
 *   CSRF surface); any `Cookie` → 403 (cookies never authenticate here); a
 *   subprotocol other than exactly `wssp.connect.v1` → 400;
 * - `sdkAuthentication` (shared): a credential in the query → 400, duplicate
 *   `Authorization` → 401, non-`API` kinds → 401; then the /v1 key budgets;
 * - the route: `connectUpgradeLimiter` (30/min per key, 60/min per IP, fail
 *   closed) → 429/503; the retained `sandboxes.connect` authorization →
 *   403 (scope) / 404 (missing or another owner's sandbox) / 409
 *   (`sandbox.managed`); a sandbox that is not READY on a usable host → 409
 *   `sandbox.state_conflict`; a build, verify or CLI-login sandbox → 400
 *   `UNSUPPORTED_CAPABILITY` (`connect_sandbox_unsupported`); a host that did
 *   not negotiate channels → 400 `UNSUPPORTED_CAPABILITY`
 *   (`connect_host_outdated`); a host not connected here → 409
 *   `sandbox.host_unavailable`; connection caps → 429.
 *
 * After the upgrade the connection re-reads nothing before `hello` unless its
 * retained authorization went stale in between (then it re-reads first); no
 * client frame is acted on before `hello` (connect-manager.ts).
 */
import { upgradeWebSocket, type WebSocketLike } from "@hono/node-server";
import { ORPCError } from "@orpc/server";
import { createProcedureBudget } from "@wssp/api/lib/procedure-budget";
import type { RetainedServiceAuthorization } from "@wssp/api/lib/sdk-key-access";
import { checkSandboxConnect } from "@wssp/api/sandbox/connect-binding";
import { CONNECT_SUBPROTOCOL } from "@wssp/sandbox-contracts";
import { type Context, Hono, type MiddlewareHandler } from "hono";
import type { WSContext } from "hono/ws";
import { resolveClientIp } from "../client-ip.js";
import type {
  ConnectClientSocket,
  ConnectConnection,
  ConnectManager,
  ConnectReservation,
} from "../sandbox-relay/connect-manager.js";
import type { SandboxApiEnv } from "./auth.js";

export const CONNECT_ROUTE = "/sandboxes/:id/connect";

/** Subprotocol entries that look like a credential (never accepted anywhere). */
const CREDENTIAL_LIKE = /wssp_(?:sdk|host|device|agent)_|bearer|token|ticket/i;

type ConnectEnv = SandboxApiEnv & {
  Variables: SandboxApiEnv["Variables"] & {
    connectReservation: ConnectReservation;
    connectRetained: RetainedServiceAuthorization;
  };
};

/**
 * The connect upgrade budget (plan §9): its own buckets, fail closed. One
 * upgrade costs a full authorization read and a held connection slot.
 */
function createConnectUpgradeLimiter() {
  const options = {
    durationSeconds: 60,
    failClosed: true,
    overBudgetMessage: () => "Connect budget exceeded.",
    unavailableMessage: "Service temporarily unavailable.",
    unavailableLog: "[sandbox-connect] budget unavailable",
    redactErrors: true,
  } as const;
  const perKey = createProcedureBudget({ ...options, keyPrefix: "sdk-connect:key", points: 30 });
  const perIp = createProcedureBudget({ ...options, keyPrefix: "sdk-connect:ip", points: 60 });
  return async (keyId: string, ip: string) => {
    await perIp(ip);
    await perKey(keyId);
  };
}

function refuse(c: Context, status: 426, message: string): Response {
  return c.json(
    { error: { code: "BAD_REQUEST", message, requestId: String(c.get("requestId") ?? "") } },
    status,
  );
}

/** Refusals that need no credential; mounted BEFORE `sdkAuthentication`. */
export function connectPreAuthentication(options: {
  manager: () => Pick<ConnectManager, "shuttingDown">;
  isShuttingDown?: () => boolean;
}): MiddlewareHandler<SandboxApiEnv> {
  return async (c, next) => {
    if (c.req.method !== "GET") throw new ORPCError("METHOD_NOT_SUPPORTED");
    if (options.isShuttingDown?.() === true || options.manager().shuttingDown)
      throw new ORPCError("SERVICE_UNAVAILABLE", { message: "The server is shutting down." });
    if (c.req.header("upgrade")?.toLowerCase() !== "websocket")
      return refuse(c, 426, "A WebSocket upgrade is required.");
    if (c.req.header("origin") !== undefined)
      throw new ORPCError("FORBIDDEN", { message: "Browser origins cannot connect." });
    if (c.req.header("cookie") !== undefined)
      throw new ORPCError("FORBIDDEN", { message: "Cookies never authenticate a connect." });
    const offered = (c.req.header("sec-websocket-protocol") ?? "")
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
    if (
      offered.length !== 1 ||
      offered[0] !== CONNECT_SUBPROTOCOL ||
      CREDENTIAL_LIKE.test(offered.join(","))
    )
      throw new ORPCError("BAD_REQUEST", {
        message: `Offer exactly the ${CONNECT_SUBPROTOCOL} subprotocol.`,
      });
    await next();
  };
}

type ConnectWsContext = WSContext<WebSocketLike>;

function clientSocket(ws: ConnectWsContext): ConnectClientSocket {
  return {
    get readyState() {
      return ws.readyState;
    },
    get bufferedAmount() {
      const raw = ws.raw;
      return typeof raw === "object" && raw && "bufferedAmount" in raw
        ? Number(raw.bufferedAmount)
        : 0;
    },
    send(data: string | Uint8Array) {
      if (typeof data === "string") {
        ws.send(data);
        return;
      }
      const copy = new Uint8Array(data.byteLength);
      copy.set(data);
      ws.send(copy.buffer);
    },
    close(code: number, reason: string) {
      ws.close(code, reason);
    },
    ping() {
      (ws.raw as { ping?: () => void } | undefined)?.ping?.();
    },
  };
}

type PongSource = {
  on?(event: "pong", listener: () => void): unknown;
  off?(event: "pong", listener: () => void): unknown;
};

/** The authenticated half: budget, authorization, host, caps, then the upgrade. */
export function registerConnectRoute(
  app: Hono<SandboxApiEnv>,
  options: {
    manager: () => ConnectManager;
    limiter?: (keyId: string, ip: string) => Promise<void>;
    check?: typeof checkSandboxConnect;
  },
) {
  const limiter = options.limiter ?? createConnectUpgradeLimiter();
  const check = options.check ?? checkSandboxConnect;
  // Its own typed sub-app; the parent's middlewares (request id, budgets,
  // pre-authentication, `sdkAuthentication`) run before it.
  const routes = new Hono<ConnectEnv>();
  routes.get(
    CONNECT_ROUTE,
    async (c, next) => {
      const principal = c.get("principal");
      await limiter(principal.keyId, resolveClientIp(c));
      const manager = options.manager();
      // Lifecycle changes from here to the socket's open are not missed: the
      // connection re-reads before hello when any happened.
      const lifecycleMark = options.manager().lifecycleMark();
      const checked = await check(principal, c.req.param("id"));
      if (!checked.ok) {
        if (checked.intent === "stale")
          throw new ORPCError("SERVICE_UNAVAILABLE", {
            message: "Authority changed during authorization; retry.",
          });
        if (checked.intent === "unsupported")
          throw new ORPCError("BAD_REQUEST", {
            message: "This sandbox has no shell access.",
            data: { code: "UNSUPPORTED_CAPABILITY", reason: "connect_sandbox_unsupported" },
          });
        throw new ORPCError("CONFLICT", {
          message: "The sandbox is not running.",
          data: { code: "sandbox.state_conflict" },
        });
      }
      const host = manager.hostAvailability(checked.binding);
      if (host === "outdated")
        throw new ORPCError("BAD_REQUEST", {
          message: "The sandbox's node does not support shells yet; update its daemon.",
          data: { code: "UNSUPPORTED_CAPABILITY", reason: "connect_host_outdated" },
        });
      if (host !== "ok")
        throw new ORPCError("CONFLICT", {
          message: "The sandbox's host is not connected.",
          data: { code: "sandbox.host_unavailable" },
        });
      const reserved = manager.reserve(checked.binding, lifecycleMark);
      if (!reserved.ok)
        throw reserved.reason === "shutdown"
          ? new ORPCError("SERVICE_UNAVAILABLE", { message: "The server is shutting down." })
          : new ORPCError("TOO_MANY_REQUESTS", { message: "Connection limit reached." });
      c.set("connectReservation", reserved.reservation);
      c.set("connectRetained", checked.retained);
      try {
        await next();
      } catch (error) {
        reserved.reservation.release();
        throw error;
      }
      // No WebSocket will open (the adapter refused the upgrade): free the slot now.
      if (c.res.status >= 400) reserved.reservation.release();
    },
    upgradeWebSocket((c: Context<ConnectEnv>) => {
      const reservation = c.get("connectReservation");
      const retained = c.get("connectRetained");
      const principal = c.get("principal");
      let connection: ConnectConnection | undefined;
      let pongs: { source: PongSource; listener: () => void } | undefined;
      const release = () => {
        pongs?.source.off?.("pong", pongs.listener);
        pongs = undefined;
      };
      return {
        onOpen(_event, ws) {
          const attached = options.manager().attach(reservation, principal, retained);
          connection = attached;
          const source = ws.raw as PongSource | undefined;
          if (source?.on) {
            const listener = () => attached.activity();
            source.on("pong", listener);
            pongs = { source, listener };
          }
          attached.opened(clientSocket(ws));
        },
        onMessage(event) {
          connection?.message(event.data);
        },
        onClose() {
          release();
          if (connection) connection.gone();
          else reservation.release();
        },
        onError() {
          release();
          if (connection) connection.gone();
          else reservation.release();
        },
      };
    }),
  );
  app.route("/", routes);
}
