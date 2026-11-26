import { upgradeWebSocket, type WebSocketLike } from "@hono/node-server";
import type { Context, MiddlewareHandler } from "hono";
import type { WSContext } from "hono/ws";
import { resolveClientIp } from "../client-ip.js";
import { createRateLimiterMiddleware, hostRelayLimiter } from "../rate-limit.js";
import { authenticateSandboxHostWebsocket, type SandboxHostWebsocketIdentity } from "./auth.js";
import { parseSandboxRelaySubprotocolHeader, SANDBOX_RELAY_SUBPROTOCOL } from "./protocol.js";
import { type SandboxRelaySocket, sandboxRelaySessionManager } from "./session-manager.js";

type SandboxRelayVariables = {
  sandboxRelayIdentity: SandboxHostWebsocketIdentity;
};

function bearerSecret(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match?.[1] ?? null;
}

/** How long a daemon refused by a draining server waits before redialing. */
const SANDBOX_RELAY_SHUTDOWN_RETRY_AFTER_SECONDS = 1;

type SandboxRelayUpgradeOptions = {
  /** Graceful shutdown began: daemons register only with the next process. */
  isShuttingDown?: () => boolean;
};

export function createSandboxRelayWebsocketMiddleware(
  options: SandboxRelayUpgradeOptions = {},
): MiddlewareHandler<{
  Variables: SandboxRelayVariables;
}> {
  const shuttingDown = () => options.isShuttingDown?.() === true;
  // A draining process already closed (or is closing) every host session; a
  // daemon admitted again here would lose that second session abruptly at
  // exit. The daemon honours `Retry-After` and redials the next process.
  const refuseShuttingDown = (c: Context) => {
    c.header("Cache-Control", "no-store");
    c.header("Retry-After", String(SANDBOX_RELAY_SHUTDOWN_RETRY_AFTER_SECONDS));
    return c.json({ error: "The server is restarting. Reconnect shortly." }, 503);
  };
  const rateLimit = createRateLimiterMiddleware(hostRelayLimiter, {
    failClosed: true,
    resolveKey: resolveClientIp,
  });

  return async (c, next) => {
    if (shuttingDown()) return refuseShuttingDown(c);
    if (c.req.header("upgrade")?.toLowerCase() !== "websocket") {
      return c.json({ error: "WebSocket upgrade required." }, 426);
    }

    let admitted = false;
    const limited = await rateLimit(c, async () => {
      admitted = true;
    });
    if (!admitted) return limited;

    const requestedProtocol = parseSandboxRelaySubprotocolHeader(
      c.req.header("sec-websocket-protocol"),
    );
    if (!requestedProtocol.supported) {
      return c.json(
        {
          type: "protocol.error",
          failure: "protocol_error",
          message: "Unsupported sandbox relay websocket subprotocol.",
          supportedSubprotocol: SANDBOX_RELAY_SUBPROTOCOL,
        },
        426,
      );
    }

    const secret = bearerSecret(c.req.header("authorization"));
    if (!secret) {
      return c.json({ error: "Sandbox host websocket authentication required." }, 401);
    }

    const authenticated = await authenticateSandboxHostWebsocket(secret);
    if (!authenticated) {
      return c.json({ error: "Invalid or revoked sandbox host websocket credential." }, 401);
    }
    if ("refusal" in authenticated) {
      // Only after the full secret verified: an explicit verdict about THIS
      // credential, on which the daemon stops its VMs (it can receive no stops).
      // Header: complete once the status line parses (the daemon reads it
      // first); the body code mirrors it.
      c.header("x-wssp-credential-refusal", authenticated.refusal);
      return c.json(
        {
          error: "Invalid or revoked sandbox host websocket credential.",
          code: authenticated.refusal,
        },
        401,
      );
    }
    // Shutdown may have begun while the credential lookup was in flight.
    if (shuttingDown()) return refuseShuttingDown(c);
    const identity = authenticated.identity;
    c.set("sandboxRelayIdentity", identity);
    await next();
  };
}

type SandboxRelayWsContext = WSContext<WebSocketLike>;

const relaySockets = new WeakMap<SandboxRelayWsContext, SandboxRelaySocket>();

function pausable(raw: unknown): { pause(): void; resume(): void } | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const candidate = raw as { pause?: unknown; resume?: unknown };
  return typeof candidate.pause === "function" && typeof candidate.resume === "function"
    ? (candidate as { pause(): void; resume(): void })
    : undefined;
}

type PongSource = {
  on?(event: "pong", listener: () => void): unknown;
  off?(event: "pong", listener: () => void): unknown;
  ping?(): void;
};

/** Pong listeners per socket (WP4 liveness); removed on every socket end. */
const pongListeners = new WeakMap<SandboxRelayWsContext, () => void>();

function relaySocketFor(ws: SandboxRelayWsContext): SandboxRelaySocket {
  const existing = relaySockets.get(ws);
  if (existing) return existing;

  const socket: SandboxRelaySocket = {
    get readyState() {
      return ws.readyState;
    },
    get bufferedAmount() {
      const raw = ws.raw;
      return typeof raw === "object" && raw && "bufferedAmount" in raw
        ? Number(raw.bufferedAmount)
        : 0;
    },
    send(data: string | ArrayBuffer | Uint8Array) {
      if (data instanceof Uint8Array) {
        const copy = new Uint8Array(data.byteLength);
        copy.set(data);
        ws.send(copy.buffer);
        return;
      }
      ws.send(data);
    },
    close(code?: number, reason?: string) {
      ws.close(code, reason);
    },
    // Receive backpressure: `ws` stops reading the TCP socket while paused.
    pause() {
      pausable(ws.raw)?.pause();
    },
    resume() {
      pausable(ws.raw)?.resume();
    },
    ping() {
      (ws.raw as PongSource | undefined)?.ping?.();
    },
  };
  relaySockets.set(ws, socket);
  return socket;
}

/** Pongs bypass the receive queue: `ws` handles them at the transport. */
function listenForPongs(ws: SandboxRelayWsContext, socket: SandboxRelaySocket) {
  const source = ws.raw as PongSource | undefined;
  if (!source?.on) return;
  const listener = () => sandboxRelaySessionManager.notePeerAlive(socket);
  source.on("pong", listener);
  pongListeners.set(ws, listener);
}

function releaseSocket(ws: SandboxRelayWsContext) {
  const listener = pongListeners.get(ws);
  if (listener) (ws.raw as PongSource | undefined)?.off?.("pong", listener);
  pongListeners.delete(ws);
  relaySockets.delete(ws);
}

/** The relay's CLI connect manager (`/v1/sandboxes/{id}/connect`). */
export function sandboxConnectManager() {
  return sandboxRelaySessionManager.connects;
}

export function sandboxRelayUpgradeHandler(options: SandboxRelayUpgradeOptions = {}) {
  return upgradeWebSocket((c: Context<{ Variables: SandboxRelayVariables }>) => {
    const identity = c.get("sandboxRelayIdentity");
    return {
      onOpen(_event, ws) {
        // An upgrade admitted just before shutdown began never gets a session
        // (the shutdown's session removal may already have run): 1012 = restart.
        if (options.isShuttingDown?.() === true) {
          ws.close(1012, "shutting_down");
          return;
        }
        const socket = relaySocketFor(ws);
        if (sandboxRelaySessionManager.acceptAuthenticatedSocket({ socket, identity }))
          listenForPongs(ws, socket);
      },
      onMessage(event, ws) {
        const socket = relaySocketFor(ws);
        if (typeof event.data === "string") {
          sandboxRelaySessionManager.handleTextFrame(socket, event.data);
          return;
        }
        if (event.data instanceof ArrayBuffer) {
          sandboxRelaySessionManager.handleBinaryFrame(socket, event.data);
        }
      },
      onClose(_event, ws) {
        const socket = relaySocketFor(ws);
        sandboxRelaySessionManager.removeSession(socket);
        releaseSocket(ws);
      },
      onError(_event, ws) {
        const socket = relaySocketFor(ws);
        sandboxRelaySessionManager.removeSession(socket);
        releaseSocket(ws);
      },
    };
  });
}
