/**
 * HTTP upgrade half of the browser terminal plane (C53); see
 * `browser-terminal.ts` for the session contract. Every refusal here happens
 * before the WebSocket exists (an HTTP refusal; a browser sees only close
 * 1006), so a refused upgrade can never allocate a PTY. Refusals after the
 * ticket is consumed and matched (stale generation, sandbox not running,
 * revoked on re-read, host unavailable) are NOT made here: the upgrade is
 * accepted and the post-upgrade re-read closes it with a readable CloseIntent
 * and 4401 before any PTY is opened (docs/design/browser-terminal-auth.md).
 */
import { randomUUID } from "node:crypto";
import { upgradeWebSocket, type WebSocketLike } from "@hono/node-server";
import { consumeHostTerminalTicket } from "@wssp/api/sandbox/host-terminal-tickets";
import {
  type BrowserTerminalBinding,
  consumeTerminalTicket,
  isHostTerminalBinding,
} from "@wssp/api/sandbox/terminal-tickets";
import type { Session } from "@wssp/auth";
import {
  BROWSER_TERMINAL_SUBPROTOCOL,
  BROWSER_TERMINAL_SUBPROTOCOL_V2,
  BROWSER_TERMINAL_TICKET_PROTOCOL_PREFIX,
  HOST_TERMINAL_TICKET_PROTOCOL_PREFIX,
} from "@wssp/config/browser-terminal";
import type { Context, MiddlewareHandler } from "hono";
import type { WSContext } from "hono/ws";
import { createRateLimiterMiddleware, terminalUpgradeLimiter } from "../rate-limit.js";
import { isAllowedBrowserOrigin } from "../request-origin.js";
import { sessionMiddleware } from "../session-middleware.js";
import {
  type BrowserSocket,
  type BrowserTerminal,
  type BrowserTerminalService,
  type BrowserTerminalVersion,
  browserTerminalService,
} from "./browser-terminal.js";
import { SANDBOX_RELAY_SUBPROTOCOL } from "./protocol.js";

export const BROWSER_TERMINAL_ROUTE = "/api/dashboard/sandboxes/:sandboxId/terminal/ws";
const BROWSER_TERMINAL_PATH_PATTERN = /^\/api\/dashboard\/sandboxes\/[^/]+\/terminal\/ws$/;
export const HOST_TERMINAL_ROUTE = "/api/dashboard/hosts/:hostId/terminal/ws";
const HOST_TERMINAL_PATH_PATTERN = /^\/api\/dashboard\/hosts\/[^/]+\/terminal\/ws$/;
const MACHINE_CREDENTIAL = /wssp_(?:sdk|host|device)_/;

type BrowserTerminalVariables = {
  browserTerminalBinding: BrowserTerminalBinding;
  browserTerminalRequestId: string;
  browserTerminalVersion: BrowserTerminalVersion;
  session: Session | null;
};

/**
 * The one subprotocol selection for the shared WebSocketServer: the relay
 * endpoint selects only the relay subprotocol, the sandbox terminal endpoint
 * `wssp.terminal.v2` (WP8) or `wssp.terminal.v1`, the host terminal endpoint
 * only v1 — never the ticket, never across planes.
 */
export function selectWebSocketSubprotocol(
  protocols: ReadonlySet<string>,
  url: string | undefined,
): string | false {
  const path = new URL(url ?? "/", "http://localhost").pathname;
  if (path === "/ws/sandbox-host")
    return protocols.has(SANDBOX_RELAY_SUBPROTOCOL) ? SANDBOX_RELAY_SUBPROTOCOL : false;
  if (BROWSER_TERMINAL_PATH_PATTERN.test(path) && protocols.has(BROWSER_TERMINAL_SUBPROTOCOL_V2))
    return BROWSER_TERMINAL_SUBPROTOCOL_V2;
  if (BROWSER_TERMINAL_PATH_PATTERN.test(path) || HOST_TERMINAL_PATH_PATTERN.test(path))
    return protocols.has(BROWSER_TERMINAL_SUBPROTOCOL) ? BROWSER_TERMINAL_SUBPROTOCOL : false;
  return false;
}

/**
 * Exactly one terminal subprotocol plus one ticket protocol; anything else is
 * refused. v2 is offered only on the sandbox path (host terminals stay v1).
 */
function ticketFromSubprotocols(
  offered: string[],
  prefix: string,
  allowV2: boolean,
): { ticket: string; version: BrowserTerminalVersion } | null {
  if (offered.length !== 2) return null;
  const version =
    offered[0] === BROWSER_TERMINAL_SUBPROTOCOL
      ? 1
      : allowV2 && offered[0] === BROWSER_TERMINAL_SUBPROTOCOL_V2
        ? 2
        : null;
  if (version === null) return null;
  const ticket = offered[1]!;
  if (!ticket.startsWith(prefix)) return null;
  return { ticket: ticket.slice(prefix.length), version };
}

export function createBrowserTerminalUpgradeMiddleware(
  options: {
    /** Graceful shutdown began (C53-FS-2): refuse before any ticket is consumed. */
    isShuttingDown?: () => boolean;
    service?: Pick<BrowserTerminalService, "shuttingDown">;
  } = {},
): MiddlewareHandler<{
  Variables: BrowserTerminalVariables;
}> {
  const rateLimit = createRateLimiterMiddleware(terminalUpgradeLimiter, { failClosed: true });
  const service = options.service ?? browserTerminalService;
  const shuttingDown = () => options.isShuttingDown?.() === true || service.shuttingDown;
  return async (c, next) => {
    const requestId = randomUUID();
    c.header("Cache-Control", "no-store");
    c.header("X-Request-Id", requestId);
    // Bodies are generic: a refused upgrade never says which check failed
    // beyond its class, and never contains request data.
    const refuse = (status: 400 | 401 | 403 | 404 | 426 | 503, code: string) => {
      // A refused upgrade's body is discarded by the WebSocket handshake; the
      // class also rides a header for operators and tests (never request data).
      c.header("X-Terminal-Refusal", code);
      return c.json({ error: { code, requestId } }, status);
    };
    // No terminal attaches once shutdown begins; the ticket stays unconsumed.
    if (shuttingDown()) return refuse(503, "SERVICE_UNAVAILABLE");
    if (c.req.header("upgrade")?.toLowerCase() !== "websocket")
      return refuse(426, "UPGRADE_REQUIRED");
    const offered = (c.req.header("sec-websocket-protocol") ?? "")
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
    // Plane separation comes first: SDK, host and device credentials (as a
    // bearer header, or smuggled as a subprotocol) never authorize this plane.
    if (
      c.req.header("authorization") !== undefined ||
      offered.some((part) => part === SANDBOX_RELAY_SUBPROTOCOL || MACHINE_CREDENTIAL.test(part))
    )
      return refuse(401, "CREDENTIAL_PLANE");
    if (!isAllowedBrowserOrigin(c.req.header("origin"))) return refuse(403, "ORIGIN_REFUSED");
    const hostTarget = HOST_TERMINAL_PATH_PATTERN.test(c.req.path);
    const offer = ticketFromSubprotocols(
      offered,
      hostTarget ? HOST_TERMINAL_TICKET_PROTOCOL_PREFIX : BROWSER_TERMINAL_TICKET_PROTOCOL_PREFIX,
      !hostTarget,
    );
    if (offer === null) return refuse(400, "SUBPROTOCOL_REQUIRED");
    const { ticket, version } = offer;
    // The cookie session is resolved BEFORE the budget so the limiter keys an
    // authenticated attempt by its user and only an anonymous one by client
    // IP: anonymous attempts from a shared NAT/egress can never spend an
    // owner's budget (C53-CO-3). The session read is the same one `/rpc`
    // makes before `rpcLimiter`; it never throws (anonymous on failure).
    await sessionMiddleware(c, async () => undefined);
    let admitted = false;
    const limited = await rateLimit(c, async () => {
      admitted = true;
    });
    if (!admitted) {
      if (!limited) return refuse(503, "SERVICE_UNAVAILABLE");
      limited.headers.set(
        "X-Terminal-Refusal",
        limited.status === 429 ? "RATE_LIMITED" : "SERVICE_UNAVAILABLE",
      );
      return limited;
    }
    const session = c.get("session");
    if (!session?.user) return refuse(401, "UNAUTHORIZED");
    try {
      const binding = hostTarget
        ? await consumeHostTerminalTicket(ticket)
        : await consumeTerminalTicket(ticket);
      // A consumed ticket is gone whatever happens next: a refused upgrade
      // burns it, and only a fresh createSession can open another terminal.
      if (
        !binding ||
        binding.sessionId !== session.session.id ||
        binding.userId !== session.user.id ||
        (hostTarget
          ? !isHostTerminalBinding(binding) || binding.hostId !== c.req.param("hostId")
          : isHostTerminalBinding(binding) ||
            binding.sandboxId !== c.req.param("sandboxId") ||
            // WP8: a resume ticket attaches only a v2 socket (the ticket is
            // burned either way).
            (binding.resume !== undefined && version !== 2))
      )
        return refuse(401, "TICKET_INVALID");
      // Authenticated, owner-matched ticket: from here every refusal is a
      // readable CloseIntent + 4401 from the post-upgrade re-read, which runs
      // before any PTY is opened (BrowserTerminal.revalidate).
      c.set("browserTerminalBinding", binding);
      c.set("browserTerminalRequestId", requestId);
      c.set("browserTerminalVersion", version);
    } catch (error) {
      // Class only: never a message that could carry request data.
      console.error(
        `[browser-terminal] [${requestId}] upgrade check failed (${error instanceof Error ? error.constructor.name : typeof error})`,
      );
      return refuse(503, "SERVICE_UNAVAILABLE");
    }
    await next();
  };
}

type BrowserWsContext = WSContext<WebSocketLike>;

function browserSocket(ws: BrowserWsContext): BrowserSocket {
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
      const raw = ws.raw as { ping?: () => void } | undefined;
      raw?.ping?.();
    },
  };
}

type PongSource = {
  on?(event: "pong", listener: () => void): unknown;
  off?(event: "pong", listener: () => void): unknown;
};

export function browserTerminalUpgradeHandler(service = browserTerminalService) {
  return upgradeWebSocket((c: Context<{ Variables: BrowserTerminalVariables }>) => {
    const binding = c.get("browserTerminalBinding");
    const requestId = c.get("browserTerminalRequestId");
    const version = c.get("browserTerminalVersion");
    // Attached only once the handshake completed: an aborted handshake leaves
    // nothing registered (no timer, no listener, no entry).
    let terminal: BrowserTerminal | undefined;
    // The browser's pongs are liveness (C55); removed on every socket end.
    let pongs: { source: PongSource; listener: () => void } | undefined;
    const release = () => {
      pongs?.source.off?.("pong", pongs.listener);
      pongs = undefined;
    };
    return {
      onOpen(_event, ws) {
        const attached = service.attach(binding, requestId, version);
        terminal = attached;
        const source = ws.raw as PongSource | undefined;
        if (source?.on) {
          const listener = () => attached.activity();
          source.on("pong", listener);
          pongs = { source, listener };
        }
        attached.opened(browserSocket(ws));
      },
      onMessage(event) {
        terminal?.message(event.data);
      },
      onClose() {
        release();
        terminal?.gone();
      },
      onError() {
        release();
        terminal?.gone();
      },
    };
  });
}
