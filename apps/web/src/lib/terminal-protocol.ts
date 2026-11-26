import {
  BROWSER_TERMINAL_CLOSE_CODE,
  BROWSER_TERMINAL_MAX_COLS,
  BROWSER_TERMINAL_MAX_ROWS,
} from "@wssp/config/browser-terminal";
import { z } from "zod";

/**
 * The browser side of the terminal wire (C54), as pure functions: PTY size
 * clamping, the socket URL, server frame parsing and close classification.
 * Contract: docs/design/browser-terminal-auth.md and
 * docs/design/terminal-relay-contract.md. Nothing here touches the network.
 */

export type TerminalSize = { rows: number; cols: number };

/**
 * The size the browser may put on the wire, or `null` when the measurement is
 * not a size at all (NaN, Infinity, not a number). A finite size is clamped
 * into the contract's bounds (1–512 rows, 1–1024 columns), so an out-of-range
 * size never reaches the server, which would refuse it.
 */
export function clampTerminalSize(
  size: { rows: unknown; cols: unknown } | null | undefined,
): TerminalSize | null {
  if (!size) return null;
  const { rows, cols } = size;
  if (typeof rows !== "number" || typeof cols !== "number") return null;
  if (!Number.isFinite(rows) || !Number.isFinite(cols)) return null;
  return {
    rows: Math.min(BROWSER_TERMINAL_MAX_ROWS, Math.max(1, Math.floor(rows))),
    cols: Math.min(BROWSER_TERMINAL_MAX_COLS, Math.max(1, Math.floor(cols))),
  };
}

/** The size a terminal opens with before the container has been measured. */
export const DEFAULT_TERMINAL_SIZE: TerminalSize = { rows: 24, cols: 80 };

function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname === "[::1]" ||
    /^127(?:\.\d{1,3}){3}$/.test(hostname)
  );
}

/**
 * The WebSocket URL for a terminal path on the API server. `wss:` for an
 * `https:` server; plain `ws:` only for explicit loopback development. Any
 * other server URL yields `null` and the terminal refuses to connect.
 */
export function terminalSocketUrl(serverUrl: string, path: string): string | null {
  let base: URL;
  try {
    base = new URL(serverUrl);
  } catch {
    return null;
  }
  let scheme: "wss:" | "ws:";
  if (base.protocol === "https:") scheme = "wss:";
  else if (base.protocol === "http:" && isLoopbackHost(base.hostname)) scheme = "ws:";
  else return null;
  const prefix = base.pathname.replace(/\/+$/, "");
  return `${scheme}//${base.host}${prefix}${path}`;
}

/** A requestId the server's control grammar accepts (`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`). */
export function terminalRequestId(random: () => string = () => crypto.randomUUID()): string {
  return random().replace(/[^A-Za-z0-9_-]/g, "");
}

export function resizeFrame(requestId: string, size: TerminalSize): string {
  return JSON.stringify({ type: "resize", requestId, rows: size.rows, cols: size.cols });
}

export function closeFrame(requestId: string): string {
  return JSON.stringify({ type: "close", requestId });
}

const serverFrameSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("ready"),
    rows: z.number(),
    cols: z.number(),
    // v2, answering an open or a resume of a resumable terminal (WP8). Loose
    // here so a malformed value never drops the `ready` itself; checked by
    // `resumeIdentity`.
    terminalId: z.unknown().optional(),
    outputSeq: z.unknown().optional(),
  }),
  // v2: the PTY may still be detached on the host for `graceMs`; the socket
  // then closes with 4402 (WP8).
  z.object({ type: z.literal("reconnecting"), terminalId: z.string(), graceMs: z.number() }),
  z.object({ type: z.literal("error"), code: z.string(), requestId: z.string().optional() }),
  z.object({
    type: z.literal("close"),
    code: z.number(),
    intent: z.string().optional(),
    reason: z.enum(["pool_access_removed", "host_terminals_disabled"]).optional(),
    exitCode: z.number().optional(),
    error: z.object({ code: z.string() }).passthrough().optional(),
    requestId: z.string().optional(),
  }),
]);

export type ServerFrame = z.infer<typeof serverFrameSchema>;
export type CloseFrame = Extract<ServerFrame, { type: "close" }>;
export type ReconnectingFrame = Extract<ServerFrame, { type: "reconnecting" }>;

/** The id the server mints for a resumable terminal (`t` + 32 hex). */
const TERMINAL_ID = /^t[0-9a-f]{32}$/;

export function validTerminalId(value: unknown): value is string {
  return typeof value === "string" && TERMINAL_ID.test(value);
}

/** The largest `nextOutputSeq` a resume may ask for (the server's input bound). */
export const RESUME_OUTPUT_SEQ_MAX = 2_147_483_647;

/** A v2 `ready`'s resume identity, or `null` when it carries none (or a malformed one). */
export function resumeIdentity(
  frame: Extract<ServerFrame, { type: "ready" }>,
): { terminalId: string; outputSeq: number } | null {
  const { terminalId, outputSeq } = frame;
  if (!validTerminalId(terminalId)) return null;
  if (typeof outputSeq !== "number" || !Number.isSafeInteger(outputSeq) || outputSeq < 0)
    return null;
  return { terminalId, outputSeq };
}

/**
 * The longest server text frame read (UTF-16 code units). The largest one the
 * server sends is a CloseIntent forwarding a host error: a message of up to
 * 1000 UTF-8 bytes plus two 128-character ids, each character JSON-escaped to
 * at most 6 (`\u0001`), is under 8 KiB with the frame's other fields. A
 * close frame must never be dropped for its length, or the end would be
 * misreported as a lost connection (C54-CO-4).
 */
export const SERVER_FRAME_MAX_CHARS = 16 * 1024;

/** A server text frame, or `null` for anything the contract does not define. */
export function parseServerFrame(text: string): ServerFrame | null {
  if (text.length > SERVER_FRAME_MAX_CHARS) return null;
  try {
    const parsed = serverFrameSchema.safeParse(JSON.parse(text));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/**
 * Why a terminal is no longer attached. Each kind is one `terminal:notice.*`
 * message. Kinds come from the CloseIntent frame's `intent` or `error.code`,
 * from the session-create refusal, or from the client itself; never from the
 * close event's human reason string (C53-CO-5).
 */
type TerminalNoticeKind =
  // CloseIntent `intent` values (C52).
  | "client"
  | "detached"
  | "replaced"
  | "backpressure"
  | "revoked"
  | "poolAccessRemoved"
  | "hostTerminalsDisabled"
  | "superseded"
  | "protocolViolation"
  | "hostDisconnected"
  | "hostShutdown"
  | "hostRevoked"
  | "expired"
  | "hostExpired"
  | "openTimedOut"
  | "sandboxStopped"
  | "sandboxDestroyed"
  | "lifecycleUnconfirmed"
  | "shutdown"
  // CloseIntent without an intent.
  | "exited"
  | "noTerminalIdentity"
  | "hostCapacity"
  | "hostRefused"
  | "ended"
  // Transport, as the browser sees it.
  | "connectionLost"
  | "couldNotConnect"
  // The session-create refusal (oRPC errors are readable).
  | "signedOut"
  | "forbidden"
  | "notFound"
  | "notReady"
  | "rateLimited"
  | "unavailable"
  | "createFailed"
  // Client-side.
  | "pageLeft"
  | "insecure"
  | "loadFailed"
  // WP8: the detached terminal could not be reattached (refused, or every
  // attempt within the grace failed).
  | "resumeFailed";

export type TerminalNotice = {
  kind: TerminalNoticeKind;
  exitCode?: number;
  /** The CloseIntent's error code, shown for host refusals without a dedicated message. */
  code?: string;
};

/**
 * Own-key lookups only (C54-F2): a wire value such as `__proto__` or
 * `constructor` must never resolve to an inherited `Object.prototype` member.
 */
function lookup(table: Record<string, TerminalNoticeKind>, key: string) {
  return Object.hasOwn(table, key) ? table[key] : undefined;
}

const INTENT_KINDS: Record<string, TerminalNoticeKind> = {
  client: "client",
  detached: "detached",
  replaced: "replaced",
  backpressure: "backpressure",
  revoked: "revoked",
  superseded: "superseded",
  protocol_violation: "protocolViolation",
  host_disconnected: "hostDisconnected",
  expired: "expired",
  sandbox_stopped: "sandboxStopped",
  sandbox_destroyed: "sandboxDestroyed",
  lifecycle_unconfirmed: "lifecycleUnconfirmed",
  shutdown: "shutdown",
};

const ERROR_KINDS: Record<string, TerminalNoticeKind> = {
  // The host refuses an open when this sandbox cannot host a terminal: its
  // journal lease records no guest identity, it is a build sandbox, or the
  // runtime has no PTY support.
  unsupported_capability: "noTerminalIdentity",
  host_capacity: "hostCapacity",
  rate_limited: "hostCapacity",
  disconnected: "hostDisconnected",
  transport: "hostDisconnected",
};

/**
 * Classify a terminal close. `frame` is the CloseIntent frame the server sent
 * before closing, if any; `code` is the close event's code. The close event's
 * reason string is deliberately not an input.
 */
export function classifyClose(frame: CloseFrame | null, code: number): TerminalNotice {
  if (frame) {
    if (frame.intent === "revoked" && frame.reason === "pool_access_removed")
      return { kind: "poolAccessRemoved" };
    if (frame.intent === "revoked" && frame.reason === "host_terminals_disabled")
      return { kind: "hostTerminalsDisabled" };
    // `expired` is also the intent of an open the host never answered; only the
    // error code tells it from a lease that ran out (the sandbox still runs).
    if (frame.intent === "expired" && frame.error?.code === "timeout")
      return { kind: "openTimedOut" };
    // `shutdown` with `disconnected` is the node daemon stopping (C55-CO-6);
    // a bare `shutdown` is the server's own.
    if (frame.intent === "shutdown" && frame.error?.code === "disconnected")
      return { kind: "hostShutdown" };
    // `host_disconnected` with `access_denied` is the host's credential going
    // inactive (C52-R2-1): the owner's own sign-in is not the problem.
    if (frame.intent === "host_disconnected" && frame.error?.code === "access_denied")
      return { kind: "hostRevoked" };
    const byIntent = frame.intent ? lookup(INTENT_KINDS, frame.intent) : undefined;
    if (byIntent) return { kind: byIntent };
    const errorCode = frame.error?.code;
    if (errorCode)
      return { kind: lookup(ERROR_KINDS, errorCode) ?? "hostRefused", code: errorCode };
    if (frame.exitCode !== undefined) return { kind: "exited", exitCode: frame.exitCode };
    return { kind: "ended" };
  }
  if (code === BROWSER_TERMINAL_CLOSE_CODE) return { kind: "ended" };
  return { kind: "connectionLost" };
}

type ErrorShape = { code?: unknown; status?: unknown; data?: unknown };

/** Classify a refused `sandboxTerminals.createSession` call by its oRPC code. */
export function classifyCreateError(error: unknown): TerminalNotice {
  const shape = (error && typeof error === "object" ? error : {}) as ErrorShape;
  const code = typeof shape.code === "string" ? shape.code : undefined;
  const status = typeof shape.status === "number" ? shape.status : undefined;
  if (code === "UNAUTHORIZED" || status === 401) return { kind: "signedOut" };
  if (code === "FORBIDDEN" || status === 403) return { kind: "forbidden" };
  if (code === "NOT_FOUND" || status === 404) return { kind: "notFound" };
  if (code === "CONFLICT" || status === 409) return { kind: "notReady" };
  if (code === "TOO_MANY_REQUESTS" || status === 429) return { kind: "rateLimited" };
  if (code === "SERVICE_UNAVAILABLE" || status === 503) return { kind: "unavailable" };
  return { kind: "createFailed" };
}

/** Non-final server `error` frames, shown as a passing warning. */
export type TerminalWarning =
  | "inputThrottled"
  | "inputTooLarge"
  | "notReadyYet"
  | "refused"
  // WP8: the host no longer had all output since the browser's last frame.
  | "outputLost";

export function warningFor(code: string): TerminalWarning {
  if (code === "rate_limited") return "inputThrottled";
  if (code === "request_too_large") return "inputTooLarge";
  if (code === "state_conflict") return "notReadyYet";
  return "refused";
}
