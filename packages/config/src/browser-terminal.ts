// Browser terminal plane (C53): the cookie-session WebSocket that attaches a
// browser to one sandbox PTY. Shared by the server endpoint and the web client
// (C54) so the two cannot drift. Contract: docs/design/browser-terminal-auth.md.

import terminalLimits from "./sandbox-terminal-limits.json";

/** The original browser terminal subprotocol: every end is final (4401). */
export const BROWSER_TERMINAL_SUBPROTOCOL = "wssp.terminal.v1";

/**
 * WP8 reattach (sandbox terminals only): a v2 attachment learns its
 * `terminalId` and output sequence in `ready`, and a relay drop or server
 * restart sends it `reconnecting` + {@link BROWSER_TERMINAL_RECONNECT_CLOSE_CODE}
 * instead of the final 4401, so it can resume the same PTY with a new
 * one-use ticket. Host terminals stay on v1.
 */
export const BROWSER_TERMINAL_SUBPROTOCOL_V2 = "wssp.terminal.v2";

/**
 * The one-use upgrade ticket travels as a second offered subprotocol,
 * `wssp.terminal.ticket.<ticket>`. It is never selected or echoed, and never
 * part of the URL, so it stays out of request logs, proxies' access logs and
 * browser history.
 */
export const BROWSER_TERMINAL_TICKET_PROTOCOL_PREFIX = "wssp.terminal.ticket.";

/** Ticket grammar: 32 random bytes, base64url without padding. */
export const BROWSER_TERMINAL_TICKET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** A ticket is single-use and must be presented within this window. */
export const BROWSER_TERMINAL_TICKET_TTL_MS = 30_000;

/** Final close code of every terminal socket (never retried as the same session). */
export const BROWSER_TERMINAL_CLOSE_CODE = 4401;

/**
 * v2 only: the socket ended but its PTY may still be detached on the host for
 * `graceMs` (the preceding `reconnecting` frame). The browser may resume it
 * with `sandboxTerminals.createSession({ resume })`; never 4401.
 */
export const BROWSER_TERMINAL_RECONNECT_CLOSE_CODE = 4402;

/** D5: the node's reattach grace when nothing else is known (default 120 s, max 10 min). */
export const TERMINAL_RESUME_GRACE_DEFAULT_MS: number = terminalLimits.resumeGraceDefaultMs;
export const TERMINAL_RESUME_GRACE_MAX_MS: number = terminalLimits.resumeGraceMaxMs;

/**
 * Reattach budget per detached terminal (WP8): at most this many attempts,
 * spread across the grace. Each attempt costs one mint point (20 per 60 s per
 * user) and one upgrade point (30 per 60 s); neither budget is raised.
 */
export const TERMINAL_RESUME_MAX_ATTEMPTS = 3;

/**
 * A sandbox terminal is never resumable after this long from its first open
 * (the guest PTY's own lifetime, `sandbox_runtime::PTY_DEFAULT_SESSION`).
 * Reattaching never extends it.
 */
export const BROWSER_TERMINAL_MAX_LIFETIME_MS: number = terminalLimits.guestMaxLifetimeMs;

/** Path of the upgrade endpoint for one sandbox. */
export function browserTerminalPath(sandboxId: string): string {
  return `/api/dashboard/sandboxes/${encodeURIComponent(sandboxId)}/terminal/ws`;
}

/** PTY size bounds of the relay contract (C52): out-of-range sizes are refused. */
export const BROWSER_TERMINAL_MAX_ROWS: number = terminalLimits.maxRows;
export const BROWSER_TERMINAL_MAX_COLS: number = terminalLimits.maxCols;

/** Largest binary input frame the server accepts (`request_too_large` otherwise). */
export const BROWSER_TERMINAL_INPUT_FRAME_MAX_BYTES: number = terminalLimits.dataMaxBytes;

/** Most input bytes the server queues toward the host before refusing frames (`rate_limited`). */
export const BROWSER_TERMINAL_INPUT_QUEUE_MAX_BYTES: number = terminalLimits.inputQueueMaxBytes;

/** A socket buffering more than this is detached rather than queued (C52 slow consumer). */
export const BROWSER_TERMINAL_BUFFERED_MAX_BYTES: number =
  terminalLimits.attachmentBufferedMaxBytes;

/** Host tickets have a separate namespace AND a separate durable consumer. */
export const HOST_TERMINAL_TICKET_PROTOCOL_PREFIX = "wssp.host-terminal.ticket.";
export function hostTerminalPath(hostId: string): string {
  return `/api/dashboard/hosts/${encodeURIComponent(hostId)}/terminal/ws`;
}
