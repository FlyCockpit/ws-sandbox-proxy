/**
 * Browser terminal plane (C53): `/api/dashboard/sandboxes/:sandboxId/terminal/ws`.
 *
 * Cookie session only. A browser first calls `sandboxTerminals.createSession`
 * (protected oRPC: live session row, ban/deletion/forced-2FA policy, owner's
 * READY sandbox), which mints a one-use ticket bound to (auth session, owner,
 * sandbox, host, generation). It then upgrades here offering the subprotocols
 * `wssp.terminal.v1` and `wssp.terminal.ticket.<ticket>`. The ticket is never
 * in the URL, never selected or echoed, and never logged.
 *
 * Upgrade (HTTP refusals, before any WebSocket or PTY exists): relay enabled →
 * WebSocket upgrade → plane separation (any `Authorization` header or machine
 * credential refused) → exact Origin → subprotocol shape → cookie session →
 * rate limit (per user; per IP without a session) → atomic ticket consume →
 * binding equals (session, user, path sandbox).
 *
 * Once a valid ticket is consumed and matched, every further refusal is
 * readable by the browser: the upgrade is accepted, and the binding re-read
 * (`checkTerminalBinding`, sampling the owner/host authority ticket around the
 * read) runs BEFORE the PTY is opened; no browser frame is acted on before
 * that. A failed re-read, or a host that cannot open the PTY, closes the
 * socket with the explicit CloseIntent frame (stable intent / error code and
 * the upgrade's requestId) and code 4401, and no PTY is ever opened. The same
 * re-read then runs on a heartbeat (`BROWSER_TERMINAL_REVALIDATE_MS`), on
 * every owner or host authority commit (ban, 2FA, role, deletion, forced-2FA
 * policy), on every auth session deletion of the owner (logout, revocation)
 * and on every committed sandbox lifecycle write.
 *
 * Every identity handed to the terminal manager comes from the server-side
 * binding, never from the browser. A new attach for a sandbox REPLACES the
 * active one (C52 single attachment): the old socket receives intent
 * `replaced` and 4401.
 *
 * Lifecycle (C55): every exit path (browser close or error, client close,
 * idle timeout, re-read refusal, failed open, the host's exit, shutdown)
 * goes through the one idempotent `close`, which clears both timers and
 * forgets the terminal. Idleness is liveness: the server pings the browser
 * every `BROWSER_TERMINAL_HEARTBEAT_MS`; a browser that sends nothing (no
 * frame, no pong) for `BROWSER_TERMINAL_IDLE_MS` is gone (half-open TCP, a
 * suspended laptop) and its PTY is closed with intent `detached` and error
 * `timeout`. A watched but untouched terminal answers pings and stays open.
 * After `dispose()` (graceful shutdown) no new attach can open a PTY.
 *
 * Reattach (WP8, `wssp.terminal.v2`, sandbox terminals only): `ready` tells a
 * v2 browser its `terminalId` and output sequence, and the first open writes
 * the durable `SandboxTerminalSession` row the resume gate reads. When the
 * node negotiated `terminalResume`, a relay drop or graceful server shutdown
 * sends `reconnecting {terminalId, graceMs}` and closes with 4402 instead of
 * the final 4401; the row stays open. A resume is an ordinary attach whose
 * ticket names the terminal: the same re-read (plus the row) runs before the
 * manager sends `terminal.resume`. Every other end marks the row closed once
 * the PTY was asked to close. v1 attachments behave exactly as before.
 */

import {
  bindSandboxTerminalLifecycle,
  type SandboxTerminalLifecycleChange,
} from "@wssp/api/sandbox/terminal-lifecycle";
import {
  closeTerminalSession,
  recordTerminalSessionOpened,
} from "@wssp/api/sandbox/terminal-sessions";
import {
  checkBrowserTerminalBinding,
  type GuestTerminalGrant,
  isHostTerminalBinding,
  type BrowserTerminalBinding as TerminalBinding,
  type TerminalRevocation,
} from "@wssp/api/sandbox/terminal-tickets";
import {
  BROWSER_TERMINAL_CLOSE_CODE,
  BROWSER_TERMINAL_RECONNECT_CLOSE_CODE,
  TERMINAL_RESUME_GRACE_DEFAULT_MS,
} from "@wssp/config/browser-terminal";
import { authorityTicket, onAuthorityCommitted } from "@wssp/db/authority";
import { onAuthSessionsRevoked } from "@wssp/db/session-revocation";
import { z } from "zod";
import { type SandboxErrorCode, TERMINAL_LIMITS } from "./protocol.js";
import { sandboxRelaySessionManager } from "./session-manager.js";
import type {
  SandboxTerminalManager,
  TerminalAttachment,
  TerminalCloseNotice,
  TerminalResumeInfo,
  TerminalSessionHandle,
} from "./terminal-manager.js";

/** Session and sandbox re-read cadence while a terminal is attached. */
const BROWSER_TERMINAL_REVALIDATE_MS = 15_000;
/** Server → browser WebSocket ping cadence (C55 liveness heartbeat). */
const BROWSER_TERMINAL_HEARTBEAT_MS = 20_000;
/** No browser activity (frame or pong) for this long closes the terminal (C55). */
const BROWSER_TERMINAL_IDLE_MS = 60_000;
/** Browser text control frames are tiny JSON objects. */
const BROWSER_CONTROL_MAX_BYTES = 1024;
/**
 * Re-reads made stale by a concurrent owner/host authority change before
 * failing closed. Only an observed authority change counts: a notification
 * (a hint with no authority) re-runs the read but never ends the terminal.
 */
const VERIFY_ATTEMPTS = 3;
/**
 * Passing pre-PTY re-reads that a notification raced, before failing closed
 * (C53-N1). The PTY opens only on a read no notification raced; a hint stream
 * that races every read would otherwise keep the terminal `verifying`
 * forever. After this many consecutive raced reads the terminal ends
 * `lifecycle_unconfirmed` instead: never opened on a raced read, and no
 * attach that a storm would not already have stalled is refused (an open
 * terminal is never ended by hints, C53-CC-1). 5 leaves room for a short
 * burst of unrelated lifecycle writes.
 */
export const BROWSER_TERMINAL_RACED_OPEN_READS = 5;
/** One re-read that takes longer than this fails closed (`lifecycle_unconfirmed`). */
const BROWSER_TERMINAL_CHECK_TIMEOUT_MS = 5_000;
const clientControlSchema = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("resize"),
      requestId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/),
      rows: z.number(),
      cols: z.number(),
    })
    .strict(),
  z
    .object({
      type: z.literal("close"),
      requestId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/),
    })
    .strict(),
]);

export type BrowserSocket = {
  readonly readyState: number;
  readonly bufferedAmount: number;
  send(data: string | Uint8Array): void;
  close(code: number, reason: string): void;
  /** WebSocket ping; the browser answers with a pong on its own (C55). */
  ping?(): void;
};

type Check = typeof checkBrowserTerminalBinding;

/** WP8 durable rows; failures are logged by class and never end a terminal. */
export type TerminalSessionStore = {
  opened(identity: Parameters<typeof recordTerminalSessionOpened>[0]): Promise<void>;
  closed(terminalId: string): Promise<void>;
};
const terminalSessionStore: TerminalSessionStore = {
  opened: (identity) => recordTerminalSessionOpened(identity),
  closed: (terminalId) => closeTerminalSession(terminalId),
};

/** The browser terminal subprotocol the upgrade selected. */
export type BrowserTerminalVersion = 1 | 2;

/**
 * One upgraded browser socket. Its `TerminalAttachment` methods never throw
 * (C52-F-5 / C52-R2-2): a failing browser transport schedules a `detached`
 * close instead of unwinding into the host relay.
 */
export class BrowserTerminal implements TerminalAttachment {
  private state: "verifying" | "opening" | "open" | "closed" = "verifying";
  private socket: BrowserSocket | undefined;
  private handle: TerminalSessionHandle | undefined;
  private checking = false;
  private grant: GuestTerminalGrant | undefined;
  private transportOwnerId: string | undefined;
  private dirty = false;
  /** Passing pre-PTY reads a notification raced (C53-N1). */
  private racedOpenReads = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  /** Liveness heartbeat (C55). */
  private heartbeatTimer: ReturnType<typeof setTimeout> | undefined;
  private lastActivity = 0;
  /** requestId of the client close frame, echoed in the final close frame. */
  private closeRequestId: string | undefined;
  /** Intent for a terminal closed before its socket opened. */
  private pendingIntent: "shutdown" | undefined;
  /** WP8: the resumable terminal this socket is (or resumes); null: none. */
  private terminalId: string | null;
  /** WP8: row writes, in order (an open is never overtaken by its close). */
  private rowWrites: Promise<void> = Promise.resolve();

  constructor(
    readonly binding: TerminalBinding,
    private readonly service: BrowserTerminalService,
    /** The upgrade's `X-Request-Id`, echoed on the final close frame. */
    private readonly requestId?: string,
    /** The selected subprotocol (WP8); v2 only for sandbox terminals. */
    readonly version: BrowserTerminalVersion = 1,
  ) {
    this.terminalId =
      !isHostTerminalBinding(binding) && binding.resume ? binding.resume.terminalId : null;
  }

  /** WP8: a v2 sandbox attachment (the manager's reattach gate reads this). */
  get resumable(): boolean {
    return this.version === 2 && !isHostTerminalBinding(this.binding);
  }

  matchesOwner(ownerId: string) {
    return this.binding.userId === ownerId || this.transportOwnerId === ownerId;
  }

  get closed() {
    return this.state === "closed";
  }

  /** Armed timers (C55 resource sweep): 0 once closed. */
  get timers(): number {
    return (this.timer ? 1 : 0) + (this.heartbeatTimer ? 1 : 0);
  }

  // -- TerminalAttachment ------------------------------------------------

  get bufferedAmount(): number {
    try {
      const amount = Number(this.socket?.bufferedAmount ?? 0);
      return Number.isFinite(amount) ? amount : TERMINAL_LIMITS.attachmentBufferedMaxBytes;
    } catch {
      return TERMINAL_LIMITS.attachmentBufferedMaxBytes;
    }
  }

  sendOutput(bytes: Uint8Array): void {
    if (this.state !== "open") return;
    try {
      this.socket?.send(bytes);
    } catch {
      this.detachSoon();
    }
  }

  ready(size: { rows: number; cols: number }, resume?: TerminalResumeInfo): void {
    if (this.state === "closed") return;
    this.state = "open";
    if (resume && this.resumable && !isHostTerminalBinding(this.binding)) {
      // The first open writes the row; a resume keeps the original `openedAt`.
      if (this.terminalId === null) {
        const binding = this.binding;
        this.writeRow(() =>
          this.service.sessions.opened({
            terminalId: resume.terminalId,
            userId: binding.userId,
            sessionId: binding.sessionId,
            sandboxId: binding.sandboxId,
            hostId: binding.hostId,
            generation: binding.generation,
          }),
        );
      }
      this.terminalId = resume.terminalId;
      this.sendText({
        type: "ready",
        rows: size.rows,
        cols: size.cols,
        terminalId: resume.terminalId,
        outputSeq: resume.outputSeq,
      });
      return;
    }
    this.sendText({ type: "ready", rows: size.rows, cols: size.cols });
  }

  close(notice: TerminalCloseNotice): void {
    if (this.state === "closed") return;
    if (notice.reconnect && this.resumable) {
      this.reconnecting(notice.reconnect);
      return;
    }
    this.state = "closed";
    this.stop();
    this.forgetRow();
    // Explicit CloseIntent on the wire, then the final 4401.
    this.sendText({
      type: "close",
      code: BROWSER_TERMINAL_CLOSE_CODE,
      ...(notice.intent ? { intent: notice.intent } : {}),
      ...(notice.reason ? { reason: notice.reason } : {}),
      ...(notice.exitCode !== undefined ? { exitCode: notice.exitCode } : {}),
      ...(notice.error ? { error: notice.error } : {}),
      // The client's close request, else the upgrade's own requestId.
      ...(this.closeRequestId || this.requestId
        ? { requestId: this.closeRequestId ?? this.requestId }
        : {}),
    });
    try {
      this.socket?.close(BROWSER_TERMINAL_CLOSE_CODE, notice.intent ?? "exit");
    } catch {
      /* Transport already gone. */
    }
  }

  // -- socket events -------------------------------------------------------

  /** The upgrade completed: re-read before opening the PTY. */
  opened(socket: BrowserSocket) {
    this.socket = socket;
    if (this.state === "closed") {
      // Closed before the socket existed (shutdown): send the final frame now.
      this.state = "verifying";
      this.close({ code: BROWSER_TERMINAL_CLOSE_CODE, intent: this.pendingIntent ?? "detached" });
      return;
    }
    this.activity();
    this.armHeartbeat();
    void this.revalidate();
  }

  /** Any frame or pong from the browser: it is still there (C55). */
  activity() {
    this.lastActivity = this.service.now();
  }

  message(data: unknown) {
    if (this.state === "closed") return;
    this.activity();
    if (typeof data === "string") {
      this.control(data);
      return;
    }
    if (!(data instanceof ArrayBuffer)) return;
    if (this.state !== "open" || !this.handle) {
      this.sendError("state_conflict");
      return;
    }
    if (data.byteLength > TERMINAL_LIMITS.dataMaxBytes) {
      this.sendError("request_too_large");
      return;
    }
    const result = this.handle.input(new Uint8Array(data));
    if (!result.ok) this.sendError(result.code);
  }

  /**
   * Graceful server shutdown: the PTY is asked to close, the browser gets
   * 4401. WP8: a resumable PTY is left for the node to detach and a v2
   * browser gets `reconnecting` + 4402 instead (the manager decides).
   */
  shutdown() {
    if (this.handle) this.handle.close("shutdown");
    else if (this.socket && this.resumable && this.terminalId !== null && !this.closed) {
      // A resume still verifying: nothing was sent to the node yet.
      this.reconnecting({ terminalId: this.terminalId, graceMs: TERMINAL_RESUME_GRACE_DEFAULT_MS });
      return;
    }
    if (!this.socket && this.state !== "closed") {
      // Attached during shutdown, socket not yet open: refuse at `opened`.
      this.state = "closed";
      this.pendingIntent = "shutdown";
      this.stop();
      return;
    }
    this.close({ code: BROWSER_TERMINAL_CLOSE_CODE, intent: "shutdown" });
  }

  /** The browser socket closed or errored. */
  gone() {
    if (this.state === "closed") return;
    this.state = "closed";
    this.stop();
    this.forgetRow();
    this.handle?.close("detached");
  }

  /**
   * WP8: the PTY may still be detached on the node. The row stays open; the
   * browser may resume it with a new ticket within `graceMs`.
   */
  private reconnecting(reconnect: { terminalId: string; graceMs: number }) {
    this.state = "closed";
    this.stop();
    this.sendText({
      type: "reconnecting",
      terminalId: reconnect.terminalId,
      graceMs: reconnect.graceMs,
    });
    try {
      this.socket?.close(BROWSER_TERMINAL_RECONNECT_CLOSE_CODE, "reconnecting");
    } catch {
      /* Transport already gone. */
    }
  }

  /**
   * WP8: once the PTY was asked to close (any end but a reconnect, after the
   * manager accepted the open or resume), the terminal is never resumable.
   * A refusal before that (host not back yet, a failed re-read) leaves the
   * row alone so a later attempt can still pass the gate.
   */
  private forgetRow() {
    const terminalId = this.terminalId;
    if (terminalId === null || !this.handle) return;
    this.terminalId = null;
    this.writeRow(() => this.service.sessions.closed(terminalId));
  }

  private writeRow(write: () => Promise<void>) {
    this.rowWrites = this.rowWrites.then(write).catch((error: unknown) => {
      console.error(
        `[browser-terminal] terminal session row write failed (${error instanceof Error ? error.constructor.name : typeof error})`,
      );
    });
  }

  // -- authority -----------------------------------------------------------

  /**
   * Re-read the binding. Coalesced: one read in flight per socket; a
   * notification arriving meanwhile marks it `dirty`, and the read is re-run
   * once after it settles. A notification is only a hint: it never counts
   * toward failing closed once the PTY is open (C53-CC-1), and a dirty
   * passing read is simply repeated. Before the PTY opens, the PTY waits for
   * a read no notification raced, at most `BROWSER_TERMINAL_RACED_OPEN_READS`
   * times (C53-N1); then the terminal fails closed.
   */
  async revalidate(): Promise<void> {
    if (this.state === "closed") return;
    if (this.checking) {
      this.dirty = true;
      return;
    }
    this.checking = true;
    this.dirty = false;
    clearTimeout(this.timer);
    try {
      const outcome = await this.verify();
      if (this.closed) return;
      if (outcome !== "ok") {
        this.end(outcome);
        return;
      }
      if (this.state === "verifying") {
        if (!this.dirty) this.openPty();
        else if (++this.racedOpenReads >= BROWSER_TERMINAL_RACED_OPEN_READS) {
          this.end("lifecycle_unconfirmed");
          return;
        }
      }
      // C53-N3: a failed open closed the terminal; never re-arm a closed one.
      if (this.closed) return;
      this.arm();
    } finally {
      this.checking = false;
    }
  }

  private async verify(): Promise<"ok" | TerminalRevocation> {
    for (let stale = 0; stale < VERIFY_ATTEMPTS; stale += 1) {
      // Sampled BEFORE the read: an owner/host authority change (ban, 2FA,
      // forced-2FA policy, host removal) that starts before or during it
      // makes this stale, so the read is repeated rather than trusted. Only
      // this observed staleness counts toward failing closed.
      const fresh = authorityTicket({ ownerId: this.binding.userId, hostId: this.binding.hostId });
      const transportFresh = authorityTicket({
        hostId: this.binding.hostId,
        ...(this.transportOwnerId ? { ownerId: this.transportOwnerId } : {}),
      });
      let checked: Awaited<ReturnType<Check>>;
      try {
        checked = await this.checkWithDeadline();
      } catch {
        // A read error or a read past its deadline: authority unconfirmed.
        return "lifecycle_unconfirmed";
      }
      if (this.state === "closed") return "lifecycle_unconfirmed";
      if (!checked.ok) return checked.intent;
      if (fresh() && transportFresh()) {
        if ("grant" in checked && checked.grant) {
          if (
            this.transportOwnerId !== checked.grant.hostOwnerId &&
            checked.grant.hostOwnerId !== this.binding.userId
          ) {
            this.transportOwnerId = checked.grant.hostOwnerId;
            continue; // sample BOTH owners before the durable read, including the first open.
          }
          this.transportOwnerId = checked.grant.hostOwnerId;
          this.grant = checked.grant;
        }
        return "ok";
      }
    }
    return "lifecycle_unconfirmed";
  }

  /** `service.check`, bounded: a hung query never suspends revocation (C53-CC-3). */
  private checkWithDeadline(): ReturnType<Check> {
    let read: ReturnType<Check>;
    try {
      read = this.service.check(this.binding);
    } catch (error) {
      return Promise.reject(error);
    }
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      deadline = setTimeout(
        () => reject(new Error("terminal re-read timed out")),
        this.service.checkTimeoutMs,
      );
      deadline.unref?.();
    });
    return Promise.race([read, timeout]).finally(() => clearTimeout(deadline));
  }

  private openPty() {
    this.state = "opening";
    const binding = this.binding;
    const base = {
      ownerId: binding.userId,
      hostId: binding.hostId,
      rows: binding.rows,
      cols: binding.cols,
      attachment: this,
    };
    const opened = this.service.terminals().open(
      isHostTerminalBinding(binding)
        ? {
            ...base,
            epoch: binding.epoch,
            target: { kind: "host" },
            hostPolicy: {
              policyRevision: binding.policyRevision,
              proofRequired: binding.proofRequired,
            },
          }
        : {
            ...base,
            sandboxId: binding.sandboxId,
            generation: binding.generation,
            grant: this.grant,
            ...(this.grant?.defaultCwd ? { cwd: this.grant.defaultCwd } : {}),
            ...(binding.resume ? { resume: binding.resume } : {}),
          },
    );
    if (!opened.ok) {
      this.close({ code: BROWSER_TERMINAL_CLOSE_CODE, error: opened.error });
      return;
    }
    this.handle = opened.session;
  }

  private end(intent: TerminalRevocation) {
    if (intent === "resume_unavailable") {
      // WP8: the resumed terminal's row no longer passes the gate (closed,
      // past its lifetime, or its auth session is gone): this attachment
      // ends; the sandbox's other terminals are untouched.
      const error = {
        code: "state_conflict" as const,
        message: "the terminal can no longer be resumed",
      };
      this.close({ code: BROWSER_TERMINAL_CLOSE_CODE, intent: "expired", error });
      if (this.handle) this.handle.close("expired", error);
      return;
    }
    if (intent === "host_disconnected") {
      // WP8: the host connection this terminal rode ended or moved on (a
      // relay reconnect, or a new server process's boot sweep revoking the
      // epoch while this one still drains). A resumable PTY is left to the
      // node (the manager answers with a reconnect notice and sends no
      // `terminal.close`); anything else ends as a host disconnect.
      if (this.handle) this.handle.close("host_disconnected");
      if (!this.closed)
        this.close({
          code: BROWSER_TERMINAL_CLOSE_CODE,
          // Before the PTY: the same refusal as a host not connected here
          // (a resume attempt retries it).
          ...(this.handle
            ? { intent: "host_disconnected" as const }
            : { error: { code: "disconnected" as const, message: "host is not connected" } }),
        });
      return;
    }
    // The sandbox itself is no longer running: every live terminal of it ends
    // (carry-in 3). `superseded` closes only this binding: a terminal already
    // opened against the NEW generation must survive the old one's re-read.
    if (
      !isHostTerminalBinding(this.binding) &&
      (intent === "sandbox_stopped" || intent === "sandbox_destroyed" || intent === "expired")
    )
      this.service.terminals().closeSandbox(this.binding.sandboxId, intent);
    const reason =
      intent === "pool_access_removed" || intent === "host_terminals_disabled" ? intent : undefined;
    const wireIntent =
      intent === "pool_access_removed" || intent === "host_terminals_disabled" ? "revoked" : intent;
    // Send the specific browser reason before the manager notifies the attachment.
    this.close({ code: BROWSER_TERMINAL_CLOSE_CODE, intent: wireIntent, reason });
    if (this.handle) this.handle.close(wireIntent);
  }

  private arm() {
    if (this.closed) return;
    clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.revalidate(), this.service.revalidateMs);
    this.timer.unref?.();
    if (this.dirty) {
      this.dirty = false;
      queueMicrotask(() => void this.revalidate());
    }
  }

  /** Liveness (C55): ping, or close a browser that has gone silent. */
  private armHeartbeat() {
    if (this.closed) return;
    clearTimeout(this.heartbeatTimer);
    this.heartbeatTimer = setTimeout(() => this.heartbeat(), this.service.heartbeatMs);
    this.heartbeatTimer.unref?.();
  }

  private heartbeat() {
    this.heartbeatTimer = undefined;
    if (this.closed) return;
    if (this.service.now() - this.lastActivity >= this.service.idleMs) {
      const error = { code: "timeout" as const, message: "browser terminal idle" };
      // The manager's close notifies this attachment (one CloseIntent).
      if (this.handle) this.handle.close("detached", error);
      this.close({ code: BROWSER_TERMINAL_CLOSE_CODE, intent: "detached", error });
      return;
    }
    try {
      this.socket?.ping?.();
    } catch {
      this.detachSoon();
      return;
    }
    this.armHeartbeat();
  }

  private stop() {
    clearTimeout(this.timer);
    this.timer = undefined;
    clearTimeout(this.heartbeatTimer);
    this.heartbeatTimer = undefined;
    this.service.forget(this);
  }

  private control(text: string) {
    if (text.length > BROWSER_CONTROL_MAX_BYTES) {
      this.protocolViolation();
      return;
    }
    let parsed: z.infer<typeof clientControlSchema>;
    try {
      parsed = clientControlSchema.parse(JSON.parse(text));
    } catch {
      this.protocolViolation();
      return;
    }
    if (parsed.type === "close") {
      this.closeRequestId = parsed.requestId;
      if (this.handle) this.handle.close("client");
      else this.close({ code: BROWSER_TERMINAL_CLOSE_CODE, intent: "client" });
      return;
    }
    if (this.state !== "open" || !this.handle) {
      this.sendError("state_conflict", parsed.requestId);
      return;
    }
    const resized = this.handle.resize(parsed.rows, parsed.cols);
    if (!resized.ok) this.sendError(resized.code, parsed.requestId);
  }

  private protocolViolation() {
    const error = { code: "protocol_error" as const, message: "invalid terminal control frame" };
    if (this.handle) {
      this.handle.close("protocol_violation");
      return;
    }
    this.close({ code: BROWSER_TERMINAL_CLOSE_CODE, intent: "protocol_violation", error });
  }

  private sendError(code: SandboxErrorCode, requestId?: string) {
    // A browser that floods refused frames without reading the answers is
    // detached like a slow output consumer: error frames never grow the buffer.
    if (this.bufferedAmount > TERMINAL_LIMITS.attachmentBufferedMaxBytes) {
      if (this.handle) this.handle.close("backpressure");
      else this.close({ code: BROWSER_TERMINAL_CLOSE_CODE, intent: "backpressure" });
      return;
    }
    this.sendText({ type: "error", code, ...(requestId ? { requestId } : {}) });
  }

  private sendText(frame: Record<string, unknown>) {
    try {
      this.socket?.send(JSON.stringify(frame));
    } catch {
      this.detachSoon();
    }
  }

  private detachSoon() {
    queueMicrotask(() => {
      if (this.state === "closed") return;
      this.state = "closed";
      this.stop();
      this.forgetRow();
      this.handle?.close("detached");
    });
  }
}

/** Owns every attached browser terminal of this process and their re-read triggers. */
export class BrowserTerminalService {
  private readonly attached = new Set<BrowserTerminal>();
  private unsubscribe: (() => void) | undefined;
  private disposed = false;

  constructor(
    readonly terminals: () => SandboxTerminalManager,
    readonly check: Check = checkBrowserTerminalBinding,
    readonly revalidateMs = BROWSER_TERMINAL_REVALIDATE_MS,
    readonly checkTimeoutMs = BROWSER_TERMINAL_CHECK_TIMEOUT_MS,
    readonly heartbeatMs = BROWSER_TERMINAL_HEARTBEAT_MS,
    readonly idleMs = BROWSER_TERMINAL_IDLE_MS,
    /** The idle clock (C55: fake-clock testable). */
    readonly now: () => number = Date.now,
    /** WP8 durable reattach rows. */
    readonly sessions: TerminalSessionStore = terminalSessionStore,
  ) {}

  /** Live browser terminals (metadata only; tests and metrics). */
  count(): number {
    return this.attached.size;
  }

  /** Graceful shutdown began: no attach may open a PTY any more (C53-FS-2). */
  get shuttingDown(): boolean {
    return this.disposed;
  }

  /** Outstanding resources (C55 end-of-scenario sweep): all 0 when idle. */
  resources() {
    let timers = 0;
    for (const terminal of this.attached) timers += terminal.timers;
    return { attached: this.attached.size, timers, subscribed: this.unsubscribe ? 1 : 0 };
  }

  attach(
    binding: TerminalBinding,
    requestId?: string,
    version: BrowserTerminalVersion = 1,
  ): BrowserTerminal {
    const terminal = new BrowserTerminal(binding, this, requestId, version);
    if (this.disposed) {
      // C53-FS-2: an upgrade completing during shutdown never re-subscribes
      // and never opens a PTY: it gets CloseIntent `shutdown` + 4401.
      terminal.shutdown();
      return terminal;
    }
    this.start();
    this.attached.add(terminal);
    return terminal;
  }

  forget(terminal: BrowserTerminal) {
    this.attached.delete(terminal);
    // The last terminal gone: drop the re-read subscriptions too.
    if (this.attached.size === 0) this.stopListening();
  }

  /** Graceful shutdown: every browser terminal ends with intent `shutdown`. */
  dispose() {
    this.disposed = true;
    this.stopListening();
    for (const terminal of [...this.attached]) terminal.shutdown();
  }

  private stopListening() {
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }

  private revalidateWhere(match: (binding: TerminalBinding) => boolean) {
    for (const terminal of [...this.attached])
      if (match(terminal.binding)) void terminal.revalidate();
  }

  private start() {
    if (this.unsubscribe) return;
    const offAuthority = onAuthorityCommitted((scope) => {
      for (const terminal of [...this.attached]) {
        if (
          scope.kind === "global" ||
          (scope.ownerId !== undefined && terminal.matchesOwner(scope.ownerId)) ||
          (scope.hostId !== undefined && terminal.binding.hostId === scope.hostId)
        )
          void terminal.revalidate();
      }
    });
    const offSessions = onAuthSessionsRevoked(({ userId, sessionId }) =>
      this.revalidateWhere(
        (binding) =>
          (userId === undefined || binding.userId === userId) &&
          (sessionId === undefined || binding.sessionId === sessionId),
      ),
    );
    bindSandboxTerminalLifecycle((change: SandboxTerminalLifecycleChange) =>
      this.revalidateWhere(
        (binding) =>
          change === "all" ||
          (!isHostTerminalBinding(binding) && change.sandboxIds.has(binding.sandboxId)),
      ),
    );
    this.unsubscribe = () => {
      offAuthority();
      offSessions();
      bindSandboxTerminalLifecycle(null);
    };
  }
}

export const browserTerminalService = new BrowserTerminalService(
  () => sandboxRelaySessionManager.terminals,
);
