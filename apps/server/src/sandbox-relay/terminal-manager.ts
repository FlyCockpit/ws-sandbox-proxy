/**
 * Server half of the C52 terminal channel: session dispatch, fence
 * validation, credit-window flow control and bounded per-session queues.
 *
 * A terminal session binds ONE browser attachment to ONE host PTY. The
 * in-memory session never survives its host socket (no adoption across socket
 * or generation replacement) and input is never replayed. WP8 reattach is a
 * NEW session for the same PTY: when the node negotiated `terminalResume`
 * and the attachment speaks `wssp.terminal.v2`, a sandbox session lost with
 * its host socket (or at graceful server shutdown) ends with a `reconnect`
 * notice instead of a final one, and a later `open({ resume })` (a fresh
 * one-use ticket, re-checked against `SandboxTerminalSession`) sends
 * `terminal.resume` for the same terminal id under the new connection's
 * fence. Without the capability every path behaves exactly as before. Every identity the
 * host receives is minted here (session/operation/request ids) or comes from
 * the caller's server-side records (owner, host, sandbox, generation) and
 * the authenticated host connection (epoch); never from the browser.
 *
 * Single attachment: at most one ACTIVE session per sandbox. A new open
 * replaces it: the old attachment closes with 4401 and intent `replaced`,
 * and its PTY is closed on the host. Sessions stay counted (per host and per
 * sandbox) until the host's final `terminal.exit` or the socket ends.
 *
 * One close boundary (C55): every trigger (browser loss or close, idle
 * timeout, replacement, backpressure, revocation, supersession, lifecycle,
 * host loss and shutdown) ends a session through `closeSession` (server
 * initiated) or `finish` (the host's exit / the socket's end). Both are
 * idempotent: the attachment hears exactly one CloseIntent + 4401, the host
 * gets at most one `terminal.close`, and the count is released exactly once.
 * An exit with `reaped: false` keeps the session counted (`unreaped`) until
 * the host's reconciliation sweep confirms the reap with a second exit
 * (`reaped: true`) or the socket ends; it is never released optimistically.
 *
 * Terminal frames bypass the host socket's serialized receive queue: they are
 * validated and routed synchronously, so a PTY flood never queues ahead of
 * heartbeats, cancellation or expiry control. Host output is bounded by the
 * credit window; browser output is bounded by the attachment's
 * `bufferedAmount` (overflow detaches with an explicit backpressure error).
 *
 * Authority (C52-CO-1/TB-1): both directions use the host link's cached
 * ticket. Host→server frames are gated (held, never dropped) by the relay
 * session manager before they reach this class. Server→host input and
 * resizes are gated here: under a stale ticket they stay queued/deferred and
 * are sent by `resumeHost` once the ticket is refreshed; a revoked host gets
 * none of them (its socket's sessions are removed).
 */
import { randomUUID } from "node:crypto";

import {
  encodeServerControlMessage,
  encodeTerminalDataFrame,
  type SandboxErrorCode,
  TERMINAL_LIMITS,
  type TerminalCloseIntent,
  type TerminalDataMetadata,
  type TerminalFence,
} from "./protocol.js";

type HostSocket = {
  readonly readyState: number;
  send(data: string | ArrayBuffer | Uint8Array): void;
};

const WS_READY_STATE_OPEN = 1;
/** Outstanding resize requests per session (each answered by `terminal.ready`). */
export const TERMINAL_MAX_PENDING_RESIZES = 4;
/** Foreign (unknown, non-tombstoned) terminal frames tolerated per host socket. */
export const TERMINAL_FOREIGN_FRAME_LIMIT = 256;
const AUDIT_LOGS_PER_SOCKET = 16;

/** The browser-facing error of a node daemon's own `shutdown` exit (C55-CO-6). */
export const NODE_DAEMON_SHUTDOWN_ERROR = {
  code: "disconnected",
  message: "the sandbox node daemon shut down",
} as const satisfies { code: SandboxErrorCode; message: string };

/**
 * The browser-facing error of a host whose credential stopped authorizing it
 * (revoked, expired, deleted, banned owner; C52-R2-1). Its terminals end
 * `host_disconnected`, never `revoked`: the owner's own sign-in is fine.
 */
export const HOST_CREDENTIAL_INACTIVE_ERROR = {
  code: "access_denied",
  message: "the sandbox host's credential is no longer active",
} as const satisfies { code: SandboxErrorCode; message: string };

/** Final notice delivered to a browser attachment, exactly once. */
export type TerminalCloseNotice = {
  code: typeof TERMINAL_LIMITS.closeCode;
  /** Absent: the shell exited on its own (`exitCode`). */
  intent?: TerminalCloseIntent;
  /** `ended_elsewhere`: the owner ended it from the Terminals page (intent `client`). */
  reason?: "pool_access_removed" | "host_terminals_disabled" | "ended_elsewhere";
  exitCode?: number;
  error?: { code: SandboxErrorCode; message: string };
  /**
   * WP8: the PTY may still be detached on the node for `graceMs`; a v2
   * attachment may resume it. Only ever set for a resumable session.
   */
  reconnect?: { terminalId: string; graceMs: number };
};

/** WP8: the resumable identity a v2 attachment learns on an open/resume answer. */
export type TerminalResumeInfo = { terminalId: string; outputSeq: number };

/**
 * The browser side of one session (C53 binds it to the upgraded socket).
 * Implementations should not throw; the manager still contains any throw from
 * `ready`, `sendOutput` or `bufferedAmount` and closes the session `detached`
 * (C52-F-5), so a failing browser never unwinds into host frame handling.
 */
export type TerminalAttachment = {
  /** Bytes queued toward the browser but not yet written (WebSocket semantics). */
  readonly bufferedAmount: number;
  sendOutput(bytes: Uint8Array): void;
  /**
   * Open answered or resize applied, with the size the PTY now has. `resume`
   * only on the answer to an open or resume of a resumable session.
   */
  ready(size: { rows: number; cols: number }, resume?: TerminalResumeInfo): void;
  /** WP8: a `wssp.terminal.v2` attachment (can reconnect). Absent: v1. */
  readonly resumable?: boolean;
  /** Send the explicit close intent, then close the socket with 4401. */
  close(notice: TerminalCloseNotice): void;
};

/** What the relay session manager knows about one registered host socket. */
export type TerminalHostLink = {
  socket: HostSocket;
  hostId: string;
  ownerId: string;
  epoch: number;
  hostPolicy?: import("./host-terminal-policy.js").HostTerminalPolicy;
  protocolVersion: string;
  /** WP8: the node's negotiated reattach grace; absent: it never detaches a PTY. */
  resumeGraceMs?: number;
  /** Cached host-credential authority (no IO): false holds input and resizes back. */
  authorized(): boolean;
};

export type TerminalHosts = {
  terminalHost(
    hostId: string,
    kind?: "host" | "sandbox",
    /** WP8: a reattach of a detached PTY, not a fresh open. A quiescing
     * host refuses fresh opens only: the daemon still serves a resume. */
    purpose?: "open" | "resume",
  ): { link: TerminalHostLink } | { error: { code: SandboxErrorCode; message: string } };
  /** The host socket abused the channel; close it with a protocol error. */
  closeHostSocket(socket: HostSocket, message: string): void;
};

export type TerminalOpenInput = {
  grant?: import("@wssp/api/sandbox/terminal-tickets").GuestTerminalGrant;
  target?: never;
  /** Owner from the authenticated browser session (C53 re-reads it). */
  ownerId: string;
  /** Host, sandbox and generation from the server's sandbox record. */
  hostId: string;
  sandboxId: string;
  generation: number;
  rows: number;
  cols: number;
  /** The revision's default cwd (server-side record); absent: guest home. */
  cwd?: string;
  /**
   * WP8: reattach this detached terminal instead of opening a PTY. From the
   * consumed ticket row (gated against `SandboxTerminalSession`), never the
   * browser's socket.
   */
  resume?: { terminalId: string; nextOutputSeq: number };
  attachment: TerminalAttachment;
};

/** Host input comes only from the durable browser binding authorizer. */
export type HostTerminalOpenInput = {
  epoch?: number;
  ownerId: string;
  hostId: string;
  target: { kind: "host" };
  hostPolicy: { policyRevision: number; proofRequired: boolean };
  rows: number;
  cols: number;
  attachment: TerminalAttachment;
};

export type TerminalSessionHandle = {
  readonly sessionId: string;
  /** Queue guest input; refused (nothing queued) when the bounded queue is full. */
  input(bytes: Uint8Array): { ok: true } | { ok: false; code: SandboxErrorCode };
  resize(rows: number, cols: number): { ok: true } | { ok: false; code: SandboxErrorCode };
  /** Idempotent; `error` rides the attachment's CloseIntent (e.g. idle `timeout`). */
  close(
    intent?: TerminalCloseIntent,
    error?: { code: SandboxErrorCode; message: string },
    reason?: TerminalCloseNotice["reason"],
  ): void;
};

/**
 * `closing`: asked to end, still counted until the host's exit.
 * `unreaped`: the host exited with an uncertain reap; still counted until
 * its reconciliation exit (C55). `ended`: released (terminal state).
 */
type SessionState = "opening" | "open" | "closing" | "unreaped" | "ended";

/** Outstanding resources (C55): every scenario must end with all at zero. */
export type TerminalManagerResources = {
  /** Sessions still counted against a host or sandbox cap. */
  sessions: number;
  /**
   * Sessions in the global `sessionId` index (C55-CC-2). Every counted
   * session is indexed and every released one is removed, so this equals
   * `sessions`; a session left in only one of the two shows up here.
   */
  indexed: number;
  /** Of those, sessions held only by an uncertain reap. */
  unreaped: number;
  openTimers: number;
  queuedInputBytes: number;
  pendingResizes: number;
  deferredResizes: number;
  /** Host sockets with per-socket state (open rate, tombstones). */
  sockets: number;
};

type TerminalSession = {
  creatorId: string;
  fence: TerminalFence;
  protocolVersion: string;
  socket: HostSocket;
  /** The host link's cached authority; gates every byte sent to the host. */
  authorized: () => boolean;
  attachment: TerminalAttachment;
  attachmentClosed: boolean;
  /** WP8: sandbox target, v2 attachment, node negotiated `terminalResume`. */
  resumeGraceMs?: number;
  /** WP8: an outstanding `terminal.resume` asked for output from here. */
  resumeFrom?: number;
  state: SessionState;
  openRequestId: string;
  pendingResizes: Map<string, { rows: number; cols: number }>;
  /** Latest resize asked for while the host's authority was being revalidated. */
  deferredResize?: { rows: number; cols: number };
  /** Next expected host→server output sequence. */
  outputNext: number;
  /** Next server→host input sequence and the count the host acknowledged. */
  inputNext: number;
  inputAcked: number;
  /** Coalesced input chunks (C52-F-1): every entry but the last is full. */
  inputQueue: InputChunk[];
  inputQueuedBytes: number;
  violations: number;
  openTimer?: ReturnType<typeof setTimeout>;
};

/** A queued input frame body, grown in place up to `dataMaxBytes` (C52-F-1). */
type InputChunk = { bytes: Uint8Array; length: number };

type SocketState = {
  sessions: Set<TerminalSession>;
  opens: { at: number; creatorId: string | null }[];
  tombstones: string[];
  foreign: number;
  audits: number;
};

function mintId(prefix: string): string {
  return `${prefix}${randomUUID().replaceAll("-", "")}`;
}

function sameFence(a: TerminalFence, b: TerminalFence): boolean {
  return (
    a.sessionId === b.sessionId &&
    a.operationId === b.operationId &&
    a.hostId === b.hostId &&
    sameTarget(a.target, b.target) &&
    a.epoch === b.epoch
  );
}

function sameTarget(a: TerminalFence["target"], b: TerminalFence["target"]): boolean {
  return (
    a.kind === b.kind &&
    (a.kind === "host" ||
      (b.kind === "sandbox" && a.sandboxId === b.sandboxId && a.generation === b.generation))
  );
}
function targetKey(t: TerminalFence["target"]): string {
  return t.kind === "host" ? "host" : `sandbox:${t.sandboxId}`;
}

function validSize(rows: number, cols: number): boolean {
  return (
    Number.isInteger(rows) &&
    Number.isInteger(cols) &&
    rows >= 1 &&
    rows <= TERMINAL_LIMITS.maxRows &&
    cols >= 1 &&
    cols <= TERMINAL_LIMITS.maxCols
  );
}

/**
 * Queue input as coalesced chunks (C52-F-1): bytes are appended to the last
 * not-yet-full chunk, so the queue holds at most
 * ceil(inputQueueMaxBytes / dataMaxBytes) + 1 entries however small the
 * browser's frames are. A chunk's buffer grows geometrically, so appends are
 * amortized O(bytes).
 */
function enqueueInput(session: TerminalSession, bytes: Uint8Array) {
  let offset = 0;
  while (offset < bytes.byteLength) {
    let last = session.inputQueue.at(-1);
    if (!last || last.length === TERMINAL_LIMITS.dataMaxBytes) {
      last = { bytes: new Uint8Array(0), length: 0 };
      session.inputQueue.push(last);
    }
    const take = Math.min(TERMINAL_LIMITS.dataMaxBytes - last.length, bytes.byteLength - offset);
    if (last.bytes.byteLength < last.length + take) {
      const grown = new Uint8Array(
        Math.min(
          TERMINAL_LIMITS.dataMaxBytes,
          Math.max(last.length + take, last.bytes.byteLength * 2, 64),
        ),
      );
      grown.set(last.bytes.subarray(0, last.length));
      last.bytes = grown;
    }
    last.bytes.set(bytes.subarray(offset, offset + take), last.length);
    last.length += take;
    offset += take;
    session.inputQueuedBytes += take;
  }
}

/** C52-F-5: an unreadable browser buffer counts as full (detach, never throw). */
function attachmentBuffered(session: TerminalSession): number {
  try {
    const amount = Number(session.attachment.bufferedAmount);
    return Number.isFinite(amount) && amount >= 0
      ? amount
      : TERMINAL_LIMITS.attachmentBufferedMaxBytes;
  } catch {
    return TERMINAL_LIMITS.attachmentBufferedMaxBytes;
  }
}

const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
/** Terminal ids this server mints (`mintId("t")`); a resume names only those. */
const TERMINAL_ID = /^t[0-9a-f]{32}$/;

export type HostTerminalControl =
  | {
      type: "terminal.ready";
      requestId: string;
      fence: TerminalFence;
      rows: number;
      cols: number;
      /** WP8: only on the answer to `terminal.resume`. */
      outputSeq?: number;
    }
  | { type: "terminal.ack"; fence: TerminalFence; sequence: number }
  | {
      type: "terminal.exit";
      requestId?: string;
      fence: TerminalFence;
      exitCode?: number;
      intent?: TerminalCloseIntent;
      reaped: boolean;
      error?: { code: SandboxErrorCode; message: string };
    };

export class SandboxTerminalManager {
  private sessions = new Map<string, TerminalSession>();
  private sockets = new Map<HostSocket, SocketState>();

  constructor(
    private readonly hosts: TerminalHosts,
    private readonly now: () => number = Date.now,
  ) {}

  /** Outstanding resources across every socket (C55 end-of-scenario sweep). */
  resources(): TerminalManagerResources {
    const counted = [...this.sockets.values()].flatMap((state) => [...state.sessions]);
    return {
      sessions: counted.length,
      indexed: this.sessions.size,
      unreaped: counted.filter((session) => session.state === "unreaped").length,
      openTimers: counted.filter((session) => session.openTimer !== undefined).length,
      queuedInputBytes: counted.reduce((sum, session) => sum + session.inputQueuedBytes, 0),
      pendingResizes: counted.reduce((sum, session) => sum + session.pendingResizes.size, 0),
      deferredResizes: counted.filter((session) => session.deferredResize !== undefined).length,
      sockets: this.sockets.size,
    };
  }

  /** Live sessions (opening, open or closing) per host socket — for tests/metrics. */
  sessionCount(socket?: HostSocket): number {
    if (!socket) return this.sessions.size;
    return this.sockets.get(socket)?.sessions.size ?? 0;
  }

  /** The fence of a live session (metadata only; for observability/tests). */
  sessionFence(sessionId: string): TerminalFence | undefined {
    const session = this.sessions.get(sessionId);
    return session ? { ...session.fence } : undefined;
  }

  open(
    input: TerminalOpenInput | HostTerminalOpenInput,
  ):
    | { ok: true; session: TerminalSessionHandle }
    | { ok: false; error: { code: SandboxErrorCode; message: string } } {
    const refuse = (code: SandboxErrorCode, message: string) =>
      ({ ok: false, error: { code, message } }) as const;
    const hostTarget = input.target?.kind === "host";
    const target: TerminalFence["target"] = input.target ?? {
      kind: "sandbox",
      sandboxId: input.sandboxId,
      generation: input.generation,
    };
    if (
      !validSize(input.rows, input.cols) ||
      !ID.test(input.hostId) ||
      (target.kind === "sandbox" &&
        (!ID.test(target.sandboxId) ||
          !Number.isSafeInteger(target.generation) ||
          target.generation < 1))
    )
      return refuse("protocol_error", "invalid terminal open request");
    const resume = input.target ? undefined : input.resume;
    if (
      resume &&
      (!TERMINAL_ID.test(resume.terminalId) ||
        !Number.isSafeInteger(resume.nextOutputSeq) ||
        resume.nextOutputSeq < 0)
    )
      return refuse("protocol_error", "invalid terminal resume request");
    // Host-target terminals are never resumable (WP8).
    if (input.target && "resume" in input)
      return refuse("unsupported_capability", "host terminals cannot be resumed");
    const host = this.hosts.terminalHost(input.hostId, target.kind, resume ? "resume" : "open");
    if ("error" in host) return { ok: false, error: host.error };
    const { link } = host;
    // A resume needs the node's capability and a v2 attachment; the reattach
    // gate already passed (ticket + `SandboxTerminalSession` re-read).
    if (resume && (link.resumeGraceMs === undefined || input.attachment.resumable !== true))
      return refuse("unsupported_capability", "Unsupported capability: terminalResume");
    // One live session per terminal id: a resume never takes over a session
    // that is still attached (or closing) here.
    if (resume && this.sessions.has(resume.terminalId))
      return refuse("state_conflict", "terminal is still attached");
    if (input.target) {
      if (
        link.ownerId !== input.ownerId ||
        (input.epoch !== undefined && input.epoch !== link.epoch)
      )
        return refuse("sandbox_not_found", "sandbox not found");
    } else {
      const grant = input.grant;
      if (
        grant
          ? grant.creatorId !== input.ownerId ||
            grant.hostOwnerId !== link.ownerId ||
            grant.hostId !== link.hostId ||
            grant.epoch !== link.epoch ||
            grant.sandboxId !== input.sandboxId ||
            grant.generation !== input.generation
          : link.ownerId !== input.ownerId
      )
        return refuse("sandbox_not_found", "sandbox not found");
    }
    if (!link.authorized() || link.socket.readyState !== WS_READY_STATE_OPEN)
      return refuse("disconnected", "host is not connected");
    if (
      input.target &&
      (!link.hostPolicy?.hostTerminal ||
        link.hostPolicy.policyRevision !== input.hostPolicy.policyRevision ||
        link.hostPolicy.requireHostTerminalTotp !== input.hostPolicy.proofRequired)
    )
      return refuse("access_denied", "host terminal policy changed");
    const socketState = this.socketState(link.socket);
    const now = this.now();
    socketState.opens = socketState.opens.filter(({ at }) => now - at < 60_000);
    if (
      socketState.opens.length >= TERMINAL_LIMITS.opensPerMinutePerHost ||
      (!hostTarget &&
        (socketState.opens.filter((o) => o.creatorId !== null).length >=
          TERMINAL_LIMITS.opensPerMinutePerHost - TERMINAL_LIMITS.reservedHostOpensPerMinute ||
          socketState.opens.filter((o) => o.creatorId === input.ownerId).length >=
            TERMINAL_LIMITS.opensPerMinutePerGuestCreator))
    )
      return refuse("rate_limited", "terminal open rate exceeded for this host");
    // Capacity is checked BEFORE replacement: a refused open never closes the
    // active session. Closing sessions stay counted until the host confirms.
    if (socketState.sessions.size >= TERMINAL_LIMITS.maxSessionsPerHost)
      return refuse("host_capacity", "host terminal capacity reached");
    const counted = [...socketState.sessions];
    if (
      !hostTarget &&
      (counted.filter((s) => s.fence.target.kind === "sandbox").length >=
        TERMINAL_LIMITS.maxGuestSessionsPerHost ||
        counted.filter((s) => s.fence.target.kind === "sandbox" && s.creatorId === input.ownerId)
          .length >= TERMINAL_LIMITS.maxSessionsPerGuestCreator)
    )
      return refuse("host_capacity", "guest terminal capacity reached");
    const sandboxSessions = counted.filter(
      (session) => targetKey(session.fence.target) === targetKey(target),
    );
    if (sandboxSessions.length >= TERMINAL_LIMITS.maxLiveSessionsPerSandbox)
      return refuse("host_capacity", "a previous terminal for this sandbox is still closing");

    const fence: TerminalFence = {
      sessionId: resume?.terminalId ?? mintId("t"),
      operationId: mintId("top"),
      hostId: link.hostId,
      target,
      epoch: link.epoch,
    };
    const session: TerminalSession = {
      creatorId: input.ownerId,
      fence,
      socket: link.socket,
      protocolVersion: link.protocolVersion,
      authorized: link.authorized,
      attachment: input.attachment,
      attachmentClosed: false,
      ...(!hostTarget && link.resumeGraceMs !== undefined && input.attachment.resumable === true
        ? { resumeGraceMs: link.resumeGraceMs }
        : {}),
      ...(resume ? { resumeFrom: resume.nextOutputSeq } : {}),
      state: "opening",
      openRequestId: mintId("tr"),
      pendingResizes: new Map(),
      outputNext: 0,
      inputNext: 0,
      inputAcked: 0,
      inputQueue: [],
      inputQueuedBytes: 0,
      violations: 0,
    };
    try {
      link.socket.send(
        encodeServerControlMessage(
          resume
            ? {
                // Sent only after the node's `reconcile.complete`: a sandbox
                // `terminalHost` link exists only for a reconciled session.
                type: "terminal.resume",
                requestId: session.openRequestId,
                fence,
                nextOutputSeq: resume.nextOutputSeq,
                rows: input.rows,
                cols: input.cols,
              }
            : {
                ...(input.target ? { hostPolicy: input.hostPolicy } : {}),
                type: "terminal.open",
                requestId: session.openRequestId,
                fence,
                rows: input.rows,
                cols: input.cols,
                ...(!input.target && input.cwd ? { cwd: input.cwd } : {}),
              },
          session.protocolVersion,
        ),
      );
    } catch {
      // Nothing changed: the active session and the open rate are untouched.
      return refuse("transport", "terminal open could not be sent");
    }
    socketState.opens.push({ at: now, creatorId: hostTarget ? null : input.ownerId });
    // New attach replaces the active one (single attachment), only once the
    // new open is on the wire.
    for (const old of sandboxSessions)
      if (old.state === "opening" || old.state === "open") this.closeSession(old, "replaced");
    this.sessions.set(fence.sessionId, session);
    socketState.sessions.add(session);
    session.openTimer = setTimeout(() => {
      session.openTimer = undefined;
      if (session.state === "opening")
        this.closeSession(session, "expired", {
          code: "timeout",
          message: "terminal open was not answered in time",
        });
    }, TERMINAL_LIMITS.openTimeoutMs);
    session.openTimer.unref?.();
    return { ok: true, session: this.handle(session) };
  }

  closeHostTarget(hostId: string, reason?: TerminalCloseNotice["reason"]): void {
    for (const session of this.sessions.values())
      if (session.fence.hostId === hostId && session.fence.target.kind === "host")
        this.closeSession(session, "revoked", undefined, reason);
  }

  /** Close every live session of one sandbox (lifecycle, revocation). */
  closeSandbox(sandboxId: string, intent: TerminalCloseIntent): number {
    let closed = 0;
    for (const session of [...this.sessions.values()])
      if (
        session.fence.target.kind === "sandbox" &&
        session.fence.target.sandboxId === sandboxId &&
        (session.state === "opening" || session.state === "open")
      ) {
        this.closeSession(session, intent);
        closed += 1;
      }
    return closed;
  }

  /**
   * The host socket ended or was replaced: every session ends with it. The
   * host stops every PTY of a connection that ends, and keeps its own slot
   * of a PTY whose reap is uncertain, so the per-socket counts (including
   * `unreaped` ones) are released here exactly once.
   *
   * `askHost` (graceful server shutdown only): while the socket is still
   * open, each live session first gets its `terminal.close` with `intent`, so
   * the host ends it with that intent instead of `host_disconnected`. A
   * revoked or replaced socket is never sent anything. `error` rides each
   * attachment's CloseIntent (a host whose credential went inactive).
   */
  removeHostSocket(
    socket: HostSocket,
    intent: TerminalCloseIntent = "host_disconnected",
    askHost = false,
    error?: { code: SandboxErrorCode; message: string },
  ) {
    const state = this.sockets.get(socket);
    if (!state) return;
    for (const session of [...state.sessions]) {
      const live = session.state === "opening" || session.state === "open";
      // WP8: the node keeps a resumable PTY detached; the browser is told it
      // may reattach, and the PTY is never asked to close.
      if (!error && (intent === "host_disconnected" || intent === "shutdown")) {
        const reconnect = this.reconnectNotice(session);
        if (reconnect) {
          this.release(session, { code: TERMINAL_LIMITS.closeCode, intent, reconnect });
          continue;
        }
      }
      if (askHost && live)
        this.sendToHost(session, {
          type: "terminal.close",
          requestId: mintId("tr"),
          fence: session.fence,
          intent,
        });
      this.release(session, {
        code: TERMINAL_LIMITS.closeCode,
        intent,
        ...(error ? { error } : {}),
      });
    }
    this.sockets.delete(socket);
  }

  /** Graceful shutdown: every host is asked to close every live PTY first. */
  closeAll(intent: TerminalCloseIntent) {
    for (const socket of [...this.sockets.keys()]) this.removeHostSocket(socket, intent, true);
  }

  /** The host's authority ticket was refreshed: send what was held back. */
  resumeHost(socket: HostSocket) {
    const state = this.sockets.get(socket);
    if (!state) return;
    for (const session of [...state.sessions]) {
      if (session.state !== "open") continue;
      this.flushInput(session);
      const deferred = session.deferredResize;
      if (deferred && session.state === "open" && session.authorized()) {
        session.deferredResize = undefined;
        this.sendResize(session, deferred.rows, deferred.cols);
      }
    }
  }

  handleHostControl(socket: HostSocket, message: HostTerminalControl) {
    const session = this.lookup(socket, message.fence);
    if (!session) return;
    switch (message.type) {
      case "terminal.ready": {
        // C52-F-3: a close we asked for races the host's answer to an open or
        // resize sent before it; that late `ready` is dropped like late
        // output, never counted as a violation.
        if (session.state === "closing") return;
        if (session.state === "opening" && message.requestId === session.openRequestId) {
          // WP8: a resume answer names where output continues (>= what the
          // browser asked for; more means the node's ring lost output). An
          // open answer never carries one.
          const resumeFrom = session.resumeFrom;
          if (
            resumeFrom === undefined
              ? message.outputSeq !== undefined
              : message.outputSeq === undefined || message.outputSeq < resumeFrom
          ) {
            this.closeSession(session, "protocol_violation", {
              code: "protocol_error",
              message: "terminal resume answer out of range",
            });
            return;
          }
          clearTimeout(session.openTimer);
          session.state = "open";
          session.resumeFrom = undefined;
          session.outputNext = message.outputSeq ?? 0;
          this.attachmentReady(
            session,
            { rows: message.rows, cols: message.cols },
            session.resumeGraceMs === undefined
              ? undefined
              : { terminalId: session.fence.sessionId, outputSeq: session.outputNext },
          );
          return;
        }
        const resize = session.pendingResizes.get(message.requestId);
        if (session.state === "open" && resize && message.outputSeq === undefined) {
          session.pendingResizes.delete(message.requestId);
          this.attachmentReady(session, { rows: message.rows, cols: message.cols });
          return;
        }
        this.violation(session, "unexpected terminal.ready");
        return;
      }
      case "terminal.ack": {
        if (message.sequence < session.inputAcked || message.sequence >= session.inputNext) {
          this.violation(session, "terminal input ack out of range");
          return;
        }
        session.inputAcked = message.sequence + 1;
        this.flushInput(session);
        return;
      }
      case "terminal.exit": {
        if (session.state === "unreaped") {
          // The host's reconciliation sweep (C55): only a confirmed reap
          // releases the held slot; anything else is a violation.
          if (message.reaped) this.release(session);
          else this.violation(session, "repeated uncertain terminal exit");
          return;
        }
        // A host-originated `shutdown` is its daemon stopping (C55-CO-6). The
        // server's own shutdown never reaches here (its browsers are closed
        // first and its sockets released), so the browser is told which one
        // it was by `disconnected`, not shown "the server restarted".
        const error =
          message.error ?? (message.intent === "shutdown" ? NODE_DAEMON_SHUTDOWN_ERROR : undefined);
        const notice: TerminalCloseNotice = {
          code: TERMINAL_LIMITS.closeCode,
          ...(message.intent ? { intent: message.intent } : {}),
          ...(message.exitCode !== undefined ? { exitCode: message.exitCode } : {}),
          ...(error ? { error } : {}),
        };
        if (message.reaped) {
          this.release(session, notice);
          return;
        }
        // Uncertain reap: the browser hears the end now, but the session
        // stays counted (never released optimistically) until the host
        // confirms the reap or its socket ends.
        this.hold(session, notice);
        return;
      }
    }
  }

  handleHostData(socket: HostSocket, metadata: TerminalDataMetadata, body: Uint8Array) {
    const session = this.lookup(socket, metadata.fence);
    if (!session) return;
    // Output racing a close we requested is dropped: the host ends it anyway.
    if (session.state === "closing") return;
    if (session.state === "unreaped" || session.state === "ended") {
      this.violation(session, "terminal output after exit");
      return;
    }
    if (session.state !== "open") {
      this.violation(session, "terminal output before ready");
      return;
    }
    if (metadata.sequence < session.outputNext) {
      // Duplicate/replayed output: zero bytes delivered.
      this.violation(session, "duplicate terminal output sequence");
      return;
    }
    if (metadata.sequence > session.outputNext) {
      // A gap on an ordered transport means the stream lost integrity.
      this.closeSession(session, "protocol_violation", {
        code: "protocol_error",
        message: "terminal output sequence gap",
      });
      return;
    }
    if (
      attachmentBuffered(session) + body.byteLength >
      TERMINAL_LIMITS.attachmentBufferedMaxBytes
    ) {
      // Slow consumer: detach with an explicit error, never grow the buffer.
      this.closeSession(session, "backpressure", {
        code: "rate_limited",
        message: "terminal output exceeded the browser buffer",
      });
      return;
    }
    session.outputNext += 1;
    try {
      session.attachment.sendOutput(body);
    } catch {
      // C52-F-5: a failing browser transport never unwinds into the relay.
      this.closeSession(session, "detached");
      return;
    }
    this.sendToHost(session, {
      type: "terminal.ack",
      fence: session.fence,
      sequence: metadata.sequence,
    });
  }

  private handle(session: TerminalSession): TerminalSessionHandle {
    return {
      sessionId: session.fence.sessionId,
      input: (bytes) => {
        if (session.state !== "open" || session.attachmentClosed)
          return { ok: false, code: "state_conflict" };
        if (bytes.byteLength === 0) return { ok: true };
        if (session.inputQueuedBytes + bytes.byteLength > TERMINAL_LIMITS.inputQueueMaxBytes)
          return { ok: false, code: "rate_limited" };
        enqueueInput(session, bytes);
        this.flushInput(session);
        return { ok: true };
      },
      resize: (rows, cols) => {
        if (!validSize(rows, cols)) return { ok: false, code: "protocol_error" };
        if (session.state !== "open" || session.attachmentClosed)
          return { ok: false, code: "state_conflict" };
        if (session.pendingResizes.size >= TERMINAL_MAX_PENDING_RESIZES)
          return { ok: false, code: "rate_limited" };
        // Stale host authority: keep only the latest size; `resumeHost` sends it.
        if (!session.authorized()) session.deferredResize = { rows, cols };
        else this.sendResize(session, rows, cols);
        return { ok: true };
      },
      close: (intent = "client", error, reason) => {
        if (this.sessions.get(session.fence.sessionId) !== session) return;
        // WP8: graceful server shutdown, and a host connection the binding
        // re-read found ended or moved on, never close a resumable PTY; the
        // node detaches it when its connection to this server ends.
        const reconnect =
          (intent === "shutdown" || intent === "host_disconnected") && !error
            ? this.reconnectNotice(session)
            : undefined;
        if (reconnect) {
          this.release(session, { code: TERMINAL_LIMITS.closeCode, intent, reconnect });
          return;
        }
        this.closeSession(session, intent, error, reason);
      },
    };
  }

  private sendResize(session: TerminalSession, rows: number, cols: number) {
    const requestId = mintId("tr");
    session.pendingResizes.set(requestId, { rows, cols });
    this.sendToHost(session, {
      type: "terminal.resize",
      requestId,
      fence: session.fence,
      rows,
      cols,
    });
  }

  /** The single server→host input gate: nothing is sent under a stale ticket. */
  private flushInput(session: TerminalSession) {
    if (!session.authorized()) return;
    while (
      session.state === "open" &&
      session.inputQueue.length > 0 &&
      session.inputNext - session.inputAcked < TERMINAL_LIMITS.inputWindowFrames
    ) {
      const chunk = session.inputQueue.shift()!;
      session.inputQueuedBytes -= chunk.length;
      const sequence = session.inputNext;
      session.inputNext += 1;
      try {
        session.socket.send(
          encodeTerminalDataFrame(
            { type: "terminal.data", fence: session.fence, sequence },
            chunk.bytes.subarray(0, chunk.length),
          ),
        );
      } catch {
        this.closeSession(session, "host_disconnected");
        return;
      }
    }
  }

  private lookup(socket: HostSocket, fence: TerminalFence): TerminalSession | undefined {
    const session = this.sessions.get(fence.sessionId);
    const state = this.sockets.get(socket);
    if (!session || session.socket !== socket) {
      // Zero bytes delivered, bounded. `terminal.exit` is the host's last
      // frame for a session, so even a frame naming a recently ended
      // (tombstoned) session is counted; only its audit line is skipped.
      const foreign = this.socketState(socket);
      foreign.foreign += 1;
      if (!state?.tombstones.includes(fence.sessionId))
        this.audit(foreign, "foreign terminal frame", fence.sessionId);
      if (foreign.foreign > TERMINAL_FOREIGN_FRAME_LIMIT)
        this.hosts.closeHostSocket(socket, "Too many foreign terminal frames.");
      return undefined;
    }
    if (!sameFence(session.fence, fence)) {
      this.violation(session, "terminal fence mismatch");
      return undefined;
    }
    return session;
  }

  private violation(session: TerminalSession, reason: string) {
    session.violations += 1;
    const state = this.sockets.get(session.socket);
    if (state) this.audit(state, reason, session.fence.sessionId);
    if (
      session.violations >= TERMINAL_LIMITS.fenceViolationLimit &&
      (session.state === "opening" || session.state === "open")
    )
      this.closeSession(session, "protocol_violation", {
        code: "protocol_error",
        message: "repeated terminal protocol violations",
      });
  }

  private audit(state: SocketState, reason: string, sessionId: string) {
    if (state.audits >= AUDIT_LOGS_PER_SOCKET) return;
    state.audits += 1;
    console.warn(`[sandbox-relay] terminal frame dropped (${reason}) session=${sessionId}`);
  }

  /**
   * The single server-initiated close (C55). Idempotent: only an opening or
   * open session changes; it notifies the attachment once and asks the host
   * once. An unsendable close releases at once (the socket is gone, and its
   * removal ends the host's PTYs).
   */
  private closeSession(
    session: TerminalSession,
    intent: TerminalCloseIntent,
    error?: { code: SandboxErrorCode; message: string },
    reason?: TerminalCloseNotice["reason"],
  ) {
    if (session.state !== "opening" && session.state !== "open") return;
    this.quiesce(session);
    session.state = "closing";
    this.notifyAttachment(session, {
      code: TERMINAL_LIMITS.closeCode,
      intent,
      ...(reason ? { reason } : {}),
      ...(error ? { error } : {}),
    });
    if (
      !this.sendToHost(session, {
        type: "terminal.close",
        requestId: mintId("tr"),
        fence: session.fence,
        intent,
      })
    )
      this.release(session, { code: TERMINAL_LIMITS.closeCode, intent });
  }

  /**
   * WP8: the reconnect notice of a session the node will keep detached: a
   * resumable session that is open, or still waiting for its own resume
   * answer. Anything else (a fresh open not yet answered, a closing or
   * exited session) ends finally, as before.
   */
  private reconnectNotice(session: TerminalSession): TerminalCloseNotice["reconnect"] {
    if (
      session.resumeGraceMs === undefined ||
      session.fence.target.kind !== "sandbox" ||
      !(
        session.state === "open" ||
        (session.state === "opening" && session.resumeFrom !== undefined)
      )
    )
      return undefined;
    return { terminalId: session.fence.sessionId, graceMs: session.resumeGraceMs };
  }

  /** Every exit path: no timer, no queued input, no pending resize survives. */
  private quiesce(session: TerminalSession) {
    clearTimeout(session.openTimer);
    session.openTimer = undefined;
    session.deferredResize = undefined;
    session.pendingResizes.clear();
    session.inputQueue = [];
    session.inputQueuedBytes = 0;
  }

  /** Uncertain reap: the attachment ends, the count stays held (C55). */
  private hold(session: TerminalSession, notice: TerminalCloseNotice) {
    this.quiesce(session);
    session.state = "unreaped";
    this.notifyAttachment(session, notice);
  }

  /**
   * The ONE release of a session's count (C55): the host confirmed the end
   * and the reap, or its socket ended. Idempotent: a second call is a no-op,
   * so no path can release twice.
   */
  private release(session: TerminalSession, notice?: TerminalCloseNotice) {
    if (session.state === "ended") return;
    this.quiesce(session);
    session.state = "ended";
    if (notice) this.notifyAttachment(session, notice);
    if (this.sessions.get(session.fence.sessionId) === session)
      this.sessions.delete(session.fence.sessionId);
    const state = this.sockets.get(session.socket);
    if (!state) return;
    if (!state.sessions.delete(session)) return;
    state.tombstones.push(session.fence.sessionId);
    if (state.tombstones.length > TERMINAL_LIMITS.endedSessionTombstones) state.tombstones.shift();
  }

  /** C52-F-5: attachment callbacks never throw into host frame handling. */
  private attachmentReady(
    session: TerminalSession,
    size: { rows: number; cols: number },
    resume?: TerminalResumeInfo,
  ) {
    if (session.attachmentClosed) return;
    try {
      if (resume) session.attachment.ready(size, resume);
      else session.attachment.ready(size);
    } catch {
      this.closeSession(session, "detached");
    }
  }

  private notifyAttachment(session: TerminalSession, notice: TerminalCloseNotice) {
    if (session.attachmentClosed) return;
    session.attachmentClosed = true;
    try {
      session.attachment.close(notice);
    } catch {
      /* The browser transport already failed. */
    }
  }

  private sendToHost(
    session: TerminalSession,
    message: Parameters<typeof encodeServerControlMessage>[0],
  ): boolean {
    if (session.socket.readyState !== WS_READY_STATE_OPEN) return false;
    try {
      session.socket.send(encodeServerControlMessage(message, session.protocolVersion));
      return true;
    } catch {
      return false;
    }
  }

  private socketState(socket: HostSocket): SocketState {
    let state = this.sockets.get(socket);
    if (!state) {
      state = { sessions: new Set(), opens: [], tombstones: [], foreign: 0, audits: 0 };
      this.sockets.set(socket, state);
    }
    return state;
  }
}
