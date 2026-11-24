import {
  BROWSER_TERMINAL_BUFFERED_MAX_BYTES,
  BROWSER_TERMINAL_CLOSE_CODE,
  BROWSER_TERMINAL_INPUT_FRAME_MAX_BYTES,
  BROWSER_TERMINAL_INPUT_QUEUE_MAX_BYTES,
  BROWSER_TERMINAL_RECONNECT_CLOSE_CODE,
  browserTerminalPath,
  TERMINAL_RESUME_GRACE_DEFAULT_MS,
  TERMINAL_RESUME_GRACE_MAX_MS,
  TERMINAL_RESUME_MAX_ATTEMPTS,
} from "@wssp/config/browser-terminal";

import {
  type CloseFrame,
  clampTerminalSize,
  classifyClose,
  classifyCreateError,
  closeFrame,
  DEFAULT_TERMINAL_SIZE,
  parseServerFrame,
  RESUME_OUTPUT_SEQ_MAX,
  type ReconnectingFrame,
  resizeFrame,
  resumeIdentity,
  type TerminalNotice,
  type TerminalSize,
  type TerminalWarning,
  terminalRequestId,
  terminalSocketUrl,
  validTerminalId,
  warningFor,
} from "./terminal-protocol";
import {
  acquireResumeTurn,
  defaultResumeLocks,
  type ReleaseTurn,
  type ResumeLocks,
} from "./terminal-resume-turns";

/**
 * One browser terminal attachment (C54): the explicit attach, the one-use
 * ticket, the socket, and the xterm view it drives. Framework-free so the
 * React hook (`use-terminal-session`) only owns its lifetime.
 *
 * - **Ticket.** `createSession` returns the ticket inside `protocols`. It is
 *   held in a local only long enough to construct the WebSocket, then dropped:
 *   never in a query cache, storage, the URL or a field of this object
 *   (C53-CO-6).
 * - **Refusals.** A socket that closes before `open` is a refused upgrade
 *   (1006, unreadable). It is never retried blindly: `createSession` runs once
 *   to classify it. A refusal there is shown; a success gets exactly one more
 *   upgrade, and a second pre-open close is "could not connect" (C53-CO-1).
 * - **Close.** After `open`, the close is classified by the CloseIntent
 *   frame's `intent` / `error.code` (or `exitCode`), never by the close reason
 *   string (C53-CO-5). Every end is final: nothing reconnects on its own, a
 *   new attach is a new session with a new ticket.
 * - **Detach.** Sends the `close` control frame, then closes the socket.
 * - **Backpressure.** Input that would push the socket's `bufferedAmount`
 *   past the contract's 1 MiB detaches instead of queueing.
 * - **Resize.** Only clamped sizes are sent, only once the PTY is ready, and
 *   only when the size changed. A refused resize (matched by its requestId)
 *   shows no warning; the current size is sent again on the next `ready`.
 * - **Reattach (WP8, sandbox terminals with `resumable`).** The client
 *   offers `wssp.terminal.v2`; the server's `ready` names the `terminalId`
 *   and the output sequence, and every binary output message advances it. A
 *   relay drop or server restart sends `reconnecting` + 4402 (or, on a crash,
 *   the socket just drops): the view and its scrollback stay, input stops,
 *   and the client makes at most `TERMINAL_RESUME_MAX_ATTEMPTS` attempts
 *   spread across the grace (the first after a jittered 1–5 s), each a new
 *   one-use ticket naming the terminal and the next output sequence it has
 *   not shown. Tabs take turns through a Web Lock held only for one
 *   attempt (`terminal-resume-turns.ts`). An independent grace deadline and a
 *   per-attempt timeout abort whatever is pending (turn wait, mint, socket),
 *   release the turn and ignore late results. A definitive
 *   refusal, the last failed attempt or the end of the grace ends the session
 *   ("Attach again"); a 4401 is final as before.
 * - **Page loss (C55).** `pagehide` (navigation, close, back-forward cache)
 *   and `freeze` (the page lifecycle's discard step) send the CloseIntent
 *   best-effort and end the session with the `pageLeft` notice: a returning
 *   page (back-forward cache restore, frozen tab resumed) says why and needs
 *   a new attach and a new PTY. A merely hidden tab keeps its terminal; a browser that vanishes
 *   without either event (network drop, suspended laptop) is closed by the
 *   server's liveness timeout.
 */

export type PasteOutcome = "done" | "empty" | "unavailable" | "tooLarge" | "ended";

/**
 * xterm wraps a paste in `ESC[200~` … `ESC[201~` (6 bytes each) when the
 * shell enabled bracketed paste (C54-F3): the paste cap leaves room for them.
 */
const BRACKETED_PASTE_MARKER_BYTES = 12;
/** The largest paste (UTF-8 bytes, after marker stripping) ever sent. */
export const PASTE_MAX_BYTES =
  BROWSER_TERMINAL_INPUT_QUEUE_MAX_BYTES - BRACKETED_PASTE_MARKER_BYTES;
/**
 * Clipboard text longer than this (UTF-16 code units) is refused as
 * `tooLarge` before any scan (C55-CO-7). Stripping only shrinks text, and a
 * code unit is at least one UTF-8 byte, so only a clipboard made mostly of
 * paste markers could have fit the cap: refusing it is the safe answer.
 */
export const PASTE_SCAN_MAX_CHARS = 4 * PASTE_MAX_BYTES;

/**
 * Remove every bracketed-paste start/end marker (`ESC[200~`, `ESC[201~`, and
 * their 8-bit C1 forms `CSI 200~`, `CSI 201~` with CSI = U+009B) from
 * clipboard text (C54-F4, C55-FS-N3): a poisoned clipboard cannot end the
 * bracket early and have the rest run as typed input. Markers nested to
 * reassemble once an inner one is removed (`ESC[20ESC[201~1~`) are removed
 * too.
 *
 * One linear pass (C55-CO-7): the output is a stack, and a marker can only
 * appear at its top, right after a code unit is pushed, so it is popped
 * there. The markers cannot overlap one another (each holds its only
 * introducer, ESC or CSI, first), so the result equals removing markers
 * until none is left.
 */
export function stripPasteMarkers(text: string): string {
  const out = new Uint16Array(text.length);
  let length = 0;
  for (let index = 0; index < text.length; index += 1) {
    out[length++] = text.charCodeAt(index);
    if (
      length >= 5 &&
      out[length - 1] === 0x7e && // ~
      (out[length - 2] === 0x30 || out[length - 2] === 0x31) && // 0 | 1
      out[length - 3] === 0x30 && // 0
      out[length - 4] === 0x32 // 2
    ) {
      if (out[length - 5] === 0x9b)
        length -= 5; // CSI (8-bit C1)
      else if (length >= 6 && out[length - 5] === 0x5b && out[length - 6] === 0x1b) length -= 6; // ESC [
    }
  }
  if (length === text.length) return text;
  let result = "";
  for (let start = 0; start < length; start += 8192)
    result += String.fromCharCode(...out.subarray(start, Math.min(start + 8192, length)));
  return result;
}

type TerminalStatus =
  | "idle"
  | "loading"
  | "connecting"
  | "verifying"
  | "attached"
  // WP8: the socket ended but the PTY may still be detached on the host.
  | "reconnecting"
  | "ended";

export type TerminalSnapshot = {
  status: TerminalStatus;
  notice: TerminalNotice | null;
  warning: TerminalWarning | null;
  /** The PTY size the server last confirmed. */
  size: TerminalSize | null;
};

export const IDLE_TERMINAL: TerminalSnapshot = {
  status: "idle",
  notice: null,
  warning: null,
  size: null,
};

export type Disposable = { dispose(): void };

/** The slice of xterm the client drives (implemented by `xterm-view.ts`, lazily loaded). */
export type TerminalView = {
  open(container: HTMLElement): void;
  write(data: Uint8Array): void;
  onData(listener: (data: string) => void): Disposable;
  onBinary(listener: (data: string) => void): Disposable;
  /** Native paste (Ctrl/Cmd+V, context menu): its text, never handed to xterm directly. */
  onNativePaste(listener: (text: string) => void): Disposable;
  /** Fit to the container; the resulting clamped size, or `null` when it cannot be measured. */
  fit(): TerminalSize | null;
  selection(): string;
  /** The scrollback and screen as plain text, one line per row (Select text). */
  bufferText(): string;
  paste(text: string): void;
  focus(): void;
  /** Whether the terminal's input element has focus (the phone keyboard is up for it). */
  hasFocus(): boolean;
  /** DECCKM: arrows are sent as `ESC O A` rather than `ESC [ A`. */
  applicationCursorKeys(): boolean;
  /** DECSET 2004: the program asked for bracketed paste. */
  bracketedPaste(): boolean;
  /** Cell font size in px; the caller refits afterwards. */
  setFontSize(size: number): void;
  dispose(): void;
};

type CreateTerminalSession = (
  input: {
    sandboxId: string;
    rows: number;
    cols: number;
    /** Resumable clients only: the subprotocol they will offer. */
    version?: 2;
    /** A reattach of a detached terminal (WP8). */
    resume?: { terminalId: string; nextOutputSeq: number };
  },
  options?: { signal?: AbortSignal },
) => Promise<{ path: string; protocols: string[] }>;

/** The constructor surface used here (the DOM `WebSocket`). */
export type WebSocketConstructor = new (url: string, protocols: string[]) => WebSocket;

type ObserveResize = (element: HTMLElement, onResize: () => void) => () => void;

export type TerminalClientOptions = {
  sandboxId: string;
  /** Host clients supply their path and end a refused upgrade without another mint. */
  terminalPath?: string;
  retryRefusedUpgrade?: boolean;
  serverUrl: string;
  container: HTMLElement;
  createSession: CreateTerminalSession;
  loadView: () => Promise<() => TerminalView>;
  onChange: (snapshot: TerminalSnapshot) => void;
  /** Sees every refused `createSession` first (the page's 2FA redirect). */
  onCreateError?: (error: unknown) => void;
  WebSocket?: WebSocketConstructor;
  observeResize?: ObserveResize;
  requestId?: () => string;
  resizeDebounceMs?: number;
  /** Where `pagehide` / `freeze` are observed (tests); defaults to window/document. */
  pageLifecycle?: EventTarget;
  /** The outcome of every native paste (the Paste button gets its own). */
  onPaste?: (outcome: PasteOutcome) => void;
  /**
   * WP8 (sandbox terminals only; never host terminals): mint v2 tickets and
   * reattach a detached terminal instead of ending at a relay drop.
   */
  resumable?: boolean;
  /** The cross-tab reattach lock manager (tests); default `navigator.locks`, none without it. */
  resumeLocks?: () => ResumeLocks | null;
  /** One reattach attempt (turn held, mint, upgrade, `ready`) may take at most this long. */
  resumeAttemptTimeoutMs?: number;
  /** Jitter source in [0, 1) (tests). */
  random?: () => number;
};

/** Transient refusals of a reattach: the host may simply not be back yet. */
const TRANSIENT_RESUME_ERRORS = new Set([
  "disconnected",
  "transport",
  "host_capacity",
  "rate_limited",
]);
/** Default bound of one reattach attempt, from holding the turn to `ready`. */
const RESUME_ATTEMPT_TIMEOUT_MS = 15_000;
/** The resume refusal that means the terminal is gone for good. */
const RESUME_UNAVAILABLE = "sandbox.terminal_resume_unavailable";

/** One reattach cycle: the detached terminal, its grace and its attempts. */
type ResumeCycle = {
  terminalId: string;
  startedAt: number;
  deadline: number;
  /** Attempt start offsets from `startedAt`, already jittered. */
  offsets: number[];
  attempts: number;
  timer?: ReturnType<typeof setTimeout>;
  /** Fires at `deadline` whatever is pending: ends the cycle ("Attach again"). */
  deadlineTimer?: ReturnType<typeof setTimeout>;
  /** Aborted when the cycle ends; every attempt's signal follows it. */
  abort: AbortController;
  /** The attempt in flight (its signal aborts its turn wait and its mint). */
  attempt?: AbortController;
  attemptTimer?: ReturnType<typeof setTimeout>;
  /** The held cross-tab turn, if any. */
  release?: ReleaseTurn;
  /** The `nextOutputSeq` the attempt in flight asked for. */
  asked?: number;
};

/** `promise`, or a rejection as soon as `signal` aborts (a stalled call is abandoned). */
function abandonable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new DOMException("aborted", "AbortError"));
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(new DOMException("aborted", "AbortError"));
    signal.addEventListener("abort", abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}

/**
 * Attempt offsets within a grace: the first after a jittered 1–5 s, the
 * others around 1/3 and 2/3 of the grace (plus up to 5 s), never at or past
 * the grace itself.
 */
export function resumeOffsets(graceMs: number, random: () => number): number[] {
  const offsets: number[] = [];
  let previous = -Infinity;
  for (let index = 0; index < TERMINAL_RESUME_MAX_ATTEMPTS; index += 1) {
    const base = index === 0 ? 1_000 + random() * 4_000 : (graceMs * index) / 3 + random() * 5_000;
    const offset = Math.max(base, previous + 1_000);
    if (offset >= graceMs) break;
    offsets.push(offset);
    previous = offset;
  }
  return offsets;
}

const OPEN = 1;
const CONNECTING = 0;
/** Unanswered resize requestIds kept (the server holds at most 4 pending). */
const PENDING_RESIZES_MAX = 16;

const defaultObserveResize: ObserveResize = (element, onResize) => {
  if (typeof ResizeObserver === "undefined") {
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }
  const observer = new ResizeObserver(() => onResize());
  observer.observe(element);
  return () => observer.disconnect();
};

export class TerminalClient {
  private snapshot: TerminalSnapshot = IDLE_TERMINAL;
  private view: TerminalView | null = null;
  private socket: WebSocket | null = null;
  private opened = false;
  private closeIntent: CloseFrame | null = null;
  private lastSent: TerminalSize | null = null;
  /** requestIds of resizes sent and not yet answered (C54-CO-3). */
  private readonly pendingResizes = new Set<string>();
  /** A resize was refused: re-send the current size on the next `ready`. */
  private resizeRefused = false;
  private started = false;
  private disposed = false;
  private readonly cleanups: (() => void)[] = [];
  private socketCleanup: (() => void) | null = null;
  private resizeTimer: ReturnType<typeof setTimeout> | undefined;
  private readonly encoder = new TextEncoder();
  /** v2: the attached terminal's id and the next output sequence not yet shown. */
  private terminalId: string | null = null;
  private outputSeq = 0;
  /** v2: the `reconnecting` frame of the socket now closing, if any. */
  private reconnectHint: ReconnectingFrame | null = null;
  private resume: ResumeCycle | null = null;
  /** Set while `paste` hands text to xterm: pasted data never takes latched modifiers. */
  private pasting = false;
  /** The on-screen keys' latched modifiers, applied to typed data (terminal utilities). */
  private keyFilter: ((data: string) => string) | null = null;
  /** Text size chosen before the view existed, applied before it opens. */
  private fontSize: number | null = null;
  private fontFrame: number | undefined;

  constructor(private readonly options: TerminalClientOptions) {}

  get state(): TerminalSnapshot {
    return this.snapshot;
  }

  /** The explicit owner attach. Runs once per client; a re-attach is a new client. */
  async start(): Promise<void> {
    if (this.started || this.disposed) return;
    this.started = true;
    const { sandboxId, serverUrl } = this.options;
    if (
      terminalSocketUrl(serverUrl, this.options.terminalPath ?? browserTerminalPath(sandboxId)) ===
      null
    ) {
      this.end({ kind: "insecure" });
      return;
    }
    this.update({ status: "loading", notice: null, warning: null });
    let createView: () => TerminalView;
    try {
      createView = await this.options.loadView();
    } catch {
      if (this.live()) this.end({ kind: "loadFailed" });
      return;
    }
    if (!this.live()) return;
    const view = createView();
    this.view = view;
    if (this.fontSize !== null) view.setFontSize(this.fontSize);
    view.open(this.options.container);
    const data = view.onData((text) =>
      this.input(
        this.encoder.encode(!this.pasting && this.keyFilter ? this.keyFilter(text) : text),
      ),
    );
    const binary = view.onBinary((text) => {
      const bytes = new Uint8Array(text.length);
      for (let index = 0; index < text.length; index += 1) {
        bytes[index] = text.charCodeAt(index) & 0xff;
      }
      this.input(bytes);
    });
    // Native paste takes the Paste button's path: strip, cap, all or nothing.
    const nativePaste = view.onNativePaste((text) => {
      const outcome = this.paste(text);
      if (!this.disposed) this.options.onPaste?.(outcome);
    });
    this.cleanups.push(
      () => data.dispose(),
      () => binary.dispose(),
      () => nativePaste.dispose(),
    );
    const stopObserving = (this.options.observeResize ?? defaultObserveResize)(
      this.options.container,
      () => this.scheduleResize(),
    );
    this.cleanups.push(stopObserving);
    this.watchPageLoss();
    const size = clampTerminalSize(view.fit()) ?? DEFAULT_TERMINAL_SIZE;
    await this.createAndConnect(size, true);
  }

  /** The owner's disconnect: CloseIntent on the wire, then the socket is closed. */
  detach(): void {
    if (!this.live()) return;
    this.end({ kind: "client" });
  }

  /** Unmount: as `detach`, and the xterm view (with its buffer) is disposed too. */
  dispose(): void {
    if (this.disposed) return;
    const wasLive = this.live();
    // Set first: nothing is reported to an unmounted owner.
    this.disposed = true;
    if (wasLive) this.end({ kind: "client" });
    if (this.fontFrame !== undefined) cancelAnimationFrame(this.fontFrame);
    this.fontFrame = undefined;
    this.keyFilter = null;
    this.view?.dispose();
    this.view = null;
  }

  selection(): string {
    return this.view?.selection() ?? "";
  }

  /** The buffer as text for Select text: read only, never sent anywhere. */
  bufferText(): string {
    return this.view?.bufferText() ?? "";
  }

  /**
   * Paste through xterm (bracketed paste when the shell asked for it). The
   * one path for the Paste button and native paste alike. Clipboard text over
   * `PASTE_SCAN_MAX_CHARS` is refused before any scan (C55-CO-7); otherwise
   * bracketed-paste markers inside it are stripped first (C54-F4).
   * All-or-nothing: a paste whose encoded size, plus the 12 marker
   * bytes xterm may add (C54-F3), exceeds the server's input queue
   * (`inputQueueMaxBytes`) would be sent as a burst the server partly
   * refuses, leaving holes in what the PTY receives, so it is refused whole
   * and nothing is sent. `done` means the whole paste was handed to the
   * socket and the session is still attached. The server can still refuse
   * part of it when earlier input is still queued (a slow host); that is
   * reported honestly as the `inputThrottled` warning ("some of it was
   * dropped"), never hidden.
   */
  paste(text: string): PasteOutcome {
    if (text.length > PASTE_SCAN_MAX_CHARS) return "tooLarge";
    const clean = stripPasteMarkers(text);
    if (clean.length === 0) return "empty";
    if (this.snapshot.status !== "attached" || !this.view) return "unavailable";
    if (this.encoder.encode(clean).byteLength > PASTE_MAX_BYTES) return "tooLarge";
    this.pasting = true;
    try {
      this.view.paste(clean);
    } finally {
      this.pasting = false;
    }
    // The paste itself can end the session (client-side backpressure detach).
    if (this.snapshot.status !== "attached") return "ended";
    this.view.focus();
    return "done";
  }

  focus(): void {
    this.view?.focus();
  }

  /** Whether the terminal holds keyboard focus (on-screen keys keep it there). */
  hasFocus(): boolean {
    return this.view?.hasFocus() ?? false;
  }

  /**
   * Bytes from an on-screen key (Esc, Tab, arrows, a Ctrl/Alt combo): the
   * same input path as typing, without the latched-modifier filter (the
   * caller already encoded them). False when nothing could be sent.
   */
  sendKeys(data: string): boolean {
    if (data.length === 0 || this.snapshot.status !== "attached") return false;
    this.input(this.encoder.encode(data));
    return this.snapshot.status === "attached";
  }

  /** DECCKM of the program now running (arrows from the swipe pad follow it). */
  applicationCursorKeys(): boolean {
    return this.view?.applicationCursorKeys() ?? false;
  }

  /** Whether a paste now would be bracketed (the program enabled it). */
  bracketedPaste(): boolean {
    return this.view?.bracketedPaste() ?? false;
  }

  /** Rewrites typed data (latched Ctrl/Alt); pastes are never rewritten. */
  setKeyFilter(filter: ((data: string) => string) | null): void {
    this.keyFilter = filter;
  }

  /**
   * Change the text size and refit on the next frame (xterm measures the
   * new cell then), so cols × rows follow and the PTY is resized the way a
   * container resize does. `onFit` gets the new local size.
   */
  setFontSize(size: number, onFit?: (size: TerminalSize | null) => void): void {
    this.fontSize = size;
    const view = this.view;
    if (!view) return;
    view.setFontSize(size);
    if (this.fontFrame !== undefined) cancelAnimationFrame(this.fontFrame);
    this.fontFrame = requestAnimationFrame(() => {
      this.fontFrame = undefined;
      if (this.view !== view) return;
      if (this.live() && this.snapshot.status === "attached") this.resizeNow();
      onFit?.(clampTerminalSize(view.fit()));
    });
  }

  // -- internals -------------------------------------------------------------

  /** C55: the page going away sends the CloseIntent (best effort) and ends. */
  private watchPageLoss() {
    const target = this.options.pageLifecycle ?? (typeof window === "undefined" ? null : window);
    const doc = this.options.pageLifecycle ?? (typeof document === "undefined" ? null : document);
    if (!target) return;
    const onLoss = () => {
      if (this.live()) this.end({ kind: "pageLeft" });
    };
    target.addEventListener("pagehide", onLoss);
    doc?.addEventListener("freeze", onLoss);
    this.cleanups.push(() => {
      target.removeEventListener("pagehide", onLoss);
      doc?.removeEventListener("freeze", onLoss);
    });
  }

  private live(): boolean {
    return !this.disposed && this.snapshot.status !== "ended";
  }

  private update(next: Partial<TerminalSnapshot>) {
    this.snapshot = { ...this.snapshot, ...next };
    if (!this.disposed) this.options.onChange(this.snapshot);
  }

  private async createAndConnect(size: TerminalSize, first: boolean): Promise<void> {
    let session: { path: string; protocols: string[] };
    try {
      session = await this.options.createSession({
        sandboxId: this.options.sandboxId,
        rows: size.rows,
        cols: size.cols,
        ...(this.options.resumable ? { version: 2 as const } : {}),
      });
    } catch (error) {
      if (!this.live()) return;
      // A 2FA redirect (or similar) may take the page away; the notice stays either way.
      this.options.onCreateError?.(error);
      this.end(classifyCreateError(error));
      return;
    }
    // Unmounted or detached while the ticket was being minted: drop it unused
    // (it expires in 30 s and is never presented).
    if (!this.live()) return;
    this.connect(session.path, session.protocols, size, first);
  }

  private connect(path: string, protocols: string[], size: TerminalSize, first: boolean) {
    const url = terminalSocketUrl(this.options.serverUrl, path);
    if (url === null) {
      this.end({ kind: "insecure" });
      return;
    }
    const Impl = this.options.WebSocket ?? (globalThis.WebSocket as WebSocketConstructor);
    let socket: WebSocket;
    try {
      socket = new Impl(url, protocols);
    } catch {
      this.end({ kind: "couldNotConnect" });
      return;
    }
    socket.binaryType = "arraybuffer";
    this.socket = socket;
    this.opened = false;
    this.closeIntent = null;
    this.reconnectHint = null;
    this.lastSent = size;
    // A reattach keeps saying so until the terminal is back.
    this.update({ status: this.resume ? "reconnecting" : "connecting" });

    const onOpen = () => {
      this.opened = true;
      if (!this.resume) this.update({ status: "verifying" });
    };
    const onMessage = (event: MessageEvent) => this.message(event.data);
    const onClose = (event: CloseEvent) => {
      this.releaseSocket();
      if (!this.live()) return;
      if (this.resume) {
        this.resumeClosed(event.code);
        return;
      }
      if (!this.opened) {
        this.refused(size, first);
        return;
      }
      const detached = this.detachedTerminal(event.code);
      if (detached) {
        this.beginResume(detached.terminalId, detached.graceMs);
        return;
      }
      // The close event's `reason` is never read (C53-CO-5).
      this.end(
        this.options.retryRefusedUpgrade === false &&
          this.snapshot.status === "attached" &&
          this.closeIntent?.intent === "expired" &&
          this.closeIntent.error?.code === "timeout"
          ? { kind: "hostExpired" }
          : classifyClose(this.closeIntent, event.code),
        false,
      );
    };
    socket.addEventListener("open", onOpen);
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose);
    this.socketCleanup = () => {
      socket.removeEventListener("open", onOpen);
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("close", onClose);
    };
  }

  /** A close before `open`: a refused upgrade (C53-CO-1). Never a blind retry. */
  private refused(size: TerminalSize, first: boolean) {
    if (!first || this.options.retryRefusedUpgrade === false) {
      this.end({ kind: "couldNotConnect" });
      return;
    }
    this.update({ status: "loading" });
    void this.createAndConnect(size, false);
  }

  private message(data: unknown) {
    if (!this.live()) return;
    // Tag check rather than `instanceof`: an ArrayBuffer from another realm
    // (an iframe, a test environment) is still output.
    if (Object.prototype.toString.call(data) === "[object ArrayBuffer]") {
      if (this.snapshot.status === "attached") {
        this.view?.write(new Uint8Array(data as ArrayBuffer));
        // One binary message is one host output frame (WP8 sequence).
        this.outputSeq += 1;
      }
      return;
    }
    if (typeof data !== "string") return;
    const frame = parseServerFrame(data);
    if (!frame) return;
    if (frame.type === "close") {
      this.closeIntent = frame;
      return;
    }
    if (frame.type === "reconnecting") {
      if (this.options.resumable) this.reconnectHint = frame;
      return;
    }
    if (frame.type === "error") {
      // A refused resize (C54-CO-3) is not an input problem: no input
      // warning. The size the PTY has is the last confirmed one, so the
      // current size is sent again once the server answers the resizes it
      // still holds (the next `ready`), never in a retry loop.
      if (frame.requestId !== undefined && this.pendingResizes.delete(frame.requestId)) {
        this.lastSent = this.snapshot.size;
        this.resizeRefused = true;
        return;
      }
      this.update({ warning: warningFor(frame.code) });
      return;
    }
    const confirmed = { rows: frame.rows, cols: frame.cols };
    this.lastSent = confirmed;
    // `ready` echoes no requestId and answers resizes in order: the oldest
    // outstanding one is settled.
    const oldest = this.pendingResizes.values().next();
    if (!oldest.done) this.pendingResizes.delete(oldest.value);
    const first = this.snapshot.status !== "attached";
    // v2: only the answer to the open (or resume) names the terminal; a
    // resize's answer never moves the output sequence.
    const identity = first && this.options.resumable ? resumeIdentity(frame) : null;
    const cycle = this.resume;
    let lost = false;
    if (identity) {
      lost = cycle?.asked !== undefined && identity.outputSeq > cycle.asked;
      this.terminalId = identity.terminalId;
      this.outputSeq = identity.outputSeq;
    } else if (first) {
      this.terminalId = null;
    }
    if (cycle) this.finishResume();
    this.update({ status: "attached", size: confirmed, warning: lost ? "outputLost" : null });
    if (first || this.resizeRefused) {
      if (first) this.view?.focus();
      this.resizeRefused = false;
      // The container may have changed size while the PTY was opening, or
      // since a refused resize.
      this.resizeNow();
    }
  }

  private input(bytes: Uint8Array<ArrayBuffer>) {
    const socket = this.socket;
    if (this.snapshot.status !== "attached" || !socket || socket.readyState !== OPEN) return;
    for (
      let offset = 0;
      offset < bytes.byteLength;
      offset += BROWSER_TERMINAL_INPUT_FRAME_MAX_BYTES
    ) {
      const chunk = bytes.subarray(offset, offset + BROWSER_TERMINAL_INPUT_FRAME_MAX_BYTES);
      if (socket.bufferedAmount + chunk.byteLength > BROWSER_TERMINAL_BUFFERED_MAX_BYTES) {
        this.end({ kind: "backpressure" });
        return;
      }
      socket.send(chunk);
    }
  }

  private scheduleResize() {
    clearTimeout(this.resizeTimer);
    this.resizeTimer = setTimeout(() => this.resizeNow(), this.options.resizeDebounceMs ?? 100);
  }

  private resizeNow() {
    clearTimeout(this.resizeTimer);
    this.resizeTimer = undefined;
    if (!this.live() || !this.view) return;
    // Clamped again here: whatever the view measured, only a size inside the
    // contract's bounds reaches the wire, and an unmeasurable one never does.
    const size = clampTerminalSize(this.view.fit());
    const socket = this.socket;
    if (!size || this.snapshot.status !== "attached" || !socket || socket.readyState !== OPEN)
      return;
    if (this.lastSent && this.lastSent.rows === size.rows && this.lastSent.cols === size.cols)
      return;
    this.lastSent = size;
    const requestId = this.newRequestId();
    this.pendingResizes.add(requestId);
    // Bounded: a resize the server deferred and then coalesced is never
    // answered on its own; the oldest such id is dropped first.
    if (this.pendingResizes.size > PENDING_RESIZES_MAX) {
      const oldest = this.pendingResizes.values().next();
      if (!oldest.done) this.pendingResizes.delete(oldest.value);
    }
    socket.send(resizeFrame(requestId, size));
  }

  private newRequestId() {
    return (this.options.requestId ?? terminalRequestId)();
  }

  private releaseSocket() {
    this.socketCleanup?.();
    this.socketCleanup = null;
    this.socket = null;
  }

  /**
   * Final for this client. `sendClose` (default) sends the CloseIntent request
   * on an open socket; the socket is closed in every case.
   */
  private end(notice: TerminalNotice, sendClose = true) {
    const socket = this.socket;
    this.releaseSocket();
    if (socket) {
      try {
        if (sendClose && socket.readyState === OPEN) socket.send(closeFrame(this.newRequestId()));
        if (socket.readyState === OPEN || socket.readyState === CONNECTING) socket.close(1000);
      } catch {
        /* Transport already gone. */
      }
    }
    clearTimeout(this.resizeTimer);
    this.resizeTimer = undefined;
    this.finishResume();
    for (const cleanup of this.cleanups.splice(0)) cleanup();
    this.update({ status: "ended", notice, warning: null });
  }

  // -- reattach (WP8) --------------------------------------------------------

  /**
   * The terminal a just-closed attached socket left detached on the host, if
   * any: a `reconnecting` frame then 4402, or (a server crash) a drop with no
   * CloseIntent and no 4401 of a terminal whose id is known.
   */
  private detachedTerminal(code: number): { terminalId: string; graceMs: number } | null {
    if (!this.options.resumable || code === BROWSER_TERMINAL_CLOSE_CODE) return null;
    const hint = this.reconnectHint;
    if (hint && validTerminalId(hint.terminalId))
      return { terminalId: hint.terminalId, graceMs: hint.graceMs };
    if (
      this.closeIntent === null &&
      this.snapshot.status === "attached" &&
      this.terminalId !== null &&
      code !== BROWSER_TERMINAL_RECONNECT_CLOSE_CODE
    )
      return { terminalId: this.terminalId, graceMs: TERMINAL_RESUME_GRACE_DEFAULT_MS };
    return null;
  }

  private beginResume(terminalId: string, graceMs: number) {
    const grace = Number.isFinite(graceMs)
      ? Math.min(TERMINAL_RESUME_GRACE_MAX_MS, Math.max(0, graceMs))
      : TERMINAL_RESUME_GRACE_DEFAULT_MS;
    const random = this.options.random ?? Math.random;
    const offsets = resumeOffsets(grace, random);
    if (offsets.length === 0 || this.outputSeq > RESUME_OUTPUT_SEQ_MAX) {
      this.end({ kind: "resumeFailed" }, false);
      return;
    }
    const startedAt = Date.now();
    const cycle: ResumeCycle = {
      terminalId,
      startedAt,
      deadline: startedAt + grace,
      offsets,
      attempts: 0,
      abort: new AbortController(),
    };
    this.resume = cycle;
    // Independent of any attempt: whatever is pending at the grace's end (a
    // turn wait, a stalled mint, an unanswered upgrade) is abandoned.
    cycle.deadlineTimer = setTimeout(() => {
      if (this.resume === cycle && this.live()) this.end({ kind: "resumeFailed" }, false);
    }, grace);
    this.update({ status: "reconnecting", warning: null });
    this.scheduleAttempt();
  }

  /** The next attempt at its offset, or the end when none is left. */
  private scheduleAttempt() {
    const cycle = this.resume;
    if (!cycle) return;
    const offset = cycle.offsets[cycle.attempts];
    if (offset === undefined || Date.now() >= cycle.deadline) {
      this.end({ kind: "resumeFailed" }, false);
      return;
    }
    cycle.timer = setTimeout(
      () => void this.attempt(cycle),
      Math.max(0, cycle.startedAt + offset - Date.now()),
    );
  }

  private async attempt(cycle: ResumeCycle) {
    cycle.timer = undefined;
    const attempt = new AbortController();
    const follow = () => attempt.abort();
    cycle.abort.signal.addEventListener("abort", follow, { once: true });
    attempt.signal.addEventListener(
      "abort",
      () => cycle.abort.signal.removeEventListener("abort", follow),
      { once: true },
    );
    cycle.attempt = attempt;
    const current = () =>
      this.live() && this.resume === cycle && cycle.attempt === attempt && !attempt.signal.aborted;
    const release = await acquireResumeTurn(
      (this.options.resumeLocks ?? defaultResumeLocks)(),
      attempt.signal,
      this.options.random ?? Math.random,
      // A post-grant loss (WebKit page suspension): another tab may hold the
      // turn now, so this attempt is abandoned and the next slot re-requests.
      () => queueMicrotask(() => this.abandonAttempt(cycle, attempt, true)),
    );
    if (!current()) {
      release?.();
      return;
    }
    if (!release) {
      this.end({ kind: "resumeFailed" }, false);
      return;
    }
    cycle.release = release;
    cycle.attempts += 1;
    // The turn is held for this attempt only, and only this long.
    cycle.attemptTimer = setTimeout(
      () => this.abandonAttempt(cycle, attempt),
      this.options.resumeAttemptTimeoutMs ?? RESUME_ATTEMPT_TIMEOUT_MS,
    );
    const size =
      clampTerminalSize(this.view?.fit()) ??
      this.snapshot.size ??
      this.lastSent ??
      DEFAULT_TERMINAL_SIZE;
    const asked = this.outputSeq;
    let session: { path: string; protocols: string[] };
    try {
      session = await abandonable(
        this.options.createSession(
          {
            sandboxId: this.options.sandboxId,
            rows: size.rows,
            cols: size.cols,
            version: 2,
            resume: { terminalId: cycle.terminalId, nextOutputSeq: asked },
          },
          { signal: attempt.signal },
        ),
        attempt.signal,
      );
    } catch (error) {
      // Abandoned (deadline, timeout, detach): a late answer is ignored.
      if (!current()) return;
      this.releaseTurn(cycle);
      this.resumeRefused(error);
      return;
    }
    if (!current()) return;
    cycle.asked = asked;
    this.connect(session.path, session.protocols, size, false);
  }

  /**
   * The attempt took too long, or its turn was lost after the grant: abort
   * its pending work (a late mint answer is ignored), drop its socket, give
   * the turn back (unless already lost) and try again at the next slot.
   */
  private abandonAttempt(cycle: ResumeCycle, attempt: AbortController, turnLost = false) {
    if (this.resume !== cycle || cycle.attempt !== attempt) return;
    if (turnLost) cycle.release = undefined;
    clearTimeout(cycle.attemptTimer);
    cycle.attemptTimer = undefined;
    const socket = this.socket;
    this.releaseSocket();
    try {
      if (socket && (socket.readyState === OPEN || socket.readyState === CONNECTING))
        socket.close(1000);
    } catch {
      /* Transport already gone. */
    }
    this.releaseTurn(cycle);
    if (this.live()) this.scheduleAttempt();
  }

  /** End the attempt in flight: abort its pending work and release its turn. */
  private releaseTurn(cycle: ResumeCycle) {
    clearTimeout(cycle.attemptTimer);
    cycle.attemptTimer = undefined;
    cycle.attempt?.abort();
    cycle.attempt = undefined;
    const release = cycle.release;
    cycle.release = undefined;
    release?.();
  }

  /** A refused reattach mint: definitive refusals end, the rest try again. */
  private resumeRefused(error: unknown) {
    const shape = (error && typeof error === "object" ? error : {}) as {
      code?: unknown;
      status?: unknown;
      data?: unknown;
    };
    const data = (shape.data && typeof shape.data === "object" ? shape.data : {}) as {
      code?: unknown;
    };
    if (data.code === RESUME_UNAVAILABLE) {
      this.end({ kind: "resumeFailed" }, false);
      return;
    }
    const notice = classifyCreateError(error);
    if (notice.kind === "signedOut" || notice.kind === "forbidden" || notice.kind === "notFound") {
      this.options.onCreateError?.(error);
      this.end(notice, false);
      return;
    }
    if (notice.kind === "notReady") {
      this.end(notice, false);
      return;
    }
    // Budget (429), unavailable (503) or a network failure: the next attempt.
    this.scheduleAttempt();
  }

  /** A reattach socket closed before its `ready`. */
  private resumeClosed(code: number) {
    const cycle = this.resume;
    if (!cycle) return;
    this.releaseTurn(cycle);
    const frame = this.closeIntent;
    const transient =
      !this.opened ||
      this.reconnectHint !== null ||
      code === BROWSER_TERMINAL_RECONNECT_CLOSE_CODE ||
      (frame === null && code !== BROWSER_TERMINAL_CLOSE_CODE) ||
      (frame?.error?.code !== undefined && TRANSIENT_RESUME_ERRORS.has(frame.error.code));
    if (transient) {
      this.scheduleAttempt();
      return;
    }
    const notice = classifyClose(frame, code);
    this.end(
      notice.kind === "hostRefused" || notice.kind === "ended" ? { kind: "resumeFailed" } : notice,
      false,
    );
  }

  /** The cycle is over (reattached or ended): no timer, no turn, no channel. */
  private finishResume() {
    const cycle = this.resume;
    if (!cycle) return;
    this.resume = null;
    clearTimeout(cycle.timer);
    clearTimeout(cycle.deadlineTimer);
    this.releaseTurn(cycle);
    cycle.abort.abort();
  }
}
