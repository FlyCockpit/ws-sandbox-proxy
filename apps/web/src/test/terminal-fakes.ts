import type { Disposable, TerminalView, WebSocketConstructor } from "@/lib/terminal-client";
import type { TerminalSize } from "@/lib/terminal-protocol";

/**
 * Test doubles for the browser terminal (C54): a scripted WebSocket that is
 * also the backend mock (it records every frame the browser sends and whether
 * the session was closed), an xterm stand-in that counts its listeners, and a
 * ResizeObserver stand-in. Every instance is tracked so a test can assert
 * that nothing leaked.
 */

type Listener = (event: unknown) => void;

export class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  static instances: FakeWebSocket[] = [];

  readonly url: string;
  readonly protocols: string[];
  readyState = FakeWebSocket.CONNECTING;
  binaryType = "blob";
  bufferedAmount = 0;
  /** Text frames the browser sent, parsed. */
  readonly sentText: Record<string, unknown>[] = [];
  /** Binary frames the browser sent. */
  readonly sentBinary: Uint8Array[] = [];
  /** The close the browser initiated, if any. */
  closedByClient: { code?: number } | null = null;
  private readonly listeners = new Map<string, Set<Listener>>();

  constructor(url: string, protocols: string[]) {
    this.url = url;
    this.protocols = [...protocols];
    FakeWebSocket.instances.push(this);
  }

  static reset() {
    FakeWebSocket.instances = [];
  }

  /** Sockets that are neither closed nor closing. */
  static live(): FakeWebSocket[] {
    return FakeWebSocket.instances.filter(
      (socket) =>
        socket.readyState === FakeWebSocket.CONNECTING || socket.readyState === FakeWebSocket.OPEN,
    );
  }

  static last(): FakeWebSocket {
    const socket = FakeWebSocket.instances.at(-1);
    if (!socket) throw new Error("no WebSocket was created");
    return socket;
  }

  addEventListener(type: string, listener: Listener) {
    let set = this.listeners.get(type);
    if (!set) {
      set = new Set();
      this.listeners.set(type, set);
    }
    set.add(listener);
  }

  removeEventListener(type: string, listener: Listener) {
    this.listeners.get(type)?.delete(listener);
  }

  listenerCount(): number {
    let count = 0;
    for (const set of this.listeners.values()) count += set.size;
    return count;
  }

  send(data: string | Uint8Array) {
    if (this.readyState !== FakeWebSocket.OPEN)
      throw new Error("send on a socket that is not open");
    if (typeof data === "string") this.sentText.push(JSON.parse(data));
    else this.sentBinary.push(new Uint8Array(data));
  }

  close(code?: number) {
    if (this.readyState === FakeWebSocket.CLOSED) return;
    this.closedByClient = { code };
    this.readyState = FakeWebSocket.CLOSED;
    // As in a browser, the close event follows asynchronously; a client that
    // has already let go of the socket must not react to it.
    queueMicrotask(() => this.emit("close", { code: code ?? 1005, reason: "", wasClean: true }));
  }

  /** The backend saw the session end: a close request or the socket closing. */
  get sessionClosed(): boolean {
    return this.closedByClient !== null || this.sentText.some((frame) => frame.type === "close");
  }

  // -- server side -----------------------------------------------------------

  serverOpen() {
    this.readyState = FakeWebSocket.OPEN;
    this.emit("open", {});
  }

  serverText(frame: Record<string, unknown>) {
    this.emit("message", { data: JSON.stringify(frame) });
  }

  serverBinary(text: string) {
    const bytes = new TextEncoder().encode(text);
    this.emit("message", { data: bytes.buffer.slice(0) });
  }

  /** The server (or the browser, for a refused upgrade) closes the socket. */
  serverClose(code: number, reason = "") {
    this.readyState = FakeWebSocket.CLOSED;
    this.emit("close", { code, reason, wasClean: code !== 1006 });
  }

  /** A CloseIntent frame, then the final 4401. */
  serverCloseIntent(fields: Record<string, unknown>, reason = "") {
    this.serverText({ type: "close", code: 4401, requestId: "req-upgrade", ...fields });
    this.serverClose(4401, reason);
  }

  private emit(type: string, event: unknown) {
    for (const listener of [...(this.listeners.get(type) ?? [])]) listener(event);
  }
}

/** The fake as the client's constructor type (the DOM `WebSocket` surface it uses). */
export const FakeWebSocketCtor = FakeWebSocket as unknown as WebSocketConstructor;

export class FakeTerminalView implements TerminalView {
  static instances: FakeTerminalView[] = [];
  opened: HTMLElement | null = null;
  disposed = false;
  focused = 0;
  /** What `fit` reports next (`null`: cannot measure). */
  nextFit: { rows: number; cols: number } | null = { rows: 30, cols: 100 };
  readonly written: string[] = [];
  readonly pasted: string[] = [];
  selectionText = "";
  private readonly dataListeners = new Set<(data: string) => void>();
  private readonly binaryListeners = new Set<(data: string) => void>();
  private readonly pasteListeners = new Set<(text: string) => void>();

  constructor() {
    FakeTerminalView.instances.push(this);
  }

  static reset() {
    FakeTerminalView.instances = [];
  }

  static last(): FakeTerminalView {
    const view = FakeTerminalView.instances.at(-1);
    if (!view) throw new Error("no terminal view was created");
    return view;
  }

  open(container: HTMLElement) {
    this.opened = container;
  }

  write(data: Uint8Array) {
    this.written.push(new TextDecoder().decode(data));
  }

  onData(listener: (data: string) => void): Disposable {
    this.dataListeners.add(listener);
    return { dispose: () => this.dataListeners.delete(listener) };
  }

  onBinary(listener: (data: string) => void): Disposable {
    this.binaryListeners.add(listener);
    return { dispose: () => this.binaryListeners.delete(listener) };
  }

  onNativePaste(listener: (text: string) => void): Disposable {
    this.pasteListeners.add(listener);
    return { dispose: () => this.pasteListeners.delete(listener) };
  }

  /** A native paste (Ctrl/Cmd+V) carrying `text`, as the real view reports it. */
  nativePaste(text: string) {
    for (const listener of [...this.pasteListeners]) listener(text);
  }

  get nativePasteListeners(): number {
    return this.pasteListeners.size;
  }

  fit(): TerminalSize | null {
    return this.nextFit ? { ...this.nextFit } : null;
  }

  selection() {
    return this.selectionText;
  }

  paste(text: string) {
    this.pasted.push(text);
    this.type(text);
  }

  focus() {
    this.focused += 1;
  }

  hasFocusValue = false;
  applicationCursor = false;
  bracketed = false;
  fontSize = 14;

  hasFocus() {
    return this.hasFocusValue;
  }

  applicationCursorKeys() {
    return this.applicationCursor;
  }

  bracketedPaste() {
    return this.bracketed;
  }

  setFontSize(size: number) {
    this.fontSize = size;
  }

  dispose() {
    this.disposed = true;
    this.dataListeners.clear();
    this.binaryListeners.clear();
    this.pasteListeners.clear();
  }

  listenerCount(): number {
    return this.dataListeners.size + this.binaryListeners.size;
  }

  /** The user types (xterm `onData`). */
  type(text: string) {
    for (const listener of [...this.dataListeners]) listener(text);
  }

  /** xterm `onBinary` (non-UTF-8 mouse reports). */
  typeBinary(text: string) {
    for (const listener of [...this.binaryListeners]) listener(text);
  }
}

/** A manual ResizeObserver substitute: `observeResize` for `TerminalClient`. */
export class FakeResize {
  readonly callbacks = new Set<() => void>();

  observe = (_element: HTMLElement, onResize: () => void) => {
    this.callbacks.add(onResize);
    return () => {
      this.callbacks.delete(onResize);
    };
  };

  fire() {
    for (const callback of [...this.callbacks]) callback();
  }
}

/** The ticket a fake `createSession` mints (43 base64url characters). */
export function fakeTicket(seed: number): string {
  return `T${String(seed).padStart(3, "0")}`.padEnd(43, "x");
}

export function fakeSession(sandboxId: string, ticket: string) {
  return {
    path: `/api/dashboard/sandboxes/${sandboxId}/terminal/ws`,
    protocols: ["wssp.terminal.v1", `wssp.terminal.ticket.${ticket}`],
    expiresAt: new Date(Date.now() + 30_000),
  };
}

/** Flush pending promise callbacks (dynamic imports, mocked oRPC calls). */
export async function flush(times = 5) {
  for (let index = 0; index < times; index += 1) await Promise.resolve();
}

/**
 * An in-memory exclusive Web Locks manager (WP8 reattach turns): FIFO per
 * name, one holder at a time, a waiting request withdrawn by its signal
 * (rejecting with AbortError) like `navigator.locks.request`.
 */
export class FakeLocks {
  /** Current holders per name (an exclusive lock has at most one). */
  readonly held = new Map<string, number>();
  /** Most simultaneous holders of one name ever observed. */
  maxHeld = 0;
  readonly requested: string[] = [];
  private readonly queues = new Map<string, (() => void)[]>();
  /** The current holder's forced end (WebKit page-suspension model). */
  private readonly revokers = new Map<string, () => void>();

  /**
   * Take the lock away from its holder, as WebKit does when suspending a
   * page: the holder's request rejects and the next waiter is granted, while
   * the holder's callback promise is still pending.
   */
  revoke(name: string) {
    this.revokers.get(name)?.();
  }

  request(
    name: string,
    options: { mode: "exclusive"; signal: AbortSignal },
    callback: (lock: unknown) => Promise<void>,
  ): Promise<unknown> {
    this.requested.push(name);
    return new Promise((resolve, reject) => {
      const abort = () => {
        const queue = this.queues.get(name) ?? [];
        const index = queue.indexOf(grant);
        if (index >= 0) queue.splice(index, 1);
        reject(new DOMException("aborted", "AbortError"));
      };
      const grant = () => {
        options.signal.removeEventListener("abort", abort);
        const holders = (this.held.get(name) ?? 0) + 1;
        this.held.set(name, holders);
        this.maxHeld = Math.max(this.maxHeld, holders);
        let ended = false;
        const end = () => {
          if (ended) return false;
          ended = true;
          this.revokers.delete(name);
          this.held.set(name, (this.held.get(name) ?? 1) - 1);
          const queue = this.queues.get(name) ?? [];
          const next = queue.shift();
          if (next) queueMicrotask(next);
          else this.queues.delete(name);
          return true;
        };
        this.revokers.set(name, () => {
          if (end()) reject(new DOMException("lock released", "AbortError"));
        });
        void callback({ name }).then(
          (value) => {
            if (end()) resolve(value);
          },
          (error: unknown) => {
            if (end()) reject(error);
          },
        );
      };
      if (options.signal.aborted) {
        reject(new DOMException("aborted", "AbortError"));
        return;
      }
      options.signal.addEventListener("abort", abort, { once: true });
      const queue = this.queues.get(name);
      if (!queue && (this.held.get(name) ?? 0) === 0) {
        this.queues.set(name, []);
        grant();
      } else {
        (queue ?? this.queues.set(name, []).get(name)!).push(grant);
      }
    });
  }
}

/** A resumable terminal id as the server mints it (`t` + 32 hex). */
export function fakeTerminalId(seed: number): string {
  return `t${seed.toString(16).padStart(32, "0")}`;
}
