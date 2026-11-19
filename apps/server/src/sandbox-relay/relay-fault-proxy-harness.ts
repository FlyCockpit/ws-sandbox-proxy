/**
 * WP1 reconnect chaos harness: a loopback WebSocket fault proxy between a
 * node daemon (`n`) and the relay server (`s`). It sits on the host plane
 * (`/ws/sandbox-host`) exactly where a flaky network would, forwards every
 * frame unchanged, and injects transport faults on demand:
 *
 * - `reset()`: TCP RST on BOTH sockets of every live link. This is the
 *   transport half of SrvX (server gone without a close frame or a disconnect
 *   write); a daemon-only reset is the same wire event from the daemon's side.
 * - `blackhole()`: keep both TCP sockets open but stop reading and forwarding,
 *   pings included, so neither peer sees a close (half-open).
 * - `delay(ms)`: per-direction one-way latency; frame order is preserved.
 * - `closeWith(code, reason)`: a clean close frame toward one side.
 * - `dropNext({ dir, type, kind? })`: silently lose the next matching frame.
 * - `holdUntil(pred)` / `release()`: from the first matching frame on, hold
 *   that link's frames in that direction until released (or discarded by a
 *   reset).
 * - `inject(linkId, dir, text)`: put a synthetic text frame on a live link,
 *   after anything already queued in that direction (a burst a real peer
 *   would not send on its own).
 * - `outage()` / `restore()`: refuse every new link (its TCP socket is reset
 *   at the upgrade, before any upstream dial) until restored, so the daemon
 *   cannot reach the server; live links are untouched (pair with `reset()`).
 *
 * Fault points built on them (plan WP1):
 * - (i) `holdThenReset(match)`: the matched frame is held, then the link is
 *   reset, so the frame never arrives.
 * - (ii) `forwardThenReset(match)`: the matched frame is delivered, then the
 *   link is reset before the peer's next frame is forwarded.
 * - (iii) `dropReplyThenReset(match)`: the matched frame is delivered, the
 *   first reverse-direction ACK/result/receipt is dropped, then the link is
 *   reset.
 *
 * Frames are classified leniently (JSON `type`/`kind`/`operationId`; binary
 * stream metadata `type`/`operationId`) and never validated, so the proxy
 * forwards frames neither side's schema knows yet. WebSocket ping/pong are
 * forwarded end to end (`autoPong: false` on both legs) and pass through the
 * same pipeline as frames typed `ws.ping` / `ws.pong`.
 *
 * Test-only. The upstream must be a loopback `ws://` URL.
 */
import { once } from "node:events";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import net from "node:net";
import type { Duplex } from "node:stream";
import { setTimeout as sleep } from "node:timers/promises";
import WebSocket, { type RawData, WebSocketServer } from "ws";

/** `n2s`: daemon → server. `s2n`: server → daemon. */
export type RelayFrameDirection = "n2s" | "s2n";

type RelayFrameDisposition = "pending" | "forwarded" | "dropped" | "held" | "discarded";

export type RelayProxyFrame = {
  /** Proxy-wide arrival order. */
  seq: number;
  linkId: number;
  dir: RelayFrameDirection;
  binary: boolean;
  /** JSON `type`, binary metadata `type`, `ws.ping`/`ws.pong`, or null. */
  type: string | null;
  /** JSON `kind` (dispatch/receipt kind), else null. */
  kind: string | null;
  operationId: string | null;
  /** Parsed text frame, when it is a JSON object. */
  json: Record<string, unknown> | null;
  bytes: number;
  disposition: RelayFrameDisposition;
};

export type RelayFrameSelector = {
  dir?: RelayFrameDirection;
  type?: string;
  kind?: string;
  operationId?: string;
};
export type RelayFrameMatch = RelayFrameSelector | ((frame: RelayProxyFrame) => boolean);

export type RelayHold = {
  /** Resolves with the first held frame. */
  readonly matched: Promise<RelayProxyFrame>;
  /** Frames currently held, in arrival order. */
  readonly frames: readonly RelayProxyFrame[];
  /** Deliver the held frames in order and stop holding. */
  release(): void;
};

export type RelayLinkInfo = {
  id: number;
  /** Request path the daemon dialled, forwarded unchanged upstream. */
  path: string;
  readonly live: boolean;
  readonly closed: Promise<void>;
};

export type RelayFaultProxyOptions = {
  /** Loopback `ws://` base URL of the relay server, e.g. `ws://127.0.0.1:4100`. */
  upstream: string;
};

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1", "localhost"]);
const FRAME_LOG_MAX = 50_000;
const WAIT_DEFAULT_MS = 10_000;
/** Handshake headers ws regenerates for the upstream leg. */
const HOP_HEADERS = new Set([
  "host",
  "connection",
  "upgrade",
  "sec-websocket-key",
  "sec-websocket-version",
  "sec-websocket-extensions",
  "sec-websocket-protocol",
]);
/** Upstream refusal headers worth replaying to the daemon. */
const REFUSAL_HEADERS = ["content-type", "retry-after"] as const;

/** Reverse-direction frames fault point (iii) treats as a reply. */
function isRelayReplyFrame(frame: RelayProxyFrame): boolean {
  const type = frame.type;
  if (type === null) return false;
  return (
    type === "operation.result" ||
    type === "operation.receipt" ||
    type === "receipt.confirmed" ||
    type.endsWith(".ack") ||
    type.endsWith(".result")
  );
}

function relayFrameMatches(match: RelayFrameMatch, frame: RelayProxyFrame): boolean {
  if (typeof match === "function") return match(frame);
  return (
    (match.dir === undefined || match.dir === frame.dir) &&
    (match.type === undefined || match.type === frame.type) &&
    (match.kind === undefined || match.kind === frame.kind) &&
    (match.operationId === undefined || match.operationId === frame.operationId)
  );
}

function reverse(dir: RelayFrameDirection): RelayFrameDirection {
  return dir === "n2s" ? "s2n" : "n2s";
}

function stringField(value: Record<string, unknown>, key: string): string | null {
  const field = value[key];
  return typeof field === "string" ? field : null;
}

function asBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data);
  return Buffer.from(data);
}

function classify(
  data: Buffer,
  binary: boolean,
): Pick<RelayProxyFrame, "type" | "kind" | "operationId" | "json"> {
  let value: unknown = null;
  try {
    if (!binary) {
      value = JSON.parse(data.toString("utf8"));
    } else if (data.byteLength >= 4) {
      const length = data.readUInt32BE(0);
      if (length <= data.byteLength - 4)
        value = JSON.parse(data.subarray(4, 4 + length).toString("utf8"));
    }
  } catch {
    value = null;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { type: null, kind: null, operationId: null, json: null };
  }
  const record = value as Record<string, unknown>;
  return {
    type: stringField(record, "type"),
    kind: binary ? null : stringField(record, "kind"),
    operationId: stringField(record, "operationId"),
    json: binary ? null : record,
  };
}

/** WebSocket close codes an endpoint may put on the wire. */
function sendableCloseCode(code: number): boolean {
  return (
    (code >= 1000 && code <= 1014 && code !== 1004 && code !== 1005 && code !== 1006) ||
    (code >= 3000 && code <= 4999)
  );
}

type Outgoing =
  | { kind: "message"; data: Buffer; binary: boolean }
  | { kind: "ping" | "pong"; data: Buffer };

type QueuedFrame = { frame: RelayProxyFrame; out: Outgoing };

type Deferred<T> = { promise: Promise<T>; resolve(value: T): void; reject(error: Error): void };

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  // A fault armed but never triggered must not become an unhandled rejection.
  promise.catch(() => undefined);
  return { promise, resolve, reject };
}

class ProxyLink {
  readonly id: number;
  readonly path: string;
  node: WebSocket | null = null;
  nodeSocket: Duplex;
  server: WebSocket;
  serverSocket: Duplex | null = null;
  closed = false;
  blackholed = false;
  readonly closedSignal = deferred<void>();
  readonly nodeReady = deferred<void>();
  readonly tail: Record<RelayFrameDirection, Promise<void>>;

  constructor(id: number, path: string, nodeSocket: Duplex, server: WebSocket) {
    this.id = id;
    this.path = path;
    this.nodeSocket = nodeSocket;
    this.server = server;
    this.tail = { n2s: Promise.resolve(), s2n: this.nodeReady.promise };
  }

  info(): RelayLinkInfo {
    const link = this;
    return {
      id: link.id,
      path: link.path,
      get live() {
        return !link.closed;
      },
      closed: link.closedSignal.promise,
    };
  }

  target(dir: RelayFrameDirection): WebSocket | null {
    return dir === "n2s" ? this.server : this.node;
  }
}

type Hold = {
  match: RelayFrameMatch;
  scope: { linkId: number; dir: RelayFrameDirection } | null;
  queue: QueuedFrame[];
  matched: Deferred<RelayProxyFrame>;
  done: boolean;
};

type DropRule = { match: RelayFrameMatch; dropped: Deferred<RelayProxyFrame> };

/** A one-shot fault point: returns a verdict for the frame, or undefined to pass. */
type FaultRule = (link: ProxyLink, frame: RelayProxyFrame) => "pass" | "drop" | "reset" | undefined;

type FrameWaiter = { match: RelayFrameMatch; from: number; found: Deferred<RelayProxyFrame> };

export class RelayFaultProxy {
  private readonly upstream: URL;
  private readonly http: Server;
  private readonly wss = new WebSocketServer({
    noServer: true,
    perMessageDeflate: false,
    autoPong: false,
    handleProtocols: (protocols, request) => {
      const negotiated = this.pendingProtocol.get(request);
      return negotiated !== undefined && protocols.has(negotiated) ? negotiated : false;
    },
  });
  private readonly pendingProtocol = new WeakMap<IncomingMessage, string>();
  private readonly links = new Map<number, ProxyLink>();
  private readonly linkWaiters: Array<{ count: number; ready: Deferred<RelayLinkInfo> }> = [];
  private readonly holds: Hold[] = [];
  private readonly drops: DropRule[] = [];
  private faults: FaultRule[] = [];
  private readonly waiters: FrameWaiter[] = [];
  private readonly delays: Record<RelayFrameDirection, number> = { n2s: 0, s2n: 0 };
  private nextLinkId = 1;
  private nextSeq = 1;
  private shuttingDown = false;
  private refusing = false;
  /** Upgrades refused during an outage. */
  refused = 0;
  /** Every frame seen, oldest first (bounded). */
  readonly frames: RelayProxyFrame[] = [];
  /** Total links ever accepted. */
  accepted = 0;
  url = "";

  private constructor(options: RelayFaultProxyOptions) {
    const upstream = new URL(options.upstream);
    if (upstream.protocol !== "ws:" || !LOOPBACK_HOSTS.has(upstream.hostname)) {
      throw new Error("RelayFaultProxy upstream must be a loopback ws:// URL.");
    }
    this.upstream = upstream;
    this.http = createServer((_request, response) => {
      response.writeHead(426, { connection: "close" }).end();
    });
    this.http.on("upgrade", (request: IncomingMessage, socket: Duplex, head: Buffer) =>
      this.onUpgrade(request, socket, head),
    );
  }

  static async start(options: RelayFaultProxyOptions): Promise<RelayFaultProxy> {
    const proxy = new RelayFaultProxy(options);
    proxy.http.listen(0, "127.0.0.1");
    await once(proxy.http, "listening");
    const address = proxy.http.address() as AddressInfo;
    proxy.url = `ws://127.0.0.1:${address.port}`;
    return proxy;
  }

  /** Links currently forwarding (not closed, reset or closing). */
  liveLinks(): RelayLinkInfo[] {
    return [...this.links.values()].filter((link) => !link.closed).map((link) => link.info());
  }

  /** Resolves once `count` links in total have been accepted. */
  waitForLinks(count: number, timeoutMs = WAIT_DEFAULT_MS): Promise<RelayLinkInfo> {
    const latest = [...this.links.values()].at(-1);
    if (this.accepted >= count && latest) return Promise.resolve(latest.info());
    const ready = deferred<RelayLinkInfo>();
    this.linkWaiters.push({ count, ready });
    return withTimeout(ready.promise, timeoutMs, `link #${count}`);
  }

  /** First frame (at or after `fromSeq`) matching `match`, logged or future. */
  waitForFrame(
    match: RelayFrameMatch,
    { timeoutMs = WAIT_DEFAULT_MS, fromSeq = 0 }: { timeoutMs?: number; fromSeq?: number } = {},
  ): Promise<RelayProxyFrame> {
    const seen = this.frames.find(
      (frame) => frame.seq >= fromSeq && relayFrameMatches(match, frame),
    );
    if (seen) return Promise.resolve(seen);
    const found = deferred<RelayProxyFrame>();
    this.waiters.push({ match, from: fromSeq, found });
    return withTimeout(found.promise, timeoutMs, "frame");
  }

  /** Sequence number the next frame will get (a `fromSeq` cursor). */
  get cursor(): number {
    return this.nextSeq;
  }

  // ---- primitives -------------------------------------------------------

  /** TCP RST on both sockets of every live link; held frames are discarded. */
  reset(): number {
    const live = [...this.links.values()].filter((link) => !link.closed);
    for (const link of live) this.resetLink(link);
    return live.length;
  }

  /** Stop reading and forwarding on every live link; sockets stay open. */
  blackhole(): number {
    const live = [...this.links.values()].filter((link) => !link.closed && !link.blackholed);
    for (const link of live) {
      link.blackholed = true;
      link.node?.pause();
      link.server.pause();
    }
    return live.length;
  }

  /** One-way latency for later frames in `dir` (both when omitted); 0 clears. */
  delay(ms: number, dir?: RelayFrameDirection): void {
    if (!Number.isFinite(ms) || ms < 0) throw new Error("delay must be a non-negative number.");
    if (dir === undefined || dir === "n2s") this.delays.n2s = ms;
    if (dir === undefined || dir === "s2n") this.delays.s2n = ms;
  }

  /**
   * Close every live link: `code`/`reason` toward `toward` (the daemon by
   * default, as if the server closed), 1001 toward the other side.
   */
  closeWith(code: number, reason = "", toward: "node" | "server" = "node"): number {
    if (!sendableCloseCode(code)) throw new Error(`close code ${code} cannot be sent.`);
    const live = [...this.links.values()].filter((link) => !link.closed);
    for (const link of live) {
      this.finishLink(link);
      const target = toward === "node" ? link.node : link.server;
      const other = toward === "node" ? link.server : link.node;
      target?.close(code, reason);
      other?.close(1001, "relay fault proxy closed the peer");
    }
    return live.length;
  }

  /** Lose the next frame matching `selector`; resolves with it once dropped. */
  dropNext(
    selector: RelayFrameSelector & { dir: RelayFrameDirection; type: string },
  ): Promise<RelayProxyFrame> {
    const rule: DropRule = { match: selector, dropped: deferred() };
    this.drops.push(rule);
    return rule.dropped.promise;
  }

  /**
   * From the first frame matching `match` on, hold every frame on that link in
   * that direction until `release()` (here or on the proxy). A reset or close
   * of the link discards the held frames.
   */
  holdUntil(match: RelayFrameMatch): RelayHold {
    const hold: Hold = { match, scope: null, queue: [], matched: deferred(), done: false };
    this.holds.push(hold);
    return {
      matched: hold.matched.promise,
      get frames() {
        return hold.queue.map((entry) => entry.frame);
      },
      release: () => this.releaseHold(hold),
    };
  }

  /**
   * Send a synthetic text frame on live link `linkId` in `dir`, after every
   * frame already queued there. It bypasses holds, drops and fault points,
   * and is logged like any other frame.
   */
  inject(linkId: number, dir: RelayFrameDirection, text: string): RelayProxyFrame {
    const link = this.links.get(linkId);
    if (!link || link.closed) throw new Error(`link ${linkId} is not live.`);
    const data = Buffer.from(text, "utf8");
    const frame: RelayProxyFrame = {
      seq: this.nextSeq++,
      linkId,
      dir,
      binary: false,
      bytes: data.byteLength,
      disposition: "pending",
      ...classify(data, false),
    };
    this.frames.push(frame);
    if (this.frames.length > FRAME_LOG_MAX) this.frames.shift();
    this.enqueue(link, frame, { kind: "message", data, binary: false });
    return frame;
  }

  /** Refuse (TCP RST) every new link until `restore()`; live links stay. */
  outage(): void {
    this.refusing = true;
  }

  /** End an outage: new links are accepted and forwarded again. */
  restore(): void {
    this.refusing = false;
  }

  /** Release every active hold. */
  release(): void {
    for (const hold of [...this.holds]) this.releaseHold(hold);
  }

  // ---- fault points -------------------------------------------------------

  /** (i) Hold the matched frame (never delivered), then reset its link. */
  async holdThenReset(match: RelayFrameMatch): Promise<RelayProxyFrame> {
    const hold = this.holdUntil(match);
    const frame = await hold.matched;
    const link = this.links.get(frame.linkId);
    if (link) this.resetLink(link);
    return frame;
  }

  /**
   * (ii) Deliver the matched frame, then reset its link before the peer's
   * next frame on it is forwarded. Resolves with both frames.
   */
  forwardThenReset(
    match: RelayFrameMatch,
  ): Promise<{ forwarded: RelayProxyFrame; suppressed: RelayProxyFrame }> {
    const done = deferred<{ forwarded: RelayProxyFrame; suppressed: RelayProxyFrame }>();
    let armed: RelayProxyFrame | null = null;
    this.faults.push((_link, frame) => {
      if (armed === null) {
        if (!relayFrameMatches(match, frame)) return undefined;
        armed = frame;
        return "pass";
      }
      if (frame.linkId !== armed.linkId || frame.dir !== reverse(armed.dir)) return undefined;
      done.resolve({ forwarded: armed, suppressed: frame });
      return "reset";
    });
    return done.promise;
  }

  /**
   * (iii) Deliver the matched frame, drop the first reverse-direction reply
   * (ACK/result/receipt by default), then reset the link.
   */
  dropReplyThenReset(
    match: RelayFrameMatch,
    reply: (frame: RelayProxyFrame) => boolean = isRelayReplyFrame,
  ): Promise<{ trigger: RelayProxyFrame; dropped: RelayProxyFrame }> {
    const done = deferred<{ trigger: RelayProxyFrame; dropped: RelayProxyFrame }>();
    let armed: RelayProxyFrame | null = null;
    this.faults.push((_link, frame) => {
      if (armed === null) {
        if (!relayFrameMatches(match, frame)) return undefined;
        armed = frame;
        return "pass";
      }
      if (frame.linkId !== armed.linkId || frame.dir !== reverse(armed.dir) || !reply(frame)) {
        return undefined;
      }
      done.resolve({ trigger: armed, dropped: frame });
      return "reset";
    });
    return done.promise;
  }

  /** Reset every link, refuse new ones, and stop listening. */
  async close(): Promise<void> {
    this.shuttingDown = true;
    this.reset();
    for (const hold of this.holds) hold.matched.reject(new Error("proxy closed"));
    for (const rule of this.drops) rule.dropped.reject(new Error("proxy closed"));
    for (const waiter of this.waiters) waiter.found.reject(new Error("proxy closed"));
    for (const waiter of this.linkWaiters) waiter.ready.reject(new Error("proxy closed"));
    this.holds.length = 0;
    this.drops.length = 0;
    this.waiters.length = 0;
    this.linkWaiters.length = 0;
    this.faults = [];
    this.wss.close();
    this.http.closeAllConnections();
    await new Promise<void>((resolve) => this.http.close(() => resolve()));
  }

  // ---- plumbing -----------------------------------------------------------

  private onUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer): void {
    socket.on("error", () => undefined);
    if (this.shuttingDown) {
      socket.destroy();
      return;
    }
    if (this.refusing) {
      this.refused += 1;
      if (socket instanceof net.Socket) socket.resetAndDestroy();
      else socket.destroy();
      return;
    }
    const path = request.url ?? "/";
    const headers: Record<string, string | string[]> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      if (value !== undefined && !HOP_HEADERS.has(name)) headers[name] = value;
    }
    const protocols = (request.headers["sec-websocket-protocol"] ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    const server = new WebSocket(new URL(path, this.upstream), protocols, {
      headers,
      perMessageDeflate: false,
      autoPong: false,
      followRedirects: false,
    });
    const link = new ProxyLink(this.nextLinkId++, path, socket, server);
    let refused = false;
    server.on("error", () => undefined);
    server.on("upgrade", (response) => {
      link.serverSocket = response.socket;
    });
    server.on("unexpected-response", (clientRequest, response) => {
      refused = true;
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => {
        clientRequest.destroy();
        const body = Buffer.concat(chunks);
        const lines = [`HTTP/1.1 ${response.statusCode ?? 502} ${response.statusMessage ?? ""}`];
        for (const name of REFUSAL_HEADERS) {
          const value = response.headers[name];
          if (typeof value === "string") lines.push(`${name}: ${value}`);
        }
        lines.push(`content-length: ${body.byteLength}`, "connection: close", "", "");
        socket.end(Buffer.concat([Buffer.from(lines.join("\r\n")), body]));
      });
    });
    server.once("close", () => {
      if (link.node === null && !refused && !socket.destroyed) {
        // Upstream refused before open (dial failure, not an HTTP refusal).
        if (socket.writable)
          socket.end("HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        else socket.destroy();
      }
    });
    this.wireLeg(link, server, "s2n");
    server.once("open", () => {
      if (server.protocol) this.pendingProtocol.set(request, server.protocol);
      if (this.shuttingDown || socket.destroyed) {
        server.terminate();
        return;
      }
      this.wss.handleUpgrade(request, socket, head, (node) => {
        link.node = node;
        node.on("error", () => undefined);
        this.wireLeg(link, node, "n2s");
        this.links.set(link.id, link);
        this.accepted += 1;
        link.nodeReady.resolve();
        for (const waiter of [...this.linkWaiters]) {
          if (this.accepted >= waiter.count) {
            this.linkWaiters.splice(this.linkWaiters.indexOf(waiter), 1);
            waiter.ready.resolve(link.info());
          }
        }
      });
    });
  }

  /** Frames read from `socket` travel in `dir`. */
  private wireLeg(link: ProxyLink, socket: WebSocket, dir: RelayFrameDirection): void {
    socket.on("message", (data, isBinary) => {
      const bytes = asBuffer(data);
      this.onFrame(
        link,
        dir,
        { kind: "message", data: bytes, binary: isBinary },
        classify(bytes, isBinary),
      );
    });
    socket.on("ping", (data) => {
      this.onFrame(
        link,
        dir,
        { kind: "ping", data },
        { type: "ws.ping", kind: null, operationId: null, json: null },
      );
    });
    socket.on("pong", (data) => {
      this.onFrame(
        link,
        dir,
        { kind: "pong", data },
        { type: "ws.pong", kind: null, operationId: null, json: null },
      );
    });
    socket.on("close", (code, reason) => {
      if (link.closed || link.node === null) return;
      // Transparent end: mirror a clean close, mirror an abrupt one as RST.
      this.finishLink(link);
      const other = dir === "n2s" ? link.server : link.node;
      if (sendableCloseCode(code)) other.close(code, reason);
      else if (code === 1005) other.close();
      else this.resetSockets(link);
    });
  }

  private onFrame(
    link: ProxyLink,
    dir: RelayFrameDirection,
    out: Outgoing,
    fields: Pick<RelayProxyFrame, "type" | "kind" | "operationId" | "json">,
  ): void {
    const frame: RelayProxyFrame = {
      seq: this.nextSeq++,
      linkId: link.id,
      dir,
      binary: out.kind === "message" && out.binary,
      bytes: out.data.byteLength,
      disposition: "pending",
      ...fields,
    };
    this.frames.push(frame);
    if (this.frames.length > FRAME_LOG_MAX) this.frames.shift();
    if (link.closed || link.blackholed) {
      frame.disposition = "discarded";
    } else {
      this.route(link, frame, out);
    }
    for (const waiter of [...this.waiters]) {
      if (frame.seq >= waiter.from && relayFrameMatches(waiter.match, frame)) {
        this.waiters.splice(this.waiters.indexOf(waiter), 1);
        waiter.found.resolve(frame);
      }
    }
  }

  private route(link: ProxyLink, frame: RelayProxyFrame, out: Outgoing): void {
    // A held link-direction holds every frame (holdUntil's contract), before
    // any fault point or drop sees it: a fault trigger that escaped a
    // hold-then-reset would arm on the doomed link (relay-chaos C10's result
    // and receipt arrive back to back) and never fire on the next one.
    const holding = this.holds.find(
      (hold) => hold.scope?.linkId === link.id && hold.scope.dir === frame.dir,
    );
    if (holding) {
      frame.disposition = "held";
      holding.queue.push({ frame, out });
      return;
    }
    for (const fault of [...this.faults]) {
      const verdict = fault(link, frame);
      if (verdict === undefined) continue;
      // The trigger frame of a fault point is delivered as-is.
      if (verdict === "pass") {
        this.enqueue(link, frame, out);
        return;
      }
      this.faults.splice(this.faults.indexOf(fault), 1);
      frame.disposition = "dropped";
      if (verdict === "reset") this.resetLink(link);
      return;
    }
    const drop = this.drops.find((rule) => relayFrameMatches(rule.match, frame));
    if (drop) {
      this.drops.splice(this.drops.indexOf(drop), 1);
      frame.disposition = "dropped";
      drop.dropped.resolve(frame);
      return;
    }
    for (const hold of this.holds) {
      if (hold.scope !== null || !relayFrameMatches(hold.match, frame)) continue;
      hold.scope = { linkId: link.id, dir: frame.dir };
      hold.matched.resolve(frame);
      frame.disposition = "held";
      hold.queue.push({ frame, out });
      return;
    }
    this.enqueue(link, frame, out);
  }

  private enqueue(link: ProxyLink, frame: RelayProxyFrame, out: Outgoing): void {
    const dueAt = Date.now() + this.delays[frame.dir];
    link.tail[frame.dir] = link.tail[frame.dir]
      .then(async () => {
        const wait = dueAt - Date.now();
        if (wait > 0) await sleep(wait);
        const target = link.target(frame.dir);
        if (link.closed || link.blackholed || target?.readyState !== WebSocket.OPEN) {
          frame.disposition = "discarded";
          return;
        }
        frame.disposition = "forwarded";
        if (out.kind === "message") target.send(out.data, { binary: out.binary }, () => undefined);
        else if (out.kind === "ping") target.ping(out.data);
        else target.pong(out.data);
      })
      .catch(() => undefined);
  }

  private releaseHold(hold: Hold): void {
    if (hold.done) return;
    hold.done = true;
    this.holds.splice(this.holds.indexOf(hold), 1);
    const link = hold.scope ? this.links.get(hold.scope.linkId) : undefined;
    for (const entry of hold.queue) {
      if (link && !link.closed) this.enqueue(link, entry.frame, entry.out);
      else entry.frame.disposition = "discarded";
    }
    hold.queue.length = 0;
  }

  /** Mark the link ended and discard its held frames. */
  private finishLink(link: ProxyLink): void {
    if (link.closed) return;
    link.closed = true;
    link.nodeReady.resolve();
    for (const hold of [...this.holds]) {
      if (hold.scope?.linkId !== link.id) continue;
      for (const entry of hold.queue) entry.frame.disposition = "discarded";
      hold.queue.length = 0;
      hold.done = true;
      this.holds.splice(this.holds.indexOf(hold), 1);
    }
    link.closedSignal.resolve();
  }

  private resetLink(link: ProxyLink): void {
    this.finishLink(link);
    this.resetSockets(link);
  }

  private resetSockets(link: ProxyLink): void {
    for (const socket of [link.nodeSocket, link.serverSocket]) {
      if (socket instanceof net.Socket && !socket.destroyed) socket.resetAndDestroy();
      else socket?.destroy();
    }
  }
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, what: string): Promise<T> {
  const controller = new AbortController();
  try {
    return await Promise.race([
      promise,
      sleep(timeoutMs, undefined, { signal: controller.signal }).then(() => {
        throw new Error(`RelayFaultProxy: timed out after ${timeoutMs} ms waiting for ${what}.`);
      }),
    ]);
  } finally {
    controller.abort();
  }
}
