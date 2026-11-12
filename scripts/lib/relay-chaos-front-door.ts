/**
 * The live chaos front door (`scripts/relay-chaos-live.ts`, reconnect plan
 * WP9). It listens on the server's canonical origin so the dedicated
 * daemon's journal-key binding matches: plain HTTP and non-relay upgrades go
 * straight to the server, relay upgrades (`/ws/sandbox-host`) go through the
 * fault proxy. Loopback only; it reads no environment and logs nothing.
 */
import http from "node:http";
import net from "node:net";
import type { Duplex } from "node:stream";

export const RELAY_PATH = "/ws/sandbox-host";

type Pair = { daemon: net.Socket; peer: net.Socket; relay: boolean; frozen: boolean };

function rawRequestHead(request: http.IncomingMessage): string {
  let head = `${request.method} ${request.url} HTTP/${request.httpVersion}\r\n`;
  for (let i = 0; i + 1 < request.rawHeaders.length; i += 2) {
    head += `${request.rawHeaders[i]}: ${request.rawHeaders[i + 1]}\r\n`;
  }
  return `${head}\r\n`;
}

function hostOf(url: URL): string {
  return url.hostname.replace(/^\[|\]$/g, "");
}

/**
 * Listens on the canonical origin. HTTP and non-relay upgrades go straight to
 * the server; relay upgrades go through the fault proxy. During an outage new
 * relay connections are accepted and never answered, and live ones are frozen
 * (half-open), so the server is unreachable from the daemon only.
 */
export class FrontDoor {
  private readonly server: http.Server;
  private outage = false;
  private readonly held = new Set<net.Socket>();
  private readonly pairs = new Set<Pair>();

  private constructor(
    private readonly upstream: URL,
    private readonly proxyPort: number,
  ) {
    this.server = http.createServer((request, response) => this.forward(request, response));
    this.server.on("upgrade", (request: http.IncomingMessage, socket: Duplex, head: Buffer) =>
      this.onUpgrade(request, socket as net.Socket, head),
    );
  }

  static async start(listen: URL, upstream: URL, proxyPort: number): Promise<FrontDoor> {
    const door = new FrontDoor(upstream, proxyPort);
    await new Promise<void>((resolve, reject) => {
      door.server.once("error", reject);
      door.server.listen(Number(listen.port), hostOf(listen), () => resolve());
    });
    return door;
  }

  /** The port it listens on. */
  get port(): number {
    const address = this.server.address();
    return typeof address === "object" && address !== null ? address.port : 0;
  }

  private forward(request: http.IncomingMessage, response: http.ServerResponse): void {
    const upstream = http.request(
      {
        host: hostOf(this.upstream),
        port: Number(this.upstream.port),
        method: request.method,
        path: request.url,
        headers: request.headers,
        agent: false,
      },
      (reply) => {
        response.writeHead(reply.statusCode ?? 502, reply.rawHeaders);
        reply.pipe(response);
      },
    );
    upstream.on("error", () => {
      if (!response.headersSent) response.writeHead(502, { connection: "close" });
      response.end();
    });
    request.pipe(upstream);
  }

  private onUpgrade(request: http.IncomingMessage, daemon: net.Socket, head: Buffer): void {
    daemon.on("error", () => undefined);
    const relay = (request.url ?? "").split("?")[0] === RELAY_PATH;
    if (relay && this.outage) {
      daemon.pause();
      this.held.add(daemon);
      daemon.once("close", () => this.held.delete(daemon));
      return;
    }
    const peer = relay
      ? net.connect({ host: "127.0.0.1", port: this.proxyPort })
      : net.connect({ host: hostOf(this.upstream), port: Number(this.upstream.port) });
    peer.on("error", () => undefined);
    const pair: Pair = { daemon, peer, relay, frozen: false };
    this.pairs.add(pair);
    peer.once("connect", () => {
      peer.write(rawRequestHead(request));
      if (head.length > 0) peer.write(head);
      daemon.pipe(peer);
      peer.pipe(daemon);
    });
    // A reset on one side is a reset on the other (the proxy's `reset()` is
    // RST). A frozen pair propagates nothing: the daemon keeps a silent,
    // half-open socket until the outage ends.
    const link = (from: net.Socket, to: net.Socket) =>
      from.once("close", (hadError) => {
        if (pair.frozen) return;
        this.pairs.delete(pair);
        if (to.destroyed) return;
        if (hadError) to.resetAndDestroy();
        else to.end();
      });
    link(peer, daemon);
    link(daemon, peer);
  }

  /** Live relay links (not frozen, not closed). */
  get relayLinks(): number {
    return [...this.pairs].filter((pair) => pair.relay && !pair.frozen && !pair.daemon.destroyed)
      .length;
  }

  /** Relay connections waiting unanswered during an outage. */
  get heldConnections(): number {
    return this.held.size;
  }

  /** Freeze live relay links and leave new ones unanswered. */
  beginOutage(): number {
    this.outage = true;
    let frozen = 0;
    for (const pair of this.pairs) {
      if (!pair.relay || pair.frozen) continue;
      pair.frozen = true;
      pair.daemon.unpipe(pair.peer);
      pair.peer.unpipe(pair.daemon);
      pair.daemon.pause();
      pair.peer.pause();
      frozen += 1;
    }
    return frozen;
  }

  /** Reset every frozen or held connection; the daemon reconnects. */
  endOutage(): void {
    this.outage = false;
    for (const socket of this.held) socket.resetAndDestroy();
    this.held.clear();
    for (const pair of [...this.pairs]) {
      if (!pair.frozen) continue;
      this.pairs.delete(pair);
      if (!pair.daemon.destroyed) pair.daemon.resetAndDestroy();
      if (!pair.peer.destroyed) pair.peer.resetAndDestroy();
    }
  }

  async close(): Promise<void> {
    this.endOutage();
    for (const pair of [...this.pairs]) {
      pair.daemon.destroy();
      pair.peer.destroy();
    }
    this.pairs.clear();
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }
}
