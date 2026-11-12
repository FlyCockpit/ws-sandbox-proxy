/**
 * Self-test of the WP1 fault proxy (`relay-fault-proxy-harness.ts`): each
 * primitive and fault point against a loopback "server" WebSocketServer and a
 * loopback "daemon" client. Runs under `pnpm test:relay-chaos`.
 */
import { once } from "node:events";
import type { IncomingMessage } from "node:http";
import { type AddressInfo, createServer } from "node:net";
import type { Duplex } from "node:stream";
import { setTimeout as sleep } from "node:timers/promises";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import WebSocket, { WebSocketServer } from "ws";
import { connectTarget, loopbackConnectAllowed } from "../../../../scripts/test-io-guard-loopback";
import { RELAY_CHAOS_MATRIX, relayChaosCells } from "./relay-chaos-matrix";
import { RelayFaultProxy, type RelayProxyFrame } from "./relay-fault-proxy-harness";

const SUBPROTOCOL = "ws-sandbox-proxy.relay.test";
const QUIET_MS = 250;

type Received = { data: string | Buffer; binary: boolean };

/** One endpoint: every message it received plus waiters on them. */
class Endpoint {
  readonly received: Received[] = [];
  readonly pings: Buffer[] = [];
  readonly pongs: Buffer[] = [];
  /** Error codes of the raw TCP socket under this endpoint. */
  readonly socketErrors: string[] = [];
  readonly closed: Promise<{ code: number; reason: string }>;

  constructor(
    readonly socket: WebSocket,
    raw?: Duplex,
  ) {
    raw?.on("error", (error: NodeJS.ErrnoException) =>
      this.socketErrors.push(error.code ?? error.message),
    );
    socket.once("upgrade", (response: IncomingMessage) =>
      response.socket.on("error", (error: NodeJS.ErrnoException) =>
        this.socketErrors.push(error.code ?? error.message),
      ),
    );
    socket.on("error", () => undefined);
    socket.on("message", (data, binary) => {
      const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);
      this.received.push({ data: binary ? bytes : bytes.toString("utf8"), binary });
    });
    socket.on("ping", (data) => this.pings.push(data));
    socket.on("pong", (data) => this.pongs.push(data));
    this.closed = once(socket, "close").then(([code, reason]) => ({
      code: code as number,
      reason: (reason as Buffer).toString("utf8"),
    }));
  }

  json(): Array<Record<string, unknown>> {
    return this.received.filter((m) => !m.binary).map((m) => JSON.parse(m.data as string));
  }

  types(): unknown[] {
    return this.json().map((m) => m.type);
  }

  send(message: Record<string, unknown>): void {
    this.socket.send(JSON.stringify(message));
  }

  async waitFor(count: number, timeoutMs = 5000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (this.received.length < count) {
      if (Date.now() > deadline)
        throw new Error(`expected ${count} messages, got ${this.received.length}`);
      await sleep(5);
    }
  }
}

let upstream: WebSocketServer;
let proxy: RelayFaultProxy;
let serverSide: Endpoint[];
let upgrades: IncomingMessage[];
const clients: WebSocket[] = [];

beforeEach(async () => {
  serverSide = [];
  upgrades = [];
  upstream = new WebSocketServer({
    host: "127.0.0.1",
    port: 0,
    handleProtocols: (protocols) => (protocols.has(SUBPROTOCOL) ? SUBPROTOCOL : false),
    verifyClient: (info, done) => {
      if (info.req.headers.authorization === "Bearer refuse") done(false, 401, "Unauthorized");
      else done(true);
    },
  });
  await once(upstream, "listening");
  upstream.on("connection", (socket, request) => {
    upgrades.push(request);
    serverSide.push(new Endpoint(socket, request.socket));
  });
  const { port } = upstream.address() as { port: number };
  proxy = await RelayFaultProxy.start({ upstream: `ws://127.0.0.1:${port}` });
});

afterEach(async () => {
  for (const client of clients.splice(0)) client.terminate();
  await proxy.close();
  for (const socket of upstream.clients) socket.terminate();
  await new Promise<void>((resolve) => upstream.close(() => resolve()));
});

/** Dial the proxy as a daemon would and wait for both legs. */
async function connect(): Promise<{ node: Endpoint; server: Endpoint }> {
  const before = serverSide.length;
  const socket = new WebSocket(`${proxy.url}/ws/sandbox-host`, [SUBPROTOCOL], {
    headers: { authorization: "Bearer test-only" },
  });
  clients.push(socket);
  const node = new Endpoint(socket);
  await once(socket, "open");
  while (serverSide.length === before) await sleep(2);
  return { node, server: serverSide.at(-1)! };
}

function dispatch(operationId: string, kind = "command.run") {
  return { type: "operation.dispatch", operationId, kind };
}

function result(operationId: string) {
  return { type: "operation.result", operationId, state: "succeeded" };
}

/** Binary stream frame: u32 BE metadata length, JSON metadata, body. */
function binaryFrame(metadata: Record<string, unknown>, body: string): Buffer {
  const json = Buffer.from(JSON.stringify(metadata));
  const length = Buffer.alloc(4);
  length.writeUInt32BE(json.byteLength);
  return Buffer.concat([length, json, Buffer.from(body)]);
}

describe("transparent forwarding", () => {
  it("forwards text, binary, ping/pong, path, headers and subprotocol both ways", async () => {
    const { node, server } = await connect();
    expect(node.socket.protocol).toBe(SUBPROTOCOL);
    expect(upgrades[0]?.url).toBe("/ws/sandbox-host");
    expect(upgrades[0]?.headers.authorization).toBe("Bearer test-only");

    node.send({ type: "hello", id: "h1" });
    server.send(dispatch("op-1"));
    node.socket.send(binaryFrame({ type: "stdout", operationId: "op-1" }, "abc"));
    await server.waitFor(2);
    await node.waitFor(1);
    expect(server.received[0]).toEqual({
      data: JSON.stringify({ type: "hello", id: "h1" }),
      binary: false,
    });
    expect(server.received[1]?.binary).toBe(true);
    expect(node.json()).toEqual([dispatch("op-1")]);

    const binary = await proxy.waitForFrame({ dir: "n2s", type: "stdout" });
    expect(binary).toMatchObject({ binary: true, operationId: "op-1", disposition: "forwarded" });
    const sent = await proxy.waitForFrame({ dir: "s2n", type: "operation.dispatch" });
    expect(sent).toMatchObject({ kind: "command.run", operationId: "op-1" });

    // Pings cross the proxy and the far end's pong comes back through it.
    server.socket.ping(Buffer.from("p1"));
    await proxy.waitForFrame({ dir: "n2s", type: "ws.pong" });
    while (server.pongs.length === 0) await sleep(2);
    expect(server.pongs[0]?.toString()).toBe("p1");
    expect(node.pings[0]?.toString()).toBe("p1");
  });

  it("mirrors a clean close code from either side", async () => {
    const first = await connect();
    first.server.socket.close(4003, "revoked");
    expect(await first.node.closed).toEqual({ code: 4003, reason: "revoked" });

    const second = await connect();
    second.node.socket.close(1000, "bye");
    expect((await second.server.closed).code).toBe(1000);
  });

  it("replays an upstream HTTP refusal and answers 502 when upstream is down", async () => {
    const refused = new WebSocket(`${proxy.url}/ws/sandbox-host`, {
      headers: { authorization: "Bearer refuse" },
    });
    refused.on("error", () => undefined);
    const [, response] = (await once(refused, "unexpected-response")) as [unknown, IncomingMessage];
    expect(response.statusCode).toBe(401);
    response.destroy();

    // An upstream that drops every connection before the handshake.
    const hangup = createServer((socket) => socket.destroy());
    hangup.listen(0, "127.0.0.1");
    await once(hangup, "listening");
    const dead = await RelayFaultProxy.start({
      upstream: `ws://127.0.0.1:${(hangup.address() as AddressInfo).port}`,
    });
    try {
      const client = new WebSocket(`${dead.url}/ws/sandbox-host`);
      client.on("error", () => undefined);
      const [, res] = (await once(client, "unexpected-response")) as [unknown, IncomingMessage];
      expect(res.statusCode).toBe(502);
      res.destroy();
    } finally {
      await dead.close();
      await new Promise<void>((resolve) => hangup.close(() => resolve()));
    }
  });

  it("refuses a non-loopback upstream", async () => {
    await expect(RelayFaultProxy.start({ upstream: "ws://192.0.2.1:80" })).rejects.toThrow(
      /loopback/,
    );
    await expect(RelayFaultProxy.start({ upstream: "wss://127.0.0.1:80" })).rejects.toThrow(
      /loopback/,
    );
  });
});

describe("primitives", () => {
  it("reset: RSTs both sockets (SrvX) and a new link forms afterwards", async () => {
    const { node, server } = await connect();
    const [link] = proxy.liveLinks();
    expect(proxy.reset()).toBe(1);
    expect((await node.closed).code).toBe(1006);
    expect((await server.closed).code).toBe(1006);
    // An RST, not a FIN: both peers read ECONNRESET.
    expect(node.socketErrors).toContain("ECONNRESET");
    expect(server.socketErrors).toContain("ECONNRESET");
    await link?.closed;
    expect(link?.live).toBe(false);

    const again = await connect();
    expect((await proxy.waitForLinks(2)).id).toBe(2);
    again.node.send({ type: "hello", id: "h2" });
    await again.server.waitFor(1);
  });

  it("outage: new links are reset at the upgrade until restored; live links stay", async () => {
    const { node, server } = await connect();
    proxy.outage();
    const refused = new WebSocket(`${proxy.url}/ws/sandbox-host`, [SUBPROTOCOL], {
      headers: { authorization: "Bearer test-only" },
    });
    clients.push(refused);
    // `once` would reject on the reset's "error"; wait for "close" alone.
    refused.on("error", () => undefined);
    await new Promise((resolve) => refused.once("close", resolve));
    expect(proxy.refused).toBe(1);
    expect(proxy.accepted).toBe(1);
    expect(serverSide).toHaveLength(1);
    // The live link still forwards during the outage.
    node.send({ type: "hello", id: "during-outage" });
    await server.waitFor(1);
    proxy.restore();
    await connect();
    expect(proxy.accepted).toBe(2);
    expect(proxy.refused).toBe(1);
  });

  it("inject: synthetic frames follow the queued ones on that link, in order", async () => {
    const { node, server } = await connect();
    const [link] = proxy.liveLinks();
    node.send({ type: "hello", id: "real" });
    await server.waitFor(1);
    for (let index = 0; index < 3; index++)
      proxy.inject(link!.id, "n2s", JSON.stringify({ type: "heartbeat", id: `burst-${index}` }));
    proxy.inject(link!.id, "s2n", JSON.stringify({ type: "heartbeat.pong", id: "down" }));
    await server.waitFor(4);
    await node.waitFor(1);
    expect(server.json().map((m) => m.id)).toEqual(["real", "burst-0", "burst-1", "burst-2"]);
    expect(node.json()).toEqual([{ type: "heartbeat.pong", id: "down" }]);
    expect(proxy.frames.filter((f) => f.type === "heartbeat").map((f) => f.disposition)).toEqual([
      "forwarded",
      "forwarded",
      "forwarded",
    ]);
    proxy.reset();
    expect(() => proxy.inject(link!.id, "n2s", "{}")).toThrow(/not live/);
  });

  it("blackhole: sockets stay open, nothing (pings included) is forwarded", async () => {
    const { node, server } = await connect();
    expect(proxy.blackhole()).toBe(1);
    node.send(result("op-1"));
    server.send(dispatch("op-2"));
    server.socket.ping(Buffer.from("p"));
    await sleep(QUIET_MS);
    expect(node.received).toEqual([]);
    expect(node.pings).toEqual([]);
    expect(server.received).toEqual([]);
    expect(server.pongs).toEqual([]);
    expect(node.socket.readyState).toBe(WebSocket.OPEN);
    expect(server.socket.readyState).toBe(WebSocket.OPEN);

    // A blackholed link only ends by reset; new links are unaffected.
    const fresh = await connect();
    fresh.node.send({ type: "hello", id: "h3" });
    await fresh.server.waitFor(1);
    proxy.reset();
    expect((await node.closed).code).toBe(1006);
  });

  it("delay: adds one-way latency per direction and keeps order", async () => {
    const { node, server } = await connect();
    proxy.delay(200, "n2s");
    const started = Date.now();
    for (const id of ["a", "b", "c"]) node.send({ type: "heartbeat", id });
    server.send(dispatch("op-fast"));
    await node.waitFor(1);
    expect(Date.now() - started).toBeLessThan(150);
    await server.waitFor(3);
    expect(Date.now() - started).toBeGreaterThanOrEqual(190);
    expect(server.json().map((m) => m.id)).toEqual(["a", "b", "c"]);

    proxy.delay(0);
    const after = Date.now();
    node.send({ type: "heartbeat", id: "d" });
    await server.waitFor(4);
    expect(Date.now() - after).toBeLessThan(150);
  });

  it("closeWith: sends the code toward the daemon and 1001 to the server", async () => {
    const { node, server } = await connect();
    expect(proxy.closeWith(1013, "try again later")).toBe(1);
    expect(await node.closed).toEqual({ code: 1013, reason: "try again later" });
    expect((await server.closed).code).toBe(1001);

    const other = await connect();
    proxy.closeWith(1000, "", "server");
    expect((await other.server.closed).code).toBe(1000);
    expect((await other.node.closed).code).toBe(1001);
    expect(() => proxy.closeWith(1006)).toThrow(/cannot be sent/);
  });

  it("dropNext: loses exactly the next matching frame", async () => {
    const { node, server } = await connect();
    const dropped = proxy.dropNext({ dir: "s2n", type: "operation.dispatch", kind: "command.run" });
    server.send(dispatch("op-file", "file.put"));
    server.send(dispatch("op-1"));
    server.send(dispatch("op-2"));
    node.send(dispatch("op-n2s")); // wrong direction: forwarded
    await node.waitFor(2);
    await server.waitFor(1);
    expect((await dropped).operationId).toBe("op-1");
    expect(node.json().map((m) => m.operationId)).toEqual(["op-file", "op-2"]);
    expect(proxy.frames.find((f) => f.operationId === "op-1")?.disposition).toBe("dropped");
  });

  it("holdUntil/release: holds from the match on, in that direction only", async () => {
    const { node, server } = await connect();
    const hold = proxy.holdUntil({ dir: "n2s", type: "operation.result" });
    node.send({ type: "heartbeat", id: "before" });
    await server.waitFor(1);
    node.send(result("op-1"));
    node.send({ type: "heartbeat", id: "after" });
    server.send(dispatch("op-2"));
    expect((await hold.matched).operationId).toBe("op-1");
    await node.waitFor(1);
    await sleep(QUIET_MS);
    expect(server.received).toHaveLength(1);
    expect(hold.frames.map((f) => f.type)).toEqual(["operation.result", "heartbeat"]);

    hold.release();
    await server.waitFor(3);
    expect(server.types()).toEqual(["heartbeat", "operation.result", "heartbeat"]);
    // Released: later frames flow freely.
    node.send({ type: "heartbeat", id: "later" });
    await server.waitFor(4);

    const second = proxy.holdUntil({ dir: "s2n", type: "operation.dispatch" });
    server.send(dispatch("op-3"));
    await second.matched;
    proxy.release();
    await node.waitFor(2);
  });
});

describe("fault points", () => {
  it("(i) hold-then-reset: the held frame never arrives", async () => {
    const { node, server } = await connect();
    const held = proxy.holdThenReset({ dir: "n2s", type: "operation.result" });
    node.send(result("op-1"));
    const frame = await held;
    expect((await server.closed).code).toBe(1006);
    expect((await node.closed).code).toBe(1006);
    expect(server.received).toEqual([]);
    expect(frame.disposition).toBe("discarded");
  });

  it("(ii) forward-then-reset: the frame arrives, the peer's next frame does not", async () => {
    const { node, server } = await connect();
    const fault = proxy.forwardThenReset({ dir: "s2n", type: "operation.dispatch" });
    server.send(dispatch("op-1"));
    await node.waitFor(1);
    node.send({ type: "operation.progress", operationId: "op-1" });
    const { forwarded, suppressed } = await fault;
    expect(forwarded.disposition).toBe("forwarded");
    expect(suppressed).toMatchObject({
      dir: "n2s",
      type: "operation.progress",
      disposition: "dropped",
    });
    expect((await server.closed).code).toBe(1006);
    expect((await node.closed).code).toBe(1006);
    expect(server.received).toEqual([]);
  });

  it("(iii) drop-reply-then-reset: non-replies pass, the first reply is lost", async () => {
    const { node, server } = await connect();
    const fault = proxy.dropReplyThenReset({ dir: "n2s", type: "operation.result" });
    node.send(result("op-1"));
    await server.waitFor(1);
    server.send({ type: "heartbeat.pong", id: "x" });
    await node.waitFor(1);
    server.send({ type: "receipt.ack", operationId: "op-1" });
    const { trigger, dropped } = await fault;
    expect(trigger.type).toBe("operation.result");
    expect(dropped.type).toBe("receipt.ack");
    expect((await node.closed).code).toBe(1006);
    expect(node.types()).toEqual(["heartbeat.pong"]);
  });
});

describe("support", () => {
  it("frame log records every frame with direction and sequence", async () => {
    const { node, server } = await connect();
    const cursor = proxy.cursor;
    node.send({ type: "heartbeat", id: "1" });
    server.send({ type: "heartbeat.pong", id: "1" });
    const pong = await proxy.waitForFrame(
      { dir: "s2n", type: "heartbeat.pong" },
      { fromSeq: cursor },
    );
    const seen = proxy.frames.filter((f: RelayProxyFrame) => f.seq >= cursor);
    expect(seen.map((f) => [f.dir, f.type])).toEqual([
      ["n2s", "heartbeat"],
      ["s2n", "heartbeat.pong"],
    ]);
    expect(pong.linkId).toBe(1);
  });

  it("loopback guard admits only in-process loopback listeners", () => {
    const ports = new Set([4100]);
    expect(
      loopbackConnectAllowed(connectTarget([[{ host: "127.0.0.1", port: 4100 }, null]]), ports),
    ).toBe(true);
    expect(loopbackConnectAllowed(connectTarget([4100, "localhost"]), ports)).toBe(true);
    expect(
      loopbackConnectAllowed(connectTarget([[{ host: "127.0.0.1", port: 6379 }, null]]), ports),
    ).toBe(false);
    expect(loopbackConnectAllowed(connectTarget([{ host: "192.0.2.1", port: 4100 }]), ports)).toBe(
      false,
    );
    expect(loopbackConnectAllowed(connectTarget(["/run/socket"]), ports)).toBe(false);
  });

  it("chaos matrix: C1-C15, unique, all in the PR subset", () => {
    const ids = RELAY_CHAOS_MATRIX.map((cell) => cell.id);
    expect(ids).toEqual(Array.from({ length: 15 }, (_, index) => `C${index + 1}`));
    expect(relayChaosCells("pr")).toHaveLength(15);
    expect(relayChaosCells("full").length).toBeGreaterThanOrEqual(relayChaosCells("pr").length);
    expect(["pr", "full"]).toContain(process.env.RELAY_CHAOS_SUBSET);
    for (const cell of RELAY_CHAOS_MATRIX) expect(cell.faults.length).toBeGreaterThan(0);
  });
});
