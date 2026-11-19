import assert from "node:assert/strict";
import { once } from "node:events";
import http from "node:http";
import type { AddressInfo } from "node:net";
import net from "node:net";
import { test } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { FrontDoor, RELAY_PATH } from "./relay-chaos-front-door.ts";

type FakeProxy = { port: number; sockets: net.Socket[]; received: string[]; close(): void };

/** A raw TCP stand-in for the fault proxy: records bytes, keeps sockets. */
async function fakeProxy(): Promise<FakeProxy> {
  const sockets: net.Socket[] = [];
  const received: string[] = [];
  const server = net.createServer((socket) => {
    socket.on("error", () => undefined);
    sockets.push(socket);
    const index = received.push("") - 1;
    socket.on("data", (chunk) => {
      received[index] += chunk.toString();
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    port: (server.address() as AddressInfo).port,
    sockets,
    received,
    close: () => {
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}

async function upstreamServer() {
  const upgrades: string[] = [];
  const server = http.createServer((request, response) => {
    response.writeHead(200, { "content-type": "text/plain", "x-upstream": "yes" });
    response.end(`${request.method} ${request.url} host=${request.headers.host}`);
  });
  server.on("upgrade", (request, socket) => {
    upgrades.push(request.url ?? "");
    // The front door turns a client's reset into a reset here (destroying a
    // socket with the 101 reply still unread sends RST): without a listener
    // that `read ECONNRESET` is an uncaught exception after the test ended.
    socket.on("error", () => undefined);
    socket.end("HTTP/1.1 101 Switching Protocols\r\nupgrade: test\r\nconnection: upgrade\r\n\r\n");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = (server.address() as AddressInfo).port;
  return { url: new URL(`http://127.0.0.1:${port}`), upgrades, close: () => server.close() };
}

async function rawUpgrade(port: number, path: string): Promise<net.Socket> {
  const socket = net.connect({ host: "127.0.0.1", port });
  socket.on("error", () => undefined);
  await once(socket, "connect");
  socket.write(
    `GET ${path} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`,
  );
  return socket;
}

async function until(predicate: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 200; i += 1) {
    if (predicate()) return;
    await sleep(10);
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function setup() {
  const proxy = await fakeProxy();
  const upstream = await upstreamServer();
  const door = await FrontDoor.start(new URL("http://127.0.0.1:0"), upstream.url, proxy.port);
  return {
    proxy,
    upstream,
    door,
    async close() {
      await door.close();
      proxy.close();
      upstream.close();
    },
  };
}

test("plain HTTP goes to the server with the canonical Host kept", async () => {
  const s = await setup();
  try {
    const response = await fetch(`http://127.0.0.1:${s.door.port}/v1/hosts?limit=1`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-upstream"), "yes");
    assert.equal(await response.text(), `GET /v1/hosts?limit=1 host=127.0.0.1:${s.door.port}`);
  } finally {
    await s.close();
  }
});

test("relay upgrades go to the fault proxy; other upgrades go to the server", async () => {
  const s = await setup();
  try {
    const relay = await rawUpgrade(s.door.port, `${RELAY_PATH}?v=1`);
    await until(() => (s.proxy.received[0] ?? "").includes("\r\n\r\n"), "relay head");
    assert.match(s.proxy.received[0] ?? "", /^GET \/ws\/sandbox-host\?v=1 HTTP\/1\.1\r\n/);
    assert.equal(s.door.relayLinks, 1);
    relay.write("frame-n2s");
    await until(() => (s.proxy.received[0] ?? "").endsWith("frame-n2s"), "n2s bytes");
    const seen = new Promise<string>((resolve) => relay.once("data", (b) => resolve(b.toString())));
    s.proxy.sockets[0]?.write("frame-s2n");
    assert.equal(await seen, "frame-s2n");

    const other = await rawUpgrade(s.door.port, "/ws/terminal");
    await until(() => s.upstream.upgrades.length === 1, "terminal upgrade upstream");
    assert.deepEqual(s.upstream.upgrades, ["/ws/terminal"]);
    assert.equal(s.proxy.sockets.length, 1);
    relay.destroy();
    other.destroy();
  } finally {
    await s.close();
  }
});

test("a proxy reset reaches the daemon as a reset", async () => {
  const s = await setup();
  try {
    const relay = await rawUpgrade(s.door.port, RELAY_PATH);
    await until(() => s.proxy.sockets.length === 1, "proxy link");
    const errored = new Promise<string>((resolve) =>
      relay.once("error", (error: NodeJS.ErrnoException) => resolve(error.code ?? "")),
    );
    s.proxy.sockets[0]?.resetAndDestroy();
    assert.equal(await errored, "ECONNRESET");
  } finally {
    await s.close();
  }
});

test("an outage freezes live links, leaves new ones unanswered, then resets both", async () => {
  const s = await setup();
  try {
    const live = await rawUpgrade(s.door.port, RELAY_PATH);
    await until(() => s.proxy.sockets.length === 1, "first link");
    assert.equal(s.door.beginOutage(), 1);
    assert.equal(s.door.relayLinks, 0);

    // Frozen: nothing crosses, and a server-side close is not propagated.
    const before = s.proxy.received[0]?.length ?? 0;
    live.write("lost-during-outage");
    let liveClosed = false;
    live.once("close", () => {
      liveClosed = true;
    });
    s.proxy.sockets[0]?.destroy();
    await sleep(100);
    assert.equal(s.proxy.received[0]?.length, before);
    assert.equal(liveClosed, false);

    // New relay connections are accepted and never answered or forwarded.
    const fresh = await rawUpgrade(s.door.port, RELAY_PATH);
    let freshData = false;
    fresh.on("data", () => {
      freshData = true;
    });
    await until(() => s.door.heldConnections === 1, "held connection");
    await sleep(100);
    assert.equal(s.proxy.sockets.length, 1);
    assert.equal(freshData, false);

    // `once` would reject on the reset's error event; wait for close alone.
    const closed = (socket: net.Socket) =>
      new Promise<void>((resolve) => socket.once("close", () => resolve()));
    const liveReset = closed(live);
    const freshReset = closed(fresh);
    s.door.endOutage();
    await Promise.all([liveReset, freshReset]);
    assert.equal(s.door.heldConnections, 0);

    // After the outage new links flow again.
    const again = await rawUpgrade(s.door.port, RELAY_PATH);
    await until(() => s.proxy.sockets.length === 2, "link after outage");
    assert.equal(s.door.relayLinks, 1);
    again.destroy();
  } finally {
    await s.close();
  }
});
