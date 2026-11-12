import net from "node:net";

import { afterAll } from "vitest";

/**
 * The relay chaos gate's variant of `test-io-guard.ts`. The fault proxy and
 * its self-test dial in-process WebSocket servers, which the unit guard
 * (every outbound TCP connect blocked) forbids. This guard lets a socket
 * connect only to a loopback port that a server in THIS process is listening
 * on, so a stray Redis, Postgres or network dial still fails the run. Like
 * the unit guard it is a tripwire, not a sandbox.
 */

const loopbackGuardKey = Symbol.for("wssp.test-io-guard.loopback");

type LoopbackGuardState = {
  active: true;
  blockedAttempts: number;
  listeningPorts: Set<number>;
};

const LOOPBACK_HOSTS = new Set([undefined, "127.0.0.1", "::1", "localhost"]);

export type ConnectTarget = { host?: string; port?: number; path?: string };

/** The destination of a `net.Socket#connect` call, from its raw arguments. */
export function connectTarget(args: readonly unknown[]): ConnectTarget {
  // `net.connect()` passes its normalized `[options, callback]` array.
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  if (typeof first === "object" && first !== null) {
    const options = first as { host?: unknown; port?: unknown; path?: unknown };
    return {
      host: typeof options.host === "string" ? options.host : undefined,
      port: options.port === undefined ? undefined : Number(options.port),
      path: typeof options.path === "string" ? options.path : undefined,
    };
  }
  if (typeof first === "number" || (typeof first === "string" && /^\d+$/.test(first))) {
    return { port: Number(first), host: typeof args[1] === "string" ? args[1] : undefined };
  }
  return { path: typeof first === "string" ? first : undefined };
}

export function loopbackConnectAllowed(
  target: ConnectTarget,
  listeningPorts: ReadonlySet<number>,
): boolean {
  return (
    target.path === undefined &&
    LOOPBACK_HOSTS.has(target.host) &&
    target.port !== undefined &&
    listeningPorts.has(target.port)
  );
}

const existingState = Reflect.get(globalThis, loopbackGuardKey) as LoopbackGuardState | undefined;
const state: LoopbackGuardState = existingState ?? {
  active: true,
  blockedAttempts: 0,
  listeningPorts: new Set(),
};

if (existingState === undefined) {
  Object.defineProperty(globalThis, loopbackGuardKey, {
    configurable: false,
    enumerable: false,
    value: state,
    writable: false,
  });

  const originalListen = net.Server.prototype.listen;
  net.Server.prototype.listen = function loopbackGuardedListen(
    this: net.Server,
    ...args: Parameters<net.Server["listen"]>
  ) {
    this.once("listening", () => {
      const address = this.address();
      if (typeof address !== "object" || address === null) return;
      state.listeningPorts.add(address.port);
      this.once("close", () => state.listeningPorts.delete(address.port));
    });
    return originalListen.apply(this, args);
  } as net.Server["listen"];

  const originalConnect = net.Socket.prototype.connect;
  Object.defineProperty(net.Socket.prototype, "connect", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: function loopbackGuardedConnect(this: net.Socket, ...args: unknown[]) {
      if (!loopbackConnectAllowed(connectTarget(args), state.listeningPorts)) {
        state.blockedAttempts += 1;
        throw new Error("Test I/O guard blocked a non-loopback or foreign TCP connection.");
      }
      return Reflect.apply(originalConnect, this, args);
    },
  });
}

afterAll(() => {
  if (state.blockedAttempts !== 0) {
    throw new Error(
      `Test I/O guard blocked ${state.blockedAttempts} TCP connection attempt(s) outside in-process loopback servers.`,
    );
  }
});
