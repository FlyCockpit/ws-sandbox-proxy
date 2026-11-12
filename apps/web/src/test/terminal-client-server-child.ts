/**
 * Child process of `apps/server/src/sandbox-relay/browser-terminal-web-client.test.ts`
 * (C54). Drives the REAL C54 `TerminalClient`
 * (apps/web/src/lib/terminal-client.ts, unmodified) with:
 *  - the real oRPC client stack of apps/web/src/utils/orpc.ts (RPCLink +
 *    SimpleCsrf + Batch + Dedupe + Retry plugins) against the real server's /rpc;
 *  - a `ws` WebSocket standing in for the browser's, which only adds what a
 *    browser adds by itself (Cookie, Origin) and a no-op 'error' listener (an
 *    EventEmitter without one would throw; a browser does not).
 * Only the xterm view and ResizeObserver are fakes. Events go to stdout as
 * JSON lines; commands come on stdin.
 */
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

import { createORPCClient } from "@orpc/client";
import { RPCLink } from "@orpc/client/fetch";
import {
  BatchLinkPlugin,
  ClientRetryPlugin,
  DedupeRequestsPlugin,
  SimpleCsrfProtectionLinkPlugin,
} from "@orpc/client/plugins";
import { ORPC_BATCH_MAX_SIZE } from "@wssp/config/orpc-batch";

import {
  TerminalClient,
  type TerminalView,
  type WebSocketConstructor,
} from "../lib/terminal-client";

const [argJson] = process.argv.slice(2);
const args = JSON.parse(argJson!) as {
  serverUrl: string;
  sandboxId: string;
  cookie: string;
  rpcOrigin: string;
  wsOrigin: string;
  wsModule: string;
};
const out = (event: Record<string, unknown>) => process.stdout.write(`${JSON.stringify(event)}\n`);

// The slice of `ws` this child uses (it is not resolvable from apps/web, so
// the server test hands over the module path).
interface NodeSocket {
  readonly protocol: string;
  on(event: "error" | "open", listener: () => void): void;
  on(event: "message", listener: (data: Buffer, binary: boolean) => void): void;
  on(event: "close", listener: (code: number, reason: Buffer) => void): void;
}
type NodeSocketConstructor = new (
  url: string,
  protocols: string[],
  options: { headers: Record<string, string> },
) => NodeSocket;

const { WebSocket: NodeWebSocket } = (await import(pathToFileURL(args.wsModule).href)) as {
  WebSocket: NodeSocketConstructor;
};

let sockets = 0;
class BrowserLikeWebSocket extends NodeWebSocket {
  constructor(url: string, protocols: string[]) {
    super(url, protocols, { headers: { cookie: args.cookie, origin: args.wsOrigin } });
    sockets += 1;
    const index = sockets;
    out({ event: "socket-new", index, url, protocolCount: protocols.length });
    this.on("error", () => {});
    this.on("open", () => out({ event: "socket-open", index, protocol: this.protocol }));
    this.on("message", (data, binary) => {
      if (!binary) out({ event: "socket-text", index, frame: JSON.parse(data.toString()) });
    });
    this.on("close", (code, reason) =>
      out({ event: "socket-close", index, code, reason: reason.toString() }),
    );
  }
}

const link = new RPCLink({
  url: `${args.serverUrl}/rpc`,
  plugins: [
    new SimpleCsrfProtectionLinkPlugin(),
    new BatchLinkPlugin({
      groups: [{ condition: () => true, context: {} }],
      maxSize: ORPC_BATCH_MAX_SIZE,
    }),
    new DedupeRequestsPlugin({ groups: [{ condition: () => true, context: {} }] }),
    new ClientRetryPlugin(),
  ],
  // RPCLink hands over a Request (headers inside); a browser adds Cookie and
  // Origin itself (credentials: "include" in apps/web/src/utils/orpc.ts).
  fetch(request, options) {
    const headers = new Headers((request as Request).headers);
    headers.set("cookie", args.cookie);
    headers.set("origin", args.rpcOrigin);
    return fetch(new Request(request as Request, { headers }), options as RequestInit);
  },
});
type CreateSessionInput = { sandboxId: string; rows: number; cols: number };
const rpc = createORPCClient(link) as {
  sandboxTerminals: {
    createSession(input: CreateSessionInput): Promise<{ path: string; protocols: string[] }>;
  };
};

let creates = 0;
let nextFit: { rows: number; cols: number } | null = { rows: 30, cols: 100 };
let dataListener: ((text: string) => void) | null = null;
let resizeCallback: (() => void) | null = null;
const decoder = new TextDecoder();

const view: TerminalView = {
  open: () => {},
  write: (data) => out({ event: "output", text: decoder.decode(data) }),
  onData: (listener) => {
    dataListener = listener;
    return { dispose: () => (dataListener = null) };
  },
  onBinary: () => ({ dispose: () => {} }),
  onNativePaste: () => ({ dispose: () => {} }),
  fit: () => (nextFit ? { ...nextFit } : null),
  selection: () => "",
  paste: () => {},
  focus: () => {},
  dispose: () => out({ event: "view-disposed" }),
};

const client = new TerminalClient({
  sandboxId: args.sandboxId,
  serverUrl: args.serverUrl,
  container: {} as HTMLElement,
  createSession: async (input) => {
    creates += 1;
    out({ event: "create", n: creates, input });
    try {
      const session = await rpc.sandboxTerminals.createSession(input);
      out({ event: "create-ok", n: creates, path: session.path });
      return session;
    } catch (error) {
      const e = error as { code?: unknown; status?: unknown };
      out({ event: "create-error", n: creates, code: e.code, status: e.status });
      throw error;
    }
  },
  loadView: async () => () => view,
  onChange: (snapshot) => out({ event: "state", snapshot }),
  WebSocket: BrowserLikeWebSocket as unknown as WebSocketConstructor,
  observeResize: (_element, onResize) => {
    resizeCallback = onResize;
    return () => (resizeCallback = null);
  },
  resizeDebounceMs: 10,
});

createInterface({ input: process.stdin }).on("line", (line) => {
  const command = JSON.parse(line) as {
    attach?: boolean;
    type?: string;
    resize?: { rows: number; cols: number } | null;
    detach?: boolean;
    dispose?: boolean;
    exit?: boolean;
  };
  if (command.attach) void client.start();
  if (command.type !== undefined) dataListener?.(command.type);
  if (command.resize !== undefined) {
    nextFit = command.resize;
    resizeCallback?.();
  }
  if (command.detach) client.detach();
  if (command.dispose) client.dispose();
  if (command.exit) process.exit(0);
});
out({ event: "ready" });
