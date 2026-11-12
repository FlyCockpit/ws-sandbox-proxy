/**
 * Test harness (C53): a real browser-terminal WebSocket client in a CHILD
 * process. The in-process test I/O guard blocks outbound TCP, so the browser
 * runs as a separate Node process that performs the real handshake against a
 * real listening server and streams events back as JSON lines.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

/** apps/server: where the client's `ws` import resolves, whatever the runner's cwd. */
const CLIENT_CWD = fileURLToPath(new URL("../..", import.meta.url));

const CLIENT = `
import { WebSocket } from "ws";
import { createInterface } from "node:readline";
const [url, protocols, headers, autoPong] = JSON.parse(process.argv[1]);
const out = (event) => process.stdout.write(JSON.stringify(event) + "\\n");
let ws;
try { ws = new WebSocket(url, protocols, { headers, autoPong }); } catch (e) { out({ event: "error", message: String(e) }); process.exit(0); }
ws.on("open", () => out({ event: "open", protocol: ws.protocol }));
ws.on("unexpected-response", (_req, res) => {
  let body = "";
  res.on("data", (c) => { body += c; });
  res.on("end", () => { out({ event: "refused", status: res.statusCode, refusal: res.headers["x-terminal-refusal"] ?? null }); process.exit(0); });
});
ws.on("error", (e) => { if (!String(e).includes("Unexpected server response")) out({ event: "error", message: String(e) }); });
ws.on("message", (data, binary) => out(binary ? { event: "binary", data: Buffer.from(data).toString("base64") } : { event: "text", data: data.toString() }));
ws.on("close", (code, reason) => { out({ event: "close", code, reason: reason.toString() }); process.exit(0); });
createInterface({ input: process.stdin }).on("line", (line) => {
  const command = JSON.parse(line);
  if (command.text !== undefined) ws.send(command.text);
  if (command.binary !== undefined) ws.send(Buffer.from(command.binary, "base64"));
  if (command.close) ws.close(1000);
});
`;

type BrowserClient = {
  protocol: string;
  text: Record<string, unknown>[];
  binary: string[];
  closed: Promise<{ code: number; reason: string }>;
  sendText(text: string): void;
  sendBinary(bytes: Buffer): void;
  close(): void;
};
export type Upgrade =
  | ({ kind: "open" } & BrowserClient)
  | { kind: "refused"; status: number; refusal: string | null };

const children = new Set<ChildProcess>();

/** Kill every client still running (afterAll). */
export function killBrowserClients() {
  for (const child of children) child.kill();
}

export function upgradeBrowserTerminal(options: {
  /** `host:port` of the listening server. */
  base: string;
  path: string;
  protocols: string[];
  cookie?: string;
  /** `null` sends no Origin header. */
  origin: string | null;
  authorization?: string;
  /**
   * `false`: the client never answers WebSocket pings (a half-open browser).
   * Default `true`, like every browser.
   */
  autoPong?: boolean;
}): Promise<Upgrade> {
  const headers: Record<string, string> = {};
  if (options.cookie) headers.cookie = options.cookie;
  if (options.origin !== null) headers.origin = options.origin;
  if (options.authorization) headers.authorization = options.authorization;
  const url = `ws://${options.base}${options.path}`;
  const child = spawn(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      CLIENT,
      JSON.stringify([url, options.protocols, headers, options.autoPong ?? true]),
    ],
    { cwd: CLIENT_CWD, stdio: ["pipe", "pipe", "inherit"] },
  );
  children.add(child);
  child.on("exit", () => children.delete(child));
  const text: Record<string, unknown>[] = [];
  const binary: string[] = [];
  let closeResolve!: (value: { code: number; reason: string }) => void;
  const closed = new Promise<{ code: number; reason: string }>((resolve) => {
    closeResolve = resolve;
  });
  const write = (command: Record<string, unknown>) =>
    child.stdin!.write(`${JSON.stringify(command)}\n`);
  return new Promise((resolve, reject) => {
    child.once("exit", (code) =>
      reject(new Error(`browser client exited (${code}) before a result`)),
    );
    let buffer = "";
    child.stdout!.on("data", (chunk: Buffer) => {
      buffer += chunk.toString();
      for (let index = buffer.indexOf("\n"); index >= 0; index = buffer.indexOf("\n")) {
        const event = JSON.parse(buffer.slice(0, index));
        buffer = buffer.slice(index + 1);
        if (event.event === "open")
          resolve({
            kind: "open",
            protocol: event.protocol,
            text,
            binary,
            closed,
            sendText: (value) => write({ text: value }),
            sendBinary: (bytes) => write({ binary: bytes.toString("base64") }),
            close: () => write({ close: true }),
          });
        else if (event.event === "refused")
          resolve({ kind: "refused", status: event.status, refusal: event.refusal });
        else if (event.event === "text") text.push(JSON.parse(event.data));
        else if (event.event === "binary")
          binary.push(Buffer.from(event.data, "base64").toString());
        else if (event.event === "close") closeResolve({ code: event.code, reason: event.reason });
        else if (event.event === "error") reject(new Error(event.message));
      }
    });
  });
}
