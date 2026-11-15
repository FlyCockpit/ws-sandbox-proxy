/**
 * Test harness: ONE browser child process that makes a sequence of real
 * browser-terminal upgrade attempts, one at a time, against a listening
 * server. Like `browser-terminal-client-harness.ts` (the in-process test I/O
 * guard blocks outbound TCP, so the browser is a separate Node process), but
 * the process is started once per scenario rather than once per attempt:
 * budget scenarios make 30+ attempts, and booting a Node process for each
 * made their duration a function of machine load.
 *
 * An attempt either is refused (the HTTP status and `x-terminal-refusal`) or
 * opens; an opened socket is closed by the browser right away (code 1000)
 * and the attempt settles once the close completed. Attempts that need to
 * read or write frames use the per-attempt client harness instead.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

/** apps/server: where the client's `ws` import resolves, whatever the runner's cwd. */
const CLIENT_CWD = fileURLToPath(new URL("../..", import.meta.url));

const CLIENT = `
import { WebSocket } from "ws";
import { createInterface } from "node:readline";
const out = (result) => process.stdout.write(JSON.stringify(result) + "\\n");
function attempt({ url, protocols, headers }) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (result) => { if (!done) { done = true; resolve(result); } };
    let ws;
    try { ws = new WebSocket(url, protocols, { headers }); } catch (e) { finish({ kind: "error", message: String(e) }); return; }
    let protocol = null;
    ws.on("open", () => { protocol = ws.protocol; ws.close(1000); });
    ws.on("unexpected-response", (_req, res) => {
      res.resume();
      res.on("end", () => finish({ kind: "refused", status: res.statusCode, refusal: res.headers["x-terminal-refusal"] ?? null }));
    });
    ws.on("error", (e) => { if (!String(e).includes("Unexpected server response")) finish({ kind: "error", message: String(e) }); });
    ws.on("close", (code, reason) => {
      if (protocol !== null) finish({ kind: "open", protocol, closed: { code, reason: reason.toString() } });
    });
  });
}
let queue = Promise.resolve();
createInterface({ input: process.stdin }).on("line", (line) => {
  const request = JSON.parse(line);
  queue = queue.then(() => attempt(request)).then(out);
});
`;

export type ProbeAttempt = {
  path: string;
  protocols: string[];
  cookie?: string;
  /** `null` sends no Origin header. */
  origin: string | null;
};
type ProbeResult =
  | { kind: "open"; protocol: string; closed: { code: number; reason: string } }
  | { kind: "refused"; status: number; refusal: string | null };

export type BrowserProbe = {
  /** One upgrade attempt; settles with its outcome (attempts never overlap). */
  attempt(attempt: ProbeAttempt): Promise<ProbeResult>;
  dispose(): void;
};

const children = new Set<ChildProcess>();

/** Kill every probe still running (afterAll). */
export function killBrowserProbes() {
  for (const child of children) child.kill();
}

/** Start the browser process for `base` (`host:port` of the listening server). */
export function startBrowserProbe(base: string): BrowserProbe {
  const child = spawn(process.execPath, ["--input-type=module", "-e", CLIENT], {
    cwd: CLIENT_CWD,
    stdio: ["pipe", "pipe", "inherit"],
  });
  children.add(child);
  const waiting: {
    resolve: (result: ProbeResult) => void;
    reject: (error: Error) => void;
  }[] = [];
  let exited: Error | undefined;
  child.on("exit", (code) => {
    children.delete(child);
    exited = new Error(`browser probe exited (${code})`);
    for (const pending of waiting.splice(0)) pending.reject(exited);
  });
  let buffer = "";
  child.stdout!.on("data", (chunk: Buffer) => {
    buffer += chunk.toString();
    for (let index = buffer.indexOf("\n"); index >= 0; index = buffer.indexOf("\n")) {
      const result = JSON.parse(buffer.slice(0, index)) as
        | ProbeResult
        | { kind: "error"; message: string };
      buffer = buffer.slice(index + 1);
      const pending = waiting.shift();
      if (!pending) continue;
      if (result.kind === "error") pending.reject(new Error(result.message));
      else pending.resolve(result);
    }
  });
  let tail: Promise<unknown> = Promise.resolve();
  return {
    attempt(attempt) {
      const headers: Record<string, string> = {};
      if (attempt.cookie) headers.cookie = attempt.cookie;
      if (attempt.origin !== null) headers.origin = attempt.origin;
      const request = {
        url: `ws://${base}${attempt.path}`,
        protocols: attempt.protocols,
        headers,
      };
      // Serialized here too: the next attempt starts only after this one settled.
      const result = tail.then(
        () =>
          new Promise<ProbeResult>((resolve, reject) => {
            if (exited) {
              reject(exited);
              return;
            }
            waiting.push({ resolve, reject });
            child.stdin!.write(`${JSON.stringify(request)}\n`);
          }),
      );
      tail = result.catch(() => undefined);
      return result;
    },
    dispose() {
      child.kill();
    },
  };
}
