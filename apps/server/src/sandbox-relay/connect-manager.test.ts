import { ORPCError } from "@orpc/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import type { SandboxConnectBinding, SandboxConnectCheck } from "@wssp/api/sandbox/connect-binding";
import {
  notifySandboxTerminalLifecycle,
  subscribeSandboxTerminalLifecycle,
} from "@wssp/api/sandbox/terminal-lifecycle";
import {
  type AuthorityChangeHold,
  authorityTicket,
  holdAuthorityChange,
  withAuthorityChange,
} from "@wssp/db/authority";
import {
  CONNECT_LIMITS,
  encodeConnectDataFrame,
  parseConnectDataFrame,
} from "@wssp/sandbox-contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CONNECT_CONNECTION_CAPS,
  type ConnectHostLink,
  ConnectManager,
  type HostChannelControl,
} from "./connect-manager.js";
import {
  CHANNEL_LIMITS,
  type ChannelFence,
  encodeChannelDataFrame,
  parseChannelDataFrame,
} from "./protocol.js";

vi.mock("@wssp/env/server", () => ({ env: { BETTER_AUTH_SECRET: "connect-manager-test" } }));
vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});

/** The host relay socket: every channel frame the node would act on. */
class FakeHost {
  readyState = 1;
  bufferedAmount = 0;
  sends: string[] = [];
  binary: ArrayBuffer[] = [];
  send(data: string | ArrayBuffer | Uint8Array) {
    if (typeof data === "string") this.sends.push(data);
    else this.binary.push(data instanceof ArrayBuffer ? data : data.slice().buffer);
  }
  frames(type: string) {
    return this.sends.map((s) => JSON.parse(s)).filter((f) => f.type === type);
  }
  input() {
    return this.binary.map((frame) => parseChannelDataFrame(frame)!);
  }
}

/** The upgraded CLI socket. */
class FakeClient {
  readyState = 1;
  bufferedAmount = 0;
  text: Record<string, unknown>[] = [];
  data: { channel: number; stream: string; seq: number; body: string }[] = [];
  /** Every frame in arrival order (data as `data:<stream>:<seq>`). */
  order: string[] = [];
  closes: { code: number; reason: string }[] = [];
  pings = 0;
  ping() {
    this.pings += 1;
  }
  send(data: string | Uint8Array) {
    if (typeof data === "string") {
      const frame = JSON.parse(data);
      this.text.push(frame);
      this.order.push(String(frame.type));
      return;
    }
    const parsed = parseConnectDataFrame(data)!;
    this.data.push({ ...parsed.metadata, body: new TextDecoder().decode(parsed.body) });
    this.order.push(`data:${parsed.metadata.stream}:${parsed.metadata.seq}`);
  }
  close(code: number, reason: string) {
    this.closes.push({ code, reason });
    this.readyState = 3;
  }
  frames(type: string) {
    return this.text.filter((frame) => frame.type === type);
  }
}

const principal = {
  kind: "sdkKey",
  credentialKind: "API",
  ownSandboxesOnly: false,
  expiresAt: null,
  keyId: "key-1",
  ownerId: "owner-1",
  resourceMode: "ALL_OWNED",
  scopes: new Set(["sandboxes:connect"]),
  allowedHostIds: "allOwned",
  allowedRevisionIds: "allOwned",
  allowedPoolIds: "allUsable",
} as unknown as ServicePrincipal;

function bindingFor(overrides: Partial<SandboxConnectBinding> = {}): SandboxConnectBinding {
  return {
    ownerId: "owner-1",
    keyId: "key-1",
    sandboxId: "sbx-1",
    hostId: "host-1",
    hostOwnerId: "owner-1",
    generation: 3,
    epoch: 7,
    keyExpiresAt: null,
    leaseExpiresAt: null,
    ...overrides,
  };
}

/** A retained authorization like the real one: credential + owner + host tickets. */
function retainedFor(binding: SandboxConnectBinding) {
  const ticket = authorityTicket({
    ownerId: binding.ownerId,
    credentialId: binding.keyId,
    hostId: binding.hostId,
  });
  const retained = {
    context: { sandboxId: binding.sandboxId },
    current: () =>
      ticket() && (binding.keyExpiresAt === null || binding.keyExpiresAt.getTime() > Date.now()),
    recheck: async () => retained,
  };
  return retained;
}

type Verdict =
  | "ok"
  | "forbidden"
  | "not_found"
  | Exclude<SandboxConnectCheck, { ok: true }>["intent"];

const holds: AuthorityChangeHold[] = [];
function holdChange(scope: Parameters<typeof holdAuthorityChange>[0]) {
  const change = holdAuthorityChange(scope);
  holds.push(change);
  return change;
}
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));
async function settle() {
  for (let i = 0; i < 10; i += 1) await tick();
}

let host: FakeHost;
let linkAuthorized: boolean;
let linkError: { code: "disconnected" | "unsupported_capability"; message: string } | null;
let linkKinds: string[];
let verdict: Verdict;
let checks: number;
let closedSockets: string[];
let manager: ConnectManager;

function link(): ConnectHostLink {
  return {
    socket: host,
    hostId: "host-1",
    ownerId: "owner-1",
    epoch: 7,
    protocolVersion: "1.0",
    authorized: () => linkAuthorized,
    kinds: linkKinds,
  };
}

function createManager(options: ConstructorParameters<typeof ConnectManager>[1] = {}) {
  return new ConnectManager(
    {
      connectHost: () => (linkError ? { error: linkError } : { link: link() }),
      closeHostSocket: (_socket, message) => closedSockets.push(message),
    },
    {
      check: async (_principal, _sandboxId, expected) => {
        checks += 1;
        if (verdict === "forbidden") throw new ORPCError("FORBIDDEN");
        if (verdict === "not_found") throw new ORPCError("NOT_FOUND");
        if (verdict !== "ok") return { ok: false, intent: verdict };
        const binding = bindingFor(expected ? { ...expected } : {});
        return { ok: true, binding, retained: retainedFor(binding) as never };
      },
      ...options,
    },
  );
}

function connect(binding = bindingFor(), client = new FakeClient()) {
  const reserved = manager.reserve(binding);
  if (!reserved.ok) throw new Error(reserved.reason);
  const connection = manager.attach(reserved.reservation, principal, retainedFor(binding) as never);
  connection.opened(client);
  return { connection, client };
}

function send(connection: ReturnType<typeof connect>["connection"], frame: unknown) {
  connection.message(JSON.stringify(frame));
}

function stdin(
  connection: ReturnType<typeof connect>["connection"],
  channel: number,
  seq: number,
  text: string,
) {
  const frame = encodeConnectDataFrame(
    { type: "data", channel, stream: "stdin", seq },
    new TextEncoder().encode(text),
  );
  connection.message(frame.buffer.slice(frame.byteOffset, frame.byteOffset + frame.byteLength));
}

const pty = { rows: 24, cols: 80, term: "xterm-256color" };

function openPty(connection: ReturnType<typeof connect>["connection"], channel = 1) {
  send(connection, { type: "open", channel, kind: "pty", login: true, pty });
  const open = host.frames("channel.open").at(-1)!;
  return open.fence as ChannelFence;
}

function openExec(connection: ReturnType<typeof connect>["connection"], channel = 1) {
  send(connection, { type: "open", channel, kind: "exec", argv: ["cat"] });
  return host.frames("channel.open").at(-1)!.fence as ChannelFence;
}

function hostControl(message: Record<string, unknown>) {
  manager.handleHostControl(host, message as HostChannelControl);
}

function ready(fence: ChannelFence, kind: "pty" | "exec" = "pty") {
  hostControl({
    type: "channel.ready",
    fence,
    ...(kind === "pty" ? { pty: { rows: 24, cols: 80 } } : {}),
  });
}

function output(fence: ChannelFence, seq: number, text: string, stream = "stdout") {
  const frame = encodeChannelDataFrame(
    { type: "channel.data", fence, stream: stream as "stdout", seq },
    new TextEncoder().encode(text),
  );
  const parsed = parseChannelDataFrame(frame)!;
  manager.handleHostData(host, parsed.metadata, parsed.body);
}

function exit(fence: ChannelFence, fields: Record<string, unknown> = {}) {
  hostControl({
    type: "channel.exit",
    fence,
    reaped: true,
    frames: { stdout: 0, stderr: 0 },
    ...fields,
  });
}

beforeEach(() => {
  host = new FakeHost();
  linkAuthorized = true;
  linkError = null;
  linkKinds = ["pty", "exec", "tcp", "unix"];
  verdict = "ok";
  checks = 0;
  closedSockets = [];
  manager = createManager();
});

afterEach(() => {
  for (const change of holds.splice(0)) change.settle();
  manager.dispose();
  vi.useRealTimers();
});

describe("connect manager: connection, open and identity", () => {
  it("sends hello first, then opens a channel under a server-minted fence", () => {
    const { connection, client } = connect();
    expect(client.text[0]).toEqual({
      type: "hello",
      connectionId: connection.connectionId,
      sandboxId: "sbx-1",
      limits: CONNECT_LIMITS,
    });
    const fence = openPty(connection, 5);
    expect(fence).toEqual({
      channelId: expect.stringMatching(/^h[0-9a-f]{32}$/),
      connectionId: connection.connectionId,
      hostId: "host-1",
      epoch: 7,
      target: { kind: "sandbox", sandboxId: "sbx-1", generation: 3 },
    });
    const open = host.frames("channel.open")[0];
    expect(open).toEqual({ type: "channel.open", fence, kind: "pty", login: true, pty });
    ready(fence);
    expect(client.frames("ready")).toEqual([
      { type: "ready", channel: 5, pty: { rows: 24, cols: 80 } },
    ]);
  });

  it("exec opens default to login false and carry only the kind parameters", () => {
    const { connection } = connect();
    send(connection, {
      type: "open",
      channel: 1,
      kind: "exec",
      argv: ["sh", "-c", "echo $1", "--", "a b"],
      cwd: "/work",
      env: { LANG: "C.UTF-8" },
    });
    const open = host.frames("channel.open")[0];
    expect(open.login).toBe(false);
    expect(open.argv).toEqual(["sh", "-c", "echo $1", "--", "a b"]);
    expect(Object.keys(open).sort()).toEqual([
      "argv",
      "cwd",
      "env",
      "fence",
      "kind",
      "login",
      "type",
    ]);
  });

  it("refuses a non-increasing channel id and any unknown field as a protocol violation", () => {
    const first = connect();
    openPty(first.connection, 2);
    send(first.connection, { type: "open", channel: 2, kind: "exec" });
    expect(first.client.frames("end")).toEqual([
      expect.objectContaining({ type: "end", intent: "protocol_violation" }),
    ]);
    expect(first.client.closes).toEqual([{ code: 4401, reason: "end" }]);
    const second = connect();
    send(second.connection, { type: "open", channel: 1, kind: "exec", shell: "bash -c x" });
    expect(second.client.frames("end")[0]).toMatchObject({ intent: "protocol_violation" });
  });

  it("refuses opens past the per-connection pty cap and rate with an exit", () => {
    const { connection, client } = connect();
    for (let channel = 1; channel <= CONNECT_LIMITS.maxPtyChannels; channel += 1)
      openPty(connection, channel);
    send(connection, { type: "open", channel: 100, kind: "pty", pty });
    expect(client.frames("exit")).toEqual([
      {
        type: "exit",
        channel: 100,
        error: { code: "host_capacity", message: "channel capacity reached for this connection" },
        frames: { stdout: 0, stderr: 0 },
      },
    ]);
    expect(host.frames("channel.open")).toHaveLength(CONNECT_LIMITS.maxPtyChannels);
    expect(client.frames("end")).toEqual([]);
  });

  it("enforces the per-host channel cap on the server too", () => {
    const opened: ReturnType<typeof connect>[] = [];
    for (let index = 0; index < 4; index += 1)
      opened.push(connect(bindingFor({ keyId: `key-${index}`, ownerId: `owner-${index}` })));
    let channel = 0;
    // 3 connections × 32 exec channels = the host's 96.
    for (const { connection } of opened.slice(0, 3))
      for (let i = 0; i < CONNECT_LIMITS.maxChannels; i += 1) {
        channel += 1;
        openExec(connection, channel);
      }
    expect(host.frames("channel.open")).toHaveLength(CHANNEL_LIMITS.maxChannelsPerHost);
    send(opened[3]!.connection, { type: "open", channel: 1, kind: "exec" });
    expect(opened[3]!.client.frames("exit")[0]).toMatchObject({
      error: { code: "host_capacity" },
    });
  });

  it("caps connections per sandbox, key and owner at reservation", () => {
    for (let index = 0; index < CONNECT_CONNECTION_CAPS.perSandbox; index += 1)
      expect(manager.reserve(bindingFor()).ok).toBe(true);
    expect(manager.reserve(bindingFor())).toEqual({ ok: false, reason: "capacity" });
    expect(manager.reserve(bindingFor({ sandboxId: "sbx-2" })).ok).toBe(true);
  });

  it("an open the node never answers expires after 30 s", () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager();
    const { connection, client } = connect();
    const fence = openExec(connection);
    vi.advanceTimersByTime(CONNECT_LIMITS.openTimeoutMs);
    expect(client.frames("exit")).toEqual([
      {
        type: "exit",
        channel: 1,
        intent: "expired",
        error: { code: "timeout", message: "channel open was not answered in time" },
        frames: { stdout: 0, stderr: 0 },
      },
    ]);
    expect(host.frames("channel.close")).toEqual([
      { type: "channel.close", fence, intent: "expired" },
    ]);
    // The channel stays charged until the node settles it.
    expect(manager.resources().channels).toBe(1);
    exit(fence, { intent: "expired" });
    expect(manager.resources().channels).toBe(0);
    expect(client.frames("exit")).toHaveLength(1);
  });

  it("a node refusal of an open reaches the client as an exit with its error", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    exit(fence, {
      error: { code: "credential_env_pending", message: "credential env pending" },
    });
    expect(client.frames("exit")[0]).toMatchObject({
      channel: 1,
      error: { code: "credential_env_pending" },
    });
    expect(manager.resources().channels).toBe(0);
  });
});

describe("connect manager: credits and ordering", () => {
  it("output is handed over within the client window and acked to the host only as it leaves", () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    const window = CHANNEL_LIMITS.ptyWindowFrames;
    for (let seq = 0; seq < window; seq += 1) output(fence, seq, `a${seq}`);
    expect(client.data).toHaveLength(window);
    expect(host.frames("channel.ack").map((ack) => ack.seq)).toEqual(
      Array.from({ length: window }, (_, seq) => seq),
    );
    // The client acks nothing: the next window waits on the server, unacked to the host.
    for (let seq = window; seq < 2 * window; seq += 1) output(fence, seq, `b${seq}`);
    expect(client.data).toHaveLength(window);
    expect(host.frames("channel.ack")).toHaveLength(window);
    // A third window would exceed the host's own window: a protocol violation.
    output(fence, 2 * window, "overflow");
    expect(client.frames("exit")[0]).toMatchObject({ intent: "protocol_violation" });
    expect(host.frames("channel.close").at(-1)).toMatchObject({ intent: "protocol_violation" });
  });

  it("client acks release queued output; a slow client socket holds host credit", async () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    const window = CHANNEL_LIMITS.ptyWindowFrames;
    for (let seq = 0; seq < 2 * window; seq += 1) output(fence, seq, `x${seq}`);
    send(connection, { type: "ack", channel: 1, stream: "stdout", seq: 3 });
    expect(client.data).toHaveLength(window + 4);
    expect(host.frames("channel.ack")).toHaveLength(window + 4);
    client.bufferedAmount = 64 * 1024 * 1024;
    send(connection, { type: "ack", channel: 1, stream: "stdout", seq: window + 3 });
    expect(client.data).toHaveLength(window + 4);
    client.bufferedAmount = 0;
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(client.data).toHaveLength(2 * window);
    expect(host.frames("channel.ack")).toHaveLength(2 * window);
    expect(client.data.map((frame) => frame.seq)).toEqual(
      Array.from({ length: 2 * window }, (_, seq) => seq),
    );
  });

  it("caps data bytes per second per connection in both directions, without dropping", async () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager({ maxBytesPerSecond: 1000, now: () => Date.now() });
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    const body = "x".repeat(600);
    for (let seq = 0; seq < 4; seq += 1) output(fence, seq, body);
    // 1000 bytes of burst: the second frame takes it below zero, the third waits.
    expect(client.data).toHaveLength(2);
    expect(host.frames("channel.ack")).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1_300);
    expect(client.data.length).toBeGreaterThanOrEqual(3);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(client.data.map((frame) => frame.seq)).toEqual([0, 1, 2, 3]);
    expect(host.frames("channel.ack")).toHaveLength(4);
    // Input: the same bucket size, its own balance.
    for (let seq = 0; seq < 4; seq += 1) stdin(connection, 1, seq, body);
    const sent = () =>
      host.input().filter((frame) => frame.metadata.fence.channelId === fence.channelId).length;
    expect(sent()).toBe(2);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(sent()).toBe(4);
    expect(client.frames("end")).toEqual([]);
  });

  it("an ack beyond the frames sent is a protocol violation", () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    output(fence, 0, "a");
    send(connection, { type: "ack", channel: 1, stream: "stdout", seq: 1 });
    expect(client.frames("end")[0]).toMatchObject({ intent: "protocol_violation" });
  });

  it("stdin flows within the host window and is acked to the client as the node acks it", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    stdin(connection, 1, 0, "early");
    expect(client.frames("end")[0]).toMatchObject({ intent: "protocol_violation" });

    const second = connect(bindingFor({ keyId: "key-2" }));
    const fence2 = openExec(second.connection, 1);
    ready(fence2, "exec");
    for (let seq = 0; seq < CHANNEL_LIMITS.bulkWindowFrames; seq += 1)
      stdin(second.connection, 1, seq, `in${seq}`);
    const input = host
      .input()
      .filter((frame) => frame.metadata.fence.channelId === fence2.channelId);
    expect(input.filter((f) => f.metadata.fence.connectionId === fence2.connectionId)).toHaveLength(
      CHANNEL_LIMITS.bulkWindowFrames,
    );
    hostControl({ type: "channel.ack", fence: fence2, stream: "stdin", seq: 4 });
    expect(second.client.frames("ack")).toEqual([
      { type: "ack", channel: 1, stream: "stdin", seq: 4 },
    ]);
    stdin(second.connection, 1, CHANNEL_LIMITS.bulkWindowFrames, "more");
    expect(second.client.frames("end")).toEqual([]);
    // Unacked stdin beyond the window ends the connection.
    for (
      let seq = CHANNEL_LIMITS.bulkWindowFrames + 1;
      seq < CHANNEL_LIMITS.bulkWindowFrames + 6;
      seq += 1
    )
      stdin(second.connection, 1, seq, "x");
    expect(second.client.frames("end")[0]).toMatchObject({ intent: "protocol_violation" });
    // Host channel ids are minted per channel, never the client's number.
    expect(fence.channelId).not.toBe(fence2.channelId);
  });

  it("stdin eof is forwarded after every stdin frame, with the client's count", () => {
    const { connection } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    stdin(connection, 1, 0, "a");
    stdin(connection, 1, 1, "b");
    send(connection, { type: "eof", channel: 1, stream: "stdin", frames: 2 });
    expect(host.frames("channel.eof")).toEqual([
      { type: "channel.eof", fence, stream: "stdin", frames: 2 },
    ]);
  });

  it("a natural exit leaves only after every output frame and eof before it", async () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    client.bufferedAmount = 64 * 1024 * 1024;
    output(fence, 0, "o0");
    output(fence, 0, "e0", "stderr");
    output(fence, 1, "o1");
    hostControl({ type: "channel.eof", fence, stream: "stdout", frames: 2 });
    hostControl({ type: "channel.eof", fence, stream: "stderr", frames: 1 });
    exit(fence, { exitCode: 3, frames: { stdout: 2, stderr: 1 } });
    expect(client.frames("exit")).toEqual([]);
    client.bufferedAmount = 0;
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(client.order.slice(1)).toEqual([
      "ready",
      "data:stdout:0",
      "data:stderr:0",
      "data:stdout:1",
      "eof",
      "eof",
      "exit",
    ]);
    expect(client.frames("exit")[0]).toEqual({
      type: "exit",
      channel: 1,
      exitCode: 3,
      frames: { stdout: 2, stderr: 1 },
    });
  });

  it("an exit carrying a close intent is delivered at once, dropping undelivered output", () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    const window = CHANNEL_LIMITS.ptyWindowFrames;
    for (let seq = 0; seq < 2 * window; seq += 1) output(fence, seq, "z");
    exit(fence, { intent: "backpressure", frames: { stdout: 2 * window, stderr: 0 } });
    expect(client.data).toHaveLength(window);
    expect(client.frames("exit")[0]).toEqual({
      type: "exit",
      channel: 1,
      intent: "backpressure",
      frames: { stdout: window, stderr: 0 },
    });
  });

  it("an unsettled exit keeps the channel charged until the node's final exit", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    exit(fence, { reaped: false, signal: 9, intent: "revoked" });
    expect(client.frames("exit")[0]).toMatchObject({ signal: 9, intent: "revoked" });
    expect(manager.resources()).toMatchObject({ channels: 1, unreaped: 1 });
    expect(connection.channelCount).toBe(1);
    hostControl({ type: "channel.exit", fence, reaped: true, frames: { stdout: 0, stderr: 0 } });
    expect(manager.resources()).toMatchObject({ channels: 0, unreaped: 0 });
    expect(connection.channelCount).toBe(0);
    expect(client.frames("exit")).toHaveLength(1);
  });

  it("frames for a channel that already ended are ignored, not violations", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    output(fence, 0, "a");
    exit(fence, { exitCode: 0, frames: { stdout: 1, stderr: 0 } });
    send(connection, { type: "ack", channel: 1, stream: "stdout", seq: 0 });
    send(connection, { type: "close", channel: 1 });
    expect(client.frames("end")).toEqual([]);
    send(connection, { type: "close", channel: 9 });
    expect(client.frames("end")[0]).toMatchObject({ intent: "protocol_violation" });
  });

  it("a normal client close sends channel.close{client} and forwards the node's exit", () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    send(connection, { type: "close", channel: 1 });
    expect(host.frames("channel.close")).toEqual([
      { type: "channel.close", fence, intent: "client" },
    ]);
    exit(fence, { intent: "client", exitCode: 129 });
    expect(client.frames("exit")[0]).toMatchObject({ intent: "client", exitCode: 129 });
  });

  it("host fence mismatches are violations; foreign frames are bounded per host socket", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    for (let i = 0; i < CHANNEL_LIMITS.fenceViolationLimit; i += 1)
      hostControl({
        type: "channel.eof",
        fence: { ...fence, epoch: 99 },
        stream: "stdout",
        frames: 0,
      });
    expect(client.frames("exit")[0]).toMatchObject({ intent: "protocol_violation" });
    const foreign = { ...fence, channelId: "h-foreign" };
    for (let i = 0; i <= 256; i += 1)
      hostControl({ type: "channel.eof", fence: foreign, stream: "stdout", frames: 0 });
    expect(closedSockets).toEqual(["Too many foreign channel frames."]);
  });
});

describe("connect manager: bounds against a misbehaving peer", () => {
  it("unacked bytes of a finished channel leave the budget: many short execs never wedge output", async () => {
    const { connection, client } = connect();
    await settle();
    const big = "x".repeat(CHANNEL_LIMITS.bulkDataMaxBytes);
    // Each channel leaves a full window unacked and exits; 6 of them is 6 MiB.
    for (let channel = 1; channel <= 6; channel += 1) {
      const fence = openExec(connection, channel);
      ready(fence, "exec");
      for (let seq = 0; seq < CHANNEL_LIMITS.bulkWindowFrames; seq += 1) output(fence, seq, big);
      hostControl({
        type: "channel.eof",
        fence,
        stream: "stdout",
        frames: CHANNEL_LIMITS.bulkWindowFrames,
      });
      hostControl({ type: "channel.eof", fence, stream: "stderr", frames: 0 });
      exit(fence, { exitCode: 0, frames: { stdout: CHANNEL_LIMITS.bulkWindowFrames, stderr: 0 } });
      await settle();
      await new Promise((resolve) => setTimeout(resolve, 30));
      expect(client.frames("exit").filter((e) => e.channel === channel)).toHaveLength(1);
    }
    expect(client.data).toHaveLength(6 * CHANNEL_LIMITS.bulkWindowFrames);
    expect(client.frames("end")).toEqual([]);
  });

  it("client control frames after its close are dropped; a queued flood is a violation", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    send(connection, { type: "close", channel: 1 });
    expect(host.frames("channel.close")).toHaveLength(1);
    for (let i = 0; i < 100; i += 1)
      send(connection, { type: "signal", channel: 1, signal: "TERM" });
    expect(host.frames("channel.signal")).toHaveLength(0);
    expect(client.frames("end")).toEqual([]);

    const second = connect(bindingFor({ keyId: "key-2" }));
    const fence2 = openExec(second.connection, 1);
    ready(fence2, "exec");
    linkAuthorized = false;
    for (let i = 0; i < 40; i += 1)
      send(second.connection, { type: "signal", channel: 1, signal: "TERM" });
    expect(second.client.frames("end")[0]).toMatchObject({ intent: "protocol_violation" });
  });

  it("resizes waiting behind a stale host ticket coalesce to the latest size", () => {
    const { connection } = connect();
    const fence = openPty(connection);
    ready(fence);
    linkAuthorized = false;
    for (let rows = 10; rows < 60; rows += 1)
      send(connection, { type: "resize", channel: 1, rows, cols: 80 });
    linkAuthorized = true;
    manager.resumeHost(host);
    expect(host.frames("channel.resize").map((frame) => frame.rows)).toEqual([59]);
  });

  it("a flood of refused requests or node notices ends with a violation", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    for (let i = 0; i < 80; i += 1)
      send(connection, { type: "resize", channel: 1, rows: 1, cols: 1 });
    expect(client.frames("error").length).toBeLessThanOrEqual(64);
    expect(client.frames("end")[0]).toMatchObject({ intent: "protocol_violation" });

    const second = connect(bindingFor({ keyId: "key-2" }));
    const fence2 = openExec(second.connection, 1);
    ready(fence2, "exec");
    for (let i = 0; i < 80; i += 1)
      hostControl({ type: "channel.error", fence: fence2, code: "state_conflict" });
    expect(host.frames("channel.close").at(-1)).toMatchObject({ intent: "protocol_violation" });
    expect(second.client.frames("error").length).toBeLessThanOrEqual(64);
    expect(second.client.frames("error")).toHaveLength(64);
  });

  it("a client that does not read its control replies ends backpressure", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    client.bufferedAmount = 64 * 1024 * 1024;
    send(connection, { type: "resize", channel: 1, rows: 1, cols: 1 });
    expect(client.frames("error")).toEqual([]);
    expect(client.frames("end")[0]).toMatchObject({ intent: "backpressure" });
  });

  it("the node may end a stream once: a second eof or data after it is a violation", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    hostControl({ type: "channel.eof", fence, stream: "stdout", frames: 0 });
    hostControl({ type: "channel.eof", fence, stream: "stdout", frames: 0 });
    // A repeat counts as a violation and is never relayed.
    expect(client.frames("eof")).toHaveLength(1);

    const second = connect(bindingFor({ keyId: "key-2" }));
    const fence2 = openExec(second.connection, 1);
    ready(fence2, "exec");
    hostControl({ type: "channel.eof", fence: fence2, stream: "stdout", frames: 0 });
    output(fence2, 0, "late");
    expect(second.client.data).toEqual([]);
    expect(client.frames("eof").length).toBeLessThanOrEqual(1);
  });

  it("refused opens count against the per-connection open rate", () => {
    const { connection, client } = connect();
    // The first opens fill the connection; the refused ones still count.
    for (let channel = 1; channel <= 200; channel += 1)
      send(connection, { type: "open", channel, kind: "exec", argv: ["true"] });
    const codes = client
      .frames("exit")
      .map((e) => (e.error as { code?: string } | undefined)?.code);
    expect(host.frames("channel.open")).toHaveLength(32);
    expect(codes.filter((code) => code === "host_capacity")).toHaveLength(120 - 32);
    expect(codes.filter((code) => code === "rate_limited")).toHaveLength(200 - 120);
  });

  it("a node intent outside the client wire is mapped, never passed through", () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    exit(fence, { intent: "replaced" });
    expect(client.frames("exit")[0]).toMatchObject({ intent: "superseded" });
  });
});

describe("connect manager: late ends, revocation and backpressure", () => {
  it("a revocation after an unreaped normal end still upgrades it to a kill", () => {
    const { connection } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    send(connection, { type: "close", channel: 1 });
    exit(fence, { exitCode: 0, reaped: false });
    expect(host.frames("channel.close").map((f) => f.intent)).toEqual(["client"]);
    connection.end("revoked");
    expect(host.frames("channel.close").map((f) => f.intent)).toEqual(["client", "revoked"]);
    // Only one upgrade.
    hostControl({ type: "channel.exit", fence, reaped: true, frames: { stdout: 0, stderr: 0 } });
    expect(host.frames("channel.close")).toHaveLength(2);
    expect(manager.resources().channels).toBe(0);
  });

  it("client input waits while the host socket is not draining its buffer", async () => {
    const { connection } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    host.bufferedAmount = 64 * 1024 * 1024;
    stdin(connection, 1, 0, "held");
    send(connection, { type: "signal", channel: 1, signal: "TERM" });
    expect(host.input()).toHaveLength(0);
    expect(host.frames("channel.signal")).toHaveLength(0);
    host.bufferedAmount = 0;
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(host.input().map((f) => f.metadata.fence.channelId)).toEqual([fence.channelId]);
    expect(host.frames("channel.signal")).toHaveLength(1);
  });

  it("past the lease's end nothing is delivered or opened while the re-read is pending", async () => {
    let clock = 1_000_000;
    manager.dispose();
    manager = createManager({ now: () => clock, check: () => new Promise(() => {}) });
    const { connection, client } = connect(
      bindingFor({ leaseExpiresAt: new Date(1_000_000 + 60_000) }),
    );
    const fence = openPty(connection);
    ready(fence);
    output(fence, 0, "before");
    expect(client.data).toHaveLength(1);
    clock += 61_000;
    output(fence, 1, "after the lease");
    send(connection, { type: "open", channel: 2, kind: "exec", argv: ["true"] });
    await settle();
    expect(client.data).toHaveLength(1);
    expect(host.frames("channel.open")).toHaveLength(1);
  });

  it("a server-side channel exit deferred by an authority change is delivered, then forgotten", async () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager();
    const { connection, client } = connect();
    const fence = openExec(connection);
    verdict = "ok";
    const change = holdChange({ credentialId: "key-1" });
    vi.advanceTimersByTime(CONNECT_LIMITS.openTimeoutMs);
    expect(host.frames("channel.close")).toEqual([
      { type: "channel.close", fence, intent: "expired" },
    ]);
    expect(client.frames("exit")).toEqual([]);
    exit(fence, { intent: "expired" });
    change.settle();
    await vi.advanceTimersByTimeAsync(10);
    expect(client.frames("exit")).toMatchObject([{ channel: 1, intent: "expired" }]);
    expect(connection.channelCount).toBe(0);
    expect(manager.resources().channels).toBe(0);
  });

  it("a channel whose client never acknowledges output closes with backpressure", () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager({ now: () => Date.now() });
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    output(fence, 0, "unacked");
    vi.advanceTimersByTime(CONNECT_LIMITS.ackStallMs - 1);
    expect(host.frames("channel.close")).toEqual([]);
    // Pings answered, acks never: the stall rule applies on the next heartbeat.
    connection.activity();
    vi.advanceTimersByTime(CONNECT_LIMITS.pingIntervalMs);
    expect(host.frames("channel.close")).toEqual([
      { type: "channel.close", fence, intent: "backpressure" },
    ]);
    expect(client.frames("exit")[0]).toMatchObject({ channel: 1, intent: "backpressure" });
    expect(client.frames("end")).toEqual([]);
  });

  it("a node exit whose frame counts differ from what it sent is a violation", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    output(fence, 0, "one");
    exit(fence, { exitCode: 0, frames: { stdout: 2, stderr: 0 } });
    expect(client.frames("exit")).toMatchObject([{ intent: "protocol_violation" }]);
    // Reaped: nothing is sent to a node whose channel already ended.
    expect(host.frames("channel.close")).toEqual([]);
    expect(manager.resources().channels).toBe(0);
    expect(connection.channelCount).toBe(0);

    // Unreaped: the end is upgraded to a kill.
    const second = connect(bindingFor({ keyId: "key-2" }));
    const fence2 = openExec(second.connection, 1);
    ready(fence2, "exec");
    exit(fence2, { exitCode: 0, reaped: false, frames: { stdout: 1, stderr: 0 } });
    expect(second.client.frames("exit")).toMatchObject([{ intent: "protocol_violation" }]);
    expect(host.frames("channel.close")).toEqual([
      { type: "channel.close", fence: fence2, intent: "protocol_violation" },
    ]);
  });
});

describe("connect manager: draining and congestion", () => {
  for (const reaped of [true, false]) {
    it(`output beyond one window drains after a natural exit (reaped: ${reaped})`, () => {
      const { connection, client } = connect();
      const fence = openExec(connection);
      ready(fence, "exec");
      const window = CHANNEL_LIMITS.bulkWindowFrames;
      for (let seq = 0; seq <= window; seq += 1) output(fence, seq, `o${seq}`);
      expect(client.data).toHaveLength(window);
      hostControl({ type: "channel.eof", fence, stream: "stdout", frames: window + 1 });
      hostControl({ type: "channel.eof", fence, stream: "stderr", frames: 0 });
      exit(fence, { exitCode: 0, reaped, frames: { stdout: window + 1, stderr: 0 } });
      expect(client.frames("exit")).toEqual([]);
      send(connection, { type: "ack", channel: 1, stream: "stdout", seq: window - 1 });
      expect(client.data).toHaveLength(window + 1);
      expect(client.frames("exit")).toMatchObject([{ channel: 1, exitCode: 0 }]);
      expect(client.order.slice(-4)).toEqual([`data:stdout:${window}`, "eof", "eof", "exit"]);
    });
  }

  it("a client that stops acking after the node's exit is closed with backpressure", () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager({ now: () => Date.now() });
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    const window = CHANNEL_LIMITS.bulkWindowFrames;
    for (let seq = 0; seq <= window; seq += 1) output(fence, seq, `o${seq}`);
    exit(fence, { exitCode: 0, reaped: false, frames: { stdout: window + 1, stderr: 0 } });
    // The client answers pings (activity) but never acks.
    for (let t = 0; t < CONNECT_LIMITS.ackStallMs + CONNECT_LIMITS.pingIntervalMs; t += 10_000) {
      connection.activity();
      vi.advanceTimersByTime(10_000);
    }
    expect(client.frames("end")).toEqual([]);
    expect(client.frames("exit")).toMatchObject([{ channel: 1, intent: "backpressure" }]);
    // The unsettled end is upgraded to a kill on the node.
    expect(host.frames("channel.close")).toEqual([
      { type: "channel.close", fence, intent: "backpressure" },
    ]);
  });

  it("credit to a node that stops reading is coalesced, and resumes as one ack per stream", async () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    host.bufferedAmount = 16 * 1024 * 1024;
    for (let seq = 0; seq < 5; seq += 1) output(fence, seq, `p${seq}`);
    expect(client.data).toHaveLength(5);
    expect(host.frames("channel.ack")).toEqual([]);
    host.bufferedAmount = 0;
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(host.frames("channel.ack")).toEqual([
      { type: "channel.ack", fence, stream: "stdout", seq: 4 },
    ]);
  });

  it("opens are refused while the host is congested; a host far behind is closed", () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    host.bufferedAmount = 16 * 1024 * 1024;
    send(connection, { type: "open", channel: 2, kind: "exec", argv: ["true"] });
    expect(client.frames("exit")).toMatchObject([
      { channel: 2, error: { code: "rate_limited", message: "host is congested" } },
    ]);
    expect(host.frames("channel.open")).toHaveLength(1);
    host.bufferedAmount = 64 * 1024 * 1024;
    connection.end("revoked");
    expect(closedSockets).toEqual(["Host is not reading channel frames."]);
  });
});

describe("connect manager: byte budgets and held credit", () => {
  it("a backlogged channel never starves another under the byte rate", async () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager({ maxBytesPerSecond: 1000, now: () => Date.now() });
    const { connection, client } = connect();
    const a = openExec(connection, 1);
    ready(a, "exec");
    const b = openExec(connection, 2);
    ready(b, "exec");
    const body = "x".repeat(400);
    for (let seq = 0; seq < 20; seq += 1) output(a, seq, body);
    output(b, 0, body);
    // Both channels move within a few refills, whatever arrived first.
    for (let i = 0; i < 4; i += 1) {
      send(connection, {
        type: "ack",
        channel: 1,
        stream: "stdout",
        seq: client.data.filter((f) => f.channel === 1).length - 1,
      });
      await vi.advanceTimersByTimeAsync(500);
    }
    expect(client.data.filter((f) => f.channel === 2)).toHaveLength(1);
  });

  it("stdin beyond the connection's byte budget is a protocol violation", () => {
    const { connection, client } = connect();
    const body = "s".repeat(CHANNEL_LIMITS.bulkDataMaxBytes);
    for (let channel = 1; channel <= 5; channel += 1) ready(openExec(connection, channel), "exec");
    // Congested (not yet far behind): stdin stays queued on the server.
    host.bufferedAmount = 8 * 1024 * 1024;
    let sent = 0;
    for (let channel = 1; channel <= 5; channel += 1) {
      for (let seq = 0; seq < CHANNEL_LIMITS.bulkWindowFrames; seq += 1) {
        if (client.frames("end").length > 0) break;
        stdin(connection, channel, seq, body);
        sent += 1;
      }
    }
    expect(client.frames("end")[0]).toMatchObject({ intent: "protocol_violation" });
    expect(sent).toBe(CONNECT_LIMITS.unackedInputBytes / CHANNEL_LIMITS.bulkDataMaxBytes + 1);
  });

  it("an intent exit that drops output drops the eofs counting it", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    const window = CHANNEL_LIMITS.bulkWindowFrames;
    for (let seq = 0; seq <= window; seq += 1) output(fence, seq, `o${seq}`);
    hostControl({ type: "channel.eof", fence, stream: "stdout", frames: window + 1 });
    exit(fence, { intent: "revoked", frames: { stdout: window + 1, stderr: 0 } });
    expect(client.frames("eof")).toEqual([]);
    expect(client.frames("exit")).toMatchObject([
      { channel: 1, intent: "revoked", frames: { stdout: window, stderr: 0 } },
    ]);
  });

  it("credit held for a congested node waits while the authority is changing", async () => {
    const { connection } = connect();
    const fence = openPty(connection);
    ready(fence);
    host.bufferedAmount = 16 * 1024 * 1024;
    output(fence, 0, "p");
    const change = holdChange({ credentialId: "key-1" });
    host.bufferedAmount = 0;
    manager.resumeHost(host);
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(host.frames("channel.ack")).toEqual([]);
    change.settle();
    await settle();
    manager.resumeHost(host);
    expect(host.frames("channel.ack")).toEqual([
      { type: "channel.ack", fence, stream: "stdout", seq: 0 },
    ]);
    expect(connection.ended).toBe(false);
  });

  it("credit held for a congested node never flows after the connection ended", async () => {
    const { connection } = connect();
    const fence = openPty(connection);
    ready(fence);
    host.bufferedAmount = 16 * 1024 * 1024;
    output(fence, 0, "p");
    expect(host.frames("channel.ack")).toEqual([]);
    connection.end("revoked");
    host.bufferedAmount = 0;
    manager.resumeHost(host);
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(host.frames("channel.ack")).toEqual([]);
  });
});

describe("connect manager: per-direction byte rates", () => {
  function rated() {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager({ maxBytesPerSecond: 1000, now: () => Date.now() });
    return connect();
  }
  const body = "x".repeat(400);
  const delivered = (client: FakeClient, channel: number) =>
    client.data.filter((frame) => frame.channel === channel).length;

  it("saturated stdin never starves output: each direction has its own rate", async () => {
    const { connection, client } = rated();
    const fence = openExec(connection);
    ready(fence, "exec");
    let outSeq = 0;
    let inSeq = 0;
    for (let t = 0; t < 20; t += 1) {
      // The guest keeps both directions busy; the client acks everything.
      while (outSeq - delivered(client, 1) < 8) output(fence, outSeq++, body);
      const forwarded = host.input().length;
      while (inSeq - forwarded < 8 && inSeq - forwarded >= 0) stdin(connection, 1, inSeq++, body);
      if (forwarded > 0)
        hostControl({ type: "channel.ack", fence, stream: "stdin", seq: forwarded - 1 });
      if (delivered(client, 1) > 0)
        send(connection, {
          type: "ack",
          channel: 1,
          stream: "stdout",
          seq: delivered(client, 1) - 1,
        });
      await vi.advanceTimersByTimeAsync(500);
    }
    // 10 s at 1000 B/s per direction: about 25 frames of 400 B each way.
    expect(delivered(client, 1)).toBeGreaterThanOrEqual(15);
    expect(host.input().length).toBeGreaterThanOrEqual(15);
    expect(client.frames("end")).toEqual([]);
  });

  for (const first of [1, 2]) {
    it(`two backlogged channels share the output rate evenly (channel ${first} queued first)`, async () => {
      const { connection, client } = rated();
      const fences = new Map<number, ChannelFence>();
      for (const channel of [1, 2]) {
        const fence = openExec(connection, channel);
        ready(fence, "exec");
        fences.set(channel, fence);
      }
      const next = new Map([
        [1, 0],
        [2, 0],
      ]);
      const top = (channel: number) => {
        // Keep 8 frames waiting per channel, the favoured one refilled first.
        for (const c of channel === 1 ? [1, 2] : [2, 1])
          while (next.get(c)! - delivered(client, c) < 8) {
            output(fences.get(c)!, next.get(c)!, body);
            next.set(c, next.get(c)! + 1);
          }
      };
      // The first channel's frames may use the initial burst before the other
      // has any queued (work-conserving); fairness is measured from then on.
      top(first);
      const base = [delivered(client, 1), delivered(client, 2)];
      for (let t = 0; t < 40; t += 1) {
        top(first);
        // Paired acks of both channels on every pass.
        for (const channel of [1, 2])
          if (delivered(client, channel) > 0)
            send(connection, {
              type: "ack",
              channel,
              stream: "stdout",
              seq: delivered(client, channel) - 1,
            });
        await vi.advanceTimersByTimeAsync(250);
      }
      const one = delivered(client, 1) - base[0]!;
      const two = delivered(client, 2) - base[1]!;
      expect(one + two).toBeGreaterThanOrEqual(20);
      expect(Math.abs(one - two)).toBeLessThanOrEqual(2);
    });
  }
});

describe("connect manager: stdin backlog", () => {
  it("bulk stdin waits at the high mark while credit and controls still reach the node", () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    host.bufferedAmount = 6 * 1024 * 1024;
    // Per channel order holds (a resize never overtakes earlier stdin), so
    // the resize goes first here.
    send(connection, { type: "resize", channel: 1, rows: 30, cols: 90 });
    stdin(connection, 1, 0, "held");
    output(fence, 0, "out");
    expect(host.input()).toHaveLength(0);
    expect(host.frames("channel.resize")).toHaveLength(1);
    expect(host.frames("channel.ack")).toHaveLength(1);
    expect(client.data).toHaveLength(1);
  });

  it("stdin after the client's own close is dropped, not queued", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    send(connection, { type: "close", channel: 1 });
    stdin(connection, 1, 0, "late");
    expect(host.input()).toHaveLength(0);
    expect(client.frames("end")).toEqual([]);
    expect(host.frames("channel.close").map((f) => f.fence.channelId)).toEqual([fence.channelId]);
  });

  it("three backlogged stdin channels share the input rate evenly", async () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager({ maxBytesPerSecond: 1000, now: () => Date.now() });
    const { connection } = connect();
    const fences = [1, 2, 3].map((channel) => {
      const fence = openExec(connection, channel);
      ready(fence, "exec");
      return fence;
    });
    const body = "i".repeat(400);
    const seqs = [0, 0, 0];
    const forwarded = (i: number) =>
      host.input().filter((f) => f.metadata.fence.channelId === fences[i]!.channelId).length;
    const top = () => {
      for (const i of [0, 1, 2])
        while (seqs[i]! - forwarded(i) < 6) stdin(connection, i + 1, seqs[i]!++, body);
    };
    top();
    const base = [0, 1, 2].map(forwarded);
    const acked = [0, 0, 0];
    for (let t = 0; t < 40; t += 1) {
      top();
      for (const i of [0, 1, 2])
        if (forwarded(i) > acked[i]!) {
          acked[i] = forwarded(i);
          hostControl({
            type: "channel.ack",
            fence: fences[i]!,
            stream: "stdin",
            seq: forwarded(i) - 1,
          });
        }
      await vi.advanceTimersByTimeAsync(250);
    }
    const got = [0, 1, 2].map((i) => forwarded(i) - base[i]!);
    expect(got.reduce((a, b) => a + b, 0)).toBeGreaterThanOrEqual(20);
    expect(Math.max(...got) - Math.min(...got)).toBeLessThanOrEqual(2);
  });
});

describe("connect manager: the one end path and revocation", () => {
  it("end is idempotent: one close per live channel, one end + 4401, nothing after", () => {
    const { connection, client } = connect();
    const a = openPty(connection, 1);
    const b = openExec(connection, 2);
    ready(a);
    ready(b, "exec");
    connection.end("revoked");
    connection.end("shutdown");
    expect(host.frames("channel.close")).toEqual([
      { type: "channel.close", fence: a, intent: "revoked" },
      { type: "channel.close", fence: b, intent: "revoked" },
    ]);
    expect(client.frames("end")).toEqual([{ type: "end", intent: "revoked" }]);
    expect(client.closes).toEqual([{ code: 4401, reason: "end" }]);
    output(a, 0, "late");
    stdin(connection, 2, 0, "late");
    hostControl({ type: "channel.ack", fence: b, stream: "stdin", seq: 0 });
    expect(client.data).toEqual([]);
    expect(host.binary).toEqual([]);
    expect(manager.resources()).toMatchObject({ connections: 0, channels: 2 });
    exit(a, { intent: "revoked", signal: 9 });
    exit(b, { intent: "revoked", signal: 9 });
    expect(manager.resources()).toMatchObject({ channels: 0, timers: 0 });
    expect(client.frames("exit")).toEqual([]);
  });

  it("a key revocation commit ends the connection within the same tick of reads", async () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    verdict = "forbidden";
    const started = Date.now();
    await withAuthorityChange({ ownerId: "owner-1", credentialId: "key-1" }, async () => {});
    await settle();
    expect(client.frames("end")).toEqual([{ type: "end", intent: "revoked" }]);
    expect(host.frames("channel.close")).toEqual([
      { type: "channel.close", fence, intent: "revoked" },
    ]);
    expect(Date.now() - started).toBeLessThan(1000);
    expect(checks).toBe(1);
  });

  it("authority lost between authorization and delivery holds output: zero bytes delivered", async () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    output(fence, 0, "before");
    expect(client.data).toHaveLength(1);
    verdict = "forbidden";
    const change = holdChange({ credentialId: "key-1" });
    output(fence, 1, "secret");
    stdin(connection, 1, 0, "typed");
    await settle();
    // A read the change overlapped decides nothing: everything stays held.
    expect(client.data.map((frame) => frame.body)).toEqual(["before"]);
    expect(host.binary).toEqual([]);
    expect(client.frames("end")).toEqual([]);
    change.settle();
    await settle();
    expect(client.frames("end")).toEqual([{ type: "end", intent: "revoked" }]);
    expect(client.data.map((frame) => frame.body)).toEqual(["before"]);
    expect(host.binary).toEqual([]);
  });

  it("a change that never settles fails closed after a bounded number of raced reads", async () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager();
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    holdChange({ ownerId: "owner-1" });
    output(fence, 0, "held");
    await vi.advanceTimersByTimeAsync(5_000);
    expect(client.data).toEqual([]);
    expect(client.frames("end")).toEqual([{ type: "end", intent: "lifecycle_unconfirmed" }]);
  });

  it("an unrelated authority change only delays delivery", async () => {
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    const change = holdChange({ ownerId: "owner-1" });
    output(fence, 0, "held");
    expect(client.data).toEqual([]);
    change.settle();
    await settle();
    expect(client.data.map((frame) => frame.body)).toEqual(["held"]);
    expect(client.frames("end")).toEqual([]);
  });

  it("re-reads every 15 s with no other trigger and ends with the re-read's intent", async () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager();
    const { connection, client } = connect();
    ready(openPty(connection));
    await vi.advanceTimersByTimeAsync(15_001);
    expect(checks).toBe(1);
    expect(client.frames("end")).toEqual([]);
    verdict = "sandbox_stopped";
    await vi.advanceTimersByTimeAsync(15_000);
    expect(checks).toBe(2);
    expect(client.frames("end")).toEqual([{ type: "end", intent: "sandbox_stopped" }]);
    expect(host.frames("channel.close")[0]).toMatchObject({ intent: "sandbox_stopped" });
  });

  it("re-reads at the key's expiry (expiry fires no event)", async () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager({ revalidateMs: 3_600_000 });
    const { client } = connect(bindingFor({ keyExpiresAt: new Date(Date.now() + 2_000) }));
    verdict = "forbidden";
    await vi.advanceTimersByTimeAsync(1_000);
    expect(client.frames("end")).toEqual([]);
    await vi.advanceTimersByTimeAsync(1_500);
    expect(client.frames("end")).toEqual([{ type: "end", intent: "revoked" }]);
  });

  it("a lifecycle change between the pre-upgrade read and the open re-reads before hello", async () => {
    const quiet = manager.lifecycleMark();
    const first = manager.reserve(bindingFor(), quiet);
    if (!first.ok) throw new Error(first.reason);
    const live = new FakeClient();
    manager.attach(first.reservation, principal, retainedFor(bindingFor()) as never).opened(live);
    expect(live.frames("hello")).toHaveLength(1);

    const mark = manager.lifecycleMark();
    notifySandboxTerminalLifecycle({ sandboxIds: new Set(["sbx-other"]) });
    await settle();
    verdict = "sandbox_stopped";
    const reserved = manager.reserve(bindingFor({ keyId: "key-2" }), mark);
    if (!reserved.ok) throw new Error(reserved.reason);
    const client = new FakeClient();
    manager
      .attach(reserved.reservation, principal, retainedFor(bindingFor({ keyId: "key-2" })) as never)
      .opened(client);
    expect(client.frames("hello")).toEqual([]);
    await settle();
    expect(client.frames("hello")).toEqual([]);
    expect(client.frames("end")[0]).toMatchObject({ intent: "sandbox_stopped" });
  });

  it("a lifecycle notification re-reads; other subscribers keep theirs (additive)", async () => {
    const heard: unknown[] = [];
    const off = subscribeSandboxTerminalLifecycle((change) => heard.push(change));
    const { client } = connect();
    verdict = "sandbox_destroyed";
    notifySandboxTerminalLifecycle({ sandboxIds: new Set(["sbx-other"]) });
    await settle();
    expect(client.frames("end")).toEqual([]);
    notifySandboxTerminalLifecycle({ sandboxIds: new Set(["sbx-1"]) });
    await settle();
    expect(client.frames("end")).toEqual([{ type: "end", intent: "sandbox_destroyed" }]);
    // The connect manager unsubscribed with its last connection; the other did not.
    expect(manager.resources().subscribed).toBe(0);
    notifySandboxTerminalLifecycle("all");
    expect(heard).toHaveLength(3);
    off();
  });

  it("a re-read past its 5 s deadline fails closed", async () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager({
      check: () => new Promise<never>(() => {}),
    });
    const { connection, client } = connect();
    const pending = connection.revalidate();
    await vi.advanceTimersByTimeAsync(5_001);
    await pending;
    expect(client.frames("end")).toEqual([{ type: "end", intent: "lifecycle_unconfirmed" }]);
  });

  it("a silent client is detached after 60 s; an answering one is pinged", async () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager({ revalidateMs: 3_600_000 });
    const { connection, client } = connect();
    await vi.advanceTimersByTimeAsync(CONNECT_LIMITS.pingIntervalMs);
    expect(client.pings).toBe(1);
    connection.activity();
    await vi.advanceTimersByTimeAsync(CONNECT_LIMITS.pingIntervalMs * 2);
    expect(client.frames("end")).toEqual([]);
    await vi.advanceTimersByTimeAsync(CONNECT_LIMITS.pingIntervalMs * 2);
    expect(client.frames("end")).toEqual([
      { type: "end", intent: "detached", error: { code: "timeout", message: "client silent" } },
    ]);
  });

  it("a connection never outlives its maximum lifetime, however active", async () => {
    vi.useFakeTimers();
    manager.dispose();
    manager = createManager({ revalidateMs: 3_600_000, maxLifetimeMs: 120_000 });
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    for (let elapsed = 0; elapsed < 110_000; elapsed += 10_000) {
      connection.activity();
      await vi.advanceTimersByTimeAsync(10_000);
    }
    expect(client.frames("end")).toEqual([]);
    connection.activity();
    await vi.advanceTimersByTimeAsync(10_001);
    expect(client.frames("end")).toEqual([
      {
        type: "end",
        intent: "expired",
        error: { code: "timeout", message: "connection lifetime reached" },
      },
    ]);
    expect(host.frames("channel.close")).toEqual([
      { type: "channel.close", fence, intent: "expired" },
    ]);
  });

  it("the host socket's end ends its connections and settles every channel", () => {
    const { connection, client } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    linkError = { code: "disconnected", message: "host is not connected" };
    manager.removeHostSocket(host, "host-1");
    expect(client.frames("end")[0]).toMatchObject({ intent: "host_disconnected" });
    expect(manager.resources()).toMatchObject({ connections: 0, channels: 0, hostSockets: 0 });
  });

  it("a stale host ticket holds stdin until the host link is refreshed", () => {
    const { connection } = connect();
    const fence = openExec(connection);
    ready(fence, "exec");
    linkAuthorized = false;
    stdin(connection, 1, 0, "a");
    send(connection, { type: "signal", channel: 1, signal: "INT" });
    expect(host.binary).toEqual([]);
    expect(host.frames("channel.signal")).toEqual([]);
    linkAuthorized = true;
    manager.resumeHost(host);
    expect(host.input().map((frame) => frame.metadata.seq)).toEqual([0]);
    expect(host.frames("channel.signal")).toEqual([
      { type: "channel.signal", fence, signal: "INT" },
    ]);
  });

  it("shutdown ends every connection and refuses new ones", () => {
    const { client } = connect();
    manager.dispose();
    expect(client.frames("end")).toEqual([{ type: "end", intent: "shutdown" }]);
    expect(manager.reserve(bindingFor())).toEqual({ ok: false, reason: "shutdown" });
  });

  it("a connection whose host no longer matches its binding ends before hello", () => {
    linkError = { code: "unsupported_capability", message: "no channels" };
    const { client } = connect();
    expect(client.frames("hello")).toEqual([]);
    expect(client.frames("end")[0]).toMatchObject({ intent: "host_disconnected" });
    expect(manager.hostAvailability(bindingFor())).toBe("outdated");
    linkError = null;
    expect(manager.hostAvailability(bindingFor({ epoch: 6 }))).toBe("unavailable");
    expect(manager.hostAvailability(bindingFor())).toBe("ok");
  });
});

describe("connect manager: §10 audit hooks", () => {
  let clock = 0;
  function auditedManager() {
    const audit = { opened: vi.fn(), closed: vi.fn() };
    clock = 1_700_000_000_000;
    manager.dispose();
    manager = createManager({ audit, now: () => clock });
    return audit;
  }

  it("tells the audit after hello and once at the end, with channel counts and data bytes only", () => {
    const audit = auditedManager();
    const { connection, client } = connect();
    expect(client.text[0]?.type).toBe("hello");
    expect(audit.opened).toHaveBeenCalledTimes(1);
    expect(audit.opened).toHaveBeenCalledWith({
      connectionId: connection.connectionId,
      ownerId: "owner-1",
      keyId: "key-1",
      sandboxId: "sbx-1",
      hostId: "host-1",
      // The relay's instants (hooks), never the write's.
      openedAt: 1_700_000_000_000,
    });
    const shell = openPty(connection, 1);
    ready(shell);
    const command = openExec(connection, 2);
    ready(command, "exec");
    output(shell, 0, "hello");
    output(command, 0, "abc", "stderr");
    stdin(connection, 2, 0, "1234567");
    expect(host.input().map((frame) => frame.metadata.stream)).toEqual(["stdin"]);
    expect(audit.closed).not.toHaveBeenCalled();
    clock += 42_000;
    connection.end("client");
    connection.end("client");
    expect(audit.closed).toHaveBeenCalledTimes(1);
    expect(audit.closed).toHaveBeenCalledWith({
      connectionId: connection.connectionId,
      ownerId: "owner-1",
      keyId: "key-1",
      sandboxId: "sbx-1",
      hostId: "host-1",
      openedAt: 1_700_000_000_000,
      closedAt: 1_700_000_042_000,
      intent: "client",
      ptyChannels: 1,
      execChannels: 1,
      relayChannels: 0,
      forwardedPorts: [],
      bytesIn: 7,
      bytesOut: 8,
    });
    // Ids and counters only: no argv, env, cwd or content reaches the audit.
    // The random hex connectionId is replaced first: it can contain "abc" by chance.
    const text = JSON.stringify([audit.opened.mock.calls, audit.closed.mock.calls], (key, value) =>
      key === "connectionId" ? "<id>" : value,
    );
    for (const secret of ["cat", "hello", "abc", "1234567", "xterm"])
      expect(text).not.toContain(secret);
  });

  it("counts relays apart from exec and keeps the first 16 distinct tcp ports, never a unix path", () => {
    const audit = auditedManager();
    const { connection } = connect();
    openPty(connection, 1);
    openExec(connection, 2);
    send(connection, { type: "open", channel: 3, kind: "unix", path: "/run/secret-app.sock" });
    // 8080 twice, then 20 more distinct ports: 22 tcp relays, 17 distinct.
    const ports = [8080, 8080, ...Array.from({ length: 20 }, (_, index) => 9000 + index)];
    ports.forEach((port, index) => {
      send(connection, { type: "open", channel: 10 + index, kind: "tcp", port });
    });
    expect(host.frames("channel.open")).toHaveLength(3 + ports.length);
    connection.end("client");
    expect(audit.closed).toHaveBeenCalledTimes(1);
    expect(audit.closed.mock.calls[0]?.[0]).toMatchObject({
      ptyChannels: 1,
      execChannels: 1,
      relayChannels: 23,
      forwardedPorts: [8080, ...Array.from({ length: 15 }, (_, index) => 9000 + index)],
    });
    const text = JSON.stringify(audit.closed.mock.calls);
    expect(text).not.toContain("secret-app");
    expect(text).not.toContain("/run");
  });

  it("a connection that never went live is not audited", async () => {
    const audit = auditedManager();
    verdict = "forbidden";
    const reserved = manager.reserve(bindingFor());
    if (!reserved.ok) throw new Error(reserved.reason);
    const connection = manager.attach(reserved.reservation, principal, {
      ...retainedFor(bindingFor()),
      current: () => false,
    } as never);
    connection.opened(new FakeClient());
    await settle();
    expect(connection.ended).toBe(true);
    expect(audit.opened).not.toHaveBeenCalled();
    expect(audit.closed).not.toHaveBeenCalled();
  });

  it("a revocation's end intent reaches the audit, and a throwing audit never breaks the relay", async () => {
    const audit = {
      opened: vi.fn(() => {
        throw new Error("audit down");
      }),
      closed: vi.fn(() => {
        throw new Error("audit down");
      }),
    };
    manager.dispose();
    manager = createManager({ audit });
    const { connection, client } = connect();
    const fence = openPty(connection);
    ready(fence);
    output(fence, 0, "ok");
    expect(client.data).toHaveLength(1);
    verdict = "forbidden";
    await withAuthorityChange({ ownerId: "owner-1", credentialId: "key-1" }, async () => {});
    await settle();
    expect(client.frames("end")).toEqual([{ type: "end", intent: "revoked" }]);
    expect(audit.closed).toHaveBeenCalledWith(expect.objectContaining({ intent: "revoked" }));
    expect(manager.resources().connections).toBe(0);
  });
});

describe("connect manager: tcp and unix relay channels", () => {
  function openTcp(connection: ReturnType<typeof connect>["connection"], channel = 1, port = 5432) {
    send(connection, { type: "open", channel, kind: "tcp", port });
    return host.frames("channel.open").at(-1)!.fence as ChannelFence;
  }

  it("forwards only the guest target: a port or a path, never a host or process field", () => {
    const { connection } = connect();
    const fence = openTcp(connection, 1, 15432);
    expect(host.frames("channel.open")[0]).toEqual({
      type: "channel.open",
      fence,
      kind: "tcp",
      login: false,
      port: 15432,
    });
    send(connection, { type: "open", channel: 2, kind: "unix", path: "/run/app.sock" });
    expect(host.frames("channel.open")[1]).toEqual({
      type: "channel.open",
      fence: expect.objectContaining({ connectionId: connection.connectionId }),
      kind: "unix",
      login: false,
      path: "/run/app.sock",
    });
  });

  it.each([
    { type: "open", channel: 1, kind: "tcp", port: 22, host: "10.0.0.1" },
    { type: "open", channel: 1, kind: "tcp", port: 0 },
    { type: "open", channel: 1, kind: "tcp", port: 65_536 },
    { type: "open", channel: 1, kind: "tcp" },
    { type: "open", channel: 1, kind: "tcp", port: 22, argv: ["nc"] },
    { type: "open", channel: 1, kind: "unix", path: "relative.sock" },
    { type: "open", channel: 1, kind: "unix", path: `/${"a".repeat(107)}` },
    { type: "open", channel: 1, kind: "exec", argv: ["cat"], port: 22 },
  ])("refuses the malformed relay open %j as a protocol violation", (frame) => {
    const { connection, client } = connect();
    send(connection, frame);
    expect(host.frames("channel.open")).toEqual([]);
    expect(client.frames("end")).toEqual([
      expect.objectContaining({ type: "end", intent: "protocol_violation" }),
    ]);
  });

  it("a node that did not offer the kind never sees the open (an older daemon)", () => {
    linkKinds = ["pty", "exec"];
    const { connection, client } = connect();
    send(connection, { type: "open", channel: 1, kind: "tcp", port: 5432 });
    expect(host.frames("channel.open")).toEqual([]);
    expect(client.frames("exit")).toEqual([
      {
        type: "exit",
        channel: 1,
        error: { code: "unsupported_capability", message: expect.stringContaining("tcp") },
        frames: { stdout: 0, stderr: 0 },
      },
    ]);
    // The connection stays usable for the kinds the node has.
    openExec(connection, 2);
    expect(host.frames("channel.open")).toHaveLength(1);
  });

  it("relays both half-closes and passes a refusal through as connection_refused", () => {
    const { connection, client } = connect();
    const fence = openTcp(connection);
    ready(fence, "exec");
    expect(client.frames("ready")).toEqual([{ type: "ready", channel: 1 }]);
    stdin(connection, 1, 0, "GET /");
    send(connection, { type: "eof", channel: 1, stream: "stdin", frames: 1 });
    expect(host.frames("channel.eof")).toEqual([
      { type: "channel.eof", fence, stream: "stdin", frames: 1 },
    ]);
    output(fence, 0, "200 OK");
    hostControl({ type: "channel.eof", fence, stream: "stdout", frames: 1 });
    exit(fence, { exitCode: 0, frames: { stdout: 1, stderr: 0 } });
    expect(client.order).toEqual(["hello", "ready", "data:stdout:0", "eof", "exit"]);
    const refused = openTcp(connection, 2, 6000);
    exit(refused, {
      error: {
        code: "connection_refused",
        message: "nothing in the sandbox accepted the connection",
        sandboxId: "sbx-1",
      },
    });
    expect(client.frames("exit").at(-1)).toEqual({
      type: "exit",
      channel: 2,
      error: {
        code: "connection_refused",
        message: "nothing in the sandbox accepted the connection",
      },
      frames: { stdout: 0, stderr: 0 },
    });
  });

  it("stderr on a relay is a node violation; signals and resizes are refused notices", () => {
    const { connection, client } = connect();
    const fence = openTcp(connection);
    ready(fence, "exec");
    send(connection, { type: "signal", channel: 1, signal: "TERM" });
    send(connection, { type: "resize", channel: 1, rows: 10, cols: 10 });
    expect(client.frames("error")).toEqual([
      { type: "error", channel: 1, code: "unsupported_signal" },
      { type: "error", channel: 1, code: "state_conflict" },
    ]);
    expect(host.frames("channel.signal")).toEqual([]);
    for (let i = 0; i < CHANNEL_LIMITS.fenceViolationLimit - 1; i += 1)
      output(fence, i, "x", "stderr");
    hostControl({ type: "channel.eof", fence, stream: "stderr", frames: 0 });
    expect(client.data).toEqual([]);
    expect(client.frames("exit")).toEqual([
      expect.objectContaining({ channel: 1, intent: "protocol_violation" }),
    ]);
    expect(host.frames("channel.close")).toEqual([
      { type: "channel.close", fence, intent: "protocol_violation" },
    ]);
  });

  it("a slow client holds relay credit: at most one window queued, the node acked only as frames leave", () => {
    const { connection, client } = connect();
    const fence = openTcp(connection);
    ready(fence, "exec");
    const window = CHANNEL_LIMITS.bulkWindowFrames;
    for (let seq = 0; seq < window; seq += 1) output(fence, seq, `f${seq}`);
    // The client's own window is full: nothing more leaves until it acks.
    expect(client.data).toHaveLength(window);
    expect(host.frames("channel.ack").at(-1)).toEqual({
      type: "channel.ack",
      fence,
      stream: "stdout",
      seq: window - 1,
    });
    for (let seq = window; seq < 2 * window; seq += 1) output(fence, seq, `f${seq}`);
    expect(client.data).toHaveLength(window);
    expect(host.frames("channel.ack").at(-1)?.seq).toBe(window - 1);
    // Beyond the second window the node broke its credit.
    output(fence, 2 * window, "over");
    expect(client.frames("exit")).toEqual([
      expect.objectContaining({ channel: 1, intent: "protocol_violation" }),
    ]);
  });
});

describe("connect manager: shared budgets keep a reserve per channel", () => {
  it("channels whose client stopped reading never freeze another channel's output", async () => {
    const { connection, client } = connect();
    await settle();
    const big = "x".repeat(CHANNEL_LIMITS.bulkDataMaxBytes);
    // Four channels each hold a full unacked window: the 4 MiB budget.
    for (let channel = 1; channel <= 4; channel += 1) {
      const fence = openExec(connection, channel);
      ready(fence, "exec");
      for (let seq = 0; seq < CHANNEL_LIMITS.bulkWindowFrames; seq += 1) output(fence, seq, big);
    }
    await settle();
    expect(client.data).toHaveLength(4 * CHANNEL_LIMITS.bulkWindowFrames);
    const stalled = client.data.length;
    // A fifth channel still moves, one frame per ack, and nothing else does.
    const fence = openExec(connection, 5);
    ready(fence, "exec");
    for (let seq = 0; seq < 3; seq += 1) output(fence, seq, big);
    await settle();
    for (let seq = 0; seq < 3; seq += 1) {
      const fifth = client.data.filter((frame) => frame.channel === 5);
      expect(fifth.map((frame) => frame.seq)).toEqual([...Array(seq + 1).keys()]);
      send(connection, { type: "ack", channel: 5, stream: "stdout", seq });
      await settle();
    }
    expect(client.data).toHaveLength(stalled + 3);
    expect(client.frames("end")).toEqual([]);
  });
});
