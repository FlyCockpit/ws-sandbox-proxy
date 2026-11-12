vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import {
  FakeLocks,
  FakeResize,
  FakeTerminalView,
  FakeWebSocket,
  FakeWebSocketCtor,
  fakeSession,
  fakeTerminalId,
  fakeTicket,
  flush,
} from "@/test/terminal-fakes";

import {
  PASTE_MAX_BYTES,
  PASTE_SCAN_MAX_CHARS,
  type PasteOutcome,
  resumeOffsets,
  stripPasteMarkers,
  TerminalClient,
  type TerminalClientOptions,
  type TerminalSnapshot,
} from "./terminal-client";

type CreateSession = TerminalClientOptions["createSession"];

/**
 * The terminal attachment against a scripted socket (the backend mock) and an
 * xterm stand-in: explicit attach, the ticket's path to the socket, ready,
 * input, resize clamping, detach, CloseIntent classification, the
 * no-auto-retry rules for 1006 and 4401, and backpressure.
 */

const SANDBOX = "sbx_1";

function setup(
  options: {
    createSession?: Mock<CreateSession>;
    serverUrl?: string;
    onCreateError?: (error: unknown) => void;
    host?: boolean;
    resumable?: boolean;
    resumeLocks?: TerminalClientOptions["resumeLocks"];
    resumeAttemptTimeoutMs?: number;
    random?: () => number;
    idPrefix?: string;
  } = {},
) {
  let minted = 0;
  const ownLocks = new FakeLocks();
  const createSession =
    options.createSession ??
    vi.fn<CreateSession>(async () => {
      minted += 1;
      return fakeSession(SANDBOX, fakeTicket(minted));
    });
  const resize = new FakeResize();
  const snapshots: TerminalSnapshot[] = [];
  // Per-test page lifecycle: no listener leaks onto the shared jsdom window.
  const page = new EventTarget();
  const pasteOutcomes: PasteOutcome[] = [];
  let seq = 0;
  const client = new TerminalClient({
    sandboxId: SANDBOX,
    ...(options.host
      ? { terminalPath: "/api/dashboard/hosts/host-1/terminal/ws", retryRefusedUpgrade: false }
      : {}),
    serverUrl: options.serverUrl ?? "https://app.example.test",
    container: document.createElement("div"),
    createSession,
    loadView: async () => () => new FakeTerminalView(),
    onChange: (snapshot) => snapshots.push(snapshot),
    onCreateError: options.onCreateError,
    WebSocket: FakeWebSocketCtor,
    observeResize: resize.observe,
    requestId: () => {
      seq += 1;
      return `${options.idPrefix ?? ""}req-${seq}`;
    },
    resizeDebounceMs: 10,
    pageLifecycle: page,
    onPaste: (outcome) => pasteOutcomes.push(outcome),
    ...(options.resumable
      ? {
          resumable: true,
          // An uncontended lock per client unless a test shares one (or none).
          resumeLocks: options.resumeLocks ?? (() => ownLocks),
          ...(options.resumeAttemptTimeoutMs === undefined
            ? {}
            : { resumeAttemptTimeoutMs: options.resumeAttemptTimeoutMs }),
          random: options.random ?? (() => 0),
        }
      : {}),
  });
  return {
    client,
    createSession,
    page,
    pasteOutcomes,
    resize,
    snapshots,
    status: () => client.state.status,
    notice: () => client.state.notice,
  };
}

async function attached() {
  const harness = setup();
  await harness.client.start();
  const socket = FakeWebSocket.last();
  socket.serverOpen();
  socket.serverText({ type: "ready", rows: 30, cols: 100 });
  return { ...harness, socket, view: FakeTerminalView.last() };
}

beforeEach(() => {
  FakeWebSocket.reset();
  FakeTerminalView.reset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("attach", () => {
  it("does nothing until start, then mints one ticket and offers it only as a subprotocol", async () => {
    const { client, createSession, status } = setup();
    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(createSession).not.toHaveBeenCalled();
    expect(status()).toBe("idle");

    await client.start();
    expect(createSession).toHaveBeenCalledTimes(1);
    expect(createSession).toHaveBeenCalledWith({ sandboxId: SANDBOX, rows: 30, cols: 100 });
    const socket = FakeWebSocket.last();
    expect(socket.url).toBe(
      `wss://app.example.test/api/dashboard/sandboxes/${SANDBOX}/terminal/ws`,
    );
    expect(socket.url).not.toContain(fakeTicket(1));
    expect(socket.protocols).toEqual(["wssp.terminal.v1", `wssp.terminal.ticket.${fakeTicket(1)}`]);
    expect(socket.binaryType).toBe("arraybuffer");
    expect(status()).toBe("connecting");

    socket.serverOpen();
    expect(status()).toBe("verifying");
    socket.serverText({ type: "ready", rows: 30, cols: 100 });
    expect(status()).toBe("attached");
    expect(client.state.size).toEqual({ rows: 30, cols: 100 });
    expect(FakeTerminalView.last().focused).toBeGreaterThan(0);
  });

  it("keeps the ticket out of the client's own state", async () => {
    const { client, snapshots } = await attached();
    expect(JSON.stringify(snapshots)).not.toContain(fakeTicket(1));
    expect(JSON.stringify(client.state)).not.toContain(fakeTicket(1));
    // No field of the client retains the session response. (The socket is
    // excluded: the fake records what it was offered; a browser WebSocket
    // exposes only the selected `protocol`.)
    const fields = Object.entries(client).filter(([key]) => key !== "socket");
    expect(JSON.stringify(fields)).not.toContain(fakeTicket(1));
  });

  it("refuses a plain-HTTP server that is not loopback, before minting a ticket", async () => {
    const { client, createSession, notice } = setup({ serverUrl: "http://app.example.test" });
    await client.start();
    expect(createSession).not.toHaveBeenCalled();
    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(notice()).toEqual({ kind: "insecure" });
  });

  it("drops a ticket minted after the owner detached, without connecting", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const createSession = vi.fn<CreateSession>(async () => {
      await gate;
      return fakeSession(SANDBOX, fakeTicket(1));
    });
    const { client, notice } = setup({ createSession });
    const started = client.start();
    await flush();
    client.detach();
    release();
    await started;
    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(notice()).toEqual({ kind: "client" });
  });

  it("writes output only once ready, and never stores it outside the view", async () => {
    const { socket, view, snapshots } = await attached();
    socket.serverBinary("hello\r\n");
    expect(view.written).toEqual(["hello\r\n"]);
    expect(JSON.stringify(snapshots)).not.toContain("hello");
  });

  it("sends input as binary frames, split at 16 KiB", async () => {
    const { socket, view } = await attached();
    view.type("ls\r");
    expect(new TextDecoder().decode(socket.sentBinary[0])).toBe("ls\r");
    view.type("a".repeat(16 * 1024 + 5));
    expect(socket.sentBinary.slice(1).map((frame) => frame.byteLength)).toEqual([16 * 1024, 5]);
    view.typeBinary("\x1b[M\xff");
    expect([...(socket.sentBinary.at(-1) ?? [])]).toEqual([0x1b, 0x5b, 0x4d, 0xff]);
  });

  it("does not send input before the PTY is ready", async () => {
    const { client } = setup();
    await client.start();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    FakeTerminalView.last().type("early");
    expect(socket.sentBinary).toHaveLength(0);
  });

  it("surfaces a refused input as a passing warning, not an end", async () => {
    const { socket, client } = await attached();
    socket.serverText({ type: "error", code: "rate_limited" });
    expect(client.state.warning).toBe("inputThrottled");
    expect(client.state.status).toBe("attached");
  });
});

describe("resize", () => {
  it("opens with a clamped size and sends only clamped, changed sizes once ready", async () => {
    vi.useFakeTimers();
    const harness = setup();
    await harness.client.start();
    const view = FakeTerminalView.last();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100 });

    view.nextFit = { rows: 4000, cols: 99_999 };
    harness.resize.fire();
    await vi.advanceTimersByTimeAsync(20);
    view.nextFit = { rows: 0, cols: -3 };
    harness.resize.fire();
    await vi.advanceTimersByTimeAsync(20);
    view.nextFit = { rows: 40.7, cols: 120.2 };
    harness.resize.fire();
    await vi.advanceTimersByTimeAsync(20);
    // Unchanged: nothing sent.
    harness.resize.fire();
    await vi.advanceTimersByTimeAsync(20);

    expect(socket.sentText).toEqual([
      { type: "resize", requestId: "req-1", rows: 512, cols: 1024 },
      { type: "resize", requestId: "req-2", rows: 1, cols: 1 },
      { type: "resize", requestId: "req-3", rows: 40, cols: 120 },
    ]);
  });

  it("never puts an unmeasurable or non-finite size on the wire", async () => {
    vi.useFakeTimers();
    const harness = setup();
    await harness.client.start();
    const view = FakeTerminalView.last();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100 });
    for (const next of [
      null,
      { rows: Number.NaN, cols: 80 },
      { rows: 24, cols: Number.POSITIVE_INFINITY },
    ]) {
      view.nextFit = next;
      harness.resize.fire();
      await vi.advanceTimersByTimeAsync(20);
    }
    expect(socket.sentText).toEqual([]);
  });

  it("clamps the size it asks createSession for", async () => {
    const harness = setup();
    const view = new FakeTerminalView();
    view.nextFit = { rows: 900, cols: 5000 };
    const client = new TerminalClient({
      sandboxId: SANDBOX,
      serverUrl: "https://app.example.test",
      container: document.createElement("div"),
      createSession: harness.createSession,
      loadView: async () => () => view,
      onChange: () => {},
      WebSocket: FakeWebSocketCtor,
      observeResize: harness.resize.observe,
    });
    await client.start();
    expect(harness.createSession).toHaveBeenCalledWith({
      sandboxId: SANDBOX,
      rows: 512,
      cols: 1024,
    });
  });

  it("C54-CO-3: a refused resize shows no input warning and is re-sent on the next ready", async () => {
    vi.useFakeTimers();
    const harness = setup();
    await harness.client.start();
    const view = FakeTerminalView.last();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100 });
    view.nextFit = { rows: 40, cols: 120 };
    harness.resize.fire();
    await vi.advanceTimersByTimeAsync(20);
    view.nextFit = { rows: 50, cols: 140 };
    harness.resize.fire();
    await vi.advanceTimersByTimeAsync(20);
    expect(socket.sentText).toEqual([
      { type: "resize", requestId: "req-1", rows: 40, cols: 120 },
      { type: "resize", requestId: "req-2", rows: 50, cols: 140 },
    ]);
    // The server refuses the second (too many pending): not an input problem.
    socket.serverText({ type: "error", code: "rate_limited", requestId: "req-2" });
    expect(harness.client.state.warning).toBeNull();
    expect(harness.client.state.status).toBe("attached");
    // The first is answered: the size the container has now is sent again.
    socket.serverText({ type: "ready", rows: 40, cols: 120 });
    expect(socket.sentText.at(-1)).toEqual({
      type: "resize",
      requestId: "req-3",
      rows: 50,
      cols: 140,
    });
    socket.serverText({ type: "ready", rows: 50, cols: 140 });
    expect(harness.client.state.size).toEqual({ rows: 50, cols: 140 });
    // Settled: no further resize, and an unrelated (input) error still warns.
    expect(socket.sentText).toHaveLength(3);
    socket.serverText({ type: "error", code: "rate_limited" });
    expect(harness.client.state.warning).toBe("inputThrottled");
  });

  it("a refused resize is never retried without a server ready (no self-clocked loop)", async () => {
    vi.useFakeTimers();
    const harness = setup();
    await harness.client.start();
    const view = FakeTerminalView.last();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100 });
    view.nextFit = { rows: 40, cols: 120 };
    harness.resize.fire();
    await vi.advanceTimersByTimeAsync(20);
    expect(socket.sentText).toHaveLength(1);
    const { requestId } = socket.sentText[0] as { requestId: string };
    socket.serverText({ type: "error", code: "rate_limited", requestId });
    // No ready ever arrives: nothing is re-sent on a timer.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(socket.sentText).toHaveLength(1);
    expect(harness.client.state.warning).toBeNull();
    // An error echoing an id the client never sent is not a resize refusal.
    socket.serverText({ type: "error", code: "rate_limited", requestId: "req-unknown" });
    expect(harness.client.state.warning).toBe("inputThrottled");
    // The same refused id echoed twice: the second is an ordinary warning.
    socket.serverText({ type: "error", code: "state_conflict", requestId });
    expect(harness.client.state.warning).not.toBeNull();
    // The container fires again at the refused size: it is sent again.
    harness.resize.fire();
    await vi.advanceTimersByTimeAsync(20);
    expect(socket.sentText.at(-1)).toMatchObject({ type: "resize", rows: 40, cols: 120 });
    expect(socket.sentText).toHaveLength(2);
  });

  it("stripPasteMarkers equals remove-until-fixpoint over ESC and C1 alphabets", () => {
    const markers = ["\u001b[200~", "\u001b[201~", "\u009b200~", "\u009b201~"];
    const reference = (text: string) => {
      let current = text;
      for (;;) {
        let next = current;
        for (const marker of markers) next = next.split(marker).join("");
        if (next === current) return current;
        current = next;
      }
    };
    const alphabet = ["\u001b", "[", "2", "0", "1", "~", "\u009b", "a", "\u00c2"];
    let seed = 0x9e3779b9;
    const rand = () => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      return (seed >>> 0) / 0x100000000;
    };
    for (let round = 0; round < 50_000; round += 1) {
      let text = "";
      const length = Math.floor(rand() * 24);
      for (let i = 0; i < length; i += 1) text += alphabet[Math.floor(rand() * alphabet.length)];
      const stripped = stripPasteMarkers(text);
      expect(stripped).toBe(reference(text));
      expect(markers.some((marker) => stripped.includes(marker))).toBe(false);
    }
  });

  it("does not send resizes before ready", async () => {
    vi.useFakeTimers();
    const harness = setup();
    await harness.client.start();
    const view = FakeTerminalView.last();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    view.nextFit = { rows: 10, cols: 10 };
    harness.resize.fire();
    await vi.advanceTimersByTimeAsync(20);
    expect(socket.sentText).toEqual([]);
  });
});

describe("detach and close", () => {
  it("detach sends CloseIntent, closes the socket and releases every listener", async () => {
    const { client, socket, view, resize } = await attached();
    client.detach();
    expect(socket.sentText).toEqual([{ type: "close", requestId: "req-1" }]);
    expect(socket.closedByClient).toEqual({ code: 1000 });
    expect(socket.sessionClosed).toBe(true);
    expect(socket.listenerCount()).toBe(0);
    expect(view.listenerCount()).toBe(0);
    expect(resize.callbacks.size).toBe(0);
    expect(client.state.status).toBe("ended");
    expect(client.state.notice).toEqual({ kind: "client" });
    // Typing after the end reaches nothing.
    view.type("x");
    expect(socket.sentBinary).toHaveLength(0);
    await flush();
    expect(FakeWebSocket.live()).toHaveLength(0);
  });

  it("dispose behaves as detach and disposes the view", async () => {
    const { client, socket, view } = await attached();
    client.dispose();
    expect(socket.sentText).toEqual([{ type: "close", requestId: "req-1" }]);
    expect(socket.closedByClient).toEqual({ code: 1000 });
    expect(view.disposed).toBe(true);
  });

  it.each([
    ["revoked", "revoked"],
    ["replaced", "replaced"],
    ["backpressure", "backpressure"],
    ["superseded", "superseded"],
    ["sandbox_stopped", "sandboxStopped"],
    ["sandbox_destroyed", "sandboxDestroyed"],
    ["expired", "expired"],
    ["lifecycle_unconfirmed", "lifecycleUnconfirmed"],
    ["host_disconnected", "hostDisconnected"],
    ["shutdown", "shutdown"],
    ["detached", "detached"],
    ["protocol_violation", "protocolViolation"],
  ])("classifies CloseIntent %s by its intent", async (intent, kind) => {
    const { client, socket } = await attached();
    socket.serverCloseIntent({ intent }, "misleading reason");
    expect(client.state.notice).toEqual({ kind });
  });

  it("tells an unanswered open from an expired lease: both close with intent expired", async () => {
    const lease = await attached();
    lease.socket.serverCloseIntent({ intent: "expired" });
    expect(lease.client.state.notice).toEqual({ kind: "expired" });

    const open = setup();
    await open.client.start();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverCloseIntent({
      intent: "expired",
      error: { code: "timeout", message: "terminal open was not answered in time" },
    });
    expect(open.client.state.notice).toEqual({ kind: "openTimedOut" });
  });

  it("classifies by the frame, never by the close reason string (C53-CO-5)", async () => {
    const first = await attached();
    first.socket.serverCloseIntent({ intent: "replaced" }, "revoked");
    expect(first.client.state.notice).toEqual({ kind: "replaced" });

    const second = await attached();
    // A 4401 whose reason names an intent, but no CloseIntent frame arrived.
    second.socket.serverClose(4401, "sandbox_stopped");
    expect(second.client.state.notice).toEqual({ kind: "ended" });
  });

  it("explains a pre-C52 sandbox without a guest identity (C52-CO-5)", async () => {
    const { client } = setup();
    await client.start();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverCloseIntent({
      error: {
        code: "unsupported_capability",
        message: "sandbox has no recorded terminal identity",
      },
    });
    expect(client.state.notice).toEqual({
      kind: "noTerminalIdentity",
      code: "unsupported_capability",
    });
  });

  it("reports the shell's exit code", async () => {
    const { client, socket } = await attached();
    socket.serverCloseIntent({ exitCode: 3 });
    expect(client.state.notice).toEqual({ kind: "exited", exitCode: 3 });
  });

  it("a 4401 is final: no new ticket and no new socket, however long we wait", async () => {
    vi.useFakeTimers();
    const harness = setup();
    await harness.client.start();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100 });
    socket.serverCloseIntent({ intent: "revoked" });
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(harness.createSession).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(harness.client.state.status).toBe("ended");
  });

  it("a transport drop after open ends the session without reconnecting", async () => {
    vi.useFakeTimers();
    const harness = setup();
    await harness.client.start();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100 });
    socket.serverClose(1006);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(harness.client.state.notice).toEqual({ kind: "connectionLost" });
    expect(harness.createSession).toHaveBeenCalledTimes(1);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });
});

describe("refused upgrade (1006 before open, C53-CO-1)", () => {
  it("classifies through one createSession call and shows its refusal", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const createSession = vi.fn<CreateSession>(async () => {
      calls += 1;
      if (calls === 1) return fakeSession(SANDBOX, fakeTicket(1));
      throw Object.assign(new Error("not running"), { code: "CONFLICT", status: 409 });
    });
    const harness = setup({ createSession });
    await harness.client.start();
    FakeWebSocket.last().serverClose(1006);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(createSession).toHaveBeenCalledTimes(2);
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(harness.client.state.notice).toEqual({ kind: "notReady" });
  });

  it("after a successful classification, one more upgrade; a second refusal stops", async () => {
    vi.useFakeTimers();
    const harness = setup();
    await harness.client.start();
    FakeWebSocket.last().serverClose(1006);
    await vi.advanceTimersByTimeAsync(0);
    expect(FakeWebSocket.instances).toHaveLength(2);
    // The second upgrade presents the NEW ticket, never the refused one.
    expect(FakeWebSocket.last().protocols[1]).toBe(`wssp.terminal.ticket.${fakeTicket(2)}`);
    FakeWebSocket.last().serverClose(1006);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(harness.createSession).toHaveBeenCalledTimes(2);
    expect(FakeWebSocket.instances).toHaveLength(2);
    expect(harness.client.state.notice).toEqual({ kind: "couldNotConnect" });
  });

  it("the classifying upgrade may still attach", async () => {
    const harness = setup();
    await harness.client.start();
    FakeWebSocket.last().serverClose(1006);
    await flush(10);
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100 });
    expect(harness.client.state.status).toBe("attached");
  });

  it.each([
    ["UNAUTHORIZED", "signedOut"],
    ["FORBIDDEN", "forbidden"],
    ["NOT_FOUND", "notFound"],
    ["CONFLICT", "notReady"],
    ["TOO_MANY_REQUESTS", "rateLimited"],
    ["SERVICE_UNAVAILABLE", "unavailable"],
    ["INTERNAL_SERVER_ERROR", "createFailed"],
  ])("a refused createSession (%s) is shown and passed to onCreateError", async (code, kind) => {
    const error = Object.assign(new Error(code), { code });
    const onCreateError = vi.fn();
    const createSession = vi.fn<CreateSession>(async () => {
      throw error;
    });
    const harness = setup({ createSession, onCreateError });
    await harness.client.start();
    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(harness.client.state.notice).toEqual({ kind });
    expect(onCreateError).toHaveBeenCalledWith(error);
  });
});

describe("backpressure", () => {
  it("detaches with a status instead of queueing past 1 MiB", async () => {
    const { client, socket } = await attached();
    socket.bufferedAmount = 1024 * 1024 - 2;
    FakeTerminalView.last().type("abc");
    expect(socket.sentBinary).toHaveLength(0);
    expect(socket.sentText).toEqual([{ type: "close", requestId: "req-1" }]);
    expect(socket.closedByClient).toEqual({ code: 1000 });
    expect(client.state.notice).toEqual({ kind: "backpressure" });
  });

  it("a server-side backpressure detach is reported the same way", async () => {
    const { client, socket } = await attached();
    socket.serverCloseIntent({
      intent: "backpressure",
      error: { code: "rate_limited", message: "x" },
    });
    expect(client.state.notice).toEqual({ kind: "backpressure" });
  });
});

describe("paste (all-or-nothing)", () => {
  // The server's input queue bound, written out on purpose: a drift in the
  // shared limit must fail here rather than silently move the boundary.
  const QUEUE = 65_536;
  // C54-F3: xterm's bracketed-paste markers (ESC[200~ + ESC[201~) take 12.
  const MAX = QUEUE - 12;
  const sentBytes = (socket: FakeWebSocket) =>
    socket.sentBinary.reduce((sum, chunk) => sum + chunk.byteLength, 0);

  it("sends a paste of exactly the bound (queue minus the bracket markers) whole", async () => {
    const { client, socket, view } = await attached();
    expect(client.paste("a".repeat(MAX))).toBe("done");
    expect(view.pasted).toHaveLength(1);
    expect(sentBytes(socket)).toBe(MAX);
    // With the markers xterm adds in bracketed mode it is exactly the queue.
    expect(MAX + 12).toBe(QUEUE);
    expect(client.state.status).toBe("attached");
  });

  it("refuses a paste one byte over the bound and sends nothing", async () => {
    const { client, socket, view } = await attached();
    expect(client.paste("a".repeat(MAX + 1))).toBe("tooLarge");
    expect(client.paste("a".repeat(QUEUE))).toBe("tooLarge");
    expect(view.pasted).toEqual([]);
    expect(socket.sentBinary).toHaveLength(0);
    expect(client.state.status).toBe("attached");
  });

  it("measures encoded bytes, not characters", async () => {
    const { client, socket } = await attached();
    // U+00E9 is 2 bytes: MAX / 2 + 1 characters are MAX + 2 bytes.
    expect(client.paste("\u00e9".repeat(MAX / 2 + 1))).toBe("tooLarge");
    expect(socket.sentBinary).toHaveLength(0);
    expect(client.paste("\u00e9".repeat(MAX / 2))).toBe("done");
    expect(sentBytes(socket)).toBe(MAX);
  });

  it("C54-F4: strips bracketed-paste markers (also when nested) before sending", async () => {
    const { client, view } = await attached();
    const ESC = "\x1b";
    const poisoned = `ls${ESC}[201~rm -rf ~${ESC}[200~ x ${ESC}[20${ESC}[201~1~tail`;
    expect(client.paste(poisoned)).toBe("done");
    expect(view.pasted).toEqual(["lsrm -rf ~ x tail"]);
    expect(view.pasted[0]).not.toContain(ESC);
    // Markers only: nothing is left to paste.
    expect(client.paste(`${ESC}[200~${ESC}[201~`)).toBe("empty");
    expect(view.pasted).toHaveLength(1);
  });

  it("a server refusal of queued input after a sent paste is reported, not hidden", async () => {
    const { client, socket } = await attached();
    expect(client.paste("abc")).toBe("done");
    socket.serverText({ type: "error", code: "rate_limited" });
    expect(client.state.warning).toBe("inputThrottled");
    expect(client.state.status).toBe("attached");
  });

  it("does not report success when the paste itself triggered the backpressure detach", async () => {
    const { client, socket } = await attached();
    socket.bufferedAmount = 1024 * 1024 - 2;
    expect(client.paste("abc")).toBe("ended");
    expect(client.state.notice).toEqual({ kind: "backpressure" });
    expect(client.state.status).toBe("ended");
  });

  it("an empty or detached paste is not a success either", async () => {
    const { client } = await attached();
    expect(client.paste("")).toBe("empty");
    client.detach();
    expect(client.paste("abc")).toBe("unavailable");
  });
});

describe("C55 native paste (Ctrl/Cmd+V, context menu) takes the Paste button's path", () => {
  const ESC = "\x1b";

  it("strips markers, sends the paste and reports done", async () => {
    const { view, pasteOutcomes } = await attached();
    view.nativePaste(`echo ${ESC}[201~hi`);
    expect(view.pasted).toEqual(["echo hi"]);
    expect(pasteOutcomes).toEqual(["done"]);
  });

  it("is refused whole over the cap and reported tooLarge", async () => {
    const { socket, view, pasteOutcomes } = await attached();
    view.nativePaste("a".repeat(PASTE_MAX_BYTES + 1));
    expect(view.pasted).toEqual([]);
    expect(socket.sentBinary).toHaveLength(0);
    expect(pasteOutcomes).toEqual(["tooLarge"]);
  });

  it("an empty or markers-only clipboard sends nothing", async () => {
    const { view, pasteOutcomes } = await attached();
    view.nativePaste("");
    view.nativePaste(`${ESC}[200~${ESC}[201~`);
    expect(view.pasted).toEqual([]);
    expect(pasteOutcomes).toEqual(["empty", "empty"]);
  });

  it("stops listening when the session ends", async () => {
    const { client, view, pasteOutcomes } = await attached();
    expect(view.nativePasteListeners).toBe(1);
    client.detach();
    expect(view.nativePasteListeners).toBe(0);
    view.nativePaste("late");
    expect(view.pasted).toEqual([]);
    expect(pasteOutcomes).toEqual([]);
  });
});

describe("C55-CO-7 marker stripping is linear and bounded", () => {
  const ESC = "\x1b";
  // `ESC[20` x d, `ESC[201~`, `1~` x d: every inner removal reassembles the
  // next marker, the worst case for repeated replacement (quadratic).
  const nested = (depth: number) => `${`${ESC}[20`.repeat(depth)}${ESC}[201~${"1~".repeat(depth)}`;

  it("strips a 300 KB nested-marker input in one pass, fast", () => {
    const input = nested(50_000);
    expect(input.length).toBeGreaterThan(300_000);
    const started = performance.now();
    expect(stripPasteMarkers(input)).toBe("");
    expect(performance.now() - started).toBeLessThan(250);
  });

  it("matches removing markers until none is left", () => {
    const reference = (text: string) => {
      const marker = new RegExp(`${ESC}\\[20[01]~`, "g");
      let current = text;
      for (;;) {
        const next = current.replace(marker, "");
        if (next === current) return current;
        current = next;
      }
    };
    const pieces = [
      `${ESC}[200~`,
      `${ESC}[201~`,
      `${ESC}[20`,
      "0~",
      "1~",
      ESC,
      "[",
      "a",
      "\u00e9",
      "\ud83d\ude00",
      "~",
    ];
    let seed = 7;
    for (let round = 0; round < 500; round += 1) {
      let text = "";
      for (let i = 0; i < 12; i += 1) {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        text += pieces[seed % pieces.length];
      }
      expect(stripPasteMarkers(text)).toBe(reference(text));
    }
    expect(stripPasteMarkers(nested(3))).toBe("");
    expect(stripPasteMarkers("plain text")).toBe("plain text");
  });

  // C55 final security review (FS-PROBE-3): marker fragments and single code
  // units, including lone surrogates and the C1 CSI (U+009B), at random
  // lengths, with planted nested markers; the output must equal
  // remove-until-fixpoint and never contain a marker. Since C55-FS-N3 the
  // 8-bit forms `\u009b200~` / `\u009b201~` are markers too (an 8-bit reader
  // of the UTF-8 bytes C2 9B sees a CSI); `\u009b[200~` is not one.
  const MARKERS = [`${ESC}[200~`, `${ESC}[201~`, "\u009b200~", "\u009b201~"];
  it("C55-FS-N3: strips the 8-bit C1 markers too, nested and mixed, and keeps CSI-[ text", () => {
    expect(stripPasteMarkers("a\u009b200~b\u009b201~c")).toBe("abc");
    expect(stripPasteMarkers("\u009b20\u009b201~1~rm -rf")).toBe("rm -rf");
    expect(stripPasteMarkers(`\u009b20${ESC}[201~1~x`)).toBe("x");
    expect(stripPasteMarkers("\u009b[200~")).toBe("\u009b[200~");
    expect(stripPasteMarkers("\u009b202~")).toBe("\u009b202~");
  });

  it("fuzz: equals remove-until-fixpoint and never leaves a marker (fixed seed)", () => {
    const reference = (text: string) => {
      let current = text;
      for (;;) {
        let next = current;
        for (const marker of MARKERS) next = next.replaceAll(marker, "");
        if (next === current) return current;
        current = next;
      }
    };
    const alphabet = [
      ESC,
      "[",
      "2",
      "0",
      "1",
      "~",
      "a",
      "\n",
      "\u009b",
      "\ud83d",
      "\ude00",
      `${ESC}[20`,
      `${ESC}[200~`,
      `${ESC}[201~`,
      "\u009b200~",
      "\u009b201~",
      "\u009b20",
      "\u009b[200~",
    ];
    let seed = 7;
    const random = () => {
      seed = (seed * 1103515245 + 12345) >>> 0;
      return seed / 2 ** 32;
    };
    for (let round = 0; round < 100_000; round += 1) {
      let text = "";
      const length = Math.floor(random() * 30);
      for (let i = 0; i < length; i += 1) text += alphabet[Math.floor(random() * alphabet.length)];
      if (random() < 0.3) text = text.replace("a", `${ESC}[20${ESC}[201~1~`);
      if (random() < 0.3) text = text.replace("a", `${ESC}[20${ESC}[200~0~`);
      if (random() < 0.3) text = text.replace("a", "\u009b20\u009b201~1~");
      if (random() < 0.3) text = text.replace("a", `\u009b20${ESC}[200~0~`);
      const out = stripPasteMarkers(text);
      expect(out, JSON.stringify(text)).toBe(reference(text));
      expect(
        MARKERS.some((marker) => out.includes(marker)),
        JSON.stringify(text),
      ).toBe(false);
    }
  }, 30_000);

  it("refuses an oversized clipboard before scanning it", async () => {
    const { client, view } = await attached();
    const input = nested(50_000);
    expect(input.length).toBeGreaterThan(PASTE_SCAN_MAX_CHARS);
    const started = performance.now();
    expect(client.paste(input)).toBe("tooLarge");
    expect(performance.now() - started).toBeLessThan(50);
    expect(view.pasted).toEqual([]);
  });
});

describe("C55 page loss ends the session with a CloseIntent", () => {
  it.each(["pagehide", "freeze"])(
    "%s sends the close request, closes the socket and ends",
    async (type) => {
      const { client, socket, page } = await attached();
      page.dispatchEvent(new Event(type));
      expect(socket.sentText.filter((frame) => frame.type === "close")).toHaveLength(1);
      expect(socket.closedByClient).not.toBeNull();
      // C55-CO-8: a restored page says the page was left, not "You disconnected".
      expect(client.state).toMatchObject({ status: "ended", notice: { kind: "pageLeft" } });
      page.dispatchEvent(new Event(type));
      expect(socket.sentText.filter((frame) => frame.type === "close")).toHaveLength(1);
    },
  );

  it("removes both page listeners when the session ends (whatever ends it)", async () => {
    const harness = setup();
    const added = vi.spyOn(harness.page, "addEventListener");
    const removed = vi.spyOn(harness.page, "removeEventListener");
    await harness.client.start();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100 });
    const registered = added.mock.calls.map(([type, listener]) => [type, listener]);
    expect(registered.map(([type]) => type).sort()).toEqual(["freeze", "pagehide"]);
    expect(removed).not.toHaveBeenCalled();
    harness.client.detach();
    // Exactly the listeners that were added, by identity.
    expect(removed.mock.calls.map(([type, listener]) => [type, listener])).toEqual(
      expect.arrayContaining(registered),
    );
    expect(removed).toHaveBeenCalledTimes(2);
  });

  it("a page event after a normal detach sends nothing more", async () => {
    const { client, socket, page } = await attached();
    client.detach();
    const sent = socket.sentText.length;
    page.dispatchEvent(new Event("pagehide"));
    expect(socket.sentText).toHaveLength(sent);
  });
});

describe("loading", () => {
  it("a failed xterm chunk ends with loadFailed and mints no ticket", async () => {
    const createSession = vi.fn<CreateSession>();
    const client = new TerminalClient({
      sandboxId: SANDBOX,
      serverUrl: "https://app.example.test",
      container: document.createElement("div"),
      createSession,
      loadView: async () => {
        throw new Error("chunk");
      },
      onChange: () => {},
      WebSocket: FakeWebSocketCtor,
    });
    await client.start();
    expect(createSession).not.toHaveBeenCalled();
    expect(client.state.notice).toEqual({ kind: "loadFailed" });
  });
});

it("host idle/lifetime expiry has its own notice; an unanswered host open stays an opening timeout", async () => {
  const host = setup({ host: true });
  await host.client.start();
  const hostSocket = FakeWebSocket.last();
  hostSocket.serverOpen();
  hostSocket.serverText({ type: "ready", rows: 24, cols: 80 });
  hostSocket.serverCloseIntent({ intent: "expired", error: { code: "timeout" } });
  expect(host.client.state.notice).toEqual({ kind: "hostExpired" });
  const opening = setup({ host: true });
  await opening.client.start();
  const openingSocket = FakeWebSocket.last();
  openingSocket.serverOpen();
  openingSocket.serverCloseIntent({ intent: "expired", error: { code: "timeout" } });
  expect(opening.client.state.notice).toEqual({ kind: "openTimedOut" });
});

describe("WP8 reattach (sandbox terminals, v2)", () => {
  const TERMINAL = fakeTerminalId(1);

  async function resumable(options: Parameters<typeof setup>[0] = {}) {
    const harness = setup({ resumable: true, ...options });
    await harness.client.start();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100, terminalId: TERMINAL, outputSeq: 0 });
    return { ...harness, socket, view: FakeTerminalView.last() };
  }

  function detach(socket: FakeWebSocket, graceMs = 120_000) {
    socket.serverText({ type: "reconnecting", terminalId: TERMINAL, graceMs });
    socket.serverClose(4402);
  }

  function resumed(socket: FakeWebSocket, outputSeq: number) {
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100, terminalId: TERMINAL, outputSeq });
  }

  const refusedUpgrade = () => FakeWebSocket.last().serverClose(1006);

  it("spreads at most three attempts across the grace, the first after 1–5 s", () => {
    expect(resumeOffsets(120_000, () => 0)).toEqual([1_000, 40_000, 80_000]);
    expect(resumeOffsets(120_000, () => 0.999)).toEqual([
      expect.closeTo(4_996, 0),
      expect.closeTo(44_995, 0),
      expect.closeTo(84_995, 0),
    ]);
    // Never at or past the grace.
    expect(resumeOffsets(2_000, () => 0)).toEqual([1_000]);
    expect(resumeOffsets(500, () => 0)).toEqual([]);
  });

  it("mints v2, counts output, and resumes the same terminal at its next output sequence", async () => {
    vi.useFakeTimers();
    const { createSession, socket, view, status, client } = await resumable();
    expect(createSession).toHaveBeenCalledWith({
      sandboxId: SANDBOX,
      rows: 30,
      cols: 100,
      version: 2,
    });
    socket.serverBinary("a");
    socket.serverBinary("b");
    socket.serverBinary("c");
    detach(socket);
    expect(status()).toBe("reconnecting");
    expect(view.disposed).toBe(false);
    // No input while detached.
    view.type("lost");
    expect(socket.sentBinary).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(999);
    expect(createSession).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(createSession).toHaveBeenCalledTimes(2);
    expect(createSession).toHaveBeenLastCalledWith(
      {
        sandboxId: SANDBOX,
        rows: 30,
        cols: 100,
        version: 2,
        resume: { terminalId: TERMINAL, nextOutputSeq: 3 },
      },
      { signal: expect.any(AbortSignal) },
    );
    await flush();
    const next = FakeWebSocket.last();
    expect(next).not.toBe(socket);
    expect(status()).toBe("reconnecting");
    resumed(next, 3);
    expect(status()).toBe("attached");
    expect(client.state.warning).toBeNull();
    next.serverBinary("d");
    expect(view.written).toEqual(["a", "b", "c", "d"]);
    // A second drop resumes from the new count.
    detach(next);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(createSession).toHaveBeenLastCalledWith(
      expect.objectContaining({ resume: { terminalId: TERMINAL, nextOutputSeq: 4 } }),
      { signal: expect.any(AbortSignal) },
    );
  });

  it("warns when the host no longer had all the output", async () => {
    vi.useFakeTimers();
    const { socket, client } = await resumable();
    socket.serverBinary("a");
    detach(socket);
    await vi.advanceTimersByTimeAsync(1_000);
    resumed(FakeWebSocket.last(), 7);
    expect(client.state.status).toBe("attached");
    expect(client.state.warning).toBe("outputLost");
  });

  it("gives up after three failed attempts with Attach again", async () => {
    vi.useFakeTimers();
    const { createSession, socket, notice, status } = await resumable();
    detach(socket);
    await vi.advanceTimersByTimeAsync(1_000);
    refusedUpgrade();
    await vi.advanceTimersByTimeAsync(39_000);
    expect(createSession).toHaveBeenCalledTimes(3);
    refusedUpgrade();
    await vi.advanceTimersByTimeAsync(40_000);
    expect(createSession).toHaveBeenCalledTimes(4);
    refusedUpgrade();
    await flush();
    expect(status()).toBe("ended");
    expect(notice()).toEqual({ kind: "resumeFailed" });
    await vi.advanceTimersByTimeAsync(600_000);
    expect(createSession).toHaveBeenCalledTimes(4);
  });

  it("stops at once on a definitive refusal of the resume", async () => {
    vi.useFakeTimers();
    const { createSession, socket, notice } = await resumable();
    createSession.mockRejectedValueOnce({
      code: "CONFLICT",
      status: 409,
      data: { code: "sandbox.terminal_resume_unavailable" },
    });
    detach(socket);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(notice()).toEqual({ kind: "resumeFailed" });
    await vi.advanceTimersByTimeAsync(600_000);
    expect(createSession).toHaveBeenCalledTimes(2);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it("a signed-out refusal ends with its own notice and reaches onCreateError", async () => {
    vi.useFakeTimers();
    const onCreateError = vi.fn();
    const { createSession, socket, notice } = await resumable({ onCreateError });
    const error = { code: "UNAUTHORIZED", status: 401 };
    createSession.mockRejectedValueOnce(error);
    detach(socket);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(notice()).toEqual({ kind: "signedOut" });
    expect(onCreateError).toHaveBeenCalledWith(error);
  });

  it("a budget refusal or a host that is not back yet is retried at the next slot", async () => {
    vi.useFakeTimers();
    const { createSession, socket, status } = await resumable();
    createSession.mockRejectedValueOnce({ code: "TOO_MANY_REQUESTS", status: 429 });
    detach(socket);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(status()).toBe("reconnecting");
    await vi.advanceTimersByTimeAsync(39_000);
    expect(createSession).toHaveBeenCalledTimes(3);
    await flush();
    const second = FakeWebSocket.last();
    second.serverOpen();
    second.serverCloseIntent({ error: { code: "disconnected", message: "host is not connected" } });
    expect(status()).toBe("reconnecting");
    await vi.advanceTimersByTimeAsync(40_000);
    expect(createSession).toHaveBeenCalledTimes(4);
    await flush();
    resumed(FakeWebSocket.last(), 0);
    expect(status()).toBe("attached");
  });

  it("a final close of the resumed socket ends with its own reason", async () => {
    vi.useFakeTimers();
    const { socket, notice } = await resumable();
    detach(socket);
    await vi.advanceTimersByTimeAsync(1_000);
    const next = FakeWebSocket.last();
    next.serverOpen();
    next.serverCloseIntent({ intent: "sandbox_stopped" });
    expect(notice()).toEqual({ kind: "sandboxStopped" });
  });

  it("a crashed server (drop without CloseIntent) is reattached with the default grace", async () => {
    vi.useFakeTimers();
    const { createSession, socket, status } = await resumable();
    socket.serverClose(1006);
    expect(status()).toBe("reconnecting");
    await vi.advanceTimersByTimeAsync(1_000);
    expect(createSession).toHaveBeenLastCalledWith(
      expect.objectContaining({ resume: { terminalId: TERMINAL, nextOutputSeq: 0 } }),
      { signal: expect.any(AbortSignal) },
    );
  });

  it("a 4401 stays final, and a terminal without an id is never reattached", async () => {
    const first = await resumable();
    first.socket.serverCloseIntent({ intent: "host_disconnected" });
    expect(first.notice()).toEqual({ kind: "hostDisconnected" });

    FakeWebSocket.reset();
    const harness = setup({ resumable: true });
    await harness.client.start();
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100 });
    socket.serverClose(1006);
    expect(harness.notice()).toEqual({ kind: "connectionLost" });
  });

  it("detach while reconnecting cancels every attempt and releases the turn", async () => {
    vi.useFakeTimers();
    const locks = new FakeLocks();
    const { createSession, socket, client, notice } = await resumable({
      resumeLocks: () => locks,
    });
    detach(socket);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(locks.held.get("wssp.terminal.resume")).toBe(1);
    client.detach();
    expect(notice()).toEqual({ kind: "client" });
    await flush();
    expect(locks.held.get("wssp.terminal.resume")).toBe(0);
    await vi.advanceTimersByTimeAsync(600_000);
    expect(createSession).toHaveBeenCalledTimes(2);
  });

  it("a stalled mint is abandoned at the grace: the turn is released and a late answer ignored", async () => {
    vi.useFakeTimers();
    const locks = new FakeLocks();
    let answer: ((session: { path: string; protocols: string[] }) => void) | undefined;
    let mintSignal: AbortSignal | undefined;
    let minted = 0;
    const createSession = vi.fn<CreateSession>(async (_input, call) => {
      minted += 1;
      if (minted === 1) return fakeSession(SANDBOX, fakeTicket(1));
      mintSignal = call?.signal;
      return new Promise((resolve) => {
        answer = resolve;
      });
    });
    const harness = await resumable({
      createSession,
      resumeLocks: () => locks,
      // Longer than the grace: only the independent deadline can end it.
      resumeAttemptTimeoutMs: 600_000,
    });
    detach(harness.socket, 10_000);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(createSession).toHaveBeenCalledTimes(2);
    expect(locks.held.get("wssp.terminal.resume")).toBe(1);
    expect(harness.status()).toBe("reconnecting");
    await vi.advanceTimersByTimeAsync(9_000);
    expect(harness.status()).toBe("ended");
    expect(harness.notice()).toEqual({ kind: "resumeFailed" });
    expect(mintSignal?.aborted).toBe(true);
    await flush();
    expect(locks.held.get("wssp.terminal.resume")).toBe(0);
    const sockets = FakeWebSocket.instances.length;
    answer?.(fakeSession(SANDBOX, fakeTicket(2)));
    await flush();
    expect(FakeWebSocket.instances.length).toBe(sockets);
    expect(harness.status()).toBe("ended");
  });

  it("an attempt past its timeout gives the turn back and the next slot tries again", async () => {
    vi.useFakeTimers();
    const locks = new FakeLocks();
    const { createSession, socket, status } = await resumable({
      resumeLocks: () => locks,
      resumeAttemptTimeoutMs: 5_000,
    });
    detach(socket);
    await vi.advanceTimersByTimeAsync(1_000);
    await flush();
    const stalled = FakeWebSocket.last();
    stalled.serverOpen(); // upgraded, but no ready ever comes
    await vi.advanceTimersByTimeAsync(5_000);
    expect(stalled.closedByClient).not.toBeNull();
    await flush();
    expect(locks.held.get("wssp.terminal.resume")).toBe(0);
    expect(status()).toBe("reconnecting");
    await vi.advanceTimersByTimeAsync(34_000);
    expect(createSession).toHaveBeenCalledTimes(3);
  });

  it("three tabs contending at once: exactly one holds the turn at a time", async () => {
    vi.useFakeTimers();
    const locks = new FakeLocks();
    const tabs: Awaited<ReturnType<typeof resumable>>[] = [];
    for (const prefix of ["a", "b", "c"])
      tabs.push(await resumable({ resumeLocks: () => locks, idPrefix: prefix }));
    for (const tab of tabs) detach(tab.socket);
    await vi.advanceTimersByTimeAsync(1_000);
    await flush();
    const minting = () => tabs.filter((tab) => tab.createSession.mock.calls.length === 2);
    expect(minting()).toHaveLength(1);
    expect(locks.held.get("wssp.terminal.resume")).toBe(1);
    // Each tab that reattaches hands the turn to exactly one waiting tab.
    for (let round = 1; round <= 3; round += 1) {
      const holder = minting().find((tab) => tab.status() !== "attached")!;
      resumed(FakeWebSocket.last(), 0);
      expect(holder.status()).toBe("attached");
      await flush();
      await flush();
      expect(minting()).toHaveLength(Math.min(round + 1, 3));
    }
    expect(locks.maxHeld).toBe(1);
    expect(tabs.every((tab) => tab.status() === "attached")).toBe(true);
  });

  it("a lock lost after the grant abandons the attempt: no socket while another tab holds the turn", async () => {
    vi.useFakeTimers();
    const locks = new FakeLocks();
    let answer: ((session: { path: string; protocols: string[] }) => void) | undefined;
    let mintSignal: AbortSignal | undefined;
    let minted = 0;
    const createSession = vi.fn<CreateSession>(async (_input, call) => {
      minted += 1;
      if (minted === 1) return fakeSession(SANDBOX, fakeTicket(1));
      if (minted === 2) {
        mintSignal = call?.signal;
        return new Promise((resolve) => {
          answer = resolve;
        });
      }
      return fakeSession(SANDBOX, fakeTicket(minted));
    });
    const a = await resumable({ createSession, resumeLocks: () => locks, idPrefix: "a" });
    const b = await resumable({ resumeLocks: () => locks, idPrefix: "b" });
    detach(a.socket);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(createSession).toHaveBeenCalledTimes(2); // A holds the turn, mint stalled
    detach(b.socket);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(b.createSession).toHaveBeenCalledTimes(1); // B waits for the turn
    // WebKit suspends A's page: its lock is taken away mid-mint.
    locks.revoke("wssp.terminal.resume");
    await flush();
    await flush();
    expect(mintSignal?.aborted).toBe(true);
    expect(b.createSession).toHaveBeenCalledTimes(2); // B holds the turn now
    expect(locks.maxHeld).toBe(1);
    const sockets = FakeWebSocket.instances.length;
    // A resumes and its stalled mint answers late: ignored, no socket.
    answer?.(fakeSession(SANDBOX, fakeTicket(99)));
    await flush();
    expect(FakeWebSocket.instances.length).toBe(sockets);
    expect(a.status()).toBe("reconnecting");
    // B reattaches and releases; A re-requests the turn at its next slot.
    await flush();
    resumed(FakeWebSocket.last(), 0);
    expect(b.status()).toBe("attached");
    await vi.advanceTimersByTimeAsync(40_000);
    expect(createSession).toHaveBeenCalledTimes(3);
    await flush();
    resumed(FakeWebSocket.last(), 0);
    expect(a.status()).toBe("attached");
    expect(locks.maxHeld).toBe(1);
  });

  it("without navigator.locks a tab still reattaches after a short random backoff", async () => {
    vi.useFakeTimers();
    const { createSession, socket, status } = await resumable({
      resumeLocks: () => null,
      random: () => 0.5,
    });
    detach(socket);
    // First slot 1_000 + 0.5 * 4_000 = 3_000 ms, then a 1_000 ms backoff.
    await vi.advanceTimersByTimeAsync(3_999);
    expect(createSession).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(createSession).toHaveBeenCalledTimes(2);
    await flush();
    resumed(FakeWebSocket.last(), 0);
    expect(status()).toBe("attached");
  });

  it("a host terminal is never reattached", async () => {
    const harness = setup({ host: true });
    await harness.client.start();
    expect(harness.createSession).toHaveBeenCalledWith({ sandboxId: SANDBOX, rows: 30, cols: 100 });
    const socket = FakeWebSocket.last();
    socket.serverOpen();
    socket.serverText({ type: "ready", rows: 30, cols: 100, terminalId: TERMINAL, outputSeq: 0 });
    detach(socket);
    expect(harness.status()).toBe("ended");
    expect(harness.notice()).toEqual({ kind: "connectionLost" });
  });
});
