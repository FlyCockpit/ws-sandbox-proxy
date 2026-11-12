import { revalidateSandboxHostIdentity } from "@wssp/api/lib/host-token-access";
import {
  type AuthorityChangeHold,
  holdAuthorityChange,
  withAuthorityChange,
  withGlobalAuthorityChange,
} from "@wssp/db/authority";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { helloFixture } from "./capacity-fixtures";
import {
  installFenceTransaction,
  prismaPromise,
  relayStore,
  runningCensusFrames,
} from "./fenced-prisma-harness.js";
import {
  encodeTerminalDataFrame,
  parseTerminalDataFrame,
  TERMINAL_LIMITS,
  type TerminalFence,
} from "./protocol.js";
import {
  SANDBOX_RECEIVE_MAX_FRAMES,
  SandboxRelaySessionManager,
  TERMINAL_HOLD_MAX_FRAMES,
} from "./session-manager.js";
import {
  HOST_CREDENTIAL_INACTIVE_ERROR,
  NODE_DAEMON_SHUTDOWN_ERROR,
  SandboxTerminalManager,
  TERMINAL_FOREIGN_FRAME_LIMIT,
  type TerminalAttachment,
  type TerminalCloseNotice,
  type TerminalHostLink,
  type TerminalSessionHandle,
} from "./terminal-manager.js";
import { expectNoTerminalResources } from "./terminal-resources-harness.js";

vi.mock("@wssp/api/lib/host-token-access", () => ({
  revalidateSandboxHostIdentity: vi
    .fn()
    .mockResolvedValue({ status: "active", hostDeletionRequested: false }),
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "service-principal-test",
  },
}));
vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
const { default: prisma } = await import("@wssp/db");
const db = vi.mocked(prisma, true);

class FakeSocket {
  readyState = 1;
  bufferedAmount = 0;
  sends: string[] = [];
  binarySends: ArrayBuffer[] = [];
  closes: { code?: number; reason?: string }[] = [];
  /** The next send throws (a failing transport). */
  failNextSend = false;
  send(data: string | ArrayBuffer | Uint8Array) {
    if (this.failNextSend) {
      this.failNextSend = false;
      throw new Error("send failed");
    }
    if (typeof data === "string") this.sends.push(data);
    else if (data instanceof ArrayBuffer) this.binarySends.push(data);
    else this.binarySends.push(data.slice().buffer);
  }
  close(code?: number, reason?: string) {
    this.closes.push({ code, reason });
    this.readyState = 3;
  }
  frames(type: string) {
    return this.sends.map((s) => JSON.parse(s)).filter((f) => f.type === type);
  }
  input() {
    return this.binarySends.map((frame) => parseTerminalDataFrame(frame)!);
  }
}

class FakeAttachment implements TerminalAttachment {
  bufferedAmount = 0;
  output: number[] = [];
  readies: { rows: number; cols: number }[] = [];
  closes: TerminalCloseNotice[] = [];
  sendOutput(bytes: Uint8Array) {
    this.output.push(...bytes);
  }
  ready(size: { rows: number; cols: number }) {
    this.readies.push(size);
  }
  close(notice: TerminalCloseNotice) {
    this.closes.push(notice);
  }
}

describe("SandboxTerminalManager (unit)", () => {
  let host: FakeSocket;
  let now = 0;
  let closedSockets: unknown[] = [];
  let manager: SandboxTerminalManager;
  const link = (): TerminalHostLink => ({
    socket: host,
    hostId: "host-1",
    ownerId: "owner-1",
    epoch: 7,
    protocolVersion: "1.0",
    authorized: () => true,
  });
  beforeEach(() => {
    host = new FakeSocket();
    now = 1_000_000;
    closedSockets = [];
    manager = new SandboxTerminalManager(
      {
        terminalHost: () => ({ link: link() }),
        closeHostSocket: (socket) => closedSockets.push(socket),
      },
      () => now,
    );
  });

  function open(sandboxId = "sbx-1", attachment = new FakeAttachment()) {
    const result = manager.open({
      ownerId: "owner-1",
      hostId: "host-1",
      sandboxId,
      generation: 3,
      rows: 24,
      cols: 80,
      attachment,
    });
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    const frame = host.frames("terminal.open").at(-1);
    return { handle: result.session, attachment, fence: frame.fence as TerminalFence, frame };
  }
  function ready(fence: TerminalFence, requestId: string) {
    manager.handleHostControl(host, {
      type: "terminal.ready",
      requestId,
      fence,
      rows: 24,
      cols: 80,
    });
  }
  function opened(sandboxId = "sbx-1") {
    const session = open(sandboxId);
    ready(session.fence, session.frame.requestId);
    return session;
  }
  function data(fence: TerminalFence, sequence: number, text: string, socket = host) {
    manager.handleHostData(
      socket,
      { type: "terminal.data", fence, sequence },
      new TextEncoder().encode(text),
    );
  }

  it("mints every identity server-side and binds the host epoch and record", () => {
    const { fence, frame, handle } = open();
    expect(fence).toMatchObject({
      hostId: "host-1",
      target: { kind: "sandbox", sandboxId: "sbx-1", generation: 3 },
      epoch: 7,
    });
    expect(fence.sessionId).toBe(handle.sessionId);
    for (const id of [fence.sessionId, fence.operationId, frame.requestId])
      expect(id).toMatch(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/);
    expect(Object.keys(frame).sort()).toEqual(["cols", "fence", "requestId", "rows", "type"]);
    expect(manager.sessionCount(host)).toBe(1);
  });

  it("E1-A-06: a guest open carries the revision's default cwd to the host", () => {
    const result = manager.open({
      ownerId: "owner-1",
      hostId: "host-1",
      sandboxId: "sbx-1",
      generation: 3,
      rows: 24,
      cols: 80,
      cwd: "/srv/app",
      attachment: new FakeAttachment(),
    });
    expect(result.ok).toBe(true);
    expect(host.frames("terminal.open").at(-1)).toMatchObject({ cwd: "/srv/app" });
  });

  it("delivers in-order output after ready and acknowledges each frame", () => {
    const { fence, frame, attachment } = open();
    data(fence, 0, "early");
    ready(fence, frame.requestId);
    expect(attachment.readies).toEqual([{ rows: 24, cols: 80 }]);
    data(fence, 0, "hi");
    data(fence, 1, "!");
    expect(String.fromCharCode(...attachment.output)).toBe("hi!");
    expect(host.frames("terminal.ack").map((f) => f.sequence)).toEqual([0, 1]);
  });

  it.each([
    ["generation", { target: { kind: "sandbox" as const, sandboxId: "sbx-1", generation: 4 } }],
    ["epoch", { epoch: 8 }],
    ["host", { hostId: "host-2" }],
    ["operation", { operationId: "topforged" }],
    ["sandbox", { target: { kind: "sandbox" as const, sandboxId: "sbx-2", generation: 3 } }],
  ])("a %s mismatch delivers zero bytes; repeated violations close", (_leg, change) => {
    const { fence, attachment } = opened();
    const forged = { ...fence, ...change };
    data(forged, 0, "x");
    data(forged, 0, "x");
    expect(attachment.output).toEqual([]);
    expect(attachment.closes).toEqual([]);
    data(forged, 0, "x");
    expect(attachment.output).toEqual([]);
    expect(attachment.closes).toEqual([
      expect.objectContaining({ code: 4401, intent: "protocol_violation" }),
    ]);
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "protocol_violation", fence }),
    ]);
  });

  it("C52-F-3: a late ready for an open or resize sent before a close is dropped, not a violation", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      // Closed while opening: the host answers the open after our close.
      const opening = open("sbx-1");
      opening.handle.close();
      ready(opening.fence, opening.frame.requestId);
      // Closed with a resize outstanding: the host answers that resize.
      const live = opened("sbx-2");
      expect(live.handle.resize(30, 90).ok).toBe(true);
      const resize = host.frames("terminal.resize").at(-1);
      live.handle.close();
      ready(live.fence, resize.requestId);
      expect(warn.mock.calls.filter(([line]) => String(line).includes("terminal.ready"))).toEqual(
        [],
      );
      // Neither late ready reached the browser.
      expect(opening.attachment.readies).toEqual([]);
      expect(live.attachment.readies).toEqual([{ rows: 24, cols: 80 }]);
      // Inverse: a ready after the host's own exit is still a violation.
      manager.handleHostControl(host, {
        type: "terminal.exit",
        fence: live.fence,
        reaped: false,
      });
      ready(live.fence, resize.requestId);
      expect(
        warn.mock.calls.filter(([line]) => String(line).includes("unexpected terminal.ready")),
      ).toHaveLength(1);
    } finally {
      warn.mockRestore();
    }
  });

  it("an unknown session id or another host socket delivers zero bytes to a live session", () => {
    const { fence, attachment } = opened();
    for (let i = 0; i < 5; i += 1) data({ ...fence, sessionId: "tforeign" }, 0, "x");
    const other = new FakeSocket();
    data(fence, 0, "x", other);
    expect(attachment.output).toEqual([]);
    expect(attachment.closes).toEqual([]);
    data(fence, 0, "ok");
    expect(String.fromCharCode(...attachment.output)).toBe("ok");
  });

  it("closes the host socket after too many foreign frames", () => {
    const { fence } = opened();
    for (let i = 0; i <= TERMINAL_FOREIGN_FRAME_LIMIT; i += 1)
      data({ ...fence, sessionId: `tforeign${i}` }, 0, "x");
    expect(closedSockets).toEqual([host]);
  });

  it("frames naming an ended (tombstoned) session count toward the foreign limit", () => {
    const { fence } = opened();
    manager.handleHostControl(host, { type: "terminal.exit", fence, exitCode: 0, reaped: true });
    expect(manager.sessionCount()).toBe(0);
    for (let i = 0; i < TERMINAL_FOREIGN_FRAME_LIMIT; i += 1) data(fence, i, "x");
    expect(closedSockets).toEqual([]);
    data(fence, 0, "x");
    expect(closedSockets).toEqual([host]);
  });

  it("a failed open send leaves the active session and the open rate untouched", () => {
    const first = opened();
    host.failNextSend = true;
    const refused = manager.open({
      ownerId: "owner-1",
      hostId: "host-1",
      sandboxId: "sbx-1",
      generation: 3,
      rows: 24,
      cols: 80,
      attachment: new FakeAttachment(),
    });
    expect(refused).toMatchObject({ ok: false, error: { code: "transport" } });
    expect(first.attachment.closes).toEqual([]);
    expect(host.frames("terminal.close")).toEqual([]);
    expect(manager.sessionCount()).toBe(1);
    expect(first.handle.input(new Uint8Array([1])).ok).toBe(true);
    expect(host.input()).toHaveLength(1);
    // A later open still replaces it, after its own open is on the wire.
    const second = open();
    expect(first.attachment.closes).toEqual([{ code: 4401, intent: "replaced" }]);
    const order = host.sends.map((frame) => JSON.parse(frame).type);
    expect(order.lastIndexOf("terminal.open")).toBeLessThan(order.lastIndexOf("terminal.close"));
    expect(second.attachment.closes).toEqual([]);
    // Failed sends never charge the open rate.
    for (let i = 0; i < TERMINAL_LIMITS.opensPerMinutePerHost; i += 1) {
      host.failNextSend = true;
      expect(
        manager.open({
          ownerId: "owner-1",
          hostId: "host-1",
          sandboxId: `sbx-r${i}`,
          generation: 3,
          rows: 24,
          cols: 80,
          attachment: new FakeAttachment(),
        }),
      ).toMatchObject({ ok: false, error: { code: "transport" } });
    }
    expect(open("sbx-after").handle).toBeDefined();
  });

  it("rejects duplicate output and closes on a sequence gap", () => {
    const { fence, attachment } = opened();
    data(fence, 0, "a");
    data(fence, 0, "a");
    expect(String.fromCharCode(...attachment.output)).toBe("a");
    data(fence, 5, "gap");
    expect(String.fromCharCode(...attachment.output)).toBe("a");
    expect(attachment.closes).toEqual([
      expect.objectContaining({ intent: "protocol_violation", code: 4401 }),
    ]);
  });

  it("detaches a slow browser at the buffered bound with an explicit backpressure error", () => {
    const { fence, attachment, handle } = opened();
    data(fence, 0, "a");
    attachment.bufferedAmount = TERMINAL_LIMITS.attachmentBufferedMaxBytes - 2;
    data(fence, 1, "abc");
    expect(String.fromCharCode(...attachment.output)).toBe("a");
    expect(attachment.closes).toEqual([
      {
        code: 4401,
        intent: "backpressure",
        error: { code: "rate_limited", message: expect.any(String) },
      },
    ]);
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "backpressure" }),
    ]);
    // Detached means no further bytes and no input; the PTY close is pending
    // on the host and the session stays counted until its final exit.
    data(fence, 2, "late");
    expect(handle.input(new Uint8Array([1])).ok).toBe(false);
    expect(manager.sessionCount(host)).toBe(1);
    manager.handleHostControl(host, {
      type: "terminal.exit",
      requestId: host.frames("terminal.close")[0].requestId,
      fence,
      intent: "backpressure",
      reaped: true,
    });
    expect(manager.sessionCount(host)).toBe(0);
    expect(attachment.closes).toHaveLength(1);
  });

  it("bounds input by the credit window and the queue byte cap", () => {
    const { fence, handle } = opened();
    for (let i = 0; i < 20; i += 1) expect(handle.input(new Uint8Array([65 + i])).ok).toBe(true);
    expect(host.input().map((f) => f.metadata.sequence)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    manager.handleHostControl(host, { type: "terminal.ack", fence, sequence: 3 });
    // The 12 bytes queued behind the window were coalesced (C52-F-1) into
    // ONE frame, in order.
    expect(host.input()).toHaveLength(9);
    expect(new TextDecoder().decode(host.input()[8]!.body)).toBe("IJKLMNOPQRST");
    // An ack for an unsent sequence is a violation and grants nothing.
    manager.handleHostControl(host, { type: "terminal.ack", fence, sequence: 40 });
    expect(host.input()).toHaveLength(9);
    // Exactly the cap is accepted: 3 frames fill the window, one stays queued.
    const big = new Uint8Array(TERMINAL_LIMITS.inputQueueMaxBytes);
    expect(handle.input(big)).toEqual({ ok: true });
    expect(host.input()).toHaveLength(12);
    // Past the byte cap is refused and nothing is queued.
    const over = TERMINAL_LIMITS.inputQueueMaxBytes - TERMINAL_LIMITS.dataMaxBytes + 1;
    expect(handle.input(new Uint8Array(over))).toEqual({ ok: false, code: "rate_limited" });
    expect(host.input()).toHaveLength(12);
    // A chunk never exceeds the data bound.
    manager.handleHostControl(host, { type: "terminal.ack", fence, sequence: 11 });
    expect(handle.input(new Uint8Array(TERMINAL_LIMITS.dataMaxBytes + 1)).ok).toBe(true);
    for (const frame of host.input())
      expect(frame.body.byteLength).toBeLessThanOrEqual(TERMINAL_LIMITS.dataMaxBytes);
  });

  it("C52-F-5: a throwing attachment never throws into host frame handling", () => {
    class Throwing extends FakeAttachment {
      constructor(private readonly part: "ready" | "output" | "buffered") {
        super();
        // The base class field is an own property; replace it with a throwing getter.
        if (part === "buffered")
          Object.defineProperty(this, "bufferedAmount", {
            get: () => {
              throw new Error("buffer unreadable");
            },
          });
      }
      override ready(size: { rows: number; cols: number }) {
        if (this.part === "ready") throw new Error("ready failed");
        super.ready(size);
      }
      override sendOutput(bytes: Uint8Array) {
        if (this.part === "output") throw new Error("send failed");
        super.sendOutput(bytes);
      }
    }
    for (const [part, intent] of [
      ["ready", "detached"],
      ["output", "detached"],
      ["buffered", "backpressure"],
    ] as const) {
      host = new FakeSocket();
      const session = open(`sbx-${part}`, new Throwing(part));
      expect(() => ready(session.fence, session.frame.requestId)).not.toThrow();
      if (part !== "ready") expect(() => data(session.fence, 0, "out")).not.toThrow();
      expect(host.frames("terminal.close")).toEqual([
        expect.objectContaining({ intent, fence: session.fence }),
      ]);
      // No ack was sent for output the browser never received.
      expect(host.frames("terminal.ack")).toEqual([]);
    }
  });

  it("pty_env_handshake_takeover_cancels_opening_session and drops late markers/output", () => {
    const first = open();
    expect(first.handle.input(new TextEncoder().encode("forged-before-DONE"))).toMatchObject({
      ok: false,
      code: "state_conflict",
    });
    expect(first.handle.resize(40, 100)).toMatchObject({ ok: false, code: "state_conflict" });
    const second = open();
    expect(first.attachment.closes).toEqual([{ code: 4401, intent: "replaced" }]);
    expect(host.frames("terminal.close")).toContainEqual(
      expect.objectContaining({ intent: "replaced", fence: first.fence }),
    );
    data(first.fence, 0, "late WSSP_ENV_DONE and old output");
    ready(first.fence, first.frame.requestId);
    expect(first.attachment.readies).toEqual([]);
    expect(first.attachment.output).toEqual([]);
    expect(second.attachment.readies).toEqual([]);
    expect(second.attachment.output).toEqual([]);
    ready(second.fence, second.frame.requestId);
    data(second.fence, 0, "new shell");
    expect(second.attachment.readies).toEqual([{ rows: 24, cols: 80 }]);
    expect(String.fromCharCode(...second.attachment.output)).toBe("new shell");
  });

  it("a new attach replaces the active one; a third while one closes is refused", () => {
    const first = opened();
    const second = open();
    expect(first.attachment.closes).toEqual([{ code: 4401, intent: "replaced" }]);
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "replaced", fence: first.fence }),
    ]);
    const third = manager.open({
      ownerId: "owner-1",
      hostId: "host-1",
      sandboxId: "sbx-1",
      generation: 3,
      rows: 24,
      cols: 80,
      attachment: new FakeAttachment(),
    });
    expect(third).toMatchObject({ ok: false, error: { code: "host_capacity" } });
    expect(second.attachment.closes).toEqual([]);
    expect(host.frames("terminal.open")).toHaveLength(2);
  });

  it("enforces the per-host cap before any frame and the open rate", () => {
    for (let i = 0; i < TERMINAL_LIMITS.maxSessionsPerGuestCreator; i += 1) opened(`sbx-${i}`);
    const refused = manager.open({
      ownerId: "owner-1",
      hostId: "host-1",
      sandboxId: "sbx-x",
      generation: 3,
      rows: 24,
      cols: 80,
      attachment: new FakeAttachment(),
    });
    expect(refused).toMatchObject({ ok: false, error: { code: "host_capacity" } });
    expect(host.frames("terminal.open")).toHaveLength(TERMINAL_LIMITS.maxSessionsPerGuestCreator);
    manager.removeHostSocket(host);
    host = new FakeSocket();
    for (
      let i = TERMINAL_LIMITS.maxSessionsPerGuestCreator;
      i < TERMINAL_LIMITS.opensPerMinutePerGuestCreator;
      i += 1
    ) {
      const session = open(`sbx-r${i}`);
      manager.handleHostControl(host, {
        type: "terminal.exit",
        fence: session.fence,
        reaped: true,
        exitCode: 0,
      });
    }
    // The socket changed, so the per-socket rate restarted at the new socket.
    expect(host.frames("terminal.open")).toHaveLength(
      TERMINAL_LIMITS.opensPerMinutePerGuestCreator - TERMINAL_LIMITS.maxSessionsPerGuestCreator,
    );
    for (let i = 0; i < TERMINAL_LIMITS.maxSessionsPerGuestCreator; i += 1) {
      const session = open(`sbx-s${i}`);
      manager.handleHostControl(host, {
        type: "terminal.exit",
        fence: session.fence,
        reaped: true,
      });
    }
    const limited = manager.open({
      ownerId: "owner-1",
      hostId: "host-1",
      sandboxId: "sbx-y",
      generation: 3,
      rows: 24,
      cols: 80,
      attachment: new FakeAttachment(),
    });
    expect(limited).toMatchObject({ ok: false, error: { code: "rate_limited" } });
    now += 60_000;
    expect(open("sbx-y").handle.sessionId).toBeTruthy();
  });

  it("handshake races: exit before ready fails the open; socket loss ends every session", () => {
    const failed = open();
    manager.handleHostControl(host, {
      type: "terminal.exit",
      requestId: failed.frame.requestId,
      fence: failed.fence,
      reaped: true,
      error: { code: "host_effect_not_issued", message: "not issued" },
    });
    expect(failed.attachment.readies).toEqual([]);
    expect(failed.attachment.closes).toEqual([
      { code: 4401, error: { code: "host_effect_not_issued", message: "not issued" } },
    ]);
    // A late ready/data for the ended session is dropped silently (tombstone).
    ready(failed.fence, failed.frame.requestId);
    data(failed.fence, 0, "late");
    expect(failed.attachment.output).toEqual([]);
    expect(manager.sessionCount(host)).toBe(0);

    const pending = open("sbx-2");
    const live = opened("sbx-3");
    manager.removeHostSocket(host);
    expect(pending.attachment.closes).toEqual([{ code: 4401, intent: "host_disconnected" }]);
    expect(live.attachment.closes).toEqual([{ code: 4401, intent: "host_disconnected" }]);
    // No adoption: the same fence arriving on the replacement socket is foreign.
    const replacement = new FakeSocket();
    ready(live.fence, live.frame.requestId);
    data(live.fence, 0, "x", replacement);
    expect(live.attachment.output).toEqual([]);
    expect(manager.sessionCount()).toBe(0);
  });

  it("times out an unanswered open with the fake clock", () => {
    vi.useFakeTimers();
    try {
      const session = open();
      vi.advanceTimersByTime(TERMINAL_LIMITS.openTimeoutMs - 1);
      expect(session.attachment.closes).toEqual([]);
      vi.advanceTimersByTime(1);
      expect(session.attachment.closes).toEqual([
        { code: 4401, intent: "expired", error: { code: "timeout", message: expect.any(String) } },
      ]);
      expect(host.frames("terminal.close")).toEqual([
        expect.objectContaining({ intent: "expired" }),
      ]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("close is idempotent and owner mismatch looks like a missing sandbox", () => {
    const { handle, attachment } = opened();
    handle.close();
    handle.close();
    handle.close("detached");
    expect(attachment.closes).toEqual([{ code: 4401, intent: "client" }]);
    expect(host.frames("terminal.close")).toHaveLength(1);
    const foreign = manager.open({
      ownerId: "owner-2",
      hostId: "host-1",
      sandboxId: "sbx-9",
      generation: 3,
      rows: 24,
      cols: 80,
      attachment: new FakeAttachment(),
    });
    expect(foreign).toMatchObject({ ok: false, error: { code: "sandbox_not_found" } });
    for (const [rows, cols] of [
      [0, 80],
      [24, TERMINAL_LIMITS.maxCols + 1],
    ])
      expect(
        manager.open({
          ownerId: "owner-1",
          hostId: "host-1",
          sandboxId: "sbx-9",
          generation: 3,
          rows: rows!,
          cols: cols!,
          attachment: new FakeAttachment(),
        }).ok,
      ).toBe(false);
  });
});

describe("C55 close boundary: uncertain reap, idempotence, races", () => {
  let host: FakeSocket;
  let now = 0;
  let manager: SandboxTerminalManager;
  beforeEach(() => {
    host = new FakeSocket();
    now = 1_000_000;
    manager = new SandboxTerminalManager(
      {
        terminalHost: () => ({
          link: {
            socket: host,
            hostId: "host-1",
            ownerId: "owner-1",
            epoch: 7,
            protocolVersion: "1.0",
            authorized: () => true,
          },
        }),
        closeHostSocket: () => undefined,
      },
      () => now,
    );
  });
  const openOn = (sandboxId = "sbx-1", attachment = new FakeAttachment()) => {
    const result = manager.open({
      ownerId: "owner-1",
      hostId: "host-1",
      sandboxId,
      generation: 3,
      rows: 24,
      cols: 80,
      attachment,
    });
    if (!result.ok) return { result, attachment } as const;
    const frame = host.frames("terminal.open").at(-1);
    return { result, attachment, fence: frame.fence as TerminalFence, frame } as const;
  };
  const ready = (fence: TerminalFence, requestId: string) =>
    manager.handleHostControl(host, {
      type: "terminal.ready",
      requestId,
      fence,
      rows: 24,
      cols: 80,
    });
  const exit = (fence: TerminalFence, reaped: boolean, intent?: "client") =>
    manager.handleHostControl(host, {
      type: "terminal.exit",
      fence,
      reaped,
      ...(intent ? { intent } : {}),
    });

  it("an uncertain reap keeps the count until the host's reconciliation exit, released once", () => {
    const first = openOn();
    if (!first.fence) throw new Error("open refused");
    ready(first.fence, first.frame.requestId);
    if (first.result.ok) first.result.session.close();
    exit(first.fence, false, "client");
    // The browser heard the end exactly once; the slot is still held.
    expect(first.attachment.closes).toEqual([{ code: 4401, intent: "client" }]);
    expect(manager.resources()).toMatchObject({ sessions: 1, unreaped: 1, openTimers: 0 });
    // The held slot counts toward the per-sandbox cap: one more PTY fits...
    const second = openOn();
    expect(second.result.ok).toBe(true);
    // ...a third does not, and the unreaped session was never "replaced".
    const third = openOn();
    expect(third.result).toMatchObject({ ok: false, error: { code: "host_capacity" } });
    expect(first.attachment.closes).toHaveLength(1);
    // A repeated uncertain exit releases nothing (violation, not a release).
    exit(first.fence, false);
    expect(manager.resources().unreaped).toBe(1);
    // The sweep's confirmation releases exactly once.
    exit(first.fence, true);
    expect(manager.resources()).toMatchObject({ sessions: 1, unreaped: 0 });
    exit(first.fence, true);
    expect(manager.resources()).toMatchObject({ sessions: 1, unreaped: 0 });
    expect(first.attachment.closes).toHaveLength(1);
    if (second.fence) {
      ready(second.fence, second.frame.requestId);
      exit(second.fence, true);
    }
    expectNoTerminalResources(manager, { hostSockets: 1, timers: false });
  });

  it("the socket's end releases an unreaped session (the host keeps its own slot)", () => {
    const session = openOn();
    if (!session.fence) throw new Error("open refused");
    ready(session.fence, session.frame.requestId);
    exit(session.fence, false);
    expect(manager.resources().unreaped).toBe(1);
    manager.removeHostSocket(host);
    expect(session.attachment.closes).toHaveLength(1);
    expectNoTerminalResources(manager, { hostSockets: 0, timers: false });
  });

  it("C55-CO-6: a node daemon's own shutdown exit reaches the browser marked disconnected", () => {
    const first = openOn("sbx-1");
    const second = openOn("sbx-2");
    if (!first.fence || !second.fence) throw new Error("open refused");
    ready(first.fence, first.frame.requestId);
    ready(second.fence, second.frame.requestId);
    manager.handleHostControl(host, {
      type: "terminal.exit",
      fence: first.fence,
      reaped: true,
      intent: "shutdown",
    });
    expect(first.attachment.closes).toEqual([
      { code: 4401, intent: "shutdown", error: NODE_DAEMON_SHUTDOWN_ERROR },
    ]);
    // A host-supplied error is kept as it is.
    const error = { code: "internal" as const, message: "pump failed" };
    manager.handleHostControl(host, {
      type: "terminal.exit",
      fence: second.fence,
      reaped: true,
      intent: "shutdown",
      error,
    });
    expect(second.attachment.closes).toEqual([{ code: 4401, intent: "shutdown", error }]);
    expectNoTerminalResources(manager, { hostSockets: 1, timers: false });
  });

  it("double close, close-after-exit and close-during-close converge to one effect", () => {
    const session = openOn();
    if (!session.fence || !session.result.ok) throw new Error("open refused");
    const handle = session.result.session;
    ready(session.fence, session.frame.requestId);
    handle.close("client");
    handle.close("detached"); // close during close
    manager.closeSandbox("sbx-1", "sandbox_stopped");
    expect(host.frames("terminal.close")).toHaveLength(1);
    exit(session.fence, true, "client");
    handle.close("client"); // close after exit
    manager.closeSandbox("sbx-1", "sandbox_stopped");
    manager.removeHostSocket(host);
    expect(host.frames("terminal.close")).toHaveLength(1);
    expect(session.attachment.closes).toEqual([{ code: 4401, intent: "client" }]);
    expect(handle.input(new Uint8Array([1])).ok).toBe(false);
    expectNoTerminalResources(manager, { hostSockets: 0, timers: false });
  });

  it("handshake-vs-limit: no interleaving of opens, readies, closes and exits exceeds a cap", () => {
    // Deterministic pseudo-random interleavings (seeded LCG).
    let seed = 0x5eed;
    const next = (n: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    type Live = {
      fence: TerminalFence;
      requestId: string;
      handle: { close(intent?: "client"): void };
      phase: "opening" | "open" | "closing";
    };
    const live: Live[] = [];
    let refusedCapacity = 0;
    for (let step = 0; step < 4000; step += 1) {
      now += 2_500; // keeps the open rate (30/min) from masking the caps
      const action = next(5);
      if (action <= 1) {
        const sandboxId = `sbx-${next(6)}`;
        const opened = openOn(sandboxId);
        if (opened.result.ok && opened.fence) {
          for (const old of live)
            if (
              (old.fence.target.kind === "sandbox" ? old.fence.target.sandboxId : "") ===
                sandboxId &&
              old.phase !== "closing"
            )
              old.phase = "closing";
          live.push({
            fence: opened.fence,
            requestId: opened.frame.requestId,
            handle: opened.result.session,
            phase: "opening",
          });
        } else if (!opened.result.ok && opened.result.error.code === "host_capacity") {
          refusedCapacity += 1;
        }
      } else if (live.length > 0) {
        const index = next(live.length);
        const target = live[index]!;
        if (action === 2 && target.phase === "opening") {
          ready(target.fence, target.requestId);
          target.phase = "open";
        } else if (action === 3 && target.phase !== "closing") {
          target.handle.close("client");
          target.phase = "closing";
        } else if (action === 4) {
          exit(target.fence, true);
          live.splice(index, 1);
        }
      }
      // Invariants after EVERY step.
      expect(manager.sessionCount(host)).toBeLessThanOrEqual(TERMINAL_LIMITS.maxSessionsPerHost);
      const perSandbox = new Map<string, { counted: number; active: number }>();
      for (const session of live) {
        const entry = perSandbox.get(
          session.fence.target.kind === "sandbox" ? session.fence.target.sandboxId : "",
        ) ?? { counted: 0, active: 0 };
        entry.counted += 1;
        if (session.phase !== "closing") entry.active += 1;
        perSandbox.set(
          session.fence.target.kind === "sandbox" ? session.fence.target.sandboxId : "",
          entry,
        );
      }
      for (const entry of perSandbox.values()) {
        expect(entry.counted).toBeLessThanOrEqual(TERMINAL_LIMITS.maxLiveSessionsPerSandbox);
        expect(entry.active).toBeLessThanOrEqual(TERMINAL_LIMITS.maxActiveSessionsPerSandbox);
      }
      expect(manager.sessionCount(host)).toBe(live.length);
    }
    expect(refusedCapacity).toBeGreaterThan(0);
    for (const session of live.splice(0)) exit(session.fence, true);
    expectNoTerminalResources(manager, { hostSockets: 1, timers: false });
  });
});

describe("C55 VM deletion during resize (deterministic)", () => {
  let host: FakeSocket;
  let authorized: boolean;
  let manager: SandboxTerminalManager;
  beforeEach(() => {
    host = new FakeSocket();
    authorized = true;
    manager = new SandboxTerminalManager(
      {
        terminalHost: () => ({
          link: {
            socket: host,
            hostId: "host-1",
            ownerId: "owner-1",
            epoch: 7,
            protocolVersion: "1.0",
            authorized: () => authorized,
          },
        }),
        closeHostSocket: () => undefined,
      },
      () => 1_000_000,
    );
  });
  const opened = () => {
    const attachment = new FakeAttachment();
    const result = manager.open({
      ownerId: "owner-1",
      hostId: "host-1",
      sandboxId: "sbx-1",
      generation: 3,
      rows: 24,
      cols: 80,
      attachment,
    });
    if (!result.ok) throw new Error("open refused");
    const frame = host.frames("terminal.open").at(-1);
    const fence = frame.fence as TerminalFence;
    manager.handleHostControl(host, {
      type: "terminal.ready",
      requestId: frame.requestId,
      fence,
      rows: 24,
      cols: 80,
    });
    expect(attachment.readies).toEqual([{ rows: 24, cols: 80 }]);
    return { attachment, handle: result.session, fence };
  };
  const lateReady = (fence: TerminalFence, requestId: string) =>
    manager.handleHostControl(host, {
      type: "terminal.ready",
      requestId,
      fence,
      rows: 50,
      cols: 120,
    });

  it("the host destroys the VM while resizes are in flight: one end, no late ready, no later resize", () => {
    const { attachment, handle, fence } = opened();
    expect(handle.resize(30, 100)).toEqual({ ok: true });
    expect(handle.resize(40, 110)).toEqual({ ok: true });
    const resizes = host.frames("terminal.resize");
    expect(resizes).toHaveLength(2);
    expect(manager.resources().pendingResizes).toBe(2);
    // The VM is deleted under the PTY: the host reports the exit first.
    manager.handleHostControl(host, {
      type: "terminal.exit",
      fence,
      reaped: true,
      intent: "sandbox_destroyed",
    });
    expect(attachment.closes).toEqual([{ code: 4401, intent: "sandbox_destroyed" }]);
    // The answers to the in-flight resizes arrive after the end: no ready.
    for (const resize of resizes) lateReady(fence, resize.requestId);
    expect(attachment.readies).toHaveLength(1);
    // The closed session takes no new resize and sends nothing more.
    expect(handle.resize(50, 120)).toMatchObject({ ok: false });
    manager.closeSandbox("sbx-1", "sandbox_destroyed");
    expect(host.frames("terminal.resize")).toHaveLength(2);
    expect(host.frames("terminal.close")).toHaveLength(0);
    expect(attachment.closes).toHaveLength(1);
    expectNoTerminalResources(manager, { hostSockets: 1, timers: false });
  });

  it("the server learns of the destroy first: the pending resize is dropped, its late ready is inert", () => {
    const { attachment, handle, fence } = opened();
    expect(handle.resize(30, 100)).toEqual({ ok: true });
    const [resize] = host.frames("terminal.resize");
    manager.closeSandbox("sbx-1", "sandbox_destroyed");
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "sandbox_destroyed", fence }),
    ]);
    expect(manager.resources().pendingResizes).toBe(0);
    lateReady(fence, resize.requestId);
    expect(attachment.readies).toHaveLength(1);
    expect(handle.resize(50, 120)).toMatchObject({ ok: false });
    manager.handleHostControl(host, {
      type: "terminal.exit",
      fence,
      reaped: true,
      intent: "sandbox_destroyed",
    });
    expect(attachment.closes).toEqual([{ code: 4401, intent: "sandbox_destroyed" }]);
    expect(host.frames("terminal.resize")).toHaveLength(1);
    expectNoTerminalResources(manager, { hostSockets: 1, timers: false });
  });

  it("a resize deferred under stale host authority is never sent after the destroy", () => {
    const { attachment, handle, fence } = opened();
    authorized = false;
    expect(handle.resize(30, 100)).toEqual({ ok: true });
    expect(manager.resources().deferredResizes).toBe(1);
    manager.closeSandbox("sbx-1", "sandbox_destroyed");
    expect(manager.resources().deferredResizes).toBe(0);
    authorized = true;
    manager.resumeHost(host as never);
    manager.handleHostControl(host, {
      type: "terminal.exit",
      fence,
      reaped: true,
      intent: "sandbox_destroyed",
    });
    expect(host.frames("terminal.resize")).toEqual([]);
    expect(attachment.readies).toHaveLength(1);
    expect(attachment.closes).toHaveLength(1);
    expectNoTerminalResources(manager, { hostSockets: 1, timers: false });
  });
});

/** Deterministic PRNG (32-bit LCG) so every fuzz seed replays exactly. */
function lcg(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 2 ** 32;
  };
}

// C55 final security review (FS-PROBE-1): randomized open / ready / close /
// closeSandbox / exit (reaped or not, duplicated, after release) / host loss
// / closeAll / open-timeout / rate-window interleavings over two owners and
// two hosts, checked after every step against an independent shadow ledger
// of counted slots: no cap bypass, no false `host_capacity` from a leaked
// slot, at most one browser notice, released implies notified, at most one
// host close per session, and nothing left at the end.
describe("C55 slot ledger fuzz (fixed seeds)", () => {
  const SEEDS = 120;
  const STEPS = 120;
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  type Shadow = {
    host: string;
    sock: FakeSocket;
    sandboxId: string;
    fence: TerminalFence;
    openRequestId: string;
    handle: TerminalSessionHandle;
    attachment: FakeAttachment;
    /** Model: the slot is no longer counted. */
    released: boolean;
  };

  function runSeed(seed: number) {
    const random = lcg(seed);
    const pick = <T>(items: readonly T[]): T => {
      const item = items[Math.floor(random() * items.length)];
      if (item === undefined) throw new Error("empty pick");
      return item;
    };
    let now = 1_000_000;
    const hosts = ["host-a", "host-b"] as const;
    const owners = { "host-a": "owner-a", "host-b": "owner-b" };
    const socks = { "host-a": new FakeSocket(), "host-b": new FakeSocket() };
    const epochs = { "host-a": 1, "host-b": 1 };
    const isHost = (id: string): id is (typeof hosts)[number] => id in owners;
    const manager = new SandboxTerminalManager(
      {
        terminalHost: (hostId) =>
          isHost(hostId)
            ? {
                link: {
                  socket: socks[hostId],
                  hostId,
                  ownerId: owners[hostId],
                  epoch: epochs[hostId],
                  protocolVersion: "1.0",
                  authorized: () => true,
                },
              }
            : { error: { code: "disconnected", message: "unknown host" } },
        closeHostSocket: () => undefined,
      },
      () => now,
    );
    const shadows: Shadow[] = [];
    const counted = (sock: FakeSocket) => shadows.filter((x) => x.sock === sock && !x.released);
    const opensIn = new Map<FakeSocket, number[]>();

    const check = (step: string) => {
      for (const host of hosts) {
        const sock = socks[host];
        expect(manager.sessionCount(sock), `${step} count ${host}`).toBe(counted(sock).length);
      }
      for (const x of shadows) {
        expect(x.attachment.closes.length, `${step} one notice`).toBeLessThanOrEqual(1);
        if (x.released) expect(x.attachment.closes.length, `${step} released notified`).toBe(1);
        const closes = x.sock
          .frames("terminal.close")
          .filter((frame) => frame.fence.sessionId === x.fence.sessionId);
        expect(closes.length, `${step} <=1 host close`).toBeLessThanOrEqual(1);
      }
    };

    for (let step = 0; step < STEPS; step += 1) {
      const op = random();
      const live = shadows.filter((x) => !x.released);
      const at = `seed ${seed} step ${step} op ${op.toFixed(2)}`;
      if (op < 0.25) {
        const host = pick(hosts);
        const sock = socks[host];
        const sandboxId = `sbx-${host}-${Math.floor(random() * 5)}`;
        // Sometimes a cross-owner attempt.
        const ownerId =
          random() < 0.1 ? owners[host === "host-a" ? "host-b" : "host-a"] : owners[host];
        const attachment = new FakeAttachment();
        const before = sock.sends.length;
        const result = manager.open({
          ownerId,
          hostId: host,
          sandboxId,
          generation: 1,
          rows: 24,
          cols: 80,
          attachment,
        });
        const window = (opensIn.get(sock) ?? []).filter((t) => now - t < 60_000);
        const hostCount = counted(sock).length;
        const sandboxCount = counted(sock).filter((x) => x.sandboxId === sandboxId).length;
        if (ownerId !== owners[host]) {
          expect(result.ok, `${at} cross-owner`).toBe(false);
          if (!result.ok) expect(result.error.code).toBe("sandbox_not_found");
        } else if (window.length >= TERMINAL_LIMITS.opensPerMinutePerGuestCreator) {
          expect(result.ok, `${at} rate`).toBe(false);
        } else if (hostCount >= TERMINAL_LIMITS.maxSessionsPerGuestCreator) {
          expect(result.ok, `${at} host cap bypass`).toBe(false);
          if (!result.ok) expect(result.error.code).toBe("host_capacity");
        } else if (sandboxCount >= TERMINAL_LIMITS.maxLiveSessionsPerSandbox) {
          expect(result.ok, `${at} sandbox cap bypass`).toBe(false);
          if (!result.ok) expect(result.error.code).toBe("host_capacity");
        } else {
          expect(
            result.ok,
            `${at} leak: refused ${JSON.stringify(!result.ok && result.error)}`,
          ).toBe(true);
        }
        if (result.ok) {
          window.push(now);
          opensIn.set(sock, window);
          const frame = JSON.parse(sock.sends[before] ?? "null");
          // A replaced live session is closed but stays counted until the
          // host confirms its exit.
          shadows.push({
            host,
            sock,
            sandboxId,
            fence: frame.fence,
            openRequestId: frame.requestId,
            handle: result.session,
            attachment,
            released: false,
          });
        }
      } else if (op < 0.35 && live.length) {
        const x = pick(live);
        manager.handleHostControl(x.sock, {
          type: "terminal.ready",
          requestId: x.openRequestId,
          fence: x.fence,
          rows: 24,
          cols: 80,
        });
      } else if (op < 0.45 && shadows.length) {
        pick(shadows).handle.close(pick(["client", "detached", "backpressure"] as const));
      } else if (op < 0.5 && shadows.length) {
        manager.closeSandbox(
          pick(shadows).sandboxId,
          pick(["sandbox_stopped", "expired"] as const),
        );
      } else if (op < 0.75 && shadows.length) {
        // Host exit: possibly duplicated, after release, or the
        // reconciliation exit of an uncertain reap.
        const x = pick(shadows);
        const reaped = random() < 0.6;
        if (socks[x.host as (typeof hosts)[number]] !== x.sock) continue;
        manager.handleHostControl(x.sock, {
          type: "terminal.exit",
          fence: x.fence,
          reaped,
          ...(random() < 0.5 ? { intent: "client" as const } : { exitCode: 0 }),
        });
        if (reaped) x.released = true;
      } else if (op < 0.82) {
        const host = pick(hosts);
        const old = socks[host];
        manager.removeHostSocket(old);
        for (const x of shadows) if (x.sock === old) x.released = true;
        socks[host] = new FakeSocket();
        epochs[host] += 1;
      } else if (op < 0.85) {
        manager.closeAll("shutdown");
        for (const x of shadows) x.released = true;
        for (const host of hosts) {
          socks[host] = new FakeSocket();
          epochs[host] += 1;
        }
      } else if (op < 0.9) {
        // Open timeout: sessions still opening are closed (and stay counted).
        now += 31_000;
        vi.advanceTimersByTime(31_000);
      } else {
        now += 61_000;
      }
      check(at);
    }
    for (const host of hosts) manager.removeHostSocket(socks[host]);
    for (const x of shadows) x.released = true;
    check(`seed ${seed} end`);
    expectNoTerminalResources(manager, { hostSockets: 0 });
  }

  it(`holds the shadow ledger on every step for seeds 1..${SEEDS}`, () => {
    for (let seed = 1; seed <= SEEDS; seed += 1) runSeed(seed);
  });
});

describe("terminal lane on the relay session manager", () => {
  let store = relayStore("GET_FILE");
  let manager: SandboxRelaySessionManager;
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(revalidateSandboxHostIdentity).mockResolvedValue({
      status: "active",
      hostDeletionRequested: false,
    });
    store = relayStore("GET_FILE");
    store.hosts.get("host-1")!.connectionEpoch = 0;
    installFenceTransaction(db, store);
    manager = new SandboxRelaySessionManager();
    db.sandboxTemplateAvailability.findMany.mockImplementation((args) =>
      prismaPromise(prisma.$transaction((tx) => tx.sandboxTemplateAvailability.findMany(args))),
    );
    db.sandboxHost.updateMany.mockImplementation((args) =>
      prismaPromise(prisma.$transaction((tx) => tx.sandboxHost.updateMany(args))),
    );
  });
  // Authority changes a test holds are always settled, even when it fails,
  // so the process-wide authority state never leaks into the next test.
  const holds: AuthorityChangeHold[] = [];
  const holdChange = (scope: Parameters<typeof holdAuthorityChange>[0]) => {
    const change = holdAuthorityChange(scope);
    holds.push(change);
    return change;
  };
  afterEach(() => {
    for (const change of holds.splice(0)) change.settle();
    manager.dispose();
  });

  function hello(_versions: string[], terminal: boolean) {
    return JSON.stringify(helloFixture("host-1", terminal));
  }
  async function registered(versions = ["1.0"], terminal = true) {
    const socket = new FakeSocket();
    manager.acceptAuthenticatedSocket({
      socket,
      identity: {
        hostId: "host-1",
        userId: "user-1",
        tokenId: "token-1",
        credentialKind: "hostToken" as const,
        expiresAt: null,
      },
    });
    manager.handleTextFrame(socket, hello(versions, terminal));
    await manager.drain(socket);
    for (const page of runningCensusFrames(store, "host-1", terminal))
      manager.handleTextFrame(socket, page);
    manager.handleTextFrame(socket, JSON.stringify({ type: "reconcile.complete" }));
    await manager.drain(socket);
    return socket;
  }
  function openOn(attachment = new FakeAttachment()) {
    return manager.terminals.open({
      ownerId: "user-1",
      hostId: "host-1",
      sandboxId: "sbx-1",
      generation: 1,
      rows: 24,
      cols: 80,
      attachment,
    });
  }

  it.each(["1.0"])(
    "negotiates %s, announces the epoch, and routes terminal frames synchronously",
    async (version) => {
      const socket = await registered([version, "1.0", "1.0"]);
      const ok = socket.frames("hello.ok")[0];
      expect(ok.protocolVersion).toBe(version);
      expect(ok.connectionEpoch).toBe(store.hosts.get("host-1")!.connectionEpoch);
      const attachment = new FakeAttachment();
      const opened = openOn(attachment);
      expect(opened.ok).toBe(true);
      const open = socket.frames("terminal.open")[0];
      expect(open.fence.epoch).toBe(ok.connectionEpoch);
      manager.handleTextFrame(
        socket,
        JSON.stringify({
          type: "terminal.ready",
          requestId: open.requestId,
          fence: open.fence,
          rows: 24,
          cols: 80,
        }),
      );
      // No drain: the terminal lane is synchronous.
      expect(attachment.readies).toHaveLength(1);
      manager.handleBinaryFrame(
        socket,
        encodeTerminalDataFrame(
          { type: "terminal.data", fence: open.fence, sequence: 0 },
          new TextEncoder().encode("$ "),
        ),
      );
      expect(String.fromCharCode(...attachment.output)).toBe("$ ");
    },
  );

  it("WP8: without the terminalResume offer nothing is echoed and a resume is refused", async () => {
    const plain = await registered();
    expect(plain.frames("hello.ok")[0].capabilities).not.toHaveProperty("terminalResume");
    const v2 = Object.assign(new FakeAttachment(), { resumable: true as const });
    expect(
      manager.terminals.open({
        ownerId: "user-1",
        hostId: "host-1",
        sandboxId: "sbx-1",
        generation: 1,
        rows: 24,
        cols: 80,
        attachment: v2,
        resume: { terminalId: `t${"f".repeat(32)}`, nextOutputSeq: 0 },
      }),
    ).toMatchObject({ ok: false, error: { code: "unsupported_capability" } });
    expect(plain.frames("terminal.resume")).toEqual([]);
  });

  it("WP8: terminalResume is echoed when offered; resume waits for reconcile.complete", async () => {
    const socket = new FakeSocket();
    manager.acceptAuthenticatedSocket({
      socket,
      identity: {
        hostId: "host-1",
        userId: "user-1",
        tokenId: "token-1",
        credentialKind: "hostToken" as const,
        expiresAt: null,
      },
    });
    const offer = helloFixture("host-1", true);
    offer.daemon.capabilities.terminalResume = { graceMs: 300_000 };
    manager.handleTextFrame(socket, JSON.stringify(offer));
    await manager.drain(socket);
    expect(socket.frames("hello.ok")[0].capabilities.terminalResume).toBe(true);
    const resume = () =>
      manager.terminals.open({
        ownerId: "user-1",
        hostId: "host-1",
        sandboxId: "sbx-1",
        generation: 1,
        rows: 24,
        cols: 80,
        attachment: Object.assign(new FakeAttachment(), { resumable: true as const }),
        resume: { terminalId: `t${"f".repeat(32)}`, nextOutputSeq: 2 },
      });
    expect(resume()).toMatchObject({ ok: false, error: { code: "disconnected" } });
    expect(socket.frames("terminal.resume")).toEqual([]);
    for (const page of runningCensusFrames(store, "host-1", true))
      manager.handleTextFrame(socket, page);
    manager.handleTextFrame(socket, JSON.stringify({ type: "reconcile.complete" }));
    await manager.drain(socket);
    expect(resume()).toMatchObject({ ok: true });
    expect(socket.frames("terminal.resume")[0]).toMatchObject({
      fence: { sessionId: `t${"f".repeat(32)}` },
      nextOutputSeq: 2,
    });
    // A v2 terminal on this node reconnects when the relay drops.
    const live = Object.assign(new FakeAttachment(), { resumable: true as const });
    const second = manager.terminals.open({
      ownerId: "user-1",
      hostId: "host-1",
      sandboxId: "sbx-2",
      generation: 1,
      rows: 24,
      cols: 80,
      attachment: live,
    });
    expect(second.ok).toBe(true);
    const open = socket.frames("terminal.open").at(-1);
    manager.handleTextFrame(
      socket,
      JSON.stringify({
        type: "terminal.ready",
        requestId: open.requestId,
        fence: open.fence,
        rows: 24,
        cols: 80,
      }),
    );
    manager.removeSession(socket);
    expect(live.closes).toEqual([
      {
        code: 4401,
        intent: "host_disconnected",
        reconnect: { terminalId: open.fence.sessionId, graceMs: 300_000 },
      },
    ]);
  });

  it("integ review P2c: a quiescing host refuses fresh opens but still serves a resume", async () => {
    const socket = new FakeSocket();
    manager.acceptAuthenticatedSocket({
      socket,
      identity: {
        hostId: "host-1",
        userId: "user-1",
        tokenId: "token-1",
        credentialKind: "hostToken" as const,
        expiresAt: null,
      },
    });
    const offer = helloFixture("host-1", true);
    offer.daemon.capabilities.terminalResume = { graceMs: 300_000 };
    offer.daemon.capabilities.quiesce = true;
    manager.handleTextFrame(socket, JSON.stringify(offer));
    await manager.drain(socket);
    const ok = socket.frames("hello.ok")[0];
    expect(ok.capabilities.quiesce).toBe(true);
    for (const page of runningCensusFrames(store, "host-1", true))
      manager.handleTextFrame(socket, page);
    manager.handleTextFrame(socket, JSON.stringify({ type: "reconcile.complete" }));
    manager.handleTextFrame(
      socket,
      JSON.stringify({ type: "host.quiesce", connectionEpoch: ok.connectionEpoch, sequence: 1 }),
    );
    await manager.drain(socket);
    expect(socket.frames("host.quiesce.ack")).toHaveLength(1);
    const request = (sandboxId: string, resume?: { terminalId: string; nextOutputSeq: number }) =>
      manager.terminals.open({
        ownerId: "user-1",
        hostId: "host-1",
        sandboxId,
        generation: 1,
        rows: 24,
        cols: 80,
        attachment: Object.assign(new FakeAttachment(), { resumable: true as const }),
        ...(resume ? { resume } : {}),
      });
    expect(request("sbx-2")).toMatchObject({ ok: false, error: { code: "disconnected" } });
    expect(socket.frames("terminal.open")).toEqual([]);
    expect(request("sbx-1", { terminalId: `t${"f".repeat(32)}`, nextOutputSeq: 2 })).toMatchObject({
      ok: true,
    });
    expect(socket.frames("terminal.resume")[0]).toMatchObject({
      fence: { sessionId: `t${"f".repeat(32)}` },
      nextOutputSeq: 2,
    });
  });

  it.each(["host.admission", "availability.result"])(
    "refuses %s from a session with an unsupported stored version",
    async (type) => {
      const socket = await registered(["1.0"]);
      const sessions = Reflect.get(manager, "sessionsBySocket") as Map<
        FakeSocket,
        { protocolVersion: string }
      >;
      sessions.get(socket)!.protocolVersion = "10.7";
      const frame =
        type === "host.admission"
          ? {
              type,
              connectionEpoch: 1,
              runtimeKind: "fake",
              schedulable: true,
              egressPolicy: false,
              _terminal: true,
            }
          : { type, requestId: "not-requested", page: 0, connectionEpoch: 1, entries: [] };
      manager.handleTextFrame(socket, JSON.stringify(frame));
      await manager.drain(socket);
      expect(socket.readyState).toBe(3);
      expect(manager.isHostConnected("host-1")).toBe(false);
    },
  );

  it("heartbeats and cancellation progress while the PTY floods output", async () => {
    const socket = await registered();
    const attachment = new FakeAttachment();
    expect(openOn(attachment).ok).toBe(true);
    const open = socket.frames("terminal.open")[0];
    manager.handleTextFrame(
      socket,
      JSON.stringify({
        type: "terminal.ready",
        requestId: open.requestId,
        fence: open.fence,
        rows: 24,
        cols: 80,
      }),
    );
    // Make every serialized control frame slow (per-frame authority IO).
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.mocked(revalidateSandboxHostIdentity).mockImplementation(async () => {
      await gate;
      return { status: "active", hostDeletionRequested: false };
    });
    manager.handleTextFrame(socket, JSON.stringify({ type: "heartbeat", id: "hb-flood" }));
    const flood = SANDBOX_RECEIVE_MAX_FRAMES + 64;
    const chunk = new Uint8Array(TERMINAL_LIMITS.dataMaxBytes).fill(121);
    for (let sequence = 0; sequence < flood; sequence += 1)
      manager.handleBinaryFrame(
        socket,
        encodeTerminalDataFrame({ type: "terminal.data", fence: open.fence, sequence }, chunk),
      );
    // More frames than the serialized receive queue admits, none queued:
    // every byte is delivered in order and the host socket stays open.
    expect(socket.closes).toEqual([]);
    expect(attachment.output.length).toBe(flood * chunk.byteLength);
    expect(socket.frames("terminal.ack")).toHaveLength(flood);
    const cancel = manager.cancelOperation(
      "host-1",
      "op-1",
      1,
      1,
      store.hosts.get("host-1")!.connectionEpoch,
      { kind: "session" },
    );
    release();
    await manager.drain(socket);
    expect(await cancel).toBe(true);
    expect(socket.frames("heartbeat.pong").map((f) => f.id)).toContain("hb-flood");
    expect(socket.frames("operation.cancel")).toHaveLength(1);
  });

  it("host socket replacement ends every terminal session with 4401", async () => {
    const socket = await registered();
    const attachment = new FakeAttachment();
    expect(openOn(attachment).ok).toBe(true);
    const replacement = await registered();
    expect(socket.closes.length).toBeGreaterThan(0);
    expect(attachment.closes).toEqual([{ code: 4401, intent: "host_disconnected" }]);
    const open = socket.frames("terminal.open")[0];
    manager.handleTextFrame(
      replacement,
      JSON.stringify({
        type: "terminal.ready",
        requestId: open.requestId,
        fence: open.fence,
        rows: 24,
        cols: 80,
      }),
    );
    expect(attachment.readies).toEqual([]);
  });
  async function openReady() {
    const socket = await registered();
    const attachment = new FakeAttachment();
    const opened = openOn(attachment);
    if (!opened.ok) throw new Error(JSON.stringify(opened.error));
    const open = socket.frames("terminal.open")[0];
    manager.handleTextFrame(
      socket,
      JSON.stringify({
        type: "terminal.ready",
        requestId: open.requestId,
        fence: open.fence,
        rows: 24,
        cols: 80,
      }),
    );
    expect(attachment.readies).toHaveLength(1);
    return { socket, attachment, handle: opened.session, fence: open.fence as TerminalFence };
  }
  const output = (socket: FakeSocket, fence: TerminalFence, sequence: number, text: string) =>
    manager.handleBinaryFrame(
      socket,
      encodeTerminalDataFrame(
        { type: "terminal.data", fence, sequence },
        new TextEncoder().encode(text),
      ),
    );
  const text = (attachment: FakeAttachment) => String.fromCharCode(...attachment.output);
  const settled = () => new Promise((resolve) => setTimeout(resolve, 20));

  it("C52-CO-1: a live terminal survives an unrelated owner authority change", async () => {
    const { socket, attachment, fence } = await openReady();
    output(socket, fence, 0, "a");
    // Frames arriving while the change is in flight are held, not dropped.
    const change = holdChange({ ownerId: "user-1" });
    output(socket, fence, 1, "b");
    output(socket, fence, 2, "c");
    await settled();
    expect(text(attachment)).toBe("a");
    change.settle();
    await settled();
    expect(text(attachment)).toBe("abc");
    // And after a completed change (e.g. the owner toggling 2FA).
    await withAuthorityChange({ ownerId: "user-1" }, async () => {});
    await settled();
    output(socket, fence, 3, "d");
    output(socket, fence, 4, "e");
    expect(text(attachment)).toBe("abcde");
    expect(attachment.closes).toEqual([]);
    expect(socket.closes).toEqual([]);
    expect(socket.frames("terminal.close")).toEqual([]);
    expect(socket.frames("terminal.ack").map((f) => f.sequence)).toEqual([0, 1, 2, 3, 4]);
  });

  it("C52-CO-1: terminal.exit after a global admin write closes the attachment and releases counts", async () => {
    const { socket, attachment, fence } = await openReady();
    let exitDuringChange = () => {};
    await withGlobalAuthorityChange(async () => {
      exitDuringChange();
    });
    await settled();
    // Exit right after a completed global change.
    manager.handleTextFrame(
      socket,
      JSON.stringify({ type: "terminal.exit", fence, exitCode: 0, reaped: true }),
    );
    expect(attachment.closes).toEqual([{ code: 4401, exitCode: 0 }]);
    expect(manager.terminals.sessionCount()).toBe(0);
    // Exit while a global change is in flight: held, then delivered on commit.
    const second = new FakeAttachment();
    expect(openOn(second).ok).toBe(true);
    const open2 = socket.frames("terminal.open")[1];
    manager.handleTextFrame(
      socket,
      JSON.stringify({
        type: "terminal.ready",
        requestId: open2.requestId,
        fence: open2.fence,
        rows: 24,
        cols: 80,
      }),
    );
    exitDuringChange = () =>
      manager.handleTextFrame(
        socket,
        JSON.stringify({ type: "terminal.exit", fence: open2.fence, exitCode: 7, reaped: true }),
      );
    await withGlobalAuthorityChange(async () => {
      exitDuringChange();
      expect(second.closes).toEqual([]);
    });
    await settled();
    expect(second.closes).toEqual([{ code: 4401, exitCode: 7 }]);
    expect(manager.terminals.sessionCount()).toBe(0);
    expect(socket.closes).toEqual([]);
    // Capacity was released: the sandbox can open again.
    expect(openOn().ok).toBe(true);
  });

  it("C52-TB-1: input and resizes under a stale ticket are held, then sent in order", async () => {
    const { socket, handle } = await openReady();
    const change = holdChange({ ownerId: "user-1" });
    expect(handle.input(new TextEncoder().encode("ls")).ok).toBe(true);
    expect(handle.resize(40, 100).ok).toBe(true);
    expect(handle.input(new TextEncoder().encode("\n")).ok).toBe(true);
    expect(socket.input()).toEqual([]);
    expect(socket.frames("terminal.resize")).toEqual([]);
    change.settle();
    await settled();
    expect(
      socket.input().map((f) => [f.metadata.sequence, new TextDecoder().decode(f.body)]),
      // Held input is coalesced in order (C52-F-1): one frame, nothing lost.
    ).toEqual([[0, "ls\n"]]);
    expect(socket.frames("terminal.resize")).toEqual([
      expect.objectContaining({ rows: 40, cols: 100 }),
    ]);
  });

  it("C52-TB-1: a revoked host receives zero input bytes and delivers zero output bytes, then closes", async () => {
    const { socket, attachment, handle, fence } = await openReady();
    // Every revalidation (commit listener, held-frame refresh) waits on the DB read.
    const pending: Array<(value: { status: "inactive" }) => void> = [];
    const finish = (status: "inactive") => {
      for (const resolve of pending.splice(0)) resolve({ status });
    };
    vi.mocked(revalidateSandboxHostIdentity).mockImplementation(
      () => new Promise((resolve) => pending.push(resolve)),
    );
    const revocation = holdChange({ ownerId: "user-1", credentialId: "token-1" });
    expect(handle.input(new Uint8Array(16 * 1024).fill(65)).ok).toBe(true);
    // The revocation commits; its revalidation is still in flight.
    revocation.settle();
    await settled();
    for (let i = 0; i < 12; i += 1) handle.input(new Uint8Array(16 * 1024).fill(66));
    expect(handle.resize(30, 90).ok).toBe(true);
    output(socket, fence, 0, "secret");
    manager.handleTextFrame(
      socket,
      JSON.stringify({ type: "terminal.exit", fence, exitCode: 0, reaped: true }),
    );
    expect(socket.input()).toEqual([]);
    expect(socket.frames("terminal.resize")).toEqual([]);
    expect(attachment.output).toEqual([]);
    expect(attachment.closes).toEqual([]);
    finish("inactive");
    await settled();
    expect(socket.closes[0]).toEqual({ code: 4003, reason: "credential_inactive" });
    // C52-R2-1: the HOST lost its authority; the browser is not told to sign in again.
    expect(attachment.closes).toEqual([
      { code: 4401, intent: "host_disconnected", error: HOST_CREDENTIAL_INACTIVE_ERROR },
    ]);
    expect(manager.terminals.sessionCount()).toBe(0);
    expect(socket.input()).toEqual([]);
    expect(socket.frames("terminal.resize")).toEqual([]);
    expect(attachment.output).toEqual([]);
  });

  it("C55 shutdown ordering: each PTY is asked to close before the socket closes; counters reach zero", async () => {
    const { socket, attachment } = await openReady();
    const log: string[] = [];
    const send = socket.send.bind(socket);
    socket.send = (data) => {
      if (typeof data === "string") log.push(JSON.parse(data).type);
      send(data);
    };
    const close = socket.close.bind(socket);
    socket.close = (code, reason) => {
      log.push(`close:${code}`);
      close(code, reason);
    };
    manager.dispose();
    expect(socket.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "shutdown" }),
    ]);
    // The socket itself closes only after the terminal close was sent.
    expect(log).toEqual(["terminal.close", "close:1001"]);
    expect(socket.closes).toEqual([{ code: 1001, reason: "session_removed" }]);
    expect(attachment.closes).toEqual([{ code: 4401, intent: "shutdown" }]);
    expectNoTerminalResources(manager.terminals, { hostSockets: 0, timers: false });
  });

  it("held terminal frames are bounded: a host ignoring its windows is a protocol error", async () => {
    const { socket, attachment, fence } = await openReady();
    const change = holdChange({ ownerId: "user-1" });
    for (let sequence = 0; sequence < TERMINAL_HOLD_MAX_FRAMES; sequence += 1)
      output(socket, fence, sequence, "x");
    expect(socket.closes).toEqual([]);
    output(socket, fence, TERMINAL_HOLD_MAX_FRAMES, "x");
    expect(socket.closes).toEqual([{ code: 1002, reason: "protocol_error" }]);
    expect(attachment.closes).toEqual([{ code: 4401, intent: "host_disconnected" }]);
    expect(attachment.output).toEqual([]);
    change.settle();
    await settled();
    expect(attachment.output).toEqual([]);
  });
});

describe("T1 typed host target (unit; T2 owns durable browser grants)", () => {
  it("keeps guest and host targets separate and refuses stale policy before replacing", () => {
    const socket = new FakeSocket();
    const policy = { hostTerminal: true, requireHostTerminalTotp: false, policyRevision: 1 };
    const manager = new SandboxTerminalManager({
      terminalHost: () => ({
        link: {
          socket,
          hostId: "host",
          ownerId: "owner",
          epoch: 1,
          protocolVersion: "1.0",
          authorized: () => true,
          hostPolicy: policy,
        },
      }),
      closeHostSocket: vi.fn(),
    });
    const hostAttachment = new FakeAttachment();
    const guestAttachment = new FakeAttachment();
    const host = manager.open({
      ownerId: "owner",
      hostId: "host",
      target: { kind: "host" },
      hostPolicy: { policyRevision: 1, proofRequired: false },
      rows: 24,
      cols: 80,
      attachment: hostAttachment,
    });
    const guest = manager.open({
      ownerId: "owner",
      hostId: "host",
      sandboxId: "sandbox",
      generation: 1,
      rows: 24,
      cols: 80,
      attachment: guestAttachment,
    });
    expect(host.ok && guest.ok).toBe(true);
    const hostFence = socket.frames("terminal.open")[0].fence as TerminalFence;
    expect(hostFence.target).toEqual({ kind: "host" });
    expect(
      manager.open({
        ownerId: "owner",
        hostId: "host",
        target: { kind: "host" },
        hostPolicy: { policyRevision: 0, proofRequired: false },
        rows: 24,
        cols: 80,
        attachment: new FakeAttachment(),
      }),
    ).toMatchObject({ ok: false, error: { code: "access_denied" } });
    expect(hostAttachment.closes).toEqual([]);
    manager.closeSandbox("sandbox", "sandbox_stopped");
    expect(hostAttachment.closes).toEqual([]);
    expect(guestAttachment.closes).toHaveLength(1);
    policy.policyRevision = 2;
    policy.requireHostTerminalTotp = true;
    manager.closeHostTarget("host", "host_terminals_disabled");
    expect(hostAttachment.closes).toMatchObject([
      { intent: "revoked", reason: "host_terminals_disabled" },
    ]);
    // Both closing slots remain counted until confirmed reap.
    expect(manager.sessionCount(socket)).toBe(2);
    manager.removeHostSocket(socket);
    expect(manager.sessionCount()).toBe(0);
  });
});

describe("WP8 terminal reattach (v1/v2, resume gate, host target)", () => {
  let host: FakeSocket;
  let manager: SandboxTerminalManager;
  let graceMs: number | undefined;
  const link = (): TerminalHostLink => ({
    socket: host,
    hostId: "host-1",
    ownerId: "owner-1",
    epoch: 7,
    protocolVersion: "1.0",
    ...(graceMs === undefined ? {} : { resumeGraceMs: graceMs }),
    authorized: () => true,
  });
  class V2Attachment extends FakeAttachment {
    readonly resumable = true;
    resumeInfo: unknown[] = [];
    override ready(size: { rows: number; cols: number }, resume?: unknown) {
      super.ready(size);
      this.resumeInfo.push(resume);
    }
  }
  beforeEach(() => {
    host = new FakeSocket();
    graceMs = 120_000;
    manager = new SandboxTerminalManager({
      terminalHost: () => ({ link: link() }),
      closeHostSocket: () => {},
    });
  });
  const TERMINAL_ID = `t${"a".repeat(32)}`;

  function open(
    attachment: FakeAttachment,
    resume?: { terminalId: string; nextOutputSeq: number },
  ) {
    return manager.open({
      ownerId: "owner-1",
      hostId: "host-1",
      sandboxId: "sbx-1",
      generation: 3,
      rows: 24,
      cols: 80,
      attachment,
      ...(resume ? { resume } : {}),
    });
  }
  function answer(fence: TerminalFence, requestId: string, outputSeq?: number) {
    manager.handleHostControl(host, {
      type: "terminal.ready",
      requestId,
      fence,
      rows: 24,
      cols: 80,
      ...(outputSeq === undefined ? {} : { outputSeq }),
    });
  }

  it("v1 attachments behave as before: no resume info, a relay drop is final", () => {
    const attachment = new FakeAttachment();
    expect(open(attachment).ok).toBe(true);
    const frame = host.frames("terminal.open")[0];
    answer(frame.fence, frame.requestId);
    expect(attachment.readies).toEqual([{ rows: 24, cols: 80 }]);
    manager.removeHostSocket(host);
    expect(attachment.closes).toEqual([{ code: 4401, intent: "host_disconnected" }]);
    expect(manager.sessionCount()).toBe(0);
  });

  it("v2 without the node's capability behaves exactly as v1", () => {
    graceMs = undefined;
    const attachment = new V2Attachment();
    expect(open(attachment).ok).toBe(true);
    const frame = host.frames("terminal.open")[0];
    answer(frame.fence, frame.requestId);
    expect(attachment.resumeInfo).toEqual([undefined]);
    manager.removeHostSocket(host);
    expect(attachment.closes).toEqual([{ code: 4401, intent: "host_disconnected" }]);
    expect(open(new V2Attachment(), { terminalId: TERMINAL_ID, nextOutputSeq: 0 })).toMatchObject({
      ok: false,
      error: { code: "unsupported_capability" },
    });
  });

  it("v2 on a resume-capable node learns its id and reconnects instead of ending", () => {
    const attachment = new V2Attachment();
    expect(open(attachment).ok).toBe(true);
    const frame = host.frames("terminal.open")[0];
    answer(frame.fence, frame.requestId);
    expect(attachment.resumeInfo).toEqual([{ terminalId: frame.fence.sessionId, outputSeq: 0 }]);
    manager.handleHostData(
      host,
      { type: "terminal.data", fence: frame.fence, sequence: 0 },
      new TextEncoder().encode("x"),
    );
    manager.removeHostSocket(host);
    expect(attachment.closes).toEqual([
      {
        code: 4401,
        intent: "host_disconnected",
        reconnect: { terminalId: frame.fence.sessionId, graceMs: 120_000 },
      },
    ]);
    // The PTY is never asked to close: the node keeps it detached.
    expect(host.frames("terminal.close")).toEqual([]);
    expect(manager.sessionCount()).toBe(0);
  });

  it("a credential-inactive host loss and an unanswered fresh open are still final", () => {
    const first = new V2Attachment();
    open(first);
    const frame = host.frames("terminal.open")[0];
    answer(frame.fence, frame.requestId);
    manager.removeHostSocket(host, "host_disconnected", false, HOST_CREDENTIAL_INACTIVE_ERROR);
    expect(first.closes[0]?.reconnect).toBeUndefined();
    host = new FakeSocket();
    const opening = new V2Attachment();
    open(opening);
    manager.removeHostSocket(host);
    expect(opening.closes).toEqual([{ code: 4401, intent: "host_disconnected" }]);
  });

  it("graceful shutdown leaves a resumable PTY to the node and closes the rest", () => {
    const resumable = new V2Attachment();
    const resumableOpen = open(resumable);
    const frame = host.frames("terminal.open")[0];
    answer(frame.fence, frame.requestId);
    if (!resumableOpen.ok) throw new Error("open failed");
    resumableOpen.session.close("shutdown");
    expect(resumable.closes).toEqual([
      {
        code: 4401,
        intent: "shutdown",
        reconnect: { terminalId: frame.fence.sessionId, graceMs: 120_000 },
      },
    ]);
    expect(host.frames("terminal.close")).toEqual([]);
    // A non-shutdown close of a resumable session still closes the PTY.
    const other = new V2Attachment();
    const otherOpen = open(other);
    const otherFrame = host.frames("terminal.open")[1];
    answer(otherFrame.fence, otherFrame.requestId);
    if (!otherOpen.ok) throw new Error("open failed");
    otherOpen.session.close("client");
    expect(host.frames("terminal.close")).toHaveLength(1);
    expect(other.closes[0]?.reconnect).toBeUndefined();
  });

  it("a resume sends terminal.resume under the new fence and resumes output at outputSeq", () => {
    const attachment = new V2Attachment();
    expect(open(attachment, { terminalId: TERMINAL_ID, nextOutputSeq: 41 }).ok).toBe(true);
    expect(host.frames("terminal.open")).toEqual([]);
    const [frame] = host.frames("terminal.resume");
    expect(frame).toMatchObject({
      fence: {
        sessionId: TERMINAL_ID,
        hostId: "host-1",
        epoch: 7,
        target: { kind: "sandbox", sandboxId: "sbx-1", generation: 3 },
      },
      nextOutputSeq: 41,
      rows: 24,
      cols: 80,
    });
    answer(frame.fence, frame.requestId, 44);
    expect(attachment.resumeInfo).toEqual([{ terminalId: TERMINAL_ID, outputSeq: 44 }]);
    const fence = frame.fence as TerminalFence;
    manager.handleHostData(
      host,
      { type: "terminal.data", fence, sequence: 44 },
      new TextEncoder().encode("ok"),
    );
    expect(attachment.output).toEqual([...new TextEncoder().encode("ok")]);
    expect(host.frames("terminal.ack").at(-1)).toMatchObject({ sequence: 44 });
    // Input restarts at 0 on the new fence (never replayed).
    const handle = manager.sessionFence(TERMINAL_ID);
    expect(handle?.operationId).toBe(fence.operationId);
  });

  it("refuses a resume answer that rewinds output or omits outputSeq, and an open answer with one", () => {
    const rewound = new V2Attachment();
    open(rewound, { terminalId: TERMINAL_ID, nextOutputSeq: 41 });
    const frame = host.frames("terminal.resume")[0];
    answer(frame.fence, frame.requestId, 40);
    expect(rewound.closes[0]).toMatchObject({
      intent: "protocol_violation",
      error: { code: "protocol_error" },
    });
    const bare = new V2Attachment();
    open(bare, { terminalId: `t${"b".repeat(32)}`, nextOutputSeq: 0 });
    const bareFrame = host.frames("terminal.resume")[1];
    answer(bareFrame.fence, bareFrame.requestId);
    expect(bare.closes[0]).toMatchObject({ intent: "protocol_violation" });
    host = new FakeSocket();
    const fresh = new V2Attachment();
    open(fresh);
    const openFrame = host.frames("terminal.open")[0];
    answer(openFrame.fence, openFrame.requestId, 0);
    expect(fresh.closes[0]).toMatchObject({ intent: "protocol_violation" });
  });

  it("the resume gate: v1 attachment, foreign id, live id and the node's refusal", () => {
    expect(open(new FakeAttachment(), { terminalId: TERMINAL_ID, nextOutputSeq: 0 })).toMatchObject(
      { ok: false, error: { code: "unsupported_capability" } },
    );
    for (const terminalId of ["t1", "host-term", `T${"a".repeat(32)}`, `t${"a".repeat(33)}`])
      expect(open(new V2Attachment(), { terminalId, nextOutputSeq: 0 })).toMatchObject({
        ok: false,
        error: { code: "protocol_error" },
      });
    expect(open(new V2Attachment(), { terminalId: TERMINAL_ID, nextOutputSeq: -1 })).toMatchObject({
      ok: false,
      error: { code: "protocol_error" },
    });
    const live = new V2Attachment();
    expect(open(live, { terminalId: TERMINAL_ID, nextOutputSeq: 0 }).ok).toBe(true);
    expect(open(new V2Attachment(), { terminalId: TERMINAL_ID, nextOutputSeq: 0 })).toMatchObject({
      ok: false,
      error: { code: "state_conflict" },
    });
    // The node no longer has the PTY: its exit ends the resume finally.
    const frame = host.frames("terminal.resume")[0];
    manager.handleHostControl(host, {
      type: "terminal.exit",
      requestId: frame.requestId,
      fence: frame.fence,
      reaped: true,
      error: { code: "sandbox_not_found", message: "terminal not found" },
    });
    expect(live.closes).toEqual([
      { code: 4401, error: { code: "sandbox_not_found", message: "terminal not found" } },
    ]);
  });

  it("a resume still waiting for its answer reconnects again on another relay drop", () => {
    const attachment = new V2Attachment();
    open(attachment, { terminalId: TERMINAL_ID, nextOutputSeq: 3 });
    manager.removeHostSocket(host);
    expect(attachment.closes).toEqual([
      {
        code: 4401,
        intent: "host_disconnected",
        reconnect: { terminalId: TERMINAL_ID, graceMs: 120_000 },
      },
    ]);
  });

  it("host-target terminals are never resumable and never reconnect", () => {
    const hostLink = {
      ...link(),
      hostPolicy: { hostTerminal: true, requireHostTerminalTotp: false, policyRevision: 1 },
    };
    manager = new SandboxTerminalManager({
      terminalHost: () => ({ link: hostLink }),
      closeHostSocket: () => {},
    });
    const base = {
      ownerId: "owner-1",
      hostId: "host-1",
      target: { kind: "host" } as const,
      hostPolicy: { policyRevision: 1, proofRequired: false },
      rows: 24,
      cols: 80,
    };
    expect(
      manager.open({
        ...base,
        attachment: new V2Attachment(),
        resume: { terminalId: TERMINAL_ID, nextOutputSeq: 0 },
      } as never),
    ).toMatchObject({ ok: false, error: { code: "unsupported_capability" } });
    expect(host.frames("terminal.resume")).toEqual([]);
    const attachment = new V2Attachment();
    expect(manager.open({ ...base, attachment }).ok).toBe(true);
    const frame = host.frames("terminal.open")[0];
    answer(frame.fence, frame.requestId);
    expect(attachment.resumeInfo).toEqual([undefined]);
    manager.removeHostSocket(host);
    expect(attachment.closes).toEqual([{ code: 4401, intent: "host_disconnected" }]);
  });
});
