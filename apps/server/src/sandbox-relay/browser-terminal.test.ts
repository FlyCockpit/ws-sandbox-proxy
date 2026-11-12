import { notifySandboxTerminalLifecycle } from "@wssp/api/sandbox/terminal-lifecycle";
import type {
  checkBrowserTerminalBinding as checkTerminalBinding,
  TerminalBinding,
  TerminalRevocation,
} from "@wssp/api/sandbox/terminal-tickets";
import { holdAuthorityChange, withAuthorityChange } from "@wssp/db/authority";
import { notifyAuthSessionsRevoked } from "@wssp/db/session-revocation";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  BROWSER_TERMINAL_RACED_OPEN_READS,
  type BrowserSocket,
  BrowserTerminalService,
} from "./browser-terminal.js";
import { parseTerminalDataFrame, type TerminalFence } from "./protocol.js";
import {
  HOST_CREDENTIAL_INACTIVE_ERROR,
  SandboxTerminalManager,
  type TerminalHostLink,
} from "./terminal-manager.js";
import { expectNoTerminalResources } from "./terminal-resources-harness.js";

vi.mock("@wssp/env/server", () => ({ env: { BETTER_AUTH_SECRET: "c53-browser-terminal" } }));
vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
vi.mock("@wssp/api/lib/host-token-access", () => ({
  revalidateSandboxHostIdentity: vi
    .fn()
    .mockResolvedValue({ status: "active", hostDeletionRequested: false }),
}));

/** The host relay socket: every terminal frame the host would act on. */
class FakeHost {
  readyState = 1;
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
    return this.binary.map((frame) => parseTerminalDataFrame(frame)!);
  }
}

/** The upgraded browser socket. */
class FakeBrowser implements BrowserSocket {
  readyState = 1;
  bufferedAmount = 0;
  text: Record<string, unknown>[] = [];
  output: string[] = [];
  closes: { code: number; reason: string }[] = [];
  pings = 0;
  throwOnSend = false;
  ping() {
    this.pings += 1;
  }
  send(data: string | Uint8Array) {
    if (this.throwOnSend) throw new Error("browser transport failed");
    if (typeof data === "string") this.text.push(JSON.parse(data));
    else this.output.push(new TextDecoder().decode(data));
  }
  close(code: number, reason: string) {
    this.closes.push({ code, reason });
    this.readyState = 3;
  }
  frames(type: string) {
    return this.text.filter((frame) => frame.type === type);
  }
}

const binding: TerminalBinding = {
  userId: "owner-1",
  sessionId: "auth-session-1",
  sandboxId: "sbx-1",
  hostId: "host-1",
  generation: 3,
  rows: 24,
  cols: 80,
};

let host: FakeHost;
let manager: SandboxTerminalManager;
let verdict:
  | { ok: true; grant?: import("@wssp/api/sandbox/terminal-tickets").GuestTerminalGrant }
  | { ok: false; intent: TerminalRevocation };
let check: ReturnType<typeof vi.fn<typeof checkTerminalBinding>>;
let service: BrowserTerminalService;

const link = (): TerminalHostLink => ({
  socket: host,
  hostId: "host-1",
  ownerId: "owner-1",
  epoch: 9,
  protocolVersion: "1.0",
  authorized: () => true,
});

beforeEach(() => {
  vi.useFakeTimers();
  host = new FakeHost();
  manager = new SandboxTerminalManager({
    terminalHost: () => ({ link: link() }),
    closeHostSocket: () => undefined,
  });
  verdict = { ok: true };
  check = vi.fn<typeof checkTerminalBinding>(async () => verdict);
  service = new BrowserTerminalService(() => manager, check, 15_000);
});
afterEach(() => {
  service.dispose();
  vi.useRealTimers();
});

async function flush() {
  for (let i = 0; i < 10; i += 1) await Promise.resolve();
}

async function attach(b = binding) {
  const browser = new FakeBrowser();
  const terminal = service.attach(b);
  terminal.opened(browser);
  await flush();
  return { browser, terminal };
}

function readyHost() {
  const open = host.frames("terminal.open").at(-1);
  manager.handleHostControl(host, {
    type: "terminal.ready",
    requestId: open.requestId,
    fence: open.fence as TerminalFence,
    rows: open.rows,
    cols: open.cols,
  });
  return open.fence as TerminalFence;
}

async function attached() {
  const opened = await attach();
  const fence = readyHost();
  return { ...opened, fence };
}

describe("post-upgrade re-read before any PTY", () => {
  it("opens the PTY only from the server-side binding after the re-read passes", async () => {
    const { browser } = await attach();
    expect(check).toHaveBeenCalledTimes(1);
    const [open] = host.frames("terminal.open");
    expect(open).toMatchObject({
      rows: 24,
      cols: 80,
      fence: {
        hostId: "host-1",
        target: { kind: "sandbox", sandboxId: "sbx-1", generation: 3 },
        epoch: 9,
      },
    });
    readyHost();
    expect(browser.frames("ready")).toEqual([{ type: "ready", rows: 24, cols: 80 }]);
  });

  it.each(["revoked", "sandbox_stopped", "superseded"] as const)(
    "a re-read answering %s closes 4401 with that intent and opens NO PTY",
    async (intent) => {
      verdict = { ok: false, intent };
      const { browser } = await attach();
      expect(host.frames("terminal.open")).toEqual([]);
      expect(browser.frames("close")).toEqual([{ type: "close", code: 4401, intent }]);
      expect(browser.closes).toEqual([{ code: 4401, reason: intent }]);
      expect(service.count()).toBe(0);
    },
  );

  it("a re-read error fails closed (lifecycle_unconfirmed), no PTY", async () => {
    check.mockRejectedValueOnce(new Error("db down"));
    const { browser } = await attach();
    expect(host.frames("terminal.open")).toEqual([]);
    expect(browser.frames("close")[0]).toMatchObject({ intent: "lifecycle_unconfirmed" });
  });

  it("an owner authority change racing the re-read forces another re-read before the open", async () => {
    let release!: () => void;
    check.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ ok: true });
        }),
    );
    const browser = new FakeBrowser();
    service.attach(binding).opened(browser);
    await flush();
    // The ban commits while the first read is in flight: that read must not be trusted.
    const ban = holdAuthorityChange({ ownerId: "owner-1" });
    verdict = { ok: false, intent: "revoked" };
    release();
    await flush();
    ban.settle();
    await flush();
    expect(check.mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(host.frames("terminal.open")).toEqual([]);
    expect(browser.frames("close")[0]).toMatchObject({ intent: "revoked" });
  });

  it("browser frames before the terminal is ready act on nothing", async () => {
    let release!: () => void;
    check.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ ok: true });
        }),
    );
    const browser = new FakeBrowser();
    const terminal = service.attach(binding);
    terminal.opened(browser);
    terminal.message(new TextEncoder().encode("rm -rf /\n").buffer);
    terminal.message(JSON.stringify({ type: "resize", requestId: "r1", rows: 30, cols: 90 }));
    release();
    await flush();
    expect(host.input()).toEqual([]);
    expect(host.frames("terminal.resize")).toEqual([]);
    expect(browser.frames("error")).toEqual([
      { type: "error", code: "state_conflict" },
      { type: "error", code: "state_conflict", requestId: "r1" },
    ]);
  });
});

describe("revocation and lifecycle close attached sockets with 4401", () => {
  it("heartbeat re-read (fake clock) closes a session revoked without any notification", async () => {
    const { browser, fence } = await attached();
    verdict = { ok: false, intent: "revoked" };
    await vi.advanceTimersByTimeAsync(14_999);
    expect(browser.closes).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await flush();
    expect(browser.frames("close")).toEqual([{ type: "close", code: 4401, intent: "revoked" }]);
    expect(browser.closes).toEqual([{ code: 4401, reason: "revoked" }]);
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "revoked", fence }),
    ]);
  });

  it("logout (session rows deleted) re-reads immediately and closes", async () => {
    const { browser } = await attached();
    verdict = { ok: false, intent: "revoked" };
    notifyAuthSessionsRevoked({ userId: "owner-1" });
    await flush();
    expect(browser.frames("close")[0]).toMatchObject({ code: 4401, intent: "revoked" });
    expect(host.frames("terminal.close")).toHaveLength(1);
  });

  it("ban / 2FA change (owner authority commit) re-reads immediately and closes", async () => {
    const { browser } = await attached();
    verdict = { ok: false, intent: "revoked" };
    await withAuthorityChange({ ownerId: "owner-1" }, async () => undefined);
    await flush();
    await flush();
    expect(browser.frames("close")[0]).toMatchObject({ intent: "revoked" });
  });

  it.each(["sandbox_stopped", "sandbox_destroyed", "expired"] as const)(
    "committed lifecycle change → %s closes every terminal of the sandbox",
    async (intent) => {
      const { browser, fence } = await attached();
      verdict = { ok: false, intent };
      notifySandboxTerminalLifecycle({ sandboxIds: new Set(["sbx-1"]) });
      await flush();
      expect(browser.frames("close")).toEqual([{ type: "close", code: 4401, intent }]);
      expect(host.frames("terminal.close")).toEqual([expect.objectContaining({ intent, fence })]);
    },
  );

  it("a lifecycle change of another sandbox does not touch this one", async () => {
    await attached();
    const calls = check.mock.calls.length;
    notifySandboxTerminalLifecycle({ sandboxIds: new Set(["sbx-other"]) });
    await flush();
    expect(check.mock.calls.length).toBe(calls);
  });

  it("graceful shutdown closes with intent shutdown and asks the host to close", async () => {
    const { browser } = await attached();
    service.dispose();
    expect(browser.frames("close")).toEqual([{ type: "close", code: 4401, intent: "shutdown" }]);
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "shutdown" }),
    ]);
  });
});

/** A re-read held open until released (with the verdict current at release). */
function heldCheck() {
  const releases: (() => void)[] = [];
  check.mockImplementation(
    () =>
      new Promise((resolve) => {
        releases.push(() => resolve(verdict));
      }),
  );
  return {
    pending: () => releases.length,
    async releaseAll() {
      while (releases.length > 0) {
        releases.shift()!();
        await flush();
      }
    },
  };
}

describe("notifications are hints, never fail-closed authority (C53-CC-1)", () => {
  it("a burst of unscoped notifications during every re-read never closes a live terminal", async () => {
    const { browser } = await attached();
    const held = heldCheck();
    for (let round = 0; round < 6; round += 1) {
      notifyAuthSessionsRevoked({});
      await flush();
      // Another user's sign-outs keep arriving while each read is in flight.
      for (let i = 0; i < 12; i += 1) notifyAuthSessionsRevoked({});
      await flush();
      expect(held.pending()).toBe(1);
      await held.releaseAll();
    }
    await held.releaseAll();
    expect(browser.closes).toEqual([]);
    expect(browser.frames("close")).toEqual([]);
    expect(host.frames("terminal.close")).toEqual([]);
    expect(service.count()).toBe(1);
  });

  it("a notification racing EVERY consecutive read (3+ in a row) never closes a live terminal", async () => {
    const { browser } = await attached();
    let raced = 0;
    check.mockImplementation(async () => {
      // Another user's sign-out lands while each of the next 9 reads is in flight.
      if (raced < 9) {
        raced += 1;
        notifyAuthSessionsRevoked({});
      }
      return verdict;
    });
    notifyAuthSessionsRevoked({});
    for (let i = 0; i < 20; i += 1) await flush();
    expect(browser.closes).toEqual([]);
    expect(raced).toBe(9);
    expect(browser.frames("close")).toEqual([]);
    expect(host.frames("terminal.close")).toEqual([]);
    expect(service.count()).toBe(1);
  });

  it("notifications are coalesced: one read in flight, at most one re-run per read", async () => {
    await attached();
    const held = heldCheck();
    const before = check.mock.calls.length;
    for (let i = 0; i < 50; i += 1) notifyAuthSessionsRevoked({});
    await flush();
    expect(check.mock.calls.length).toBe(before + 1);
    await held.releaseAll();
    // The 49 notifications that raced the read produce exactly one re-read.
    expect(check.mock.calls.length).toBe(before + 2);
  });

  it("a notification racing the FIRST read delays the PTY until an unraced read, never ends it", async () => {
    const releases: (() => void)[] = [];
    check.mockImplementation(
      () =>
        new Promise((resolve) => {
          releases.push(() => resolve({ ok: true }));
        }),
    );
    const browser = new FakeBrowser();
    service.attach(binding).opened(browser);
    await flush();
    for (let i = 0; i < 3; i += 1) {
      expect(releases).toHaveLength(1);
      notifyAuthSessionsRevoked({});
      await flush();
      releases.shift()!();
      await flush();
      // That read was raced by a notification: no PTY yet, a re-run is in flight.
      expect(host.frames("terminal.open")).toEqual([]);
      expect(browser.closes).toEqual([]);
    }
    expect(releases).toHaveLength(1);
    releases.shift()!();
    await flush();
    expect(host.frames("terminal.open")).toHaveLength(1);
    expect(browser.closes).toEqual([]);
  });

  it("C53-N1: a hint racing EVERY pre-PTY read ends the terminal within the bound, no PTY ever", async () => {
    let reads = 0;
    check.mockImplementation(async () => {
      reads += 1;
      // A notification lands while every read is in flight, without end.
      notifyAuthSessionsRevoked({});
      return { ok: true };
    });
    const browser = new FakeBrowser();
    const terminal = service.attach(binding);
    terminal.opened(browser);
    for (let i = 0; i < 40; i += 1) await flush();
    expect(reads).toBe(BROWSER_TERMINAL_RACED_OPEN_READS);
    expect(host.frames("terminal.open")).toEqual([]);
    expect(browser.frames("close")).toEqual([
      { type: "close", code: 4401, intent: "lifecycle_unconfirmed" },
    ]);
    expect(browser.closes).toEqual([{ code: 4401, reason: "lifecycle_unconfirmed" }]);
    expect(terminal.closed).toBe(true);
    expectNoTerminalResources(manager, { service, hostSockets: 0 });
  });

  it("a verdict on a raced pre-PTY read wins over the raced-read cap, requestId echoed", async () => {
    let reads = 0;
    check.mockImplementation(async () => {
      reads += 1;
      notifyAuthSessionsRevoked({});
      // The K-th read is raced too, but it answers a revocation.
      return reads < BROWSER_TERMINAL_RACED_OPEN_READS
        ? { ok: true }
        : { ok: false, intent: "revoked" };
    });
    const browser = new FakeBrowser();
    service.attach(binding, "req-upgrade-1").opened(browser);
    for (let i = 0; i < 40; i += 1) await flush();
    expect(reads).toBe(BROWSER_TERMINAL_RACED_OPEN_READS);
    expect(host.frames("terminal.open")).toEqual([]);
    expect(browser.frames("close")).toEqual([
      { type: "close", code: 4401, intent: "revoked", requestId: "req-upgrade-1" },
    ]);
    expect(browser.closes).toEqual([{ code: 4401, reason: "revoked" }]);
  });

  it("the raced-read fail-closed is final: one CloseIntent, no re-read, no PTY after more hints and time", async () => {
    let reads = 0;
    check.mockImplementation(async () => {
      reads += 1;
      notifyAuthSessionsRevoked({});
      return { ok: true };
    });
    const browser = new FakeBrowser();
    const terminal = service.attach(binding, "req-upgrade-2");
    terminal.opened(browser);
    for (let i = 0; i < 40; i += 1) await flush();
    expect(terminal.closed).toBe(true);
    notifyAuthSessionsRevoked({});
    notifyAuthSessionsRevoked({ userId: "owner-1" });
    await vi.advanceTimersByTimeAsync(120_000);
    for (let i = 0; i < 10; i += 1) await flush();
    expect(reads).toBe(BROWSER_TERMINAL_RACED_OPEN_READS);
    expect(host.frames("terminal.open")).toEqual([]);
    expect(browser.frames("close")).toEqual([
      { type: "close", code: 4401, intent: "lifecycle_unconfirmed", requestId: "req-upgrade-2" },
    ]);
    expect(browser.closes).toEqual([{ code: 4401, reason: "lifecycle_unconfirmed" }]);
    expect(terminal.timers).toBe(0);
  });

  it("C53-N1 inverse: one raced read short of the bound, then an unraced read opens the PTY", async () => {
    let reads = 0;
    check.mockImplementation(async () => {
      reads += 1;
      if (reads < BROWSER_TERMINAL_RACED_OPEN_READS) notifyAuthSessionsRevoked({});
      return { ok: true };
    });
    const browser = new FakeBrowser();
    service.attach(binding).opened(browser);
    for (let i = 0; i < 40; i += 1) await flush();
    expect(reads).toBe(BROWSER_TERMINAL_RACED_OPEN_READS);
    expect(host.frames("terminal.open")).toHaveLength(1);
    expect(browser.closes).toEqual([]);
  });

  it("the victim's own revocation still closes at once despite the burst", async () => {
    const { browser } = await attached();
    const held = heldCheck();
    for (let i = 0; i < 12; i += 1) notifyAuthSessionsRevoked({});
    await flush();
    verdict = { ok: false, intent: "revoked" };
    notifyAuthSessionsRevoked({ userId: "owner-1" });
    await held.releaseAll();
    await held.releaseAll();
    expect(browser.frames("close")).toEqual([{ type: "close", code: 4401, intent: "revoked" }]);
    expect(host.frames("terminal.close")).toEqual([expect.objectContaining({ intent: "revoked" })]);
  });

  it("inverse: an owner authority change stale across every attempt still fails closed", async () => {
    const { browser } = await attached();
    const hold = holdAuthorityChange({ ownerId: "owner-1" });
    await withAuthorityChange({ ownerId: "owner-1" }, async () => undefined);
    await flush();
    await flush();
    hold.settle();
    await flush();
    expect(check.mock.calls.length).toBeGreaterThanOrEqual(1 + 3);
    expect(browser.frames("close")).toEqual([
      { type: "close", code: 4401, intent: "lifecycle_unconfirmed" },
    ]);
  });
});

describe("the re-read has a deadline (C53-CC-3)", () => {
  it("a hung re-read of an attached terminal fails closed at the deadline (fake clock)", async () => {
    service.dispose();
    service = new BrowserTerminalService(() => manager, check, 15_000, 5_000);
    const { browser, fence } = await attached();
    check.mockImplementation(() => new Promise(() => undefined));
    notifyAuthSessionsRevoked({ userId: "owner-1" });
    await flush();
    await vi.advanceTimersByTimeAsync(4_999);
    expect(browser.closes).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await flush();
    expect(browser.frames("close")).toEqual([
      { type: "close", code: 4401, intent: "lifecycle_unconfirmed" },
    ]);
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "lifecycle_unconfirmed", fence }),
    ]);
  });

  it("a hung FIRST read never opens a PTY and closes at the deadline", async () => {
    check.mockImplementation(() => new Promise(() => undefined));
    const { browser } = await attach();
    await vi.advanceTimersByTimeAsync(5_000);
    await flush();
    expect(host.frames("terminal.open")).toEqual([]);
    expect(browser.frames("close")[0]).toMatchObject({ intent: "lifecycle_unconfirmed" });
  });

  it("inverse: a slow read that answers before the deadline keeps the terminal", async () => {
    const { browser } = await attached();
    check.mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve({ ok: true }), 4_900)),
    );
    notifyAuthSessionsRevoked({ userId: "owner-1" });
    await vi.advanceTimersByTimeAsync(5_000);
    await flush();
    expect(browser.closes).toEqual([]);
  });
});

describe("post-consume refusals are readable close frames (C53-CO-1)", () => {
  it.each(["revoked", "sandbox_stopped", "superseded", "expired"] as const)(
    "%s on the first re-read: CloseIntent with the upgrade requestId, 4401, NO PTY",
    async (intent) => {
      verdict = { ok: false, intent };
      const browser = new FakeBrowser();
      service.attach(binding, "req-upgrade-1").opened(browser);
      await flush();
      expect(host.frames("terminal.open")).toEqual([]);
      expect(browser.frames("close")).toEqual([
        { type: "close", code: 4401, intent, requestId: "req-upgrade-1" },
      ]);
      expect(browser.closes).toEqual([{ code: 4401, reason: intent }]);
    },
  );

  it("host unavailable: the open is refused with an error code and requestId, NO PTY", async () => {
    service.dispose();
    const unavailable = new SandboxTerminalManager({
      terminalHost: () => ({ error: { code: "disconnected", message: "host is not connected" } }),
      closeHostSocket: () => undefined,
    });
    service = new BrowserTerminalService(() => unavailable, check, 15_000);
    const browser = new FakeBrowser();
    service.attach(binding, "req-upgrade-2").opened(browser);
    await flush();
    expect(host.frames("terminal.open")).toEqual([]);
    expect(browser.frames("close")).toEqual([
      {
        type: "close",
        code: 4401,
        error: { code: "disconnected", message: "host is not connected" },
        requestId: "req-upgrade-2",
      },
    ]);
  });
});

describe("single attachment and the wire", () => {
  it("a second attach REPLACES the first: old socket gets CloseIntent replaced + 4401", async () => {
    const first = await attached();
    const second = await attach();
    expect(first.browser.frames("close")).toEqual([
      { type: "close", code: 4401, intent: "replaced" },
    ]);
    expect(first.browser.closes).toEqual([{ code: 4401, reason: "replaced" }]);
    expect(second.browser.closes).toEqual([]);
    // Input from the replaced socket reaches nothing.
    first.terminal.message(new TextEncoder().encode("old\n").buffer);
    expect(host.input()).toEqual([]);
  });

  it("input, resize, and a client close with requestId echo", async () => {
    const { browser, terminal, fence } = await attached();
    terminal.message(new TextEncoder().encode("ls\n").buffer);
    expect(host.input().map((f) => new TextDecoder().decode(f.body))).toEqual(["ls\n"]);
    terminal.message(JSON.stringify({ type: "resize", requestId: "rz1", rows: 40, cols: 100 }));
    expect(host.frames("terminal.resize")).toEqual([
      expect.objectContaining({ rows: 40, cols: 100 }),
    ]);
    terminal.message(JSON.stringify({ type: "resize", requestId: "rz2", rows: 0, cols: 100 }));
    expect(browser.frames("error")).toEqual([
      { type: "error", code: "protocol_error", requestId: "rz2" },
    ]);
    terminal.message(JSON.stringify({ type: "close", requestId: "bye-1" }));
    expect(browser.frames("close")).toEqual([
      { type: "close", code: 4401, intent: "client", requestId: "bye-1" },
    ]);
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "client", fence }),
    ]);
  });

  it("a malformed control frame is a protocol violation (4401), never forwarded", async () => {
    const { browser, terminal } = await attached();
    terminal.message(JSON.stringify({ type: "resize", rows: 1, cols: 1, fence: { hostId: "x" } }));
    expect(browser.frames("close")[0]).toMatchObject({ code: 4401, intent: "protocol_violation" });
    expect(host.frames("terminal.resize")).toEqual([]);
  });

  it("oversized input frames are refused", async () => {
    const { browser, terminal } = await attached();
    terminal.message(new Uint8Array(16_385).buffer);
    expect(host.input()).toEqual([]);
    expect(browser.frames("error")).toEqual([{ type: "error", code: "request_too_large" }]);
  });

  it("C52-F-1: 10 000 one-byte frames under a closed window coalesce into few bounded chunks", async () => {
    const { terminal, fence } = await attached();
    for (let i = 0; i < 10_000; i += 1) terminal.message(new Uint8Array([97]).buffer);
    // 8 single-byte frames filled the window; the rest is coalesced.
    expect(host.input()).toHaveLength(8);
    manager.handleHostControl(host, { type: "terminal.ack", fence, sequence: 7 });
    const sent = host.input().slice(8);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.body.byteLength).toBe(10_000 - 8);
  });

  it("C52-F-5 / C52-R2-2: a throwing browser transport never throws into host frame handling", async () => {
    const { browser, fence } = await attached();
    browser.throwOnSend = true;
    expect(() =>
      manager.handleHostData(
        host,
        { type: "terminal.data", fence, sequence: 0 },
        new TextEncoder().encode("out"),
      ),
    ).not.toThrow();
    await flush();
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "detached", fence }),
    ]);
    expect(service.count()).toBe(0);
  });

  it("a browser flooding refused frames without reading is detached (bounded error frames)", async () => {
    const { browser, terminal, fence } = await attached();
    browser.bufferedAmount = 1024 * 1024 + 1;
    terminal.message(new Uint8Array(16_385).buffer);
    expect(browser.frames("error")).toEqual([]);
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "backpressure", fence }),
    ]);
  });

  it("the browser going away detaches the PTY", async () => {
    const { terminal, fence } = await attached();
    terminal.gone();
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "detached", fence }),
    ]);
    expect(service.count()).toBe(0);
  });
});

/** The host's final exit for a session it was asked to close (reap confirmed). */
function hostExit(fence: TerminalFence, intent?: string, reaped = true) {
  manager.handleHostControl(host, {
    type: "terminal.exit",
    fence,
    reaped,
    ...(intent ? { intent: intent as never } : {}),
  });
}

describe("C55 trigger matrix: one close boundary for every exit path", () => {
  type Trigger = {
    name: string;
    fire: (t: Awaited<ReturnType<typeof attached>>) => Promise<void> | void;
    /** The CloseIntent the browser sees (null: the browser itself is gone). */
    intent: string | null;
    error?: string;
    /** The host is asked once (the socket still exists) or never (it is gone). */
    hostClose: boolean;
    /** The host socket ends with the trigger, which releases the count. */
    socketEnds?: boolean;
  };
  const lifecycle = (intent: TerminalRevocation) => async () => {
    verdict = { ok: false, intent };
    notifySandboxTerminalLifecycle({ sandboxIds: new Set(["sbx-1"]) });
    await flush();
  };
  const triggers: Trigger[] = [
    {
      name: "browser loss",
      fire: ({ terminal }) => terminal.gone(),
      intent: null,
      hostClose: true,
    },
    {
      name: "client close",
      fire: ({ terminal }) => terminal.message(JSON.stringify({ type: "close", requestId: "c-1" })),
      intent: "client",
      hostClose: true,
    },
    {
      name: "idle timeout (fake clock)",
      fire: async () => {
        for (let i = 0; i < 3; i += 1) {
          await vi.advanceTimersByTimeAsync(20_000);
          await flush();
        }
      },
      intent: "detached",
      error: "timeout",
      hostClose: true,
    },
    {
      name: "host loss",
      fire: () => manager.removeHostSocket(host),
      intent: "host_disconnected",
      hostClose: false,
      socketEnds: true,
    },
    {
      name: "browser credential revoke (logout)",
      fire: async () => {
        verdict = { ok: false, intent: "revoked" };
        notifyAuthSessionsRevoked({ userId: "owner-1" });
        await flush();
      },
      intent: "revoked",
      hostClose: true,
    },
    {
      // C52-R2-1: the session manager's 4003 path (`closeAuthority`).
      name: "host credential revoke (4003)",
      fire: () =>
        manager.removeHostSocket(host, "host_disconnected", false, HOST_CREDENTIAL_INACTIVE_ERROR),
      intent: "host_disconnected",
      error: "access_denied",
      hostClose: false,
      socketEnds: true,
    },
    {
      name: "generation change",
      fire: lifecycle("superseded"),
      intent: "superseded",
      hostClose: true,
    },
    { name: "sandbox expiry", fire: lifecycle("expired"), intent: "expired", hostClose: true },
    {
      name: "stop",
      fire: lifecycle("sandbox_stopped"),
      intent: "sandbox_stopped",
      hostClose: true,
    },
    {
      name: "destroy",
      fire: lifecycle("sandbox_destroyed"),
      intent: "sandbox_destroyed",
      hostClose: true,
    },
    {
      name: "graceful server shutdown",
      fire: () => {
        // lifecycle.ts order: browser terminals, then the relay sessions.
        service.dispose();
        manager.closeAll("shutdown");
      },
      intent: "shutdown",
      hostClose: true,
      socketEnds: true,
    },
  ];

  it.each(triggers)(
    "$name: one CloseIntent, one 4401, one host close, one release",
    async (trigger) => {
      const t = await attached();
      expect(manager.sessionCount()).toBe(1);
      await trigger.fire(t);
      // Repeat the trigger: still exactly one effect (idempotent close).
      await trigger.fire(t);
      const closes = t.browser.frames("close");
      if (trigger.intent === null) {
        // The browser is gone: nothing is written to its dead socket.
        expect(closes).toEqual([]);
        expect(t.browser.closes).toEqual([]);
      } else {
        expect(closes).toHaveLength(1);
        expect(closes[0]).toMatchObject({ code: 4401, intent: trigger.intent });
        if (trigger.error) expect(closes[0]).toMatchObject({ error: { code: trigger.error } });
        expect(t.browser.closes).toEqual([{ code: 4401, reason: trigger.intent }]);
      }
      const hostCloses = host.frames("terminal.close");
      expect(hostCloses).toHaveLength(trigger.hostClose ? 1 : 0);
      if (!trigger.socketEnds) {
        // Still counted until the host confirms the end and the reap.
        expect(manager.sessionCount()).toBe(1);
        hostExit(t.fence, hostCloses[0].intent);
        hostExit(t.fence, hostCloses[0].intent);
      }
      expect(manager.sessionCount()).toBe(0);
      // The browser heard the end exactly once in every case.
      expect(t.browser.frames("close")).toHaveLength(trigger.intent === null ? 0 : 1);
      // No input reaches the host after the end.
      expect(t.terminal.closed).toBe(true);
      t.terminal.message(new Uint8Array([65]).buffer);
      expect(host.input()).toEqual([]);
      expectNoTerminalResources(manager, {
        service,
        hostSockets: trigger.socketEnds ? 0 : 1,
      });
    },
  );
});

describe("C55 idle timeout is browser liveness (fake clock)", () => {
  it("pings every heartbeat; a browser that answers (pong or frames) stays open", async () => {
    const { browser, terminal } = await attached();
    for (let i = 0; i < 6; i += 1) {
      await vi.advanceTimersByTimeAsync(20_000);
      await flush();
      terminal.activity(); // the browser's pong
    }
    expect(browser.pings).toBe(6);
    expect(browser.frames("close")).toEqual([]);
    expect(host.frames("terminal.close")).toEqual([]);
  });

  it("a silent browser is closed only once the idle bound has fully passed", async () => {
    const { browser } = await attached();
    await vi.advanceTimersByTimeAsync(40_000);
    await flush();
    expect(browser.frames("close")).toEqual([]);
    await vi.advanceTimersByTimeAsync(20_000);
    await flush();
    expect(browser.frames("close")).toEqual([
      expect.objectContaining({
        intent: "detached",
        error: expect.objectContaining({ code: "timeout" }),
      }),
    ]);
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "detached" }),
    ]);
  });
});

describe("C55 every exit path clears its timers (C53-N3)", () => {
  it("a failed PTY open arms no timer on the closed terminal", async () => {
    manager = new SandboxTerminalManager({
      terminalHost: () => ({ error: { code: "disconnected", message: "host is not connected" } }),
      closeHostSocket: () => undefined,
    });
    const { browser, terminal } = await attach();
    expect(browser.frames("close")).toEqual([
      expect.objectContaining({ error: expect.objectContaining({ code: "disconnected" }) }),
    ]);
    expect(terminal.closed).toBe(true);
    expect(terminal.timers).toBe(0);
    const calls = check.mock.calls.length;
    await vi.advanceTimersByTimeAsync(120_000);
    expect(check.mock.calls.length).toBe(calls);
    expectNoTerminalResources(manager, { service, hostSockets: 0 });
  });
});

describe("C55 shutdown refuses late attaches (C53-FS-2)", () => {
  it("an upgrade completing after dispose gets shutdown + 4401 and never opens a PTY", async () => {
    await attached();
    service.dispose();
    manager.closeAll("shutdown");
    const opensBefore = host.frames("terminal.open").length;
    const late = new FakeBrowser();
    const terminal = service.attach(binding);
    terminal.opened(late);
    await flush();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(late.frames("close")).toEqual([{ type: "close", code: 4401, intent: "shutdown" }]);
    expect(late.closes).toEqual([{ code: 4401, reason: "shutdown" }]);
    expect(host.frames("terminal.open")).toHaveLength(opensBefore);
    expect(service.shuttingDown).toBe(true);
    expectNoTerminalResources(manager, { service, hostSockets: 0 });
  });
});

it("T2 host and foreign guest targets coexist; required-policy revocation closes only host", async () => {
  const policy = { hostTerminal: true, requireHostTerminalTotp: false, policyRevision: 1 };
  manager = new SandboxTerminalManager({
    terminalHost: () => ({ link: { ...link(), hostPolicy: policy } }),
    closeHostSocket: () => {},
  });
  const b: import("@wssp/api/sandbox/host-terminal-tickets").HostTerminalBinding = {
    kind: "host",
    userId: "owner-1",
    sessionId: "auth-session-1",
    hostId: "host-1",
    hostOwnerId: "owner-1",
    epoch: 9,
    rows: 24,
    cols: 80,
    policyRevision: 1,
    proofRequired: false,
    verifiedAt: null,
    observedAt: null,
    factorFingerprint: null,
  };
  const browser = new FakeBrowser();
  const terminal = service.attach(b);
  terminal.opened(browser);
  await flush();
  const hostFence = readyHost();
  expect(hostFence.target).toEqual({ kind: "host" });
  expect(host.frames("terminal.open").at(-1).hostPolicy).toEqual({
    policyRevision: 1,
    proofRequired: false,
  });
  verdict = { ok: false, intent: "revoked" };
  await terminal.revalidate();
  expect(browser.closes).toHaveLength(1);
  expect(host.frames("terminal.close").at(-1).fence.target).toEqual({ kind: "host" });
});
it("T2 combined host-owner+host hints reach foreign viewers; viewer session remains creator-scoped", async () => {
  const guest = { ...binding, userId: "foreign-creator" };
  const grant = {
    creatorId: guest.userId,
    hostOwnerId: "owner-1",
    hostId: guest.hostId,
    epoch: 9,
    sandboxId: guest.sandboxId,
    generation: guest.generation,
  };
  verdict = { ok: true, grant };
  const attached = await attach(guest);
  readyHost();
  expect(attached.browser.closes).toHaveLength(0);
  const before = check.mock.calls.length;
  await withAuthorityChange({ ownerId: "owner-1", hostId: "host-1" }, async () => {});
  await flush();
  expect(check.mock.calls.length).toBeGreaterThan(before);
  expect(attached.browser.closes).toHaveLength(0);
  verdict = { ok: false, intent: "revoked" };
  notifyAuthSessionsRevoked({ userId: "foreign-creator" });
  await flush();
  expect(attached.browser.closes).toHaveLength(1);
});

it.each(["pool_access_removed", "host_terminals_disabled"] as const)(
  "carries %s to the browser while retaining the node-daemon revoked intent",
  async (reason) => {
    const browser = new FakeBrowser();
    const terminal = service.attach(binding);
    terminal.opened(browser);
    await flush();
    readyHost();
    verdict = { ok: false, intent: reason };
    await terminal.revalidate();
    expect(browser.frames("close")).toEqual([
      { type: "close", code: 4401, intent: "revoked", reason },
    ]);
    expect(host.frames("terminal.close").at(-1)).toMatchObject({ intent: "revoked" });
  },
);

describe("WP8 v2 reattach on the browser socket", () => {
  const TERMINAL_ID = `t${"c".repeat(32)}`;
  let rows: { opened: unknown[]; closed: string[] };
  let graceMs: number | undefined;
  beforeEach(() => {
    rows = { opened: [], closed: [] };
    graceMs = 90_000;
    manager = new SandboxTerminalManager({
      terminalHost: () => ({
        link: { ...link(), ...(graceMs === undefined ? {} : { resumeGraceMs: graceMs }) },
      }),
      closeHostSocket: () => undefined,
    });
    service.dispose();
    service = new BrowserTerminalService(
      () => manager,
      check,
      15_000,
      undefined,
      undefined,
      undefined,
      undefined,
      {
        opened: async (identity) => {
          rows.opened.push(identity);
        },
        closed: async (terminalId) => {
          rows.closed.push(terminalId);
        },
      },
    );
  });

  async function attachV2(b: TerminalBinding = binding) {
    const browser = new FakeBrowser();
    const terminal = service.attach(b, "req-1", 2);
    terminal.opened(browser);
    await flush();
    return { browser, terminal };
  }

  it("v2 ready carries the terminal id and output sequence and writes the row once", async () => {
    const { browser } = await attachV2();
    const fence = readyHost();
    expect(browser.frames("ready")).toEqual([
      { type: "ready", rows: 24, cols: 80, terminalId: fence.sessionId, outputSeq: 0 },
    ]);
    await flush();
    expect(rows.opened).toEqual([
      {
        terminalId: fence.sessionId,
        userId: "owner-1",
        sessionId: "auth-session-1",
        sandboxId: "sbx-1",
        hostId: "host-1",
        generation: 3,
      },
    ]);
  });

  it("a relay drop sends reconnecting + 4402 and keeps the row open", async () => {
    const { browser } = await attachV2();
    const fence = readyHost();
    manager.removeHostSocket(host);
    await flush();
    expect(browser.frames("reconnecting")).toEqual([
      { type: "reconnecting", terminalId: fence.sessionId, graceMs: 90_000 },
    ]);
    expect(browser.frames("close")).toEqual([]);
    expect(browser.closes).toEqual([{ code: 4402, reason: "reconnecting" }]);
    expect(rows.closed).toEqual([]);
    expectNoTerminalResources(manager, { service, hostSockets: 0 });
  });

  it("v1 on the same node and v2 on a node without the capability end with 4401", async () => {
    const v1 = await attach();
    readyHost();
    graceMs = undefined;
    host = new FakeHost();
    const v2 = await attachV2({ ...binding, sandboxId: "sbx-2" });
    readyHost();
    expect(v2.browser.frames("ready")[0]).toEqual({ type: "ready", rows: 24, cols: 80 });
    manager.removeHostSocket(host);
    expect(v2.browser.closes).toEqual([{ code: 4401, reason: "host_disconnected" }]);
    expect(v1.browser.frames("ready")[0]).toEqual({ type: "ready", rows: 24, cols: 80 });
    expect(rows.opened).toEqual([]);
  });

  it("every final end of an opened terminal marks the row closed", async () => {
    const { browser, terminal } = await attachV2();
    const fence = readyHost();
    terminal.message(JSON.stringify({ type: "close", requestId: "c-1" }));
    await flush();
    expect(rows.closed).toEqual([fence.sessionId]);
    expect(browser.closes.at(-1)?.code).toBe(4401);
    const gone = await attachV2();
    const goneFence = readyHost();
    gone.terminal.gone();
    await flush();
    expect(rows.closed).toEqual([fence.sessionId, goneFence.sessionId]);
  });

  it("graceful shutdown reconnects a resumable terminal and never closes its PTY", async () => {
    const { browser } = await attachV2();
    const fence = readyHost();
    service.dispose();
    expect(browser.frames("reconnecting")).toEqual([
      { type: "reconnecting", terminalId: fence.sessionId, graceMs: 90_000 },
    ]);
    expect(browser.closes).toEqual([{ code: 4402, reason: "reconnecting" }]);
    expect(host.frames("terminal.close")).toEqual([]);
    await flush();
    expect(rows.closed).toEqual([]);
  });

  it("a resume binding sends terminal.resume and keeps the stored openedAt (no row write)", async () => {
    const resume = { terminalId: TERMINAL_ID, nextOutputSeq: 7 };
    const { browser } = await attachV2({ ...binding, resume });
    const [frame] = host.frames("terminal.resume");
    expect(frame).toMatchObject({ fence: { sessionId: TERMINAL_ID }, nextOutputSeq: 7 });
    manager.handleHostControl(host, {
      type: "terminal.ready",
      requestId: frame.requestId,
      fence: frame.fence,
      rows: 24,
      cols: 80,
      outputSeq: 9,
    });
    expect(browser.frames("ready")).toEqual([
      { type: "ready", rows: 24, cols: 80, terminalId: TERMINAL_ID, outputSeq: 9 },
    ]);
    await flush();
    expect(rows.opened).toEqual([]);
    expect(check.mock.calls[0]?.[0]).toMatchObject({ resume });
  });

  it("a resume refused before the node is reached leaves the row; a node refusal closes it", async () => {
    const resume = { terminalId: TERMINAL_ID, nextOutputSeq: 0 };
    // The node is not back yet: refused before any frame, the row stays open.
    manager = new SandboxTerminalManager({
      terminalHost: () => ({ error: { code: "disconnected", message: "host is not connected" } }),
      closeHostSocket: () => undefined,
    });
    const early = await attachV2({ ...binding, resume });
    expect(early.browser.frames("close")[0]).toMatchObject({
      error: { code: "disconnected" },
    });
    await flush();
    expect(rows.closed).toEqual([]);
    // The node answered: it no longer has the PTY.
    manager = new SandboxTerminalManager({
      terminalHost: () => ({ link: { ...link(), resumeGraceMs: 90_000 } }),
      closeHostSocket: () => undefined,
    });
    const late = await attachV2({ ...binding, resume });
    const [frame] = host.frames("terminal.resume");
    manager.handleHostControl(host, {
      type: "terminal.exit",
      requestId: frame.requestId,
      fence: frame.fence,
      reaped: true,
      error: { code: "sandbox_not_found", message: "terminal not found" },
    });
    await flush();
    expect(late.browser.closes.at(-1)?.code).toBe(4401);
    expect(rows.closed).toEqual([TERMINAL_ID]);
  });

  it("a failed resume gate ends only this attachment with a readable refusal", async () => {
    verdict = { ok: false, intent: "resume_unavailable" };
    const { browser } = await attachV2({
      ...binding,
      resume: { terminalId: TERMINAL_ID, nextOutputSeq: 0 },
    });
    expect(browser.frames("close")).toEqual([
      {
        type: "close",
        code: 4401,
        intent: "expired",
        error: { code: "state_conflict", message: "the terminal can no longer be resumed" },
        requestId: "req-1",
      },
    ]);
    expect(host.frames("terminal.resume")).toEqual([]);
    expect(host.frames("terminal.close")).toEqual([]);
  });

  // Live P1 (deploy restart): the new server process's boot sweep revoked the
  // host epoch while this (old) process still held the relay; its heartbeat
  // re-read used to answer `superseded`, closing the browser finally and
  // asking the node to close the PTY.
  it("a heartbeat re-read finding the host connection moved on reconnects a resumable terminal, never closes its PTY", async () => {
    const { browser } = await attachV2();
    const fence = readyHost();
    verdict = { ok: false, intent: "host_disconnected" };
    await vi.advanceTimersByTimeAsync(15_000);
    await flush();
    expect(browser.frames("reconnecting")).toEqual([
      { type: "reconnecting", terminalId: fence.sessionId, graceMs: 90_000 },
    ]);
    expect(browser.frames("close")).toEqual([]);
    expect(browser.closes).toEqual([{ code: 4402, reason: "reconnecting" }]);
    expect(host.frames("terminal.close")).toEqual([]);
    await flush();
    expect(rows.closed).toEqual([]);
    expect(service.count()).toBe(0);
    expect(manager.sessionCount()).toBe(0);
    // The old process then drains: nothing more reaches the browser or node.
    service.dispose();
    manager.closeAll("shutdown");
    expect(browser.closes).toHaveLength(1);
    expect(host.frames("terminal.close")).toEqual([]);
  });

  it("a host connection that moved on ends v1 finally as host_disconnected (nothing can resume it)", async () => {
    const { browser, fence } = await attached();
    verdict = { ok: false, intent: "host_disconnected" };
    await vi.advanceTimersByTimeAsync(15_000);
    await flush();
    expect(browser.frames("reconnecting")).toEqual([]);
    expect(browser.frames("close")).toEqual([
      { type: "close", code: 4401, intent: "host_disconnected" },
    ]);
    expect(browser.closes).toEqual([{ code: 4401, reason: "host_disconnected" }]);
    expect(host.frames("terminal.close")).toEqual([
      expect.objectContaining({ intent: "host_disconnected", fence }),
    ]);
  });

  it("a resume whose host is not (yet) connected here is refused retryably: no frame to the node, row kept", async () => {
    verdict = { ok: false, intent: "host_disconnected" };
    const { browser } = await attachV2({
      ...binding,
      resume: { terminalId: TERMINAL_ID, nextOutputSeq: 0 },
    });
    expect(browser.frames("close")).toEqual([
      {
        type: "close",
        code: 4401,
        error: { code: "disconnected", message: "host is not connected" },
        requestId: "req-1",
      },
    ]);
    expect(host.frames("terminal.resume")).toEqual([]);
    expect(host.frames("terminal.close")).toEqual([]);
    await flush();
    expect(rows.closed).toEqual([]);
  });

  it.each(["superseded", "replaced"] as const)(
    "a legitimate %s still ends a resumable terminal finally and closes its row",
    async (intent) => {
      const { browser } = await attachV2();
      const fence = readyHost();
      if (intent === "superseded") {
        verdict = { ok: false, intent };
        await vi.advanceTimersByTimeAsync(15_000);
      } else {
        await attachV2();
      }
      await flush();
      expect(browser.frames("reconnecting")).toEqual([]);
      expect(browser.frames("close")).toEqual([
        expect.objectContaining({ type: "close", code: 4401, intent }),
      ]);
      expect(browser.closes).toEqual([{ code: 4401, reason: intent }]);
      expect(host.frames("terminal.close")).toContainEqual(
        expect.objectContaining({ intent, fence }),
      );
      expect(rows.closed).toEqual([fence.sessionId]);
    },
  );
});
