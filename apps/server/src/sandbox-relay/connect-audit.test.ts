import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectAuditSink as Sink } from "./connect-audit.js";

vi.mock("@wssp/env/server", () => ({ env: { BETTER_AUTH_SECRET: "connect-audit-test" } }));
vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});

const { ConnectAuditRecorder } = await import("./connect-audit.js");

const ids = {
  connectionId: "c0123456789abcdef0123456789abcdef",
  ownerId: "owner-1",
  keyId: "key-1",
  sandboxId: "sbx-1",
  hostId: "host-1",
};
const OPENED_AT = 1_700_000_000_000;
const CLOSED_AT = OPENED_AT + 61_000;
const openOf = (overrides: Partial<{ connectionId: string }> = {}) => ({
  ...ids,
  openedAt: OPENED_AT,
  ...overrides,
});
const closeOf = (overrides: Partial<{ connectionId: string; intent: string }> = {}) => ({
  ...ids,
  openedAt: OPENED_AT,
  closedAt: CLOSED_AT,
  intent: "client",
  ptyChannels: 1,
  execChannels: 2,
  bytesIn: 10,
  bytesOut: 20,
  ...overrides,
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const tick = () => new Promise((resolve) => setImmediate(resolve));
const endRow = {
  closedAt: new Date(CLOSED_AT),
  closeIntent: "client",
  ptyChannels: 1,
  execChannels: 2,
  bytesIn: 10,
  bytesOut: 20,
};

let info: ReturnType<typeof vi.spyOn>;
let warn: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  info = vi.spyOn(console, "info").mockImplementation(() => {});
  warn = vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

describe("ConnectAuditRecorder", () => {
  it("writes the open then the close (the close waits for its open), one log line each", async () => {
    const open = deferred<boolean>();
    const order: string[] = [];
    const sink: Sink = {
      open: vi.fn(async () => {
        order.push("open:start");
        const ok = await open.promise;
        order.push("open:done");
        return ok;
      }),
      close: vi.fn(async () => {
        order.push("close");
        return true;
      }),
    };
    const recorder = new ConnectAuditRecorder({ sink });
    recorder.opened(openOf());
    recorder.closed(closeOf());
    await tick();
    expect(order).toEqual(["open:start"]);
    open.resolve(true);
    await recorder.drain();
    expect(order).toEqual(["open:start", "open:done", "close"]);
    // The relay's instants travel with the rows (never the write's clock).
    expect(sink.open).toHaveBeenCalledWith({
      id: ids.connectionId,
      ownerId: "owner-1",
      sandboxId: "sbx-1",
      hostId: "host-1",
      keyId: "key-1",
      openedAt: new Date(OPENED_AT),
    });
    expect(sink.close).toHaveBeenCalledWith({
      id: ids.connectionId,
      ownerId: "owner-1",
      ...endRow,
    });
    expect(info).toHaveBeenCalledTimes(2);
    expect(info.mock.calls[0]?.[1]).toEqual({ code: "connect_open", ...ids });
    expect(info.mock.calls[1]?.[1]).toMatchObject({ code: "connect_close", intent: "client" });
    expect(recorder.pendingWrites).toBe(0);
  });

  it("a close whose open is still queued coalesces into one insert", async () => {
    const gate = deferred<boolean>();
    const sink: Sink = {
      open: vi.fn((row) => (row.id === "busy" ? gate.promise : Promise.resolve(true))),
      close: vi.fn(async () => true),
    };
    const recorder = new ConnectAuditRecorder({ sink, concurrency: 1 });
    recorder.opened(openOf({ connectionId: "busy" }));
    recorder.opened(openOf());
    recorder.closed(closeOf());
    gate.resolve(true);
    await recorder.drain();
    expect(sink.open).toHaveBeenCalledTimes(2);
    expect(sink.open).toHaveBeenLastCalledWith(
      expect.objectContaining({ id: ids.connectionId, end: endRow }),
    );
    expect(sink.close).not.toHaveBeenCalled();
  });

  it("a failed or refused open drops its close; failures are logged without ids or messages", async () => {
    const sink: Sink = {
      open: vi.fn(async () => {
        throw Object.assign(new Error("secret db detail"), { code: "P2002" });
      }),
      close: vi.fn(async () => true),
    };
    const recorder = new ConnectAuditRecorder({ sink });
    recorder.opened(openOf());
    recorder.closed(closeOf());
    await recorder.drain();
    expect(sink.close).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(warn.mock.calls)).not.toContain("secret db detail");
    expect(JSON.stringify(warn.mock.calls)).not.toContain(ids.connectionId);

    const refused: Sink = { open: vi.fn(async () => false), close: vi.fn(async () => true) };
    const second = new ConnectAuditRecorder({ sink: refused });
    second.opened(openOf());
    await second.drain();
    second.closed(closeOf());
    await second.drain();
    expect(refused.close).not.toHaveBeenCalled();
  });

  it("a stalled database never holds more than the fixed concurrency; a full queue drops opens only", async () => {
    const gate = deferred<boolean>();
    const sink: Sink = { open: vi.fn(() => gate.promise), close: vi.fn(() => gate.promise) };
    const recorder = new ConnectAuditRecorder({ sink, concurrency: 2, maxPending: 3 });
    for (let i = 0; i < 8; i += 1) recorder.opened(openOf({ connectionId: `c${i}` }));
    await tick();
    // 2 running, 3 queued, 3 dropped (and counted).
    expect(sink.open).toHaveBeenCalledTimes(2);
    expect(recorder.runningWrites).toBe(2);
    expect(recorder.pendingWrites).toBe(5);
    expect(recorder.dropped).toBe(3);
    // Every admitted connection ends while the database is stalled: the
    // closes coalesce or follow, the dropped opens' closes have no row.
    for (let i = 0; i < 8; i += 1) recorder.closed(closeOf({ connectionId: `c${i}` }));
    await tick();
    expect(recorder.runningWrites).toBe(2);
    expect(recorder.dropped).toBe(3);
    gate.resolve(true);
    await recorder.drain();
    // c0, c1: open then close; c2..c4: one coalesced insert each.
    expect(sink.open).toHaveBeenCalledTimes(5);
    expect(sink.close).toHaveBeenCalledTimes(2);
    expect(recorder.pendingWrites).toBe(0);
  });

  it("records every close of a burst larger than the old write limit (healthy database)", async () => {
    const written = new Set<string>();
    const completed = new Set<string>();
    const sink: Sink = {
      open: vi.fn(async (row) => {
        written.add(row.id);
        if (row.end) completed.add(row.id);
        return true;
      }),
      close: vi.fn(async (row) => {
        if (written.has(row.id)) completed.add(row.id);
        return true;
      }),
    };
    const recorder = new ConnectAuditRecorder({ sink });
    const count = 200;
    for (let i = 0; i < count; i += 1) recorder.opened(openOf({ connectionId: `c${i}` }));
    await recorder.drain();
    expect(written.size).toBe(count);
    // Shutdown: every connection ends synchronously in one burst.
    let running = 0;
    let peak = 0;
    vi.mocked(sink.close).mockImplementation(async (row) => {
      running += 1;
      peak = Math.max(peak, running);
      await tick();
      running -= 1;
      if (written.has(row.id)) completed.add(row.id);
      return true;
    });
    for (let i = 0; i < count; i += 1) recorder.closed(closeOf({ connectionId: `c${i}` }));
    await expect(recorder.drain(3_000)).resolves.toBe(true);
    expect(completed.size).toBe(count);
    expect(peak).toBeLessThanOrEqual(2);
    expect(recorder.dropped).toBe(0);
  });

  it("the shutdown drain gives up after its bound and logs, never rejecting", async () => {
    vi.useFakeTimers();
    try {
      const sink: Sink = {
        open: vi.fn(() => new Promise<boolean>(() => {})),
        close: vi.fn(async () => true),
      };
      const recorder = new ConnectAuditRecorder({ sink });
      recorder.opened(openOf());
      let result: boolean | undefined;
      void recorder.drain(3_000).then((drained) => {
        result = drained;
      });
      await vi.advanceTimersByTimeAsync(2_999);
      expect(result).toBeUndefined();
      await vi.advanceTimersByTimeAsync(1);
      expect(result).toBe(false);
      expect(warn).toHaveBeenCalledWith(
        "[sandbox-connect] audit drain timed out:",
        expect.objectContaining({ code: "connect_audit_drain_timeout", pending: 1 }),
      );
      // Idle already: resolves at once.
      await expect(new ConnectAuditRecorder({ sink }).drain(3_000)).resolves.toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("rate-caps its log lines and never throws, even when the sink throws synchronously", async () => {
    const sink: Sink = {
      open: vi.fn(() => {
        throw new Error("sync");
      }) as never,
      close: vi.fn(() => {
        throw new Error("sync");
      }) as never,
    };
    const recorder = new ConnectAuditRecorder({ sink, logsPerMinute: 3, now: () => 1000 });
    for (let i = 0; i < 10; i += 1) {
      expect(() => recorder.opened(openOf({ connectionId: `c${i}` }))).not.toThrow();
      expect(() => recorder.closed(closeOf({ connectionId: `c${i}` }))).not.toThrow();
    }
    await recorder.drain();
    expect(info).toHaveBeenCalledTimes(3);
    expect(warn.mock.calls.length).toBeLessThanOrEqual(3);
  });
});
