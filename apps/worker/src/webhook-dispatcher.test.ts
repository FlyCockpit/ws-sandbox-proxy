import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  fanOut: vi.fn(),
  enqueue: vi.fn(),
  maintenance: vi.fn(),
  rewrap: vi.fn(),
}));
vi.mock("@wssp/api/webhooks/ledger", () => ({
  FAN_OUT_BATCH: 100,
  newEnqueueCursor: () => ({ afterEndpointId: "" }),
  newFanOutCursor: () => ({ afterSeq: -1n, contendedMs: 0 }),
  newRekeyCursor: () => ({ afterId: null }),
  fanOutEvents: state.fanOut,
  enqueuePending: state.enqueue,
  runMaintenance: state.maintenance,
}));
vi.mock("@wssp/api/credentials/rewrap", () => ({
  newCredentialRewrapCursor: () => ({ value: null, returnKey: null }),
  rewrapCredentialKeys: state.rewrap,
}));
const { startWebhookDispatcher } = await import("./webhook-dispatcher");

beforeEach(() => {
  vi.clearAllMocks();
  state.fanOut.mockResolvedValue(0);
  state.enqueue.mockResolvedValue(0);
  state.rewrap.mockResolvedValue({ values: 0, returnKeys: 0, failed: 0, stale: false });
  state.maintenance.mockResolvedValue({
    reclaimed: 0,
    expired: 0,
    clearedOverlaps: 0,
    rekeyed: 0,
    rekeyFailed: 0,
  });
});

describe("webhook dispatcher loop (unit; ledger SQL: webhook-ledger.pg.test.ts)", () => {
  it("runs maintenance on a MONOTONIC cadence: a wall-clock jump back never stalls it", async () => {
    let mono = 0;
    const dispatcher = startWebhookDispatcher({
      config: null,
      enqueue: vi.fn(),
      autoStart: false,
      maintenanceMs: 60_000,
      monotonic: () => mono,
    });
    await Promise.all([dispatcher.tick(), dispatcher.tick()]); // single-flight
    expect(state.fanOut).toHaveBeenCalledTimes(1);
    expect(state.enqueue).toHaveBeenCalledTimes(1);
    expect(state.maintenance).toHaveBeenCalledTimes(1);
    // The wall clock moving an hour backwards is irrelevant: only monotonic time counts.
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() - 3_600_000);
    try {
      mono += 2_000;
      await dispatcher.tick();
      expect(state.maintenance).toHaveBeenCalledTimes(1);
      mono += 60_000;
      await dispatcher.tick();
      expect(state.maintenance).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
    await dispatcher.stop();
  });

  it("carries one fan-out cursor across polls and stops draining on contention", async () => {
    const cursors: unknown[] = [];
    state.fanOut.mockImplementation(async (_client, _now, cursor: { contendedMs: number }) => {
      cursors.push(cursor);
      cursor.contendedMs = cursors.length === 1 ? 250 : 0;
      return cursors.length === 1 ? 100 : 0;
    });
    const dispatcher = startWebhookDispatcher({ config: null, enqueue: vi.fn(), autoStart: false });
    await dispatcher.tick(); // full batch but contended: no second batch this poll
    await dispatcher.tick();
    expect(cursors).toHaveLength(2);
    expect(cursors[0]).toBe(cursors[1]);
    await dispatcher.stop();
  });

  it("carries one release cursor across polls, so every backlogged endpoint is reached", async () => {
    const cursors: unknown[] = [];
    state.enqueue.mockImplementation(async (_enqueue, _client, _now, cursor: unknown) => {
      cursors.push(cursor);
      return 0;
    });
    const dispatcher = startWebhookDispatcher({ config: null, enqueue: vi.fn(), autoStart: false });
    await dispatcher.tick();
    await dispatcher.tick();
    expect(cursors).toHaveLength(2);
    expect(cursors[0]).toEqual({ afterEndpointId: "" });
    expect(cursors[0]).toBe(cursors[1]);
    await dispatcher.stop();
  });

  it("enqueue and maintenance do not wait for fan-out, and a failure logs only closed diagnostics", async () => {
    let release!: () => void;
    state.fanOut.mockImplementation(
      () =>
        new Promise<number>((resolve) => {
          release = () => resolve(0);
        }),
    );
    const dispatcher = startWebhookDispatcher({ config: null, enqueue: vi.fn(), autoStart: false });
    const tick = dispatcher.tick();
    await vi.waitFor(() => expect(state.enqueue).toHaveBeenCalledTimes(1));
    expect(state.maintenance).toHaveBeenCalledTimes(1);
    release();
    await tick;
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    state.fanOut.mockResolvedValue(0);
    state.enqueue.mockRejectedValueOnce(new Error("private-redis-detail"));
    await dispatcher.tick();
    expect(log).toHaveBeenCalled();
    expect(JSON.stringify(log.mock.calls)).not.toContain("private-");
    log.mockRestore();
    await dispatcher.stop();
  });

  it("carries one rekey cursor across maintenance ticks and reports failures as a count only", async () => {
    let mono = 0;
    const cursors: unknown[] = [];
    state.maintenance.mockImplementation(async (options: { rekeyCursor: unknown }) => {
      cursors.push(options.rekeyCursor);
      return { reclaimed: 0, expired: 0, clearedOverlaps: 0, rekeyed: 1, rekeyFailed: 3 };
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const dispatcher = startWebhookDispatcher({
      config: null,
      enqueue: vi.fn(),
      autoStart: false,
      maintenanceMs: 60_000,
      monotonic: () => mono,
    });
    await dispatcher.tick();
    mono += 60_000;
    await dispatcher.tick();
    expect(cursors).toHaveLength(2);
    expect(cursors[0]).toBeDefined();
    expect(cursors[0]).toBe(cursors[1]);
    expect(warn).toHaveBeenCalledTimes(2);
    expect(String(warn.mock.calls[0]?.[0])).toMatch(/^\[webhook-dispatcher\] 3 endpoint secret/);
    warn.mockRestore();
    await dispatcher.stop();
  });

  it("runs the credential rewrap on the maintenance cadence with one cursor; its failure never blocks webhook maintenance", async () => {
    let mono = 0;
    const cursors: unknown[] = [];
    state.rewrap.mockImplementation(async (options: { cursor: unknown }) => {
      cursors.push(options.cursor);
      if (cursors.length === 1) throw new Error("private-db-detail");
      return { values: 2, returnKeys: 1, failed: 1, stale: false };
    });
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const dispatcher = startWebhookDispatcher({
      config: null,
      enqueue: vi.fn(),
      autoStart: false,
      maintenanceMs: 60_000,
      monotonic: () => mono,
    });
    await dispatcher.tick();
    expect(state.maintenance).toHaveBeenCalledTimes(1);
    mono += 2_000;
    await dispatcher.tick();
    expect(state.rewrap).toHaveBeenCalledTimes(1);
    mono += 60_000;
    await dispatcher.tick();
    expect(state.rewrap).toHaveBeenCalledTimes(2);
    expect(state.maintenance).toHaveBeenCalledTimes(2);
    expect(cursors[0]).toBe(cursors[1]);
    expect(JSON.stringify(error.mock.calls)).not.toContain("private-");
    expect(String(warn.mock.calls.at(-1)?.[0])).toMatch(/^\[credential-maintenance\] 1 stored key/);
    error.mockRestore();
    warn.mockRestore();
    await dispatcher.stop();
  });
});
