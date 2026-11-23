import { inspect } from "node:util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  start: vi.fn(),
  stop: vi.fn(),
  disconnectDb: vi.fn(),
  disconnectRedis: vi.fn(),
  listen: vi.fn(),
  close: vi.fn(),
  on: vi.fn(),
  alert: vi.fn(),
}));
vi.mock("@wssp/env/load-dotenv", () => ({}));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "production" } }));
vi.mock("@wssp/db", () => ({ default: { $disconnect: state.disconnectDb } }));
vi.mock("@wssp/queue", () => ({ redisConnection: { disconnect: state.disconnectRedis } }));
vi.mock("node:http", () => ({
  createServer: () => ({ listen: state.listen, close: state.close, on: state.on }),
}));
vi.mock("./operational-alerts.js", () => ({ sendOperationalFailureAlert: state.alert }));
vi.mock("./runtime.js", () => ({
  startWorkerRuntime: state.start,
  WorkerDrainError: class WorkerDrainError extends Error {
    constructor(
      message: string,
      readonly reason: string,
      readonly pendingQueues: readonly string[],
    ) {
      super(message);
    }
  },
}));
const listeners = new Map<string, (...args: unknown[]) => void>();
beforeEach(() => {
  vi.useFakeTimers();
  vi.resetModules();
  vi.resetAllMocks();
  listeners.clear();
  vi.spyOn(process, "on").mockImplementation((event, listener) => {
    listeners.set(String(event), listener);
    return process;
  });
  vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
  state.start.mockImplementation(async (options) => {
    expect(listeners.has("SIGTERM")).toBe(true);
    expect(listeners.has("SIGINT")).toBe(true);
    expect(listeners.has("unhandledRejection")).toBe(true);
    expect(options.signal).toBeInstanceOf(AbortSignal);
    expect(options.embedded).toBe(false);
    return { isReady: () => true, stop: state.stop };
  });
  state.stop.mockResolvedValue(undefined);
  state.disconnectDb.mockResolvedValue(undefined);
  state.alert.mockResolvedValue(undefined);
});
afterEach(() => {
  vi.clearAllTimers();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("worker process entrypoint", () => {
  it("owns signals before processing, then listens only on the production loopback interface", async () => {
    await import("./index");
    expect(state.listen).toHaveBeenCalledWith(3001, "127.0.0.1");
    listeners.get("SIGTERM")?.();
    await vi.advanceTimersByTimeAsync(0);
    expect(state.stop).toHaveBeenCalledOnce();
    expect(state.disconnectDb).toHaveBeenCalledOnce();
    expect(process.exit).toHaveBeenCalledWith(0);
  });

  it.each(["SIGTERM", "SIGINT", "unhandledRejection", "consumer failure"])(
    "%s during pending initial heartbeat cancels and drains before shared teardown",
    async (event) => {
      let finish: (() => void) | undefined;
      let fatal: ((error: Error) => void) | undefined;
      let aborted = false;
      state.start.mockImplementation((options) => {
        fatal = options.onFatal;
        return new Promise((_resolve, reject) => {
          options.signal.addEventListener("abort", () => {
            aborted = true;
            finish = () => reject(new Error("cancelled after clean drain"));
          });
        });
      });
      const starting = import("./index");
      await vi.waitFor(() => expect(state.start).toHaveBeenCalled());
      if (event === "consumer failure") fatal?.(new Error("fatal"));
      else listeners.get(event)?.(new Error("fatal"));
      expect(aborted).toBe(true);
      expect(state.disconnectDb).not.toHaveBeenCalled();
      expect(state.listen).not.toHaveBeenCalled();
      finish?.();
      await starting;
      await vi.advanceTimersByTimeAsync(0);
      expect(state.disconnectDb).toHaveBeenCalledOnce();
      expect(process.exit).toHaveBeenCalledWith(event.startsWith("SIG") ? 0 : 1);
    },
  );

  it("an unclean startup drain does not permit shared-client teardown", async () => {
    const { WorkerDrainError } = await import("./runtime.js");
    state.start.mockRejectedValue(new WorkerDrainError("still running", "deadline", []));
    await import("./index");
    await vi.advanceTimersByTimeAsync(0);
    expect(state.disconnectDb).not.toHaveBeenCalled();
    expect(state.disconnectRedis).not.toHaveBeenCalled();
    expect(process.exit).toHaveBeenCalledWith(1);
  });

  it("watchdog bounds a hung startup drain even if the fatal alert stalls", async () => {
    state.start.mockImplementation(() => new Promise(() => {}));
    state.alert.mockImplementation(() => new Promise(() => {}));
    void import("./index");
    await vi.waitFor(() => expect(state.start).toHaveBeenCalled());
    listeners.get("unhandledRejection")?.(new Error("fatal"));
    await vi.advanceTimersByTimeAsync(20_000);
    expect(process.exit).toHaveBeenCalledWith(1);
    expect(state.disconnectDb).not.toHaveBeenCalled();
  });

  it("health listener errors use the same fatal drain", async () => {
    await import("./index");
    const listener = state.on.mock.calls.find(([event]) => event === "error")?.[1];
    listener(new Error("listen failed"));
    await vi.advanceTimersByTimeAsync(0);
    expect(state.stop).toHaveBeenCalledOnce();
    expect(process.exit).toHaveBeenCalledWith(1);
  });
});

it.each(["startup", "consumer", "drain", "health", "unhandledRejection", "uncaughtException"])(
  "sanitizes worker %s failures with stable diagnostics",
  async (failure) => {
    const sentinel = "synthetic-private-worker-error";
    const raw = Object.assign(new TypeError(sentinel, { cause: new Error(sentinel) }), {
      name: sentinel,
      stack: sentinel,
    });
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    if (failure === "startup") state.start.mockRejectedValueOnce(raw);
    if (failure === "drain") state.stop.mockRejectedValueOnce(raw);
    await import("./index");
    if (failure === "consumer") state.start.mock.calls[0]![0].onFatal(raw);
    else if (failure === "health")
      state.on.mock.calls.find(([event]) => event === "error")?.[1](raw);
    else if (failure === "drain") listeners.get("SIGTERM")?.();
    else if (failure !== "startup") listeners.get(failure)?.(raw);
    await vi.advanceTimersByTimeAsync(0);
    const code = {
      startup: "worker_startup_failed",
      consumer: "worker_consumer_failed",
      drain: "worker_drain_failed",
      health: "worker_health_listener_failed",
      unhandledRejection: "worker_unhandled_rejection",
      uncaughtException: "worker_uncaught_exception",
    }[failure];
    expect(
      log.mock.calls.some((call) => call[1]?.code === code && call[1]?.errorClass === "TypeError"),
    ).toBe(true);
    expect(inspect(log.mock.calls, { depth: 20 })).not.toContain(sentinel);
  },
);

it("logs the failed drain step and its unclosed queues, never the message", async () => {
  const sentinel = "synthetic-private-drain-message";
  const { WorkerDrainError } = await import("./runtime.js");
  state.stop.mockRejectedValueOnce(
    new WorkerDrainError(sentinel, "consumers", ["webhook-delivery"]),
  );
  const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
  await import("./index");
  listeners.get("SIGTERM")?.();
  await vi.advanceTimersByTimeAsync(0);
  expect(log).toHaveBeenCalledWith(
    "[worker] Unclean drain; exiting without tearing down shared clients:",
    {
      code: "worker_drain_failed",
      errorClass: "WorkerDrainError",
      reason: "consumers",
      pendingQueues: ["webhook-delivery"],
    },
  );
  expect(inspect(log.mock.calls, { depth: 20 })).not.toContain(sentinel);
});
