import { readFileSync } from "node:fs";
import { inspect } from "node:util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const instance = vi.hoisted(() => ({ start: vi.fn(), ready: vi.fn(), stop: vi.fn() }));
vi.mock("@wssp/db/instance-heartbeat", () => ({ startInstanceHeartbeat: instance.start }));
const state = vi.hoisted(() => ({
  mode: "embedded",
  backups: false,
  startTransfers: vi.fn(),
  startContexts: vi.fn(),
  closeContexts: vi.fn(),
  closeTransfers: vi.fn(),
  postgres: vi.fn(),
  redis: vi.fn(),
  disconnectDb: vi.fn(),
  disconnectRedis: vi.fn(),
  start: vi.fn(),
  stop: vi.fn(),
  events: [] as string[],
}));
vi.mock("@wssp/db", () => ({
  default: { $queryRaw: state.postgres, $disconnect: state.disconnectDb },
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    get BACKUP_ENABLED() {
      return state.backups;
    },
    get WORKER_MODE() {
      return state.mode;
    },
  },
}));
vi.mock("@wssp/queue", () => ({
  redisConnection: { ping: state.redis, disconnect: state.disconnectRedis },
}));
vi.mock("worker/runtime", () => ({
  startWorkerRuntime: state.start,
  WorkerDrainError: class WorkerDrainError extends Error {},
}));
vi.mock("./sandbox-transfers/runtime.js", () => ({ startTransferStore: state.startTransfers }));
vi.mock("./template-builds/runtime.js", () => ({
  startBuildContextStore: state.startContexts,
  bindBuildContextStores: vi.fn(),
}));
vi.mock("./sandbox-image-relay/index.js", () => ({
  resetImageRelay: vi.fn(async () => {}),
  imageRelaySpool: vi.fn(),
}));
vi.mock("./sandbox-image-relay/scheduler.js", () => ({
  startImageScheduler: vi.fn(() => () => {}),
}));
const markStorage = vi.hoisted(() => vi.fn());
vi.mock("@wssp/api/template-builds/config", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@wssp/api/template-builds/config")>()),
  markTemplateBuildStorageUnavailable: markStorage,
}));
const builds = vi.hoisted(() => ({ start: vi.fn(), stop: vi.fn() }));
vi.mock("@wssp/api/template-builds/orchestrator", () => ({
  startTemplateBuildOrchestrator: builds.start,
}));
const initializeReservations = vi.hoisted(() => vi.fn());
vi.mock("@wssp/api/sandbox/host-admission", () => ({
  initializeHostMemoryReservations: initializeReservations,
}));
const startOutbox = vi.hoisted(() => vi.fn());
const startRetention = vi.hoisted(() => vi.fn());
vi.mock("./sandbox-relay/outbox-processor.js", () => ({
  startSandboxOutboxProcessor: startOutbox,
}));
vi.mock("./sandbox-relay/command-output.js", () => ({
  startCommandOutputRetention: startRetention,
}));
const sweepHosts = vi.hoisted(() => vi.fn());
vi.mock("./sandbox-relay/host-liveness.js", () => ({ sweepConnectedHosts: sweepHosts }));
const relay = vi.hoisted(() => ({
  disposeTerminals: vi.fn(),
  disposeSessions: vi.fn(),
}));
vi.mock("./sandbox-relay/browser-terminal.js", () => ({
  browserTerminalService: { dispose: relay.disposeTerminals },
}));
vi.mock("./sandbox-relay/session-manager.js", () => ({
  sandboxRelaySessionManager: {
    dispose: relay.disposeSessions,
    verifyHostImage: vi.fn(),
    probeSandbox: vi.fn(),
  },
}));
const listeners = new Map<string, (...args: unknown[]) => void>();
beforeEach(() => {
  vi.useFakeTimers();
  vi.resetModules();
  vi.resetAllMocks();
  instance.start.mockReturnValue({ markReady: instance.ready, stop: instance.stop });
  instance.stop.mockResolvedValue(undefined);
  listeners.clear();
  state.mode = "embedded";
  state.backups = false;
  initializeReservations.mockResolvedValue(undefined);
  sweepHosts.mockResolvedValue({ disconnected: 0 });
  startOutbox.mockReturnValue(async () => {});
  startRetention.mockReturnValue(async () => {});
  state.startTransfers.mockResolvedValue({ close: state.closeTransfers });
  state.closeTransfers.mockResolvedValue(undefined);
  state.startContexts.mockResolvedValue({ close: state.closeContexts });
  state.closeContexts.mockResolvedValue(undefined);
  state.events.length = 0;
  builds.stop.mockResolvedValue(undefined);
  builds.start.mockReturnValue({ wake: vi.fn(), stop: builds.stop });
  vi.spyOn(process, "on").mockImplementation((event, listener) => {
    listeners.set(String(event), listener);
    return process;
  });
  vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
  state.postgres.mockResolvedValue(1);
  state.redis.mockResolvedValue("PONG");
  state.stop.mockImplementation(async () => {
    state.events.push("jobs-drained");
  });
  state.disconnectDb.mockImplementation(async () => {
    state.events.push("db-disconnect");
  });
  state.start.mockImplementation(async (options) => {
    expect(listeners.has("SIGTERM")).toBe(true);
    expect(listeners.has("SIGINT")).toBe(true);
    expect(listeners.has("unhandledRejection")).toBe(true);
    expect(options.signal).toBeInstanceOf(AbortSignal);
    return { isReady: () => true, stop: state.stop };
  });
});
afterEach(() => {
  vi.clearAllTimers();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

// Every test re-imports ./lifecycle after vi.resetModules(), so each one pays a
// cold module-graph import; under a full parallel turbo run that alone can pass
// the 5 s default and leave a timed-out start running into the next test.
const COLD_IMPORT_TIMEOUT_MS = 30_000;

describe("createServerLifecycle", { timeout: COLD_IMPORT_TIMEOUT_MS }, () => {
  it("owns signals before jobs, starts the default embedded runtime, and rejects re-entry", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { createServerLifecycle } = await import("./lifecycle");
    const lifecycle = createServerLifecycle();
    const listen = vi.fn(() => ({ close: vi.fn(), closeIdleConnections: vi.fn() }));
    expect(lifecycle.isWorkerReady()).toBe(false);
    await lifecycle.start(listen);
    expect(state.start).toHaveBeenCalledWith(expect.objectContaining({ embedded: true }));
    expect(lifecycle.isWorkerReady()).toBe(true);
    expect(listen).toHaveBeenCalledOnce();
    await expect(lifecycle.start(listen)).rejects.toThrow("already started");
    const notices = log.mock.calls
      .flat()
      .filter((line) => String(line).includes("Automatic database backups are OFF"));
    expect(notices).toHaveLength(1);
    expect(notices[0]).toContain("BACKUP_ENABLED=true");
    expect(notices[0]).toContain("BACKUP_SCHEDULE=daily");
  });

  it("initializes reservations before listener/outbox", async () => {
    let finish: (() => void) | undefined;
    initializeReservations.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    );
    const { createServerLifecycle } = await import("./lifecycle");
    const listen = vi.fn(() => ({ close: vi.fn(), closeIdleConnections: vi.fn() }));
    const starting = createServerLifecycle().start(listen);
    await vi.waitFor(() => expect(initializeReservations).toHaveBeenCalledOnce());
    expect(listen).not.toHaveBeenCalled();
    expect(startOutbox).not.toHaveBeenCalled();
    expect(state.start).not.toHaveBeenCalled();
    finish?.();
    await starting;
    expect(listen).toHaveBeenCalledOnce();
  });

  it("external placement never starts an embedded fallback", async () => {
    state.mode = "external";
    const { createServerLifecycle } = await import("./lifecycle");
    const lifecycle = createServerLifecycle();
    await lifecycle.start(() => ({ close: vi.fn(), closeIdleConnections: vi.fn() }));
    expect(state.start).not.toHaveBeenCalled();
  });

  it("starts the outbox processor alongside retention", async () => {
    const { createServerLifecycle } = await import("./lifecycle");
    const lifecycle = createServerLifecycle();
    await lifecycle.start(() => ({ close: vi.fn(), closeIdleConnections: vi.fn() }));
    expect(startRetention).toHaveBeenCalledOnce();
    expect(startOutbox).toHaveBeenCalledOnce();
  });

  it.each(["SIGTERM", "SIGINT", "unhandledRejection", "consumer failure"])(
    "%s during initial heartbeat stops admission and waits for cleanup before shared teardown",
    async (event) => {
      let finish: (() => void) | undefined;
      let fatal: ((error: Error) => void) | undefined;
      state.start.mockImplementation((options) => {
        fatal = options.onFatal;
        state.events.push("job-running");
        return new Promise((_resolve, reject) => {
          options.signal.addEventListener("abort", () => {
            state.events.push("admission-stopped");
            finish = () => {
              state.events.push("jobs-drained");
              reject(new Error("cancelled"));
            };
          });
        });
      });
      const { createServerLifecycle } = await import("./lifecycle");
      const lifecycle = createServerLifecycle();
      const listen = vi.fn(() => ({ close: vi.fn(), closeIdleConnections: vi.fn() }));
      const starting = lifecycle.start(listen);
      await vi.waitFor(() => expect(state.events).toContain("job-running"));
      if (event === "consumer failure") fatal?.(new Error("fatal"));
      else listeners.get(event)?.(new Error("fatal"));
      expect(lifecycle.isShuttingDown()).toBe(true);
      expect(state.events).toContain("admission-stopped");
      expect(state.disconnectDb).not.toHaveBeenCalled();
      expect(listen).not.toHaveBeenCalled();
      finish?.();
      await starting;
      expect(state.events.indexOf("jobs-drained")).toBeLessThan(
        state.events.indexOf("db-disconnect"),
      );
      expect(process.exit).toHaveBeenCalledWith(event.startsWith("SIG") ? 0 : 1);
      await expect(lifecycle.start(listen)).rejects.toThrow("already started");
    },
  );

  it("exits on an unclean startup drain without closing shared dependencies", async () => {
    const { WorkerDrainError } = await import("worker/runtime");
    state.start.mockRejectedValue(new WorkerDrainError("unfinished job"));
    const { createServerLifecycle } = await import("./lifecycle");
    await createServerLifecycle().start(() => ({ close: vi.fn(), closeIdleConnections: vi.fn() }));
    expect(state.disconnectDb).not.toHaveBeenCalled();
    expect(state.disconnectRedis).not.toHaveBeenCalled();
    expect(process.exit).toHaveBeenCalledWith(1);
  });

  it("bounds hung startup cancellation and refuses later listener admission", async () => {
    vi.useFakeTimers();
    state.start.mockImplementation(() => new Promise(() => {}));
    const { createServerLifecycle } = await import("./lifecycle");
    const lifecycle = createServerLifecycle();
    const listen = vi.fn(() => ({ close: vi.fn(), closeIdleConnections: vi.fn() }));
    void lifecycle.start(listen);
    await vi.waitFor(() => expect(state.start).toHaveBeenCalled());
    listeners.get("SIGTERM")?.();
    await vi.advanceTimersByTimeAsync(25_000);
    expect(process.exit).toHaveBeenCalledWith(1);
    expect(state.disconnectDb).not.toHaveBeenCalled();
    expect(listen).not.toHaveBeenCalled();
  });

  it("drains HTTP and jobs, preserves a fatal exit arriving during a signal drain", async () => {
    vi.useFakeTimers();
    let finish: (() => void) | undefined;
    state.stop.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    );
    const close = vi.fn((done: () => void) => {
      state.events.push("http-drained");
      done();
    });
    const closeIdleConnections = vi.fn(() => {
      state.events.push("idle-connections-closed");
    });
    const { createServerLifecycle } = await import("./lifecycle");
    const lifecycle = createServerLifecycle();
    await lifecycle.start(() => ({ close, closeIdleConnections }));
    listeners.get("SIGTERM")?.();
    listeners.get("unhandledRejection")?.(new Error("fatal while draining"));
    expect(lifecycle.isWorkerReady()).toBe(false);
    await vi.advanceTimersByTimeAsync(5000);
    expect(closeIdleConnections).toHaveBeenCalledOnce();
    expect(state.events.indexOf("idle-connections-closed")).toBeLessThan(
      state.events.indexOf("http-drained"),
    );
    expect(close).toHaveBeenCalledOnce();
    expect(state.disconnectDb).not.toHaveBeenCalled();
    finish?.();
    await vi.advanceTimersByTimeAsync(0);
    expect(state.stop).toHaveBeenCalledOnce();
    expect(state.disconnectDb).toHaveBeenCalledOnce();
    expect(process.exit).toHaveBeenCalledWith(1);
  });

  it("cancels pending dependency startup without creating workers or listener", async () => {
    let finish: (() => void) | undefined;
    state.postgres.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    );
    const { createServerLifecycle } = await import("./lifecycle");
    const lifecycle = createServerLifecycle();
    const listen = vi.fn(() => ({ close: vi.fn(), closeIdleConnections: vi.fn() }));
    const starting = lifecycle.start(listen);
    listeners.get("SIGINT")?.();
    finish?.();
    await starting;
    expect(state.start).not.toHaveBeenCalled();
    expect(listen).not.toHaveBeenCalled();
  });

  it("the real entrypoint wires lifecycle readiness and passes the server queue inventory", () => {
    const source = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
    expect(source).toContain("const lifecycle = createServerLifecycle()");
    expect(source).toMatch(/await lifecycle\.start\(\s*\(\) =>/);
    expect(source).toContain("await createApp(lifecycle)");
    const application = readFileSync(new URL("./app.ts", import.meta.url), "utf8");
    expect(application).toContain("lifecycle.isShuttingDown()");
    expect(application).toContain("lifecycle.isWorkerReady()");
    expect(application).toContain(
      "hasExternalConsumer(redisConnection, Object.values(QUEUE_NAMES))",
    );
    expect(source).not.toContain("startWorkerRuntime(");
  });
});

it("waits for spool recovery before listening and for spool drain before disconnecting PostgreSQL", async () => {
  state.mode = "external";
  let recover!: () => void;
  state.startTransfers.mockImplementation(
    () =>
      new Promise((resolve) => {
        recover = () => resolve({ close: state.closeTransfers });
      }),
  );
  let drained!: () => void;
  state.closeTransfers.mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        drained = resolve;
      }),
  );
  const { createServerLifecycle } = await import("./lifecycle");
  const lifecycle = createServerLifecycle();
  const listen = vi.fn(() => ({ close: (done: () => void) => done() }));
  const starting = lifecycle.start(listen);
  await vi.waitFor(() => expect(state.startTransfers).toHaveBeenCalledOnce());
  expect(listen).not.toHaveBeenCalled();
  recover();
  await starting;
  expect(listen).toHaveBeenCalledOnce();
  listeners.get("SIGTERM")!();
  await vi.advanceTimersByTimeAsync(5000);
  expect(state.closeTransfers).toHaveBeenCalledOnce();
  expect(state.disconnectDb).not.toHaveBeenCalled();
  drained();
  await vi.waitFor(() => expect(state.disconnectDb).toHaveBeenCalledOnce());
});

it("finishes build-context recovery before the transfer store starts, and drains both (template-builds §3.7)", async () => {
  state.mode = "external";
  let recovered!: () => void;
  state.startContexts.mockImplementation(
    () =>
      new Promise((resolve) => {
        recovered = () => {
          state.events.push("contexts-recovered");
          resolve({ close: state.closeContexts });
        };
      }),
  );
  state.startTransfers.mockImplementation(async () => {
    state.events.push("transfers-started");
    return { close: state.closeTransfers };
  });
  const { createServerLifecycle } = await import("./lifecycle");
  const lifecycle = createServerLifecycle();
  const starting = lifecycle.start(vi.fn(() => ({ close: (done: () => void) => done() })));
  await vi.waitFor(() => expect(state.startContexts).toHaveBeenCalledOnce());
  await vi.advanceTimersByTimeAsync(10);
  expect(state.startTransfers).not.toHaveBeenCalled();
  recovered();
  await starting;
  expect(state.events).toEqual(["contexts-recovered", "transfers-started"]);
  listeners.get("SIGTERM")!();
  await vi.advanceTimersByTimeAsync(5000);
  await vi.waitFor(() => expect(state.closeContexts).toHaveBeenCalledOnce());
});

it("JS-7: shutdown waits for the in-flight build tick before closing contexts and host sockets", async () => {
  state.mode = "external";
  let finishTick!: () => void;
  builds.stop.mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        finishTick = () => {
          state.events.push("build-tick-done");
          resolve();
        };
      }),
  );
  state.closeContexts.mockImplementation(async () => {
    state.events.push("contexts-closed");
  });
  relay.disposeSessions.mockImplementation(() => state.events.push("sockets-closed"));
  const { createServerLifecycle } = await import("./lifecycle");
  const lifecycle = createServerLifecycle();
  await lifecycle.start(() => ({ close: (done: () => void) => done() }));
  expect(builds.start).toHaveBeenCalledOnce();
  listeners.get("SIGTERM")!();
  await vi.advanceTimersByTimeAsync(10);
  expect(builds.stop).toHaveBeenCalled();
  expect(state.closeContexts).not.toHaveBeenCalled();
  expect(relay.disposeSessions).not.toHaveBeenCalled();
  finishTick();
  await vi.advanceTimersByTimeAsync(5000);
  await vi.waitFor(() => expect(relay.disposeSessions).toHaveBeenCalledOnce());
  expect(state.events.indexOf("build-tick-done")).toBeLessThan(
    state.events.indexOf("contexts-closed"),
  );
  expect(state.events.indexOf("contexts-closed")).toBeLessThan(
    state.events.indexOf("sockets-closed"),
  );
});

describe("C55-CC-3: terminals get their shutdown close whatever the drains do", {
  timeout: COLD_IMPORT_TIMEOUT_MS,
}, () => {
  async function started() {
    state.mode = "external";
    relay.disposeTerminals.mockImplementation(() => state.events.push("terminals-closed"));
    relay.disposeSessions.mockImplementation(() => state.events.push("sockets-closed"));
    const { createServerLifecycle } = await import("./lifecycle");
    const lifecycle = createServerLifecycle();
    await lifecycle.start(() => ({ close: (done: () => void) => done() }));
    return lifecycle;
  }

  it("a rejected drain still closes terminals first, then the host sockets", async () => {
    startOutbox.mockReturnValue(async () => {
      state.events.push("outbox-rejected");
      throw new Error("outbox drain failed");
    });
    await started();
    listeners.get("SIGTERM")!();
    await vi.advanceTimersByTimeAsync(0);
    expect(state.events.slice(0, 2)).toEqual(["terminals-closed", "outbox-rejected"]);
    await vi.advanceTimersByTimeAsync(5000);
    await vi.waitFor(() => expect(relay.disposeSessions).toHaveBeenCalledOnce());
    expect(relay.disposeTerminals).toHaveBeenCalledOnce();
    expect(state.events.indexOf("terminals-closed")).toBeLessThan(
      state.events.indexOf("sockets-closed"),
    );
    // The rejection still fails the exit.
    await vi.waitFor(() => expect(process.exit).toHaveBeenCalledWith(1));
  });

  it("a hung drain cut short by the watchdog has already closed the terminals", async () => {
    startOutbox.mockReturnValue(() => new Promise<void>(() => {}));
    await started();
    listeners.get("SIGTERM")!();
    await vi.advanceTimersByTimeAsync(0);
    expect(relay.disposeTerminals).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(25_000);
    expect(process.exit).toHaveBeenCalledWith(1);
    // The hung outbox may still own host sockets: they are not closed early.
    expect(relay.disposeSessions).not.toHaveBeenCalled();
  });
});

it.each(["unhandledRejection", "uncaughtException"])(
  "3A %s logs only a safe code and preserves fail-fast behavior",
  async (event) => {
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { createServerLifecycle } = await import("./lifecycle");
    const lifecycle = createServerLifecycle();
    const sentinel = "synthetic-prisma-env-stdin-global-3a";
    const raw = Object.assign(
      new Error(sentinel, { cause: new Error(Buffer.from(sentinel).toString("base64")) }),
      { name: sentinel, stack: sentinel },
    );
    listeners.get(event)!(raw);
    await vi.advanceTimersByTimeAsync(0);
    expect(log).toHaveBeenCalledWith(`[server] ${event}`, {
      code: "unhandled_error",
      errorClass: "Error",
    });
    expect(inspect(log.mock.calls, { depth: 20 })).not.toContain(sentinel);
    expect(inspect(log.mock.calls, { depth: 20 })).not.toContain(
      Buffer.from(sentinel).toString("base64"),
    );
    expect(process.exit).toHaveBeenCalledWith(1);
    if (event === "unhandledRejection") expect(lifecycle.isShuttingDown()).toBe(true);
  },
);

it.each(["startup", "embedded", "drain", "http-close"])(
  "sanitizes %s lifecycle failures with stable diagnostics",
  async (failure) => {
    const sentinel = "synthetic-private-lifecycle-error";
    const raw = Object.assign(new TypeError(sentinel, { cause: new Error(sentinel) }), {
      name: sentinel,
      stack: sentinel,
    });
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    if (failure === "startup") state.start.mockRejectedValueOnce(raw);
    if (failure === "drain") state.stop.mockRejectedValueOnce(raw);
    const { createServerLifecycle } = await import("./lifecycle");
    const lifecycle = createServerLifecycle();
    const starting = lifecycle.start(() => ({
      close: (done) => done(failure === "http-close" ? raw : undefined),
    }));
    if (failure === "startup") await vi.advanceTimersByTimeAsync(0);
    await starting;
    if (failure === "embedded") state.start.mock.calls[0]![0].onFatal(raw);
    else if (failure !== "startup") listeners.get("SIGTERM")?.();
    await vi.advanceTimersByTimeAsync(5000);
    const code = {
      startup: "server_startup_failed",
      embedded: "server_embedded_consumer_failed",
      drain: "server_background_drain_failed",
      "http-close": "server_http_close_failed",
    }[failure];
    expect(
      log.mock.calls.some((call) => call[1]?.code === code && call[1]?.errorClass === "TypeError"),
    ).toBe(true);
    expect(inspect(log.mock.calls, { depth: 20 })).not.toContain(sentinel);
  },
);

it("keeps serving with template builds unavailable when the context store cannot start", async () => {
  const sentinel = "/synthetic/private/path";
  state.startContexts.mockRejectedValueOnce(
    Object.assign(new Error(`EACCES: permission denied, mkdir '${sentinel}'`), {
      code: "EACCES",
    }),
  );
  const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
  const { createServerLifecycle } = await import("./lifecycle");
  const lifecycle = createServerLifecycle();
  const listen = vi.fn(() => ({ close: vi.fn(), closeIdleConnections: vi.fn() }));
  await lifecycle.start(listen);
  expect(listen).toHaveBeenCalledOnce();
  expect(state.startTransfers).toHaveBeenCalledOnce();
  expect(markStorage).toHaveBeenCalledOnce();
  expect(lifecycle.isShuttingDown()).toBe(false);
  expect(process.exit).not.toHaveBeenCalled();
  expect(log).toHaveBeenCalledWith("[server] Optional feature unavailable:", {
    step: "template_build_context_store",
    code: "server_optional_feature_unavailable",
    errorClass: "Error",
    errno: "EACCES",
  });
  expect(inspect(log.mock.calls, { depth: 20 })).not.toContain(sentinel);
});

it("names the failed startup step and errno without the message", async () => {
  const sentinel = "/synthetic/private/spool";
  state.startTransfers.mockRejectedValueOnce(Object.assign(new Error(sentinel), { code: "EROFS" }));
  const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
  const { createServerLifecycle } = await import("./lifecycle");
  const lifecycle = createServerLifecycle();
  const listen = vi.fn(() => ({ close: vi.fn(), closeIdleConnections: vi.fn() }));
  await lifecycle.start(listen);
  expect(listen).not.toHaveBeenCalled();
  expect(log).toHaveBeenCalledWith("[server] Startup failed:", {
    step: "transfer_store",
    code: "server_startup_failed",
    errorClass: "Error",
    errno: "EROFS",
  });
  expect(inspect(log.mock.calls, { depth: 20 })).not.toContain(sentinel);
});

describe("WP4 host_liveness_sweep", { timeout: COLD_IMPORT_TIMEOUT_MS }, () => {
  it("runs once, after the transfer store and before the listener and the outbox", async () => {
    const order: string[] = [];
    state.startTransfers.mockImplementation(async () => {
      order.push("transfer_store");
      return { close: state.closeTransfers };
    });
    sweepHosts.mockImplementation(async () => {
      order.push("host_liveness_sweep");
      return { disconnected: 2 };
    });
    startOutbox.mockImplementation(() => {
      order.push("outbox");
      return async () => {};
    });
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const { createServerLifecycle } = await import("./lifecycle");
    await createServerLifecycle().start(() => {
      order.push("http_listen");
      return { close: vi.fn(), closeIdleConnections: vi.fn() };
    });
    expect(order).toEqual(["transfer_store", "host_liveness_sweep", "http_listen", "outbox"]);
    expect(sweepHosts).toHaveBeenCalledOnce();
    // No periodic sweep: nothing re-runs it later.
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(sweepHosts).toHaveBeenCalledOnce();
  });

  it("a sweep failure fails boot: no listener, no outbox, the step is named", async () => {
    sweepHosts.mockRejectedValueOnce(new Error("connection refused"));
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { createServerLifecycle } = await import("./lifecycle");
    const listen = vi.fn(() => ({ close: vi.fn(), closeIdleConnections: vi.fn() }));
    await createServerLifecycle().start(listen);
    expect(listen).not.toHaveBeenCalled();
    expect(startOutbox).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledWith(
      "[server] Startup failed:",
      expect.objectContaining({ step: "host_liveness_sweep", code: "server_startup_failed" }),
    );
    await vi.waitFor(() => expect(process.exit).toHaveBeenCalledWith(1));
  });
});

it("registers after database startup and marks ready only after listen and embedded consumers", async () => {
  const { createServerLifecycle } = await import("./lifecycle");
  const lifecycle = createServerLifecycle();
  let listening!: () => void;
  const starting = lifecycle.start(
    () =>
      new Promise((resolve) => {
        listening = () => resolve({ close: (done) => done() });
      }),
  );
  expect(instance.start).not.toHaveBeenCalled();
  await vi.waitFor(() => expect(listening).toBeTypeOf("function"));
  expect(instance.start).toHaveBeenCalledExactlyOnceWith({ role: "server" });
  expect(state.start).toHaveBeenCalledWith(expect.objectContaining({ embedded: true }));
  expect(instance.ready).not.toHaveBeenCalled();
  listening();
  await starting;
  expect(instance.ready).toHaveBeenCalledOnce();
});

it("keeps the instance heartbeat through durable and HTTP drain, awaiting stop before Prisma disconnect", async () => {
  const { createServerLifecycle } = await import("./lifecycle");
  let finishJobs!: () => void;
  let finishHeartbeat!: () => void;
  state.stop.mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        finishJobs = resolve;
      }),
  );
  instance.stop.mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        finishHeartbeat = resolve;
      }),
  );
  const close = vi.fn((done: () => void) => done());
  await createServerLifecycle().start(() => ({ close }));
  listeners.get("SIGTERM")!();
  await vi.advanceTimersByTimeAsync(5000);
  expect(close).toHaveBeenCalledOnce();
  expect(instance.stop).not.toHaveBeenCalled();
  finishJobs();
  await vi.waitFor(() => expect(instance.stop).toHaveBeenCalledOnce());
  expect(state.closeTransfers).toHaveBeenCalledOnce();
  expect(state.closeContexts).toHaveBeenCalledOnce();
  expect(relay.disposeSessions).toHaveBeenCalledOnce();
  expect(state.disconnectDb).not.toHaveBeenCalled();
  finishHeartbeat();
  await vi.waitFor(() => expect(state.disconnectDb).toHaveBeenCalledOnce());
});

it("does not mark the server instance ready when its embedded consumers are unhealthy", async () => {
  state.start.mockResolvedValueOnce({ isReady: () => false, stop: state.stop });
  const { createServerLifecycle } = await import("./lifecycle");
  await createServerLifecycle().start(() => ({ close: vi.fn() }));
  expect(instance.ready).not.toHaveBeenCalled();
});

it("a failed HTTP listen never marks ready and awaits heartbeat stop before disconnect", async () => {
  const { createServerLifecycle } = await import("./lifecycle");
  let finishHeartbeat!: () => void;
  instance.stop.mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        finishHeartbeat = resolve;
      }),
  );
  const starting = createServerLifecycle().start(async () => {
    throw new Error("wssp_sdk_listen-private");
  });
  await vi.waitFor(() => expect(instance.stop).toHaveBeenCalledOnce());
  expect(instance.ready).not.toHaveBeenCalled();
  expect(state.disconnectDb).not.toHaveBeenCalled();
  finishHeartbeat();
  await starting;
  expect(state.disconnectDb).toHaveBeenCalledOnce();
  expect(process.exit).toHaveBeenCalledWith(1);
});

it("marks the instance ready once embedded consumers recover after startup", async () => {
  const isReady = vi.fn(() => false);
  state.start.mockResolvedValueOnce({ isReady, stop: state.stop });
  const { createServerLifecycle } = await import("./lifecycle");
  await createServerLifecycle().start(() => ({ close: vi.fn() }));
  await vi.advanceTimersByTimeAsync(2000);
  expect(instance.ready).not.toHaveBeenCalled();
  isReady.mockReturnValue(true);
  await vi.advanceTimersByTimeAsync(1000);
  expect(instance.ready).toHaveBeenCalledOnce();
  const checks = isReady.mock.calls.length;
  await vi.advanceTimersByTimeAsync(2000);
  expect(isReady).toHaveBeenCalledTimes(checks);
});

it("cancels readiness polling at shutdown before a late worker recovery", async () => {
  const isReady = vi.fn(() => false);
  state.start.mockResolvedValueOnce({ isReady, stop: state.stop });
  const { createServerLifecycle } = await import("./lifecycle");
  await createServerLifecycle().start(() => ({ close: (done) => done() }));
  listeners.get("SIGTERM")!();
  isReady.mockReturnValue(true);
  await vi.advanceTimersByTimeAsync(5000);
  expect(instance.ready).not.toHaveBeenCalled();
  expect(process.exit).toHaveBeenCalledWith(0);
});
