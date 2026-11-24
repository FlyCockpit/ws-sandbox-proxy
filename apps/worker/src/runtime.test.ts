import { QUEUE_NAMES } from "@wssp/queue/jobs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const instance = vi.hoisted(() => ({ start: vi.fn(), ready: vi.fn(), stop: vi.fn() }));
vi.mock("@wssp/db/instance-heartbeat", () => ({ startInstanceHeartbeat: instance.start }));
const state = vi.hoisted(() => ({
  events: [] as string[],
  workers: [] as Array<{
    name: string;
    options: { concurrency: number; autorun: boolean };
    running: boolean;
    emit(event: string, ...args: unknown[]): void;
    run: ReturnType<typeof vi.fn>;
    close: ReturnType<typeof vi.fn>;
    cancelAllJobs: ReturnType<typeof vi.fn>;
  }>,
  ping: vi.fn(),
  disconnect: vi.fn(),
  scheduler: vi.fn(),
  heartbeatStart: vi.fn(),
  heartbeatStop: vi.fn(),
  waitReady: vi.fn(),
  run: vi.fn(),
  imageUpsert: vi.fn(),
  imageRemove: vi.fn(),
  /** Schedulers already stored in Redis for the image-store queue. */
  imageStored: [] as { key: string }[],
  distribution: "auto" as string,
  restorable: true,
}));
vi.mock("@wssp/queue", async () => {
  const jobs = await import("@wssp/queue/jobs");
  return {
    ...jobs,
    createRedisConnection: () => ({
      ping: state.ping,
      disconnect: state.disconnect,
      status: "ready",
    }),
    reapExpiredAuthTokensQueue: { upsertJobScheduler: state.scheduler },
    imageStoreMaintenanceQueue: {
      add: vi.fn(),
      upsertJobScheduler: state.imageUpsert,
      removeJobScheduler: state.imageRemove,
      getJobSchedulers: vi.fn(async () => state.imageStored),
    },
    checkBackupFreshnessQueue: { upsertJobScheduler: state.scheduler },
    reapWebhookLogQueue: { upsertJobScheduler: state.scheduler },
    notifyDataDeletionsQueue: { upsertJobScheduler: state.scheduler },
    webhookDeliveryQueue: { addBulk: vi.fn(async () => []) },
  };
});
vi.mock("@wssp/api/webhooks/config", () => ({ loadWebhookConfig: () => null }));
vi.mock("@wssp/api/sandbox/image-store/config", () => ({
  imageDistributionMode: () => state.distribution,
}));
vi.mock("@wssp/api/sandbox/disk-offload/availability", () => ({
  canRestore: () => state.restorable,
}));
vi.mock("./handlers/deliver-webhook.js", () => ({ createDeliverWebhookHandler: () => vi.fn() }));
vi.mock("./handlers/notify-data-deletions.js", () => ({ handleNotifyDataDeletionsJob: vi.fn() }));
vi.mock("./handlers/reap-webhook-log.js", () => ({ handleReapWebhookLogJob: vi.fn() }));
vi.mock("./webhook-dispatcher.js", () => ({
  startWebhookDispatcher: () => {
    state.events.push("dispatcher-start");
    return {
      tick: async () => {},
      stop: async () => {
        state.events.push("dispatcher-stop");
      },
    };
  },
}));
vi.mock("@wssp/queue/consumer-health", () => ({
  createConsumerHeartbeat: (
    _connection: unknown,
    _mode: string,
    _queues: readonly string[],
    healthy: () => boolean,
  ) => ({
    start: state.heartbeatStart,
    stop: state.heartbeatStop,
    isReady: healthy,
  }),
}));
vi.mock("./backup-freshness-scheduler.js", () => ({
  syncBackupFreshnessScheduler: () => state.scheduler().then(() => "upserted"),
}));
vi.mock("./operational-alerts.js", () => ({
  closeOperationalAlertConnection: () => state.events.push("alerts-close"),
  sendOperationalFailureAlert: vi.fn(async () => {}),
}));
vi.mock("./handlers/check-backup-freshness.js", () => ({ handleCheckBackupFreshnessJob: vi.fn() }));
vi.mock("./handlers/image-store-maintenance.js", () => ({
  createImageStoreMaintenanceHandler: vi.fn(() => vi.fn()),
}));
vi.mock("./handlers/reap-expired-auth-tokens.js", () => ({
  handleReapExpiredAuthTokensJob: vi.fn(),
}));
vi.mock("bullmq", () => ({
  Worker: class {
    running = false;
    constructor(
      public name: string,
      _processor: unknown,
      public options: { concurrency: number; autorun: boolean },
    ) {
      state.workers.push(this);
    }
    handlers = new Map<string, (...args: unknown[]) => void>();
    on = vi.fn((event: string, handler: (...args: unknown[]) => void) => {
      this.handlers.set(event, handler);
    });
    emit(event: string, ...args: unknown[]) {
      this.handlers.get(event)?.(...args);
    }
    waitUntilReady = state.waitReady;
    isRunning = () => this.running;
    isPaused = () => false;
    run = vi.fn(() => {
      this.running = true;
      state.events.push("run");
      return state.run();
    });
    close = vi.fn(async () => {
      this.running = false;
      state.events.push("close");
    });
    cancelAllJobs = vi.fn(() => {
      state.events.push("cancel");
    });
  },
}));
beforeEach(() => {
  vi.resetModules();
  instance.start.mockReturnValue({ markReady: instance.ready, stop: instance.stop });
  instance.stop.mockResolvedValue(undefined);
  vi.clearAllMocks();
  state.workers.length = 0;
  state.events.length = 0;
  state.ping.mockResolvedValue("PONG");
  state.waitReady.mockResolvedValue(undefined);
  state.run.mockImplementation(() => new Promise<void>(() => {}));
  state.scheduler.mockImplementation(async () => {
    state.events.push("scheduler");
  });
  state.heartbeatStart.mockResolvedValue(undefined);
  state.heartbeatStop.mockImplementation(async () => {
    state.events.push("heartbeat-stop");
  });
  state.disconnect.mockImplementation(() => state.events.push("disconnect"));
  state.distribution = "auto";
  state.restorable = true;
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("startWorkerRuntime", () => {
  it("runs every declared queue embedded, with conservative concurrency and one scheduler path", async () => {
    const { startWorkerRuntime } = await import("./runtime");
    const runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
    expect(state.workers.map((worker) => worker.name).sort()).toEqual(
      Object.values(QUEUE_NAMES).sort(),
    );
    // Sweeps run one at a time; webhook delivery uses its configured slots (default 8).
    expect(
      state.workers.every(
        (worker) =>
          worker.options.concurrency === (worker.name === QUEUE_NAMES.webhookDelivery ? 8 : 1) &&
          !worker.options.autorun,
      ),
    ).toBe(true);
    expect(state.events).toContain("dispatcher-start");
    expect(state.events.lastIndexOf("scheduler")).toBeLessThan(state.events.indexOf("run"));
    expect(runtime.isReady()).toBe(true);
    await expect(startWorkerRuntime({ embedded: true, onFatal: vi.fn() })).rejects.toThrow(
      "already started",
    );
    const stop = runtime.stop();
    expect(runtime.stop()).toBe(stop);
    expect(runtime.isReady()).toBe(false);
    await stop;
    await expect(startWorkerRuntime({ embedded: false, onFatal: vi.fn() })).rejects.toThrow(
      "already started",
    );
  });

  it("schedules disk maintenance and the bucket sweep whenever a disk can be restored, whatever image distribution says", async () => {
    const scheduled = async () => {
      state.imageUpsert.mockClear();
      state.imageRemove.mockClear();
      const { startWorkerRuntime } = await import("./runtime");
      const runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
      await runtime.stop();
      vi.resetModules();
      return {
        on: state.imageUpsert.mock.calls.map((call) => call[0]).sort(),
        off: state.imageRemove.mock.calls.map((call) => call[0]).sort(),
      };
    };
    state.distribution = "off";
    state.restorable = true;
    // The sweep is the only reaper of orphaned disk objects (offload §6).
    expect(await scheduled()).toEqual({
      on: ["disk-offload-maintenance", "image-store-sweep"],
      off: ["image-store-gc", "image-store-prune"],
    });
    state.distribution = "auto";
    state.restorable = false;
    expect((await scheduled()).off).toEqual(["disk-offload-maintenance"]);
    state.distribution = "off";
    state.restorable = false;
    expect((await scheduled()).on).toEqual([]);
  });

  it("removes a stored scheduler that is no longer configured (the retired community refresh)", async () => {
    state.imageUpsert.mockClear();
    state.imageRemove.mockClear();
    state.distribution = "auto";
    state.restorable = true;
    state.imageStored = [{ key: "community-refresh" }, { key: "image-store-gc" }];
    try {
      const { startWorkerRuntime } = await import("./runtime");
      const runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
      await runtime.stop();
      vi.resetModules();
    } finally {
      state.imageStored = [];
    }
    expect(state.imageRemove.mock.calls.map((call) => call[0])).toEqual(["community-refresh"]);
  });

  it("still drains every consumer when heartbeat withdrawal fails", async () => {
    const { startWorkerRuntime } = await import("./runtime");
    const runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
    state.heartbeatStop.mockRejectedValueOnce(new Error("offline"));
    await expect(runtime.stop()).rejects.toThrow("did not close cleanly");
    expect(state.workers.every((worker) => worker.close.mock.calls.length === 1)).toBe(true);
  });

  it("cleans up partial startup and never starts consumers when scheduler registration fails", async () => {
    state.scheduler.mockRejectedValueOnce(new Error("registration failed"));
    const { startWorkerRuntime } = await import("./runtime");
    await expect(startWorkerRuntime({ embedded: true, onFatal: vi.fn() })).rejects.toThrow(
      "registration failed",
    );
    expect(
      state.workers.every(
        (worker) => worker.run.mock.calls.length === 0 && worker.close.mock.calls.length === 1,
      ),
    ).toBe(true);
    expect(state.disconnect).toHaveBeenCalledTimes(2);
  });

  it("retries startup Redis without creating duplicate consumers", async () => {
    vi.useFakeTimers();
    state.ping.mockRejectedValueOnce(new Error("offline"));
    const { startWorkerRuntime } = await import("./runtime");
    const starting = startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
    await vi.advanceTimersByTimeAsync(500);
    const runtime = await starting;
    expect(state.ping).toHaveBeenCalledTimes(2);
    expect(state.workers).toHaveLength(Object.keys(QUEUE_NAMES).length);
    await runtime.stop();
  });

  it("aborted startup cannot enter processing later", async () => {
    const controller = new AbortController();
    let release: (() => void) | undefined;
    state.ping.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    const { startWorkerRuntime } = await import("./runtime");
    const starting = startWorkerRuntime({
      embedded: true,
      onFatal: vi.fn(),
      signal: controller.signal,
    });
    const rejected = expect(starting).rejects.toThrow("cancelled");
    controller.abort();
    release?.();
    await rejected;
    expect(state.workers).toHaveLength(0);
  });

  it("closes admission immediately when cancelled during the initial heartbeat, and drains before cleanup", async () => {
    let publish: (() => void) | undefined;
    let drain: (() => void) | undefined;
    state.heartbeatStart.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          publish = resolve;
        }),
    );
    state.heartbeatStop.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          drain = resolve;
        }),
    );
    const controller = new AbortController();
    const { startWorkerRuntime } = await import("./runtime");
    const starting = startWorkerRuntime({
      embedded: true,
      onFatal: vi.fn(),
      signal: controller.signal,
    });
    const rejected = expect(starting).rejects.toThrow("cancelled");
    await vi.waitFor(() => expect(state.heartbeatStart).toHaveBeenCalled());
    expect(state.workers.every((worker) => worker.running)).toBe(true);
    controller.abort();
    expect(state.workers.every((worker) => worker.close.mock.calls.length === 1)).toBe(true);
    expect(state.disconnect).not.toHaveBeenCalled();
    publish?.();
    drain?.();
    await rejected;
    expect(state.disconnect).toHaveBeenCalledTimes(2);
  });

  it("propagates an unclean startup drain instead of disguising it as an ordinary startup failure", async () => {
    vi.useFakeTimers();
    state.heartbeatStart.mockRejectedValueOnce(new Error("publication failed"));
    state.heartbeatStop.mockImplementationOnce(() => new Promise(() => {}));
    const { startWorkerRuntime, WorkerDrainError } = await import("./runtime");
    const assertion = expect(
      startWorkerRuntime({ embedded: true, onFatal: vi.fn() }),
    ).rejects.toBeInstanceOf(WorkerDrainError);
    await vi.advanceTimersByTimeAsync(15_000);
    await assertion;
    expect(state.workers.every((worker) => worker.close.mock.calls.length === 1)).toBe(true);
    expect(state.disconnect).not.toHaveBeenCalled();
  });

  it("bounds a hung drain and stays unready without prematurely disconnecting dependencies", async () => {
    vi.useFakeTimers();
    const { startWorkerRuntime } = await import("./runtime");
    const runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
    state.workers[0]?.close.mockImplementation(() => new Promise(() => {}));
    const stopped = expect(runtime.stop()).rejects.toThrow("must exit");
    await vi.advanceTimersByTimeAsync(15_000);
    await stopped;
    expect(runtime.isReady()).toBe(false);
    expect(state.disconnect).not.toHaveBeenCalled();
  });

  it("cancels active jobs only after every consumer stopped admission, so a verify honouring its signal ends the drain in time", async () => {
    const { startWorkerRuntime } = await import("./runtime");
    const runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
    vi.useFakeTimers();
    // The image-store consumer holds an active verify: its close settles only
    // once the verify saw the abort signal.
    const verify = state.workers.find(
      (worker) => worker.name === QUEUE_NAMES.imageStoreMaintenance,
    );
    if (!verify) throw new Error("image-store consumer missing");
    let release: () => void = () => {};
    verify.close.mockImplementation(() => {
      state.events.push("close");
      return new Promise<void>((resolve) => {
        release = resolve;
      });
    });
    verify.cancelAllJobs.mockImplementation(() => {
      state.events.push("cancel");
      release();
    });
    const stopped = runtime.stop();
    await vi.advanceTimersByTimeAsync(0);
    await expect(stopped).resolves.toBeUndefined();
    const closes = state.events.flatMap((event, at) => (event === "close" ? [at] : []));
    const cancels = state.events.flatMap((event, at) => (event === "cancel" ? [at] : []));
    expect(closes).toHaveLength(state.workers.length);
    expect(cancels).toHaveLength(state.workers.length);
    expect(Math.max(...closes)).toBeLessThan(Math.min(...cancels));
    for (const worker of state.workers)
      expect(worker.cancelAllJobs).toHaveBeenCalledExactlyOnceWith("worker shutdown");
  });

  it("hands the image-store handler the runtime's drain signal, aborted before any job is cancelled", async () => {
    const handlers = await import("./handlers/image-store-maintenance.js");
    const { startWorkerRuntime } = await import("./runtime");
    const runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
    const factory = vi.mocked(handlers.createImageStoreMaintenanceHandler);
    expect(factory).toHaveBeenCalledOnce();
    const shutdown = factory.mock.calls[0]?.[1];
    if (!shutdown) throw new Error("no drain signal");
    expect(shutdown.aborted).toBe(false);
    let abortedAtCancel: boolean[] = [];
    for (const worker of state.workers)
      worker.cancelAllJobs.mockImplementation(() => {
        abortedAtCancel = [...abortedAtCancel, shutdown.aborted];
      });
    await runtime.stop();
    expect(shutdown.aborted).toBe(true);
    expect(abortedAtCancel).toEqual(state.workers.map(() => true));
  });

  it("names the failed drain step and only the queues whose consumer did not close cleanly", async () => {
    vi.useFakeTimers();
    let { startWorkerRuntime } = await import("./runtime");
    // Deadline: one consumer still waits on an active job.
    let runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
    const hung = state.workers[1]!;
    hung.close.mockImplementation(() => new Promise(() => {}));
    const deadline = runtime.stop().catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(15_000);
    expect(await deadline).toMatchObject({ reason: "deadline", pendingQueues: [hung.name] });
    // Consumers: one close rejected; the others closed cleanly.
    vi.resetModules();
    state.workers.length = 0;
    ({ startWorkerRuntime } = await import("./runtime"));
    runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
    const failed = state.workers[2]!;
    failed.close.mockRejectedValueOnce(new Error("still active"));
    await expect(runtime.stop()).rejects.toMatchObject({
      reason: "consumers",
      pendingQueues: [failed.name],
    });
    // Heartbeat: every consumer closed, the withdrawal failed.
    vi.resetModules();
    state.workers.length = 0;
    ({ startWorkerRuntime } = await import("./runtime"));
    runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
    state.heartbeatStop.mockRejectedValueOnce(new Error("offline"));
    await expect(runtime.stop()).rejects.toMatchObject({ reason: "heartbeat", pendingQueues: [] });
  });

  it("a missing or duplicate registered queue suppresses readiness", async () => {
    const { startWorkerRuntime } = await import("./runtime");
    const runtime = await startWorkerRuntime({ embedded: false, onFatal: vi.fn() });
    const worker = state.workers[0];
    if (!worker) throw new Error("missing test worker");
    worker.name = "unregistered-queue";
    expect(runtime.isReady()).toBe(false);
    await runtime.stop();
  });

  it("registers scheduler identity before the first job", async () => {
    const jobs = await import("@wssp/queue/jobs");
    const { startWorkerRuntime } = await import("./runtime");
    const runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
    expect(state.scheduler.mock.calls.map((args) => args[0]).filter(Boolean)).toEqual([
      jobs.NOTIFY_DATA_DELETIONS_JOB_SCHEDULER_ID,
      jobs.REAP_EXPIRED_AUTH_TOKENS_JOB_SCHEDULER_ID,
      jobs.REAP_WEBHOOK_LOG_JOB_SCHEDULER_ID,
    ]);
    expect(state.events.lastIndexOf("scheduler")).toBeLessThan(state.events.indexOf("run"));
    await runtime.stop();
  });

  it("cancelled scheduler startup admits no subsequent scheduler or job", async () => {
    const controller = new AbortController();
    state.scheduler.mockImplementationOnce(async () => {
      controller.abort();
    });
    const { startWorkerRuntime } = await import("./runtime");
    await expect(
      startWorkerRuntime({ embedded: true, onFatal: vi.fn(), signal: controller.signal }),
    ).rejects.toThrow("cancelled");
    expect(state.scheduler).toHaveBeenCalledOnce();
    expect(state.run).not.toHaveBeenCalled();
  });

  it("a pre-aborted startup and exhausted Redis retries cannot construct consumers", async () => {
    vi.useFakeTimers();
    let runtimeModule = await import("./runtime");
    await expect(
      runtimeModule.startWorkerRuntime({
        embedded: true,
        onFatal: vi.fn(),
        signal: AbortSignal.abort(),
      }),
    ).rejects.toThrow("cancelled");
    expect(state.ping).not.toHaveBeenCalled();
    expect(state.workers).toHaveLength(0);
    vi.resetModules();
    runtimeModule = await import("./runtime");
    state.ping.mockRejectedValue(new Error("offline"));
    const assertion = expect(
      runtimeModule.startWorkerRuntime({ embedded: true, onFatal: vi.fn() }),
    ).rejects.toThrow("offline");
    await vi.advanceTimersByTimeAsync(7500);
    await assertion;
    expect(state.ping).toHaveBeenCalledTimes(5);
    expect(state.workers).toHaveLength(0);
  });

  it("times out consumer readiness before starting any jobs", async () => {
    vi.useFakeTimers();
    state.waitReady.mockImplementation(() => new Promise(() => {}));
    const { startWorkerRuntime } = await import("./runtime");
    const assertion = expect(
      startWorkerRuntime({ embedded: true, onFatal: vi.fn() }),
    ).rejects.toThrow("startup timed out");
    await vi.advanceTimersByTimeAsync(10_000);
    await assertion;
    expect(state.run).not.toHaveBeenCalled();
    expect(state.workers.every((worker) => worker.close.mock.calls.length === 1)).toBe(true);
  });

  it("a consumer run rejection revokes readiness and reaches the host fatal path", async () => {
    state.run.mockRejectedValueOnce(new Error("consumer crashed"));
    const fatal = vi.fn();
    const { startWorkerRuntime } = await import("./runtime");
    const runtime = await startWorkerRuntime({ embedded: true, onFatal: fatal });
    expect(fatal).toHaveBeenCalledWith(expect.objectContaining({ message: "consumer crashed" }));
    expect(runtime.isReady()).toBe(false);
    await runtime.stop();
  });

  it("rejected consumer close cannot authorize runtime-owned connection teardown", async () => {
    const { startWorkerRuntime, WorkerDrainError } = await import("./runtime");
    const runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
    state.workers[0]?.close.mockRejectedValueOnce(new Error("still active"));
    await expect(runtime.stop()).rejects.toBeInstanceOf(WorkerDrainError);
    expect(state.disconnect).not.toHaveBeenCalled();
  });
});

it("worker connection, job and alert errors log only closed diagnostics", async () => {
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  const { sendOperationalFailureAlert } = await import("./operational-alerts.js");
  vi.mocked(sendOperationalFailureAlert).mockRejectedValue(new Error("private-alert-value"));
  const { startWorkerRuntime } = await import("./runtime");
  const runtime = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
  try {
    for (const worker of state.workers) {
      worker.emit("error", new Error("private-connection-value"));
      worker.emit("failed", undefined, new Error("private-job-value"));
    }
    // 6 connection errors, 6 job failures, 5 alert failures (webhook delivery
    // outcomes never alert: an alert would email err.message to admins).
    await vi.waitFor(() => expect(log).toHaveBeenCalledTimes(17));
    expect(JSON.stringify(log.mock.calls)).not.toContain("private-");
    expect(log.mock.calls.map((args) => args[1])).toEqual(
      expect.arrayContaining([
        { code: "data_deletion_job_failed", errorClass: "Error" },
        { code: "worker_connection_error", errorClass: "Error" },
        { code: "token_reaper_job_failed", errorClass: "Error" },
        { code: "backup_freshness_job_failed", errorClass: "Error" },
        { code: "image_store_job_failed", errorClass: "Error" },
        { code: "webhook_delivery_job_failed", errorClass: "Error" },
        { code: "webhook_log_reaper_failed", errorClass: "Error" },
        { code: "operational_alert_failed", errorClass: "Error" },
      ]),
    );
    const { sendOperationalFailureAlert: alert } = await import("./operational-alerts.js");
    expect(vi.mocked(alert).mock.calls.map((args) => args[0].queue)).not.toContain(
      "webhook-delivery",
    );
  } finally {
    await runtime.stop();
  }
});
it.each([1, 2, 3, 4])("scheduler failure %i logs only closed diagnostics", async (attempt) => {
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  let calls = 0;
  state.scheduler.mockImplementation(async () => {
    if (++calls === attempt) throw new Error("private-scheduler-value");
  });
  const { startWorkerRuntime } = await import("./runtime");
  await expect(startWorkerRuntime({ embedded: true, onFatal: vi.fn() })).rejects.toThrow(
    "private-scheduler-value",
  );
  expect(log).toHaveBeenCalledWith(expect.any(String), {
    code: [
      "data_deletion_scheduler_failed",
      "token_reaper_scheduler_failed",
      "webhook_log_scheduler_failed",
      "backup_freshness_scheduler_failed",
    ][attempt - 1],
    errorClass: "Error",
  });
  expect(JSON.stringify(log.mock.calls)).not.toContain("private-");
});

it("embedded consumers share the server instance; external consumers register and drain their own", async () => {
  const { startWorkerRuntime } = await import("./runtime");
  const embedded = await startWorkerRuntime({ embedded: true, onFatal: vi.fn() });
  expect(instance.start).not.toHaveBeenCalled();
  await embedded.stop();
  vi.resetModules();
  const externalStart = (await import("./runtime")).startWorkerRuntime;
  const runtime = await externalStart({ embedded: false, onFatal: vi.fn() });
  expect(instance.start).toHaveBeenCalledExactlyOnceWith({ role: "worker" });
  expect(instance.ready).toHaveBeenCalledOnce();
  let finishJobs!: () => void;
  state.workers.at(-1)!.close.mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        finishJobs = resolve;
      }),
  );
  let finishHeartbeat!: () => void;
  instance.stop.mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        finishHeartbeat = resolve;
      }),
  );
  const disconnects = state.disconnect.mock.calls.length;
  const stopping = runtime.stop();
  await vi.waitFor(() => expect(finishJobs).toBeTypeOf("function"));
  expect(instance.stop).not.toHaveBeenCalled();
  finishJobs();
  await vi.waitFor(() => expect(instance.stop).toHaveBeenCalledOnce());
  expect(state.disconnect).toHaveBeenCalledTimes(disconnects);
  finishHeartbeat();
  await stopping;
  expect(state.disconnect).toHaveBeenCalledTimes(disconnects + 2);
});
