import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("../sandbox/services/sandboxes", () => ({
  createSandbox: vi.fn(),
  killSandbox: vi.fn(),
  runCommand: vi.fn(),
  setSandboxTimeout: vi.fn(),
  stopSandbox: vi.fn(),
}));
vi.mock("../sandbox/image-store/captures", () => ({ captureSandbox: vi.fn() }));
const communityRefresh = vi.hoisted(() => ({ stop: vi.fn(async () => {}), check: vi.fn() }));
const startCommunityRefresh = vi.hoisted(() => vi.fn(() => communityRefresh));
vi.mock("./community/refresh-schedule", () => ({
  startCommunityRefreshSchedule: startCommunityRefresh,
}));

const {
  startTemplateBuildOrchestrator,
  TemplateBuildScheduler,
  BuildCallTimeout,
  BUILD_COPY_ARGV,
  buildLeaseMs,
  callWithDeadline,
  freezeInput,
  stepTimeoutMs,
  TEMPLATE_BUILD_CLAIM_TTL_MS,
  TEMPLATE_BUILD_SERVICE_CALL_TIMEOUT_MS,
} = await import("./orchestrator");
const { classifyServiceError } = await import("./decide");
const { buildExecPlan } = await import("./exec-plan");
const { createPrismaClient } = await import("@wssp/db/client");

afterEach(() => vi.useRealTimers());

describe("claim TTL vs service call bound (§3.3)", () => {
  it("keeps every orchestrator call well inside a claim", () => {
    expect(TEMPLATE_BUILD_CLAIM_TTL_MS).toBe(120_000);
    expect(TEMPLATE_BUILD_SERVICE_CALL_TIMEOUT_MS).toBeLessThanOrEqual(60_000);
    expect(TEMPLATE_BUILD_SERVICE_CALL_TIMEOUT_MS).toBeLessThan(TEMPLATE_BUILD_CLAIM_TTL_MS);
  });

  it("a call past its bound rejects, and the rejection is ambiguous (same key replays)", async () => {
    vi.useFakeTimers();
    const late = callWithDeadline(() => new Promise(() => {}));
    vi.advanceTimersByTime(TEMPLATE_BUILD_SERVICE_CALL_TIMEOUT_MS);
    const error = await late.catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(BuildCallTimeout);
    expect(classifyServiceError("run", error)).toEqual({ kind: "ambiguous" });
    await expect(callWithDeadline(async () => 7)).resolves.toBe(7);
  });

  it("service transactions run under Prisma's default interactive timeout (no override)", () => {
    // createPrismaClient passes no `transactionOptions`, so every service
    // transaction an orchestrator call reaches is bounded at Prisma's 5 s.
    expect(createPrismaClient.toString()).not.toMatch(/transactionOptions|timeout/);
  });
});

const NOW = new Date("2026-11-03T12:00:00Z");
const build = {
  id: "b1",
  baseRevisionId: "rev1",
  poolId: "pool1",
  requestedHostId: null,
  cpuCount: 2,
  memoryMiB: 2048,
  diskGiB: 16,
  egressRequest: { mode: "allowlist", domains: ["pypi.org"], cidrs: [] },
  timeoutMinutes: 30,
  waitForCapacityMs: 60_000,
  buildSandboxId: "sbx1",
  contextSha256: "c".repeat(64),
  deadlineAt: new Date(NOW.getTime() + 10 * 60_000),
  templateId: "tpl1",
  recipe: { scrubPaths: ["/home/user/.cache/pip"] },
};
const exec = buildExecPlan({
  recipe: {
    version: 1,
    from: { template: "base" },
    steps: [
      { type: "workdir", path: "/home/user/it's" },
      { type: "run", script: "make", user: "root" },
      { type: "env", values: { FOO: "bar" } },
      { type: "run", script: "echo $FOO" },
      { type: "copy", src: ["app/"], dest: "./", owner: "user", mode: "0644" },
    ],
  },
  buildArgs: {},
  baseEnvs: {},
  guest: { uid: 1000, gid: 1000 },
});

describe("builtWithRoot provenance (§3.3, security)", () => {
  const plan = (steps: unknown[]) =>
    buildExecPlan({
      recipe: { version: 1, from: { template: "wssp-base" }, steps },
      buildArgs: {},
      baseEnvs: {},
      guest: { uid: 1000, gid: 1000 },
    }).builtWithRoot;

  it("derives from every executed step: COPY and the WORKDIR prelude are privileged", () => {
    expect(plan([{ type: "run", script: "true" }])).toBe(false);
    expect(plan([{ type: "copy", src: ["a"], dest: "/etc/a", owner: "user" }])).toBe(true);
    expect(plan([{ type: "workdir", path: "/srv/app" }])).toBe(true);
    expect(plan([{ type: "run", script: "true", user: "root" }])).toBe(true);
  });
});

describe("frozen service inputs (§3.3)", () => {
  it("create: the base revision, the build lease (timeout + window + 15 min, kill), the frozen wait and egress", () => {
    const { key, input } = freezeInput(build, exec, "create", 0, 0, NOW, 60);
    expect(key).toBe("tb:b1:create:0:0");
    expect(input).toEqual({
      template: "revision/rev1",
      poolId: "pool1",
      cpuCount: 2,
      memoryMiB: 2048,
      diskGiB: 16,
      idempotencyKey: key,
      timeoutMs: buildLeaseMs(30, 60),
      lifecycle: { onTimeout: "kill" },
      guestSudo: false,
      waitForCapacityMs: 60_000,
      egress: { mode: "allowlist", domains: ["pypi.org"], cidrs: [] },
    });
    expect(buildLeaseMs(30, 60)).toBe((30 + 60 + 15) * 60_000);
  });

  it("create: an open build request stays open (fallback grants) and an absent one adds no egress (§6.3)", () => {
    const open = freezeInput(
      { ...build, egressRequest: { mode: "open", domains: ["pypi.org"], cidrs: [] } },
      exec,
      "create",
      0,
      0,
      NOW,
      60,
    ).input as { egress?: unknown };
    expect(open.egress).toEqual({ mode: "open", domains: ["pypi.org"], cidrs: [] });
    const absent = freezeInput({ ...build, egressRequest: null }, exec, "create", 0, 0, NOW, 60)
      .input as { egress?: unknown };
    expect(absent.egress).toBeUndefined();
  });

  it("steps: the prelude and root RUNs carry runAs root; user RUNs do not; COPY carries the fixed helper spec", () => {
    expect(exec.steps.map((step) => step.kind)).toEqual(["prelude", "run", "run", "copy"]);
    const prelude = freezeInput(build, exec, "run", 0, 0, NOW, 60).input as {
      input: { script: string };
      extras: unknown;
    };
    expect(prelude.extras).toEqual({ runAs: "root" });
    // Quoted for sh: the path's own quote cannot break out.
    expect(prelude.input.script).toContain(`mk '/home/user/it'\\''s' user '1000:1000'`);
    const root = freezeInput(build, exec, "run", 1, 0, NOW, 60).input as Record<string, unknown>;
    expect(root).toMatchObject({
      input: {
        id: "sbx1",
        idempotencyKey: "tb:b1:run:1:0",
        script: "make",
        cwd: "/home/user/it's",
      },
      extras: { runAs: "root" },
    });
    const user = freezeInput(build, exec, "run", 2, 0, NOW, 60).input as Record<string, unknown>;
    expect(user).toMatchObject({ input: { envs: { FOO: "bar" } }, extras: {} });
    const copy = freezeInput(build, exec, "run", 3, 0, NOW, 60).input as Record<string, unknown>;
    expect(copy).toEqual({
      input: {
        id: "sbx1",
        idempotencyKey: "tb:b1:run:3:0",
        timeoutMs: 10 * 60_000,
        argv: BUILD_COPY_ARGV,
      },
      extras: {
        buildCopy: {
          contextPath: "/var/tmp/wssp-build/b1/context.tar",
          sha256: "c".repeat(64),
          src: ["app"],
          dest: "/home/user/it's/",
          owner: "user",
          mode: 0o644,
        },
      },
    });
  });

  it("a step's timeout is the remaining build time, capped at 30 min", () => {
    expect(stepTimeoutMs(new Date(NOW.getTime() + 5 * 60_000), NOW)).toBe(5 * 60_000);
    expect(stepTimeoutMs(new Date(NOW.getTime() + 90 * 60_000), NOW)).toBe(30 * 60_000);
    expect(stepTimeoutMs(new Date(NOW.getTime() - 1), NOW)).toBe(1_000);
  });

  it("lease re-anchor, stop and capture (template and scrub paths from the build)", () => {
    expect(freezeInput(build, exec, "timeout", 0, 0, NOW, 60).input).toEqual({
      id: "sbx1",
      idempotencyKey: "tb:b1:timeout:0:0",
      timeoutMs: 75 * 60_000,
    });
    expect(freezeInput(build, exec, "stop", 0, 0, NOW, 60).key).toBe("tb:b1:stop:0:0");
    expect(freezeInput(build, exec, "capture", 0, 1, NOW, 60).input).toEqual({
      id: "sbx1",
      idempotencyKey: "tb:b1:capture:0:1",
      templateId: "tpl1",
      scrubPaths: ["/home/user/.cache/pip"],
    });
    expect(freezeInput(build, exec, "import", 0, 0, NOW, 60).key).toBe("tb:b1:import:0:0");
    expect(freezeInput(build, exec, "context", 0, 0, NOW, 60).key).toBe("tb:b1:context:0:0");
  });
});

describe("startTemplateBuildOrchestrator", () => {
  it("runs the daily community refresh on the server and stops it with the tick", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const orchestrator = startTemplateBuildOrchestrator(new AbortController().signal);
    expect(startCommunityRefresh).toHaveBeenCalledTimes(1);
    await orchestrator.stop();
    expect(communityRefresh.stop).toHaveBeenCalledTimes(1);
    error.mockRestore();
  });
});

describe("TemplateBuildScheduler shutdown", () => {
  it("tells the running tick to stop and resolves stop() only after it returns", async () => {
    let release = () => {};
    let seenStop: (() => boolean) | undefined;
    const tick = vi.fn(async (shouldStop: () => boolean) => {
      seenStop = shouldStop;
      await new Promise<void>((resolve) => {
        release = resolve;
      });
    });
    const scheduler = new TemplateBuildScheduler(tick, 0);
    scheduler.wake();
    expect(tick).toHaveBeenCalledTimes(1);
    expect(seenStop?.()).toBe(false);
    scheduler.wake(); // coalesced; must not run after stop
    let stopped = false;
    const stopping = scheduler.stop().then(() => {
      stopped = true;
    });
    expect(seenStop?.()).toBe(true);
    await Promise.resolve();
    expect(stopped).toBe(false);
    release();
    await stopping;
    expect(stopped).toBe(true);
    expect(tick).toHaveBeenCalledTimes(1);
    scheduler.wake();
    expect(tick).toHaveBeenCalledTimes(1);
  });

  it("resolves at once when idle, and after a tick that throws", async () => {
    const idle = new TemplateBuildScheduler(async () => {}, 0);
    await expect(idle.stop()).resolves.toBeUndefined();
    const failing = new TemplateBuildScheduler(() => {
      throw new Error("sync failure");
    }, 0);
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    failing.wake();
    await expect(failing.stop()).resolves.toBeUndefined();
    error.mockRestore();
  });
});
