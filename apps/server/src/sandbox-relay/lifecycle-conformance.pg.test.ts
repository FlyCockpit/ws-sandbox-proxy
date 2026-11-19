import { VM_SIZE_LIMITS, vmLiveMemoryChargeMiB } from "@wssp/sandbox-contracts";
import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

/**
 * C57 harness-shaped lifecycle conformance, real PostgreSQL.
 *
 * The REAL SDK (`packages/sdk/src`) → the REAL `/v1` Hono adapters (auth,
 * idempotency, routes, transfer store) → PostgreSQL → the REAL outbox
 * processor (fake lease clock) → the REAL relay session manager → the wire
 * host double `fake-node-daemon-harness.ts` (FakeRuntime semantics plus the
 * Rust journal/reconcile rules). The host-side fault rows come from the
 * shared fixture `crates/sandbox-protocol/fixtures/lifecycle_fault_matrix.json`,
 * which the Rust daemon suite asserts against the real daemon.
 *
 * Coverage boundary: this file proves the control plane end to end against a
 * host DOUBLE; the Rust half is `apps/cli/src/sandbox_relay/lifecycle_conformance_tests.rs`.
 * Real Incus/KVM hardware is outstanding evidence (docs/testing.md).
 */
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { Hono } from "hono";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import matrix from "../../../../crates/sandbox-protocol/fixtures/lifecycle_fault_matrix.json";
import { seedTemplateRevision } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import {
  binarySeed,
  runHarnessLifecycle,
  sha256Hex,
} from "../../../../packages/sdk/test/harness-lifecycle";

const spool = vi.hoisted(() => ({ dir: "" }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", async () => {
  // Default transfer caps come from the env declarations themselves: the
  // matrix asserts the shipped defaults, never a test-local copy.
  const { serverVars } = await import("@wssp/env/vars/server");
  return {
    env: {
      SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
      BETTER_AUTH_URL: "http://localhost:3000",
      BETTER_AUTH_SECRET: "c57-lifecycle-conformance",
      SANDBOX_MAX_TIMEOUT_MS: serverVars.SANDBOX_MAX_TIMEOUT_MS.parse(undefined),
      // Polling clients at a 5 ms interval: the per-key budget is raised for
      // the suite only (the shipped defaults are asserted by rate-limit.test.ts).
      RATE_LIMIT_SDK_IP_POINTS: 1_000_000,
      RATE_LIMIT_SDK_KEY_POINTS: 1_000_000,
      RATE_LIMIT_SDK_OWNER_POINTS: 1_000_000,
      RATE_LIMIT_RPC_POINTS: 1_000_000,
      RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
      get TRANSFER_SPOOL_DIR() {
        return spool.dir;
      },
      TRANSFER_MAX_BYTES: serverVars.TRANSFER_MAX_BYTES.parse(undefined),
      TRANSFER_DISK_BYTES: serverVars.TRANSFER_DISK_BYTES.parse(undefined),
      TRANSFER_OWNER_ACTIVE: serverVars.TRANSFER_OWNER_ACTIVE.parse(undefined),
      TRANSFER_GLOBAL_ACTIVE: serverVars.TRANSFER_GLOBAL_ACTIVE.parse(undefined),
      TRANSFER_IDLE_SECONDS: serverVars.TRANSFER_IDLE_SECONDS.parse(undefined),
      TRANSFER_ABSOLUTE_SECONDS: serverVars.TRANSFER_ABSOLUTE_SECONDS.parse(undefined),
    },
    ADMIN_EMAILS: new Set<string>(),
  };
});
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: {
    add: vi.fn(),
    upsertJobScheduler: vi.fn(),
    removeJobScheduler: vi.fn(),
  },
  checkBackupFreshnessQueue: {},
  notifyDataDeletionsQueue: {},
  reapExpiredAuthTokensQueue: {},
}));
vi.mock("../../../../packages/api/src/sandbox/sharing-budgets", () => ({
  consumeSharingWrite: async () => {},
  consumeInviteAccept: async () => {},
  consumeInviteIssue: async () => {},
}));
vi.mock("@wssp/mailer", () => ({
  sendEmail: async () => {},
  renderPoolAccessNotice: () => ({ subject: "Access changed", html: "Access changed" }),
}));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.57" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});

const db = await pgTestDatabase();
const { createSandboxApi } = await import("../sandbox-api/middleware.js");
const { startTransferStore } = await import("../sandbox-transfers/runtime.js");
const { bindRelayCaptures } = await import("../sandbox-transfers/captures.js");
const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");
const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
const { FakeNodeDaemon, fakeClock } = await import("./fake-node-daemon-harness.js");
const { expectNoTerminalResources } = await import("./terminal-resources-harness.js");
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { createHostToken } = await import("../../../../packages/api/src/sandbox/services/hosts");
const { SERVICE_SCOPES } = await import("@wssp/api/lib/service-scopes");
const { bindHostImageVerifier, bindHostSandboxProbe } = await import(
  "../../../../packages/api/src/sandbox/host-image-verifier"
);
const { bindSandboxDispatchWake } = await import("../../../../packages/api/src/sandbox/outbox");
const { createWsspClient } = await import("../../../../packages/sdk/src/index");
type WsspClient = ReturnType<typeof createWsspClient>;
type Daemon = InstanceType<typeof FakeNodeDaemon>;

const FP = `sha256:${"5".repeat(64)}`;
// The real adapters at the root, exactly as apps/server/src/app.ts mounts
// them, and once more under a reverse-proxy prefix (C58-1 regression legs).
const app = new Hono().route("/v1", createSandboxApi()).route("/edge/v1", createSandboxApi());
let store: Awaited<ReturnType<typeof startTransferStore>> | undefined;

beforeAll(async () => {
  spool.dir = await mkdtemp(join(tmpdir(), "wssp-c57-spool-"));
  store = await startTransferStore();
  bindRelayCaptures(store);
  bindHostSandboxProbe((input) => manager.probeSandbox(input));
  bindHostImageVerifier((input) => manager.verifyHostImage(input));
});
afterAll(async () => {
  bindSandboxDispatchWake(null);
  await manager.dispose();
  await store?.close();
  await rm(spool.dir, { recursive: true, force: true });
  await db.close();
});

/** The production wake contract, driven by the fake lease clock and serialized. */
function outboxPump(
  clock: ReturnType<typeof fakeClock>,
  observe: () => Promise<void> = async () => {},
) {
  let running: Promise<void> = Promise.resolve();
  let busy = false;
  let again = false;
  const failures: unknown[] = [];
  const wake = () => {
    if (busy) {
      again = true;
      return;
    }
    busy = true;
    running = (async () => {
      try {
        do {
          again = false;
          await observe();
          await processSandboxOutboxBatch(() => clock.now());
        } while (again);
      } catch (error) {
        failures.push(error);
      } finally {
        busy = false;
      }
    })();
  };
  bindSandboxDispatchWake(wake);
  return {
    wake,
    failures,
    async idle() {
      wake();
      await running;
    },
  };
}

type FetchFault = { route: RegExp; lose: "request" | "response"; hits?: number };

async function fixture(
  options: {
    memoryBudgetMiB?: number;
    terminal?: boolean;
    admission?: boolean;
    templateSize?: { cpuCount: number; memoryMiB: number };
    quiesce?: boolean;
  } = {},
) {
  const ownerId = `c57-${randomUUID()}`;
  await db.inspect.user.create({
    data: {
      id: ownerId,
      name: "Owner",
      email: `${ownerId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      ...options.templateSize,
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: FP,
    },
  });
  const session = { kind: "session" as const, ownerId };
  const token = await createHostToken(session, { hostId: host.id, name: "daemon" });
  const key = await createSdkKey(session, {
    name: "harness",
    scopes: [...SERVICE_SCOPES],
    resourceMode: "ALL_OWNED",
    hostIds: [],
    templateRevisionIds: [],
  });
  const clock = fakeClock();
  const pump = outboxPump(clock, async () => daemon.reportStorage());
  const daemon: Daemon = new FakeNodeDaemon(
    manager,
    {
      hostId: host.id,
      userId: ownerId,
      tokenId: token.token.id,
      credentialKind: "hostToken",
      expiresAt: null,
    },
    clock,
    {
      terminal: options.terminal,
      admission: options.admission ?? true,
      quiesce: options.quiesce,
    },
  );
  const faults: FetchFault[] = [];
  const requests: { method: string; url: string }[] = [];
  const fetch = async (input: string, init: RequestInit) => {
    const method = init.method ?? "GET";
    requests.push({ method, url: input });
    const fault = faults.find((f) => f.route.test(`${method} ${new URL(input).pathname}`));
    if (fault) {
      fault.hits = (fault.hits ?? 0) + 1;
      faults.splice(faults.indexOf(fault), 1);
      if (fault.lose === "request") throw new TypeError("fetch failed (request lost)");
      await app.fetch(new Request(input, init));
      throw new TypeError("fetch failed (response lost after commit)");
    }
    return app.fetch(new Request(input, init));
  };
  const client = (baseUrl = "https://wssp.test"): WsspClient =>
    createWsspClient({
      // Origin-only, the README form (C58-1 once turned it into `//v1/...`).
      baseUrl,
      apiKey: key.secret,
      fetch,
      polling: polling(),
    });
  if (options.memoryBudgetMiB) daemon.vmCapacity.memoryBudgetMiB = options.memoryBudgetMiB;
  await daemon.connect();
  await daemon.idle();
  await pump.idle();
  return { ownerId, host, template, daemon, pump, clock, client, faults, requests, key };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;

/**
 * This file drives the whole stack (SDK → /v1 → PostgreSQL → outbox → relay
 * → host double) and its slowest tests run hundreds of serialized database
 * transactions: eight creates on one host, 256 committed 8 KiB output chunks,
 * two-identity pool lifecycles. Measured on the 8-core development host they
 * take up to ~25 s while one other heavy job runs and up to ~38 s at load
 * average ~21; the 30 s pg default (vitest.pg.config.ts) is a generic value,
 * not a budget for this file. 90 s keeps >2x headroom over the worst
 * measured run; a real stall still fails with its own label, because `until`
 * and every fixture SDK wait end just before this deadline.
 */
vi.setConfig({ testTimeout: 90_000 });
/** `until` and fixture SDK waits end this long before the test deadline. */
const UNTIL_MARGIN_MS = 1_000;

/** The running test's wall-clock deadline (its own timeout), read by `until`. */
let testDeadline = 0;
beforeEach(({ task }) => {
  testDeadline = Date.now() + task.timeout;
});
/**
 * Fixture SDK polling. The default wait used to be a fixed 20 s, below the
 * test timeout and unrelated to the awaited work (a 2 MiB command follow
 * alone needed ~19 s under load). It now ends just before the test's own
 * deadline, so the SDK's labelled timeout, not Vitest's, reports a stall.
 * Calls that pin their own `waitTimeoutMs` are unaffected. A getter, because
 * the SDK reads its default wait afresh for every operation: a value fixed
 * when the client is built would let a wait started late in the test run
 * past the test's deadline.
 */
function polling() {
  return {
    intervalMs: 2,
    maxIntervalMs: 10,
    get waitTimeoutMs() {
      return Math.max(1_000, testDeadline - Date.now() - UNTIL_MARGIN_MS);
    },
  };
}

/**
 * Settles `promise` or gives up at `deadline`. Teardown must not hang on one
 * fixture past the hook timeout: Vitest would abandon the hook and leave the
 * remaining fixtures' daemons connected for the next test.
 */
async function byDeadline(promise: Promise<unknown>, deadline: number, label: string) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`teardown timed out waiting for ${label}`)),
          Math.max(0, deadline - Date.now()),
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Every fixture ends with no stray task failures on either side. Each one is
 * crashed and disconnected even when an earlier check (or an earlier
 * fixture) failed, so one failing test cannot leave a live host behind; the
 * first failure is rethrown after every fixture is down.
 */
const TEARDOWN_BUDGET_MS = 45_000; // below the 60 s hookTimeout
const live: Fixture[] = [];
afterEach(async () => {
  const deadline = Date.now() + TEARDOWN_BUDGET_MS;
  const errors: unknown[] = [];
  for (const f of live.splice(0)) {
    try {
      await byDeadline(f.daemon.idle(), deadline, "daemon idle");
      await byDeadline(f.pump.idle(), deadline, "outbox pump idle");
      expect(f.daemon.failures).toEqual([]);
      expect(f.pump.failures).toEqual([]);
    } catch (error) {
      errors.push(error);
    }
    f.daemon.crash();
    // removeSession revokes the epoch asynchronously: wait for it to land.
    for (;;) {
      const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
      if (host.status !== "CONNECTED") break;
      if (Date.now() >= deadline) {
        errors.push(new Error(`teardown: host ${f.host.id} still CONNECTED after crash`));
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
  }
  if (errors.length > 0) throw errors[0];
});
async function setup(options?: Parameters<typeof fixture>[0]) {
  const f = await fixture(options);
  live.push(f);
  return f;
}

const operationRow = (id: string) =>
  db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id } });

describe("C57 full lifecycle through SDK → /v1 → PostgreSQL → outbox → relay → host double", () => {
  it("negotiates the current protocol and records exact availability", async () => {
    const f = await setup({ admission: true, terminal: true });
    await f.daemon.idle();
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
    expect(host).toMatchObject({
      admissionEpoch: host.connectionEpoch,
      inventoryAcknowledgedEpoch: host.connectionEpoch,
      availabilityEpoch: host.connectionEpoch,
      availabilityCensusComplete: true,
    });
    expect(
      await db.inspect.sandboxTemplateAvailability.findFirst({
        where: { revisionId: f.template.id, hostId: f.host.id },
      }),
    ).toMatchObject({ localFingerprint: FP, status: "AVAILABLE" });
    expect(f.daemon.received.find((frame) => frame.type === "hello.ok")).toMatchObject({
      protocolVersion: "1.0",
      connectionEpoch: host.connectionEpoch,
    });
  });
  it("3D SDK create installs private defaults before boot; commands override through STOPPED and restart", async () => {
    const f = await setup({ admission: true });
    const { writeRevisionDefaults } = await import(
      "../../../../packages/api/src/sandbox/revision-config"
    );
    await db.inspect.sandboxRevisionConfig.deleteMany({ where: { revisionId: f.template.id } });
    await writeRevisionDefaults(db.inspect, f.ownerId, f.template.id, {
      APP: "synthetic-template-default",
      TEMPLATE_ONLY: "template-only",
    });
    const client = f.client();
    const sandbox = await client.sandboxes.create({
      diskGiB: 32,
      template: "revision/" + f.template.id,
      sandboxHostId: f.host.id,
      cpuCount: 2,
      memoryMiB: 2048,
      envs: { APP: "synthetic-private-default", KEEP: "retained" },
      lifecycle: { onTimeout: "stop" },
    });
    const config = f.daemon.received.findIndex((frame) => frame.type === "private.config.install");
    const boot = f.daemon.received.findIndex(
      (frame) => frame.type === "operation.dispatch" && frame.kind === "sandbox.create",
    );
    expect(config).toBeGreaterThan(-1);
    expect(boot).toBeGreaterThan(config);
    const row = await db.inspect.sandboxExecutionConfig.findUniqueOrThrow({
      where: { sandboxId: sandbox.id },
    });
    expect(row.acknowledgedEpoch).toBeGreaterThan(0);
    await sandbox.commands.run({ script: "true", envs: { APP: "override" } });
    expect([...f.daemon.commandEnvs.values()].at(-1)).toEqual({
      APP: "override",
      KEEP: "retained",
      TEMPLATE_ONLY: "template-only",
    });
    expect(JSON.stringify(sandbox)).not.toContain("synthetic-private-default");
    expect(JSON.stringify(f.daemon.dispatches)).not.toContain("synthetic-private-default");
    await sandbox.stop();
    expect(f.daemon.privateConfigs.has(sandbox.id)).toBe(true);
    f.daemon.crash();
    await f.daemon.connect();
    const connected = await client.sandboxes.connect(sandbox.id);
    await connected.commands.script("true");
    expect([...f.daemon.commandEnvs.values()].at(-1)).toEqual({
      APP: "synthetic-private-default",
      KEEP: "retained",
      TEMPLATE_ONLY: "template-only",
    });
    expect(connected.sandbox).toMatchObject({ diskGiB: 32, cpuCount: 2, memoryMiB: 2048 });
    expect(f.daemon.vms.get(sandbox.id)?.size).toEqual({
      diskGiB: 32,
      cpuCount: 2,
      memoryMiB: 2048,
    });
    const launches = f.daemon.dispatches.filter((frame) =>
      ["sandbox.create", "sandbox.reconnect"].includes(String(frame.kind)),
    );
    expect(launches).toHaveLength(2);
    for (const launch of launches)
      expect(launch).toMatchObject({ allocation: { diskGiB: 32 }, cpuCount: 2, memoryMiB: 2048 });
    await connected.destroy();
  });
  it("runs the harness lifecycle green, deterministically, with stable placement", async () => {
    const f = await setup();
    const seed = binarySeed(1536 * 1024, 57);
    const longScript = "./bootstrap.sh --long";
    let finishBoot!: () => void;
    f.daemon.programs.set(longScript, {
      stdout: new TextEncoder().encode("boot: ok\n".repeat(4096)),
      // Simulated guest time inside the 30-minute budget and the 1 h default lease.
      durationMs: 29 * 60_000,
      exitCode: 0,
      gate: new Promise<void>((resolve) => {
        finishBoot = resolve;
      }),
    });
    // Long-running: the guest holds the script open after its output until the
    // SDK has followed the committed output while the operation still runs.
    const booted = (async () => {
      try {
        await follow();
      } finally {
        // Never leave the gated guest script open: a failed wait above must
        // surface as itself (via `await booted`), not as the SDK's run
        // timing out on a script that can never finish.
        finishBoot();
      }
    })();
    // Handled here, rethrown by `await booted` below.
    booted.catch(() => {});
    async function follow() {
      await until(() => f.daemon.dispatches.some((d) => d.script === longScript), "long dispatch");
      const id = String(f.daemon.dispatches.find((d) => d.script === longScript)!.operationId);
      await until(
        async () => ["ACCEPTED", "RUNNING"].includes((await operationRow(id)).state),
        "long script running",
      );
      await until(
        () =>
          f.daemon.received.filter((m) => m.type === "command.output.ack" && m.operationId === id)
            .length >= 5,
        "long output committed",
      );
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    const transcript = await runHarnessLifecycle(f.client(), {
      template: "revision/" + f.template.id,
      sandboxHostId: f.host.id,
      seed,
      seedPath: "/home/user/seed.bin",
      longScript,
      failingScript: "make test || exit 1",
      between: async () => {
        // A due lease reclaim between steps would show up here: the pump runs
        // with the fake clock that the long script advanced.
        await f.pump.idle();
      },
    });
    await booted;
    expect(transcript.steps).toEqual([
      "create",
      "seed",
      "long-script",
      "nonzero",
      "diagnostics",
      "capture",
      "retain",
      "cold-reconnect",
      "warm-reconnect",
      "destroy",
    ]);
    expect(new Set(transcript.placements)).toEqual(new Set([f.host.id]));
    expect(transcript.states).toMatchObject({
      create: "READY",
      retain: "STOPPED",
      "cold-reconnect": "READY",
      "warm-reconnect": "READY",
    });
    expect(transcript.seedSha256).toBe(sha256Hex(seed));
    // The capture is byte-exact, including the invalid UTF-8 prefix.
    expect(transcript.captureSha256).toBe(sha256Hex(seed));
    expect(transcript.captureBytes).toBe(seed.byteLength);
    expect(transcript.longRun.exitCode).toBe(0);
    expect(transcript.longRun.stdout).toBe("boot: ok\n".repeat(4096));
    expect(transcript.longRun.events).toBeGreaterThan(0);
    expect(transcript.nonzero.exitCode).toBe(1);
    expect(transcript.diagnostics).toMatchObject({ exitCode: 1, complete: true });
    expect(transcript.diagnostics.tail).toBe("exec:script:make test || exit 1\n");
    // The 30-minute bootstrap budget reached the host verbatim.
    const longDispatch = f.daemon.dispatches.find(
      (d) => d.operationId === transcript.longRun.operationId,
    );
    expect(longDispatch).toMatchObject({ kind: "command.run", timeoutMs: 1_800_000 });
    // One VM, one effect per command, then gone.
    expect(f.daemon.effects.creates).toBe(1);
    expect(f.daemon.commandEffects(transcript.longRun.operationId)).toBe(1);
    expect(f.daemon.vms.size).toBe(0);
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({
      where: { id: transcript.sandboxId },
    });
    expect(sandbox).toMatchObject({
      state: "DELETED",
      originHostId: f.host.id,
      liveResourcesHeld: false,
    });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
    // The explicit stop is the only stop: the 29-minute guest run never let
    // the fake-clock lease reclaim (1 h default lease) fire.
    expect(f.daemon.dispatches.filter((d) => d.kind === "sandbox.stop")).toHaveLength(1);
  });
});

describe("C58-1 base URL forms reach the real adapters", () => {
  it.each([
    "https://wssp.test",
    "https://wssp.test/",
    "https://wssp.test/edge",
    "https://wssp.test/edge/",
  ])("%s: create, run and destroy route to /v1 (or the /edge prefix)", async (baseUrl) => {
    const f = await setup();
    const client = f.client(baseUrl);
    const sandbox = await client.sandboxes.create({
      template: "revision/" + f.template.id,
      sandboxHostId: f.host.id,
    });
    expect((await client.commands.script(sandbox.id, "echo routed")).stdout).toBe(
      "exec:script:echo routed\n",
    );
    await client.sandboxes.destroy(sandbox.id);
    const prefix = baseUrl.includes("/edge") ? "/edge" : "";
    const paths = f.requests.map((r) => new URL(r.url).pathname);
    expect(paths.length).toBeGreaterThan(0);
    for (const path of paths) expect(path.startsWith(`${prefix}/v1/`)).toBe(true);
  });
});

type Cell = (typeof matrix.cells)[number];
type Expectation = Cell["expect"]["sandbox.create"];
const settle = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error: error as Record<string, unknown> }),
  );
/** The error of a settled failure (the outcome must have failed). */
function errorOf<T>(
  outcome: { ok: true; value: T } | { ok: false; error: Record<string, unknown> },
): Record<string, unknown> {
  if (outcome.ok) throw new Error("expected a failure");
  return outcome.error;
}
/**
 * Polls `check` until it holds, up to the running test's own deadline.
 *
 * This was 2000 iterations of `setTimeout(2)`: an iteration count (about
 * 4–5 s of wall time) unrelated to the awaited work. On this suite's real
 * stack one create costs ~0.4–0.9 s server-side and concurrent creates
 * serialize, so a correct run could outlast the count (C57 six workers reach
 * their peak after ~10 s even on a quiet machine). The deadline is the
 * test's own timeout less a margin, so a real stall still fails with this
 * label rather than Vitest's generic test timeout.
 */
async function until(check: () => boolean | Promise<boolean>, label: string) {
  const started = Date.now();
  const deadline = testDeadline - UNTIL_MARGIN_MS;
  while (!(await check())) {
    if (Date.now() >= deadline)
      throw new Error(`timed out waiting for ${label} after ${Date.now() - started} ms`);
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}

/** Arm the cell's loss: a fetch fault (commit) or a host crash point (dispatch/effect/ack). */
function arm(f: Fixture, cell: Cell, kind: "sandbox.create" | "command.run", route: RegExp) {
  if (cell.host === null) f.faults.push({ route, lose: cell.direction as "request" | "response" });
  else
    f.daemon.arm({
      kind,
      journal: cell.host.journal as "intent" | "effect" | "result" | "delivered" | null,
      effect: cell.host.effect,
    });
}
/** A crashed host restarts on its durable journal: receipts, census, reconcile. */
async function restartIfCrashed(f: Fixture, cell: Cell) {
  if (cell.host === null) return;
  await until(() => f.daemon.socket === undefined, "host crash");
  await f.daemon.idle();
  await f.daemon.connect();
  await f.pump.idle();
}
function expectOutcome(
  outcome: Awaited<ReturnType<typeof settle>>,
  expected: Expectation,
  operationId: string,
) {
  if (expected.operation === "succeeded") {
    expect(outcome.ok, String(!outcome.ok && outcome.error)).toBe(true);
    return;
  }
  expect(outcome.ok).toBe(false);
  const error = errorOf(outcome);
  // Every failure carries THIS operation: the caller can resume, never re-create.
  expect(error.operationId).toBe(operationId);
  if (expected.operation === "unknown_outcome") expect(error.kind).toBe("unknown");
  // Polling may observe UNKNOWN before the targeted never-issued proof commits.
  // Durable state is checked separately after the host pump drains.
  else if (
    "operationErrorCode" in expected &&
    expected.operationErrorCode === "host_effect_not_issued" &&
    error.kind === "unknown"
  ) {
    expect(error.operationErrorCode).toBe("unknown_outcome");
  } else
    expect(error.operationErrorCode).toBe(
      expected.receipt?.errorCode ??
        ("operationErrorCode" in expected ? expected.operationErrorCode : undefined),
    );
}
function expectReceipt(f: Fixture, operationId: string, expected: Expectation) {
  const sent = f.daemon.receipts.filter((r) => r.operationId === operationId);
  if (expected.receipt === null) {
    expect(sent).toEqual([]);
    return;
  }
  expect(sent).toHaveLength(1);
  expect(sent[0]).toMatchObject({
    state: expected.receipt.state,
    error: expected.receipt.errorCode === null ? null : { code: expected.receipt.errorCode },
  });
}

describe("C57 fault matrix: loss at commit/dispatch/effect/ack, both directions (shared fixture rows)", () => {
  it.each(matrix.cells)(
    "$id — sandbox.create: receipts and placement stay stable; an uncertain retry never makes a second VM",
    async (cell) => {
      const f = await setup();
      const expected = cell.expect["sandbox.create"];
      const key = `matrix-create-${cell.id}`;
      const body = { template: "revision/" + f.template.id, sandboxHostId: f.host.id };
      arm(f, cell, "sandbox.create", /^POST \/v1\/sandboxes$/);
      const first = settle(f.client().sandboxes.create(body, { idempotencyKey: key }));
      await restartIfCrashed(f, cell);
      const outcome = await first;
      const operations = await db.inspect.sandboxOperation.findMany({
        where: { userId: f.ownerId, kind: "CREATE_SANDBOX" },
      });
      expect(operations).toHaveLength(1);
      const operation = operations[0]!;
      expectOutcome(outcome, expected, operation.id);
      // The uncertain retry: a FRESH client (a restarted worker) under the same key.
      const retry = await settle(f.client().sandboxes.create(body, { idempotencyKey: key }));
      expectOutcome(retry, expected, operation.id);
      // A restarted worker scanning after every claim lease (30 s) expired.
      f.clock.advance(31_000);
      await f.pump.idle();
      await f.daemon.idle();
      await f.pump.idle();
      expect(
        await db.inspect.sandboxOperation.count({
          where: { userId: f.ownerId, kind: "CREATE_SANDBOX" },
        }),
      ).toBe(1);
      expect((await operationRow(operation.id)).state).toBe(expected.operation.toUpperCase());
      // Dispatched exactly once: no loss, and no retry, ever re-issues the launch.
      expect(f.daemon.dispatches.filter((d) => d.operationId === operation.id)).toHaveLength(1);
      expect(f.daemon.effects.creates).toBe(expected.effects);
      expect(f.daemon.vms.size).toBe(expected.effects);
      expectReceipt(f, operation.id, expected);
      const sandbox = await db.inspect.sandbox.findUniqueOrThrow({
        where: { id: operation.sandboxId },
      });
      expect(sandbox.originHostId).toBe(f.host.id);
      if (expected.receipt?.state === "unknown_outcome") {
        // Uncertain creates now converge through durable teardown. The
        // daemon's original UNKNOWN receipt still describes the lost effect.
        expect(sandbox).toMatchObject({
          state: "DELETED",
          sandboxHostId: null,
          liveResourcesHeld: false,
          diskReservationHeld: false,
        });
      } else expect(sandbox.sandboxHostId).toBe(f.host.id);
      if (cell.boundary === "commit") {
        const submissions = f.requests.filter(
          (r) => r.method === "POST" && new URL(r.url).pathname === "/v1/sandboxes",
        );
        // The lost request/response was re-sent under the SAME key, then the retry.
        expect(submissions.length).toBeGreaterThanOrEqual(3);
      }
    },
  );

  it.each(matrix.cells)(
    "$id — command.run: no duplicate command effect on an uncertain retry",
    async (cell) => {
      const f = await setup();
      const expected = cell.expect["command.run"];
      const sandbox = await f
        .client()
        .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
      const key = `matrix-run-${cell.id}`;
      const input = { script: `echo matrix-${cell.id}` };
      // C58-2: an UNKNOWN_OUTCOME command reports `unknown` promptly, within a
      // budget far below its own deadline (it once waited it out as `timeout`).
      const wait = expected.operation === "unknown_outcome" ? { waitTimeoutMs: 5_000 } : {};
      arm(f, cell, "command.run", /^POST \/v1\/sandboxes\/[^/]+\/commands$/);
      const first = settle(
        f.client().commands.run(sandbox.id, input, { idempotencyKey: key, ...wait }),
      );
      await restartIfCrashed(f, cell);
      const outcome = await first;
      const operations = await db.inspect.sandboxOperation.findMany({
        where: { userId: f.ownerId, kind: "RUN_COMMAND" },
      });
      expect(operations).toHaveLength(1);
      const operation = operations[0]!;
      expectOutcome(outcome, expected, operation.id);
      const retry = await settle(
        f.client().commands.run(sandbox.id, input, { idempotencyKey: key, ...wait }),
      );
      expectOutcome(retry, expected, operation.id);
      f.clock.advance(31_000);
      await f.pump.idle();
      // The operation read still tells the caller the truth.
      expect((await f.client().commands.stat(operation.id)).state).toBe(
        expected.operation.toUpperCase(),
      );
      if (outcome.ok && retry.ok) {
        expect(retry.value).toMatchObject({
          operationId: operation.id,
          exitCode: 0,
          stdout: `exec:script:echo matrix-${cell.id}\n`,
        });
      }
      await f.daemon.idle();
      await f.pump.idle();
      expect(
        await db.inspect.sandboxOperation.count({
          where: { userId: f.ownerId, kind: "RUN_COMMAND" },
        }),
      ).toBe(1);
      expect((await operationRow(operation.id)).state).toBe(expected.operation.toUpperCase());
      expect(f.daemon.dispatches.filter((d) => d.operationId === operation.id)).toHaveLength(1);
      expect(f.daemon.commandEffects(operation.id)).toBe(expected.effects);
      expectReceipt(f, operation.id, expected);
      // The VM survived every host loss: one VM, same placement.
      expect(f.daemon.effects.creates).toBe(1);
      expect(
        (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } })).sandboxHostId,
      ).toBe(f.host.id);
    },
  );
});

function alignedMemoryBudget(slots: number): number {
  const step = VM_SIZE_LIMITS.memoryMiBStep;
  return Math.ceil((slots * vmLiveMemoryChargeMiB(1024)) / step) * step;
}

describe("C57 concurrency: six workers, retained VMs and a detached broker", () => {
  it("holds the host's live-sandbox count through six concurrent workers and two retained VMs", async () => {
    const f = await setup({ memoryBudgetMiB: alignedMemoryBudget(6) });
    const body = { template: "revision/" + f.template.id, sandboxHostId: f.host.id };
    // Two retained VMs: stopped, disk kept, no live slot.
    const retained = [];
    for (let i = 0; i < 2; i++) {
      const sandbox = await f.client().sandboxes.create(body);
      retained.push((await f.client().sandboxes.stop(sandbox.id)).id);
    }
    const host = () => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
    expect((await host()).liveCount).toBe(0);

    let release!: () => void;
    const peak = new Promise<void>((resolve) => {
      release = resolve;
    });
    const ready: string[] = [];
    let atPeak!: () => void;
    const allReady = new Promise<void>((resolve) => {
      atPeak = resolve;
    });
    const workers = Array.from({ length: 6 }, async (_, worker) => {
      const client = f.client();
      const sandbox = await client.sandboxes.create(body, { idempotencyKey: `worker-${worker}` });
      const run = await client.commands.script(sandbox.id, `echo worker-${worker}`);
      // The low-level receipt and operation-ID follower also work on 10.6.
      const process = await client.transport.request("startCommand", {
        params: { id: sandbox.id },
        body: { script: `job-${worker} || exit 1` },
        idempotencyKey: `legacy-start-${worker}`,
      });
      const broker = f.client();
      const tail = await broker.commands.tail(process.operationId);
      const stat = await broker.commands.stat(process.operationId);
      ready.push(sandbox.id);
      if (ready.length === 6) atPeak();
      await peak;
      await client.sandboxes.destroy(sandbox.id);
      return { sandbox, run, tail, stat };
    });
    // Await the peak itself, not a poll budget: six creates serialize on the
    // host and each worker then runs three commands, so the peak takes
    // seconds of real work. A worker that fails before the peak rejects the
    // race; the rest are released so none is left parked on `peak`.
    try {
      await Promise.race([allReady, Promise.all(workers)]);
    } catch (error) {
      release();
      await Promise.allSettled(workers);
      throw error;
    }
    expect(ready).toHaveLength(6);
    // At the peak: exactly the six live slots, the cap holds for creates AND cold boots.
    expect((await host()).liveCount).toBe(6);
    const creates = () =>
      db.inspect.sandboxOperation.count({ where: { userId: f.ownerId, kind: "CREATE_SANDBOX" } });
    const before = await creates();
    // The server's answer is a definite capacity refusal that commits nothing,
    // for a create AND for a cold boot of a retained VM.
    const raw = f.client().transport;
    const extra = await settle(
      raw.request("createSandbox", { body, idempotencyKey: `extra-${randomUUID()}` }),
    );
    expect(errorOf(extra)).toMatchObject({
      kind: "capacity",
      code: "sandbox.host_capacity",
    });
    const boot = await settle(
      raw.request("reconnectSandbox", {
        params: { id: retained[0]! },
        body: { mode: "cold" },
        idempotencyKey: `boot-${randomUUID()}`,
      }),
    );
    expect(errorOf(boot)).toMatchObject({
      kind: "capacity",
      code: "sandbox.host_capacity",
    });
    // C57-R1-4: a same-key retry AT capacity replays the original create:
    // replay precedes lifecycle/capacity validation, so it is that op again,
    // never a capacity refusal and never a new operation.
    const original = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { userId: f.ownerId, kind: "CREATE_SANDBOX", idempotencyKey: "worker-0" },
    });
    const replay = await settle(raw.request("createSandbox", { body, idempotencyKey: "worker-0" }));
    expect(replay.ok, String(!replay.ok && JSON.stringify(replay.error))).toBe(true);
    expect(replay.ok && replay.value).toMatchObject({ operationId: original.id });
    // The lifecycle client waits capacity out (retryable) within its budget.
    const waited = await settle(f.client().sandboxes.create(body, { waitTimeoutMs: 200 }));
    expect(waited.ok).toBe(false);
    expect(await creates()).toBe(before);
    expect((await host()).liveCount).toBe(6);
    release();
    const results = await Promise.all(workers);
    results.forEach(({ run, tail, stat }, worker) => {
      expect(run).toMatchObject({ exitCode: 0, stdout: `exec:script:echo worker-${worker}\n` });
      expect(tail.stdout).toBe(`exec:script:job-${worker} || exit 1\n`);
      expect(stat).toMatchObject({ exitCode: 1, complete: true });
    });
    await f.pump.idle();
    expect((await host()).liveCount).toBe(0);
    // Retained VMs were never touched by the refused boot and still boot now.
    expect([...f.daemon.vms.values()].map((vm) => vm.state)).toEqual(["stopped", "stopped"]);
    const booted = await f.client().sandboxes.connect(retained[0]!, { mode: "cold" });
    expect(booted).toMatchObject({ state: "READY", hostId: f.host.id });
    expect(f.daemon.effects.creates).toBe(8);
    expect(
      await db.inspect.sandboxOperation.count({
        where: { userId: f.ownerId, kind: "CREATE_SANDBOX" },
      }),
    ).toBe(8);
  });
});

describe("C57 cancellation and capture safety", () => {
  async function longRunning(f: Fixture) {
    const sandbox = await f
      .client()
      .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
    let finish!: () => void;
    const gate = new Promise<void>((resolve) => {
      finish = resolve;
    });
    f.daemon.programs.set("./serve --forever", { gate, stdout: new TextEncoder().encode("up\n") });
    return { sandbox, finish };
  }

  it("default observer abort detaches without cancellation or a second command effect", async () => {
    const f = await setup();
    const { sandbox, finish } = await longRunning(f);
    const abort = new AbortController();
    const run = settle(
      f
        .client()
        .commands.run(sandbox.id, { script: "./serve --forever" }, { signal: abort.signal }),
    );
    await until(() => f.daemon.effects.commands.size === 1, "running");
    const operationId = [...f.daemon.effects.commands.keys()][0]!;
    abort.abort();
    expect(errorOf(await run)).toMatchObject({ kind: "aborted", phase: "follow", operationId });
    expect(f.daemon.received.some((frame) => frame.type === "operation.cancel")).toBe(false);
    expect((await operationRow(operationId)).state).not.toBe("CANCELLED");
    finish();
    expect((await f.client().operations.wait(operationId)).outcome).toBe("succeeded");
    expect(f.daemon.commandEffects(operationId)).toBe(1);
  });

  it("checked natural nonzero completion keeps SUCCEEDED metadata and one effect", async () => {
    const f = await setup();
    const sandbox = await f
      .client()
      .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
    const outcome = await settle(f.client().commands.script(sandbox.id, "make test || exit 1"));
    const caught = errorOf(outcome);
    expect(caught).toMatchObject({
      name: "CommandExitError",
      kind: "command_exit",
      exitCode: 1,
      outputAvailability: "available",
    });
    expect(caught.operationId).toBeTypeOf("string");
    const operationId = caught.operationId;
    if (typeof operationId !== "string") throw new Error("Expected command recovery identity.");
    expect((await operationRow(operationId)).state).toBe("SUCCEEDED");
    expect(f.daemon.commandEffects(operationId)).toBe(1);
  });

  it("never reports a cancelled command, or its output capture, safe before the host's cancel ACK", async () => {
    const f = await setup();
    const { sandbox, finish } = await longRunning(f);
    let ack!: () => void;
    f.daemon.holdCancels(
      new Promise<void>((resolve) => {
        ack = resolve;
      }),
    );
    const client = f.client();
    const abort = new AbortController();
    // The ACK is held below, so the acknowledgement window always expires;
    // the same budget also bounds the cancel submission itself, which must
    // commit (CANCEL_REQUESTED) inside it. 400 ms was exceeded by that one
    // request under load (the run then settled on an uncertain submission
    // before the cancel committed); 5 s covers it with wide margin.
    const run = settle(
      client.commands.run(
        sandbox.id,
        { script: "./serve --forever" },
        { signal: abort.signal, onAbort: "cancel", cancelAckTimeoutMs: 5_000 },
      ),
    );
    await until(
      () => f.daemon.commandEffects([...f.daemon.effects.commands.keys()][0] ?? "") === 1,
      "running",
    );
    const operationId = [...f.daemon.effects.commands.keys()][0]!;
    const capture = settle(f.client().commands.tail(operationId, { waitTimeoutMs: 20_000 }));
    // Observed directly: a race against an already-resolved promise would
    // always lose to it (the extra `.then` hop), proving nothing.
    let captureSettled = false;
    capture.then(
      () => {
        captureSettled = true;
      },
      () => {
        captureSettled = true;
      },
    );
    abort.abort();
    // The ACK is held: the abort settles `unknown`, never `aborted`.
    const aborted = await run;
    expect(aborted.ok).toBe(false);
    expect(errorOf(aborted)).toMatchObject({
      kind: "unknown",
      operationId,
    });
    const before = await f.client().commands.stat(operationId);
    expect(before.complete).toBe(false);
    expect(before.state).toBe("CANCEL_REQUESTED");
    const unconfirmed = await settle(
      f.client().commands.cancelAndWait(operationId, { waitTimeoutMs: 300 }),
    );
    expect(unconfirmed.ok).toBe(false);
    expect(errorOf(unconfirmed).kind).toBe("unknown");
    // The capture of its output is still pending after the whole refused
    // acknowledgement window: nothing reported it complete.
    expect(captureSettled).toBe(false);
    ack();
    const confirmed = await f.client().commands.cancelAndWait(operationId);
    expect(confirmed).toMatchObject({ operationId, outcome: "cancelled" });
    const captured = await capture;
    expect(captured.ok).toBe(true);
    expect((await f.client().commands.stat(operationId)).complete).toBe(true);
    finish();
    expect(f.daemon.commandEffects(operationId)).toBe(1);
  });

  it("an abort whose cancel is acknowledged reports `aborted` only after the ACK", async () => {
    const f = await setup();
    const { sandbox, finish } = await longRunning(f);
    const abort = new AbortController();
    const run = settle(
      f
        .client()
        .commands.run(
          sandbox.id,
          { script: "./serve --forever" },
          { signal: abort.signal, onAbort: "cancel" },
        ),
    );
    await until(() => f.daemon.effects.commands.size === 1, "running");
    abort.abort();
    const outcome = await run;
    expect(outcome.ok).toBe(false);
    expect(errorOf(outcome).kind).toBe("aborted");
    const operationId = [...f.daemon.effects.commands.keys()][0]!;
    // The ACK (the host's terminal `cancelled`) was durable before the SDK said aborted.
    expect((await operationRow(operationId)).state).toBe("CANCELLED");
    expect(f.daemon.received.some((m) => m.type === "operation.cancel")).toBe(true);
    finish();
  });

  it("a host lost mid-capture never leaves a capture reported safe; the retry captures afresh", async () => {
    const f = await setup();
    const sandbox = await f
      .client()
      .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
    const seed = binarySeed(2 * 1024 * 1024 + 17, 7);
    await f.client().files.writeBytes(sandbox.id, "/home/user/big.bin", seed);
    f.daemon.crashDuringDownload = true;
    const lost = settle(f.client().files.readBytes(sandbox.id, "/home/user/big.bin"));
    await until(() => f.daemon.socket === undefined, "host lost mid-capture");
    await f.daemon.connect();
    await f.pump.idle();
    const outcome = await lost;
    expect(outcome.ok).toBe(false);
    const error = errorOf(outcome);
    expect(error.kind).toBe("unknown");
    const getFile = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { userId: f.ownerId, kind: "GET_FILE" },
    });
    expect(error.operationId).toBe(getFile.id);
    expect(getFile.state).toBe("UNKNOWN_OUTCOME");
    // The partial capture is not downloadable: no route serves an unsealed capture.
    const resumed = await settle(f.client().files.downloadRange(getFile.id, { start: 0 }));
    expect(resumed.ok).toBe(false);
    // A new capture under a NEW key is a fresh, complete, byte-exact read.
    const fresh = await f.client().files.readBytes(sandbox.id, "/home/user/big.bin", {
      maxBytes: seed.byteLength,
    });
    expect(sha256Hex(fresh)).toBe(sha256Hex(seed));
  });
});

describe("C57 capture safety against a faulty host", () => {
  it("a success claimed over a partial capture is fenced: never SUCCEEDED, never downloadable", async () => {
    const f = await setup();
    const sandbox = await f
      .client()
      .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
    const seed = binarySeed(2 * 1024 * 1024 + 5, 11);
    await f.client().files.writeBytes(sandbox.id, "/home/user/claimed.bin", seed);
    f.daemon.lieAboutDownload = true;
    const claimed = await settle(
      f.client().files.readBytes(sandbox.id, "/home/user/claimed.bin", { waitTimeoutMs: 1500 }),
    );
    expect(claimed.ok).toBe(false);
    const getFile = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { userId: f.ownerId, kind: "GET_FILE" },
    });
    // The host's result arrived and was refused at the relay fence.
    expect(f.daemon.received.some((m) => m.type === "file.chunk.ack")).toBe(true);
    expect(getFile.state).not.toBe("SUCCEEDED");
    expect(
      errorOf(await settle(f.client().files.downloadRange(getFile.id, { start: 0 }))),
    ).toMatchObject({
      code: "TRANSFER_NOT_READY",
    });
    // The host is lost; the reconnect settles the operation as uncertain.
    f.daemon.crash();
    await f.daemon.connect();
    await f.pump.idle();
    expect((await operationRow(getFile.id)).state).toBe("UNKNOWN_OUTCOME");
    expect(await settle(f.client().files.downloadRange(getFile.id, { start: 0 }))).toMatchObject({
      ok: false,
    });
  });
});

describe("C57 default caps hold in the lifecycle", () => {
  it("advertises and enforces the shipped transfer cap before any guest IO", async () => {
    const { serverVars } = await import("@wssp/env/vars/server");
    const { TRANSFER_MAX_BYTES } = await import("@wssp/sandbox-contracts");
    const f = await setup();
    const sandbox = await f
      .client()
      .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
    const limits = await f.client().files.limits();
    expect(limits.transferMaxBytes).toBe(serverVars.TRANSFER_MAX_BYTES.parse(undefined));
    expect(limits.transferMaxBytes).toBe(TRANSFER_MAX_BYTES);
    const source = {
      async *[Symbol.asyncIterator]() {
        yield new Uint8Array(1);
      },
    };
    const oversized = await settle(
      f.client().files.upload(sandbox.id, "/home/user/huge.bin", source, {
        totalBytes: limits.transferMaxBytes + 1,
      }),
    );
    expect(oversized.ok).toBe(false);
    expect(errorOf(oversized).kind).toBe("invalid_request");
    // The SDK's in-memory cap refuses before any network IO, too.
    const before = f.requests.length;
    const tooBig = await settle(
      f
        .client()
        .files.writeBytes(
          sandbox.id,
          "/home/user/mem.bin",
          new Uint8Array(limits.memoryBytesDefault + 1),
        ),
    );
    expect(tooBig.ok).toBe(false);
    expect(f.requests.length).toBe(before);
    expect(f.daemon.dispatches.filter((d) => d.kind === "file.put")).toEqual([]);
  });

  it("bounds a noisy command at the SDK accumulation cap and the server's default retention", async () => {
    const { OUTPUT_HEAD_BYTES, OUTPUT_TAIL_BYTES } = await import("@wssp/sandbox-contracts");
    const f = await setup();
    const sandbox = await f
      .client()
      .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
    const total = 2 * 1024 * 1024;
    const noisy = new Uint8Array(total);
    for (let i = 0; i < total; i++) noisy[i] = 0x61 + (Math.floor(i / 8192) % 26);
    f.daemon.programs.set("./noisy", { stdout: noisy, exitCode: 0 });
    // The SDK accumulation cap: only the trailing maxOutputChars are kept.
    const result = await f.client().commands.script(sandbox.id, "./noisy", {
      maxOutputChars: 4096,
    });
    const decoded = new TextDecoder().decode(noisy);
    expect(result.exitCode).toBe(0);
    expect(result.totalBytes).toBe(total);
    expect(result.stdout).toBe(decoded.slice(-4096));
    expect(result.discarded.stdout).toBeGreaterThan(0);
    // The server's retention cap: a later follow (a broker) sees only the
    // default head + tail, with the middle reported as a gap.
    const { DEFAULT_TAIL_CHARS, MAX_TAIL_CHARS } = await import(
      "../../../../packages/sdk/src/index"
    );
    const broker = await f.client().commands.tail(result.operationId, { maxChars: MAX_TAIL_CHARS });
    expect(broker.truncated).toBe(true);
    expect(broker.retainedBytes).toBe(OUTPUT_HEAD_BYTES + OUTPUT_TAIL_BYTES);
    expect(broker.totalBytes).toBe(total);
    // The tail read itself is bounded at the retained tail (MAX_TAIL_CHARS).
    expect(MAX_TAIL_CHARS).toBe(OUTPUT_TAIL_BYTES);
    expect(broker.stdout).toBe(decoded.slice(-OUTPUT_TAIL_BYTES));
    // And the default tail read is bounded by DEFAULT_TAIL_CHARS.
    const tail = await f.client().commands.tail(result.operationId);
    expect(tail.stdout).toBe(decoded.slice(-DEFAULT_TAIL_CHARS));
  });
});

describe("C57 repeated expiry cycles on the fake lease clock", () => {
  it("expires, retains and cold-boots the same VM three times with stable placement", async () => {
    const f = await setup({ memoryBudgetMiB: alignedMemoryBudget(1) });
    const sandbox = await f.client().sandboxes.create({
      template: "revision/" + f.template.id,
      sandboxHostId: f.host.id,
      timeoutMs: 3_600_000,
      lifecycle: { onTimeout: "stop" },
    });
    const read = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
    const generations: number[] = [];
    for (let cycle = 0; cycle < 3; cycle++) {
      // Past the lease deadline (1 h default, or the cold boot's re-armed lease).
      f.clock.advance(61 * 60_000);
      await f.pump.idle();
      expect(f.pump.failures).toEqual([]);
      await until(async () => {
        await f.pump.idle();
        return (await read()).state === "STOPPED";
      }, `expiry cycle ${cycle}`);
      await f.daemon.idle();
      expect(f.daemon.vms.get(sandbox.id)?.state).toBe("stopped");
      expect(
        (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
      ).toBe(0);
      const booted = await f.client().sandboxes.connect(sandbox.id, {
        mode: "cold",
        // Re-arm past the advanced clock: one more 61-minute step expires it.
        leaseTimeoutMs: f.clock.offsetMs() + 60 * 60_000,
      });
      expect(booted).toMatchObject({ state: "READY", hostId: f.host.id });
      generations.push(booted.generation);
    }
    // Each cold boot is a new generation of the SAME VM on the SAME host.
    expect(generations).toEqual([...generations].sort((a, b) => a - b));
    expect(new Set(generations).size).toBe(3);
    expect(f.daemon.effects.creates).toBe(1);
    expect(f.daemon.vms.size).toBe(1);
    const stops = f.daemon.dispatches.filter((d) => d.kind === "sandbox.stop");
    expect(stops).toHaveLength(3);
    expect((await read()).originHostId).toBe(f.host.id);
  });
});

describe("C57 worker and server loss", () => {
  it("a dead outbox worker strands nothing: the restarted worker dispatches the committed command once", async () => {
    const f = await setup();
    const sandbox = await f
      .client()
      .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
    // The worker dies: no wake reaches a processor while the mutation commits.
    bindSandboxDispatchWake(null);
    const run = settle(f.client().commands.script(sandbox.id, "echo after-restart"));
    await until(
      async () =>
        (await db.inspect.sandboxOperation.count({
          where: { userId: f.ownerId, kind: "RUN_COMMAND" },
        })) === 1,
      "committed command",
    );
    expect(f.daemon.dispatches.filter((d) => d.kind === "command.run")).toEqual([]);
    const restarted = outboxPump(f.clock);
    await restarted.idle();
    const outcome = await run;
    expect(outcome.ok).toBe(true);
    expect(f.daemon.dispatches.filter((d) => d.kind === "command.run")).toHaveLength(1);
  });

  it("a server that drops the host mid-command keeps the receipt: the host's result lands once on reconnect", async () => {
    const f = await setup();
    const sandbox = await f
      .client()
      .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
    let finish!: () => void;
    f.daemon.programs.set("./migrate", {
      gate: new Promise<void>((resolve) => {
        finish = resolve;
      }),
      stdout: new TextEncoder().encode("migrating\n"),
    });
    const run = settle(f.client().commands.script(sandbox.id, "./migrate"));
    await until(
      () => f.daemon.received.some((m) => m.type === "command.output.ack"),
      "output committed",
    );
    const operationId = [...f.daemon.effects.commands.keys()][0]!;
    // Server restart: the socket is gone, the host process and its work are not.
    f.daemon.serverDrop();
    finish();
    await f.daemon.idle();
    expect(f.daemon.journal.get(operationId)).toMatchObject({
      phase: "result",
      state: "succeeded",
    });
    await f.daemon.connect();
    await f.pump.idle();
    const outcome = await run;
    expect(outcome.ok, String(!outcome.ok && outcome.error)).toBe(true);
    expect(f.daemon.receipts.filter((r) => r.operationId === operationId)).toHaveLength(1);
    expect(f.daemon.commandEffects(operationId)).toBe(1);
    expect((await operationRow(operationId)).state).toBe("SUCCEEDED");
    expect(f.daemon.journal.has(operationId)).toBe(false);
  });

  it("C13: a command the host stopped at its carry cap settles FAILED host_disconnect_expired on reconnect", async () => {
    const f = await setup();
    const sandbox = await f
      .client()
      .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
    f.daemon.programs.set("./soak", {
      gate: new Promise<void>(() => {}),
      stdout: new TextEncoder().encode("soaking\n"),
    });
    const run = settle(f.client().commands.script(sandbox.id, "./soak"));
    await until(
      () => f.daemon.received.some((m) => m.type === "command.output.ack"),
      "output committed",
    );
    const operationId = [...f.daemon.effects.commands.keys()][0]!;
    f.daemon.serverDrop();
    f.daemon.expireCarry(operationId);
    await f.daemon.idle();
    expect(f.daemon.journal.get(operationId)).toMatchObject({
      phase: "result",
      state: "failed",
      error: { code: "host_disconnect_expired" },
    });
    await f.daemon.connect();
    await f.pump.idle();
    expect(errorOf(await run)).toMatchObject({
      kind: "unavailable",
      operationId,
      operationErrorCode: "host_disconnect_expired",
    });
    expect(await operationRow(operationId)).toMatchObject({
      state: "FAILED",
      errorCode: "host_disconnect_expired",
    });
    expect(f.daemon.commandEffects(operationId)).toBe(1);
  });
});

describe("WP7 graceful quiesce holds new commands before the claim (D9)", () => {
  it("a quiescing host's command stays QUEUED and unclaimed across a server restart, then runs once on the new daemon", async () => {
    const f = await setup({ quiesce: true });
    expect(f.daemon.received.findLast((m) => m.type === "hello.ok")).toMatchObject({
      capabilities: { quiesce: true },
    });
    const sandbox = await f
      .client()
      .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
    await f.daemon.quiesce();
    await f.daemon.idle();
    expect(f.daemon.received.findLast((m) => m.type === "host.quiesce.ack")).toEqual({
      type: "host.quiesce.ack",
      sequence: 1,
    });
    const run = settle(f.client().commands.script(sandbox.id, "echo held"));
    const command = async () =>
      db.inspect.sandboxOperation.findFirst({
        where: { sandboxId: sandbox.id, kind: "RUN_COMMAND" },
      });
    await until(async () => (await command()) !== null, "command accepted");
    const operationId = (await command())!.id;
    const held = async () => {
      // Several full outbox passes: the in-transaction fence holds the event.
      for (let pass = 0; pass < 3; pass++) await f.pump.idle();
      expect(await operationRow(operationId)).toMatchObject({
        state: "QUEUED",
        dispatchAttempt: 0,
        dispatchedHostId: null,
        dispatchedConnectionEpoch: null,
      });
      const events = await db.inspect.outboxEvent.findMany({
        where: { userId: f.ownerId, aggregateId: sandbox.id, operationId },
        select: { claimToken: true, sentAt: true, processedAt: true },
      });
      expect(events).toEqual([{ claimToken: null, sentAt: null, processedAt: null }]);
      expect(f.daemon.commandEffects(operationId)).toBe(0);
      expect(
        f.daemon.dispatches.some((d) => d.operationId === operationId),
        "no command.run dispatch while quiescing",
      ).toBe(false);
    };
    await held();
    // Server restart mid-quiesce: the reconnect hello carries `quiescing`,
    // which the server sets at registration, so nothing leaks.
    f.daemon.serverDrop();
    await f.daemon.connect();
    await f.daemon.idle();
    await held();
    // The new binary starts without `quiescing`: the held command runs once.
    f.daemon.quiescing = false;
    f.daemon.crash();
    await f.daemon.connect();
    await f.daemon.idle();
    await f.pump.idle();
    const outcome = await run;
    expect(outcome.ok, String(!outcome.ok && outcome.error)).toBe(true);
    expect(await operationRow(operationId)).toMatchObject({
      state: "SUCCEEDED",
      dispatchAttempt: 1,
    });
    expect(f.daemon.commandEffects(operationId)).toBe(1);
  });
});

describe("C57 terminal leg (C52–C55 contract) inside the lifecycle", () => {
  class Sink {
    bufferedAmount = 0;
    /** A browser that stops reading: every delivered byte stays buffered. */
    stalled = false;
    bytes = 0;
    readies: { rows: number; cols: number }[] = [];
    closes: Record<string, unknown>[] = [];
    sendOutput(bytes: Uint8Array) {
      this.bytes += bytes.byteLength;
      if (this.stalled) this.bufferedAmount += bytes.byteLength;
    }
    ready(size: { rows: number; cols: number }) {
      this.readies.push(size);
    }
    close(notice: Record<string, unknown>) {
      this.closes.push(notice);
    }
  }

  it("attach → flood → detach on overflow (4401) → single attach → a new session, never a resume, after host loss", async () => {
    const f = await setup({ terminal: true });
    const sandbox = await f
      .client()
      .sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id });
    const open = (sink: Sink) => {
      const opened = manager.terminals.open({
        ownerId: f.ownerId,
        hostId: f.host.id,
        sandboxId: sandbox.id,
        generation: sandbox.generation,
        rows: 24,
        cols: 80,
        attachment: sink,
      });
      if (!opened.ok) throw new Error(JSON.stringify(opened.error));
      return opened.session;
    };
    const first = new Sink();
    const a = open(first);
    await until(() => first.readies.length === 1, "attach");
    // Single attachment: a second attach REPLACES the first, whose PTY closes.
    const second = new Sink();
    const b = open(second);
    await until(() => second.readies.length === 1 && first.closes.length === 1, "replace");
    expect(first.closes[0]).toMatchObject({ code: 4401, intent: "replaced" });
    await until(() => f.daemon.terminalFence(a.sessionId) === undefined, "replaced PTY closed");
    // Flood a stalled browser: detached at the 1 MiB bound with 4401 backpressure.
    second.stalled = true;
    await f.daemon.floodTerminal(b.sessionId, 400);
    await until(() => second.closes.length === 1, "backpressure detach");
    expect(second.closes[0]).toMatchObject({
      code: 4401,
      intent: "backpressure",
      error: { code: "rate_limited" },
    });
    expect(second.bufferedAmount).toBeLessThanOrEqual(1024 * 1024);
    await until(() => f.daemon.terminalFence(b.sessionId) === undefined, "flooded PTY closed");
    // Host loss: the live attachment gets 4401 host_disconnected; reconnecting
    // opens a NEW session on a new PTY, never the old one.
    const third = new Sink();
    const c = open(third);
    await until(() => third.readies.length === 1, "third attach");
    f.daemon.crash();
    await until(() => third.closes.length === 1, "host lost");
    expect(third.closes[0]).toMatchObject({ code: 4401, intent: "host_disconnected" });
    expect(c.input(new TextEncoder().encode("ls\n")).ok).toBe(false);
    await f.daemon.connect();
    await f.pump.idle();
    const fourth = new Sink();
    const d = open(fourth);
    await until(() => fourth.readies.length === 1, "fresh attach after reconnect");
    expect(new Set([a.sessionId, b.sessionId, c.sessionId, d.sessionId]).size).toBe(4);
    expect(f.daemon.liveTerminals()).toBe(1);
    d.close("client");
    await until(() => manager.terminals.sessionCount() === 0, "released");
    expect(fourth.closes[0]).toMatchObject({ code: 4401, intent: "client" });
    expect(f.daemon.liveTerminals()).toBe(0);
    expectNoTerminalResources(manager.terminals, { hostSockets: 1 });
  });
});

describe("B6 VM allocation cross-surface qualification", () => {
  it("inherits 2/2048, partially overrides, reads actual SDK allocation and survives budget shrink/restart", async () => {
    const f = await setup({ admission: true, templateSize: { cpuCount: 2, memoryMiB: 2048 } });
    const client = f.client();
    const first = await client.sandboxes.create({
      template: "revision/" + f.template.id,
      sandboxHostId: f.host.id,
    });
    const partial = await client.sandboxes.create({
      template: "revision/" + f.template.id,
      sandboxHostId: f.host.id,
      memoryMiB: 3072,
    });
    expect(first.sandbox).toMatchObject({ diskGiB: 32, cpuCount: 2, memoryMiB: 2048 });
    expect(partial.sandbox).toMatchObject({ diskGiB: 32, cpuCount: 2, memoryMiB: 3072 });
    for (const read of [
      await client.sandboxes.get(partial.id),
      await client.sandboxes.find(partial.id),
      await partial.get(),
    ]) {
      expect(read).toMatchObject({ diskGiB: 32, cpuCount: 2, memoryMiB: 3072 });
    }
    const page = await client.sandboxes.list({ limit: 10 });
    expect(page.items.find((row) => row.id === partial.id)).toMatchObject({
      diskGiB: 32,
      cpuCount: 2,
      memoryMiB: 3072,
    });
    const host = () => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
    expect(await host()).toMatchObject({
      liveCount: 2,
      memoryReservedMiB: vmLiveMemoryChargeMiB(2048) + vmLiveMemoryChargeMiB(3072),
    });
    f.daemon.crash();
    f.daemon.vmCapacity = { vcpuBudget: 64, memoryBudgetMiB: 4096, maxCpuCount: 4 };
    await f.daemon.connect();
    await f.daemon.idle();
    expect(await host()).toMatchObject({
      daemonMemoryBudgetMiB: 4096,
      memoryReservedMiB: vmLiveMemoryChargeMiB(2048) + vmLiveMemoryChargeMiB(3072),
    });
    await expect(
      client.sandboxes.create({ template: "revision/" + f.template.id, sandboxHostId: f.host.id }),
    ).rejects.toMatchObject({ kind: "capacity", code: "sandbox.host_capacity" });
    await first.stop();
    expect(await host()).toMatchObject({
      liveCount: 1,
      memoryReservedMiB: vmLiveMemoryChargeMiB(3072),
    });
    await expect(client.sandboxes.connect(first.id)).rejects.toMatchObject({
      kind: "capacity",
      code: "sandbox.host_capacity",
    });
    await partial.stop();
    expect(await host()).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
    const connected = await client.sandboxes.connect(first.id);
    expect(connected.sandbox).toMatchObject({ diskGiB: 32, cpuCount: 2, memoryMiB: 2048 });
    expect(f.daemon.vms.get(first.id)?.size).toEqual({ diskGiB: 32, cpuCount: 2, memoryMiB: 2048 });
    await client.sandboxes.destroy(first.id);
    await partial.destroy();
    expect(await host()).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
  });
});

// S3 qualification uses real creator admission and graph services, never an
// owner-swapped sandbox fixture. A owns the transport; B owns every guest below.
async function sharingFixture(mode: "shared" | "contributed" = "shared", terminal = false) {
  const f = await setup({ admission: true, terminal });
  const creatorId = `s3d-${randomUUID()}`;
  const creator = await db.inspect.user.create({
    data: {
      id: creatorId,
      name: "Creator B",
      email: `${creatorId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const a = { kind: "session" as const, ownerId: f.ownerId };
  const b = { kind: "session" as const, ownerId: creatorId };
  const { createPool, addPoolMember } = await import(
    "../../../../packages/api/src/sandbox/services/pools"
  );
  const { grantPoolShare, contributePoolHost } = await import(
    "../../../../packages/api/src/sandbox/services/sharing"
  );
  const poolOwner = mode === "shared" ? a : b;
  const pool = await createPool(poolOwner, { slug: "foreign", label: "Foreign usable pool" });
  // A short injected-clock promise; the accepted lease remains an hour long.
  await db.inspect.sandboxPool.update({
    where: { id: pool.id },
    data: { disconnectGraceSeconds: 60 },
  });
  if (mode === "shared") {
    await grantPoolShare(a, {
      poolId: pool.id,
      email: creator.email,
      canUse: true,
      canContribute: false,
      maxMemoryMiB: null,
      maxVcpu: null,
      maxDiskGiB: null,
      signupAllowed: false,
    });
    await addPoolMember(a, { poolId: pool.id, sandboxHostId: f.host.id, enabled: true });
  } else {
    const hostOwner = await db.inspect.user.findUniqueOrThrow({ where: { id: f.ownerId } });
    await grantPoolShare(b, {
      poolId: pool.id,
      email: hostOwner.email,
      canUse: false,
      canContribute: true,
      maxMemoryMiB: null,
      maxVcpu: null,
      maxDiskGiB: null,
      signupAllowed: false,
    });
    await contributePoolHost(a, {
      poolId: pool.id,
      sandboxHostId: f.host.id,
      enabled: true,
      memoryCapPercent: null,
      vcpuCapPercent: null,
    });
  }
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: creatorId,
      sandboxHostId: f.host.id,
      slug: "private",
      label: "B private revision",
      incusFingerprint: FP,
    },
  });
  const key = await createSdkKey(b, {
    name: "B pool only",
    scopes: SERVICE_SCOPES.filter(
      // An allowlist key can hold neither webhooks:write (all-owned only) nor
      // credentials:use without an allowlisted login; host scopes need a host grant.
      (scope) =>
        scope !== "webhooks:write" &&
        scope !== "credentials:use" &&
        scope !== "hosts:execute" &&
        scope !== "hosts:files",
    ),
    resourceMode: "ALLOWLIST",
    poolMode: "SELECTED",
    hostIds: [],
    templateRevisionIds: [revision.id],
    poolIds: [pool.id],
  });
  const client = createWsspClient({
    baseUrl: "https://wssp.test",
    apiKey: key.secret,
    fetch: async (input, init) => app.fetch(new Request(input, init)),
    polling: polling(),
  });
  const create = () =>
    client.sandboxes.create({
      template: `revision/${revision.id}`,
      poolId: pool.id,
      timeoutMs: 3_600_000,
      lifecycle: { onTimeout: "stop" },
      envs: { PRIVATE_B: "synthetic-private-b" },
      expectedDisconnectGraceSeconds: 60,
    });
  return { ...f, creator, a, b, pool, revision, foreignKey: key, foreignClient: client, create };
}

async function accessSweep(f: Awaited<ReturnType<typeof sharingFixture>>) {
  const { scanSandboxAccess } = await import("../../../../packages/api/src/sandbox/sharing-access");
  await scanSandboxAccess(
    () => f.clock.now(),
    () => false,
    new Set([f.pool.id]),
  );
  await f.pump.idle();
  await f.daemon.idle();
  await f.pump.idle();
}
const sandboxRow = (id: string) => db.inspect.sandbox.findUniqueOrThrow({ where: { id } });

// No hardware claim: this is the production SDK/HTTP/DB/relay path and the
// FakeRuntime wire double. Rust's journal/runtime half remains separately tested.
describe("S3 A/B foreign-host lifecycle and owner oracle qualification (real PostgreSQL)", () => {
  it.each(["shared", "contributed"] as const)(
    "%s pool: create → command/files → stop → cold/warm start → destroy, with separate transport/creator identities",
    async (mode) => {
      const f = await sharingFixture(mode);
      expect((await f.foreignClient.pools.list()).items.map((row) => row.id)).toContain(f.pool.id);
      expect(await f.foreignClient.pools.get(f.pool.id)).toMatchObject({ memberCount: 1 });
      const discoveredMembers = await f.foreignClient.pools.members(f.pool.id);
      if (mode === "shared") {
        expect(discoveredMembers.items).toHaveLength(1);
        expect(Object.keys(discoveredMembers.items[0]!).sort()).toEqual(["id", "poolId"]);
      } else {
        expect(discoveredMembers.items[0]).toMatchObject({ hostId: f.host.id });
      }
      const sandbox = await f.create();
      const first = await sandboxRow(sandbox.id);
      expect(first).toMatchObject({
        userId: f.creator.id,
        hostOwnerId: f.ownerId,
        sandboxHostId: f.host.id,
        usagePoolId: f.pool.id,
        liveResourcesHeld: true,
        diskReservationHeld: true,
      });
      expect(sandbox.sandbox).toMatchObject({
        hostId: null,
        storageId: null,
        acceptedGraceSeconds: 60,
      });
      const commands = await sandbox.commands.script("echo foreign");
      const seed = binarySeed(1024 * 1024 + 17, 3);
      await f.foreignClient.files.writeBytes(sandbox.id, "/home/user/shared.bin", seed);
      expect(await f.foreignClient.files.readBytes(sandbox.id, "/home/user/shared.bin")).toEqual(
        seed,
      );
      await sandbox.stop();
      expect(await sandboxRow(sandbox.id)).toMatchObject({
        state: "STOPPED",
        liveResourcesHeld: false,
        diskReservationHeld: true,
      });
      f.daemon.crash();
      await f.daemon.connect();
      await f.daemon.idle();
      const restarted = await f.foreignClient.sandboxes.connect(sandbox.id, {
        mode: "cold",
        leaseTimeoutMs: 3_600_000,
      });
      expect(await f.foreignClient.files.readBytes(sandbox.id, "/home/user/shared.bin")).toEqual(
        seed,
      );
      await f.foreignClient.sandboxes.connect(sandbox.id, { mode: "warm" });
      await restarted.commands.script("true");
      expect([...f.daemon.commandEnvs.values()].at(-1)).toEqual({
        PRIVATE_B: "synthetic-private-b",
      });
      const placement = await db.inspect.sandboxPlacement.findUniqueOrThrow({
        where: { id: (await sandboxRow(sandbox.id)).currentPlacementId! },
      });
      expect(placement).toMatchObject({
        userId: f.creator.id,
        hostOwnerId: f.ownerId,
        originHostId: f.host.id,
        acceptedGraceSeconds: 60,
      });
      expect((await operationRow(commands.operationId)).userId).toBe(f.creator.id);
      for (const frame of f.daemon.dispatches.filter((d) => d.sandboxId === sandbox.id))
        expect(frame.sandboxOwnerId).toBe(f.creator.id);
      expect(
        await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
      ).toMatchObject({ quarantinedAt: null });
      await restarted.destroy();
      expect(await sandboxRow(sandbox.id)).toMatchObject({
        state: "DELETED",
        liveResourcesHeld: false,
        diskReservationHeld: false,
      });
      expect(
        await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
      ).toMatchObject({ liveCount: 0, rootCount: 0, memoryReservedMiB: 0, vcpuReserved: 0 });
    },
  );

  it("use loss denies IO immediately, wire STOP retains root, restore cold-starts the same disk, repeated loss destroys only at the pinned deadline", async () => {
    const f = await sharingFixture();
    const sandbox = await f.create();
    await f.foreignClient.files.writeBytes(
      sandbox.id,
      "/home/user/kept",
      new Uint8Array([0, 255, 7]),
    );
    const original = await sandboxRow(sandbox.id);
    const { revokePoolShare, grantPoolShare } = await import(
      "../../../../packages/api/src/sandbox/services/sharing"
    );
    await revokePoolShare(f.a, { poolId: f.pool.id, granteeUserId: f.creator.id });
    const before = f.daemon.dispatches.length;
    await expect(sandbox.commands.script("denied")).rejects.toMatchObject({ status: 403 });
    await expect(
      f.foreignClient.files.readBytes(sandbox.id, "/home/user/kept"),
    ).rejects.toMatchObject({ status: 403 });
    expect(f.daemon.dispatches).toHaveLength(before);
    await accessSweep(f);
    const stopped = await sandboxRow(sandbox.id);
    expect(stopped).toMatchObject({
      state: "STOPPED",
      liveResourcesHeld: false,
      diskReservationHeld: true,
      storagePoolId: original.storagePoolId,
      storageMarker: original.storageMarker,
    });
    expect(stopped.accessGraceUntil).not.toBeNull();
    expect(f.daemon.vms.get(sandbox.id)?.state).toBe("stopped");
    expect(
      f.daemon.dispatches.filter((d) => d.sandboxId === sandbox.id && d.kind === "sandbox.stop"),
    ).toHaveLength(1);
    await grantPoolShare(f.a, {
      poolId: f.pool.id,
      email: f.creator.email,
      canUse: true,
      canContribute: false,
      maxMemoryMiB: null,
      maxVcpu: null,
      maxDiskGiB: null,
      signupAllowed: false,
    });
    await accessSweep(f);
    expect((await sandboxRow(sandbox.id)).accessGraceUntil).toBeNull();
    // The original selected key retains cleanup/history, but regrant does not
    // recreate its future pool selection. Mint a new immutable key for cold work.
    await expect(
      f.foreignClient.sandboxes.connect(sandbox.id, { mode: "cold" }),
    ).rejects.toMatchObject({ status: 404 });
    const renewed = await createSdkKey(f.b, {
      name: "B restored",
      scopes: SERVICE_SCOPES.filter(
        // An allowlist key can hold neither webhooks:write (all-owned only) nor
        // credentials:use without an allowlisted login; host scopes need a host grant.
        (scope) =>
          scope !== "webhooks:write" &&
          scope !== "credentials:use" &&
          scope !== "hosts:execute" &&
          scope !== "hosts:files",
      ),
      resourceMode: "ALLOWLIST",
      poolMode: "SELECTED",
      hostIds: [],
      templateRevisionIds: [f.revision.id],
      poolIds: [f.pool.id],
    });
    const client = createWsspClient({
      baseUrl: "https://wssp.test",
      apiKey: renewed.secret,
      fetch: async (input, init) => app.fetch(new Request(input, init)),
      polling: polling(),
    });
    // Cold start uses current pool selection; immutable creation-key authority
    // still owns retained work, so use a fresh all-owned key for this restart.
    const all = await createSdkKey(f.b, {
      name: "B restore owner",
      scopes: [...SERVICE_SCOPES],
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
    });
    const ownerClient = createWsspClient({
      baseUrl: "https://wssp.test",
      apiKey: all.secret,
      fetch: async (input, init) => app.fetch(new Request(input, init)),
      polling: polling(),
    });
    await expect(client.sandboxes.connect(sandbox.id, { mode: "cold" })).rejects.toMatchObject({
      status: 403,
    });
    const restored = await ownerClient.sandboxes.connect(sandbox.id, { mode: "cold" });
    expect(await ownerClient.files.readBytes(sandbox.id, "/home/user/kept")).toEqual(
      new Uint8Array([0, 255, 7]),
    );
    expect((await sandboxRow(sandbox.id)).storagePoolId).toBe(original.storagePoolId);
    await revokePoolShare(f.a, { poolId: f.pool.id, granteeUserId: f.creator.id });
    await accessSweep(f);
    const loss = await sandboxRow(sandbox.id);
    f.clock.advance(30_000);
    await accessSweep(f);
    expect((await sandboxRow(sandbox.id)).accessGraceUntil).toEqual(loss.accessGraceUntil);
    expect((await sandboxRow(sandbox.id)).diskReservationHeld).toBe(true);
    f.clock.advance(31_000);
    await accessSweep(f);
    expect(await sandboxRow(sandbox.id)).toMatchObject({
      state: "DELETED",
      liveResourcesHeld: false,
      diskReservationHeld: false,
    });
    expect(f.daemon.vms.has(restored.id)).toBe(false);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    ).toMatchObject({ liveCount: 0, rootCount: 0 });
  });

  it("host withdrawal stops a foreign guest; re-contribution restores the retained disk without a historical-member gate", async () => {
    const f = await sharingFixture("contributed");
    const sandbox = await f.create();
    const { withdrawPoolHost, contributePoolHost } = await import(
      "../../../../packages/api/src/sandbox/services/sharing"
    );
    await withdrawPoolHost(f.a, { poolId: f.pool.id, sandboxHostId: f.host.id });
    await expect(sandbox.commands.script("denied")).rejects.toMatchObject({ status: 403 });
    await accessSweep(f);
    expect(await sandboxRow(sandbox.id)).toMatchObject({
      state: "STOPPED",
      diskReservationHeld: true,
    });
    await contributePoolHost(f.a, {
      poolId: f.pool.id,
      sandboxHostId: f.host.id,
      enabled: true,
      memoryCapPercent: null,
      vcpuCapPercent: null,
    });
    await accessSweep(f);
    expect((await sandboxRow(sandbox.id)).accessGraceUntil).toBeNull();
    const restarted = await f.foreignClient.sandboxes.connect(sandbox.id, { mode: "cold" });
    await restarted.commands.script("true");
    await restarted.destroy();
  });
  it("host/pool custody and admin role confer no guest authority; native owner oracle and impersonated execution/file matrix have zero effects", async () => {
    const f = await sharingFixture("contributed");
    const sandbox = await f.create();
    const command = await sandbox.commands.run({
      script: "echo private-output",
      startEvidence: "required",
    });
    const identity = await operationRow(command.operationId);
    expect(identity).toMatchObject({ processPid: 42, processId: expect.any(String) });
    if (!identity.processId || !identity.processPid)
      throw new Error("Fixture process identity missing");
    const process = {
      sandboxId: sandbox.id,
      generation: identity.generation,
      processId: identity.processId,
      attempt: identity.dispatchAttempt,
      pid: identity.processPid,
    };
    const qualifiers = {
      generation: process.generation,
      processId: process.processId,
      attempt: process.attempt,
    };
    await f.foreignClient.files.writeBytes(
      sandbox.id,
      "/home/user/private",
      new Uint8Array([9, 0, 255]),
    );
    await f.foreignClient.files.readBytes(sandbox.id, "/home/user/private");
    const capture = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id, kind: "GET_FILE" },
    });
    const transfer = await db.inspect.sandboxTransfer.findFirstOrThrow({
      where: { sandboxId: sandbox.id, direction: "UPLOAD" },
    });
    // The inverse direction isolates pool custody: B owns this pool but
    // neither A's host nor A's guest. Both creators coexist on one transport.
    const { updatePoolShare } = await import(
      "../../../../packages/api/src/sandbox/services/sharing"
    );
    await updatePoolShare(f.b, {
      poolId: f.pool.id,
      granteeUserId: f.ownerId,
      canUse: true,
      canContribute: true,
      maxMemoryMiB: null,
      maxVcpu: null,
      maxDiskGiB: null,
    });
    const aGuest = await f.client().sandboxes.create({
      template: `revision/${f.template.id}`,
      poolId: f.pool.id,
      timeoutMs: 3_600_000,
      lifecycle: { onTimeout: "stop" },
    });
    const aCommand = await aGuest.commands.script("echo private-a");
    await f
      .client()
      .files.writeBytes(aGuest.id, "/home/user/private-a", new Uint8Array([3, 0, 254]));
    const allB = await createSdkKey(f.b, {
      name: "pool owner only",
      resourceMode: "ALL_OWNED",
      scopes: [...SERVICE_SCOPES],
      hostIds: [],
      templateRevisionIds: [],
    });
    const poolOwnerClient = createWsspClient({
      baseUrl: "https://wssp.test",
      apiKey: allB.secret,
      fetch: async (input, init) => app.fetch(new Request(input, init)),
      polling: polling(),
    });
    const { SDK_ROUTES } = await import("@wssp/sandbox-contracts");
    type Route = keyof typeof SDK_ROUTES;
    const cases: { route: Route; id: string; body?: Record<string, unknown>; query?: string }[] = [
      { route: "getSandbox", id: sandbox.id },
      { route: "getSandboxCapabilities", id: sandbox.id },
      { route: "getOperation", id: command.operationId },
      { route: "getOperationResult", id: command.operationId },
      { route: "getCommandOutput", id: command.operationId },
      { route: "downloadFile", id: capture.id },
      { route: "stopSandbox", id: sandbox.id, body: {} },
      { route: "destroySandbox", id: sandbox.id, body: {} },
      { route: "reconnectSandbox", id: sandbox.id, body: { mode: "warm" } },
      { route: "renewSandboxLease", id: sandbox.id, body: { timeoutMs: 60000 } },
      { route: "probeSandbox", id: sandbox.id, body: {} },
      { route: "startCommand", id: sandbox.id, body: { script: "denied" } },
      { route: "writeStdin", id: command.operationId, body: { contentBase64: "eA==" } },
      { route: "cancelOperation", id: command.operationId, body: {} },
      { route: "statPath", id: sandbox.id, body: { path: "/home/user/private" } },
      { route: "listDir", id: sandbox.id, body: { path: "/home/user" } },
      { route: "mkdir", id: sandbox.id, body: { path: "/home/user/denied" } },
      {
        route: "movePath",
        id: sandbox.id,
        body: { path: "/home/user/private", destPath: "/home/user/denied" },
      },
      { route: "removePath", id: sandbox.id, body: { path: "/home/user/private" } },
      { route: "requestDownload", id: sandbox.id, body: { path: "/home/user/private" } },
      { route: "listProcesses", id: sandbox.id, body: {} },
      {
        route: "connectProcess",
        id: sandbox.id,
        query: `generation=${process.generation}&processId=${process.processId}&attempt=${process.attempt}`,
      },
      {
        route: "signalProcess",
        id: sandbox.id,
        body: { ...qualifiers, signal: "SIGTERM" },
      },
      {
        route: "killProcess",
        id: sandbox.id,
        body: { ...qualifiers },
      },
      {
        route: "sendProcessStdin",
        id: sandbox.id,
        body: { ...qualifiers, contentBase64: "eA==" },
      },
      { route: "getUpload", id: transfer.id },
      { route: "commitUpload", id: transfer.id, body: { sha256: "a".repeat(64) } },
      { route: "abortUpload", id: transfer.id, body: {} },
    ];
    const aUser = await db.inspect.user.update({
      where: { id: f.ownerId },
      data: { role: "admin" },
    });
    const aSession = await db.inspect.session.create({
      data: { userId: f.ownerId, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
    });
    const { createRouterClient } = await import("@orpc/server");
    const { adminObservabilityRouter } = await import(
      "../../../../packages/api/src/routers/admin-observability"
    );
    const admin = createRouterClient(adminObservabilityRouter, {
      context: {
        clientIp: undefined,
        session: { user: aUser, session: aSession },
      } as import("../../../../packages/api/src/context").Context,
    });
    const metadata = await admin.listSandboxes({ ownerId: f.creator.id, limit: 10 });
    expect(metadata.items.map((row) => row.id)).toContain(sandbox.id);
    for (const row of metadata.items) {
      expect(Object.keys(row).sort()).toEqual(
        [
          "id",
          "userId",
          "createdAt",
          "sandboxHostId",
          "templateId",
          "templateRevisionId",
          "originPoolId",
          "state",
          "generation",
          "cpuCount",
          "memoryMiB",
          "diskGiB",
          // Guest privilege flags (admin-observability.ts): metadata only, no owner content.
          "guestSudo",
          "guestRoot",
          "guestSudoReason",
        ].sort(),
      );
    }
    expect(JSON.stringify(metadata)).not.toContain("synthetic-private-b");
    const sent = f.daemon.dispatches.length;
    const operations = await db.inspect.sandboxOperation.count({
      where: { sandboxId: sandbox.id },
    });
    const aOperations = await db.inspect.sandboxOperation.count({
      where: { sandboxId: aGuest.id },
    });
    const poolCustodyRefusals = [
      () => poolOwnerClient.sandboxes.get(aGuest.id),
      () => poolOwnerClient.commands.script(aGuest.id, "denied"),
      () => poolOwnerClient.commands.stat(aCommand.operationId),
      () => poolOwnerClient.commands.tail(aCommand.operationId),
      () => poolOwnerClient.files.readBytes(aGuest.id, "/home/user/private-a"),
      () => poolOwnerClient.files.writeBytes(aGuest.id, "/home/user/denied", new Uint8Array([1])),
      () => poolOwnerClient.sandboxes.stop(aGuest.id),
      () => poolOwnerClient.sandboxes.connect(aGuest.id),
      () => poolOwnerClient.sandboxes.destroy(aGuest.id),
    ];
    for (const work of poolCustodyRefusals)
      await expect(work()).rejects.toMatchObject({ status: 404 });
    const request = async (test: (typeof cases)[number], id: string) => {
      const route = SDK_ROUTES[test.route];
      const path = route.path.replace("{id}", id).replace("{pid}", String(process.pid));
      const response = await app.fetch(
        new Request(`https://wssp.test${path}${test.query ? `?${test.query}` : ""}`, {
          method: route.method.toUpperCase(),
          headers: {
            Authorization: `Bearer ${f.key.secret}`,
            "Content-Type": "application/json",
            "Idempotency-Key": randomUUID(),
          },
          ...(test.body ? { body: JSON.stringify(test.body) } : {}),
        }),
      );
      return {
        status: response.status,
        body: (await response.json()) as { error: { code: string; message: string } },
      };
    };
    for (const test of cases) {
      const foreign = await request(test, test.id);
      const missing = await request(test, randomUUID());
      expect(foreign.status, test.route).toBe(404);
      expect(missing.status, test.route).toBe(foreign.status);
      expect(foreign.body.error.code, test.route).toBe(missing.body.error.code);
      expect(foreign.body.error.message, test.route).toBe(missing.body.error.message);
    }
    await expect(
      f.client().files.upload(sandbox.id, "/home/user/denied", new Uint8Array([1])),
    ).rejects.toMatchObject({ status: 404 });
    expect((await f.client().sandboxes.list()).items.map((row) => row.id)).not.toContain(
      sandbox.id,
    );
    const bHosts = await app.fetch(
      new Request("https://wssp.test/v1/hosts", {
        headers: { Authorization: `Bearer ${f.foreignKey.secret}` },
      }),
    );
    expect(await bHosts.json()).toMatchObject({ items: [] });
    await expect(
      f.foreignClient.sandboxes.create({
        template: `revision/${f.revision.id}`,
        sandboxHostId: f.host.id,
      }),
    ).rejects.toMatchObject({ status: 403 });
    await expect(
      createSdkKey(f.b, {
        name: "forbidden foreign host",
        scopes: SERVICE_SCOPES.filter(
          // An allowlist key can hold neither webhooks:write (all-owned only) nor
          // credentials:use without an allowlisted login; host scopes need a host grant.
          (scope) =>
            scope !== "webhooks:write" &&
            scope !== "credentials:use" &&
            scope !== "hosts:execute" &&
            scope !== "hosts:files",
        ),
        resourceMode: "ALLOWLIST",
        hostIds: [f.host.id],
        templateRevisionIds: [f.revision.id],
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    const { sandboxesRouter } = await import("../../../../packages/api/src/routers/sandboxes");
    const bSession = await db.inspect.session.create({
      data: {
        userId: f.creator.id,
        token: randomUUID(),
        impersonatedBy: f.ownerId,
        expiresAt: new Date(Date.now() + 3600000),
      },
    });
    const impersonated = createRouterClient(sandboxesRouter, {
      context: {
        clientIp: undefined,
        session: { user: f.creator, session: bSession },
      } as import("../../../../packages/api/src/context").Context,
    });
    const id = sandbox.id,
      idempotencyKey = randomUUID();
    let browser = impersonated;
    const refused: (() => Promise<unknown>)[] = [
      () => browser.runCommand({ id, script: "denied", idempotencyKey }),
      () => browser.readFile({ id, path: "/home/user/private", idempotencyKey }),
      () => browser.listDir({ id, path: "/home/user", idempotencyKey }),
      () => browser.statPath({ id, path: "/home/user/private", idempotencyKey }),
      () => browser.mkdir({ id, path: "/home/user/denied", idempotencyKey }),
      () =>
        browser.movePath({
          id,
          path: "/home/user/private",
          destPath: "/home/user/denied",
          idempotencyKey,
        }),
      () => browser.removePath({ id, path: "/home/user/private", idempotencyKey }),
      () => browser.getOperation({ operationId: command.operationId }),
      () => browser.getOperationResult({ operationId: command.operationId }),
      () => browser.getCommandOutput({ operationId: command.operationId }),
      () =>
        browser.writeStdin({
          operationId: command.operationId,
          contentBase64: "eA==",
          idempotencyKey,
        }),
      () => browser.cancelOperation({ operationId: command.operationId }),
      () => browser.listProcesses({ id, idempotencyKey }),
      () => browser.connectProcess({ process }),
      () => browser.killProcess({ process, idempotencyKey }),
      () => browser.signalProcess({ process, signal: "SIGTERM", idempotencyKey }),
      () => browser.sendProcessStdin({ process, contentBase64: "eA==", idempotencyKey }),
    ];
    for (const work of refused)
      await expect(work()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    const liveSession = await db.inspect.session.create({
      data: {
        userId: f.creator.id,
        token: randomUUID(),
        expiresAt: new Date(Date.now() + 3600000),
      },
    });
    browser = createRouterClient(sandboxesRouter, {
      context: {
        clientIp: undefined,
        session: { user: f.creator, session: liveSession },
      } as import("../../../../packages/api/src/context").Context,
    });
    expect((await browser.getOperation({ operationId: command.operationId })).id).toBe(
      command.operationId,
    );
    await db.inspect.session.delete({ where: { id: liveSession.id } });
    for (const work of refused)
      await expect(work()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    const bAdmin = createRouterClient(adminObservabilityRouter, {
      context: {
        clientIp: undefined,
        session: { user: f.creator, session: bSession },
      } as import("../../../../packages/api/src/context").Context,
    });
    await expect(bAdmin.listSandboxes({ ownerId: f.ownerId })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    const { mintTerminalTicket } = await import(
      "../../../../packages/api/src/sandbox/terminal-tickets"
    );
    await expect(
      mintTerminalTicket(
        { userId: f.ownerId, sessionId: aSession.id },
        { sandboxId: id, rows: 24, cols: 80 },
      ),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(f.daemon.dispatches).toHaveLength(sent);
    expect(await db.inspect.sandboxOperation.count({ where: { sandboxId: id } })).toBe(operations);
    expect(await db.inspect.sandboxOperation.count({ where: { sandboxId: aGuest.id } })).toBe(
      aOperations,
    );
    await sandbox.destroy();
    await aGuest.destroy();
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    ).toMatchObject({ liveCount: 0, rootCount: 0 });
  });
});

it("T2: durably authorized foreign creator opens real wire guest PTY; host owner is denied and credential revocation closes it", async () => {
  const f = await sharingFixture("shared", true);
  const sandbox = await f.create();
  const session = await db.inspect.session.create({
    data: {
      userId: f.creator.id,
      token: randomUUID(),
      expiresAt: new Date(Date.now() + 3600000),
    },
  });
  const { mintTerminalTicket, consumeTerminalTicket, checkTerminalBinding } = await import(
    "../../../../packages/api/src/sandbox/terminal-tickets"
  );
  const { ticket } = await mintTerminalTicket(
    { userId: f.creator.id, sessionId: session.id },
    { sandboxId: sandbox.id, rows: 24, cols: 80 },
  );
  const binding = (await consumeTerminalTicket(ticket))!;
  const checked = await checkTerminalBinding(binding);
  expect(checked.ok).toBe(true);
  if (!checked.ok || !checked.grant) throw new Error("missing durable guest grant");
  const closes: unknown[] = [];
  let ready = false;
  const sink = {
    bufferedAmount: 0,
    sendOutput: () => {},
    ready: () => {
      ready = true;
    },
    close: (notice: unknown) => {
      closes.push(notice);
    },
  };
  const denied = manager.terminals.open({
    ownerId: f.ownerId,
    hostId: f.host.id,
    sandboxId: sandbox.id,
    generation: sandbox.generation,
    rows: 24,
    cols: 80,
    attachment: sink,
    grant: checked.grant,
  });
  expect(denied.ok).toBe(false);
  const opened = manager.terminals.open({
    ownerId: f.creator.id,
    hostId: f.host.id,
    sandboxId: sandbox.id,
    generation: sandbox.generation,
    rows: 24,
    cols: 80,
    attachment: sink,
    grant: checked.grant,
  });
  expect(opened.ok).toBe(true);
  await until(() => ready, "foreign guest terminal ready");
  const { revokeHostToken } = await import("../../../../packages/api/src/sandbox/services/hosts");
  const credential = await db.inspect.hostToken.findFirstOrThrow({
    where: { sandboxHostId: f.host.id },
    select: { id: true },
  });
  await revokeHostToken(f.a, { id: credential.id });
  await until(() => closes.length === 1, "host-owner credential revoke closes foreign guest PTY");
  expect(closes[0]).toMatchObject({ intent: "host_disconnected" });
  expect(manager.terminals.sessionCount()).toBe(0);
  // The wire double models peer disconnect explicitly (the Rust socket loop owns real reaps).
  f.daemon.crash();
  expect(f.daemon.liveTerminals()).toBe(0);
});

it("r1 raw oRPC operation details redact foreign host metadata before and after revocation; owned details retain their host", async () => {
  const f = await sharingFixture();
  const sandbox = await f.create();
  const command = await sandbox.commands.script("echo metadata");
  const create = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: {
      sandboxId: sandbox.id,
      kind: "CREATE_SANDBOX",
    },
  });
  const { RPCHandler } = await import("@orpc/server/fetch");
  const { sandboxesRouter } = await import("../../../../packages/api/src/routers/sandboxes");
  const { revokePoolShare } = await import("../../../../packages/api/src/sandbox/services/sharing");
  const handler = new RPCHandler({ sandboxes: sandboxesRouter });
  async function detail(userId: string, operationId: string) {
    const user = await db.inspect.user.findUniqueOrThrow({ where: { id: userId } });
    const session = await db.inspect.session.create({
      data: {
        userId,
        token: randomUUID(),
        expiresAt: new Date(Date.now() + 3600000),
      },
    });
    const response = await handler.handle(
      new Request("https://wssp.test/rpc/sandboxes/getOperationView", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ json: { operationId } }),
      }),
      {
        prefix: "/rpc",
        context: {
          clientIp: undefined,
          session: { user, session },
        } as import("../../../../packages/api/src/context").Context,
      },
    );
    if (!response.matched) throw new Error("Operation detail route not matched");
    return response.response;
  }
  for (const revoked of [false, true]) {
    if (revoked) await revokePoolShare(f.a, { poolId: f.pool.id, granteeUserId: f.creator.id });
    for (const operationId of [create.id, command.operationId]) {
      const response = await detail(f.creator.id, operationId);
      expect(response.status).toBe(200);
      const raw = await response.text();
      expect(JSON.parse(raw)).toMatchObject({
        json: { id: operationId, sandbox: { id: sandbox.id, host: null } },
      });
      expect(raw).not.toContain(f.host.id);
      expect(raw).not.toMatch(/hostOwnerId|lastConnectedAt|lastHeartbeatAt|deletionRequestedAt/);
    }
  }
  expect((await detail(f.ownerId, command.operationId)).status).toBe(404);
  const own = await f
    .client()
    .sandboxes.create({ template: `revision/${f.template.id}`, sandboxHostId: f.host.id });
  const ownCreate = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: {
      sandboxId: own.id,
      kind: "CREATE_SANDBOX",
    },
  });
  const response = await detail(f.ownerId, ownCreate.id);
  expect(response.status).toBe(200);
  const raw = await response.text();
  expect(JSON.parse(raw)).toMatchObject({
    json: { sandbox: { host: { id: f.host.id, slug: f.host.slug, label: f.host.label } } },
  });
  expect(raw).not.toContain("hostOwnerId");
});
