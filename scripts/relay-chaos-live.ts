/**
 * Opt-in LIVE relay chaos (reconnect plan WP9, D7). Real Incus VMs, at most
 * two, on a DEDICATED daemon only:
 *
 *   RELAY_CHAOS_LIVE=1 pnpm test:relay-chaos:live
 *
 * The daemon runs as its own transient user unit `wssp-chaos-<run>`
 * (`systemd-run --user`, never sudo) with its own data and config dirs, its
 * own enrolled test host and its own Incus project. The script refuses to
 * start when any of those belongs to the production `wssp-host` service
 * (`scripts/lib/relay-chaos-live.ts` `guardRefusals`). It shares this
 * machine's Incus server with `wssp-host`, so the unit sets the test-only
 * `WSSP_TEST_SHARED_INCUS=1` (one wssp daemon per Incus server is the
 * supported topology). Only debug builds honour it, with a loopback control
 * plane, so `WSSP_CHAOS_WSSP_BIN` (default: this checkout's `target/debug/wssp`) must be a debug build;
 * the script refuses a release binary.
 *
 * Topology (every hop loopback):
 *
 *   SDK ───────────── HTTP ──────────────┐
 *   daemon ─ WS /ws/sandbox-host ─▶ front door (WSSP_CHAOS_API_URL)
 *                                   ├─ HTTP, other upgrades ─▶ server (WSSP_CHAOS_UPSTREAM_URL)
 *                                   └─ relay WS ─▶ RelayFaultProxy ─▶ server
 *
 * The front door listens on the server's canonical origin (BETTER_AUTH_URL),
 * so the daemon's journal-key binding matches and keyed work runs; only the
 * relay WebSocket passes through the fault proxy. SDK traffic is never
 * faulted.
 *
 * Cells: L1 server unreachable mid-command (blackhole, then refused-silent
 * new connections) → SUCCEEDED with exact stdout; L2 create in Intent (image
 * fetch / VM create) with relay resets → READY; L3 quiesce-restart with a
 * running command (stdout intact) and a held new command. L4 (terminal
 * reattach) is browser-driven and manual: the SDK has no terminal client.
 *
 * Cleanup (finally): SDK destroy by run label, stop the unit, then a
 * read-only `incus list wssp-sbx-` in the chaos project. A leak exits 1.
 * Secret values (SDK key, host token) are never logged or put in an argv.
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, readlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { RelayFaultProxy } from "../apps/server/src/sandbox-relay/relay-fault-proxy-harness.ts";
import { createWsspClient, type HostDto, type WsspClient } from "../packages/sdk/src/index.ts";
import { FrontDoor } from "./lib/relay-chaos-front-door.ts";
import {
  CHAOS_ENV,
  type CleanupInput,
  cleanupVerdict,
  exactOutputProblem,
  guardRefusals,
  honorsSharedIncusOverride,
  hostAvailabilityRefusal,
  hostRelayHash,
  L2_CREATE_DISPATCH,
  type LiveCell,
  type LiveConfig,
  LiveVmCap,
  PRODUCTION_UNIT,
  parseIncusNames,
  parseLiveConfig,
  parseSystemctlShow,
  productionFootprint,
  RUN_LABEL_KEY,
  runLiveCells,
  SHARED_INCUS_ENV,
  systemdRunArgv,
  tickerOutput,
  tickerScript,
  UNIT_SHOW_PROPERTIES,
  type UnitShow,
} from "./lib/relay-chaos-live.ts";

const MINUTE = 60_000;

function log(message: string): void {
  process.stderr.write(`[relay-chaos-live] ${message}\n`);
}

/** A bounded error description: SDK codes and messages, never raw bodies. */
function describe(error: unknown): string {
  if (error && typeof error === "object") {
    const code = "code" in error && typeof error.code === "string" ? error.code : null;
    const message = error instanceof Error ? error.message : String(error);
    return (code ? `${code}: ${message}` : message).slice(0, 300);
  }
  return String(error).slice(0, 300);
}

type Run = { status: number; stdout: string; stderr: string };

/** Runs a command without a shell. Output is returned, never echoed. */
function exec(command: string, args: string[], env?: NodeJS.ProcessEnv): Run {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    timeout: 2 * MINUTE,
    env: env ?? process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.error ? result.error.message : (result.stderr ?? ""),
  };
}

function systemctlShow(unit: string): UnitShow {
  const run = exec("systemctl", [
    "--user",
    "show",
    unit,
    ...UNIT_SHOW_PROPERTIES.map((property) => `--property=${property}`),
  ]);
  if (run.status !== 0) throw new Error(`systemctl --user show ${unit} failed`);
  // The output may hold wssp-host's Environment (secrets): parsed, never printed.
  return parseSystemctlShow(run.stdout);
}

/** Paths the process holds open (`/proc/<pid>/fd` link targets), bounded. */
function openPaths(pid: number): string[] {
  if (pid <= 0) return [];
  const dir = `/proc/${pid}/fd`;
  let entries: string[];
  try {
    entries = readdirSync(dir).slice(0, 4096);
  } catch {
    return [];
  }
  const paths: string[] = [];
  for (const entry of entries) {
    try {
      paths.push(readlinkSync(join(dir, entry)));
    } catch {
      // Closed meanwhile.
    }
  }
  return paths;
}

/** Instance names in the chaos project; [] when the project does not exist yet. */
function incusNames(project: string): string[] | null {
  const projects = exec("incus", ["project", "list", "--format", "csv", "--columns", "n"]);
  if (projects.status !== 0) return null;
  const known = projects.stdout.split("\n").map((line) => line.trim().replace(/ \(current\)$/, ""));
  if (!known.includes(project)) return [];
  const list = exec("incus", [
    "list",
    "--project",
    project,
    "--format",
    "csv",
    "--columns",
    "n",
    "wssp-sbx-",
  ]);
  return list.status === 0 ? parseIncusNames(list.stdout) : null;
}

// ---- run ----------------------------------------------------------------------

type Ctx = {
  config: LiveConfig;
  wssp: WsspClient;
  proxy: RelayFaultProxy;
  door: FrontDoor;
  /** Sandbox ids created (READY) by this run. */
  tracked: string[];
  /** Creates submitted, for the D7 cap. */
  vms: LiveVmCap;
};

async function findHost(wssp: WsspClient, hostId: string): Promise<HostDto | undefined> {
  let cursor: string | undefined;
  for (let page = 0; page < 20; page += 1) {
    const result = await wssp.transport.request("listHosts", {
      query: { limit: "100", ...(cursor ? { cursor } : {}) },
    });
    const host = result.items.find((item) => item.id === hostId);
    if (host) return host;
    if (!result.nextCursor) return undefined;
    cursor = result.nextCursor;
  }
  return undefined;
}

async function waitHostConnected(ctx: Ctx, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const host = await findHost(ctx.wssp, ctx.config.hostId);
    if (host?.status === "CONNECTED" && host.egressGuard.ok) return;
    await sleep(2_000);
  }
  throw new Error("the dedicated daemon did not connect with a healthy egress guard in time");
}

async function createSandbox(ctx: Ctx, cell: string) {
  ctx.vms.reserve();
  const sandbox = await ctx.wssp.sandboxes.create(
    {
      template: ctx.config.template,
      sandboxHostId: ctx.config.hostId,
      metadata: { [RUN_LABEL_KEY]: ctx.config.runId, wssp_chaos_cell: cell },
      allowInternetAccess: false,
      timeoutMs: 45 * MINUTE,
      lifecycle: { onTimeout: "kill" },
    },
    { waitTimeoutMs: 20 * MINUTE },
  );
  ctx.tracked.push(sandbox.id);
  return sandbox;
}

function check(problem: string | null, what: string): void {
  if (problem !== null) throw new Error(`${what}: ${problem}`);
}

/** L1: the server is unreachable from the daemon for the outage mid-command. */
async function cellL1(ctx: Ctx, sandboxId: string): Promise<void> {
  const ticks = Math.ceil(ctx.config.outageMs / 1000) + 60;
  let started: () => void = () => undefined;
  const running = new Promise<void>((resolve) => {
    started = resolve;
  });
  const gaps: string[] = [];
  const result = ctx.wssp.commands.script(sandboxId, tickerScript(ticks, 1), {
    timeoutMs: (ticks + 300) * 1000,
    waitTimeoutMs: (ticks + 900) * 1000,
    onStdout: (text) => {
      if (text.includes("tick-3\n")) started();
    },
    onOutput: (event) => {
      if (event.kind === "gap") gaps.push(`${event.start}-${event.end}`);
    },
  });
  result.catch(() => undefined);
  await Promise.race([running, result]);
  const frozen = ctx.door.beginOutage();
  if (frozen === 0) {
    ctx.door.endOutage();
    throw new Error("L1: no live relay link to cut");
  }
  log(`L1: outage begins (${frozen} relay link(s) frozen) for ${ctx.config.outageMs} ms`);
  await sleep(ctx.config.outageMs);
  ctx.door.endOutage();
  log("L1: outage ends");
  const outcome = await result;
  check(gaps.length > 0 ? `output gaps ${gaps.join(",")}` : null, "L1");
  check(exactOutputProblem(outcome, tickerOutput(ticks)), "L1");
}

/** L3: quiesce-restart with a running command and a held new command. */
async function cellL3(ctx: Ctx, sandboxId: string): Promise<void> {
  const ticks = 40;
  let started: () => void = () => undefined;
  const running = new Promise<void>((resolve) => {
    started = resolve;
  });
  const first = ctx.wssp.commands.script(sandboxId, tickerScript(ticks, 1), {
    timeoutMs: 10 * MINUTE,
    waitTimeoutMs: 20 * MINUTE,
    onStdout: (text) => {
      if (text.includes("tick-3\n")) started();
    },
  });
  first.catch(() => undefined);
  await Promise.race([running, first]);
  const before = systemctlShow(ctx.config.unitName).mainPid;
  if (before <= 0) throw new Error("L3: the chaos unit has no main pid");
  const linksBefore = ctx.proxy.accepted;
  const fromSeq = ctx.proxy.cursor;
  // Never inherit MAINPID or any secret: the subcommand needs only its dirs.
  const quiesce = exec(ctx.config.wsspBin, ["host", "daemon", "quiesce", "--pid", String(before)], {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    WSSP_DATA_DIR: ctx.config.dataDir,
    WSSP_CONFIG_DIR: ctx.config.configDir,
  });
  if (quiesce.status !== 0 || !quiesce.stdout.includes("quiescing")) {
    throw new Error(`L3: wssp host daemon quiesce did not quiesce (exit ${quiesce.status})`);
  }
  await ctx.proxy.waitForFrame(
    { dir: "n2s", type: "host.quiesce" },
    { fromSeq, timeoutMs: 30_000 },
  );
  log("L3: daemon is quiescing; submitting the held command");
  const held = ctx.wssp.commands.script(sandboxId, "echo held", {
    timeoutMs: 2 * MINUTE,
    waitTimeoutMs: 20 * MINUTE,
  });
  held.catch(() => undefined);
  check(exactOutputProblem(await first, tickerOutput(ticks)), "L3 running command");
  check(exactOutputProblem(await held, "held\n"), "L3 held command");
  const after = systemctlShow(ctx.config.unitName).mainPid;
  if (after <= 0 || after === before) throw new Error("L3: the daemon did not restart");
  if (ctx.proxy.accepted <= linksBefore) throw new Error("L3: the respawned daemon never relinked");
}

/** L2: create in Intent (image fetch / VM create) with relay resets → READY. */
async function cellL2(ctx: Ctx): Promise<void> {
  const fromSeq = ctx.proxy.cursor;
  const creating = createSandbox(ctx, "L2");
  creating.catch(() => undefined);
  await Promise.race([
    ctx.proxy.waitForFrame(L2_CREATE_DISPATCH, { fromSeq, timeoutMs: 5 * MINUTE }),
    creating.then(() => {
      throw new Error("L2: the create finished before its dispatch was seen");
    }),
  ]);
  for (const delayMs of [3_000, 10_000]) {
    await sleep(delayMs);
    log(`L2: relay reset during create (${ctx.proxy.reset()} link(s))`);
  }
  const sandbox = await creating;
  check(
    exactOutputProblem(await ctx.wssp.commands.script(sandbox.id, "echo l2-ok"), "l2-ok\n"),
    "L2",
  );
  await ctx.wssp.sandboxes.destroy(sandbox.id, { waitTimeoutMs: 10 * MINUTE });
}

async function listRunSandboxes(ctx: Ctx): Promise<{ id: string; state: string }[]> {
  const found: { id: string; state: string }[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 10; page += 1) {
    const result = await ctx.wssp.sandboxes.list({
      metadata: { [RUN_LABEL_KEY]: ctx.config.runId },
      limit: 100,
      ...(cursor ? { cursor } : {}),
    });
    for (const sandbox of result.items) found.push({ id: sandbox.id, state: sandbox.state });
    if (!result.nextCursor) return found;
    cursor = result.nextCursor;
  }
  throw new Error("run-label listing exceeded 10 pages");
}

async function cleanup(
  ctx: Ctx,
  baseline: string[] | null,
): Promise<ReturnType<typeof cleanupVerdict>> {
  const input: CleanupInput = {
    tracked: ctx.tracked,
    remaining: [],
    destroyFailures: [],
    listed: false,
    unitStopped: false,
    baseline,
    after: null,
  };
  const failures: { id: string; code: string }[] = [];
  try {
    for (const sandbox of await listRunSandboxes(ctx)) {
      if (sandbox.state === "DELETED") continue;
      try {
        await ctx.wssp.sandboxes.destroy(sandbox.id, { waitTimeoutMs: 10 * MINUTE });
      } catch (error) {
        failures.push({ id: sandbox.id, code: describe(error).slice(0, 80) });
      }
    }
    input.remaining = await listRunSandboxes(ctx);
    input.listed = true;
  } catch (error) {
    log(`cleanup: run-label listing failed: ${describe(error)}`);
  }
  input.destroyFailures = failures;
  exec("systemctl", ["--user", "stop", ctx.config.unitName]);
  const unit = systemctlShow(ctx.config.unitName);
  input.unitStopped = unit.loadState === "not-found" || unit.activeState !== "active";
  await ctx.door.close().catch(() => undefined);
  await ctx.proxy.close().catch(() => undefined);
  input.after = incusNames(ctx.config.incusProject);
  return cleanupVerdict(input);
}

async function main(): Promise<number> {
  const home = homedir();
  const parsed = parseLiveConfig(process.env, {
    home,
    randomRunId: () => randomBytes(5).toString("hex"),
  });
  if (!parsed.ok) {
    for (const error of parsed.errors) log(`refused: ${error}`);
    return 2;
  }
  const config = parsed.config;
  if (!existsSync(config.wsspBin)) {
    log(`refused: ${CHAOS_ENV.wsspBin} (${config.wsspBin}) does not exist.`);
    return 2;
  }
  if (!honorsSharedIncusOverride(readFileSync(config.wsspBin))) {
    log(
      `refused: ${CHAOS_ENV.wsspBin} (${config.wsspBin}) is a release build; the chaos daemon shares this Incus server with wssp-host and needs a debug build (target/debug/wssp) for ${SHARED_INCUS_ENV}.`,
    );
    return 2;
  }
  const production = systemctlShow(PRODUCTION_UNIT);
  const footprint = productionFootprint(
    production.loadState === "not-found" ? null : production,
    openPaths(production.mainPid),
    home,
  );
  const refusals = guardRefusals(config, footprint, {
    chaosUnit: systemctlShow(config.unitName),
    runDirExists: existsSync(config.runDir),
    productionRelayDirExists: (dir, hash) => existsSync(join(dir, "relay", hash)),
  });
  const wssp = createWsspClient({ baseUrl: config.upstreamUrl.origin, apiKey: config.sdkKey });
  if (refusals.length === 0) {
    // Before the front door exists, ask the server directly.
    const refusal = hostAvailabilityRefusal(await findHost(wssp, config.hostId));
    if (refusal) refusals.push(refusal);
  }
  if (refusals.length > 0) {
    for (const refusal of refusals) log(`refused: ${refusal}`);
    return 3;
  }
  log(
    `run ${config.runId}: unit ${config.unitName}, dir ${config.runDir}, project ${config.incusProject}, host relay ${hostRelayHash(config.hostId).slice(0, 12)}…, cells ${config.cells.join(",")}`,
  );
  const baseline = incusNames(config.incusProject);
  mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  mkdirSync(config.configDir, { recursive: true, mode: 0o700 });

  const upstreamWs = new URL(config.upstreamUrl.origin);
  upstreamWs.protocol = "ws:";
  const proxy = await RelayFaultProxy.start({ upstream: upstreamWs.origin });
  const door = await FrontDoor.start(
    config.apiUrl,
    config.upstreamUrl,
    Number(new URL(proxy.url).port),
  );
  const ctx: Ctx = {
    config,
    wssp: createWsspClient({ baseUrl: config.apiUrl.origin, apiKey: config.sdkKey }),
    proxy,
    door,
    tracked: [],
    vms: new LiveVmCap(),
  };
  let results = new Map<LiveCell, string | null>();
  let verdict: ReturnType<typeof cleanupVerdict> | null = null;
  try {
    const started = exec("systemd-run", systemdRunArgv(config, process.env.WSSP_TEST_RELAY_TIMING));
    if (started.status !== 0) throw new Error(`systemd-run failed (exit ${started.status})`);
    await waitHostConnected(ctx, 3 * MINUTE);
    log("dedicated daemon connected through the fault proxy");
    // L1 and L3 share one primary, kept across L2 (two VMs in all).
    results = await runLiveCells(config.cells, {
      createSandbox: async (cell) => (await createSandbox(ctx, cell)).id,
      l1: (primary) => cellL1(ctx, primary),
      l2: () => cellL2(ctx),
      l3: (primary) => cellL3(ctx, primary),
      recover: () => {
        door.endOutage();
        proxy.release();
      },
      describe,
      log,
    });
  } catch (error) {
    log(`run aborted: ${describe(error)}`);
  } finally {
    verdict = await cleanup(ctx, baseline).catch((error) => {
      log(`cleanup failed: ${describe(error)}`);
      return null;
    });
  }
  for (const cell of config.cells) {
    const outcome = results.get(cell);
    log(
      `${cell}: ${outcome === undefined ? "NOT RUN" : outcome === null ? "PASS" : `FAIL ${outcome}`}`,
    );
  }
  log("L4: manual (browser terminal reattach; see docs/testing.md)");
  if (!verdict) return 1;
  for (const problem of verdict.problems) log(`cleanup: ${problem}`);
  for (const leak of verdict.leaks) log(`LEAK: ${leak} remains in project ${config.incusProject}`);
  const passed = config.cells.every((cell) => results.get(cell) === null);
  log(verdict.ok ? "cleanup: clean" : "cleanup: NOT clean");
  return passed && verdict.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(
    (code) => process.exit(code),
    (error: unknown) => {
      log(`fatal: ${describe(error)}`);
      process.exit(1);
    },
  );
}
