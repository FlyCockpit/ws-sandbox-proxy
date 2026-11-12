/**
 * Opt-in LIVE qualification of stopped-sandbox S3 offload. Real Incus VMs on two DEDICATED chaos daemons (host A and
 * host B, each its own transient user unit and Incus project) and the local
 * dev S3 gateway (`pnpm dev:s3`) only. Never run by CI or `pnpm verify`.
 *
 *   OFFLOAD_LIVE=1 pnpm test:offload:live
 *
 * Wrap the whole session in the chaos-stack lock:
 *   flock ~/projects/wssp-coord/chaos-stack.lock pnpm test:offload:live
 *
 * Cells (all on one sandbox unless noted):
 *   L1 create with guestSudo, write a marker, stop → disk `host_and_store`;
 *   L2 drain A `--offload` (host credential) → OFFLOADED; start → restored on
 *      B; marker, machine-id, SSH host keys and the pinned
 *      `volatile.cloud-init.instance-id` unchanged; `volatile.base_image` is
 *      the restore base tag; the guest's passwordless root probe works; A no
 *      longer holds the VM;
 *   L3 stop on B → stored; undrain A, drain B → OFFLOADED; start, SIGKILL
 *      daemon B's main process (systemd-verified) mid-fetch → the start
 *      fails and the sandbox returns to OFFLOADED; the restarted unit then
 *      restores it (same-host retry after a daemon restart);
 *   L4 a guestSudo=false sandbox offloaded and restored on the other host
 *      passes revoke-audit: the passwordless root probe is refused.
 *
 * Guards: loopback API only; units must be `wssp-chaos-*` and never the
 * production `wssp-host`; projects must not be `default` or `wssp`; each
 * unit must run with `--incus-project` equal to its configured project and
 * with the test-only `WSSP_TEST_SHARED_INCUS=1` (start it with
 * `systemd-run --user --setenv=WSSP_TEST_SHARED_INCUS=1 ...`) from a DEBUG
 * build (`target/debug/wssp`): one wssp daemon per Incus server is the
 * supported topology, and these daemons share this machine's Incus server
 * with each other and with `wssp-host`. Only debug builds honour the
 * override, and only with a loopback control plane.
 * Cleanup (finally): undrain both hosts, destroy every run-labelled sandbox,
 * then a read-only `incus list` of both projects. Secret values (SDK key,
 * host tokens) are read from the environment and never logged or put in an
 * argv.
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import process from "node:process";
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { SANDBOX_STATES } from "../packages/sandbox-contracts/src/dto.ts";
import { createWsspClient, type WsspClient } from "../packages/sdk/src/index.ts";
import { honorsSharedIncusOverride, SHARED_INCUS_ENV } from "./lib/relay-chaos-live.ts";

const MINUTE = 60_000;
const RUN_LABEL_KEY = "wssp_chaos_run";
const PRODUCTION_UNIT = "wssp-host";
const UNIT = /^wssp-chaos-[a-z0-9-]{1,40}$/;
const PROJECT = /^[a-z][a-z0-9-]{0,62}$/;
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const FORBIDDEN_PROJECTS = new Set(["default", "wssp"]);

type Side = { hostId: string; tokenEnv: string; unit: string; project: string };
type Config = {
  api: URL;
  sdkKey: string;
  template: string;
  runId: string;
  a: Side;
  b: Side;
};

export function parseOffloadLiveConfig(
  env: NodeJS.ProcessEnv,
  randomRunId: () => string,
): { ok: true; config: Config } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  if (env.OFFLOAD_LIVE !== "1") errors.push("OFFLOAD_LIVE=1 is required (real VMs).");
  let api: URL | null = null;
  try {
    api = new URL(env.WSSP_OFFLOAD_API_URL ?? "");
    if (!["127.0.0.1", "localhost", "[::1]"].includes(api.hostname))
      errors.push("WSSP_OFFLOAD_API_URL must be a loopback origin.");
  } catch {
    errors.push("WSSP_OFFLOAD_API_URL must be a URL.");
  }
  const side = (name: "A" | "B"): Side => {
    const s = {
      hostId: env[`WSSP_OFFLOAD_HOST_${name}`] ?? "",
      tokenEnv: `WSSP_OFFLOAD_HOST_${name}_TOKEN`,
      unit: env[`WSSP_OFFLOAD_UNIT_${name}`] ?? "",
      project: env[`WSSP_OFFLOAD_PROJECT_${name}`] ?? "",
    };
    if (!ID.test(s.hostId)) errors.push(`WSSP_OFFLOAD_HOST_${name} must be a host id.`);
    if (!env[s.tokenEnv]?.startsWith("wssp_host_"))
      errors.push(`${s.tokenEnv} must hold that host's wssp_host_ token.`);
    if (!UNIT.test(s.unit) || s.unit === PRODUCTION_UNIT)
      errors.push(`WSSP_OFFLOAD_UNIT_${name} must be a wssp-chaos-* unit.`);
    if (!PROJECT.test(s.project) || FORBIDDEN_PROJECTS.has(s.project))
      errors.push(`WSSP_OFFLOAD_PROJECT_${name} must be a dedicated Incus project.`);
    return s;
  };
  const a = side("A");
  const b = side("B");
  if (a.hostId === b.hostId || a.unit === b.unit || a.project === b.project)
    errors.push("Hosts A and B need distinct host ids, units and projects.");
  const sdkKey = env.WSSP_OFFLOAD_SDK_KEY ?? "";
  if (!sdkKey.startsWith("wssp_sdk_")) errors.push("WSSP_OFFLOAD_SDK_KEY must be a wssp_sdk_ key.");
  const template = env.WSSP_OFFLOAD_TEMPLATE ?? "";
  if (!template) errors.push("WSSP_OFFLOAD_TEMPLATE must name a template selector.");
  const runId = env.WSSP_OFFLOAD_RUN_ID ?? randomRunId();
  if (!/^[a-z0-9]{6,16}$/.test(runId)) errors.push("WSSP_OFFLOAD_RUN_ID must be [a-z0-9]{6,16}.");
  if (errors.length > 0 || !api) return { ok: false, errors };
  return { ok: true, config: { api, sdkKey, template, runId, a, b } };
}

function log(message: string): void {
  console.log(`[offload-live ${new Date().toISOString().slice(11, 19)}] ${message}`);
}

function describe(error: unknown): string {
  const e = error as { kind?: string; code?: string; message?: string };
  return `${e.kind ?? ""} ${e.code ?? ""} ${String(e.message ?? error)}`
    .replace(/wssp_(sdk|host|device)_[A-Za-z0-9_-]+/g, "wssp_$1_REDACTED")
    .slice(0, 400);
}

function run(command: string, args: string[]): { status: number; stdout: string } {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 120_000 });
  return { status: result.status ?? -1, stdout: result.stdout ?? "" };
}

function unitProject(unit: string): string | null {
  const shown = run("systemctl", ["--user", "show", unit, "-p", "ExecStart", "--value"]).stdout;
  return /--incus-project\s+(\S+)/.exec(shown)?.[1] ?? null;
}

/** Whether `systemctl show -p Environment --value` output sets the override. */
export function unitSharesIncus(environment: string): boolean {
  return environment.split(/\s+/).includes(`${SHARED_INCUS_ENV}=1`);
}

/** The daemon binary of a unit's `ExecStart` (`path=` field), if any. */
export function unitBinary(execStart: string): string | null {
  return /path=(\S+)/.exec(execStart)?.[1] ?? null;
}

function unitExecStart(unit: string): string {
  return run("systemctl", ["--user", "show", unit, "-p", "ExecStart", "--value"]).stdout;
}

function unitEnvironment(unit: string): string {
  return run("systemctl", ["--user", "show", unit, "-p", "Environment", "--value"]).stdout;
}

function check(ok: boolean, what: string): void {
  if (!ok) throw new Error(`check failed: ${what}`);
  log(`ok: ${what}`);
}

const instance = (sandboxId: string) => `wssp-sbx-${sandboxId}`;

function incusGet(project: string, sandboxId: string, key: string): string {
  return run("incus", [
    "config",
    "get",
    instance(sandboxId),
    key,
    "--project",
    project,
  ]).stdout.trim();
}

/** Root-side identity facts read through Incus (never through the SDK). */
function identity(project: string, sandboxId: string) {
  const out = run("incus", [
    "exec",
    instance(sandboxId),
    "--project",
    project,
    "--",
    "sh",
    "-c",
    "cat /etc/machine-id; cat /home/user/marker.txt; for k in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf $k | cut -d' ' -f2; done | sort | tr '\\n' ,",
  ]).stdout.split("\n");
  return {
    machineId: out[0] ?? "",
    marker: out[1] ?? "",
    hostKeys: out[2] ?? "",
    cloudInitId: incusGet(project, sandboxId, "volatile.cloud-init.instance-id"),
  };
}

function instances(project: string): string[] | null {
  const listed = run("incus", ["list", "--project", project, "-f", "csv", "-c", "n"]);
  return listed.status === 0 ? listed.stdout.split("\n").filter(Boolean) : null;
}

async function drain(config: Config, side: Side, draining: boolean, offload = false) {
  const response = await fetch(new URL("/api/sandbox-host/drain", config.api), {
    method: "POST",
    headers: {
      authorization: `Bearer ${process.env[side.tokenEnv] ?? ""}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ id: side.hostId, draining, offload }),
  });
  if (response.status !== 200) throw new Error(`drain ${side.hostId} HTTP ${response.status}`);
}

async function waitFor(
  wssp: WsspClient,
  sandboxId: string,
  done: (s: { state: string; disk: { location: string } | null }) => boolean,
  what: string,
  timeoutMs: number,
) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const s = await wssp.sandboxes.get(sandboxId);
    if (done({ state: s.state, disk: s.disk })) return s;
    await sleep(2000);
  }
  throw new Error(`timed out waiting for ${what}`);
}

const stored = (s: { disk: { location: string } | null }) => s.disk?.location === "host_and_store";
const offloaded = (s: { state: string }) => s.state === "OFFLOADED";

async function create(ctx: Ctx, guestSudo: boolean) {
  const s = await ctx.wssp.sandboxes.create({
    sandboxHostId: ctx.config.a.hostId,
    template: ctx.config.template,
    timeoutMs: 6 * 60 * MINUTE,
    guestSudo,
    metadata: { [RUN_LABEL_KEY]: ctx.config.runId },
  });
  const marker = `offload-live-${randomBytes(6).toString("hex")}`;
  const r = await s.commands.script(`echo ${marker} > /home/user/marker.txt`);
  check(r.exitCode === 0, `sandbox ${s.id} READY on A with marker`);
  return { id: s.id, marker };
}

async function sudoProbe(ctx: Ctx, sandboxId: string): Promise<boolean> {
  // Runs inside the guest VM as the guest user (never on this host).
  const probe = ["sudo", "-n", "true"].join(" ");
  const r = await ctx.wssp.commands.run(sandboxId, `${probe} && echo SUDO_OK || echo SUDO_NO`);
  return r.stdout.includes("SUDO_OK");
}

type Ctx = { config: Config; wssp: WsspClient };

async function cellL1L2(ctx: Ctx): Promise<string> {
  const { a, b } = ctx.config;
  const { id, marker } = await create(ctx, true);
  const before = identity(a.project, id);
  check(before.marker === marker, "L1 marker readable before stop");
  await ctx.wssp.sandboxes.stop(id);
  await waitFor(ctx.wssp, id, stored, "L1 host_and_store", 20 * MINUTE);
  log("L1 PASS");
  await drain(ctx.config, a, true, true);
  await waitFor(ctx.wssp, id, offloaded, "L2 eviction to OFFLOADED", 15 * MINUTE);
  check(
    (instances(a.project) ?? ["?"]).every((n) => n !== instance(id)),
    "L2 A deleted its copy",
  );
  const restored = await ctx.wssp.sandboxes.connect(id, {
    mode: "cold",
    waitTimeoutMs: 20 * MINUTE,
  });
  const dto = await restored.get();
  check(dto.hostId === b.hostId, "L2 restore landed on B");
  const after = identity(b.project, id);
  check(after.marker === marker, "L2 marker survived the restore");
  check(after.machineId === before.machineId, "L2 machine-id unchanged");
  check(after.hostKeys === before.hostKeys, "L2 SSH host keys unchanged");
  check(after.cloudInitId === before.cloudInitId, "L2 pinned cloud-init instance id accepted");
  const base = incusGet(b.project, id, "volatile.base_image");
  check(
    `sha256:${base}` === incusGet(b.project, id, "user.flycockpit.restore_base"),
    "L2 volatile.base_image is the restore base",
  );
  check(await sudoProbe(ctx, id), "L2 guest root probe works after restore (grant)");
  log("L2 PASS");
  return id;
}

async function cellL3(ctx: Ctx, id: string): Promise<void> {
  const { a, b } = ctx.config;
  await ctx.wssp.sandboxes.stop(id);
  await waitFor(ctx.wssp, id, stored, "L3 host_and_store on B", 20 * MINUTE);
  await drain(ctx.config, a, false);
  await drain(ctx.config, b, true, true);
  await waitFor(ctx.wssp, id, offloaded, "L3 eviction from B", 15 * MINUTE);
  // Undrain B again so the same-host retry can land there; A is drained
  // without offload so the restore goes to B.
  await drain(ctx.config, a, true, false);
  await drain(ctx.config, b, false);
  let settled: string | null = null;
  const start = ctx.wssp.sandboxes
    .connect(id, { mode: "cold", waitTimeoutMs: 20 * MINUTE })
    .then(
      () => "ready",
      (error: unknown) => `failed: ${describe(error)}`,
    )
    .then((outcome) => (settled = outcome));
  const until = Date.now() + 5 * MINUTE;
  while (settled === null && Date.now() < until) {
    if ((await ctx.wssp.sandboxes.get(id)).state === "PROVISIONING") break;
    await sleep(500);
  }
  check(settled === null, `L3 restore admitted and still running (${settled ?? ""})`);
  await sleep(4000); // inside the fetch (the fetch cap is set in B's config)
  const killed = run("systemctl", ["--user", "kill", "-s", "KILL", "--kill-whom=main", b.unit]);
  check(killed.status === 0, `L3 SIGKILL ${b.unit} mid-fetch`);
  const first = await start;
  check(first.startsWith("failed"), `L3 interrupted start failed (${first.slice(0, 120)})`);
  await waitFor(ctx.wssp, id, offloaded, "L3 back to OFFLOADED", 10 * MINUTE);
  // No manual reconnect: the unit's own restart confirms the SYSTEM_DETACH
  // kill's receipt (bd9cd2c5), so the retry completes by itself.
  const retry = ctx.wssp.sandboxes.connect(id, { mode: "cold", waitTimeoutMs: 20 * MINUTE });
  check((await (await retry).get()).hostId === b.hostId, "L3 retry restored on B after restart");
  log("L3 PASS");
}

async function cellL4(ctx: Ctx): Promise<void> {
  const { a, b } = ctx.config;
  await drain(ctx.config, a, false);
  const { id } = await create(ctx, false);
  check(!(await sudoProbe(ctx, id)), "L4 guestSudo=false: guest root probe refused before offload");
  await ctx.wssp.sandboxes.stop(id);
  await waitFor(ctx.wssp, id, stored, "L4 host_and_store", 20 * MINUTE);
  await drain(ctx.config, a, true, true);
  await waitFor(ctx.wssp, id, offloaded, "L4 eviction", 15 * MINUTE);
  const restored = await ctx.wssp.sandboxes.connect(id, {
    mode: "cold",
    waitTimeoutMs: 20 * MINUTE,
  });
  check((await restored.get()).hostId === b.hostId, "L4 restored on B");
  check(
    !(await sudoProbe(ctx, id)),
    "L4 revoke-audit: guest root probe still refused after restore",
  );
  log("L4 PASS");
}

async function cleanup(ctx: Ctx): Promise<boolean> {
  for (const side of [ctx.config.a, ctx.config.b])
    await drain(ctx.config, side, false).catch((e) => log(`cleanup: undrain: ${describe(e)}`));
  let ok = true;
  const mine = new Set<string>();
  try {
    const page = await ctx.wssp.sandboxes.list({
      metadata: { [RUN_LABEL_KEY]: ctx.config.runId },
      // The list defaults to READY only; an OFFLOADED or STOPPED run
      // sandbox must be destroyed too.
      states: SANDBOX_STATES.filter((state) => state !== "DELETED"),
      limit: 100,
    });
    for (const s of page.items) {
      mine.add(instance(s.id));
      if (s.state === "DELETED") continue;
      await ctx.wssp.sandboxes.destroy(s.id, { waitTimeoutMs: 10 * MINUTE }).catch((e) => {
        ok = false;
        log(`cleanup: destroy ${s.id}: ${describe(e)}`);
      });
    }
  } catch (error) {
    ok = false;
    log(`cleanup: listing failed: ${describe(error)}`);
  }
  for (const side of [ctx.config.a, ctx.config.b]) {
    const listed = instances(side.project);
    const left = listed === null ? ["<unreadable>"] : listed.filter((n) => mine.has(n));
    if (left.length > 0) {
      ok = false;
      log(`cleanup: ${side.project} still lists ${left.join(", ")}`);
    }
  }
  return ok;
}

async function main(): Promise<number> {
  const parsed = parseOffloadLiveConfig(process.env, () => randomBytes(5).toString("hex"));
  if (!parsed.ok) {
    for (const error of parsed.errors) log(`refused: ${error}`);
    return 2;
  }
  const config = parsed.config;
  for (const side of [config.a, config.b]) {
    const project = unitProject(side.unit);
    if (project !== side.project) {
      log(`refused: unit ${side.unit} is not running with --incus-project ${side.project}.`);
      return 3;
    }
    const binary = unitBinary(unitExecStart(side.unit));
    let honours = false;
    try {
      honours = binary !== null && honorsSharedIncusOverride(readFileSync(binary));
    } catch {
      honours = false;
    }
    if (!honours) {
      log(
        `refused: unit ${side.unit} must run a debug wssp build (target/debug/wssp); release builds ignore ${SHARED_INCUS_ENV}.`,
      );
      return 3;
    }
    if (!unitSharesIncus(unitEnvironment(side.unit))) {
      log(
        `refused: unit ${side.unit} must run with --setenv=${SHARED_INCUS_ENV}=1 (test-only; the chaos daemons share this Incus server).`,
      );
      return 3;
    }
  }
  const production = unitProject(PRODUCTION_UNIT);
  if (production && (production === config.a.project || production === config.b.project)) {
    log("refused: a configured project belongs to the production wssp-host unit.");
    return 3;
  }
  const ctx: Ctx = {
    config,
    wssp: createWsspClient({ baseUrl: config.api.origin, apiKey: config.sdkKey }),
  };
  log(
    `run ${config.runId}: A ${config.a.unit}/${config.a.project}, B ${config.b.unit}/${config.b.project}`,
  );
  const results: Record<string, string> = {};
  try {
    const id = await cellL1L2(ctx);
    results["L1+L2"] = "PASS";
    await cellL3(ctx, id).then(
      () => (results.L3 = "PASS"),
      (e) => (results.L3 = `FAIL ${describe(e)}`),
    );
    await cellL4(ctx).then(
      () => (results.L4 = "PASS"),
      (e) => (results.L4 = `FAIL ${describe(e)}`),
    );
  } catch (error) {
    results["L1+L2"] ??= `FAIL ${describe(error)}`;
  } finally {
    results.cleanup = (await cleanup(ctx).catch(() => false)) ? "clean" : "NOT clean";
  }
  for (const [cell, outcome] of Object.entries(results)) log(`${cell}: ${outcome}`);
  return Object.values(results).every((v) => v === "PASS" || v === "clean") ? 0 : 1;
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
