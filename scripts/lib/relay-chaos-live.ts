/**
 * Pure logic of `scripts/relay-chaos-live.ts` (reconnect plan WP9): config
 * parsing, the production-daemon guards, the transient unit's argv, and the
 * cleanup verdict. No IO here, so every refusal and every leak rule is unit
 * tested (`relay-chaos-live.test.ts`).
 *
 * Secrets (the SDK key, the host token) are validated by prefix only and are
 * never part of an error, a refusal, an argv or a log line.
 */
import { createHash } from "node:crypto";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Environment variable NAMES the live script reads. Values are never logged. */
export const CHAOS_ENV = {
  gate: "RELAY_CHAOS_LIVE",
  apiUrl: "WSSP_CHAOS_API_URL",
  upstreamUrl: "WSSP_CHAOS_UPSTREAM_URL",
  sdkKey: "WSSP_CHAOS_SDK_KEY",
  hostId: "WSSP_CHAOS_HOST_ID",
  hostToken: "WSSP_CHAOS_HOST_TOKEN",
  template: "WSSP_CHAOS_TEMPLATE",
  runId: "WSSP_CHAOS_RUN_ID",
  dataRoot: "WSSP_CHAOS_DATA_ROOT",
  wsspBin: "WSSP_CHAOS_WSSP_BIN",
  incusProject: "WSSP_CHAOS_INCUS_PROJECT",
  cells: "WSSP_CHAOS_CELLS",
  outageMs: "WSSP_CHAOS_OUTAGE_MS",
} as const;

/** The production service the guards protect. */
export const PRODUCTION_UNIT = "wssp-host";
/** D7: at most two VMs per live run (so never more than two live at once). */
export const MAX_LIVE_VMS = 2;
/** Sandbox metadata key carrying the run label. */
export const RUN_LABEL_KEY = "wssp_chaos_run";
/**
 * L2 waits for the create's dispatch on the wire. Wire frames carry the relay
 * kind (`OPERATION_DISPATCH_KIND.CREATE_SANDBOX`, "sandbox.create"), never
 * the server's operation kind ("CREATE_SANDBOX").
 */
export const L2_CREATE_DISPATCH = {
  dir: "s2n",
  type: "operation.dispatch",
  kind: "sandbox.create",
} as const;
export const LIVE_CELLS = ["L1", "L2", "L3"] as const;
export type LiveCell = (typeof LIVE_CELLS)[number];

export type LiveConfig = {
  runId: string;
  unitName: string;
  /** Canonical origin (the server's BETTER_AUTH_URL); the front door listens here. */
  apiUrl: URL;
  /** Where the server really listens (loopback, cleartext). */
  upstreamUrl: URL;
  sdkKey: string;
  hostId: string;
  template: string;
  runDir: string;
  dataDir: string;
  configDir: string;
  wsspBin: string;
  incusProject: string;
  cells: LiveCell[];
  outageMs: number;
};

type Env = Readonly<Record<string, string | undefined>>;

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);
const RUN_ID = /^[a-z0-9]{6,16}$/;
const HOST_ID = /^[A-Za-z0-9_-]{1,64}$/;
const INCUS_PROJECT = /^[a-z][a-z0-9-]{0,62}$/;

function loopbackOrigin(name: string, value: string | undefined, errors: string[]): URL | null {
  if (!value) {
    errors.push(`${name} is required.`);
    return null;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    errors.push(`${name} must be a URL.`);
    return null;
  }
  if (
    url.protocol !== "http:" ||
    !LOOPBACK.has(url.hostname) ||
    url.port === "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.username !== "" ||
    url.password !== ""
  ) {
    errors.push(`${name} must be a loopback http:// origin with an explicit port and no path.`);
    return null;
  }
  return url;
}

/**
 * Reads and validates the live config. Errors name variables, never values.
 * `randomRunId` is used when `WSSP_CHAOS_RUN_ID` is unset.
 */
export function parseLiveConfig(
  env: Env,
  { home, randomRunId }: { home: string; randomRunId: () => string },
): { ok: true; config: LiveConfig } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  if (env[CHAOS_ENV.gate] !== "1") {
    return {
      ok: false,
      errors: [`${CHAOS_ENV.gate}=1 is required: this script drives real Incus VMs.`],
    };
  }
  const apiUrl = loopbackOrigin(CHAOS_ENV.apiUrl, env[CHAOS_ENV.apiUrl], errors);
  const upstreamUrl = loopbackOrigin(CHAOS_ENV.upstreamUrl, env[CHAOS_ENV.upstreamUrl], errors);
  if (apiUrl && upstreamUrl && apiUrl.port === upstreamUrl.port) {
    errors.push(`${CHAOS_ENV.upstreamUrl} must use a different port from ${CHAOS_ENV.apiUrl}.`);
  }
  const sdkKey = env[CHAOS_ENV.sdkKey] ?? "";
  if (!sdkKey.startsWith("wssp_sdk_")) {
    errors.push(`${CHAOS_ENV.sdkKey} must hold a wssp_sdk_ key.`);
  }
  if (!(env[CHAOS_ENV.hostToken] ?? "").startsWith("wssp_host_")) {
    errors.push(`${CHAOS_ENV.hostToken} must hold a wssp_host_ token for the test host.`);
  }
  const hostId = env[CHAOS_ENV.hostId] ?? "";
  if (!HOST_ID.test(hostId)) errors.push(`${CHAOS_ENV.hostId} must be a host id.`);
  const template = env[CHAOS_ENV.template] ?? "";
  if (template.length === 0) errors.push(`${CHAOS_ENV.template} is required.`);
  const runId = env[CHAOS_ENV.runId] ?? randomRunId();
  if (!RUN_ID.test(runId)) errors.push(`${CHAOS_ENV.runId} must match ${RUN_ID}.`);
  const dataRoot = env[CHAOS_ENV.dataRoot] ?? join(home, ".local/share/wssp-chaos");
  if (!isAbsolute(dataRoot)) errors.push(`${CHAOS_ENV.dataRoot} must be absolute.`);
  // Default: this checkout's debug build, the only kind that honours the
  // shared-Incus override the chaos daemon needs beside `wssp-host`.
  const wsspBin = env[CHAOS_ENV.wsspBin] ?? DEFAULT_WSSP_BIN;
  if (!isAbsolute(wsspBin)) errors.push(`${CHAOS_ENV.wsspBin} must be absolute.`);
  const incusProject = env[CHAOS_ENV.incusProject] ?? "wssp-chaos";
  if (!INCUS_PROJECT.test(incusProject)) {
    errors.push(`${CHAOS_ENV.incusProject} must be an Incus project name.`);
  }
  const cells: LiveCell[] = [];
  for (const raw of (env[CHAOS_ENV.cells] ?? LIVE_CELLS.join(",")).split(",")) {
    const cell = raw.trim();
    if (cell === "L4") {
      errors.push("L4 (terminal reattach) is browser-driven and manual; see docs/testing.md.");
    } else if ((LIVE_CELLS as readonly string[]).includes(cell)) {
      if (!cells.includes(cell as LiveCell)) cells.push(cell as LiveCell);
    } else {
      errors.push(`${CHAOS_ENV.cells} lists an unknown cell.`);
    }
  }
  const outageMs = Number(env[CHAOS_ENV.outageMs] ?? 90_000);
  if (!Number.isInteger(outageMs) || outageMs < 1_000 || outageMs > 600_000) {
    errors.push(`${CHAOS_ENV.outageMs} must be an integer between 1000 and 600000.`);
  }
  if (errors.length > 0 || !apiUrl || !upstreamUrl) return { ok: false, errors };
  const runDir = resolve(dataRoot, runId);
  return {
    ok: true,
    config: {
      runId,
      unitName: `wssp-chaos-${runId}`,
      apiUrl,
      upstreamUrl,
      sdkKey,
      hostId,
      template,
      runDir,
      dataDir: join(runDir, "data"),
      configDir: join(runDir, "config"),
      wsspBin: resolve(wsspBin),
      incusProject,
      cells,
      outageMs,
    },
  };
}

// ---- systemd ----------------------------------------------------------------

export type UnitShow = {
  loadState: string;
  activeState: string;
  mainPid: number;
  execStart: string;
  workingDirectory: string;
  /** Parsed in memory only: it may hold a production secret. Never log it. */
  environment: ReadonlyMap<string, string>;
};

/** `systemctl --user show` properties the guards read. */
export const UNIT_SHOW_PROPERTIES = [
  "LoadState",
  "ActiveState",
  "MainPID",
  "ExecStart",
  "WorkingDirectory",
  "Environment",
] as const;

function splitEnvironment(value: string): Map<string, string> {
  const result = new Map<string, string>();
  const words = value.match(/"(?:[^"\\]|\\.)*"|\S+/g) ?? [];
  for (const word of words) {
    const unquoted = word.startsWith('"') ? word.slice(1, -1).replace(/\\(.)/g, "$1") : word;
    const eq = unquoted.indexOf("=");
    if (eq > 0) result.set(unquoted.slice(0, eq), unquoted.slice(eq + 1));
  }
  return result;
}

/** Parses `systemctl show -p …` output (`Key=value` lines). */
export function parseSystemctlShow(text: string): UnitShow {
  const props = new Map<string, string>();
  for (const line of text.split("\n")) {
    const eq = line.indexOf("=");
    if (eq > 0) props.set(line.slice(0, eq), line.slice(eq + 1));
  }
  const mainPid = Number(props.get("MainPID") ?? "0");
  return {
    loadState: props.get("LoadState") ?? "not-found",
    activeState: props.get("ActiveState") ?? "inactive",
    mainPid: Number.isInteger(mainPid) ? mainPid : 0,
    execStart: props.get("ExecStart") ?? "",
    workingDirectory: props.get("WorkingDirectory") ?? "",
    environment: splitEnvironment(props.get("Environment") ?? ""),
  };
}

function unitExists(unit: UnitShow): boolean {
  return unit.loadState !== "not-found";
}

/**
 * The transient unit: `systemd-run --user`, no sudo. The host token is passed
 * by NAME (`--setenv=NAME` copies it from this process), so no secret value
 * is ever in an argv.
 */
/** `target/debug/wssp` of the repository this script lives in. */
export const DEFAULT_WSSP_BIN = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../target/debug/wssp",
);

/** The debug-only override the chaos daemons need (they share this Incus server). */
export const SHARED_INCUS_ENV = "WSSP_TEST_SHARED_INCUS";

/**
 * Whether a `wssp` binary honours {@link SHARED_INCUS_ENV}. Release builds
 * compile the override out and never name it (`cli-ci.yml` greps for it), so
 * a release binary would refuse to start beside `wssp-host`.
 */
export function honorsSharedIncusOverride(binary: Uint8Array): boolean {
  return Buffer.from(binary.buffer, binary.byteOffset, binary.byteLength).includes(
    SHARED_INCUS_ENV,
  );
}

export function systemdRunArgv(config: LiveConfig, relayTiming?: string): string[] {
  return [
    "--user",
    `--unit=${config.unitName}`,
    `--description=wssp live relay chaos run ${config.runId}`,
    "--collect",
    "--property=Restart=always",
    "--property=RestartSec=2s",
    "--property=KillMode=mixed",
    "--property=TimeoutStopSec=75s",
    "--property=UMask=0077",
    "--property=LimitCORE=0",
    `--setenv=WSSP_DATA_DIR=${config.dataDir}`,
    `--setenv=WSSP_CONFIG_DIR=${config.configDir}`,
    `--setenv=${CHAOS_ENV.hostToken}`,
    // Test-only: the production `wssp-host` already holds this machine's
    // Incus server (one wssp daemon per Incus server). Debug builds accept
    // the override only with a loopback control plane and log a warning.
    `--setenv=${SHARED_INCUS_ENV}=1`,
    ...(relayTiming === undefined ? [] : ["--setenv=WSSP_TEST_RELAY_TIMING"]),
    "--",
    config.wsspBin,
    "connect",
    "--runtime",
    "incus",
    "--incus-project",
    config.incusProject,
    "--server",
    config.apiUrl.origin,
    "--host-id",
    config.hostId,
    "--host-token-env",
    CHAOS_ENV.hostToken,
    "--label",
    config.unitName,
  ];
}

// ---- production footprint and guards ------------------------------------------

export type ProductionFootprint = {
  dataDirs: string[];
  configDirs: string[];
  incusProjects: string[];
  hostIds: string[];
  /** SHA-256 relay directory names the running production daemon has open. */
  relayHashes: string[];
  execStart: string;
  workingDirectory: string;
};

function flagValues(command: string, flag: string): string[] {
  const values: string[] = [];
  const pattern = new RegExp(`${flag}(?:=|\\s+)([^\\s;]+)`, "g");
  for (const match of command.matchAll(pattern)) if (match[1]) values.push(match[1]);
  return values;
}

/**
 * What the production `wssp-host` daemon owns, from its unit and from the
 * paths its main process holds open (`/proc/<pid>/fd` links: names only).
 * Defaults are always included, so a missing or stopped unit still protects
 * `~/.local/share/wssp`, `~/.config/wssp` and the `wssp`/`default` projects.
 */
export function productionFootprint(
  unit: UnitShow | null,
  openPaths: readonly string[],
  home: string,
): ProductionFootprint {
  const env = unit?.environment ?? new Map<string, string>();
  const execStart = unit?.execStart ?? "";
  const dataDirs = new Set([join(home, ".local/share/wssp")]);
  const configDirs = new Set([join(home, ".config/wssp")]);
  const incusProjects = new Set(["wssp", "default"]);
  const envData = env.get("WSSP_DATA_DIR");
  if (envData) dataDirs.add(resolve(envData));
  for (const value of flagValues(execStart, "WSSP_DATA_DIR")) dataDirs.add(resolve(value));
  const envConfig = env.get("WSSP_CONFIG_DIR");
  if (envConfig) configDirs.add(resolve(envConfig));
  for (const value of flagValues(execStart, "WSSP_CONFIG_DIR")) configDirs.add(resolve(value));
  const envProject = env.get("WSSP_INCUS_PROJECT");
  if (envProject) incusProjects.add(envProject);
  for (const value of flagValues(execStart, "--incus-project")) incusProjects.add(value);
  const relayHashes = new Set<string>();
  for (const path of openPaths) {
    const match = /^(.*)\/relay\/([0-9a-f]{64})(?:\/|$)/.exec(path);
    if (match?.[1] && match[2]) {
      dataDirs.add(match[1]);
      relayHashes.add(match[2]);
    }
  }
  return {
    dataDirs: [...dataDirs],
    configDirs: [...configDirs],
    incusProjects: [...incusProjects],
    hostIds: flagValues(execStart, "--host-id"),
    relayHashes: [...relayHashes],
    execStart,
    workingDirectory: unit?.workingDirectory ?? "",
  };
}

/** The daemon's relay directory name for a host id (`relay/<SHA-256>`). */
export function hostRelayHash(hostId: string): string {
  return createHash("sha256").update(hostId).digest("hex");
}

/** `child` is `parent` or below it (path-segment aware). */
function isInside(child: string, parent: string): boolean {
  const rel = relative(resolve(parent), resolve(child));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/** Equal, or one inside the other. */
export function pathsOverlap(a: string, b: string): boolean {
  return isInside(a, b) || isInside(b, a);
}

export type GuardFacts = {
  /** `systemctl --user show <unitName>` of the would-be chaos unit. */
  chaosUnit: UnitShow;
  /** The run directory already exists. */
  runDirExists: boolean;
  /** `relay/<hash>` exists under a production data dir. */
  productionRelayDirExists: (dataDir: string, hash: string) => boolean;
};

/**
 * Every reason the run must not start. Empty means the target is a dedicated
 * daemon. Messages carry paths and names, never secret values.
 */
export function guardRefusals(
  config: LiveConfig,
  production: ProductionFootprint,
  facts: GuardFacts,
): string[] {
  const refusals: string[] = [];
  if (config.unitName === PRODUCTION_UNIT) refusals.push("the chaos unit name is wssp-host.");
  if (unitExists(facts.chaosUnit)) {
    refusals.push(`unit ${config.unitName} already exists; pick a new run id.`);
  }
  if (facts.runDirExists) {
    refusals.push(`run directory ${config.runDir} already exists; pick a new run id.`);
  }
  for (const dir of production.dataDirs) {
    if (pathsOverlap(config.runDir, dir)) {
      refusals.push(`run directory ${config.runDir} overlaps the wssp-host data dir ${dir}.`);
    }
  }
  for (const dir of production.configDirs) {
    if (pathsOverlap(config.runDir, dir)) {
      refusals.push(`run directory ${config.runDir} overlaps the wssp-host config dir ${dir}.`);
    }
  }
  // `!` marks "missing is fine"; `/` and unset are no claim on a directory.
  const workingDirectory = production.workingDirectory.replace(/^!/, "");
  if (
    isAbsolute(workingDirectory) &&
    workingDirectory !== "/" &&
    isInside(workingDirectory, config.runDir)
  ) {
    refusals.push(
      `the wssp-host WorkingDirectory ${workingDirectory} is inside the run directory.`,
    );
  }
  if (production.execStart.includes(config.runDir)) {
    refusals.push(`the wssp-host ExecStart names the run directory ${config.runDir}.`);
  }
  if (production.incusProjects.includes(config.incusProject)) {
    refusals.push(`Incus project ${config.incusProject} is used by wssp-host.`);
  }
  const hash = hostRelayHash(config.hostId);
  if (production.hostIds.includes(config.hostId)) {
    refusals.push("the test host id is the one the wssp-host ExecStart serves.");
  }
  if (production.relayHashes.includes(hash)) {
    refusals.push("the running wssp-host daemon holds the test host's relay journal open.");
  }
  if (production.dataDirs.some((dir) => facts.productionRelayDirExists(dir, hash))) {
    refusals.push("a wssp-host data dir already has a relay journal for the test host id.");
  }
  return refusals;
}

/** The host must be enrolled, visible to the key, and served by no daemon yet. */
export function hostAvailabilityRefusal(
  host: { status: string; draining: boolean } | undefined,
): string | null {
  if (host === undefined) return "the test host id is not visible to the SDK key.";
  if (host.status === "CONNECTED") {
    return "the test host is already CONNECTED: another daemon (perhaps wssp-host) serves it.";
  }
  if (host.status === "REVOKED") return "the test host's credential is revoked.";
  if (host.draining) return "the test host is draining; undrain it first.";
  return null;
}

// ---- cleanup accounting -------------------------------------------------------

function incusInstanceName(sandboxId: string): string {
  return `wssp-sbx-${sandboxId}`;
}

/** `incus list --format csv --columns n wssp-sbx-` output → instance names. */
export function parseIncusNames(csv: string): string[] {
  return csv
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("wssp-sbx-"));
}

export type CleanupInput = {
  /** Sandbox ids this run created (or whose create it submitted). */
  tracked: readonly string[];
  /** Sandboxes still listed under the run label after the destroys. */
  remaining: readonly { id: string; state: string }[];
  /** Destroys that failed, by sandbox id (error codes only). */
  destroyFailures: readonly { id: string; code: string }[];
  /** Whether the label listing itself succeeded. */
  listed: boolean;
  unitStopped: boolean;
  /** Instance names in the chaos project before the run; null if unread. */
  baseline: readonly string[] | null;
  /** Instance names after cleanup; null if the read-only list failed. */
  after: readonly string[] | null;
};

export type CleanupVerdict = { ok: boolean; leaks: string[]; problems: string[] };

/** A run is clean only when every check could be made and found nothing left. */
export function cleanupVerdict(input: CleanupInput): CleanupVerdict {
  const problems: string[] = [];
  const leaks: string[] = [];
  const ids = new Set([...input.tracked, ...input.remaining.map((sandbox) => sandbox.id)]);
  for (const failure of input.destroyFailures) {
    problems.push(`destroy of ${failure.id} failed (${failure.code}).`);
  }
  if (!input.listed) problems.push("the run-label sandbox listing failed.");
  for (const sandbox of input.remaining) {
    if (sandbox.state !== "DELETED") {
      problems.push(`sandbox ${sandbox.id} is still ${sandbox.state}.`);
    }
  }
  if (!input.unitStopped) problems.push("the chaos unit did not stop.");
  if (input.after === null) {
    problems.push("the read-only incus list failed; VM cleanup is unverified.");
  } else {
    const own = new Set([...ids].map(incusInstanceName));
    const baseline = new Set(input.baseline ?? []);
    for (const name of input.after) {
      if (own.has(name)) leaks.push(name);
      else if (input.baseline !== null && !baseline.has(name)) leaks.push(name);
    }
    if (input.baseline === null) problems.push("no incus baseline; only run VMs were checked.");
  }
  return { ok: problems.length === 0 && leaks.length === 0, leaks, problems };
}

// ---- cell expectations --------------------------------------------------------

/** A command printing `tick-1` … `tick-<n>`, one per `intervalS` seconds. */
export function tickerScript(n: number, intervalS: number): string {
  return `i=1; while [ "$i" -le ${n} ]; do echo "tick-$i"; i=$((i+1)); sleep ${intervalS}; done`;
}

export function tickerOutput(n: number): string {
  let out = "";
  for (let i = 1; i <= n; i += 1) out += `tick-${i}\n`;
  return out;
}

export type CommandOutcome = { exitCode: number; stdout: string; truncated: boolean };

/** Why a command result is not the exact expected output, or null. */
export function exactOutputProblem(result: CommandOutcome, expected: string): string | null {
  if (result.exitCode !== 0) return `exit code ${result.exitCode}`;
  if (result.truncated) return "output has a gap (truncated)";
  if (result.stdout !== expected) {
    return `stdout differs (${result.stdout.length} chars, expected ${expected.length})`;
  }
  return null;
}

/** The VM cap: every create of a run reserves one of {@link MAX_LIVE_VMS}. */
export class LiveVmCap {
  #creates = 0;
  get creates(): number {
    return this.#creates;
  }
  /** Reserves a create, or throws once the run has used the cap. */
  reserve(): void {
    if (this.#creates >= MAX_LIVE_VMS) throw new Error(`At most ${MAX_LIVE_VMS} VMs per run`);
    this.#creates += 1;
  }
}

/** What a live run does per cell; every external effect goes through here. */
export type LiveCellOps = {
  /** Creates (READY) a sandbox for `cell`, reserving a cap slot. */
  createSandbox(cell: string): Promise<string>;
  l1(primary: string): Promise<void>;
  /** Creates its own sandbox (the create under test) and destroys it. */
  l2(): Promise<void>;
  l3(primary: string): Promise<void>;
  /** Releases any fault a failed cell left in place. */
  recover(): void;
  describe(error: unknown): string;
  log(message: string): void;
};

/**
 * Runs `cells` in order. L1 and L3 share one primary sandbox, created by the
 * first of them and kept across L2: L2's own create is the run's second VM,
 * so the default L1→L2→L3 run makes two VMs in all and at most two are ever
 * live. Each cell's result is null (PASS) or its failure.
 */
export async function runLiveCells(
  cells: readonly LiveCell[],
  ops: LiveCellOps,
): Promise<Map<LiveCell, string | null>> {
  const results = new Map<LiveCell, string | null>();
  let primary: string | null = null;
  for (const cell of cells) {
    ops.log(`${cell}: start`);
    try {
      if (cell === "L2") await ops.l2();
      else {
        primary ??= await ops.createSandbox("primary");
        await (cell === "L1" ? ops.l1(primary) : ops.l3(primary));
      }
      results.set(cell, null);
      ops.log(`${cell}: PASS`);
    } catch (error) {
      results.set(cell, ops.describe(error));
      ops.log(`${cell}: FAIL ${ops.describe(error)}`);
      ops.recover();
    }
  }
  return results;
}
