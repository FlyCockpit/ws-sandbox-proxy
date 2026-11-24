/**
 * The one disposable-PostgreSQL owner shared by the operations smokes
 * (test-runtime-operations) and the `pnpm test:pg`
 * harness (scripts/test-pg.mjs). Never reads `.env`; never pulls an image.
 *
 * Every container is `docker.io/library/postgres:18.6-trixie@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42`, `--rm`, `--pull=never` (a missing
 * image fails fast with the pull command to run; it is never fetched
 * implicitly), labelled `wssp.disposable-postgres=<owner>`, published on
 * loopback only, with a random password. `stop()` is idempotent, and
 * exit/SIGINT/SIGTERM/SIGHUP handlers force-remove every container AND every
 * `disposableDirectory()` this process still owns.
 *
 * Teardown order is fixed: every `spawnOwnedProcessGroup()` child tree that
 * could still be using a database is terminated and gone BEFORE any container
 * or directory is removed. On a signal the handler forwards it to
 * every process group in each owned tree (the leader's and any its
 * descendants created, e.g. Turbo's per-task groups), waits for them to empty
 * (bounded, then SIGKILL), then releases containers and directories, then
 * exits. Each owned tree is spawned with a unique `WSSP_OWNED_PROCESS_TREE`
 * marker in its environment; on Linux, teardown also finds every process that
 * inherited it (via /proc), so a group orphaned the instant its creator exits
 * is still owned. Limits: a descendant that starts with a scrubbed
 * environment (`env -i`, a runner that drops unlisted variables) carries no
 * marker and is found only while it is still below the tree; off Linux there
 * is no /proc, so only the live ancestry is followed.
 *
 * Docker failures never echo argv: `--env` values are redacted from every
 * error this module throws. The container password never reaches
 * argv at all: it is passed through a 0600 `--env-file` in a private
 * temporary directory that is removed as soon as `docker run` returns.
 *
 * Failures of the teardown itself are loud, never silent:
 * a container that survives every removal attempt, or a process-tree listing
 * that fails at teardown, is reported on stderr naming what was left, and the
 * process exits non-zero.
 *
 * POSIX only: `spawnOwnedProcessGroup` needs process groups and the POSIX
 * `ps` command (`ps -A -o pid=,ppid=,pgid=`, procps on Linux) to find the
 * process groups a child tree created. It refuses to start without a working
 * `ps` rather than degrade to signalling the leader's group alone.
 */
import { execFileSync, spawn } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { MAX_TEST_CONTAINER_PREFIX, testContainerPrefix } from "./test-container-prefix.mjs";

/**
 * The single pin. CI pulls it via `pnpm test:pg:pull-image`; a workflow service
 * container may name exactly this reference (the migrations job's server), never
 * another tag or digest.
 */
export const POSTGRES_IMAGE =
  "docker.io/library/postgres:18.6-trixie@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42";
const DISPOSABLE_LABEL = "wssp.disposable-postgres";

const owned = new Set();
const ownedDirectories = new Set();
/** Teardown failures reported so far; any one makes the process exit non-zero. */
const teardownFailures = [];
let handlersInstalled = false;

/** Reports a teardown failure loudly and marks the process as failed. */
function teardownFailure(message) {
  installHandlers(); // the exit handler keeps the exit code non-zero
  teardownFailures.push(message);
  process.exitCode = 1;
  console.error(`FAILED (disposable-postgres teardown): ${message}`);
}

/** `KEY=value` after `--env`/`-e` (or `--env=`/`-e=`) → `KEY=<redacted>`. */
export function redactDockerArgs(args) {
  const secrets = [];
  const redacted = args.map((arg, index) => {
    const inline = /^(--env=|-e=)([^=]+)=(.*)$/s.exec(arg);
    const previous = args[index - 1];
    const separate = (previous === "--env" || previous === "-e") && /^([^=]+)=(.*)$/s.exec(arg);
    if (inline) {
      if (inline[3]) secrets.push(inline[3]);
      return `${inline[1]}${inline[2]}=<redacted>`;
    }
    if (separate) {
      if (separate[2]) secrets.push(separate[2]);
      return `${separate[1]}=<redacted>`;
    }
    return arg;
  });
  return { redacted, secrets };
}

/**
 * Runs a command like execFileSync, but a failure is rethrown as a new Error
 * that names the redacted argv, the exit status and the last stderr lines with
 * every `--env` value removed. Node's own message ("Command failed: <argv>")
 * and the original error object (whose `spawnargs` hold the raw argv) never
 * escape.
 */
export function execRedacted(file, args, { timeout = 30_000 } = {}) {
  try {
    return execFileSync(file, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout,
    }).trim();
  } catch (error) {
    const { redacted, secrets } = redactDockerArgs(args);
    const scrub = (text) =>
      secrets.reduce((value, secret) => value.replaceAll(secret, "<redacted>"), text);
    const stderr = scrub(String(error?.stderr ?? "").trim())
      .split("\n")
      .slice(-3)
      .join(" | ");
    const status = error?.signal ? `signal ${error.signal}` : `exit ${error?.status ?? "unknown"}`;
    throw new Error(
      `${[file.split("/").at(-1), ...redacted].join(" ")} failed (${status})${stderr ? `: ${stderr}` : ""}`,
    );
  }
}

function docker(args, timeout = 30_000) {
  return execRedacted("docker", args, { timeout });
}

/**
 * "present", "absent", or "unknown" when the inspection itself failed (daemon
 * unreachable, timed out, killed). Only Docker's own "no such container"
 * answer confirms absence.
 */
function containerState(name) {
  try {
    execFileSync("docker", ["container", "inspect", name], {
      encoding: "utf8",
      stdio: ["ignore", "ignore", "pipe"],
      timeout: 15_000,
    });
    return { state: "present" };
  } catch (error) {
    const stderr = String(error?.stderr ?? "").trim();
    if (/no such (container|object)/i.test(stderr)) return { state: "absent" };
    const status = error?.signal ? `signal ${error.signal}` : `exit ${error?.status ?? "unknown"}`;
    return {
      state: "unknown",
      reason: `${status}${stderr ? `: ${stderr.split("\n").at(-1)}` : ""}`,
    };
  }
}

/** Consecutive failed inspections after which Docker is treated as unreachable. */
const INSPECTION_FAILURE_LIMIT = 3;

function containerId(name) {
  try {
    return execFileSync("docker", ["container", "inspect", "--format", "{{.Id}}", name], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 15_000,
    }).trim();
  } catch {
    return "";
  }
}

/**
 * Synchronous (usable from an `exit` handler): returns true once Docker
 * confirms the container is gone, so `docker ps -a` never shows a harness
 * leftover. It never forgets a container silently: after `attempts`
 * failed removals it names the container and its id on stderr, with the
 * command to remove it; when Docker cannot even be asked (inspection fails
 * repeatedly), it reports that removal is unconfirmed and keeps owning the
 * container, so a later teardown retries. Either way it marks the process
 * failed (exit code 1, also enforced by the exit handler) and returns false.
 */
export function forceRemove(name, { attempts = 100 } = {}) {
  const pause = new Int32Array(new SharedArrayBuffer(4));
  let inspected = containerState(name);
  let inspectionFailures = inspected.state === "unknown" ? 1 : 0;
  for (
    let attempt = 0;
    attempt < attempts &&
    inspected.state !== "absent" &&
    inspectionFailures < INSPECTION_FAILURE_LIMIT;
    attempt++
  ) {
    try {
      execFileSync("docker", ["rm", "--force", name], { stdio: "ignore", timeout: 30_000 });
    } catch {
      /* `--rm` auto-removal may already be in progress; re-check below. */
    }
    inspected = containerState(name);
    inspectionFailures = inspected.state === "unknown" ? inspectionFailures + 1 : 0;
    if (inspected.state !== "absent") Atomics.wait(pause, 0, 0, 100);
  }
  if (inspected.state === "absent") {
    owned.delete(name);
    return true;
  }
  if (inspected.state === "unknown") {
    teardownFailure(
      `could not confirm container ${name} was removed: docker container inspect failed (${inspected.reason}); check it by hand: docker rm --force ${name}`,
    );
    return false;
  }
  owned.delete(name);
  const id = containerId(name);
  teardownFailure(
    `container ${name}${id ? ` (id ${id})` : ""} still exists after ${attempts} removal attempts; remove it by hand: docker rm --force ${name}`,
  );
  return false;
}

function removeDirectory(path) {
  rmSync(path, { recursive: true, force: true });
  ownedDirectories.delete(path);
}

/** Synchronous, so it is safe from `exit` and signal handlers. */
function releaseEverything() {
  for (const name of [...owned]) forceRemove(name);
  for (const path of [...ownedDirectories]) removeDirectory(path);
}

/** Owned child process groups (pgid = the detached leader's pid). */
const ownedGroups = new Set();
const GROUP_TERM_GRACE_MS = 10_000;
const GROUP_KILL_GRACE_MS = 5_000;

function groupAlive(pgid) {
  try {
    process.kill(-pgid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

function signalGroup(pgid, signal) {
  try {
    process.kill(-pgid, signal);
  } catch {
    /* already gone */
  }
}

/** `pid ppid pgid` for every process, from POSIX `ps`. Throws when `ps` fails. */
function processTable() {
  return execFileSync("ps", ["-A", "-o", "pid=,ppid=,pgid="], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 5_000,
  });
}

/**
 * `seeds` plus the group of every live descendant of any member of a group
 * already included, to a fixpoint. Membership of a group survives
 * reparenting, so a descendant orphaned in a known group is still found, and
 * so is anything it spawned.
 */
function expandGroups(table, seeds) {
  const children = new Map();
  const members = new Map();
  for (const row of table.split("\n")) {
    const [pid, ppid, pgid] = row.trim().split(/\s+/).map(Number);
    if (!pid) continue;
    if (!children.has(ppid)) children.set(ppid, []);
    children.get(ppid).push({ pid, pgid });
    if (!members.has(pgid)) members.set(pgid, []);
    members.get(pgid).push(pid);
  }
  const groups = new Set();
  const visited = new Set();
  const pending = [];
  const visit = (pid) => {
    if (visited.has(pid)) return;
    visited.add(pid);
    pending.push(pid);
  };
  const include = (pgid) => {
    if (groups.has(pgid)) return;
    groups.add(pgid);
    for (const member of members.get(pgid) ?? []) visit(member);
  };
  for (const pgid of seeds) include(pgid);
  while (pending.length) {
    for (const { pid, pgid } of children.get(pending.pop()) ?? []) {
      include(pgid);
      visit(pid);
    }
  }
  return { groups };
}

/** Environment variable naming the owned trees a process descends from,
 * `:`-separated, so a tree nested inside another stays visible to both owners. */
const OWNED_TREE_ENV = "WSSP_OWNED_PROCESS_TREE";

/**
 * Process groups of every live process whose initial environment carries
 * `marker` in `OWNED_TREE_ENV`, from /proc. Unlike ancestry, the
 * inherited environment survives the immediate reparenting of an orphan.
 * Linux only: undefined elsewhere. Throws when /proc cannot be listed.
 */
function markedGroups(marker) {
  if (process.platform !== "linux") return undefined;
  const prefix = `${OWNED_TREE_ENV}=`;
  const groups = new Set();
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    let environ;
    let stat;
    try {
      environ = readFileSync(`/proc/${entry}/environ`, "latin1");
      stat = readFileSync(`/proc/${entry}/stat`, "latin1");
    } catch {
      continue; // exited meanwhile, or another user's process (never ours)
    }
    const entryVar = environ.split("\0").find((variable) => variable.startsWith(prefix));
    if (!entryVar?.slice(prefix.length).split(":").includes(marker)) continue;
    // Fields after the parenthesised command: state ppid pgrp ...
    const pgid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[2]);
    if (pgid > 0) groups.add(pgid);
  }
  return groups;
}

/**
 * The process groups of an owned tree: the leader's, every group holding a
 * process that inherited the tree's marker environment, and every live
 * descendant's. A task runner may put its tasks in groups of their own (Turbo
 * does), so signalling only the leader's group would rely on the runner's own
 * shutdown, and once a group's creator exits the group is reparented out of
 * the tree at once. Needs POSIX `ps`, checked before any group is spawned; if
 * `ps` or /proc fails anyway at teardown, the groups still found are signalled
 * and the failure is reported loudly (the process exits non-zero), never
 * silently degraded.
 */
function treeGroups(group, reported = new Set()) {
  // Teardown rescans repeatedly; each kind of listing failure is reported once.
  const report = (kind, message) => {
    if (reported.has(kind)) return;
    reported.add(kind);
    teardownFailure(message);
  };
  const seeds = new Set([group.pgid]);
  try {
    for (const pgid of markedGroups(group.marker) ?? []) seeds.add(pgid);
  } catch (error) {
    report(
      "proc",
      `could not scan /proc for the processes of tree ${group.pgid} (${error instanceof Error ? error.message : error}); a descendant reparented out of the tree may survive`,
    );
  }
  let table;
  try {
    table = processTable();
  } catch (error) {
    report(
      "ps",
      `could not list the descendants of process group ${group.pgid} (ps -A -o pid=,ppid=,pgid= failed: ${error instanceof Error ? error.message : error}); only the groups already known were signalled, so a descendant in its own group may survive`,
    );
    return seeds;
  }
  return expandGroups(table, seeds).groups;
}

/**
 * Terminates one owned tree and returns true once it is gone. The tree is
 * rescanned until a scan finds nothing alive, because a process handling the
 * signal may create a new group (or orphan one) that no earlier scan held:
 * every group seen for the first time gets `signal`, and once the TERM grace
 * has passed every group still alive gets SIGKILL. Past the total bound the
 * survivors are reported loudly (the process exits non-zero) and it returns false.
 */
async function terminateGroup(group, signal = "SIGTERM") {
  const started = Date.now();
  const killAt = started + GROUP_TERM_GRACE_MS;
  const giveUpAt = killAt + GROUP_KILL_GRACE_MS;
  const reported = new Set();
  const signalled = new Map();
  let leaderAwaited = false;
  for (;;) {
    const alive = [...treeGroups(group, reported)].filter(groupAlive);
    if (alive.length === 0) return true;
    const now = Date.now();
    if (now >= giveUpAt) {
      teardownFailure(
        `process group(s) ${alive.join(", ")} of the tree led by ${group.pgid} survived SIGKILL for ${GROUP_KILL_GRACE_MS} ms; they may still be using a database that is about to be removed`,
      );
      return false;
    }
    const next = now >= killAt ? "SIGKILL" : signal;
    for (const pgid of alive) {
      if (signalled.get(pgid) === next || signalled.get(pgid) === "SIGKILL") continue;
      signalGroup(pgid, next);
      signalled.set(pgid, next);
    }
    if (!leaderAwaited) {
      leaderAwaited = true;
      // The leader must be reaped first (a zombie leader keeps its group "alive").
      // Unref'd: a settled race must not keep this process alive for the bound.
      await Promise.race([
        group.leaderExited,
        new Promise((resolveTimeout) => setTimeout(resolveTimeout, killAt - now).unref()),
      ]);
    } else {
      await delay(50);
    }
  }
}

/**
 * Spawns `file` as the leader of a new process group that this process owns.
 * `exited` resolves with the leader's exit code (1 for a signal or a spawn
 * error) only once the whole group is gone: a descendant that outlived the
 * leader is terminated first, so no process in the tree can still be using a
 * database when the caller tears it down. Signals reaching this process are
 * forwarded to the group by the shared handlers (the group is detached, so a
 * terminal's Ctrl-C no longer reaches it directly). POSIX only.
 */
export function spawnOwnedProcessGroup(file, args, options = {}) {
  try {
    processTable();
  } catch (error) {
    throw new Error(
      `spawnOwnedProcessGroup needs the POSIX ps command (ps -A -o pid=,ppid=,pgid=; procps on Linux) to terminate every process group a child tree creates, and it failed: ${error instanceof Error ? error.message : error}. Install ps and retry.`,
    );
  }
  installHandlers();
  const marker = randomUUID();
  const env = options.env ?? process.env;
  const child = spawn(file, args, {
    ...options,
    env: {
      ...env,
      [OWNED_TREE_ENV]: env[OWNED_TREE_ENV] ? `${env[OWNED_TREE_ENV]}:${marker}` : marker,
    },
    detached: true,
  });
  let leaderExit;
  const group = {
    pgid: child.pid,
    marker,
    leaderExited: new Promise((resolveExit) => {
      child.once("exit", (code, signal) => {
        leaderExit = signal ? 1 : (code ?? 1);
        resolveExit();
      });
      child.once("error", () => {
        leaderExit = 1;
        resolveExit();
      });
    }),
  };
  if (child.pid) ownedGroups.add(group);
  const exited = group.leaderExited.then(async () => {
    // A tree that could not be emptied stays owned, so the exit handler kills it again.
    if (child.pid && (await terminateGroup(group))) ownedGroups.delete(group);
    return leaderExit;
  });
  return { child, pgid: child.pid, exited };
}

/** `exit` cannot await: SIGKILL every owned group, then release synchronously.
 * Any teardown failure seen during the run forces a non-zero exit code, even
 * when the caller set `process.exitCode = 0` after the failure was reported. */
function releaseOnExit() {
  for (const group of ownedGroups)
    for (const pgid of treeGroups(group)) signalGroup(pgid, "SIGKILL");
  releaseEverything();
  if (teardownFailures.length > 0 && !process.exitCode) process.exitCode = 1;
}

let shuttingDown = false;
async function shutdownOnSignal(signal, code) {
  if (shuttingDown) return;
  shuttingDown = true;
  // Children first: nothing may still be using a database when it is removed.
  await Promise.all([...ownedGroups].map((group) => terminateGroup(group, signal)));
  releaseEverything();
  process.exit(code);
}

function installHandlers() {
  if (handlersInstalled) return;
  handlersInstalled = true;
  process.once("exit", releaseOnExit);
  for (const [signal, code] of [
    ["SIGINT", 130],
    ["SIGTERM", 143],
    ["SIGHUP", 129],
  ]) {
    // `on`, not `once`: a repeated signal during the bounded shutdown must not
    // fall through to Node's default (immediate death, leaking everything).
    process.on(signal, () => void shutdownOnSignal(signal, code));
  }
}

/**
 * A private temporary directory owned like a container: removed by `remove()`,
 * and by the exit/signal handlers when a signal ends the process before the
 * caller's own `finally` can run.
 */
export function disposableDirectory(prefix) {
  installHandlers();
  const path = mkdtempSync(resolve(tmpdir(), prefix));
  ownedDirectories.add(path);
  return { path, remove: () => removeDirectory(path) };
}

/** Undefined when `image` is present; otherwise the reason, naming the one pull entry. */
export function missingImageReason(image = POSTGRES_IMAGE) {
  try {
    docker(["image", "inspect", image, "--format", "{{.Id}}"]);
    return undefined;
  } catch {
    return `image ${image} is not present; run: pnpm test:pg:pull-image`;
  }
}

/** `{ ok: true }` when a Docker daemon answers; otherwise a one-line reason. */
export function dockerAvailability() {
  try {
    docker(["version", "--format", "{{.Server.Version}}"], 15_000);
  } catch (error) {
    const stderr = error?.stderr ? String(error.stderr).trim().split("\n").at(-1) : "";
    return { ok: false, reason: stderr || (error instanceof Error ? error.message : "unknown") };
  }
  const missing = missingImageReason();
  return missing ? { ok: false, reason: missing } : { ok: true };
}

/** PostgreSQL keeps `cluster_name` to NAMEDATALEN - 1 bytes and truncates a
 * longer one, after which the server can no longer prove it is its container
 * (test:pg's per-file drop compares the two). */
export const CLUSTER_NAME_MAX = 63;
const OWNER = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
export const MAX_OWNER = 16;
/** 16 hex digits: 64 random bits, unique enough for one machine's fixtures. */
const NAME_SUFFIX_HEX = 16;
// `<prefix>-<owner>-<suffix>`: the longest accepted prefix and owner still fit.
if (MAX_TEST_CONTAINER_PREFIX + 1 + MAX_OWNER + 1 + NAME_SUFFIX_HEX > CLUSTER_NAME_MAX)
  throw new Error("disposable PostgreSQL names can exceed the 63-byte cluster_name");

/**
 * The container name, `<prefix>-<owner>-<16 hex>` (TEST_CONTAINER_PREFIX
 * namespaces it, scripts/lib/test-container-prefix.mjs). The server sets its
 * `cluster_name` to it, so it is at most CLUSTER_NAME_MAX bytes.
 *
 * @param {string} owner
 * @param {NodeJS.ProcessEnv} [env]
 */
export function disposablePostgresName(owner, env = process.env) {
  if (!OWNER.test(owner) || owner.length > MAX_OWNER)
    throw new Error(
      `disposable PostgreSQL owner ${JSON.stringify(owner)} must be lowercase words joined by "-", at most ${MAX_OWNER} characters`,
    );
  return `${testContainerPrefix({ env })}-${owner}-${randomBytes(NAME_SUFFIX_HEX / 2).toString("hex")}`;
}

/**
 * Starts one disposable PostgreSQL 18 container and waits until it accepts TCP
 * connections on its loopback-published port.
 *
 * @param {{ owner: string, memory?: string, tmpfsSize?: string, durabilityOff?: boolean }} options
 */
export async function startDisposablePostgres(options) {
  installHandlers();
  // Fail fast with the pull command, before any container exists.
  const missing = missingImageReason();
  if (missing) throw new Error(`Disposable PostgreSQL unavailable: ${missing}`);
  const name = disposablePostgresName(options.owner);
  const password = randomUUID();
  // The password never rides argv (visible to every local user via /proc):
  // a 0600 env file in a private 0700 directory, removed right after
  // `docker run` has read it, and by the exit/signal handlers otherwise.
  const secrets = disposableDirectory("wssp-pg-env-");
  const envFile = resolve(secrets.path, "postgres.env");
  writeFileSync(envFile, `POSTGRES_PASSWORD=${password}\n`, { mode: 0o600 });
  const args = [
    "run",
    "--detach",
    "--rm",
    // Never fetch implicitly, even if the image vanished after the check above.
    "--pull=never",
    "--name",
    name,
    "--label",
    `${DISPOSABLE_LABEL}=${options.owner}`,
    ...(options.memory ? ["--memory", options.memory] : []),
    "--tmpfs",
    `/var/lib/postgresql:rw,size=${options.tmpfsSize ?? "256m"}`,
    "--publish",
    "127.0.0.1::5432",
    "--env-file",
    envFile,
    POSTGRES_IMAGE,
    // The server names itself after its container, so a client handed this
    // URL can prove which server it reached (test:pg's per-file drop does).
    "-c",
    `cluster_name=${name}`,
  ];
  // Disposable data only: durability is irrelevant, and turning it off keeps
  // CREATE DATABASE ... TEMPLATE and commit-heavy tests fast on small hosts.
  if (options.durabilityOff) {
    // The data directory is a small tmpfs: checkpoint often so WAL (default
    // max_wal_size 1 GB) cannot fill it during commit-heavy tests such as the
    // 1 GiB transfer round trip, which otherwise fails with ENOSPC.
    args.push(
      "-c",
      "fsync=off",
      "-c",
      "synchronous_commit=off",
      "-c",
      "full_page_writes=off",
      "-c",
      "max_wal_size=48MB",
      "-c",
      "min_wal_size=32MB",
    );
  }
  owned.add(name);
  try {
    try {
      docker(args);
    } finally {
      secrets.remove();
    }
    const port = docker(["port", name, "5432/tcp"]).split(":").at(-1);
    if (!/^\d+$/.test(port ?? "")) throw new Error(`unexpected published port: ${port}`);
    for (let attempt = 0; ; attempt++) {
      try {
        // -h 127.0.0.1: the entrypoint's init server listens on the socket only,
        // so TCP readiness means the final server is up.
        docker(["exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"]);
        break;
      } catch {
        if (attempt === 99) throw new Error("Disposable PostgreSQL did not become ready.");
        await delay(100);
      }
    }
    const url = (database = "postgres") =>
      `postgresql://postgres:${password}@127.0.0.1:${port}/${database}`;
    return {
      name,
      port,
      password,
      url,
      stop() {
        if (!owned.has(name)) return;
        try {
          docker(["stop", "--time", "5", name]);
        } catch {
          /* fall through to force removal */
        }
        if (!forceRemove(name))
          throw new Error(`Disposable PostgreSQL container ${name} could not be removed.`);
      },
    };
  } catch (error) {
    forceRemove(name);
    throw error;
  }
}

/**
 * Relocate the production migration closure so its module-relative ROOT and
 * Prisma config's ../../.env both resolve inside this disposable directory.
 * Only installed DB dependencies are linked; checkout environment and seed
 * sources never enter the fixture. Apply committed migrations once, then let
 * test:pg freeze the database for inexpensive per-file clones.
 */
export function canonicalApplyFixture(root, temporary, databaseUrl) {
  const prismaCwd = resolve(temporary, "packages/db");
  mkdirSync(prismaCwd, { recursive: true });
  mkdirSync(resolve(temporary, "scripts/lib"), { recursive: true });
  cpSync(resolve(root, "scripts/db"), resolve(temporary, "scripts/db"), { recursive: true });
  cpSync(
    resolve(root, "scripts/lib/bounded-child.mjs"),
    resolve(temporary, "scripts/lib/bounded-child.mjs"),
  );
  for (const name of ["package.json", "prisma.config.ts"])
    cpSync(resolve(root, "packages/db", name), resolve(prismaCwd, name));
  for (const name of ["schema", "migrations"])
    cpSync(resolve(root, "packages/db/prisma", name), resolve(prismaCwd, "prisma", name), {
      recursive: true,
    });
  symlinkSync(resolve(root, "packages/db/node_modules"), resolve(prismaCwd, "node_modules"), "dir");
  const env = {
    PATH: process.env.PATH,
    DATABASE_URL: databaseUrl,
    NODE_ENV: "production",
  };
  const runner = resolve(temporary, "scripts/db/migrate-runtime.mjs");
  return {
    env,
    prismaCwd,
    runner,
    apply() {
      return execFileSync(process.execPath, [runner, "apply"], {
        cwd: temporary,
        env,
        timeout: 180_000,
        stdio: "pipe",
      });
    },
  };
}

// `node scripts/lib/disposable-postgres.mjs pull` (`pnpm test:pg:pull-image`):
// the explicit, one place an image fetch happens, so CI cannot drift from the pin.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv[2] !== "pull") {
    console.error("usage: node scripts/lib/disposable-postgres.mjs pull");
    process.exit(2);
  }
  execFileSync("docker", ["pull", POSTGRES_IMAGE], { stdio: "inherit", timeout: 600_000 });
}
