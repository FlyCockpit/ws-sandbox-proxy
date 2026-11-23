/** Onboarding walk e2e: instance admin first run, invited node owner, node
 * enrolment, in a real browser (the `agent-browser` CLI) against a disposable
 * local stack. Owns only rp5-wsonbwalk-e2e Docker resources and its own
 * agent-browser sessions. No existing environment file is used: every variable
 * the server and Vite read is set here (a root `.env` key this script does not
 * set is blanked, which the env schemas read as unset). Secrets (passwords,
 * TOTP keys, verification and invitation links) stay in memory or reach
 * agent-browser on stdin, never argv, logs or the PASS/FAIL table.
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { existsSync, readFileSync, rmSync, statSync } from "node:fs";
import { mkdir, mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { parseEnvContents } from "../../packages/env/src/root-env.ts";

const root = resolve(import.meta.dirname, "../..");
const project = "rp5-wsonbwalk-e2e";
const mailContainer = `${project}-mail`;
// The disposable stack's database is `wssp`; a linked worktree's migration
// guard expects its own database name, so run this from a main checkout.
if (!existsSync(resolve(root, ".git")) || !statSync(resolve(root, ".git")).isDirectory())
  throw new Error("run test:e2e:onboarding from a main checkout, not a linked worktree");
// One run at a time on this machine: an atomic lock directory, taken before any
// resource check, owned and removed by this run only.
// Fixed path, not TMPDIR: every run on this machine (one Docker daemon) shares it.
const lockDir = `/tmp/${project}.lock`;
const lockPid = resolve(lockDir, "pid");
async function takeLock() {
  await mkdir(lockDir);
  await writeFile(lockPid, String(process.pid), { mode: 0o600 });
}
try {
  await takeLock();
} catch (error) {
  if (error.code !== "EEXIST") throw error;
  // A lock left by a run that no longer exists (killed, OOM) is reclaimed once.
  let holder = 0;
  try {
    holder = Number(readFileSync(lockPid, "utf8"));
  } catch {}
  let alive = true;
  try {
    process.kill(holder, 0);
  } catch (probe) {
    alive = !(holder > 0 && probe.code === "ESRCH");
  }
  if (alive)
    throw new Error(`another ${project} run holds ${lockDir} (remove it if no run is active)`);
  rmSync(lockDir, { recursive: true, force: true });
  await takeLock();
}
let lockHeld = true;
// An early failure (before cleanup is armed) still releases the lock.
process.on("exit", () => {
  if (lockHeld)
    try {
      rmSync(lockDir, { recursive: true, force: true });
    } catch {}
});
const mailImage =
  "axllent/mailpit@sha256:aef2aacc11f075ec0fb6874275ee4a421e688e11a96ebb296134d1735c7761ce";
const temporary = await mkdtemp(resolve(tmpdir(), `${project}-`));
const run_id = randomBytes(4).toString("hex");
const children = [];
const browserCommands = new Set();
const sessions = new Set();
const rows = [];
let composeStarted = false;
let mailId = null;
let mailCreateAttempted = false;
let cleanupTask;
let shuttingDown = false;
let activeStage = "setup";
const secret = () => randomBytes(32).toString("base64url");
const baseEnv = Object.fromEntries(
  [
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "TZ",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
  ]
    .filter((k) => process.env[k])
    .map((k) => [k, process.env[k]]),
);
baseEnv.CARGO_BUILD_JOBS = "4";
async function port() {
  const server = createServer();
  await new Promise((yes, no) => {
    server.once("error", no);
    server.listen(0, "127.0.0.1", yes);
  });
  const value = server.address().port;
  await new Promise((yes, no) => server.close((e) => (e ? no(e) : yes())));
  return value;
}
const [postgresPort, redisPort, serverPort, webPort, smtpPort, mailHttpPort] = await Promise.all([
  port(),
  port(),
  port(),
  port(),
  port(),
  port(),
]);
const origin = `http://localhost:${webPort}`;
const mailApi = `http://127.0.0.1:${mailHttpPort}/api/v1`;
const adminEmail = `admin-${run_id}@onb.test`;
const ownerEmail = `owner-${run_id}@onb.test`;
const env = {
  ...baseEnv,
  NODE_ENV: "development",
  DATABASE_URL: `postgresql://postgres:password@127.0.0.1:${postgresPort}/wssp`,
  REDIS_URL: `redis://127.0.0.1:${redisPort}`,
  DEV_POSTGRES_PORT: String(postgresPort),
  DEV_REDIS_PORT: String(redisPort),
  PORT: String(serverPort),
  SERVER_PORT: String(serverPort),
  VITE_DEV_PORT: String(webPort),
  VITE_DEV_SERVER_URL: `http://localhost:${serverPort}`,
  BETTER_AUTH_URL: origin,
  CORS_ORIGIN: origin,
  ADMIN_EMAILS: adminEmail,
  SMTP_HOST: "127.0.0.1",
  SMTP_PORT: String(smtpPort),
  SMTP_FROM: `noreply-${run_id}@onb.test`,
  BETTER_AUTH_SECRET: secret(),
  SANDBOX_REQUEST_HMAC_SECRET: randomBytes(32).toString("hex"),
  DATA_ENCRYPTION_KEY: randomBytes(32).toString("hex"),
  BACKUP_ENABLED: "false",
  MIGRATE_ON_START: "false",
  WORKER_MODE: "embedded",
  TRANSFER_SPOOL_DIR: resolve(temporary, "transfers"),
  IMAGE_RELAY_SPOOL_DIR: resolve(temporary, "image-relay"),
};
// Vite's config and the server load the repository's root `.env` for keys the
// process does not set (dotenv never overrides). Blank every such key so a
// developer's settings cannot leak into this stack; names only are printed.
const rootEnv = resolve(root, ".env");
if (existsSync(rootEnv)) {
  // The same parser the loaders use, so every key they would read is blanked.
  const keys = Object.keys(parseEnvContents(readFileSync(rootEnv, "utf8"))).filter(
    (key) => !(key in env),
  );
  for (const key of keys) env[key] = "";
  console.warn(
    `warning: a root .env exists; its keys not set by this script are blanked: ${keys.join(", ") || "(none)"}`,
  );
}
for (const key of [
  "DATABASE_URL",
  "REDIS_URL",
  "BETTER_AUTH_SECRET",
  "BETTER_AUTH_URL",
  "CORS_ORIGIN",
  "SANDBOX_REQUEST_HMAC_SECRET",
  "DATA_ENCRYPTION_KEY",
  "ADMIN_EMAILS",
  "SMTP_HOST",
  "SMTP_PORT",
  "SMTP_FROM",
  "PORT",
  "VITE_DEV_PORT",
  "VITE_DEV_SERVER_URL",
])
  assert.ok(env[key], `${key} must be set explicitly`);
const nodeDir = resolve(temporary, "node");
const nodeEnv = {
  ...baseEnv,
  WSSP_CONFIG_DIR: resolve(nodeDir, "config"),
  WSSP_DATA_DIR: resolve(nodeDir, "data"),
  XDG_CONFIG_HOME: resolve(nodeDir, "xdg-config"),
  XDG_DATA_HOME: resolve(nodeDir, "xdg-data"),
  // Debug builds read this stand-in for `/`: never the machine's own guard.
  WSSP_TEST_GUARD_ROOT: resolve(nodeDir, "guard-root"),
  WSSP_FAKE_ENFORCE_EGRESS: "1",
};
const wssp = resolve(root, "target/debug/wssp");
// The e2e's own Vite: no file watching (an edit elsewhere in the tree must not
// reload the page mid-test; HMR stays on for the dependency optimizer's own
// reloads) and its own dependency cache. The
// wrapper lives under apps/web/node_modules so the config's imports resolve.
const viteDir = resolve(root, "apps/web/node_modules/.cache", `${project}-${run_id}`);
const viteConfig = resolve(viteDir, "vite.e2e.config.mjs");

async function start(name, executable, args, childEnv = env, { cwd = root, stdout } = {}) {
  if (shuttingDown && !["compose-down", "mail-rm", "browser-close"].includes(name))
    throw new Error("run interrupted");
  const log = await open(resolve(temporary, `${name}.log`), "a", 0o600);
  // Cleanup may have taken its snapshot while the log opened: spawn nothing then.
  if (shuttingDown && !["compose-down", "mail-rm", "browser-close"].includes(name)) {
    await log.close();
    throw new Error("run interrupted");
  }
  const child = spawn("nice", ["-n", "10", executable, ...args], {
    cwd,
    env: childEnv,
    detached: true,
    stdio: ["ignore", stdout ? "pipe" : log.fd, log.fd],
  });
  await log.close();
  children.push(child);
  return child;
}
async function run(name, executable, args, childEnv = env, options = {}) {
  const { timeoutMs = 10 * 60_000, ...startOptions } = options;
  const child = await start(name, executable, args, childEnv, startOptions);
  let timedOut = false;
  let escalate;
  const timer = setTimeout(() => {
    timedOut = true;
    killGroup(child, "SIGTERM");
    // Escalate only while the group still exists; cancelled once it is gone.
    escalate = setTimeout(() => {
      if (groupAlive(child)) killGroup(child, "SIGKILL");
    }, 5000);
    escalate.unref();
  }, timeoutMs);
  const code = await new Promise((yes, no) => {
    child.once("error", no);
    child.once("exit", yes);
  }).finally(() => clearTimeout(timer));
  // A timed-out command's group: wait for it to drain before going on, so no
  // escalation outlives it (a group id is not reused while the group exists).
  if (timedOut) {
    for (let i = 0; i < 50 && groupAlive(child); i++) await sleep(100);
    if (groupAlive(child)) killGroup(child, "SIGKILL");
    clearTimeout(escalate);
  }
  if (timedOut) throw new Error(`${name} timed out after ${timeoutMs} ms`);
  if (code !== 0)
    throw new Error(`${name} exited ${code}; private diagnostics: ${temporary}/${name}.log`);
}
/** Whether any process of the child's group is alive (a group id is never reused while it exists). */
function groupAlive(child) {
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch {
    return false;
  }
}
function killGroup(child, signal) {
  try {
    process.kill(-child.pid, signal);
  } catch {}
}
/** Every HTTP probe is bounded, so a stalled server cannot outlive `until`'s deadline. */
const get = (url) => fetch(url, { signal: AbortSignal.timeout(10_000) });
async function until(work, label, timeout = 90000) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    try {
      const value = await work();
      if (value) return value;
    } catch (error) {
      last = error;
    }
    await sleep(1000);
  }
  throw new Error(`timeout: ${label}${last ? ` (${last.message.slice(0, 200)})` : ""}`);
}
async function stage(name, work) {
  activeStage = name;
  await work();
  rows.push([name, "PASS"]);
  console.log(`PASS ${name}`);
}
function totp(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of base32.replaceAll("=", "").toUpperCase())
    bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => Number.parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac("sha1", key).update(counter).digest();
  return String((h.readUInt32BE(h.at(-1) & 15) & 0x7fffffff) % 1000000).padStart(6, "0");
}

// --- browser (agent-browser CLI; one session per person) ---------------------
function abRaw(session, args, input) {
  // During shutdown only `close` may run: a late poll must not reopen a browser.
  if (shuttingDown && args[0] !== "close") return Promise.reject(new Error("run interrupted"));
  return new Promise((yes, no) => {
    const child = spawn("agent-browser", ["--session", session, ...args], {
      env: baseEnv,
      stdio: ["pipe", "pipe", "pipe"],
    });
    if (args[0] !== "close") browserCommands.add(child);
    let out = "";
    child.stdout.on("data", (d) => {
      out += d;
    });
    child.stderr.resume();
    const timer = setTimeout(() => child.kill("SIGKILL"), 120000);
    child.once("error", no);
    child.once("exit", () => {
      browserCommands.delete(child);
      clearTimeout(timer);
      yes(out);
    });
    child.stdin.end(input ?? "");
  });
}
function lastJson(out) {
  const lines = out
    .trim()
    .split("\n")
    .filter((l) => l.startsWith("{") || l.startsWith("["));
  if (!lines.length) throw new Error("agent-browser returned no JSON");
  return JSON.parse(lines.at(-1));
}
/** A non-secret command; errors carry only agent-browser's error text. */
async function ab(session, ...args) {
  sessions.add(session);
  const reply = lastJson(await abRaw(session, ["--json", ...args]));
  if (!reply.success) throw new Error(`browser ${args[0]}: ${String(reply.error).slice(0, 200)}`);
  return reply.data;
}
/** Commands carrying a secret: sent on stdin; the reply is never printed. */
async function abSecret(session, commands) {
  sessions.add(session);
  const reply = lastJson(
    await abRaw(session, ["batch", "--json", "--bail"], JSON.stringify(commands)),
  );
  const failed = Array.isArray(reply)
    ? reply.find((r) => !r.success)
    : reply.success
      ? null
      : reply;
  if (failed) {
    // The step may hold a secret (link or value): its error goes to a private
    // file, never to the thrown message.
    await writeFile(resolve(temporary, "browser-secret-step.log"), String(failed.error ?? ""), {
      mode: 0o600,
      flag: "a",
    });
    throw new Error(`browser batch step failed; private diagnostics: ${temporary}`);
  }
}
const evaluate = async (session, js) => (await ab(session, "eval", js)).result;
// A cold dev server may answer a first visit with a stale optimized chunk; the
// route error boundary then offers a reload. Reload and keep waiting.
const waitFor = (session, js, label, timeout = 90000) =>
  until(
    async () =>
      await evaluate(
        session,
        `(() => { if (/didn.t load/.test(document.body?.innerText ?? "")) { location.reload(); return false; } return (${js}); })()`,
      ),
    label,
    timeout,
  );
const visit = async (session, path) => {
  await ab(session, "open", `${origin}${path}`);
};
/** Clicks the last element matching `selector` whose trimmed text is `text` (the topmost overlay). */
const clickText = (session, selector, text, timeout = 90000) =>
  waitFor(
    session,
    `(() => { const el = [...document.querySelectorAll(${JSON.stringify(selector)})].filter((e) => e.textContent.trim().replaceAll("\u2019", "'") === ${JSON.stringify(text)} && !e.disabled).at(-1); if (!el) return false; el.click(); return true; })()`,
    `click ${text}`,
    timeout,
  );
const present = (selector) => `!!document.querySelector(${JSON.stringify(selector)})`;

/** Real sign-in through the form, paced inside the 3-per-10-second credential budget. */
async function signIn(session, email, password) {
  await visit(session, "/en-US/login");
  await waitFor(session, present('main input[type="email"]'), "login form");
  await sleep(4000);
  await abSecret(session, [
    ["fill", 'main input[type="email"]', email],
    ["fill", 'main input[type="password"]', password],
    ["click", 'main form button[type="submit"]'],
  ]);
}

// --- mail (Mailpit HTTP API) ---------------------------------------------------
async function mail(to, subject, after = 0) {
  return until(
    async () => {
      const list = await (await get(`${mailApi}/messages`)).json();
      const message = list.messages.find(
        (m) =>
          m.To.some((t) => t.Address === to) &&
          m.Subject === subject &&
          Date.parse(m.Created) > after,
      );
      if (!message) return null;
      return (await (await get(`${mailApi}/message/${message.ID}`)).json()).Text;
    },
    `mail "${subject}" to ${to.split("@")[0]}`,
    60000,
  );
}
const link = (text, pattern = /\( (http\S+) \)/) => {
  const found = text.match(pattern)?.[1];
  assert.ok(found, "mail carries a link");
  return found;
};

function cleanup() {
  cleanupTask ??= cleanupAll();
  return cleanupTask;
}
async function cleanupAll() {
  shuttingDown = true;
  const failures = [];
  // Stop browser commands still in flight before closing their sessions.
  for (const child of browserCommands) child.kill("SIGKILL");
  await Promise.race([
    Promise.all([...browserCommands].map((child) => new Promise((yes) => child.once("exit", yes)))),
    sleep(5000),
  ]);
  for (const session of sessions) await abRaw(session, ["close"]).catch(() => {});
  // The groups this run still owns: a leader still running, so its group id
  // has existed continuously. Every long-lived child leads its own group
  // (`nice` execs node, the daemon or vite), so there is no launcher whose
  // early exit could orphan a server. A group is dropped from `owned` the
  // first time any poll sees it gone, and is never signalled after that, so a
  // reused id is never targeted.
  let owned = children
    .filter((child) => child.pid && child.exitCode === null && child.signalCode === null)
    .toReversed();
  const remaining = () => {
    owned = owned.filter(groupAlive);
    return owned.length;
  };
  for (const child of owned) killGroup(child, "SIGTERM");
  for (let i = 0; i < 50 && remaining(); i++) await sleep(100);
  remaining();
  for (const child of owned) killGroup(child, "SIGKILL");
  for (let i = 0; i < 50 && remaining(); i++) await sleep(100);
  if (owned.length) failures.push("process groups");
  await rm(viteDir, { recursive: true, force: true }).catch(() => failures.push("vite config"));
  try {
    // Only the container this run created: by its id, or, when creation was
    // attempted but the id never recorded, by this run's exact label.
    if (!mailId && mailCreateAttempted)
      mailId =
        execFileSync(
          "docker",
          ["ps", "-aq", "--no-trunc", "--filter", `label=rp5-wsonbwalk-e2e.run=${run_id}`],
          { env: baseEnv, encoding: "utf8", timeout: 30_000 },
        )
          .trim()
          .split("\n")[0] || null;
    if (mailId)
      await run("mail-rm", "docker", ["rm", "-f", "-v", mailId], baseEnv, { timeoutMs: 120_000 });
  } catch {
    failures.push("mail container");
  }
  try {
    if (composeStarted)
      await run(
        "compose-down",
        "docker",
        [
          "compose",
          "-p",
          project,
          "-f",
          "docker-compose.dev.yml",
          "down",
          "-v",
          "--remove-orphans",
        ],
        env,
        { timeoutMs: 180_000 },
      );
  } catch {
    failures.push("compose project");
  }
  if (lockHeld) {
    await rm(lockDir, { recursive: true, force: true }).catch(() => failures.push("run lock"));
    lockHeld = false;
  }
  if (failures.length)
    throw new Error(`Cleanup failed for owned resources: ${failures.join(", ")}`);
}
// Every delivery runs the same (idempotent) cleanup; a second Ctrl-C or a
// closed terminal cannot cut it short.
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"])
  process.on(signal, () => {
    void cleanup().then(
      () => process.exit(signal === "SIGINT" ? 130 : 143),
      (error) => {
        console.error(error.message);
        process.exit(1);
      },
    );
  });

let browserVersion = "unknown";
let failure;
const admin = `${project}-admin-${run_id}`;
const owner = `${project}-owner-${run_id}`;
const adminPassword = secret();
let ownerTempPassword;
let ownerPassword;
try {
  await stage("agent-browser present", async () => {
    try {
      browserVersion = execFileSync("agent-browser", ["--version"], {
        env: baseEnv,
        encoding: "utf8",
      }).trim();
    } catch {
      throw new Error("agent-browser is not installed (it drives the browser steps)");
    }
  });
  await stage("Postgres 18 / Valkey 9 / Mailpit / migrations / server / Vite", async () => {
    // Project-specific reads: never adopt or tear down another run's resources.
    await run("project-unused", "sh", [
      "-c",
      // Containers, volumes and networks: nothing of this project may exist.
      // By label and by name prefix; any docker error fails the check (set -e).
      [
        "set -e",
        `c=$(docker compose -p ${project} -f docker-compose.dev.yml ps -aq)`,
        `v=$(docker volume ls -q --filter label=com.docker.compose.project=${project}; docker volume ls -q --filter name=^${project}_)`,
        `n=$(docker network ls -q --filter label=com.docker.compose.project=${project}; docker network ls -q --filter name=^${project}_)`,
        `m=$(docker ps -aq --filter name=^${mailContainer}$)`,
        'test -z "$c$v$n$m"',
      ].join("; "),
    ]);
    composeStarted = true;
    await run("compose-up", "docker", [
      "compose",
      "-p",
      project,
      "-f",
      "docker-compose.dev.yml",
      "up",
      "-d",
      "--wait",
    ]);
    // Create first and record the id, so a failed start is still cleaned up.
    mailCreateAttempted = true;
    await run(
      "mail-create",
      "docker",
      [
        "create",
        "--name",
        mailContainer,
        "--label",
        `rp5-wsonbwalk-e2e.run=${run_id}`,
        "-p",
        `127.0.0.1:${smtpPort}:1025`,
        "-p",
        `127.0.0.1:${mailHttpPort}:8025`,
        mailImage,
      ],
      baseEnv,
    );
    mailId =
      execFileSync(
        "docker",
        [
          "container",
          "inspect",
          "--format",
          `{{if eq (index .Config.Labels "rp5-wsonbwalk-e2e.run") "${run_id}"}}{{.Id}}{{end}}`,
          mailContainer,
        ],
        { env: baseEnv, encoding: "utf8", timeout: 30_000 },
      ).trim() || null;
    assert.ok(mailId, "the mail container is this run's");
    await run("mail-start", "docker", ["start", mailId], baseEnv, { timeoutMs: 120_000 });
    await until(async () => (await get(`${mailApi}/messages`)).ok, "mailpit", 30000);
    assert.match(env.DATABASE_URL, new RegExp(`@127\\.0\\.0\\.1:${postgresPort}/wssp$`));
    await run("migrate", "pnpm", ["db:migrate:apply"]);
    await start("server", process.execPath, ["--import", "tsx", "apps/server/src/index.ts"]);
    await until(async () => (await get(`http://localhost:${serverPort}/ready`)).ok, "server ready");
    await mkdir(viteDir, { recursive: true });
    await writeFile(
      viteConfig,
      [
        'import base from "../../../vite.config.ts";',
        "export default async (configEnv) => {",
        '  const config = typeof base === "function" ? await base(configEnv) : base;',
        "  return {",
        "    ...config,",
        `    cacheDir: ${JSON.stringify(resolve(viteDir, "vite"))},`,
        "    server: { ...config.server, watch: null },",
        "  };",
        "};",
        "",
      ].join("\n"),
    );
    // Vite itself leads its group (`nice` execs node): no launcher that could
    // exit early and leave the server behind.
    await start(
      "web",
      process.execPath,
      [
        resolve(root, "apps/web/node_modules/vite/bin/vite.js"),
        "--config",
        viteConfig,
        "--port",
        String(webPort),
        "--strictPort",
      ],
      env,
      { cwd: resolve(root, "apps/web") },
    );
    await until(async () => (await get(`${origin}/en-US`)).status < 500, "vite ready", 120000);
  });

  await stage("warm up the dev server's routes", async () => {
    const warm = `${project}-warm-${run_id}`;
    for (const route of ["/en-US", "/en-US/login", "/en-US/signup", "/en-US/verify-email"]) {
      await visit(warm, route);
      await waitFor(
        warm,
        `document.readyState === "complete" && !!document.querySelector("main")`,
        route,
      );
      await sleep(3000);
    }
  });
  await stage(
    "path 1: admin signs up (closed sign-up, ADMIN_EMAILS) and verifies by mail",
    async () => {
      await visit(admin, "/en-US/signup");
      await waitFor(admin, present("[data-signup-limited]"), "sign-up limited notice");
      await sleep(4000);
      const before = Date.now() - 1000;
      await abSecret(admin, [
        ["fill", 'main input[name="name"]', "E2E Admin"],
        ["fill", 'main input[name="email"]', adminEmail],
        ["fill", 'main input[name="password"]', adminPassword],
        ["click", 'main form button[type="submit"]'],
      ]);
      const verify = link(await mail(adminEmail, "Verify your email", before));
      await abSecret(admin, [["open", verify]]);
      await waitFor(admin, `location.pathname.endsWith("/verify-email")`, "verified page");
      await signIn(admin, adminEmail, adminPassword);
      await waitFor(admin, `location.pathname.endsWith("/dashboard/sandboxes")`, "signed in");
    },
  );
  await stage("path 1: the admin 2FA deadline shows in the app shell", async () => {
    await waitFor(admin, present('[data-two-factor-nudge="shell"]'), "shell 2FA nudge");
  });
  await stage("path 1: admin enrols TOTP in the browser", async () => {
    await visit(admin, "/en-US/settings/security");
    await clickText(admin, "button", "Enable Two-Factor Authentication");
    await waitFor(admin, present("#confirm-password"), "2FA password step");
    await sleep(4000);
    await abSecret(admin, [["fill", "#confirm-password", adminPassword]]);
    await clickText(admin, "button", "Continue");
    const key = await waitFor(
      admin,
      `(() => { for (const el of document.querySelectorAll("main *")) { const t = el.childElementCount === 0 ? el.textContent.trim() : ""; if (/^[A-Z2-7]{16,}$/.test(t)) return t; } return false; })()`,
      "TOTP setup key",
    );
    await clickText(admin, "button", "I've saved my backup codes");
    await waitFor(admin, present("#setup-verify-code"), "TOTP code step");
    await sleep(4000);
    await abSecret(admin, [["fill", "#setup-verify-code", totp(key)]]);
    await clickText(admin, "button", "Verify & Enable");
    await waitFor(
      admin,
      `[...document.querySelectorAll("button")].some((b) => b.textContent.trim() === "Disable Two-Factor Authentication")`,
      "2FA enabled",
    );
  });
  await stage("path 1: admin overview shows the deployment setup", async () => {
    await visit(admin, "/en-US/admin");
    await waitFor(admin, present("[data-deployment-setup]"), "deployment setup card");
    await waitFor(admin, present('[data-setup-row="email"][data-setup-state="ok"]'), "email ok");
    await waitFor(
      admin,
      present('[data-setup-row="data-key"][data-setup-state="ok"]'),
      "data key ok",
    );
    assert.ok(await evaluate(admin, present('[data-setup-row="image-store"]')));
    assert.ok(
      await evaluate(admin, present('[data-setup-row="backups"][data-setup-state="optional"]')),
    );
  });
  await stage("path 1: admin invites the node owner (temporary password)", async () => {
    await visit(admin, "/en-US/admin/users");
    await clickText(admin, "button", "Invite user");
    await waitFor(admin, present('[role="dialog"] input[name="email"]'), "invite form");
    await ab(admin, "fill", '[role="dialog"] input[name="name"]', "E2E Owner");
    await ab(admin, "fill", '[role="dialog"] input[name="email"]', ownerEmail);
    await clickText(admin, '[role="dialog"] button', "Send invite");
    ownerTempPassword = await waitFor(
      admin,
      `(() => { for (const el of document.querySelectorAll('[role="dialog"] *')) { const t = el.childElementCount === 0 ? el.textContent.trim() : ""; if (/^[A-Za-z0-9_-]{24,}$/.test(t)) return t; } return false; })()`,
      "temporary password",
    );
    await clickText(admin, '[role="dialog"] button', "I've saved the password");
  });
  await stage("path 1: admin creates a pool and shares it by email", async () => {
    await visit(admin, "/en-US/settings/pools");
    await clickText(admin, "button", "Create pool");
    await waitFor(admin, present('[role="dialog"] input[name="slug"]'), "pool form");
    await ab(admin, "fill", '[role="dialog"] input[name="slug"]', "e2e-pool");
    await ab(admin, "fill", '[role="dialog"] input[name="label"]', "E2E pool");
    await clickText(admin, '[role="dialog"] button', "Save");
    await waitFor(
      admin,
      `[...document.querySelectorAll("main h2")].some((h) => h.textContent.trim() === "E2E pool")`,
      "pool listed",
    );
    await clickText(admin, "button", "Manage sharing");
    await clickText(admin, "button", "Share or invite");
    await waitFor(admin, present('[role="dialog"] input[name="email"]'), "share form");
    await ab(admin, "fill", '[role="dialog"] input[name="email"]', ownerEmail);
    await clickText(admin, '[role="dialog"] button', "Save");
    // The one-time link is revealed in the Share dialog, whose description is
    // the inviter's forwarding warning.
    await waitFor(admin, present('[role="dialog"] [role="status"]'), "invitation link revealed");
    await clickText(admin, '[role="dialog"] button', "I've saved it");
  });

  await stage("path 2: invitee accepts the admin invitation, then chooses a password", async () => {
    // The temporary password alone is no mailbox proof: sign-in is refused.
    await signIn(owner, ownerEmail, ownerTempPassword);
    await waitFor(
      owner,
      `document.body.textContent.includes("Verify your email before signing in")`,
      "verification-specific refusal",
    );
    // Accepting the mailed invitation verifies the address (no second mail).
    const accept = link(await mail(ownerEmail, "You've been invited"));
    await abSecret(owner, [["open", accept]]);
    await waitFor(owner, `location.pathname.endsWith("/verify-email")`, "verified page");
    await signIn(owner, ownerEmail, ownerTempPassword);
    // Before anything else, the admin-known password is replaced.
    await waitFor(owner, present("[data-forced-password-change]"), "password change takeover");
    assert.equal(await evaluate(owner, present("[data-onboarding]")), false);
    ownerPassword = secret();
    await abSecret(owner, [
      ["fill", 'input[name="currentPassword"]', ownerTempPassword],
      ["fill", 'input[name="newPassword"]', ownerPassword],
      ["fill", 'input[name="confirmPassword"]', ownerPassword],
    ]);
    await clickText(owner, "[data-forced-password-change] button", "Change password");
    await waitFor(owner, `location.pathname.endsWith("/dashboard/sandboxes")`, "invitee signed in");
    await waitFor(owner, present("[data-onboarding]"), "onboarding checklist");
    assert.equal(await evaluate(owner, present("[data-forced-password-change]")), false);
  });
  await stage("path 2: invitee accepts the pool invitation", async () => {
    const invite = link(
      await mail(ownerEmail, "Pool sharing invitation"),
      /\( (http\S+\/invite#\S+) \)/,
    );
    await abSecret(owner, [["open", invite]]);
    await waitFor(owner, present("[data-pool-invite-page]"), "invitation page");
    assert.equal(await evaluate(owner, present("[data-pool-invite-missing]")), false);
    // The page names the pool (and the inviter) before acceptance.
    await waitFor(
      owner,
      `document.querySelector("[data-pool-invite-preview]")?.textContent.includes("E2E pool")`,
      "invitation preview",
    );
    await clickText(owner, "[data-pool-invite-page] button", "Accept pool invitation");
    await waitFor(owner, present("[data-pool-invite-accepted]"), "accepted");
    await ab(owner, "click", '[data-pool-invite-accepted] a[href*="tab=shared"]');
    await waitFor(
      owner,
      `location.search.includes("tab=shared") && [...document.querySelectorAll("main h2")].some((h) => h.textContent.trim() === "E2E pool")`,
      "shared pool listed",
    );
    // The secret lived only in memory: the page without it asks for the link.
    await visit(owner, "/en-US/settings/pools/invite");
    await waitFor(owner, present("[data-pool-invite-missing]"), "missing-secret status");
  });

  await stage("path 3: node enrols with a device code approved in the browser", async () => {
    await run(
      "cargo-build",
      "cargo",
      ["build", "-p", "wssp", "--bin", "wssp", "--locked"],
      baseEnv,
      { timeoutMs: 40 * 60_000 },
    );
    for (const dir of ["config", "data", "xdg-config", "xdg-data", "guard-root"])
      await mkdir(resolve(nodeDir, dir), { recursive: true, mode: 0o700 });
    const enroll = await start(
      "enroll",
      wssp,
      ["host", "enroll", "--slug", "e2e-node", "--server", origin],
      nodeEnv,
      { stdout: true },
    );
    let out = "";
    enroll.stdout.on("data", (d) => {
      out += d;
    });
    const exited = new Promise((yes) => enroll.once("exit", yes));
    const uri = await until(() => out.match(/verification URI: (\S+)/)?.[1], "device URI", 60000);
    await abSecret(owner, [["open", uri]]);
    await clickText(owner, "button", "Approve");
    const settled = new AbortController();
    const code = await Promise.race([
      exited,
      sleep(90000, "timeout", { signal: settled.signal }).catch(() => "aborted"),
    ]);
    settled.abort();
    assert.equal(code, 0, `enroll exit ${code}; private diagnostics: ${temporary}/enroll.log`);
    // Messages are fixed: the transcript holds the device code and is not printed.
    assert.ok(/device enrollment complete/.test(out), "enroll reports completion");
    assert.ok(
      /next: start the daemon with `wssp host run`/.test(out),
      "enroll names the next step",
    );
    assert.ok(/egress guard is not installed/.test(out), "enroll names the missing guard");
    const show = execFileSync(wssp, ["host", "config", "show"], { env: nodeEnv, encoding: "utf8" });
    assert.match(show, /guard = not ok/);
  });
  await stage("path 3: fake-runtime daemon connects; host listed Connected", async () => {
    await start("daemon", wssp, ["host", "run", "--runtime", "fake"], nodeEnv);
    await visit(owner, "/en-US/settings/hosts");
    await waitFor(
      owner,
      `[...document.querySelectorAll("main a")].some((a) => a.textContent.includes("e2e-node") && a.textContent.includes("Connected"))`,
      "host connected",
    );
  });
  await stage("path 3: owner contributes the host to the shared pool, named by slug", async () => {
    await visit(owner, "/en-US/settings/pools?tab=shared");
    await clickText(owner, "button", "Contribute a host");
    await waitFor(
      owner,
      `(() => { const label = [...document.querySelectorAll('[role="dialog"] label')].find((l) => l.textContent.includes("e2e-node")); const input = label?.querySelector("input") ?? (label?.htmlFor && document.getElementById(label.htmlFor)); if (!input) return false; input.click(); return true; })()`,
      "choose host",
    );
    await clickText(owner, '[role="dialog"] button', "Contribute a host");
    await waitFor(
      owner,
      `[...document.querySelectorAll("[data-contributed-host]")].some((e) => e.textContent.includes("(e2e-node)"))`,
      "contributed host named",
    );
  });
} catch (error) {
  failure = error;
  rows.push([activeStage, "FAIL"]);
  console.error(error.message);
  // Private diagnostics: what each person's page showed at the failure.
  for (const session of sessions)
    await abRaw(session, ["screenshot", resolve(temporary, `${session}.png`)]).catch(() => {});
} finally {
  try {
    await cleanup();
    rows.push(["cleanup", "PASS"]);
  } catch (error) {
    failure ??= error;
    rows.push(["cleanup", "FAIL"]);
    console.error(error.message);
  }
  console.log(`agent-browser: ${browserVersion}`);
  console.table(rows.map(([test, result]) => ({ test, result })));
  if (!failure) await rm(temporary, { recursive: true, force: true });
  else console.error(`Private diagnostics retained: ${temporary}`);
}
process.exitCode = failure ? 1 : 0;
