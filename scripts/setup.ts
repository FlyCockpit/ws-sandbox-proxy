/**
 * First-run onboarding script. Idempotent — safe to re-run.
 *
 * One command takes a fresh clone to a runnable state:
 *   1. Copy .env.example -> .env if .env does not exist.
 *   2. Copy apps/web/.env.example -> apps/web/.env if it does not exist.
 *   3. Generate server secrets if missing/empty in .env.
 *   4. Ask for the developer's email and write it to ADMIN_EMAILS in .env, so
 *      their first local sign-up becomes the first admin.
 *   5. Start the local Docker services — Postgres + Redis (`pnpm dev:services`,
 *      the canonical root docker-compose.dev.yml).
 *   6. Wait for Postgres and Redis to accept connections.
 *   7. Apply the schema (`pnpm db:worktree` then `pnpm db:migrate:apply`).
 *   8. Check whether the global portless CLI is available for `pnpm dev`.
 *   9. Install the Claude Code safety hooks into .claude/settings.json (see
 *      `pnpm claude:hooks:install`; harmless for other harnesses).
 *
 * After this, `pnpm dev` is the only remaining step.
 *
 * Run: `pnpm run setup` (the explicit `run` form — `setup` is also a pnpm
 * builtin, and on some pnpm versions the bare `pnpm setup` invokes the builtin
 * instead of this script)
 */

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { parseEnvContents } from "@wssp/env/root-env";

import { installClaudeHooks } from "./install-claude-hooks.js";
import { looksLikeEmail, readAdminEmailsValue, withAdminEmail } from "./lib/admin-email-env.js";

const ROOT = resolve(import.meta.dirname!, "..");
const ENV_PATH = resolve(ROOT, ".env");
const ENV_EXAMPLE_PATH = resolve(ROOT, ".env.example");
const WEB_ENV_PATH = resolve(ROOT, "apps/web/.env");
const WEB_ENV_EXAMPLE_PATH = resolve(ROOT, "apps/web/.env.example");

function log(msg: string) {
  console.log(`[setup] ${msg}`);
}

function fail(msg: string): never {
  console.error(`[setup] ERROR: ${msg}`);
  process.exit(1);
}

function run(command: string, args: string[]) {
  log(`running: ${command} ${args.join(" ")}`);
  const result = spawnSync(command, args, {
    cwd: ROOT,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  if (result.status !== 0) {
    fail(`command failed: ${command} ${args.join(" ")}`);
  }
}

function commandExists(command: string): boolean {
  const result = spawnSync(command, ["--version"], {
    cwd: ROOT,
    stdio: "ignore",
    shell: process.platform === "win32",
  });
  return result.status === 0;
}

function detectCrossPlatformPnpmHome(pnpmHome: string): string | null {
  const normalized = pnpmHome.replace(/\\/g, "/");
  if (process.platform === "linux" && normalized.startsWith("/Users/")) {
    return "macOS-style /Users path on Linux/WSL";
  }
  if (process.platform === "linux" && /^\/mnt\/[a-z]\/Users\//i.test(normalized)) {
    return "Windows home mounted into WSL";
  }
  if (process.platform === "darwin" && normalized.startsWith("/home/")) {
    return "Linux-style /home path on macOS";
  }
  if (process.platform !== "win32" && /^[A-Za-z]:\//.test(normalized)) {
    return "Windows drive path in a Unix-like shell";
  }
  return null;
}

function checkPnpmHome() {
  const pnpmHome = process.env.PNPM_HOME;
  if (!pnpmHome) return;

  const mismatch = detectCrossPlatformPnpmHome(pnpmHome);
  if (!mismatch) return;

  fail(
    `PNPM_HOME points at ${pnpmHome} (${mismatch}). ` +
      "Unset PNPM_HOME in this shell, then remove or fix the stale export in your shell profile. " +
      "On Linux/WSL, either leave PNPM_HOME unset or set it to $HOME/.local/share/pnpm.",
  );
}

// ---------------------------------------------------------------------------
// 1. Copy .env.example -> .env
// ---------------------------------------------------------------------------
function ensureEnvFile() {
  if (existsSync(ENV_PATH)) {
    log(".env already exists — leaving it alone");
    return;
  }
  if (!existsSync(ENV_EXAMPLE_PATH)) {
    fail(".env.example not found at repo root");
  }
  const template = readFileSync(ENV_EXAMPLE_PATH, "utf-8");
  writeFileSync(ENV_PATH, template, "utf-8");
  log("created .env from .env.example");
}

// ---------------------------------------------------------------------------
// 2. Copy apps/web/.env.example -> apps/web/.env
//
// apps/web/.env.example is all-optional (every VITE_ var is commented out),
// so copying it verbatim is a safe, runnable default. Without this file the
// web app still boots, but onboarding docs previously made this a manual step
// the user had to remember — fold it into `pnpm run setup` instead.
// ---------------------------------------------------------------------------
function ensureWebEnvFile() {
  if (existsSync(WEB_ENV_PATH)) {
    log("apps/web/.env already exists — leaving it alone");
    return;
  }
  if (!existsSync(WEB_ENV_EXAMPLE_PATH)) {
    fail("apps/web/.env.example not found");
  }
  const template = readFileSync(WEB_ENV_EXAMPLE_PATH, "utf-8");
  writeFileSync(WEB_ENV_PATH, template, "utf-8");
  log("created apps/web/.env from apps/web/.env.example");
}

// ---------------------------------------------------------------------------
// 3. Generate server secrets if missing/empty
// ---------------------------------------------------------------------------
function ensureServerSecret(
  key: "BETTER_AUTH_SECRET" | "SANDBOX_REQUEST_HMAC_SECRET",
  encoding: "base64" | "hex",
) {
  const contents = readFileSync(ENV_PATH, "utf-8");
  const lines = contents.split("\n");
  let touched = false;
  let foundLine = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    // Skip pure comment lines.
    if (line.trim().startsWith("#")) continue;
    const match = line.match(new RegExp(`^(\\s*)${key}\\s*=\\s*(.*?)\\s*$`));
    if (!match) continue;
    foundLine = true;
    const value = (match[2] ?? "").replace(/^["']|["']$/g, "");
    if (value.length > 0) {
      log(`${key} already set — leaving it alone`);
      return;
    }
    const secret = randomBytes(32).toString(encoding);
    lines[i] = `${match[1]}${key}=${secret}`;
    touched = true;
    log(`generated and wrote a new ${key}`);
    break;
  }

  if (!foundLine) {
    // Append it if the line was missing entirely.
    const secret = randomBytes(32).toString(encoding);
    lines.push(`${key}=${secret}`);
    touched = true;
    log(`${key} line was missing — appended a generated value`);
  }

  if (touched) {
    writeFileSync(ENV_PATH, lines.join("\n"), "utf-8");
  }
}

// ---------------------------------------------------------------------------
// 5. Ask for the developer's email -> ADMIN_EMAILS in .env
//
// This is the gap that leaves a fresh clone unable to sign in: SIGNUP_ENABLED
// defaults false and ADMIN_EMAILS defaults empty, so without this step the
// developer's first local sign-up fails with no admin ever bootstrapped
// (packages/env/src/server.ts prints a boot-time warning, but nobody watches
// server logs before they've signed up). Asking here, once, up front, is the
// same admin-bootstrap mechanism used in production (an ADMIN_EMAILS address
// signing up gets promoted by the Better-Auth database hook) — this step
// only fills in the value locally.
//
// Non-interactive use (CI, agents, scripted installs): pass
// `--admin-email <addr>` or set the ADMIN_EMAIL process env. Neither is a
// new app env var — ADMIN_EMAIL is read directly here, the same way
// checkPnpmHome() above reads PNPM_HOME, and only ever becomes the real
// ADMIN_EMAILS value written into .env.
// ---------------------------------------------------------------------------
function parseAdminEmailFlag(argv: string[]): string | null {
  const index = argv.indexOf("--admin-email");
  if (index === -1) return null;
  const value = argv[index + 1];
  return value && value.length > 0 ? value : null;
}

async function promptForAdminEmail(): Promise<string | null> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question(
      "Your email address. You'll sign up with it to become the first admin " +
        "(leave blank to skip): ",
    );
    const trimmed = answer.trim();
    return trimmed.length > 0 ? trimmed : null;
  } finally {
    rl.close();
  }
}

async function ensureAdminEmail() {
  const contents = readFileSync(ENV_PATH, "utf-8");
  if (readAdminEmailsValue(contents) !== null) {
    log("ADMIN_EMAILS is already set in .env — leaving it alone");
    return;
  }

  const flagEmail = parseAdminEmailFlag(process.argv.slice(2));
  const envEmail = process.env.ADMIN_EMAIL;
  let rawEmail: string | null;

  if (flagEmail) {
    rawEmail = flagEmail;
  } else if (envEmail) {
    rawEmail = envEmail;
  } else if (!process.stdin.isTTY) {
    log(
      "Skipping admin email setup (no interactive terminal). To finish: add " +
        "ADMIN_EMAILS=<your email> to .env yourself, or re-run " +
        "`pnpm run setup --admin-email <you@example.com>`.",
    );
    return;
  } else {
    rawEmail = await promptForAdminEmail();
    if (!rawEmail) {
      log(
        "Skipping admin email setup — add ADMIN_EMAILS=<your email> to .env " +
          "later, then restart the dev server, to sign up as the first admin.",
      );
      return;
    }
  }

  const normalized = rawEmail.trim().toLowerCase();
  if (!looksLikeEmail(normalized)) {
    log(
      `"${rawEmail.trim()}" doesn't look like an email address — skipping ADMIN_EMAILS setup. ` +
        "Add ADMIN_EMAILS=<your email> to .env yourself when ready.",
    );
    return;
  }

  writeFileSync(ENV_PATH, withAdminEmail(contents, normalized), "utf-8");
  log(
    `Wrote ADMIN_EMAILS=${normalized} to .env — sign up with that address to become the first admin.`,
  );
}

// ---------------------------------------------------------------------------
// 6. Start Docker services — Postgres + Redis
//
// Uses `pnpm dev:services` (root docker-compose.dev.yml), the canonical
// local-services command referenced everywhere else in the docs.
// Starting Redis here too means queue-backed features (BullMQ
// workers, rate limiting) work out of the box without a remembered extra
// step.
// ---------------------------------------------------------------------------
/** Mirror chosen local Compose ports into URLs without changing credentials or paths. */
export function localServiceConfiguration(
  contents: string,
  overrides: Record<string, string | undefined> = {},
): { contents: string; ports: Record<string, string> } {
  const parsed = parseEnvContents(contents);
  const entries: Record<string, string> = {};
  const ports: Record<string, string> = {};
  for (const [portKey, urlKey, defaultPort] of [
    ["DEV_POSTGRES_PORT", "DATABASE_URL", "5432"],
    ["DEV_REDIS_PORT", "REDIS_URL", "6379"],
  ] as const) {
    const rawUrl = overrides[urlKey] || parsed[urlKey];
    if (!rawUrl) throw new Error(`${urlKey} must be configured before starting local services.`);
    if (/[\r\n\0]/.test(rawUrl)) throw new Error(`${urlKey} must be a single-line local URL.`);
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      throw new Error(`${urlKey} must be a valid local URL.`);
    }
    if (!["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
      throw new Error(`${urlKey} must use a loopback host for local setup.`);
    }
    const port = overrides[portKey] || parsed[portKey] || url.port || defaultPort;
    if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
      throw new Error(`${portKey} must be an integer from 1 to 65535.`);
    }
    ports[portKey] = String(Number(port));
    url.port = ports[portKey];
    entries[urlKey] = url.toString();
    entries[portKey] = ports[portKey];
  }
  const remaining = new Set(Object.keys(entries));
  const lines: string[] = [];
  for (const line of contents.split("\n")) {
    const key = /^\s*(?:export\s+)?([A-Z_]+)\s*=/.exec(line)?.[1];
    if (!key || !(key in entries)) {
      lines.push(line);
    } else if (remaining.delete(key)) {
      lines.push(`${key}='${entries[key]!.replaceAll("'", "%27")}'`);
    }
  }
  for (const key of remaining) lines.push(`${key}='${entries[key]!.replaceAll("'", "%27")}'`);
  return { contents: `${lines.join("\n").replace(/\n*$/, "")}\n`, ports };
}

function configureLocalServices() {
  const configured = localServiceConfiguration(readFileSync(ENV_PATH, "utf8"), process.env);
  writeFileSync(ENV_PATH, configured.contents, "utf8");
  Object.assign(process.env, configured.ports);
  const parsed = parseEnvContents(configured.contents);
  process.env.DATABASE_URL = parsed.DATABASE_URL;
  process.env.REDIS_URL = parsed.REDIS_URL;
  // The exact local guard uses the same selected Postgres port.
  process.env.EXPECTED_PORT = configured.ports.DEV_POSTGRES_PORT;
}

function startDocker() {
  run("pnpm", ["dev:services"]);
}

// ---------------------------------------------------------------------------
// 7. Wait for Postgres + Redis
// ---------------------------------------------------------------------------
function parseEnvUrl(varName: string, defaultPort: number): { host: string; port: number } | null {
  const value = process.env[varName] || parseEnvContents(readFileSync(ENV_PATH, "utf8"))[varName];
  if (!value) return null;
  try {
    const url = new URL(value);
    return { host: url.hostname, port: url.port ? Number(url.port) : defaultPort };
  } catch {
    return null;
  }
}

function tcpProbe(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolveProbe) => {
    const socket = connect({ host, port });
    let done = false;
    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolveProbe(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}

async function waitForService(
  label: string,
  envVar: string,
  defaultPort: number,
  containerHint: string,
) {
  const target = parseEnvUrl(envVar, defaultPort);
  if (!target) {
    log(`could not parse ${envVar} — skipping ${label} readiness wait`);
    return;
  }
  log(`waiting for ${label} at ${target.host}:${target.port} (up to 30s)`);
  const deadline = Date.now() + 30_000;
  let attempt = 0;
  while (Date.now() < deadline) {
    attempt++;
    const ok = await tcpProbe(target.host, target.port, 1500);
    if (ok) {
      log(`${label} is accepting connections (after ${attempt} attempt(s))`);
      return;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  fail(
    `${label} did not become ready within 30s at ${target.host}:${target.port}. ` +
      `Check Docker is running and \`docker ps\` shows the ${containerHint} container.`,
  );
}

// ---------------------------------------------------------------------------
// 8. Apply schema
// ---------------------------------------------------------------------------
function runMigrations() {
  run("pnpm", ["db:worktree"]);
  delete process.env.DATABASE_URL;
  run("pnpm", ["db:migrate:apply"]);
}

// ---------------------------------------------------------------------------
// 9. Check global portless CLI
// ---------------------------------------------------------------------------
function checkPortless() {
  if (commandExists("portless")) {
    log("portless is available — `pnpm dev` will use https://wssp.localhost");
    return;
  }
  log(
    "portless is not installed. Install it globally with `npm install -g portless` " +
      "before running `pnpm dev`, or use `pnpm dev:raw` as the manual-port fallback.",
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  log("starting first-run setup");
  checkPnpmHome();
  ensureEnvFile();
  ensureWebEnvFile();
  ensureServerSecret("BETTER_AUTH_SECRET", "base64");
  ensureServerSecret("SANDBOX_REQUEST_HMAC_SECRET", "hex");
  await ensureAdminEmail();
  configureLocalServices();
  startDocker();
  await waitForService("Postgres", "DATABASE_URL", 5432, "postgres");
  await waitForService("Redis", "REDIS_URL", 6379, "redis");
  runMigrations();
  checkPortless();
  installClaudeHooks();
  log("Ready. Run `pnpm dev` to start.");
}

if (process.argv[1] === fileURLToPath(import.meta.url))
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
