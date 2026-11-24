/** Real local MCP qualification. Owns only rp5-fuwssp-e2e Docker resources.
 * No existing environment file is read by this harness. Secrets stay in memory
 * or mode-0600 temporary logs, never in argv or the PASS/FAIL table.
 */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, open, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import pg from "pg";

const root = resolve(import.meta.dirname, "../..");
const project = "rp5-fuwssp-e2e";
const temporary = await mkdtemp(resolve(tmpdir(), `${project}-`));
const children = [];
const userUnits = new Set();
const clients = [];
const rows = [];
let database;
let composeStarted = false;
let cleanupTask;
let shuttingDown = false;
let activeStage = "setup";
const secret = () => randomBytes(32).toString("base64url");
const baseEnv = Object.fromEntries(
  ["PATH", "USER", "LOGNAME", "LANG", "TZ", "TMPDIR", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]
    .filter((k) => process.env[k])
    .map((k) => [k, process.env[k]]),
);
baseEnv.CARGO_BUILD_JOBS = "6";
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
const [postgresPort, redisPort, serverPort] = await Promise.all([port(), port(), port()]);
const origin = `http://127.0.0.1:${serverPort}`;
const env = {
  ...baseEnv,
  NODE_ENV: "development",
  DATABASE_URL: `postgresql://postgres:password@127.0.0.1:${postgresPort}/wssp`,
  REDIS_URL: `redis://127.0.0.1:${redisPort}`,
  DEV_POSTGRES_PORT: String(postgresPort),
  DEV_REDIS_PORT: String(redisPort),
  SERVER_PORT: String(serverPort),
  BETTER_AUTH_URL: origin,
  CORS_ORIGIN: origin,
  SIGNUP_ENABLED: "true",
  MCP_ENABLED: "true",
  BETTER_AUTH_SECRET: secret(),
  SANDBOX_REQUEST_HMAC_SECRET: randomBytes(32).toString("hex"),
  BACKUP_ENABLED: "false",
  IMAGE_DISTRIBUTION: "off",
  MIGRATE_ON_START: "false",
  WORKER_MODE: "embedded",
  TRANSFER_SPOOL_DIR: resolve(temporary, "transfers"),
  IMAGE_RELAY_SPOOL_DIR: resolve(temporary, "image-relay"),
};
async function start(name, executable, args, childEnv = env, stdin = "ignore") {
  if (shuttingDown && name !== "compose-down" && name !== "scope-cleanup")
    throw new Error("run interrupted");
  const log = await open(resolve(temporary, `${name}.log`), "a", 0o600);
  const child = spawn("nice", ["-n", "10", executable, ...args], {
    cwd: root,
    env: childEnv,
    detached: true,
    stdio: [stdin, log.fd, log.fd],
  });
  await log.close();
  children.push(child);
  return child;
}
async function run(name, executable, args, childEnv = env, input) {
  const child = await start(
    name,
    executable,
    args,
    childEnv,
    input === undefined ? "ignore" : "pipe",
  );
  if (input !== undefined) child.stdin.end(input);
  const code = await new Promise((yes, no) => {
    child.once("error", no);
    child.once("exit", yes);
  });
  if (code !== 0)
    throw new Error(`${name} exited ${code}; private diagnostics: ${temporary}/${name}.log`);
}
async function until(work, label, timeout = 60000) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    try {
      const value = await work();
      if (value) return value;
    } catch (error) {
      last = error;
    }
    await sleep(1500);
  }
  throw new Error(`timeout: ${label}${last ? ` (${last.message})` : ""}`);
}
async function stage(name, work) {
  activeStage = name;
  await work();
  rows.push([name, "PASS"]);
  console.log(`PASS ${name}`);
}
function totp(uri) {
  const text = new URL(uri).searchParams.get("secret");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of text.replaceAll("=", "").toUpperCase())
    bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => Number.parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac("sha1", key).update(counter).digest();
  return String((h.readUInt32BE(h.at(-1) & 15) & 0x7fffffff) % 1000000).padStart(6, "0");
}
function person() {
  const cookies = new Map();
  return {
    cookies,
    async request(path, body, { method = "POST", form = false } = {}) {
      const response = await fetch(origin + path, {
        method,
        redirect: "manual",
        headers: {
          origin,
          cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; "),
          "x-csrf-token": "orpc",
          ...(method === "POST"
            ? { "content-type": form ? "application/x-www-form-urlencoded" : "application/json" }
            : {}),
        },
        ...(method === "POST"
          ? { body: form ? new URLSearchParams(body) : JSON.stringify(body) }
          : {}),
      });
      for (const cookie of response.headers.getSetCookie()) {
        const [pair] = cookie.split(";");
        const split = pair.indexOf("=");
        cookies.set(pair.slice(0, split), pair.slice(split + 1));
      }
      return response;
    },
    async auth(path, body) {
      await sleep(4000); // Stay inside the real 3-per-10-second credential burst budget.
      const r = await this.request(`/api/auth/${path}`, body);
      if (!r.ok) {
        const b = await r.json().catch(() => ({}));
        throw new Error(`auth ${path} HTTP ${r.status}: ${b.code ?? b.error ?? "unknown"}`);
      }
      return r.json();
    },
    async rpc(path, input = {}) {
      const r = await this.request(`/rpc/${path}`, { json: input });
      const b = await r.json();
      if (!r.ok)
        throw new Error(
          `rpc ${path} HTTP ${r.status}: ${b.json?.data?.code ?? b.json?.code ?? "unknown"}`,
        );
      return b.json;
    },
  };
}
async function signup(label) {
  const p = person();
  const password = secret();
  const email = `${label}-${randomBytes(5).toString("hex")}@example.test`;
  // Sign-up answers every address with the same neutral body, so the id comes
  // from the row it created.
  await p.auth("sign-up/email", { name: label, email, password });
  // Test-only mail delivery affordance: this exact disposable DB, no auth gate
  // is changed. The real login and TOTP enrollment still run over HTTP.
  const verified = await database.query(
    'UPDATE "user" SET "emailVerified" = true WHERE email = $1 RETURNING id',
    [email],
  );
  await p.auth("sign-in/email", { email, password });
  const enrollment = await p.auth("two-factor/enable", { password });
  await p.auth("two-factor/verify-totp", { code: totp(enrollment.totpURI) });
  p.id = verified.rows[0].id;
  p.email = email;
  return p;
}
async function mcp(token) {
  const client = new Client(
    { name: project, version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  clients.push(client);
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), {
      requestInit: { headers: { authorization: `Bearer ${token}` } },
    }),
  );
  return client;
}
async function call(client, name, args = {}) {
  const result = await client.callTool({ name, arguments: args });
  if (result.isError)
    throw new Error(`${name}: ${result.structuredContent?.error?.code ?? "tool_error"}`);
  return result.structuredContent.result;
}
function cleanup() {
  cleanupTask ??= cleanupAll();
  return cleanupTask;
}
async function cleanupAll() {
  shuttingDown = true;
  for (const client of clients) await client.close().catch(() => {});
  for (const child of children.toReversed()) {
    if (child.exitCode !== null || child.signalCode !== null) continue;
    try {
      process.kill(-child.pid, "SIGTERM");
    } catch {}
    await Promise.race([new Promise((yes) => child.once("exit", yes)), sleep(5000)]);
    if (child.exitCode === null && child.signalCode === null) {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
    }
  }
  const failures = [];
  for (const unit of userUnits) {
    try {
      const state = execFileSync(
        "nice",
        ["-n", "10", "systemctl", "--user", "show", unit, "--property=LoadState", "--value"],
        { env: baseEnv, encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "pipe"] },
      ).trim();
      if (state !== "not-found")
        await run("scope-cleanup", "systemctl", ["--user", "stop", unit], baseEnv);
    } catch {
      failures.push(unit);
    }
  }
  try {
    if (database) await database.end();
  } catch {
    failures.push("database client");
  }
  try {
    if (composeStarted)
      await run("compose-down", "docker", [
        "compose",
        "-p",
        project,
        "-f",
        "docker-compose.dev.yml",
        "down",
        "-v",
        "--remove-orphans",
      ]);
  } catch {
    failures.push("compose project");
  }
  if (failures.length)
    throw new Error(`Cleanup failed for owned resources: ${failures.join(", ")}`);
}
for (const signal of ["SIGINT", "SIGTERM"])
  process.once(signal, () => {
    void cleanup().then(
      () => process.exit(signal === "SIGINT" ? 130 : 143),
      (error) => {
        console.error(error.message);
        process.exit(1);
      },
    );
  });
let failure;
try {
  await stage("Postgres 18 / Valkey 9 / migrations / server", async () => {
    // A project-specific read prevents adopting or tearing down another run.
    await run("project-unused", "sh", [
      "-c",
      'test -z "$(docker compose -p rp5-fuwssp-e2e -f docker-compose.dev.yml ps -aq)"',
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
    await run("migrate", "pnpm", ["db:migrate:apply"]);
    database = new pg.Pool({ connectionString: env.DATABASE_URL });
    await start("server", process.execPath, ["--import", "tsx", "apps/server/src/index.ts"]);
    await until(async () => (await fetch(`${origin}/ready`)).ok, "server ready");
  });
  let a, b;
  await stage("two verified people / real TOTP enrollment", async () => {
    a = await signup("A");
    b = await signup("B");
  });
  let hostA, hostB, daemonAEnv, daemonBEnv, template, tokenA, tokenB, clientA, clientB;
  const maskSecret = secret();
  const nodeEnv = async (label, token) => {
    const config = resolve(temporary, label, "config"),
      data = resolve(temporary, label, "data");
    await mkdir(config, { recursive: true });
    await mkdir(data, { recursive: true });
    return {
      ...baseEnv,
      XDG_CONFIG_HOME: config,
      XDG_DATA_HOME: data,
      WSSP_CONFIG_DIR: config,
      WSSP_DATA_DIR: data,
      WSSP_E2E_HOST_TOKEN: token,
      WSSP_FAKE_ENFORCE_EGRESS: "1",
      E2E_API_TOKEN: maskSecret,
    };
  };
  const nodeConfig = async (label, nodeEnvironment, args, raise = false) => {
    if (raise) {
      // A local person terminal must be outside every daemon's cgroup. Keep
      // the real ancestry/TTY guard and collect the temporary user service.
      const unit = `${project}-${label}-${randomBytes(4).toString("hex")}.service`;
      userUnits.add(unit);
      await run(
        label,
        "systemd-run",
        [
          "--user",
          "--quiet",
          "--wait",
          "--pipe",
          "--collect",
          "--service-type=exec",
          `--setenv=WSSP_CONFIG_DIR=${nodeEnvironment.WSSP_CONFIG_DIR}`,
          `--setenv=WSSP_DATA_DIR=${nodeEnvironment.WSSP_DATA_DIR}`,
          "--unit",
          unit,
          "--",
          "script",
          "-qec",
          [resolve(root, "target/debug/wssp"), "host", "config", ...args]
            .map((x) => "'" + x.replaceAll("'", "'\\''") + "'")
            .join(" "),
          "/dev/null",
        ],
        nodeEnvironment,
        "on\n",
      );
    } else
      await run(
        label,
        resolve(root, "target/debug/wssp"),
        ["host", "config", ...args],
        nodeEnvironment,
      );
  };
  await stage("two enrolled fake-runtime daemons / shared pool", async () => {
    await run("cargo-build", "cargo", ["build", "-p", "wssp", "--bin", "wssp", "--locked"]);
    hostA = await a.rpc("sandboxHosts/createHost", { slug: "node-a", label: "Node A" });
    hostB = await b.rpc("sandboxHosts/createHost", { slug: "node-b", label: "Node B" });
    const enrollmentA = await a.rpc("sandboxHosts/createHostToken", {
      hostId: hostA.id,
      name: "e2e",
    });
    const enrollmentB = await b.rpc("sandboxHosts/createHostToken", {
      hostId: hostB.id,
      name: "e2e",
    });
    daemonAEnv = await nodeEnv("node-a", enrollmentA.secret);
    daemonBEnv = await nodeEnv("node-b", enrollmentB.secret);
    for (const [host, environment, label] of [
      [hostA, daemonAEnv, "daemon-a"],
      [hostB, daemonBEnv, "daemon-b"],
    ])
      await start(
        label,
        resolve(root, "target/debug/wssp"),
        [
          "host",
          "run",
          "--runtime",
          "fake",
          "--server",
          origin,
          "--host-id",
          host.id,
          "--host-token-env",
          "WSSP_E2E_HOST_TOKEN",
        ],
        environment,
      );
    await until(
      async () => (await a.rpc("sandboxHosts/getHost", { id: hostA.id })).status === "CONNECTED",
      "A connected",
    );
    await until(
      async () => (await b.rpc("sandboxHosts/getHost", { id: hostB.id })).status === "CONNECTED",
      "B connected",
    );
    const pool = await b.rpc("sandboxPools/create", { slug: "shared", label: "Shared" });
    await b.rpc("sandboxPools/grantShare", {
      poolId: pool.id,
      email: a.email,
      canUse: true,
      canContribute: true,
    });
    await a.rpc("sandboxPools/contributeHost", { poolId: pool.id, sandboxHostId: hostA.id });
    template = await a.rpc("sandboxTemplates/createTemplate", {
      hostId: hostA.id,
      slug: "fake",
      label: "Fake",
      imageRef: "fake:base",
    });
  });
  const toolScopes = {
    sandbox_list: ["sandboxes:read"],
    sandbox_get: ["sandboxes:read"],
    sandbox_wait_ready: ["sandboxes:read"],
    sandbox_create: ["sandboxes:create"],
    sandbox_stop: ["sandboxes:manage"],
    sandbox_destroy: ["sandboxes:destroy"],
    command_run: ["commands:execute", "commands:read", "operations:read"],
    command_start: ["commands:execute"],
    command_output: ["commands:read", "operations:read"],
    command_stdin: ["commands:execute"],
    command_cancel: ["operations:cancel", "commands:execute"],
    file_read: ["files:read"],
    file_list: ["files:read"],
    file_write: ["files:write"],
    host_list: ["hosts:read"],
    host_get: ["hosts:read"],
    host_command_run: ["hosts:execute"],
    host_command_get: ["hosts:execute"],
    host_command_cancel: ["hosts:execute"],
    host_command_queue: ["hosts:execute"],
    host_file_read: ["hosts:files"],
    host_file_list: ["hosts:files"],
    host_file_write: ["hosts:files"],
    host_file_edit: ["hosts:files"],
  };
  const allScopes = [
    "hosts:read",
    "hosts:execute",
    "hosts:files",
    "pools:read",
    "templates:read",
    "templates:write",
    "templates:build",
    "sandboxes:read",
    "sandboxes:create",
    "sandboxes:manage",
    "sandboxes:destroy",
    "commands:read",
    "commands:execute",
    "files:read",
    "files:write",
    "operations:read",
    "operations:cancel",
    "webhooks:write",
    "credentials:read",
    "credentials:write",
    "credentials:use",
  ];
  const checkTools = async (client, scopes) => {
    assert.deepEqual(
      (await client.listTools()).tools.map((t) => t.name).sort(),
      Object.entries(toolScopes)
        .filter(([, required]) => required.every((s) => scopes.includes(s)))
        .map(([name]) => name)
        .sort(),
    );
  };
  await stage("OAuth DCR / PKCE / limited consent / exact tool visibility", async () => {
    const limited = [
      "sandboxes:read",
      "sandboxes:create",
      "commands:execute",
      "commands:read",
      "operations:read",
    ];
    const requested = [...limited, "hosts:execute", "offline_access"];
    const callback = `${origin}/e2e-callback`;
    const registered = await person().auth("oauth2/register", {
      client_name: project,
      application_type: "native",
      resources: [`${origin}/mcp`],
      redirect_uris: [callback],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: requested.join(" "),
    });
    const verifier = secret();
    const query = new URLSearchParams({
      response_type: "code",
      client_id: registered.client_id,
      redirect_uri: callback,
      scope: requested.join(" "),
      resource: `${origin}/mcp`,
      code_challenge_method: "S256",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      state: secret(),
    });
    const authorization = await a.request(`/api/auth/oauth2/authorize?${query}`, undefined, {
      method: "GET",
    });
    let consentUrl;
    if (authorization.status === 302) consentUrl = authorization.headers.get("location");
    else {
      assert.equal(authorization.status, 200);
      const handoff = await authorization.json();
      assert.equal(handoff.redirect, true);
      consentUrl = handoff.url;
    }
    const consent = new URL(consentUrl, origin);
    assert.equal(consent.pathname, "/en-US/mcp-consent");
    const approved = await a.auth("oauth2/consent", {
      accept: true,
      oauth_query: consent.search.slice(1),
      scope: limited.join(" "),
      resourceMode: "ALL_OWNED",
      poolMode: "ALL_USABLE",
      ownSandboxesOnly: true,
      hostIds: [],
      templateRevisionIds: [],
      poolIds: [],
      credentialIds: [],
    });
    const code = new URL(approved.url).searchParams.get("code");
    assert.ok(code);
    const exchange = await a.request(
      "/api/auth/oauth2/token",
      {
        grant_type: "authorization_code",
        client_id: registered.client_id,
        code,
        code_verifier: verifier,
        redirect_uri: callback,
        resource: `${origin}/mcp`,
      },
      { form: true },
    );
    assert.equal(exchange.status, 200);
    const access = await exchange.json();
    const client = await mcp(access.access_token);
    await checkTools(client, limited);
    await assert.rejects(
      client.callTool({
        name: "host_command_run",
        arguments: { hostId: hostA.id, script: "true" },
      }),
      /Tool host_command_run not found/,
    );
  });
  await stage("person-minted agent tokens / exact tool visibility", async () => {
    const input = {
      name: "Full agent",
      scopes: allScopes,
      resourceMode: "ALL_OWNED",
      ownSandboxesOnly: true,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    };
    tokenA = await a.rpc("agentTokens/create", input);
    tokenB = await b.rpc("agentTokens/create", input);
    clientA = await mcp(tokenA.secret);
    clientB = await mcp(tokenB.secret);
    await checkTools(clientA, allScopes);
    await checkTools(clientB, allScopes);
  });
  await stage("MCP fake sandbox create / ready / command / files / stop / destroy", async () => {
    const created = await call(clientA, "sandbox_create", {
      sandboxHostId: hostA.id,
      template: `revision/${template.firstRevisionId}`,
      egress: { mode: "allowlist", domains: [], cidrs: [] },
      guestSudo: false,
    });
    const operation = await until(async () => {
      const r = await a.rpc("sandboxes/getOperation", { operationId: created.operationId });
      return r.state === "SUCCEEDED" ? r : false;
    }, "sandbox create");
    const id = operation.sandboxId;
    assert.ok(id);
    const ready = await call(clientA, "sandbox_wait_ready", { id, waitMs: 60000 });
    assert.equal(ready.state, "READY");
    const command = await call(clientA, "command_run", {
      id,
      script: "printf mcp-e2e",
      waitMs: 60000,
    });
    assert.equal(command.complete, true);
    assert.equal(command.result.result.exitCode, 0);
    assert.ok(command.output.some((page) => page.chunks.length > 0));
    const write = await call(clientA, "file_write", {
      id,
      path: "/tmp/mcp-e2e",
      content: "mcp-e2e-file",
    });
    await until(
      async () =>
        (await a.rpc("sandboxes/getOperation", { operationId: write.operationId })).state ===
        "SUCCEEDED",
      "file write",
    );
    const read = await call(clientA, "file_read", { id, path: "/tmp/mcp-e2e", waitMs: 60000 });
    assert.equal(Buffer.from(read.contentBase64, "base64").toString(), "mcp-e2e-file");
    const stopped = await call(clientA, "sandbox_stop", { id });
    await until(
      async () =>
        (await a.rpc("sandboxes/getOperation", { operationId: stopped.operationId })).state ===
        "SUCCEEDED",
      "sandbox stop",
    );
    const destroyed = await call(clientA, "sandbox_destroy", { id });
    await until(
      async () =>
        (await a.rpc("sandboxes/getOperation", { operationId: destroyed.operationId })).state ===
        "SUCCEEDED",
      "sandbox destroy",
    );
  });
  await stage("host off / CLI TTY raise / masked output / dashboard cancellation", async () => {
    const off = await clientA.callTool({
      name: "host_command_run",
      arguments: { hostId: hostA.id, argv: ["true"] },
    });
    assert.equal(off.structuredContent.error.code, "host.agent_access_off");
    assert.equal(off.structuredContent.error.retryable, false);
    await nodeConfig("agent-on", daemonAEnv, ["set-agent-host-commands", "on"], true);
    await until(
      async () => (await a.rpc("sandboxHosts/getHost", { id: hostA.id })).agentPolicy?.hostCommands,
      "agent on",
    );
    const output = await call(clientA, "host_command_run", {
      hostId: hostA.id,
      argv: ["/bin/echo", maskSecret],
      waitMs: 10000,
    });
    assert.equal(output.state, "succeeded");
    const text = Buffer.from(output.stdout.data, "base64").toString();
    assert.ok(text.includes("⟦redacted⟧"));
    assert.ok(!text.includes(maskSecret));
    const running = await call(clientA, "host_command_run", {
      hostId: hostA.id,
      script: "sleep 60",
      waitMs: 0,
    });
    await a.rpc("sandboxHosts/lowerAgentHostCommands", { id: hostA.id });
    await until(async () => {
      const r = await call(clientA, "host_command_get", {
        hostId: hostA.id,
        commandId: running.commandId,
        waitMs: 0,
      });
      return ["cancelled", "interrupted"].includes(r.state);
    }, "command cancelled");
    const lowered = await clientA.callTool({
      name: "host_command_run",
      arguments: { hostId: hostA.id, argv: ["true"] },
    });
    assert.equal(lowered.structuredContent.error.code, "host.agent_access_off");
  });
  await stage("queued command / person review wrapper / agent decision refusal", async () => {
    const queued = await call(clientA, "host_command_queue", {
      hostId: hostA.id,
      command: "printf reviewed",
      reason: "e2e review",
    });
    assert.equal(queued.state, "QUEUED");
    const page = await a.rpc("hostQueuedCommands/list", { hostId: hostA.id, limit: 10 });
    assert.ok(page.items.some((q) => q.id === queued.id));
    const decision = await a.rpc("hostQueuedCommands/run", { id: queued.id });
    assert.equal(decision.state, "RUN");
    assert.ok(decision.typedCommand.includes("wssp-queued"));
    assert.ok(!decision.typedCommand.endsWith("\n"));
    for (const name of [
      "host_command_queue_run",
      "host_command_queue_dismiss",
      "terminal_open",
      "agent_token_create",
      "host_policy_raise",
    ])
      await assert.rejects(
        clientA.callTool({ name, arguments: { id: queued.id } }),
        new RegExp(`Tool ${name} not found`),
      );
    for (const path of [
      "hostQueuedCommands/run",
      "hostQueuedCommands/dismiss",
      "sandboxHosts/lowerAgentHostCommands",
      "agentTokens/create",
      "hostTerminals/createSession",
    ]) {
      const refused = await fetch(`${origin}/rpc/${path}`, {
        method: "POST",
        headers: {
          origin,
          authorization: `Bearer ${tokenA.secret}`,
          "content-type": "application/json",
          "x-csrf-token": "orpc",
        },
        body: JSON.stringify({ json: { id: queued.id } }),
      });
      assert.equal(refused.status, 401);
    }
  });
  await stage("B full scopes / shared node physical ownership refusal", async () => {
    assert.ok(!(await call(clientB, "host_list")).items.some((h) => h.id === hostA.id));
    for (const [name, args] of [
      ["host_command_run", { argv: ["true"] }],
      ["host_file_read", { path: "/tmp/test" }],
      ["host_command_queue", { command: "true", reason: "review" }],
    ]) {
      const r = await clientB.callTool({ name, arguments: { hostId: hostA.id, ...args } });
      assert.equal(r.isError, true);
      assert.ok(["FORBIDDEN", "host.not_owned"].includes(r.structuredContent.error.code));
    }
  });
} catch (error) {
  failure = error;
  rows.push([activeStage, "FAIL"]);
  console.error(error.message);
} finally {
  try {
    await cleanup();
    rows.push(["cleanup", "PASS"]);
  } catch (error) {
    failure ??= error;
    rows.push(["cleanup", "FAIL"]);
    console.error(error.message);
  }
  console.table(rows.map(([test, result]) => ({ test, result })));
  if (!failure) await rm(temporary, { recursive: true, force: true });
  else console.error(`Private diagnostics retained: ${temporary}`);
}
process.exitCode = failure ? 1 : 0;
