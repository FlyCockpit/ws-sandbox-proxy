import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

for (const runtime of ["docker", "podman"]) {
  test(`dev wrapper rootless option and canonical CLI discovery with ${runtime}`, () => {
    const root = mkdtempSync(join(tmpdir(), "wssp-compose-test-"));
    try {
      mkdirSync(join(root, "scripts/lib"), { recursive: true });
      for (const file of [
        "scripts/dev-docker.sh",
        "scripts/dev-docker-logs.sh",
        "scripts/lib/dev-docker-runtime.sh",
        "docker-compose.podman-rootless.yml",
      ]) {
        cpSync(new URL(`../${file}`, import.meta.url), join(root, file));
      }
      writeFileSync(join(root, "docker-compose.agent.yml"), "services: {}\n");
      const bin = join(root, "bin");
      mkdirSync(bin);
      const log = join(root, "argv");
      // No containers or compose programs are run: only argv is captured.
      const stub = `#!/bin/sh\nprintf '%s\\n' "$@" > '${log}'\n`;
      writeFileSync(join(bin, runtime), stub, { mode: 0o755 });
      writeFileSync(join(bin, "podman-compose"), stub, { mode: 0o755 });
      const env = {
        ...process.env,
        CONTAINER_RUNTIME: runtime,
        PATH: `${bin}:${process.env.PATH}`,
      };
      execFileSync(
        "bash",
        [join(root, "scripts/dev-docker.sh"), "43120", "--prod", "--rootless-podman"],
        { env },
      );
      const state = JSON.parse(readFileSync(join(root, ".agent-ports.json"), "utf8"));
      assert.equal(state.cliUrl, "https://localhost:49220");
      assert.equal(state.podmanRootless, String(runtime === "podman"));
      const argv = readFileSync(log, "utf8");
      assert.equal(argv.includes("--in-pod\nfalse"), runtime === "podman");
      assert.equal(argv.includes("docker-compose.podman-rootless.yml"), runtime === "podman");
      assert.match(argv, /--profile\nprod\nup\n--build/);
      execFileSync("bash", [join(root, "scripts/dev-docker-logs.sh"), "43120", "app-dev"], { env });
      const logArgv = readFileSync(log, "utf8");
      assert.equal(logArgv.includes("--in-pod\nfalse"), runtime === "podman");
      assert.equal(logArgv.includes("docker-compose.podman-rootless.yml"), runtime === "podman");
      assert.match(logArgv, /logs\n-f\n--tail\n200\napp-dev/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

test("dev wrapper supplies a stable per-stack SANDBOX_REQUEST_HMAC_SECRET", () => {
  const root = mkdtempSync(join(tmpdir(), "wssp-compose-hmac-test-"));
  try {
    mkdirSync(join(root, "scripts/lib"), { recursive: true });
    for (const file of ["scripts/dev-docker.sh", "scripts/lib/dev-docker-runtime.sh"]) {
      cpSync(new URL(`../${file}`, import.meta.url), join(root, file));
    }
    writeFileSync(join(root, "docker-compose.agent.yml"), "services: {}\n");
    const bin = join(root, "bin");
    mkdirSync(bin);
    const seen = join(root, "seen");
    // The stub compose records the exported throwaway test value; nothing runs.
    const stub = `#!/bin/sh\nprintf '%s' "$AGENT_SANDBOX_REQUEST_HMAC_SECRET" > '${seen}'\n`;
    writeFileSync(join(bin, "docker"), stub, { mode: 0o755 });
    const env = {
      ...process.env,
      AGENT_SANDBOX_REQUEST_HMAC_SECRET: "",
      CONTAINER_RUNTIME: "docker",
      PATH: `${bin}:${process.env.PATH}`,
    };
    const run = (...args) =>
      execFileSync("bash", [join(root, "scripts/dev-docker.sh"), "43130", ...args], { env });
    run("--prod");
    const first = readFileSync(seen, "utf8");
    // Same constraints as packages/env/src/vars/server.ts: even-length lowercase hex >= 64.
    assert.match(first, /^[0-9a-f]{64}$/);
    const { volumeRoot } = JSON.parse(readFileSync(join(root, ".agent-ports.json"), "utf8"));
    const file = join(volumeRoot, "sandbox-request-hmac-secret");
    assert.equal(statSync(file).mode & 0o777, 0o600);
    // Stable across re-runs of the same stack (it keys stored digests).
    run();
    assert.equal(readFileSync(seen, "utf8"), first);
    // --reset wipes the stack and its secret, so a fresh value is generated.
    run("--prod", "--reset");
    assert.notEqual(readFileSync(seen, "utf8"), first);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("dev wrapper supplies a strong per-stack BETTER_AUTH_SECRET for --prod", () => {
  const root = mkdtempSync(join(tmpdir(), "wssp-compose-auth-test-"));
  try {
    mkdirSync(join(root, "scripts/lib"), { recursive: true });
    for (const file of ["scripts/dev-docker.sh", "scripts/lib/dev-docker-runtime.sh"]) {
      cpSync(new URL(`../${file}`, import.meta.url), join(root, file));
    }
    writeFileSync(join(root, "docker-compose.agent.yml"), "services: {}\n");
    const bin = join(root, "bin");
    mkdirSync(bin);
    const seen = join(root, "seen");
    // The stub compose records the exported throwaway values; nothing runs.
    const stub = `#!/bin/sh\nprintf '%s %s' "$AGENT_BETTER_AUTH_SECRET" "$AGENT_SANDBOX_REQUEST_HMAC_SECRET" > '${seen}'\n`;
    writeFileSync(join(bin, "docker"), stub, { mode: 0o755 });
    const env = {
      ...process.env,
      AGENT_BETTER_AUTH_SECRET: "weak",
      CONTAINER_RUNTIME: "docker",
      PATH: `${bin}:${process.env.PATH}`,
    };
    const run = (...args) =>
      execFileSync("bash", [join(root, "scripts/dev-docker.sh"), "43140", ...args], { env });
    run("--prod");
    const [first, hmac] = readFileSync(seen, "utf8").split(" ");
    // secret32 format (scripts/generate-secrets.ts); an inherited value never wins.
    assert.match(first, /^[0-9a-f]{64}$/);
    assert.notEqual(first, hmac);
    const { volumeRoot } = JSON.parse(readFileSync(join(root, ".agent-ports.json"), "utf8"));
    assert.equal(statSync(join(volumeRoot, "better-auth-secret")).mode & 0o777, 0o600);
    run("--prod");
    assert.equal(readFileSync(seen, "utf8").split(" ")[0], first);
    run("--prod", "--reset");
    assert.notEqual(readFileSync(seen, "utf8").split(" ")[0], first);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("app-prod takes the generated BETTER_AUTH_SECRET, never the weak placeholder", () => {
  const compose = readFileSync(new URL("../docker-compose.agent.yml", import.meta.url), "utf8");
  const start = compose.indexOf("\n  app-prod:\n");
  const rest = compose.slice(start + 1);
  const block = rest.slice(0, rest.slice(1).search(/\n {2}[a-z][a-z0-9-]*:\n/) + 1);
  // `environment` overrides both env_file entries (defaults placeholder, .env).
  assert.ok(block.includes('BETTER_AUTH_SECRET: "${AGENT_BETTER_AUTH_SECRET:-}"'));
});

test("agent compose passes the generated HMAC secret to server containers only", () => {
  const compose = readFileSync(new URL("../docker-compose.agent.yml", import.meta.url), "utf8");
  const service = (name) => {
    const start = compose.indexOf(`\n  ${name}:\n`);
    assert.notEqual(start, -1, name);
    const rest = compose.slice(start + 1);
    const next = rest.slice(1).search(/\n {2}[a-z][a-z0-9-]*:\n/);
    return next === -1 ? rest : rest.slice(0, next + 1);
  };
  const wired = `SANDBOX_REQUEST_HMAC_SECRET: "\${AGENT_SANDBOX_REQUEST_HMAC_SECRET:-}"`;
  assert.ok(service("app-dev").includes(wired));
  assert.ok(service("app-prod").includes(wired));
  assert.ok(!service("worker-prod").includes("SANDBOX_REQUEST_HMAC_SECRET"));
  const defaults = readFileSync(new URL("../.env.docker.defaults", import.meta.url), "utf8");
  assert.doesNotMatch(defaults, /^SANDBOX_REQUEST_HMAC_SECRET=/m);
});

test("turbo passes SANDBOX_REQUEST_HMAC_SECRET to server#dev and web#dev only", () => {
  // Strict env mode would otherwise drop the per-stack value the dev-docker
  // container sets, and the server's dotenv load would fall back to a root .env.
  // web#dev runs the TanStack Start server functions, which validate the full
  // server env through @wssp/auth (apps/web/turbo.json). The worker never needs it.
  // A dummy value; the dry run reports names with hashes, never printed here.
  const repo = new URL("..", import.meta.url).pathname;
  const out = execFileSync(
    join(repo, "node_modules/.bin/turbo"),
    ["run", "dev", "--dry=json", "--filter=server", "--filter=web", "--filter=worker"],
    {
      cwd: repo,
      env: { ...process.env, SANDBOX_REQUEST_HMAC_SECRET: "dummy", TURBO_TELEMETRY_DISABLED: "1" },
      stdio: ["ignore", "pipe", "ignore"],
    },
  ).toString();
  const passthrough = Object.fromEntries(
    JSON.parse(out)
      .tasks.filter((task) => task.task === "dev")
      .map((task) => [
        task.package,
        (task.environmentVariables.passthrough ?? []).map((entry) => entry.split("=")[0]),
      ]),
  );
  assert.ok(passthrough.server.includes("SANDBOX_REQUEST_HMAC_SECRET"));
  assert.ok(passthrough.web.includes("SANDBOX_REQUEST_HMAC_SECRET"));
  assert.ok(!passthrough.worker.includes("SANDBOX_REQUEST_HMAC_SECRET"));
  // The shared `dev` task (every package) must not carry it.
  const shared = JSON.parse(
    readFileSync(new URL("../turbo.json", import.meta.url), "utf8").replace(/^\s*\/\/.*$/gm, ""),
  );
  assert.ok(!shared.tasks.dev.passThroughEnv.includes("SANDBOX_REQUEST_HMAC_SECRET"));
});

test("agent compose forwards the data-encryption root and its optional previous root", () => {
  const compose = readFileSync(new URL("../docker-compose.agent.yml", import.meta.url), "utf8");
  const service = (name) => {
    const start = compose.indexOf(`\n  ${name}:\n`);
    assert.notEqual(start, -1, name);
    const rest = compose.slice(start + 1);
    const next = rest.slice(1).search(/\n {2}[a-z][a-z0-9-]*:\n/);
    return next === -1 ? rest : rest.slice(0, next + 1);
  };
  for (const name of ["app-dev", "app-prod", "worker-prod"]) {
    const block = service(name);
    assert.ok(block.includes('DATA_ENCRYPTION_KEY: "${AGENT_DATA_ENCRYPTION_KEY:-}"'), name);
    // Empty default: an unset AGENT_ value starts without a previous root.
    assert.ok(
      block.includes('DATA_ENCRYPTION_KEY_PREVIOUS: "${AGENT_DATA_ENCRYPTION_KEY_PREVIOUS:-}"'),
      name,
    );
  }
});

test("turbo passes the data-encryption root, credentials switch and webhook vars to server#dev and worker#dev only", () => {
  // Strict env mode drops undeclared vars before `pnpm dev:raw` starts the
  // server and worker. Dummy values; the dry run is parsed, never printed.
  const repo = new URL("..", import.meta.url).pathname;
  const keys = [
    "DATA_ENCRYPTION_KEY",
    "DATA_ENCRYPTION_KEY_PREVIOUS",
    "CREDENTIALS_ENABLED",
    "WEBHOOK_ALLOWED_PRIVATE_CIDRS",
    "WEBHOOK_ALLOWED_PRIVATE_HOSTS",
    "WEBHOOK_TRANSLATION_PREFIXES",
    "WEBHOOK_PRIVATE_ALLOWLIST_SCOPE",
    "WEBHOOK_ALLOW_PLAINTEXT_PRIVATE",
  ];
  const out = execFileSync(
    join(repo, "node_modules/.bin/turbo"),
    ["run", "dev", "--dry=json", "--filter=server", "--filter=web", "--filter=worker"],
    {
      cwd: repo,
      env: {
        ...process.env,
        ...Object.fromEntries(keys.map((key) => [key, "dummy"])),
        TURBO_TELEMETRY_DISABLED: "1",
      },
      stdio: ["ignore", "pipe", "ignore"],
    },
  ).toString();
  const passthrough = Object.fromEntries(
    JSON.parse(out)
      .tasks.filter((task) => task.task === "dev")
      .map((task) => [
        task.package,
        (task.environmentVariables.passthrough ?? []).map((entry) => entry.split("=")[0]),
      ]),
  );
  for (const key of keys) {
    assert.ok(passthrough.server.includes(key), `server#dev ${key}`);
    assert.ok(passthrough.worker.includes(key), `worker#dev ${key}`);
    assert.ok(!passthrough.web.includes(key), `web#dev ${key}`);
  }
});
