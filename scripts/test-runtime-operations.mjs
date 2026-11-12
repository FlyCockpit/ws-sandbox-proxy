/** Explicit operations smoke; owns disposable services and never loads the root .env. */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import {
  canonicalApplyFixture,
  disposableDirectory,
  startDisposablePostgres,
} from "./lib/disposable-postgres.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const file = fileURLToPath(import.meta.url);

async function runtimeCheck(mode) {
  assert.ok(["embedded", "external"].includes(mode));
  const [{ startWorkerRuntime }, queues, { default: prisma }, health, { serverVars }] =
    await Promise.all([
      import("../apps/worker/src/runtime.ts"),
      import("../packages/queue/src/index.ts"),
      import("../packages/db/src/index.ts"),
      import("../packages/queue/src/consumer-health.ts"),
      import("../packages/env/src/vars/server.ts"),
    ]);
  assert.equal(serverVars.WORKER_MODE.parse(undefined), "embedded");
  const inventory = Object.values(queues.QUEUE_NAMES);
  assert.equal(await health.hasExternalConsumer(queues.redisConnection, inventory), false);
  // Adjacent-release regression against actual Redis Lua: the old inventory
  // stays live while the new server needs an additional queue. Its heartbeat
  // must never admit that server, even after the old worker republishes.
  const old = health.createConsumerHeartbeat(
    queues.redisConnection,
    "external",
    ["legacy-queue"],
    () => true,
  );
  await old.start();
  assert.equal(await health.hasExternalConsumer(queues.redisConnection, ["legacy-queue"]), true);
  assert.equal(await health.hasExternalConsumer(queues.redisConnection, inventory), false);
  const replacement = health.createConsumerHeartbeat(
    queues.redisConnection,
    "external",
    ["legacy-queue"],
    () => true,
  );
  await replacement.start();
  await old.stop();
  assert.equal(await health.hasExternalConsumer(queues.redisConnection, ["legacy-queue"]), true);
  await replacement.stop();
  const expiringQueue = `heartbeat-expiry-${randomUUID()}`;
  const expiring = health.createConsumerHeartbeat(
    queues.redisConnection,
    "external",
    [expiringQueue],
    () => true,
  );
  await expiring.start();
  assert.equal(await health.hasExternalConsumer(queues.redisConnection, [expiringQueue]), true);
  const expiryKey = `wssp:consumers:v2:external:${expiringQueue}`;
  const [replicaId] = await queues.redisConnection.zrange(expiryKey, 0, -1);
  assert.ok(replicaId);
  // Model a crashed publisher's expired score without waiting fifteen seconds.
  // The actual production read Lua must use Redis TIME and reject that score.
  await queues.redisConnection.zadd(expiryKey, 0, replicaId);
  assert.equal(await health.hasExternalConsumer(queues.redisConnection, [expiringQueue]), false);
  await expiring.stop();
  const fatal = [];
  let runtime;
  try {
    runtime = await startWorkerRuntime({
      embedded: mode === "embedded",
      onFatal: (error) => fatal.push(error),
    });
    assert.equal(runtime.isReady(), true);
    assert.equal(
      await health.hasExternalConsumer(queues.redisConnection, inventory),
      mode === "external",
    );
    assert.equal(
      await health.hasExternalConsumer(queues.redisConnection, [
        ...inventory,
        "next-release-queue",
      ]),
      false,
    );
    const id = `runtime-${randomUUID()}`;
    const job = await queues.reapExpiredAuthTokensQueue.add(
      "reap-expired-auth-tokens",
      { reason: "cron" },
      { jobId: id },
    );
    const deadline = Date.now() + 15_000;
    while ((await job.getState()) !== "completed" && Date.now() < deadline) await delay(50);
    assert.equal(await job.getState(), "completed");
    const result = (await queues.reapExpiredAuthTokensQueue.getJob(id)).returnvalue;
    assert.equal(result.reason, "cron");
    assert.equal(typeof result.deleted.sessions, "number");
    assert.equal(typeof result.deleted.verifications, "number");
    assert.equal(typeof result.deleted.deviceCodes, "number");
    const stopping = runtime.stop();
    assert.equal(runtime.isReady(), false);
    assert.equal(runtime.stop(), stopping);
    await stopping;
    assert.equal(await health.hasExternalConsumer(queues.redisConnection, inventory), false);
    await assert.rejects(
      startWorkerRuntime({ embedded: mode === "embedded", onFatal: () => {} }),
      /already started/,
    );
    assert.deepEqual(fatal, []);
    console.log(`${mode}: schema-backed reap, readiness, withdrawal, drain, and re-entry passed.`);
  } finally {
    await runtime?.stop();
    await Promise.all(
      Object.values(queues)
        .filter((value) => value instanceof queues.Queue)
        .map((queue) => queue.close()),
    );
    queues.redisConnection.disconnect();
    await prisma.$disconnect();
  }
}

async function main() {
  if (process.argv[2] === "--runtime-child") {
    assert.equal(process.env.RUNTIME_OPERATIONS_CHILD, "owned-disposable-services");
    await runtimeCheck(process.argv[3]);
    return;
  }
  if (process.argv[2] !== "--disposable-services") {
    throw new Error("Use node scripts/test-runtime-operations.mjs --disposable-services.");
  }
  const environment = { PATH: process.env.PATH };
  const docker = (...args) =>
    execFileSync("docker", args, {
      env: environment,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
    }).trim();
  docker(
    "image",
    "inspect",
    "docker.io/valkey/valkey:9.1.3-alpine@sha256:bf09d58e96d6b4524a15396b65b242bbe18beebbcc15a04d8ee75ddac62fae0b",
    "--format",
    "{{.Id}}",
  );
  // Removed by the finally below, or by the shared signal path.
  const temporaryDirectory = disposableDirectory("wssp-runtime-operations-");
  const temporary = temporaryDirectory.path;
  const containers = [];
  let postgres;
  try {
    postgres = await startDisposablePostgres({
      owner: "runtime-pg",
      memory: "256m",
      tmpfsSize: "256m",
    });
    const redis = docker(
      "run",
      "--detach",
      "--rm",
      "--name",
      `wssp-runtime-redis-${randomUUID()}`,
      "--memory",
      "64m",
      "--publish",
      "127.0.0.1::6379",
      "docker.io/valkey/valkey:9.1.3-alpine@sha256:bf09d58e96d6b4524a15396b65b242bbe18beebbcc15a04d8ee75ddac62fae0b",
      "valkey-server",
      "--save",
      "",
      "--appendonly",
      "no",
      "--maxmemory",
      "32mb",
      "--maxmemory-policy",
      "noeviction",
    );
    containers.push(redis);
    const port = (id, mapping) => {
      const value = docker("port", id, mapping).split(":").at(-1);
      assert.match(value, /^\d+$/);
      return value;
    };
    const databaseUrl = postgres.url();
    const redisUrl = `redis://127.0.0.1:${port(redis, "6379/tcp")}`;
    // The real Prisma config and schema, copied away from root .env. Only
    // installed packages are linked; dotenv resolves a missing file there.
    const migration = canonicalApplyFixture(root, temporary, databaseUrl);
    const fixtureEnv = { ...environment, ...migration.env, REDIS_URL: redisUrl };
    for (const operation of ["empty database", "unchanged migrations"]) {
      migration.apply();
      console.log(`Canonical migration runner with real Prisma: ${operation} passed.`);
    }
    for (const mode of ["embedded", "external"]) {
      const result = execFileSync(
        process.execPath,
        ["--import", "tsx", file, "--runtime-child", mode],
        {
          cwd: root,
          env: {
            ...fixtureEnv,
            MIGRATE_ON_START: "false",
            RUNTIME_OPERATIONS_CHILD: "owned-disposable-services",
          },
          timeout: 45_000,
          stdio: ["ignore", "pipe", "pipe"],
          encoding: "utf8",
        },
      );
      process.stdout.write(result);
    }
  } finally {
    const cleanupErrors = [];
    try {
      postgres?.stop();
    } catch (error) {
      cleanupErrors.push(error);
    }
    for (const id of containers.reverse()) {
      try {
        docker("stop", "--time", "2", id);
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    try {
      temporaryDirectory.remove();
    } catch (error) {
      cleanupErrors.push(error);
    }
    if (cleanupErrors.length) {
      console.error("Disposable fixture cleanup failed; inspect this run's owned containers.");
      process.exitCode = 1;
    } else {
      console.log("Removed only this smoke run's disposable containers and temporary fixture.");
    }
  }
}

try {
  await main();
} catch (error) {
  console.error(error instanceof Error ? error.message : "Runtime operations check failed.");
  process.exitCode = 1;
}
