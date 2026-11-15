#!/usr/bin/env node
/**
 * `pnpm test:s3`: the real-S3 layer for the template image store.
 *
 * Starts ONE disposable S3-compatible gateway (RustFS, single drive on a
 * tmpfs), published on 127.0.0.1 only, with random credentials passed through a 0600 env file
 * (never argv), runs every `*.s3.test.ts` against it, and always removes the
 * container. The image is never pulled implicitly: run
 * `pnpm test:s3:pull-image` once (the one place the pinned digest is pulled).
 *
 * The `.s3.test.ts` files mock the database (`@wssp/db`) and exercise the real
 * AWS SDK presigning, multipart, ListParts, GET and the verify/sweep handlers.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { disposableDirectory, forceRemove } from "./lib/disposable-postgres.mjs";
import {
  credentialsEnvFile,
  docker,
  imagePresent,
  S3_CONTAINER_PORT,
  S3_ENV_ARGS,
  S3_IMAGE,
  waitForReady,
} from "./lib/s3-gateway.mjs";
import { testContainerPrefix } from "./lib/test-container-prefix.mjs";

const LABEL = "wssp.disposable-s3";
const ROOT = resolve(import.meta.dirname, "..");

async function main() {
  if (process.argv[2] === "pull") {
    execFileSync("docker", ["pull", S3_IMAGE], { stdio: "inherit", timeout: 600_000 });
    return 0;
  }
  if (!imagePresent()) {
    console.error(`[test:s3] image ${S3_IMAGE} is not present; run: pnpm test:s3:pull-image`);
    return 1;
  }
  const name = `${testContainerPrefix()}-s3-${randomUUID()}`;
  const access = `wssp${randomBytes(8).toString("hex")}`;
  const secret = randomBytes(24).toString("base64url");
  const secrets = disposableDirectory("wssp-s3-env-");
  const envFile = resolve(secrets.path, "s3.env");
  writeFileSync(envFile, credentialsEnvFile(access, secret), { mode: 0o600 });
  let status = 1;
  try {
    try {
      docker([
        "run",
        "--detach",
        "--rm",
        "--pull=never",
        "--name",
        name,
        "--label",
        `${LABEL}=test-s3`,
        "--memory",
        "256m",
        // The image runs as its own non-root user; a fresh tmpfs is root-owned.
        "--tmpfs",
        "/data:rw,size=192m,mode=1777",
        "--publish",
        `127.0.0.1::${S3_CONTAINER_PORT}`,
        ...S3_ENV_ARGS,
        "--env-file",
        envFile,
        S3_IMAGE,
      ]);
    } finally {
      secrets.remove();
    }
    const port = Number(
      docker(["port", name, `${S3_CONTAINER_PORT}/tcp`])
        .split("\n")[0]
        .split(":")
        .pop(),
    );
    await waitForReady(port, Date.now() + 30_000);
    const env = {
      ...process.env,
      WSSP_TEST_S3_ENDPOINT: `http://127.0.0.1:${port}`,
      WSSP_TEST_S3_ACCESS_KEY_ID: access,
      WSSP_TEST_S3_SECRET_ACCESS_KEY: secret,
    };
    const run = spawnSync(
      "pnpm",
      ["--filter", "@wssp/api", "exec", "vitest", "run", "--config", "../../vitest.s3.config.ts"],
      { cwd: ROOT, env, stdio: "inherit" },
    );
    status = run.status ?? 1;
  } finally {
    forceRemove(name);
  }
  return status;
}

process.exitCode = await main();
