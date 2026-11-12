#!/usr/bin/env node
/**
 * `pnpm dev:s3` / `pnpm dev:s3:stop`: ONE long-running local S3 gateway for
 * development (image store, sandbox disk offload). Never the production
 * bucket, never used by CI.
 *
 * - The same pinned RustFS image as `pnpm test:s3` (pull it once with
 *   `pnpm test:s3:pull-image`; it is never pulled implicitly).
 * - Container `wssp-dev-s3`, published on 127.0.0.1:7457 only (test:s3 uses
 *   an ephemeral port; the relay chaos stack uses PORT+5000 / PORT+6100).
 *   `--name <container>` and `--port <port>` override both, for `stop` too,
 *   e.g. to run beside another worktree's gateway.
 * - Persistent, gitignored state in `.local/dev-s3/`: `rustfs/` (the drive,
 *   owned by you: the container runs as your uid, via `--userns=keep-id`
 *   under rootless Podman) and `gateway.env` (0600, random root
 *   credentials; never passed on argv).
 * - Creates bucket `wssp-offload-dev` if absent.
 * - Upserts the `IMAGE_S3_*` variables into the gitignored repo-root `.env`
 *   (newline-safe, 0600). It prints key names only, never a value.
 *
 * Idempotent: a re-run reuses the running container and the stored
 * credentials. `dev:s3:stop` removes the container and keeps `.local/dev-s3/`.
 * Presigned URLs are http, which the daemons accept on loopback only, so the
 * daemons that use this gateway must run on this machine.
 */
import { execFileSync } from "node:child_process";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { parseArgs } from "node:util";
import { upsertEnvFile } from "./lib/env-file.mjs";
import {
  credentialsEnvFile,
  docker,
  imagePresent,
  S3_REGION as REGION,
  S3_CONTAINER_PORT,
  S3_ENV_ARGS,
  S3_IMAGE,
  waitForReady,
} from "./lib/s3-gateway.mjs";

const { values: options, positionals } = parseArgs({
  allowPositionals: true,
  options: { name: { type: "string" }, port: { type: "string" } },
});
const NAME = options.name ?? "wssp-dev-s3";
const PORT = Number(options.port ?? 7457);
if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(NAME)) throw new Error("--name is not a container name");
if (!Number.isInteger(PORT) || PORT < 1024 || PORT > 65535)
  throw new Error("--port must be 1024-65535");
const LABEL = "wssp.dev-s3";
const BUCKET = "wssp-offload-dev";
const ROOT = resolve(import.meta.dirname, "..");
const STATE = resolve(ROOT, ".local/dev-s3");
// Not `data/`: that held the previous gateway's posix layout, which is kept.
const DATA = resolve(STATE, "rustfs");
const CREDENTIALS = resolve(STATE, "gateway.env");
const ENV_FILE = resolve(ROOT, ".env");

function say(message) {
  console.log(`[dev:s3] ${message}`);
}

function inspect(format) {
  try {
    return docker(["container", "inspect", NAME, "--format", format]);
  } catch {
    return null;
  }
}

function removeContainer() {
  if (inspect("{{.Id}}") === null) return false;
  execFileSync("docker", ["rm", "--force", NAME], { stdio: "ignore", timeout: 30_000 });
  return true;
}

/**
 * Stored root credentials, generated with crypto randomness on first run. A
 * file in the previous gateway's key names is rewritten in place with the
 * same values, so `.env` stays valid.
 */
function credentials() {
  if (existsSync(CREDENTIALS)) {
    const text = readFileSync(CREDENTIALS, "utf8");
    const value = (key) => text.match(new RegExp(`^${key}=([A-Za-z0-9_-]+)$`, "m"))?.[1];
    const accessKeyId = value("RUSTFS_ACCESS_KEY") ?? value("ROOT_ACCESS_KEY_ID");
    const secretAccessKey = value("RUSTFS_SECRET_KEY") ?? value("ROOT_SECRET_ACCESS_KEY");
    if (!accessKeyId || !secretAccessKey)
      throw new Error(`${CREDENTIALS} is malformed; delete it and run pnpm dev:s3 again.`);
    chmodSync(CREDENTIALS, 0o600);
    if (value("RUSTFS_ACCESS_KEY") === undefined || value("RUSTFS_SECRET_KEY") === undefined)
      writeFileSync(CREDENTIALS, credentialsEnvFile(accessKeyId, secretAccessKey), { mode: 0o600 });
    return { accessKeyId, secretAccessKey };
  }
  const accessKeyId = `wsspdev${randomBytes(8).toString("hex")}`;
  const secretAccessKey = randomBytes(24).toString("base64url");
  writeFileSync(CREDENTIALS, credentialsEnvFile(accessKeyId, secretAccessKey), {
    mode: 0o600,
    flag: "wx",
  });
  return { accessKeyId, secretAccessKey };
}

/** Changes whenever the credentials or port do, so a stale container is recreated. */
function fingerprint(creds) {
  return createHash("sha256")
    .update(`dev-s3:${creds.accessKeyId}:${PORT}`)
    .digest("hex")
    .slice(0, 16);
}

/**
 * Run the gateway as the invoking user so its drive stays removable without
 * root. Rootless Podman (behind the `docker` CLI) maps ids through a user
 * namespace: `--userns=keep-id` maps your uid into it, and `--user` is still
 * needed because the image names its own non-root USER.
 */
function userArgs() {
  let rootlessPodman = false;
  try {
    rootlessPodman = docker(["info", "--format", "{{.Host.Security.Rootless}}"]) === "true";
  } catch {
    /* Docker's info has no .Host; not Podman. */
  }
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  const user = uid === undefined || gid === undefined ? [] : ["--user", `${uid}:${gid}`];
  return rootlessPodman ? ["--userns=keep-id", ...user] : user;
}

function startContainer(creds) {
  const wanted = fingerprint(creds);
  const running = inspect("{{.State.Running}}") === "true";
  const sameImage = inspect("{{.Config.Image}}") === S3_IMAGE;
  const sameCreds = inspect(`{{index .Config.Labels "${LABEL}"}}`) === wanted;
  if (running && sameImage && sameCreds) {
    say(`reusing running container ${NAME}`);
    return;
  }
  removeContainer();
  docker([
    "run",
    "--detach",
    "--pull=never",
    "--name",
    NAME,
    "--label",
    `${LABEL}=${wanted}`,
    "--memory",
    "512m",
    ...userArgs(),
    "--publish",
    `127.0.0.1:${PORT}:${S3_CONTAINER_PORT}`,
    "--volume",
    `${DATA}:/data`,
    ...S3_ENV_ARGS,
    "--env-file",
    CREDENTIALS,
    S3_IMAGE,
  ]);
  say(`started container ${NAME}`);
}

const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const hmac = (key, data) => createHmac("sha256", key).update(data).digest();

/** A SigV4-signed path-style bucket request with an empty body. */
async function bucketRequest(method, creds) {
  const host = `127.0.0.1:${PORT}`;
  const path = `/${BUCKET}`;
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
  const day = amzDate.slice(0, 8);
  const payloadHash = sha256("");
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  const canonical = [
    method,
    path,
    "",
    `host:${host}`,
    `x-amz-content-sha256:${payloadHash}`,
    `x-amz-date:${amzDate}`,
    "",
    signedHeaders,
    payloadHash,
  ].join("\n");
  const scope = `${day}/${REGION}/s3/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n");
  const key = hmac(
    hmac(hmac(hmac(`AWS4${creds.secretAccessKey}`, day), REGION), "s3"),
    "aws4_request",
  );
  const signature = createHmac("sha256", key).update(toSign).digest("hex");
  return fetch(`http://${host}${path}`, {
    method,
    headers: {
      "x-amz-content-sha256": payloadHash,
      "x-amz-date": amzDate,
      authorization: `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    },
  });
}

async function ensureBucket(creds) {
  const deadline = Date.now() + 30_000;
  for (;;) {
    const head = await bucketRequest("HEAD", creds).catch(() => null);
    if (head?.status === 200) return say(`bucket ${BUCKET} present`);
    if (head?.status === 404) {
      const put = await bucketRequest("PUT", creds);
      const body = await put.text();
      if (put.ok || body.includes("BucketAlreadyOwnedByYou"))
        return say(`created bucket ${BUCKET}`);
      throw new Error(`creating bucket ${BUCKET} failed with HTTP ${put.status}`);
    }
    if (Date.now() > deadline)
      throw new Error(`bucket check failed with ${head ? `HTTP ${head.status}` : "no response"}`);
    await new Promise((r) => setTimeout(r, 300));
  }
}

async function start() {
  try {
    docker(["version", "--format", "{{.Server.Version}}"]);
  } catch {
    console.error("[dev:s3] docker is not available");
    return 1;
  }
  if (!imagePresent()) {
    console.error(`[dev:s3] image ${S3_IMAGE} is not present; run: pnpm test:s3:pull-image`);
    return 1;
  }
  mkdirSync(DATA, { recursive: true, mode: 0o700 });
  chmodSync(STATE, 0o700);
  const creds = credentials();
  startContainer(creds);
  await waitForReady(PORT, Date.now() + 60_000, () => inspect("{{.State.Running}}") === "true");
  await ensureBucket(creds);
  const { replaced, appended } = upsertEnvFile(ENV_FILE, {
    IMAGE_S3_ENDPOINT: `http://127.0.0.1:${PORT}`,
    IMAGE_S3_REGION: REGION,
    IMAGE_S3_BUCKET: BUCKET,
    IMAGE_S3_ACCESS_KEY_ID: creds.accessKeyId,
    IMAGE_S3_SECRET_ACCESS_KEY: creds.secretAccessKey,
    IMAGE_S3_FORCE_PATH_STYLE: "true",
  });
  if (replaced.length > 0) say(`.env: replaced ${replaced.join(", ")}`);
  if (appended.length > 0) say(`.env: added ${appended.join(", ")}`);
  say(`ready on 127.0.0.1:${PORT}, bucket ${BUCKET}; restart the server and worker to pick it up`);
  return 0;
}

function stop() {
  say(removeContainer() ? `removed container ${NAME}` : `no container ${NAME}`);
  say(".local/dev-s3/ (data and credentials) is kept; .env is unchanged");
  return 0;
}

try {
  process.exitCode = positionals[0] === "stop" ? stop() : await start();
} catch (error) {
  console.error(`[dev:s3] ${error instanceof Error ? error.message : "failed"}`);
  process.exitCode = 1;
}
