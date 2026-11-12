/**
 * The pinned S3-compatible gateway shared by `pnpm test:s3` (disposable, one
 * per run) and `pnpm dev:s3` (one long-running local gateway): RustFS, single
 * drive, path-style only (no `RUSTFS_SERVER_DOMAINS`), console off. The image
 * is pulled only by `pnpm test:s3:pull-image`, never implicitly.
 *
 * Root credentials reach the container only through a 0600 `--env-file`
 * (`RUSTFS_ACCESS_KEY` / `RUSTFS_SECRET_KEY`), never argv.
 */
import { execFileSync } from "node:child_process";

/** rustfs/rustfs 1.0.5, multi-arch index digest. */
export const S3_IMAGE =
  "docker.io/rustfs/rustfs:1.0.5@sha256:b81d16a90ee25bd9511280127ca1471788c6e874cf0f0da759645f46b2dc1d74";

/** The gateway's in-container S3 listen port. */
export const S3_CONTAINER_PORT = 9000;

/** The region the gateway signs and answers for. */
export const S3_REGION = "us-east-1";

/**
 * Non-secret gateway settings, as `--env` pairs. Logs go to stdout (the
 * image's default `/logs` is not writable when the container runs as the
 * invoking user).
 */
export const S3_ENV_ARGS = [
  "--env",
  `RUSTFS_REGION=${S3_REGION}`,
  "--env",
  "RUSTFS_CONSOLE_ENABLE=false",
  "--env",
  "RUSTFS_OBS_LOG_DIRECTORY=",
  "--env",
  "RUSTFS_VOLUMES=/data",
];

/** The env-file body carrying the root credentials. */
export function credentialsEnvFile(accessKeyId, secretAccessKey) {
  return `RUSTFS_ACCESS_KEY=${accessKeyId}\nRUSTFS_SECRET_KEY=${secretAccessKey}\n`;
}

export function docker(args, timeout = 60_000) {
  return execFileSync("docker", args, { stdio: ["ignore", "pipe", "pipe"], timeout })
    .toString()
    .trim();
}

export function imagePresent() {
  try {
    docker(["image", "inspect", S3_IMAGE, "--format", "{{.Id}}"]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Wait until the gateway reports ready (`/health/ready`, unauthenticated):
 * an open port alone precedes storage initialisation. `alive` (optional)
 * fails fast once the container has exited; see `docker logs <name>`.
 */
export async function waitForReady(port, deadline, alive = () => true) {
  while (Date.now() < deadline) {
    if (!alive()) throw new Error("S3 gateway container exited; see docker logs");
    const ready = await fetch(`http://127.0.0.1:${port}/health/ready`, {
      signal: AbortSignal.timeout(2_000),
    })
      .then((response) => response.status === 200)
      .catch(() => false);
    if (ready) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("S3 gateway did not become ready");
}
