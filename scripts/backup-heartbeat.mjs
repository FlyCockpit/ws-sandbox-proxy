#!/usr/bin/env node
/**
 * Optional dead-man's-switch ping after a successful off-site upload. A local
 * dump cannot attest off-site delivery. Failure only warns: the dump is safe.
 * Never log the URL, fetch exception, or response body: each can contain tokens.
 */
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const TIMEOUT_MS = 10_000;
const ATTEMPTS = 3;
const BACKOFF_MS = [1_000, 2_000];

/** Dependency injection keeps retries and secret-safe failures testable offline. */
export async function sendBackupHeartbeat({
  env = process.env,
  fetch: request = globalThis.fetch,
  sleep = delay,
  warn = (message) => console.error(`WARNING: ${message}`),
  log = (message) => console.log(message),
} = {}) {
  const raw = env.BACKUP_HEARTBEAT_URL;
  if (!raw) {
    warn("BACKUP_HEARTBEAT_URL is not set — no heartbeat sent.");
    return;
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    warn("BACKUP_HEARTBEAT_URL is not a valid URL — no heartbeat sent.");
    return;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    warn("BACKUP_HEARTBEAT_URL must use HTTP or HTTPS — no heartbeat sent.");
    return;
  }
  let lastError = "unreachable";
  for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const response = await request(url, { method: "GET", signal: controller.signal });
      // Release the response without reading or logging its potentially secret body.
      await response.body?.cancel();
      if (response.ok) {
        log("Heartbeat sent.");
        return;
      }
      lastError = `HTTP ${response.status}`;
    } catch {
      lastError = controller.signal.aborted ? "timed out" : "unreachable";
    } finally {
      clearTimeout(timer);
    }
    if (attempt < ATTEMPTS) await sleep(BACKOFF_MS[attempt - 1]);
  }
  warn(`backup heartbeat ${lastError} after ${ATTEMPTS} attempts. The dump itself is safe.`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await sendBackupHeartbeat();
