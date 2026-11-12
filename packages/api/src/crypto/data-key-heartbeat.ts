import { hostname } from "node:os";
import type { DataKeyring } from "./data-key";

/**
 * ADVISORY data-key heartbeats: every server and
 * external worker process writes `{role, keysHeld}` (kids only, never key
 * material) every 30 s with a 120 s TTL, so the status view shows which
 * processes still lack a key. They never gate anything: the DB write fence
 * (data-key-epoch.ts) is what makes rotation safe. No database import here:
 * process entrypoints load this before env validation of the DB graph.
 */

export const DATA_KEY_HEARTBEAT_PREFIX = "wssp:data-key:heartbeat:";
export const DATA_KEY_HEARTBEAT_EVERY_MS = 30_000;
export const DATA_KEY_HEARTBEAT_TTL_SECONDS = 120;
const HEARTBEAT_READ_CAP = 64;

export type DataKeyHeartbeat = { role: string; keysHeld: string[]; at: string };

/** The Redis surface heartbeats need (ioredis satisfies it). */
export type HeartbeatRedis = {
  set(key: string, value: string, mode: "EX", seconds: number): Promise<unknown>;
  scan(
    cursor: string,
    matchToken: "MATCH",
    pattern: string,
    countToken: "COUNT",
    count: number,
  ): Promise<[string, string[]]>;
  mget(keys: string[]): Promise<(string | null)[]>;
};

/** Kids only: never key material. */
export function heldKids(ring: DataKeyring | null): string[] {
  if (!ring) return [];
  return ring.previous ? [ring.current.id, ring.previous.id] : [ring.current.id];
}

/** Publishes this process's held kids every 30 s until `signal` aborts. Failures are ignored. */
export function startDataKeyHeartbeat(options: {
  redis: HeartbeatRedis;
  role: "server" | "worker";
  readRing: () => DataKeyring | null;
  signal: AbortSignal;
}): void {
  const key = `${DATA_KEY_HEARTBEAT_PREFIX}${options.role}:${hostname()}:${process.pid}`;
  const beat = () => {
    let keysHeld: string[] = [];
    try {
      keysHeld = heldKids(options.readRing());
    } catch {
      // An invalid key value surfaces at boot; the heartbeat stays quiet.
    }
    const value: DataKeyHeartbeat = { role: options.role, keysHeld, at: new Date().toISOString() };
    try {
      void Promise.resolve(
        options.redis.set(key, JSON.stringify(value), "EX", DATA_KEY_HEARTBEAT_TTL_SECONDS),
      ).catch(() => {});
    } catch {
      // Advisory only: a Redis failure never affects the process.
    }
  };
  beat();
  const timer = setInterval(beat, DATA_KEY_HEARTBEAT_EVERY_MS);
  timer.unref?.();
  options.signal.addEventListener("abort", () => clearInterval(timer), { once: true });
}

export async function readDataKeyHeartbeats(redis: HeartbeatRedis): Promise<DataKeyHeartbeat[]> {
  const keys: string[] = [];
  let cursor = "0";
  // Bounded: at most a few SCAN pages and HEARTBEAT_READ_CAP keys.
  for (let page = 0; page < 8 && keys.length < HEARTBEAT_READ_CAP; page++) {
    const [next, found] = await redis.scan(
      cursor,
      "MATCH",
      `${DATA_KEY_HEARTBEAT_PREFIX}*`,
      "COUNT",
      100,
    );
    keys.push(...found.slice(0, HEARTBEAT_READ_CAP - keys.length));
    cursor = next;
    if (cursor === "0") break;
  }
  if (keys.length === 0) return [];
  const values = await redis.mget(keys);
  const out: DataKeyHeartbeat[] = [];
  for (const raw of values) {
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw) as Partial<DataKeyHeartbeat>;
      if (typeof parsed.role !== "string" || !Array.isArray(parsed.keysHeld)) continue;
      out.push({
        role: parsed.role,
        keysHeld: parsed.keysHeld.filter((kid): kid is string => typeof kid === "string"),
        at: typeof parsed.at === "string" ? parsed.at : "",
      });
    } catch {
      // Malformed heartbeat: advisory data, skipped.
    }
  }
  return out.sort((a, b) => a.role.localeCompare(b.role) || a.at.localeCompare(b.at));
}
