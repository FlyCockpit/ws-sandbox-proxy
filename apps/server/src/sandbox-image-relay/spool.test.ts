import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { afterEach, describe, expect, it } from "vitest";
import { ImageRelaySpool, SpoolError } from "./spool";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});
function spool(max = 1 << 20) {
  const dir = mkdtempSync(join(tmpdir(), "wssp-spool-test-"));
  dirs.push(dir);
  return new ImageRelaySpool(join(dir, "spool"), max);
}
/** A body that yields `size` bytes only after `gate` resolves. */
function slowBody(size: number, gate: Promise<void>) {
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      await gate;
      controller.enqueue(new Uint8Array(size).fill(7));
      controller.close();
    },
  });
}
const body = (size: number) => slowBody(size, Promise.resolve());

const waiterKeys = (s: ImageRelaySpool) => [
  ...(s as unknown as { waiters: Map<string, Set<unknown>> }).waiters.keys(),
];

describe("image relay spool waiters", () => {
  it("a timed-out last waiter leaves no empty set behind", async () => {
    const s = spool();
    expect(await s.waitFor("w1", 1, 5)).toBeNull();
    expect(waiterKeys(s)).toEqual([]);
    // One of two waiters timing out keeps the other's set.
    const long = s.waitFor("w1", 2, 60_000);
    expect(await s.waitFor("w1", 2, 5)).toBeNull();
    expect(waiterKeys(s)).toEqual(["w1:2"]);
    const spooled = await s.put("w1", 2, 4, body(4));
    expect(await long).toEqual(spooled);
    expect(waiterKeys(s)).toEqual([]);
  });

  it("dropTransfer wakes only that transfer's waiters with null", async () => {
    const s = spool();
    const dropped = s.waitFor("w2", 1, 60_000);
    const other = s.waitFor("w3", 1, 60_000);
    await s.dropTransfer("w2");
    expect(await dropped).toBeNull();
    expect(waiterKeys(s)).toEqual(["w3:1"]);
    await s.put("w3", 1, 4, body(4));
    expect(await other).not.toBeNull();
  });

  it("reset wakes every waiter with null", async () => {
    const s = spool();
    const waits = [s.waitFor("w4", 1, 60_000), s.waitFor("w5", 3, 60_000)];
    await s.reset();
    expect(await Promise.all(waits)).toEqual([null, null]);
    expect(waiterKeys(s)).toEqual([]);
  });
});

describe("image relay spool", () => {
  it("P2-10: a concurrent PUT of the same part is refused before IO and never deletes the writer's file", async () => {
    const s = spool();
    let release!: () => void;
    const first = s.put("t1", 1, 1024, slowBody(1024, new Promise((r) => (release = r))));
    await expect(s.put("t1", 1, 1024, body(1024))).rejects.toMatchObject({
      code: "duplicate",
      status: 409,
    });
    release();
    const spooled = await first;
    expect(statSync(spooled.path).size).toBe(1024);
    expect(s.usedBytes).toBe(1024);
    // A completed part is a duplicate too, and still intact afterwards.
    await expect(s.put("t1", 1, 1024, body(1024))).rejects.toBeInstanceOf(SpoolError);
    expect(statSync(spooled.path).size).toBe(1024);
  });

  it("a failed write releases its reservation and only its own file", async () => {
    const s = spool();
    await expect(s.put("t2", 1, 10, body(11))).rejects.toMatchObject({ code: "too_large" });
    expect(s.usedBytes).toBe(0);
    expect(s.has("t2", 1)).toBe(false);
    await s.put("t2", 1, 10, body(10));
    expect(s.transferIds()).toEqual(["t2"]);
    await s.dropTransfer("t2");
    expect(s.transferIds()).toEqual([]);
    expect(s.usedBytes).toBe(0);
  });

  it("a full spool refuses before reserving", async () => {
    const s = spool(100);
    await expect(s.put("t3", 1, 101, body(101))).rejects.toMatchObject({ code: "spool_full" });
    expect(s.usedBytes).toBe(0);
  });
});

describe("image relay spool cancellation (round-2 P2-6)", () => {
  it("dropTransfer aborts a paused writer, releases its reservation once and never publishes the part", async () => {
    const s = spool(4096);
    let release!: () => void;
    const paused = s.put("t4", 1, 1024, slowBody(1024, new Promise((r) => (release = r))));
    const outcome = paused.then(
      () => "published",
      (error: SpoolError) => error.code,
    );
    // The in-flight writer is visible to reconciliation.
    expect(s.transferIds()).toEqual(["t4"]);
    expect(s.usedBytes).toBe(1024);
    await s.dropTransfer("t4");
    // Released when the drop returns, not when the slow source finishes.
    expect(s.usedBytes).toBe(0);
    expect(s.transferIds()).toEqual([]);
    release();
    expect(await outcome).toBe("ended");
    expect(s.has("t4", 1)).toBe(false);
    expect(s.usedBytes).toBe(0);
    // A late PUT of the ended transfer (a link consumed before the drop) is refused.
    await expect(s.put("t4", 2, 10, body(10))).rejects.toMatchObject({ code: "ended" });
    expect(s.usedBytes).toBe(0);
    // Other transfers are unaffected.
    await s.put("t5", 1, 10, body(10));
    expect(s.usedBytes).toBe(10);
  });

  it("a writer that finishes while its transfer is being dropped is not published", async () => {
    const s = spool(4096);
    const done = s.put("t6", 1, 10, body(10));
    const dropped = s.dropTransfer("t6");
    await expect(done).rejects.toMatchObject({ code: "ended" });
    await dropped;
    expect(s.has("t6", 1)).toBe(false);
    expect(s.usedBytes).toBe(0);
  });
});

describe("image relay spool cancellation of a streaming PUT (round-3 P2-3)", () => {
  it("dropTransfer settles promptly while a real loopback PUT is paused mid-stream", async () => {
    const s = spool(4096);
    const outcomes: string[] = [];
    let entered!: () => void;
    const started = new Promise<void>((r) => (entered = r));
    const app = new Hono().put("/part", async (c) => {
      entered();
      try {
        await s.put("t7", 1, 1024, c.req.raw.body);
        outcomes.push("published");
      } catch (error) {
        outcomes.push((error as SpoolError).code);
      }
      return c.body(null, 204);
    });
    const server = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" });
    await new Promise<void>((r) => server.once("listening", () => r()));
    const { port } = server.address() as AddressInfo;
    // The in-process test I/O guard blocks outbound TCP: the client is a child
    // process that sends 100 of 1,024 bytes, then pauses with the body open.
    const client = spawn(process.execPath, ["-e", PAUSED_PUT, String(port)], {
      stdio: ["ignore", "ignore", "ignore"],
    });
    try {
      await started;
      // Let the first chunk reach the writer, so streaming has begun.
      for (let i = 0; i < 50 && !statOk(s); i++) await new Promise((r) => setTimeout(r, 10));
      expect(s.usedBytes).toBe(1024);
      const settled = await Promise.race([
        s.dropTransfer("t7").then(() => "settled"),
        new Promise((r) => setTimeout(() => r("pending"), 2000)),
      ]);
      expect(settled).toBe("settled");
      expect(s.usedBytes).toBe(0);
      expect(s.transferIds()).toEqual([]);
      expect(s.has("t7", 1)).toBe(false);
      for (let i = 0; i < 100 && outcomes.length === 0; i++)
        await new Promise((r) => setTimeout(r, 10));
      expect(outcomes).toEqual(["ended"]);
      // Released exactly once: nothing below zero, and new work is admitted.
      expect(s.usedBytes).toBe(0);
      await s.put("t8", 1, 4096, body(4096));
      expect(s.usedBytes).toBe(4096);
    } finally {
      client.kill("SIGKILL");
      await new Promise((r) => server.close(r));
    }
  });
});

const PAUSED_PUT = `
const http = require("node:http");
const req = http.request({ host: "127.0.0.1", port: Number(process.argv[1]), path: "/part",
  method: "PUT", headers: { "content-length": "1024" } });
req.on("error", () => {});
req.write(Buffer.alloc(100, 7));
setInterval(() => {}, 1000);
`;

/** True once the paused writer's file holds the first streamed bytes. */
function statOk(s: ImageRelaySpool): boolean {
  const dir = (s as unknown as { dir: string }).dir;
  try {
    return statSync(join(dir, "t7.1.part")).size > 0;
  } catch {
    return false;
  }
}
