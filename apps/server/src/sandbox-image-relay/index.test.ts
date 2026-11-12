import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ live: [] as { id: string }[], where: null as unknown }));
vi.mock("@wssp/env/server", () => ({
  env: { IMAGE_RELAY_SPOOL_DIR: "/nonexistent", IMAGE_RELAY_SPOOL_BYTES: 1 },
}));
vi.mock("@wssp/db", () => ({
  default: {
    sandboxImageTransfer: {
      findMany: vi.fn(async (args: { where: unknown }) => {
        mocks.where = args.where;
        return mocks.live;
      }),
    },
  },
}));

const { reconcileImageRelaySpool } = await import("./index.js");
const { ImageRelaySpool } = await import("./spool.js");

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});
const body = (size: number) =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(size));
      controller.close();
    },
  });

describe("relay spool reconciliation (P2-13)", () => {
  it("drops parts and reservations of transfers no longer OPEN or past expiry; keeps live ones", async () => {
    const dir = mkdtempSync(join(tmpdir(), "wssp-spool-reconcile-"));
    dirs.push(dir);
    const spool = new ImageRelaySpool(join(dir, "spool"), 1 << 20);
    await spool.put("live", 1, 100, body(100));
    await spool.put("expired", 1, 200, body(200));
    await spool.put("expired", 2, 300, body(300));
    mocks.live = [{ id: "live" }];
    const now = new Date();
    expect(await reconcileImageRelaySpool(spool, now)).toBe(1);
    expect(spool.transferIds()).toEqual(["live"]);
    expect(spool.usedBytes).toBe(100);
    expect(mocks.where).toEqual({
      id: { in: ["live", "expired"] },
      state: "OPEN",
      expiresAt: { gt: now },
    });
  });
});
