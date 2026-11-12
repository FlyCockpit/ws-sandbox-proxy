import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import type { Principal } from "@wssp/api/sandbox/contracts";
import {
  TRANSFER_MAX_BYTES as CAP,
  TRANSFER_CHUNK_BYTES as CHUNK,
  type TransferCreate,
  UPLOAD_ROUTES,
} from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { SandboxApiEnv } from "../sandbox-api/auth.js";
import { sdkErrorResponse } from "../sandbox-api/errors.js";
import { transferSlotsInUse } from "./http-admission.js";
import { checkReservation } from "./limits.js";
import { registerUploadRoutes } from "./upload-routes.js";

const state = vi.hoisted(() => ({
  store: { create: vi.fn(), status: vi.fn(), write: vi.fn(), commit: vi.fn(), abort: vi.fn() },
}));
vi.mock("./runtime.js", () => ({ transferStore: () => state.store }));
vi.mock("@wssp/env/server", () => ({
  env: { TRANSFER_GLOBAL_ACTIVE: 16, TRANSFER_OWNER_ACTIVE: 4 },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
const principal: Principal = { kind: "session", ownerId: "owner" };
const id = randomUUID();
const receipt = (totalBytes: number, receivedBytes = 0) => ({
  id,
  sandboxId: "sandbox",
  generation: 1,
  direction: "UPLOAD",
  state: "OPEN",
  totalBytes,
  receivedBytes,
  chunkBytes: CHUNK,
  idleExpiresAt: new Date().toISOString(),
  expiresAt: new Date().toISOString(),
});
let app: Hono<SandboxApiEnv>;
const authorize = vi.fn(async () => principal);
const checkNow = vi.fn(async () => {});
beforeEach(() => {
  vi.clearAllMocks();
  checkNow.mockReset();
  app = new Hono<SandboxApiEnv>();
  app.onError((error, c) => sdkErrorResponse(c, error));
  app.use("*", async (c, next) => {
    c.set("requestId", randomUUID());
    await next();
  });
  registerUploadRoutes(app, authorize, checkNow);
  state.store.status.mockResolvedValue(receipt(CHUNK));
  state.store.write.mockResolvedValue(receipt(CHUNK, CHUNK));
});
function chunk(
  body: ReadableStream<Uint8Array> | Uint8Array,
  range = `bytes 0-${CHUNK - 1}/${CHUNK}`,
  extra: Record<string, string> = {},
  signal?: AbortSignal,
) {
  return app.request(
    new Request(`http://localhost/transfers/${id}`, {
      method: "PUT",
      body: body as RequestInit["body"],
      duplex: "half",
      signal,
      headers: { "content-type": "application/octet-stream", "content-range": range, ...extra },
    } as RequestInit),
  );
}
function generated(size: number) {
  let remaining = size;
  return new ReadableStream<Uint8Array>({
    pull(c) {
      if (!remaining) {
        c.close();
        return;
      }
      const bytes = new Uint8Array(Math.min(65536, remaining)).fill(173);
      remaining -= bytes.length;
      c.enqueue(bytes);
    },
  });
}
it.each([5 * CHUNK, 33 * CHUNK + 1, CAP])(
  "streams %i bytes through fixed HTTP chunks into a counting sink",
  async (total) => {
    let count = 0;
    let max = 0;
    state.store.status.mockImplementation(async () => receipt(total, count));
    state.store.write.mockImplementation(
      async (_owner, _id, offset: number, bytes: Uint8Array, sha?: string) => {
        expect(offset).toBe(count);
        // The store hashes its own copy; the route no longer pre-hashes.
        expect(sha).toBeUndefined();
        expect(bytes[0]).toBe(173);
        max = Math.max(max, bytes.length);
        count += bytes.length;
        return receipt(total, count);
      },
    );
    while (count < total) {
      const length = Math.min(CHUNK, total - count);
      expect(
        (await chunk(generated(length), `bytes ${count}-${count + length - 1}/${total}`)).status,
      ).toBe(200);
    }
    expect(count).toBe(total);
    expect(max).toBe(CHUNK);
  },
  30000,
);
it("rejects unknown totals malformed ranges compression and undeclared overflow before writes", async () => {
  for (const range of [
    "bytes 0-0/*",
    "bytes -1-0/1",
    "bytes 0-1/1",
    "bytes 0-0/2",
    "bytes 1-1/1048576",
    "bytes 0-1/9007199254740992",
    "bytes 0-0/1, bytes 0-0/1",
  ]) {
    expect((await chunk(new Uint8Array([1]), range)).status, range).toBe(400);
  }
  expect((await chunk(generated(CHUNK + 1))).status).toBe(413);
  expect(
    (await chunk(generated(CHUNK), undefined, { "content-length": String(CHUNK + 1) })).status,
  ).toBe(413);
  expect((await chunk(generated(CHUNK), undefined, { "content-encoding": "gzip" })).status).toBe(
    415,
  );
  expect((await chunk(new Uint8Array([1]))).status).toBe(400);
  expect((await chunk(new Uint8Array(), undefined, { "content-type": "text/plain" })).status).toBe(
    415,
  );
  expect(state.store.write).not.toHaveBeenCalled();
});
it("rejects default cap plus one at reservation before commit or content allocation", async () => {
  state.store.create.mockImplementation(async (_owner: Principal, input: TransferCreate) => {
    checkReservation(
      input.totalBytes,
      {
        maxBytes: CAP,
        diskBytes: 10 * CAP,
        globalActive: 16,
        ownerActive: 4,
        idleMs: 1,
        absoluteMs: 1,
      },
      0n,
      0,
      0,
    );
    return receipt(input.totalBytes);
  });
  const res = await app.request("/transfers", {
    method: "POST",
    headers: { "content-type": "application/json", "idempotency-key": "cap" },
    body: JSON.stringify({ sandboxId: "sandbox", guestPath: "/tmp/file", totalBytes: CAP + 1 }),
  });
  expect(res.status).toBe(413);
  expect(((await res.json()) as { error: { code: string } }).error.code).toBe("PAYLOAD_TOO_LARGE");
  expect(state.store.commit).not.toHaveBeenCalled();
  expect(state.store.write).not.toHaveBeenCalled();
});
it("cancels a stalled body releases its permit and resumes from the unchanged offset", async () => {
  const controllers: AbortController[] = [];
  let entered = 0;
  let reach!: () => void;
  const allEntered = new Promise<void>((resolve) => {
    reach = resolve;
  });
  state.store.status.mockImplementation(async () => {
    if (++entered === 4) reach();
    return receipt(CHUNK);
  });
  const requests = Array.from({ length: 4 }, () => {
    const controller = new AbortController();
    controllers.push(controller);
    return chunk(
      new ReadableStream({
        start(c) {
          c.enqueue(new Uint8Array([1]));
        },
      }),
      undefined,
      {},
      controller.signal,
    );
  });
  await allEntered;
  expect((await chunk(generated(CHUNK))).status).toBe(429);
  for (const c of controllers) c.abort();
  expect((await Promise.all(requests)).map((r) => r.status)).toEqual([400, 400, 400, 400]);
  expect(state.store.write).not.toHaveBeenCalled();
  expect((await chunk(generated(CHUNK))).status).toBe(200);
  expect(state.store.write).toHaveBeenCalledTimes(1);
});
it("registers every upload route through the same handler inventory", () => {
  const mounted = app.routes.filter((r) => r.method !== "ALL").map((r) => `${r.method} ${r.path}`);
  expect(mounted.sort()).toEqual(
    Object.values(UPLOAD_ROUTES)
      .map((r) => `${r.method.toUpperCase()} ${r.path.replace("/v1", "").replace("{id}", ":id")}`)
      .sort(),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  expect(transferSlotsInUse()).toBe(0);
});

it("bounds one MiB in one KiB pieces to three body checks plus the exit fence", async () => {
  // Deterministic elapsed time: this test measures byte cadence, not CPU speed.
  vi.spyOn(Date, "now").mockReturnValue(0);
  let pieces = 0;
  const body = new ReadableStream<Uint8Array>(
    {
      pull(c) {
        if (pieces++ === 1024) c.close();
        else c.enqueue(new Uint8Array(1024));
      },
    },
    { highWaterMark: 0 },
  );
  expect((await chunk(body)).status).toBe(200);
  expect(pieces).toBe(1025);
  expect(checkNow).toHaveBeenCalledTimes(4); // first read, one MiB, EOF, exit
  expect(authorize).toHaveBeenCalledTimes(2); // entry and pre-acceptance
  expect(state.store.write).toHaveBeenCalledTimes(1);
});

it.each(["time", "bytes"])(
  "detects mid-body revocation at the %s cadence without another read",
  async (cadence) => {
    let now = 0;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    let pieces = 0;
    let revoked = false;
    const cancel = vi.fn();
    checkNow.mockImplementation(async () => {
      if (revoked) throw new ORPCError("UNAUTHORIZED");
    });
    const stop = cadence === "time" ? 10 : 1024;
    const body = new ReadableStream<Uint8Array>(
      {
        pull(c) {
          pieces++;
          if (pieces === stop) {
            revoked = true;
            if (cadence === "time") now = 1000;
          }
          c.enqueue(new Uint8Array(1024));
        },
        cancel,
      },
      { highWaterMark: 0 },
    );
    expect((await chunk(body)).status).toBe(401);
    expect(pieces).toBe(stop);
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(state.store.write).not.toHaveBeenCalled();
  },
);

it("a transient DB failure at the body fence stays internal and releases without another read", async () => {
  let now = 0;
  vi.spyOn(Date, "now").mockImplementation(() => now);
  vi.spyOn(console, "error").mockImplementation(() => {});
  checkNow.mockResolvedValueOnce().mockRejectedValueOnce(new Error("private DB diagnostic"));
  let reads = 0;
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>(
    {
      pull(c) {
        reads++;
        now = 1000;
        c.enqueue(new Uint8Array(1024));
      },
      cancel,
    },
    { highWaterMark: 0 },
  );
  const response = await chunk(body);
  expect(response.status).toBe(500);
  expect(await response.json()).toMatchObject({ error: { code: "INTERNAL_SERVER_ERROR" } });
  expect(checkNow).toHaveBeenCalledTimes(3); // first, failed cadence, recovered exit
  expect(reads).toBe(1);
  expect(cancel).toHaveBeenCalledTimes(1);
  expect(state.store.write).not.toHaveBeenCalled();
  expect(transferSlotsInUse()).toBe(0);
});
