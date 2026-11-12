import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  downloadUrl,
  probeDownload,
  THROTTLE_MAX_WAIT_MS,
  THROTTLE_MAX_WAITS,
  TRANSFER_CHUNK_BYTES,
  TRANSFER_MAX_BYTES,
  TransferError,
  uploadToSandbox,
} from "./sandbox-transfers";

/**
 * The browser transfer adapter against a scripted `fetch`: cookie-only
 * (`credentials: "include"`, no Authorization header), exact chunk ranges,
 * a whole-file SHA-256 commit, caps enforced before any byte, and a failed
 * or cancelled upload releasing its reservation.
 */

const SERVER = "https://app.example.test";
const TRANSFER = "3f7c1f1e-5a0b-4c7e-9d2a-1b2c3d4e5f60";

type Call = { method: string; url: string; headers: Record<string, string>; body?: Uint8Array };

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function fakeServer(
  respond: (call: Call, index: number) => Response | Promise<Response> | "network",
) {
  const calls: Call[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = Object.fromEntries(new Headers(init?.headers).entries());
    if (init?.credentials !== "include") throw new Error("expected cookie credentials");
    const body =
      init?.body instanceof Uint8Array
        ? new Uint8Array(init.body)
        : typeof init?.body === "string"
          ? new TextEncoder().encode(init.body)
          : undefined;
    const call = { method: init?.method ?? "GET", url: String(input), headers, body };
    calls.push(call);
    const answer = await respond(call, calls.length - 1);
    if (answer === "network") throw new TypeError("Failed to fetch");
    return answer;
  }) as typeof fetch;
  return { calls, fetchImpl };
}

function bytes(size: number) {
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) data[i] = (i * 31 + 7) % 251;
  return data;
}

const receipt = (received = 0) => ({ id: TRANSFER, receivedBytes: received });

describe("upload", () => {
  it("creates, sends exact 1 MiB ranges, commits the whole-file SHA-256, cookie-only", async () => {
    const data = bytes(TRANSFER_CHUNK_BYTES * 2 + 5);
    const server = fakeServer((call) => {
      if (call.method === "POST" && call.url.endsWith("/transfers")) return json(201, receipt());
      if (call.method === "PUT") return json(200, receipt());
      if (call.url.endsWith("/commit")) return json(202, { operationId: "op-1", state: "QUEUED" });
      return json(500, {});
    });
    const progress: number[] = [];
    const result = await uploadToSandbox(
      { serverUrl: `${SERVER}/`, fetch: server.fetchImpl, random: () => "r" },
      {
        sandboxId: "sbx-1",
        guestPath: "/home/user/data.bin",
        file: new Blob([data]),
        onProgress: (sent) => progress.push(sent),
      },
    );
    const sha = createHash("sha256").update(data).digest("hex");
    expect(result).toEqual({ transferId: TRANSFER, operationId: "op-1", sha256: sha });
    expect(server.calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `POST ${SERVER}/api/dashboard/transfers`,
      `PUT ${SERVER}/api/dashboard/transfers/${TRANSFER}`,
      `PUT ${SERVER}/api/dashboard/transfers/${TRANSFER}`,
      `PUT ${SERVER}/api/dashboard/transfers/${TRANSFER}`,
      `POST ${SERVER}/api/dashboard/transfers/${TRANSFER}/commit`,
    ]);
    const [create, ...rest] = server.calls;
    expect(JSON.parse(new TextDecoder().decode(create!.body))).toEqual({
      sandboxId: "sbx-1",
      guestPath: "/home/user/data.bin",
      totalBytes: data.length,
    });
    expect(create!.headers["idempotency-key"]).toBe("web.upload.r");
    const puts = rest.filter((call) => call.method === "PUT");
    const total = data.length;
    expect(puts.map((call) => call.headers["content-range"])).toEqual([
      `bytes 0-${TRANSFER_CHUNK_BYTES - 1}/${total}`,
      `bytes ${TRANSFER_CHUNK_BYTES}-${2 * TRANSFER_CHUNK_BYTES - 1}/${total}`,
      `bytes ${2 * TRANSFER_CHUNK_BYTES}-${total - 1}/${total}`,
    ]);
    expect(puts.map((call) => call.body?.length)).toEqual([
      TRANSFER_CHUNK_BYTES,
      TRANSFER_CHUNK_BYTES,
      5,
    ]);
    expect(puts[2]!.body).toEqual(data.subarray(2 * TRANSFER_CHUNK_BYTES));
    const commit = server.calls.at(-1)!;
    expect(JSON.parse(new TextDecoder().decode(commit.body))).toEqual({ sha256: sha });
    expect(commit.headers["idempotency-key"]).toBe("web.upload-commit.r");
    // The session cookie is the only credential: no bearer/SDK key anywhere.
    for (const call of server.calls) {
      expect(call.headers.authorization).toBeUndefined();
      expect(JSON.stringify(call.headers)).not.toContain("wssp_");
    }
    expect(progress).toEqual([0, TRANSFER_CHUNK_BYTES, 2 * TRANSFER_CHUNK_BYTES, total]);
  });

  it("an empty file commits the empty digest without a chunk", async () => {
    const server = fakeServer((call) =>
      call.url.endsWith("/commit")
        ? json(202, { operationId: "op-0" })
        : json(201, { id: TRANSFER }),
    );
    const result = await uploadToSandbox(
      { serverUrl: SERVER, fetch: server.fetchImpl },
      { sandboxId: "s", guestPath: "/e", file: new Blob([]) },
    );
    expect(result.sha256).toBe(createHash("sha256").digest("hex"));
    expect(server.calls.filter((call) => call.method === "PUT")).toEqual([]);
  });

  it("a file over the product cap is refused before any request", async () => {
    const server = fakeServer(() => json(500, {}));
    const huge = { size: TRANSFER_MAX_BYTES + 1, slice: () => new Blob([]) } as unknown as Blob;
    await expect(
      uploadToSandbox(
        { serverUrl: SERVER, fetch: server.fetchImpl },
        { sandboxId: "s", guestPath: "/big", file: huge },
      ),
    ).rejects.toMatchObject({ problem: "tooLarge" });
    expect(server.calls).toEqual([]);
  });

  it("the server's lower cap refuses the reservation before any byte is sent", async () => {
    const server = fakeServer(() => json(413, { error: { code: "PAYLOAD_TOO_LARGE" } }));
    await expect(
      uploadToSandbox(
        { serverUrl: SERVER, fetch: server.fetchImpl },
        { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(10)]) },
      ),
    ).rejects.toMatchObject({ problem: "tooLarge", status: 413 });
    expect(server.calls.map((call) => call.method)).toEqual(["POST"]);
  });

  it("a session revoked mid-upload stops it and releases the reservation", async () => {
    const server = fakeServer((call, index) => {
      if (index === 0) return json(201, receipt());
      if (call.method === "PUT" && index === 1) return json(200, receipt(TRANSFER_CHUNK_BYTES));
      if (call.method === "PUT") return json(403, { error: { code: "FORBIDDEN" } });
      return json(200, receipt());
    });
    await expect(
      uploadToSandbox(
        { serverUrl: SERVER, fetch: server.fetchImpl },
        { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(TRANSFER_CHUNK_BYTES + 1)]) },
      ),
    ).rejects.toMatchObject({ problem: "forbidden", status: 403 });
    expect(server.calls.map((call) => call.method)).toEqual(["POST", "PUT", "PUT", "DELETE"]);
    expect(server.calls.some((call) => call.url.endsWith("/commit"))).toBe(false);
  });

  it("a quota refusal is explained as such", async () => {
    const server = fakeServer(() => json(429, { error: { code: "TRANSFER_QUOTA" } }));
    await expect(
      uploadToSandbox(
        { serverUrl: SERVER, fetch: server.fetchImpl },
        { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(3)]) },
      ),
    ).rejects.toMatchObject({ problem: "quota" });
  });

  it("a lost chunk response is resent identically, and a lost commit replays its key", async () => {
    let putFailures = 1;
    let commitFailures = 1;
    const server = fakeServer((call) => {
      if (call.method === "POST" && call.url.endsWith("/transfers")) return json(201, receipt());
      if (call.method === "PUT" && putFailures-- > 0) return "network";
      if (call.method === "PUT") return json(200, receipt());
      if (commitFailures-- > 0) return "network";
      return json(202, { operationId: "op-2" });
    });
    const data = bytes(10);
    await expect(
      uploadToSandbox(
        { serverUrl: SERVER, fetch: server.fetchImpl },
        { sandboxId: "s", guestPath: "/f", file: new Blob([data]) },
      ),
    ).resolves.toMatchObject({ operationId: "op-2" });
    const puts = server.calls.filter((call) => call.method === "PUT");
    expect(puts).toHaveLength(2);
    expect(puts[1]!.body).toEqual(puts[0]!.body);
    expect(puts[1]!.headers["content-range"]).toBe(puts[0]!.headers["content-range"]);
    const commits = server.calls.filter((call) => call.url.endsWith("/commit"));
    expect(commits).toHaveLength(2);
    expect(commits[1]!.headers["idempotency-key"]).toBe(commits[0]!.headers["idempotency-key"]);
  });

  it("cancelling stops before the next chunk and releases the reservation", async () => {
    const controller = new AbortController();
    const server = fakeServer((call) => {
      if (call.method === "POST") return json(201, receipt());
      if (call.method === "PUT") {
        controller.abort();
        return json(200, receipt());
      }
      return json(200, receipt());
    });
    const error = await uploadToSandbox(
      { serverUrl: SERVER, fetch: server.fetchImpl },
      {
        sandboxId: "s",
        guestPath: "/f",
        file: new Blob([bytes(TRANSFER_CHUNK_BYTES + 1)]),
        signal: controller.signal,
      },
    ).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(TransferError);
    expect((error as TransferError).problem).toBe("cancelled");
    expect(server.calls.map((call) => call.method)).toEqual(["POST", "PUT", "DELETE"]);
  });

  /** The server accepts the commit; the browser cancels before its answer arrives. */
  function cancelDuringCommit(afterCancel: (call: Call) => Response) {
    const controller = new AbortController();
    let commits = 0;
    const server = fakeServer((call) => {
      if (call.method === "POST" && call.url.endsWith("/transfers")) return json(201, receipt());
      if (call.method === "PUT") return json(200, receipt());
      if (call.url.endsWith("/commit") && commits++ === 0) {
        controller.abort();
        return "network";
      }
      return afterCancel(call);
    });
    const result = uploadToSandbox(
      { serverUrl: SERVER, fetch: server.fetchImpl, random: () => "k" },
      { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(10)]), signal: controller.signal },
    );
    return { server, result };
  }

  it("a cancel after the commit was accepted recovers its receipt instead of claiming nothing was written", async () => {
    const { server, result } = cancelDuringCommit((call) =>
      call.method === "DELETE"
        ? json(409, { error: { code: "CONFLICT" } })
        : json(200, { operationId: "op-landed", state: "QUEUED" }),
    );
    await expect(result).resolves.toMatchObject({ operationId: "op-landed" });
    const commits = server.calls.filter((call) => call.url.endsWith("/commit"));
    expect(commits).toHaveLength(2);
    expect(commits[1]!.headers["idempotency-key"]).toBe("web.upload-commit.k");
    expect(commits[1]!.body).toEqual(commits[0]!.body);
  });

  it("a cancel after commit whose outcome cannot be recovered is reported as uncertain", async () => {
    const { result } = cancelDuringCommit(() => json(409, { error: { code: "CONFLICT" } }));
    await expect(result).rejects.toMatchObject({ problem: "uncertain" });
  });

  /** Headers arrive, then the body is lost (the stream errors mid-read). */
  const bodyLost = (status: number) =>
    new Response(
      new ReadableStream({
        start(controller) {
          controller.error(new TypeError("network error"));
        },
      }),
      { status, headers: { "content-type": "application/json" } },
    );

  it("a recovered receipt whose body is lost is reported as uncertain, not as a failure", async () => {
    const { server, result } = cancelDuringCommit((call) =>
      call.method === "DELETE" ? json(409, { error: { code: "CONFLICT" } }) : bodyLost(202),
    );
    await expect(result).rejects.toMatchObject({ problem: "uncertain" });
    expect(server.calls.filter((call) => call.url.endsWith("/commit"))).toHaveLength(2);
  });

  it("an accepted commit whose body is lost is recovered by replaying its key", async () => {
    let commits = 0;
    const server = fakeServer((call) => {
      if (call.method === "POST" && call.url.endsWith("/transfers")) return json(201, receipt());
      if (call.method === "PUT") return json(200, receipt());
      if (call.method === "DELETE") return json(409, { error: { code: "CONFLICT" } });
      return commits++ === 0 ? bodyLost(202) : json(200, { operationId: "op-body" });
    });
    await expect(
      uploadToSandbox(
        { serverUrl: SERVER, fetch: server.fetchImpl, random: () => "b" },
        { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(4)]) },
      ),
    ).resolves.toMatchObject({ operationId: "op-body" });
    const commitCalls = server.calls.filter((call) => call.url.endsWith("/commit"));
    expect(commitCalls.map((call) => call.headers["idempotency-key"])).toEqual([
      "web.upload-commit.b",
      "web.upload-commit.b",
    ]);
  });

  it.each([
    ["a 401", () => json(401, { error: { code: "UNAUTHORIZED" } })],
    ["exhausted throttling", () => throttled("1")],
  ])(
    "a lost commit followed by %s on every later request is reported as uncertain",
    async (_label, refusal) => {
      let commits = 0;
      const server = fakeServer((call) => {
        if (call.method === "POST" && call.url.endsWith("/transfers")) return json(201, receipt());
        if (call.method === "PUT") return json(200, receipt());
        // The first commit is accepted, but its answer never arrives.
        if (call.url.endsWith("/commit") && commits++ === 0) return "network";
        return refusal();
      });
      const error = await uploadToSandbox(
        { serverUrl: SERVER, fetch: server.fetchImpl, random: () => "u", wait: async () => {} },
        { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(4)]) },
      ).catch((caught: unknown) => caught);
      expect(error).toMatchObject({ problem: "uncertain" });
      // Recovery was attempted: an abort, and a replay under the original key.
      expect(server.calls.some((call) => call.method === "DELETE")).toBe(true);
      const commitCalls = server.calls.filter((call) => call.url.endsWith("/commit"));
      expect(new Set(commitCalls.map((call) => call.headers["idempotency-key"]))).toEqual(
        new Set(["web.upload-commit.u"]),
      );
      expect(commitCalls.length).toBeGreaterThanOrEqual(3);
    },
  );

  it.each([
    [403, "FORBIDDEN"],
    [404, "NOT_FOUND"],
  ])("an accepted first commit answered %i is recovered from its receipt", async (status, code) => {
    let commits = 0;
    const server = fakeServer((call) => {
      if (call.method === "POST" && call.url.endsWith("/transfers")) return json(201, receipt());
      if (call.method === "PUT") return json(200, receipt());
      if (call.method === "DELETE") return json(409, { error: { code: "CONFLICT" } });
      // The operation is durable, but the post-commit check answers the error.
      return commits++ === 0
        ? json(status, { error: { code } })
        : json(200, { operationId: "op-late" });
    });
    await expect(
      uploadToSandbox(
        { serverUrl: SERVER, fetch: server.fetchImpl, random: () => "f" },
        { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(4)]) },
      ),
    ).resolves.toMatchObject({ operationId: "op-late" });
    const commitCalls = server.calls.filter((call) => call.url.endsWith("/commit"));
    expect(commitCalls.map((call) => call.headers["idempotency-key"])).toEqual([
      "web.upload-commit.f",
      "web.upload-commit.f",
    ]);
    expect(server.calls.some((call) => call.method === "DELETE")).toBe(true);
  });

  it.each([
    [403, "FORBIDDEN"],
    [404, "NOT_FOUND"],
  ])(
    "a first commit answered %i whose receipt cannot be recovered is reported as uncertain",
    async (status, code) => {
      const server = fakeServer((call) => {
        if (call.method === "POST" && call.url.endsWith("/transfers")) return json(201, receipt());
        if (call.method === "PUT") return json(200, receipt());
        if (call.method === "DELETE") return json(409, { error: { code: "CONFLICT" } });
        return json(status, { error: { code } });
      });
      await expect(
        uploadToSandbox(
          { serverUrl: SERVER, fetch: server.fetchImpl },
          { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(4)]) },
        ),
      ).rejects.toMatchObject({ problem: "uncertain" });
      expect(server.calls.filter((call) => call.url.endsWith("/commit"))).toHaveLength(2);
    },
  );

  it("a first commit refused with 403 is settled as nothing written when the abort succeeds", async () => {
    const server = fakeServer((call) => {
      if (call.method === "POST" && call.url.endsWith("/transfers")) return json(201, receipt());
      if (call.method === "PUT") return json(200, receipt());
      if (call.method === "DELETE") return json(200, { ...receipt(), state: "ABORTED" });
      return json(403, { error: { code: "FORBIDDEN" } });
    });
    const error = await uploadToSandbox(
      { serverUrl: SERVER, fetch: server.fetchImpl },
      { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(4)]) },
    ).catch((caught: unknown) => caught);
    expect(error).toMatchObject({ status: 403 });
    expect(error).not.toMatchObject({ problem: "uncertain" });
    expect(server.calls.filter((call) => call.url.endsWith("/commit"))).toHaveLength(1);
  });

  it("a lost commit then a refusal is still settled as nothing written when the abort succeeds", async () => {
    let commits = 0;
    const server = fakeServer((call) => {
      if (call.method === "POST" && call.url.endsWith("/transfers")) return json(201, receipt());
      if (call.method === "PUT") return json(200, receipt());
      if (call.method === "DELETE") return json(200, { ...receipt(), state: "ABORTED" });
      return commits++ === 0 ? "network" : json(400, { error: { code: "BAD_REQUEST" } });
    });
    await expect(
      uploadToSandbox(
        { serverUrl: SERVER, fetch: server.fetchImpl },
        { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(4)]) },
      ),
    ).rejects.toMatchObject({ problem: "invalid" });
  });

  it("a cancel after commit is reported as nothing written only once the abort succeeds", async () => {
    const { server, result } = cancelDuringCommit((call) =>
      call.method === "DELETE" ? json(200, { ...receipt(), state: "ABORTED" }) : json(500, {}),
    );
    await expect(result).rejects.toMatchObject({ problem: "cancelled" });
    expect(server.calls.filter((call) => call.url.endsWith("/commit"))).toHaveLength(1);
  });

  // The request limiter's actual rejection (apps/server/src/rate-limit.ts).
  const throttled = (retryAfter: string | null) =>
    new Response(
      JSON.stringify({ error: "Too many attempts. Please wait a moment and try again." }),
      {
        status: 429,
        headers: {
          "content-type": "application/json",
          ...(retryAfter == null ? {} : { "retry-after": retryAfter }),
        },
      },
    );

  it("request throttling waits out Retry-After and keeps the transfer; only the quota code is quota", async () => {
    const data = bytes(TRANSFER_CHUNK_BYTES * 3);
    let putIndex = 0;
    let commitThrottled = false;
    const server = fakeServer((call) => {
      if (call.method === "POST" && call.url.endsWith("/transfers")) return json(201, receipt());
      if (call.method === "PUT")
        return putIndex++ % 2 === 0 ? throttled("7") : json(200, receipt());
      if (!commitThrottled) {
        commitThrottled = true;
        return throttled(null);
      }
      return json(202, { operationId: "op-t" });
    });
    const waits: number[] = [];
    await expect(
      uploadToSandbox(
        {
          serverUrl: SERVER,
          fetch: server.fetchImpl,
          wait: async (ms) => {
            waits.push(ms);
          },
        },
        { sandboxId: "s", guestPath: "/f", file: new Blob([data]) },
      ),
    ).resolves.toMatchObject({ operationId: "op-t" });
    expect(waits).toEqual([7000, 7000, 7000, 1000]);
    expect(server.calls.some((call) => call.method === "DELETE")).toBe(false);
    const ranges = server.calls
      .filter((call) => call.method === "PUT")
      .map((call) => call.headers["content-range"]);
    expect(new Set(ranges).size).toBe(3);
    expect(ranges).toHaveLength(6);
  });

  it("throttle waits are bounded, and a cancel during one stops at once", async () => {
    const server = fakeServer((call) =>
      call.method === "POST" ? json(201, receipt()) : throttled("3600"),
    );
    const waits: number[] = [];
    const error = await uploadToSandbox(
      {
        serverUrl: SERVER,
        fetch: server.fetchImpl,
        wait: async (ms) => {
          waits.push(ms);
        },
      },
      { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(3)]) },
    ).catch((caught: unknown) => caught);
    expect(error).toMatchObject({ problem: "busy", status: 429 });
    expect(waits.every((ms) => ms === THROTTLE_MAX_WAIT_MS)).toBe(true);
    // One request's bounded waits, plus the background release's.
    expect(waits.length).toBeLessThanOrEqual(THROTTLE_MAX_WAITS * 2);
    expect(waits.length).toBeGreaterThanOrEqual(THROTTLE_MAX_WAITS);

    const controller = new AbortController();
    const cancelled = await uploadToSandbox(
      {
        serverUrl: SERVER,
        fetch: fakeServer((call) =>
          call.method === "POST" ? json(201, receipt()) : throttled("30"),
        ).fetchImpl,
        wait: (_ms, signal) =>
          new Promise((_resolve, reject) => {
            signal?.addEventListener("abort", () => reject(new TransferError("cancelled")));
            controller.abort();
          }),
      },
      { sandboxId: "s", guestPath: "/f", file: new Blob([bytes(3)]), signal: controller.signal },
    ).catch((caught: unknown) => caught);
    expect(cancelled).toMatchObject({ problem: "cancelled" });
  });
});

describe("download", () => {
  it("saves from the cookie-session content route", () => {
    expect(downloadUrl({ serverUrl: SERVER }, "op 1")).toBe(
      `${SERVER}/api/dashboard/operations/op%201/content`,
    );
  });

  it("probes with HEAD and explains an expired capture or a refused session", async () => {
    const ok = fakeServer(
      () => new Response(null, { status: 200, headers: { "content-length": "42" } }),
    );
    await expect(
      probeDownload({ serverUrl: SERVER, fetch: ok.fetchImpl }, "op-1"),
    ).resolves.toEqual({ sizeBytes: 42 });
    expect(ok.calls[0]).toMatchObject({
      method: "HEAD",
      url: `${SERVER}/api/dashboard/operations/op-1/content`,
    });
    for (const [status, problem] of [
      [410, "expired"],
      [403, "forbidden"],
      [404, "notFound"],
      [409, "conflict"],
    ] as const) {
      const server = fakeServer(() => new Response(null, { status }));
      await expect(
        probeDownload({ serverUrl: SERVER, fetch: server.fetchImpl }, "op-1"),
      ).rejects.toMatchObject({ problem });
    }
  });
});
