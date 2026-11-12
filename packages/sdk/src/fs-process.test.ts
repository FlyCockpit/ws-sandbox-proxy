import { readFileSync } from "node:fs";
import { inspect } from "node:util";
import {
  type EntryInfo,
  type OperationErrorCode,
  type ProcessRef,
  SDK_ERRORS,
  type SdkErrorCode,
} from "@wssp/sandbox-contracts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createWsspClient } from "./client";
import type { RunOptions } from "./commands";
import { CommandExitError, FileSystemError, ProcessError, WsspError } from "./errors";
import type { FetchLike } from "./transport";

const zeroPolicy = vi.hoisted(() => ({ enabled: false }));
vi.mock("../../sandbox-contracts/src/command-timeout-policy", () => ({
  get commandTimeoutZeroEnabled() {
    return zeroPolicy.enabled;
  },
}));
afterEach(() => {
  zeroPolicy.enabled = false;
});

const NOW = "2026-10-28T00:00:00.000Z";
const LATER = "2026-10-28T01:00:00.000Z";
const REF: ProcessRef = { sandboxId: "sbx", generation: 1, processId: "proc", attempt: 1, pid: 42 };
const PRIVATE = ["private", "description", "sentinel"].join("-");
const KEY = ["wssp", "sdk", "fixture"].join("_");
const entry: EntryInfo = {
  name: "a",
  path: "/a",
  type: "file",
  size: 23,
  mode: 420,
  permissions: "rw-r--r--",
  uid: 1000,
  gid: 1000,
  owner: null,
  group: null,
  modifiedTime: NOW,
  symlinkTarget: null,
};
function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
function error(code: SdkErrorCode) {
  return json(
    {
      error: {
        code,
        message: SDK_ERRORS[code][1],
        requestId: "7f412cfa-bc9a-402b-a20b-b0801893fdfd",
      },
    },
    SDK_ERRORS[code][0],
  );
}
function receipt(id = "op", state = "QUEUED") {
  return json({ operationId: id, state, location: `/v1/operations/${id}` }, 202);
}
function status(over: Record<string, unknown> = {}) {
  return {
    id: "op",
    sandboxId: "sbx",
    generation: 1,
    kind: "RUN_COMMAND",
    state: "SUCCEEDED",
    outcome: "succeeded",
    errorCode: null,
    failure: null,
    leaseIntent: null,
    createdAt: NOW,
    updatedAt: NOW,
    dispatchedAt: NOW,
    completedAt: NOW,
    ...over,
  };
}
function result(body: unknown, over: Record<string, unknown> = {}) {
  return {
    operationId: "op",
    sandboxId: "sbx",
    generation: 1,
    kind: "RUN_COMMAND",
    outcome: "succeeded",
    observedAt: NOW,
    expiresAt: null,
    result: body,
    ...over,
  };
}
function commandResult(exitCode: number | null = null) {
  return result(
    { type: "command", process: REF, startedAt: NOW, exitCode },
    { outcome: exitCode === null ? "pending" : "succeeded" },
  );
}
function connection(offset = 4) {
  return {
    info: {
      process: REF,
      operationId: "op",
      kind: "command",
      cmd: "sh",
      args: [],
      argsTruncated: false,
      cwd: "/",
      startedAt: NOW,
      observedAt: NOW,
    },
    state: "RUNNING",
    exitCode: null,
    outputOperationId: "op",
    attempt: 1,
    attachmentCursor: `1_${offset}`,
  };
}
function output(exitCode = 7, over: Record<string, unknown> = {}) {
  return {
    operationId: "op",
    state: "SUCCEEDED",
    exitCode,
    attempt: 1,
    reset: false,
    offset: 0,
    chunks: [],
    gaps: [],
    nextCursor: "1_0",
    hasMore: false,
    receivedBytes: 0,
    totalBytes: 0,
    retainedBytes: 0,
    truncated: false,
    complete: true,
    expiresAt: LATER,
    ...over,
  };
}
function chunk(stream: "stdout" | "stderr", offset: number, text: string) {
  return { stream, offset, data: Buffer.from(text).toString("base64") };
}
type Call = { url: URL; init: RequestInit };
type Step = Response | ((call: Call) => Response | Promise<Response>);
function harness(...steps: Step[]) {
  const calls: Call[] = [];
  const fetch: FetchLike = async (url, init) => {
    const call = { url: new URL(url), init };
    calls.push(call);
    const step = steps.shift();
    if (!step) throw new Error("Unexpected fixture request.");
    return typeof step === "function" ? step(call) : step;
  };
  const client = createWsspClient({
    baseUrl: "https://api.example.test",
    apiKey: KEY,
    fetch,
    polling: { intervalMs: 1, maxIntervalMs: 1, waitTimeoutMs: 1000 },
  });
  return { client, calls, remaining: () => steps.length };
}
function body(call: Call | undefined) {
  return JSON.parse(String(call?.init.body)) as Record<string, unknown>;
}
async function rejected(promise: Promise<unknown>): Promise<WsspError> {
  const caught = await promise.then(
    () => null,
    (caught: unknown) => caught,
  );
  expect(caught).toBeInstanceOf(WsspError);
  return caught as WsspError;
}
function safe(caught: WsspError) {
  for (const automatic of [
    String(caught),
    caught.stack ?? "",
    inspect(caught),
    JSON.stringify(caught),
  ])
    expect(automatic).not.toContain(PRIVATE);
  expect(caught.cause).toBeUndefined();
}
afterEach(() => vi.useRealTimers());

describe("rich filesystem results", () => {
  it("retries a transient result 503 after a committed mkdir without resubmission", async () => {
    const h = harness(
      receipt(),
      json(status({ kind: "MKDIR" })),
      error("SERVICE_UNAVAILABLE"),
      json(result({ type: "file.mkdir", created: true }, { kind: "MKDIR" })),
    );
    await expect(
      h.client.files.makeDir("sbx", "/a", { idempotencyKey: "mkdir-recovery" }),
    ).resolves.toBe(true);
    expect(h.calls.filter((c) => c.init.method === "POST")).toHaveLength(1);
    expect(h.calls[2]?.url.href).toBe(h.calls[3]?.url.href);
  });

  it("returns one bounded page and preserves its continuation without aggregation", async () => {
    const { client, calls, remaining } = harness(
      receipt(),
      json(status({ kind: "LIST_DIR" })),
      json(
        result(
          {
            type: "file.list",
            path: "/",
            depth: 1,
            items: [entry],
            nextCursor: "next",
            consistency: "live",
          },
          { kind: "LIST_DIR", expiresAt: LATER },
        ),
      ),
    );
    expect(await client.files.list("sbx", "/")).toEqual({
      items: [entry],
      nextCursor: "next",
      consistency: "live",
    });
    expect(body(calls[0])).toEqual({ path: "/", depth: 1, limit: 100 });
    expect(calls).toHaveLength(3);
    expect(remaining()).toBe(0);
  });
  it.each([true, false])("returns mkdir's actual created=%s", async (created) => {
    const { client, calls } = harness(
      receipt(),
      json(status({ kind: "MKDIR" })),
      json(result({ type: "file.mkdir", created }, { kind: "MKDIR" })),
    );
    expect(await client.files.makeDir("sbx", "/a")).toBe(created);
    expect(calls).toHaveLength(3);
  });
  it("uses rich stat/rename entries and nonrecursive remove by default", async () => {
    for (const action of ["stat", "getInfo", "rename", "remove"] as const) {
      const kind =
        action === "rename" ? "MOVE_PATH" : action === "remove" ? "REMOVE_PATH" : "STAT_PATH";
      const data =
        action === "remove"
          ? { type: "file.remove", removed: true }
          : { type: action === "rename" ? "file.rename" : "file.stat", entry };
      const { client, calls } = harness(
        receipt(),
        json(status({ kind })),
        json(result(data, { kind, expiresAt: kind === "REMOVE_PATH" ? null : LATER })),
      );
      const value =
        action === "rename"
          ? await client.files.rename("sbx", "/old", "/a")
          : await client.files[action]("sbx", "/a");
      expect(value).toEqual(
        action === "remove"
          ? undefined
          : action === "stat"
            ? { ...entry, operationId: "op" }
            : entry,
      );
      if (action === "remove") expect(body(calls[0])).toEqual({ path: "/a", recursive: false });
    }
  });
  const fsCodes = [
    "fs_not_found",
    "fs_is_directory",
    "fs_not_directory",
    "fs_not_regular",
    "fs_permission_denied",
    "fs_read_only",
    "fs_already_exists",
    "fs_not_empty",
    "fs_cross_device",
    "fs_no_space",
    "fs_symlink_refused",
    "fs_entry_too_large",
    "fs_listing_limit",
    "fs_invalid_encoding",
    "fs_metadata_unrepresentable",
  ] as const satisfies readonly OperationErrorCode[];
  it.each(fsCodes)("preserves precise %s without calling it key authorization", async (code) => {
    const { client } = harness(
      receipt(),
      json(status({ kind: "STAT_PATH", state: "FAILED", outcome: "failed", errorCode: code })),
      json(result(null, { kind: "STAT_PATH", outcome: "failed", expiresAt: LATER })),
    );
    const caught = await rejected(client.files.getInfo("sbx", "/a"));
    expect(caught).toBeInstanceOf(FileSystemError);
    expect(caught).toMatchObject({
      filesystemKind: code.slice(3),
      operationErrorCode: code,
      operationId: "op",
      phase: "result",
    });
    expect(caught.kind).not.toBe("authorization");
  });
  it.each(["fs_not_found"])(
    "stat converts %s only after authorized result version/expiry",
    async (errorCode) => {
      const failed = status({ kind: "STAT_PATH", state: "FAILED", outcome: "failed", errorCode });
      const { client } = harness(
        receipt(),
        json(failed),
        json(result(null, { kind: "STAT_PATH", outcome: "failed", expiresAt: LATER })),
      );
      expect(await client.files.stat("sbx", "/a")).toBeNull();
      for (const code of [
        "OPERATION_RESULT_UNSUPPORTED",
        "OPERATION_RESULT_EXPIRED",
        "sandbox.operation_not_found",
        "FORBIDDEN",
      ] as const) {
        const h = harness(receipt(), json(failed), error(code));
        expect(await rejected(h.client.files.exists("sbx", "/a"))).toMatchObject({ code });
        expect(h.calls).toHaveLength(3);
      }
    },
  );
  it.each(["stat", "exists"] as const)(
    "%s preserves a generic not_found operation error",
    async (method) => {
      const { client } = harness(
        receipt(),
        json(
          status({ kind: "STAT_PATH", state: "FAILED", outcome: "failed", errorCode: "not_found" }),
        ),
        json(result(null, { kind: "STAT_PATH", outcome: "failed", expiresAt: LATER })),
      );
      const caught = await rejected(client.files[method]("sbx", "/a"));
      expect(caught).toMatchObject({ kind: "not_found", code: "not_found", operationId: "op" });
      expect(caught).not.toBeInstanceOf(FileSystemError);
    },
  );
  it.each(["sandbox.not_found", "sandbox.operation_not_found"] as const)(
    "never converts %s to a missing file",
    async (code) => {
      const h =
        code === "sandbox.not_found" ? harness(error(code)) : harness(receipt(), error(code));
      expect(await rejected(h.client.files.stat("sbx", "/a"))).toMatchObject({ code });
    },
  );
  it.each(["file", "process", "extra"])(
    "strict malformed %s validation carries no response details",
    async (shape) => {
      const malformed =
        shape === "file"
          ? result(
              { type: "file.stat", entry: { ...entry, uid: PRIVATE } },
              { kind: "STAT_PATH", expiresAt: LATER },
            )
          : shape === "process"
            ? result(
                {
                  type: "process.list",
                  items: [{ ...connection().info, cmd: PRIVATE, unexpected: PRIVATE }],
                  nextCursor: null,
                  consistency: "live",
                },
                { kind: "LIST_PROCESSES", expiresAt: LATER },
              )
            : { ...commandResult(), [PRIVATE]: PRIVATE };
      const h = harness(json(malformed));
      const caught = await rejected(h.client.operations.getResult("op"));
      expect(caught.kind).toBe("protocol");
      safe(caught);
    },
  );
});

describe("same-key output throttling", () => {
  it("run survives one catalog 429 on an output page with one submission", async () => {
    const h = harness(receipt(), error("TOO_MANY_REQUESTS"), json(output(0)), json(status()));
    expect(
      await h.client.commands.run("sbx", "true", { idempotencyKey: "run-throttled" }),
    ).toMatchObject({ exitCode: 0 });
    expect(h.calls.filter((c) => c.init.method === "POST")).toHaveLength(1);
    expect(h.calls[1]?.url.href).toBe(h.calls[2]?.url.href);
  });
});

describe("checked command completion", () => {
  const forms = [
    "run-string",
    "run-object",
    "script",
    "argv",
    "start.wait",
    "connect.wait",
  ] as const;
  for (const form of forms)
    for (const check of [undefined, false] as const) {
      it(`${form} nonzero check=${check}`, async () => {
        const setup =
          form === "connect.wait"
            ? [json(connection(0))]
            : form === "start.wait"
              ? [receipt(), json(commandResult())]
              : [receipt()];
        const h = harness(
          ...setup,
          json(
            output(7, {
              chunks: [chunk("stderr", 0, PRIVATE)],
              nextCursor: `1_${PRIVATE.length}`,
              receivedBytes: PRIVATE.length,
              retainedBytes: PRIVATE.length,
              totalBytes: PRIVATE.length,
            }),
          ),
        );
        const options = { check };
        const promise =
          form === "start.wait"
            ? (await h.client.commands.start("sbx", "exit 7")).wait(options)
            : form === "connect.wait"
              ? (await h.client.commands.connect(REF)).wait(options)
              : form === "run-string"
                ? h.client.commands.run("sbx", "exit 7", options)
                : form === "run-object"
                  ? h.client.commands.run("sbx", { script: "exit 7" }, options)
                  : form === "argv"
                    ? h.client.commands.argv("sbx", ["sh", "-c", "exit 7"], options)
                    : h.client.commands.script("sbx", "exit 7", options);
        if (check === false) expect(await promise).toMatchObject({ exitCode: 7, stderr: PRIVATE });
        else {
          const caught = await rejected(promise);
          expect(caught).toBeInstanceOf(CommandExitError);
          expect(caught).toMatchObject({
            exitCode: 7,
            outputAvailability: "available",
            stderr: PRIVATE,
          });
          safe(caught);
        }
        expect(h.remaining()).toBe(0);
      });
    }
  it.each([
    ["CANCELLED", "cancelled", "cancelled", "aborted"],
    ["FAILED", "failed", "timeout", "timeout"],
    ["UNKNOWN_OUTCOME", "unknown", "unknown_outcome", "unknown"],
  ])("%s wins over an exit-like integer", async (state, outcome, errorCode, kind) => {
    const h = harness(
      receipt(),
      json(output(137, { state })),
      json(status({ state, outcome, errorCode })),
    );
    const caught = await rejected(h.client.commands.run("sbx", "x"));
    expect(caught).not.toBeInstanceOf(CommandExitError);
    expect(caught.kind).toBe(kind);
  });
  it("bounds both exception streams to UTF-8 tails while automatic formats stay private-free", async () => {
    const text = PRIVATE + "é界🙂".repeat(14000);
    // Per-page maximum remains 64 KiB; the result buffer spans many bounded pages.
    const pieces: Step[] = [];
    let offset = 0;
    for (const stream of ["stdout", "stderr"] as const) {
      for (let start = 0; start < text.length; start += 8000) {
        const value = text.slice(start, start + 8000);
        const end = offset + Buffer.byteLength(value);
        pieces.push(
          json(
            output(9, {
              complete: false,
              offset,
              chunks: [chunk(stream, offset, value)],
              nextCursor: `1_${end}`,
              hasMore: true,
              receivedBytes: end,
              totalBytes: null,
              retainedBytes: end,
            }),
          ),
        );
        offset = end;
      }
    }
    const h = harness(
      receipt(),
      ...pieces,
      json(
        output(9, {
          offset,
          nextCursor: `1_${offset}`,
          receivedBytes: offset,
          totalBytes: offset,
          retainedBytes: offset,
        }),
      ),
      json(status()),
    );
    const caught = await rejected(h.client.commands.run("sbx", "x"));
    expect(caught).toBeInstanceOf(CommandExitError);
    const exit = caught as CommandExitError;
    expect(Buffer.byteLength(exit.stdout)).toBeLessThanOrEqual(65536);
    expect(Buffer.byteLength(exit.stderr)).toBeLessThanOrEqual(65536);
    expect(exit.stdout.endsWith("🙂")).toBe(true);
    expect(exit.stdout).not.toContain("�");
    expect(exit.truncated).toBe(true);
    safe(exit);
  });
  it.each([undefined, false] as const)(
    "natural nonzero racing explicit cancellation still checks exit (%s)",
    async (check) => {
      const controller = new AbortController();
      const h = harness(
        receipt(),
        () => {
          controller.abort();
          return new Promise(() => {});
        },
        receipt("cancel", "SUCCEEDED"),
        json(output(7)),
        json(status()),
      );
      const promise = h.client.commands.run("sbx", "x", {
        signal: controller.signal,
        onAbort: "cancel",
        check,
      });
      if (check === false) expect(await promise).toMatchObject({ exitCode: 7 });
      else expect(await rejected(promise)).toBeInstanceOf(CommandExitError);
      expect(h.calls.filter((call) => call.url.pathname.endsWith("/cancel"))).toHaveLength(1);
      expect(h.remaining()).toBe(0);
    },
  );
  it("expired output never conceals a denied result read and keeps recovery context", async () => {
    const h = harness(
      json(connection()),
      error("OUTPUT_EXPIRED"),
      json(status()),
      error("FORBIDDEN"),
    );
    const handle = await h.client.commands.connect(REF);
    expect(await rejected(handle.wait())).toMatchObject({
      code: "FORBIDDEN",
      operationId: "op",
      process: REF,
      phase: "result",
    });
    expect(h.calls).toHaveLength(4);
  });
  it("labels genuinely empty output available", async () => {
    const h = harness(receipt(), json(output()), json(status()));
    expect(await rejected(h.client.commands.run("sbx", "x"))).toMatchObject({
      stdout: "",
      stderr: "",
      truncated: false,
      outputAvailability: "available",
    });
  });
  it("uses permanent exit evidence when output expires, while check:false preserves gone", async () => {
    const h = harness(receipt(), error("OUTPUT_EXPIRED"), json(status()), json(commandResult(7)));
    expect(await rejected(h.client.commands.run("sbx", "x"))).toMatchObject({
      kind: "command_exit",
      process: REF,
      stdout: "",
      stderr: "",
      truncated: true,
      outputAvailability: "expired",
    });
    const unchecked = harness(receipt(), error("OUTPUT_EXPIRED"));
    expect(
      await rejected(unchecked.client.commands.run("sbx", "x", { check: false })),
    ).toMatchObject({ kind: "gone", code: "OUTPUT_EXPIRED" });
  });
  it.each(["FORBIDDEN", "sandbox.operation_not_found"] as const)(
    "output %s remains primary without exit/result preflight",
    async (code) => {
      const h = harness(receipt(), error(code));
      expect(await rejected(h.client.commands.run("sbx", "x"))).toMatchObject({
        code,
        operationId: "op",
        phase: "follow",
      });
      expect(h.calls).toHaveLength(2);
    },
  );
});

describe("identity-confirmed handles and attachment", () => {
  it("start waits for evidence and does not retain input, env, stdin or submission signal", async () => {
    const controller = new AbortController();
    const h = harness(
      receipt(),
      error("OPERATION_RESULT_NOT_READY"),
      json(commandResult(0)),
      receipt("stdin", "SUCCEEDED"),
      json(output(0)),
      json(status()),
    );
    const input = { script: PRIVATE, envs: { PRIVATE } };
    const handle = await h.client.commands.start("sbx", input, {
      signal: controller.signal,
      stdin: PRIVATE,
    });
    expect(body(h.calls[0])).toEqual({ ...input, startEvidence: "required" });
    expect(handle.process).toEqual(REF);
    expect(Object.isFrozen(handle.process)).toBe(true);
    expect(JSON.stringify(handle)).not.toContain(PRIVATE);
    expect(Object.keys(handle)).not.toContain("signal");
    controller.abort();
    // The original signal is no longer an observer; a fresh wait succeeds.
    expect(await handle.wait()).toMatchObject({ exitCode: 0, process: REF });
  });
  it.each(["script", "argv", "nonce", "envs"])(
    "forged %s descriptions are absent from validation diagnostics",
    async (field) => {
      const h = harness(
        json({ ...connection(), info: { ...connection().info, [field]: PRIVATE } }),
      );
      const caught = await rejected(h.client.commands.connect(REF));
      expect(caught.kind).toBe("protocol");
      safe(caught);
    },
  );
  it("connect never invents a command replay key", async () => {
    const h = harness(
      json(connection(0)),
      json(output(7, { state: "UNKNOWN_OUTCOME", complete: false, totalBytes: null })),
      json(status({ state: "UNKNOWN_OUTCOME", outcome: "unknown", errorCode: "unknown_outcome" })),
    );
    const handle = await h.client.commands.connect(REF);
    const caught = await rejected(handle.wait());
    expect(caught).toMatchObject({
      kind: "unknown",
      operationId: "op",
      process: REF,
      idempotencyKey: null,
    });
    expect(caught.message).toContain("recover using this operation ID");
    expect(h.calls).toHaveLength(3);
    expect(h.calls.every((call) => call.init.method === "GET")).toBe(true);
  });
  it("start wait preserves the actual submission key for recovery", async () => {
    const h = harness(receipt(), json(commandResult()), error("FORBIDDEN"));
    const handle = await h.client.commands.start("sbx", "x", {
      idempotencyKey: "original-command",
    });
    expect(await rejected(handle.wait())).toMatchObject({
      code: "FORBIDDEN",
      operationId: "op",
      process: REF,
      idempotencyKey: "original-command",
    });
  });
  it("connected output authorization remains primary with qualified recovery context", async () => {
    const h = harness(json(connection()), error("FORBIDDEN"));
    const handle = await h.client.commands.connect(REF);
    expect(await rejected(handle.wait())).toMatchObject({
      code: "FORBIDDEN",
      process: REF,
      operationId: "op",
      phase: "follow",
    });
    expect(h.calls).toHaveLength(2);
  });
  it("start abort during identity wait is unknown with the original key and no cancellation", async () => {
    const controller = new AbortController();
    const h = harness(receipt(), () => {
      controller.abort();
      return new Promise(() => {});
    });
    const caught = await rejected(
      h.client.commands.start("sbx", PRIVATE, {
        idempotencyKey: "start-recovery",
        signal: controller.signal,
      }),
    );
    expect(caught).toMatchObject({
      kind: "unknown",
      reason: "aborted",
      operationId: "op",
      idempotencyKey: "start-recovery",
      phase: "start",
    });
    expect(h.calls).toHaveLength(2);
    safe(caught);
  });
  it("live attachment includes output emitted after its committed snapshot and reads retained error tails", async () => {
    const h = harness(
      json(connection(4)),
      json(
        output(7, {
          offset: 4,
          chunks: [chunk("stdout", 4, "gap")],
          nextCursor: "1_7",
          receivedBytes: 7,
          totalBytes: 7,
          retainedBytes: 7,
        }),
      ),
      json(
        output(7, {
          chunks: [chunk("stdout", 0, "old gap")],
          nextCursor: "1_7",
          receivedBytes: 7,
          totalBytes: 7,
          retainedBytes: 7,
        }),
      ),
    );
    const handle = await h.client.commands.connect(REF);
    expect(h.calls).toHaveLength(1);
    const caught = await rejected(handle.wait());
    expect(caught).toMatchObject({
      stdout: "old gap",
      startOffset: 0,
      outputAvailability: "available",
    });
    expect(h.calls[1]?.url.searchParams.get("cursor")).toBe("1_4");
    expect(h.remaining()).toBe(0);
  });
  it.each(["retained", "cursor"] as const)(
    "supports %s replay with unchanged output DTO",
    async (mode) => {
      const h = harness(json(connection(4)), json(output(0)), json(status()));
      const handle = await h.client.commands.connect(
        REF,
        mode === "retained" ? { replay: "retained" } : { fromCursor: "1_0" },
      );
      expect(await handle.wait()).toMatchObject({ startOffset: 0 });
      expect(h.calls[1]?.url.searchParams.get("cursor")).toBe("1_0");
    },
  );
  it("rejects simultaneous cursor and replay before IO", async () => {
    const h = harness();
    expect(
      await rejected(h.client.commands.connect(REF, { fromCursor: "1_0", replay: "live" })),
    ).toMatchObject({ kind: "invalid_request" });
    expect(h.calls).toHaveLength(0);
  });
  it("preserves reset and gap markers from an old cursor", async () => {
    const h = harness(
      json(connection()),
      json(
        output(0, {
          attempt: 2,
          reset: true,
          chunks: [chunk("stdout", 2, "x")],
          gaps: [{ start: 0, end: 2 }],
          nextCursor: "2_3",
          receivedBytes: 3,
          retainedBytes: 1,
          totalBytes: 3,
          truncated: true,
        }),
      ),
      json(status()),
    );
    const events: unknown[] = [];
    const handle = await h.client.commands.connect(REF, { fromCursor: "1_5" });
    expect(
      await handle.wait({
        onOutput: (event) => {
          events.push(event);
        },
      }),
    ).toMatchObject({ startOffset: 0, stdout: "x", truncated: true });
    expect(events).toEqual([
      { kind: "reset", attempt: 2, offset: 0 },
      { kind: "gap", start: 0, end: 2 },
      { kind: "data", stream: "stdout", offset: 2, text: "x" },
    ]);
  });
  it("refuses a cursor from another attempt before output IO", async () => {
    const h = harness(json(connection()));
    expect(await rejected(h.client.commands.connect(REF, { fromCursor: "2_0" }))).toMatchObject({
      kind: "invalid_request",
      process: REF,
    });
    expect(h.calls).toHaveLength(1);
  });
  it("disconnect fences late callbacks and affects only one of two handles", async () => {
    let entered!: () => void;
    const entryGate = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const h = harness(
      json(connection(0)),
      json(connection(0)),
      json(
        output(0, {
          chunks: [chunk("stdout", 0, "a"), chunk("stderr", 1, "b")],
          nextCursor: "1_2",
          receivedBytes: 2,
          retainedBytes: 2,
          totalBytes: 2,
        }),
      ),
      json(output(0)),
      json(status()),
    );
    const one = await h.client.commands.connect(REF);
    const two = await h.client.commands.connect(REF);
    const callbacks = vi.fn();
    const waiting = rejected(
      one.wait({
        onAbort: "cancel",
        onOutput: async () => {
          entered();
          await blocked;
        },
        onStdout: callbacks,
        onStderr: callbacks,
      }),
    );
    await entryGate;
    one.disconnect();
    one.disconnect();
    expect(await waiting).toMatchObject({ kind: "aborted", phase: "follow", process: REF });
    release();
    await Promise.resolve();
    expect(await two.wait()).toMatchObject({ exitCode: 0 });
    expect(callbacks).not.toHaveBeenCalled();
    expect(h.calls.every((call) => call.init.method === "GET")).toBe(true);
  });
  it.each([false, true])("observer abort explicit cancel=%s", async (cancel) => {
    const controller = new AbortController();
    const h = harness(
      receipt(),
      () => {
        controller.abort();
        return new Promise(() => {});
      },
      receipt("cancel", "CANCELLED"),
    );
    const caught = await rejected(
      h.client.commands.run("sbx", "sleep 10", {
        signal: controller.signal,
        ...(cancel ? { onAbort: "cancel" as const } : {}),
      }),
    );
    expect(caught.kind).toBe("aborted");
    expect(h.calls.filter((call) => call.url.pathname.endsWith("/cancel"))).toHaveLength(
      cancel ? 1 : 0,
    );
    if (!cancel) expect(caught).toMatchObject({ phase: "follow", operationId: "op" });
  });
  it("async callback rejection is safe and sends no cancel even with cancel opt-in", async () => {
    const h = harness(
      receipt(),
      json(
        output(0, {
          chunks: [chunk("stdout", 0, "x")],
          nextCursor: "1_1",
          receivedBytes: 1,
          retainedBytes: 1,
          totalBytes: 1,
        }),
      ),
    );
    const caught = await rejected(
      h.client.commands.run("sbx", PRIVATE, {
        onAbort: "cancel",
        onStdout: async () => {
          throw new Error(PRIVATE);
        },
      }),
    );
    expect(caught.kind).toBe("unknown");
    expect(h.calls).toHaveLength(2);
    safe(caught);
  });
});

function readySandbox() {
  return {
    diskGiB: 32,
    id: "sbx",
    name: "quiet-otter",
    hostId: "host",
    storageId: "storage",
    storagePoolName: "default",
    storageMarker: "marker",
    templateId: "tpl",
    templateRevisionId: "tpl",
    originPoolId: null,
    cpuCount: 1,
    memoryMiB: 1024,
    state: "READY",
    generation: 1,
    endAt: null,
    startedAt: null,
    readyAt: null,
    lifecycle: { onTimeout: "kill", autoResume: false },
    sandboxDomain: null,
    portExposure: null,
    lease: { revision: 0, expiresAt: null, onExpire: "stop", requested: null, effective: null },
    egress: { mode: "allowlist", domains: [], cidrs: [] },
    egressRequest: null,
    egressModeReason: null,
    egressDeniedGrants: [],
    guestSudo: true,
    guestSudoRequested: true,
    guestSudoReason: null,
    guestRoot: true,
    disk: {
      location: "host",
      offloadState: "none",
      offloadFailure: null,
      offloadedAt: null,
      sizeBytes: null,
      eligibility: "any_host",
      offloadPin: "ANY",
    },
    metadata: {},
    createdAt: NOW,
    updatedAt: NOW,
  };
}
const bindSteps = () => [
  receipt("lease"),
  json(
    status({
      id: "lease",
      kind: "RECONNECT_SANDBOX",
      leaseIntent: {
        acceptedAt: NOW,
        timeoutMs: 300000,
        revision: 1,
        endAt: LATER,
        onTimeout: "kill",
        acknowledgedAt: NOW,
        acknowledgedAttempt: 1,
        acknowledgedEpoch: 1,
      },
    }),
  ),
  json(readySandbox()),
];
describe("qualified control consumers", () => {
  it.each([false, true])(
    "off-state signal bound=%s preserves one server refusal and never falls back",
    async (bound) => {
      const h = harness(...(bound ? bindSteps() : []), error("UNSUPPORTED_CAPABILITY"));
      const commands = bound
        ? (await h.client.sandboxes.connect("sbx")).commands
        : h.client.commands;
      const caught = await rejected(
        commands.signal(REF, "SIGTERM", { idempotencyKey: "signal-key" }),
      );
      expect(caught).toMatchObject({
        kind: "unsupported",
        code: "UNSUPPORTED_CAPABILITY",
        idempotencyKey: "signal-key",
        process: REF,
      });
      const controls = h.calls.filter((call) => call.url.pathname.includes("/processes/"));
      expect(controls).toHaveLength(1);
      expect(controls[0]?.url.pathname.endsWith("/signal")).toBe(true);
      expect(h.remaining()).toBe(0);
    },
  );
  it.each(["kill", "SIGKILL"])(
    "%s uses canonical cancel and waits for authoritative target termination",
    async (action) => {
      const cancel = {
        id: "cancel",
        kind: "operations.cancel",
        state: "SUCCEEDED",
        outcome: "succeeded",
        sandboxId: "sbx",
        generation: 1,
        errorCode: null,
        targetOperationId: "op",
        resourceId: null,
        observation: null,
        createdAt: NOW,
        updatedAt: NOW,
      };
      const h = harness(
        receipt("cancel", "SUCCEEDED"),
        json(cancel),
        json(status({ state: "CANCELLED", outcome: "cancelled", errorCode: "cancelled" })),
      );
      expect(
        await (action === "kill"
          ? h.client.commands.kill(REF)
          : h.client.commands.signal(REF, "SIGKILL")),
      ).toBe("killed");
      expect(h.calls[0]?.url.pathname).toBe("/v1/sandboxes/sbx/processes/42/kill");
      expect(body(h.calls[0])).toEqual({ generation: 1, processId: "proc", attempt: 1 });
    },
  );
  it.each(["kill", "SIGKILL"] as const)(
    "%s accepted then deadline is unknown with recovery identity",
    async (action) => {
      vi.useFakeTimers();
      const h = harness(
        receipt("cancel", "SUCCEEDED"),
        json({
          id: "cancel",
          kind: "operations.cancel",
          state: "SUCCEEDED",
          outcome: "succeeded",
          sandboxId: "sbx",
          generation: 1,
          errorCode: null,
          targetOperationId: "op",
          resourceId: null,
          observation: null,
          createdAt: NOW,
          updatedAt: NOW,
        }),
        ...Array.from(
          { length: 10 },
          () => () => json(status({ state: "RUNNING", outcome: "pending" })),
        ),
      );
      const options = { idempotencyKey: "kill-recover", waitTimeoutMs: 10 };
      const pending = rejected(
        action === "kill"
          ? h.client.commands.kill(REF, options)
          : h.client.commands.signal(REF, "SIGKILL", options),
      );
      await vi.advanceTimersByTimeAsync(20);
      expect(await pending).toMatchObject({
        kind: "unknown",
        reason: "timeout",
        operationId: "op",
        idempotencyKey: "kill-recover",
        process: REF,
      });
      expect(h.calls.filter((c) => c.init.method === "POST")).toHaveLength(1);
    },
  );
  it("kill never claims an effect-unknown FAILED target already exited", async () => {
    const h = harness(
      receipt("cancel", "SUCCEEDED"),
      json({
        id: "cancel",
        kind: "operations.cancel",
        state: "SUCCEEDED",
        outcome: "succeeded",
        sandboxId: "sbx",
        generation: 1,
        errorCode: null,
        targetOperationId: "op",
        resourceId: null,
        observation: null,
        createdAt: NOW,
        updatedAt: NOW,
      }),
      json(
        status({
          state: "FAILED",
          outcome: "failed",
          errorCode: "disconnected",
          failure: { resource: "process", effect: "unknown" },
        }),
      ),
    );
    expect(
      await rejected(h.client.commands.kill(REF, { idempotencyKey: "kill-failed" })),
    ).toMatchObject({
      kind: "unknown",
      operationId: "op",
      process: REF,
      idempotencyKey: "kill-failed",
    });
  });
  it("UNKNOWN kill remains uncertain under explicit same/new-key recovery calls", async () => {
    const h = harness(...Array.from({ length: 3 }, () => error("sandbox.process_unknown_outcome")));
    for (const idempotencyKey of ["unknown-kill", "unknown-kill", "new-kill"]) {
      const caught = await rejected(h.client.commands.kill(REF, { idempotencyKey }));
      expect(caught).toBeInstanceOf(ProcessError);
      expect(caught).toMatchObject({
        kind: "unknown",
        process: REF,
        idempotencyKey,
        processKind: "unknown_outcome",
      });
    }
    expect(h.calls).toHaveLength(3);
    expect(h.calls.every((call) => call.url.pathname.endsWith("/kill"))).toBe(true);
  });
  it("stdin and both EOF aliases share durable acceptance, with private body errors", async () => {
    const h = harness(receipt("stdin", "SUCCEEDED"), receipt("stdin2", "SUCCEEDED"));
    await h.client.commands.writeStdin(REF, "abc");
    await h.client.commands.closeStdin(REF);
    expect(body(h.calls[0])).toMatchObject({ contentBase64: "YWJj", eof: false });
    expect(body(h.calls[1])).toMatchObject({ contentBase64: "", eof: true });
    expect(h.calls).toHaveLength(2);
    const broken = harness(() => {
      throw new Error(PRIVATE);
    });
    const caught = await rejected(
      broken.client.commands.writeStdin(REF, PRIVATE, { waitTimeoutMs: 1 }),
    );
    safe(caught);
  });
  it("handle stdin writes and EOF use the qualified writer; disconnect leaves stdin open", async () => {
    const h = harness(
      json(connection()),
      ...Array.from({ length: 3 }, (_, i) => receipt(`stdin-${i}`, "SUCCEEDED")),
    );
    const handle = await h.client.commands.connect(REF);
    await handle.writeStdin("a");
    await handle.writeStdin("b");
    await handle.closeStdin();
    handle.disconnect();
    expect(h.calls).toHaveLength(4);
    expect(
      h.calls.slice(1).every((call) => call.url.pathname.endsWith("/processes/42/stdin")),
    ).toBe(true);
    expect(h.calls.slice(1).map((call) => body(call).eof)).toEqual([false, false, true]);
  });
  it.each(["process_stale", "process_permission_denied", "signal_unsupported_on_guest"] as const)(
    "typed signal operation preserves %s",
    async (errorCode) => {
      const h = harness(
        receipt(),
        json(status({ kind: "SIGNAL_PROCESS", state: "FAILED", outcome: "failed", errorCode })),
      );
      const caught = await rejected(h.client.commands.signal(REF, "SIGTERM"));
      expect(caught).toBeInstanceOf(ProcessError);
      expect(caught).toMatchObject({ operationErrorCode: errorCode, process: REF });
      expect(caught.kind).not.toBe("authorization");
      expect(h.calls).toHaveLength(2);
    },
  );
  it("typed signal delivery reports group acceptance without claiming target death", async () => {
    const delivery = {
      type: "process.signal",
      process: REF,
      targetOperationId: "target",
      signal: "SIGTERM",
      accepted: true,
      delivery: "process_group",
    };
    const h = harness(
      receipt(),
      json(status({ kind: "SIGNAL_PROCESS" })),
      json(result(delivery, { kind: "SIGNAL_PROCESS" })),
    );
    expect(await h.client.commands.signal(REF, "SIGTERM")).toEqual(delivery);
    expect(h.calls).toHaveLength(3);
  });
  it("returns a bounded process page without following nextCursor", async () => {
    const h = harness(
      receipt(),
      json(status({ kind: "LIST_PROCESSES" })),
      json(
        result(
          {
            type: "process.list",
            items: [connection().info],
            nextCursor: "next",
            consistency: "live",
          },
          { kind: "LIST_PROCESSES", expiresAt: LATER },
        ),
      ),
    );
    expect(await h.client.commands.list("sbx")).toMatchObject({
      items: [connection().info],
      nextCursor: "next",
    });
    expect(body(h.calls[0])).toEqual({ limit: 100 });
    expect(h.calls).toHaveLength(3);
  });
});

describe("timeout roles", () => {
  it.each(["string", "object", "script", "argv", "start"] as const)(
    "%s serializes only the command budget",
    async (form) => {
      const h =
        form === "start"
          ? harness(receipt(), json(commandResult()))
          : harness(receipt(), json(output(0)), json(status()));
      const options = { timeoutMs: 1234, waitTimeoutMs: 5678 };
      if (form === "string") await h.client.commands.run("sbx", "true", options);
      else if (form === "object") await h.client.commands.run("sbx", { script: "true" }, options);
      else if (form === "script") await h.client.commands.script("sbx", "true", options);
      else if (form === "argv") await h.client.commands.argv("sbx", ["true"], options);
      else await h.client.commands.start("sbx", "true", options);
      expect(body(h.calls[0]).timeoutMs).toBe(1234);
      expect(body(h.calls[0])).not.toHaveProperty("waitTimeoutMs");
    },
  );
  it("rejects duplicate command budgets and removed guest/wait spellings before IO", async () => {
    const h = harness();
    expect(
      await rejected(h.client.commands.run("sbx", { script: "x", timeoutMs: 5 }, { timeoutMs: 5 })),
    ).toMatchObject({ kind: "invalid_request" });
    const oldGuest = { guestTimeoutMs: 5 };
    expect(await rejected(h.client.commands.run("sbx", "x", oldGuest as RunOptions))).toMatchObject(
      { kind: "invalid_request" },
    );
    expect(() =>
      createWsspClient({
        baseUrl: "https://api.example.test",
        apiKey: KEY,
        polling: Object.assign({ intervalMs: 1 }, { timeoutMs: 5 }),
      }),
    ).toThrow("waitTimeoutMs");
    expect(h.calls).toHaveLength(0);
  });
  it.each([0, -1, 1.5, 1800001])(
    "keeps zero-command-timer off and rejects invalid command budget %s",
    async (timeoutMs) => {
      const h = harness();
      expect(await rejected(h.client.commands.run("sbx", "x", { timeoutMs }))).toMatchObject({
        kind: "invalid_request",
      });
      expect(h.calls).toHaveLength(0);
    },
  );
  it("an explicit observer budget wins over a shorter command budget without killing", async () => {
    vi.useFakeTimers();
    const h = harness(receipt(), () => new Promise(() => {}));
    const pending = rejected(
      h.client.commands.run("sbx", "x", { timeoutMs: 10, waitTimeoutMs: 50 }),
    );
    await vi.advanceTimersByTimeAsync(11);
    expect(h.calls).toHaveLength(2);
    let settled = false;
    void pending.then(() => {
      settled = true;
    });
    await Promise.resolve();
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(40);
    expect(await pending).toMatchObject({ kind: "timeout", operationId: "op" });
    expect(h.calls).toHaveLength(2);
  });
});

// Compile-time migration checks; this function is never invoked.
it("exports separate guest and observation timeout types", () => {
  const checkTypes = (
    client: ReturnType<typeof createWsspClient>,
    handle: Awaited<ReturnType<ReturnType<typeof createWsspClient>["commands"]["start"]>>,
  ) => {
    client.commands.run("sbx", "x", { timeoutMs: 10, waitTimeoutMs: 20 });
    client.commands.start("sbx", { argv: ["true"], timeoutMs: 10 }, { waitTimeoutMs: 20 });
    // @ts-expect-error removed guest budget spelling
    client.commands.script("sbx", "x", { guestTimeoutMs: 10 });
    // @ts-expect-error handle waits take only observer budgets
    handle.wait({ timeoutMs: 20 });
    // @ts-expect-error operation waits no longer accept the old alias
    client.operations.wait("op", { timeoutMs: 20 });
    createWsspClient({
      baseUrl: "https://api.example.test",
      apiKey: KEY,
      // @ts-expect-error client polling takes only observer budgets
      polling: { timeoutMs: 20 },
    });
  };
  expect(typeof checkTypes).toBe("function");
});

describe("D-20 timerless command consumers", () => {
  it.each([
    "run",
    "script",
    "argv",
    "object",
    "start",
    "bound-run",
    "bound-start",
    "bound-script",
    "bound-argv",
    "bound-object",
  ])("%s preserves zero while waits stay finite", async (form) => {
    zeroPolicy.enabled = true;
    const steps = form.includes("start")
      ? [receipt(), json(commandResult(0))]
      : [receipt(), json(output(0)), json(status())];
    const h = harness(...(form.startsWith("bound") ? bindSteps() : []), ...steps);
    const commandCall = form.startsWith("bound") ? 3 : 0;
    const options = { timeoutMs: 0, waitTimeoutMs: 1000 };
    switch (form) {
      case "start":
        await h.client.commands.start(
          "sbx",
          { argv: ["true"], envs: { DEFAULT: "present" } },
          options,
        );
        break;
      case "bound-start":
        await (await h.client.sandboxes.connect("sbx")).commands.start({ argv: ["true"] }, options);
        break;
      case "bound-run":
        await (await h.client.sandboxes.connect("sbx")).commands.run("true", options);
        break;
      case "bound-script":
        await (await h.client.sandboxes.connect("sbx")).commands.script("true", options);
        break;
      case "bound-argv":
        await (await h.client.sandboxes.connect("sbx")).commands.argv(["true"], options);
        break;
      case "bound-object":
        await (await h.client.sandboxes.connect("sbx")).commands.run(
          { argv: ["true"], timeoutMs: 0 },
          { waitTimeoutMs: 1000 },
        );
        break;
      case "script":
        await h.client.commands.script("sbx", "true", options);
        break;
      case "argv":
        await h.client.commands.argv("sbx", ["true"], options);
        break;
      case "object":
        await h.client.commands.run(
          "sbx",
          { argv: ["true"], timeoutMs: 0 },
          { waitTimeoutMs: 1000 },
        );
        break;
      default:
        await h.client.commands.run("sbx", "true", options);
    }
    expect(body(h.calls[commandCall]).timeoutMs).toBe(0);
    expect(body(h.calls[commandCall])).not.toHaveProperty("waitTimeoutMs");
    expect(h.calls.filter((c) => c.init.method === "POST")).toHaveLength(
      form.startsWith("bound") ? 2 : 1,
    );
  });
  it("off-state zero and wait-only zero refuse before IO", async () => {
    const h = harness();
    expect(await rejected(h.client.commands.run("sbx", "true", { timeoutMs: 0 }))).toMatchObject({
      kind: "invalid_request",
    });
    zeroPolicy.enabled = true;
    await expect(
      h.client.commands.run("sbx", "true", { timeoutMs: 0, waitTimeoutMs: 0 }),
    ).rejects.toThrow("waitTimeoutMs");
    expect(h.calls).toHaveLength(0);
  });
  it("zero without waitTimeoutMs uses exactly the finite 600000ms default and never cancels", async () => {
    zeroPolicy.enabled = true;
    vi.useFakeTimers();
    const calls: Call[] = [];
    const client = createWsspClient({
      baseUrl: "https://api.example.test",
      apiKey: KEY,
      fetch: async (url, init) => {
        calls.push({ url: new URL(url), init });
        return calls.length === 1 ? receipt() : new Promise<Response>(() => {});
      },
    });
    const startedAt = Date.now();
    let settled = false;
    const pending = rejected(client.commands.run("sbx", "true", { timeoutMs: 0 })).then((error) => {
      settled = true;
      return error;
    });
    await vi.advanceTimersByTimeAsync(599_999);
    expect(settled).toBe(false);
    expect(body(calls[0]).timeoutMs).toBe(0);
    expect(body(calls[0])).not.toHaveProperty("waitTimeoutMs");
    await vi.advanceTimersByTimeAsync(1);
    expect(await pending).toMatchObject({ kind: "timeout", operationId: "op" });
    expect(Date.now() - startedAt).toBe(600_000);
    expect(calls.filter((c) => c.init.method === "POST")).toHaveLength(1);
    expect(calls.some((c) => c.url.pathname.endsWith("/cancel"))).toBe(false);
  });
  it("finite observation timeout detaches a timerless command without cancel", async () => {
    zeroPolicy.enabled = true;
    const h = harness(receipt(), () => new Promise<Response>(() => {}));
    expect(
      await rejected(h.client.commands.run("sbx", "true", { timeoutMs: 0, waitTimeoutMs: 20 })),
    ).toMatchObject({ kind: "timeout", operationId: "op" });
    expect(h.calls.filter((c) => c.init.method === "POST")).toHaveLength(1);
    expect(h.calls.some((c) => c.url.pathname.endsWith("/cancel"))).toBe(false);
  });
});

it("fake-host scenario: start, detach, second-client list/connect/tail, stdin/EOF and nonzero exit", async () => {
  const start = harness(receipt(), json(commandResult()));
  const first = await start.client.commands.start("sbx", "read line; cat; exit 7");
  first.disconnect();
  expect(start.calls).toHaveLength(2);
  expect(start.calls.some((call) => /cancel|stdin/.test(call.url.pathname))).toBe(false);

  // Independent client observes the same server-held identity and output cursor.
  const second = harness(
    receipt("list"),
    json(status({ id: "list", kind: "LIST_PROCESSES" })),
    json(
      result(
        { type: "process.list", items: [connection().info], nextCursor: null, consistency: "live" },
        { operationId: "list", kind: "LIST_PROCESSES", expiresAt: LATER },
      ),
    ),
    json(connection(4)),
    receipt("stdin", "SUCCEEDED"),
    receipt("eof", "SUCCEEDED"),
    json(
      output(7, {
        offset: 4,
        chunks: [chunk("stdout", 4, "tail")],
        nextCursor: "1_8",
        receivedBytes: 8,
        retainedBytes: 8,
        totalBytes: 8,
      }),
    ),
    json(
      output(7, {
        chunks: [chunk("stdout", 0, "old tail")],
        nextCursor: "1_8",
        receivedBytes: 8,
        retainedBytes: 8,
        totalBytes: 8,
      }),
    ),
  );
  const page = await second.client.commands.list("sbx");
  expect(page.items[0]?.process).toEqual(first.process);
  const attached = await second.client.commands.connect(page.items[0]!.process);
  await attached.writeStdin("line\n");
  await attached.closeStdin();
  expect(body(second.calls[4])).toMatchObject({
    contentBase64: Buffer.from("line\n").toString("base64"),
    eof: false,
  });
  expect(body(second.calls[5])).toMatchObject({ contentBase64: "", eof: true });
  expect(await rejected(attached.wait())).toMatchObject({
    exitCode: 7,
    process: REF,
    stdout: "old tail",
  });
  expect(second.calls[6]?.url.searchParams.get("cursor")).toBe("1_4");
  expect(
    second.calls.filter(
      (call) => call.init.method === "POST" && call.url.pathname.endsWith("/commands"),
    ),
  ).toHaveLength(0);
  expect(second.remaining()).toBe(0);
});

it("D-23 guest defaults, supported 24.04/HWE and distinct host-Incus guidance remain documented", () => {
  const doc = (path: string) => readFileSync(new URL(`../../../${path}`, import.meta.url), "utf8");
  for (const path of ["docs/operations/templates.md", "docs/design/declarative-build.md"]) {
    const text = doc(path);
    expect(text).toContain("images:ubuntu/26.04/cloud");
    expect(text).toMatch(/24\.04[\s\S]*supported/);
    expect(text).toContain("HWE");
    expect(text).toContain("6.9");
  }
  expect(doc("docs/guide/hosts.md")).toContain(
    "**Ubuntu 24.04.** The archive's `incus` package is 6.0.0",
  );
  expect(doc("packages/sdk/README.md")).not.toMatch(/The `ACCEPTED` action\s+receipt/);
  const nativeContract = doc("docs/design/native-http-contract.md");
  expect(nativeContract).toContain("Established observer abort detaches by");
  expect(nativeContract).not.toContain("action receipt's `ACCEPTED`");
  expect(doc("docs/testing.md")).toContain("FS/process real-guest acceptance (not yet run)");
});
