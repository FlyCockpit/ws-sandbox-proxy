import { describe, expect, it } from "vitest";

import {
  clampTerminalSize,
  classifyClose,
  classifyCreateError,
  closeFrame,
  parseServerFrame,
  resizeFrame,
  SERVER_FRAME_MAX_CHARS,
  terminalRequestId,
  terminalSocketUrl,
} from "./terminal-protocol";

describe("clampTerminalSize", () => {
  it.each([
    [
      { rows: 24, cols: 80 },
      { rows: 24, cols: 80 },
    ],
    [
      { rows: 512, cols: 1024 },
      { rows: 512, cols: 1024 },
    ],
    [
      { rows: 513, cols: 1025 },
      { rows: 512, cols: 1024 },
    ],
    [
      { rows: 1e9, cols: 1e9 },
      { rows: 512, cols: 1024 },
    ],
    [
      { rows: 0, cols: 0 },
      { rows: 1, cols: 1 },
    ],
    [
      { rows: -5, cols: -1 },
      { rows: 1, cols: 1 },
    ],
    [
      { rows: 1, cols: 1 },
      { rows: 1, cols: 1 },
    ],
    [
      { rows: 24.9, cols: 80.1 },
      { rows: 24, cols: 80 },
    ],
  ])("clamps %j into the contract's bounds", (input, expected) => {
    expect(clampTerminalSize(input)).toEqual(expected);
  });

  it.each([
    null,
    undefined,
    { rows: Number.NaN, cols: 80 },
    { rows: 24, cols: Number.POSITIVE_INFINITY },
    { rows: Number.NEGATIVE_INFINITY, cols: 80 },
    { rows: "24", cols: 80 },
    { rows: 24, cols: undefined },
  ])("refuses a measurement that is not a size: %j", (input) => {
    expect(clampTerminalSize(input)).toBeNull();
  });
});

describe("terminalSocketUrl", () => {
  const path = "/api/dashboard/sandboxes/sbx_1/terminal/ws";
  it.each([
    ["https://app.example.test", `wss://app.example.test${path}`],
    ["https://app.example.test/", `wss://app.example.test${path}`],
    ["https://app.example.test:8443/base/", `wss://app.example.test:8443/base${path}`],
    ["http://localhost:3000", `ws://localhost:3000${path}`],
    ["http://api.wssp.localhost", `ws://api.wssp.localhost${path}`],
    ["http://127.0.0.1:3000", `ws://127.0.0.1:3000${path}`],
    ["http://[::1]:3000", `ws://[::1]:3000${path}`],
  ])("%s → %s", (server, expected) => {
    expect(terminalSocketUrl(server, path)).toBe(expected);
  });

  it.each([
    "http://app.example.test",
    "http://localhost.example.test",
    "http://10.0.0.5",
    "ftp://app.example.test",
    "not a url",
  ])("refuses %s (WSS required off loopback)", (server) => {
    expect(terminalSocketUrl(server, path)).toBeNull();
  });
});

describe("frames", () => {
  it("encodes the two control frames the server accepts", () => {
    expect(JSON.parse(resizeFrame("r1", { rows: 2, cols: 3 }))).toEqual({
      type: "resize",
      requestId: "r1",
      rows: 2,
      cols: 3,
    });
    expect(JSON.parse(closeFrame("r2"))).toEqual({ type: "close", requestId: "r2" });
  });

  it("generates requestIds in the server's grammar", () => {
    const id = terminalRequestId();
    expect(id).toMatch(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/);
  });

  it("parses the server's frames and ignores anything else", () => {
    expect(parseServerFrame('{"type":"ready","rows":2,"cols":3}')).toEqual({
      type: "ready",
      rows: 2,
      cols: 3,
    });
    expect(parseServerFrame('{"type":"close","code":4401,"intent":"revoked"}')).toMatchObject({
      type: "close",
      intent: "revoked",
    });
    expect(parseServerFrame("not json")).toBeNull();
    expect(parseServerFrame('{"type":"exec","cmd":"rm"}')).toBeNull();
    expect(
      parseServerFrame(
        `{"type":"ready","rows":2,"cols":3,"x":"${"a".repeat(SERVER_FRAME_MAX_CHARS)}"}`,
      ),
    ).toBe(null);
  });

  it("C54-CO-4: the largest CloseIntent the server forwards is still read by its intent", () => {
    // A host error message at its 1000-byte cap, every byte a control
    // character JSON-escaped to 6, plus both 128-character ids escaped too.
    const control = "\u0001";
    const frame = JSON.stringify({
      type: "close",
      code: 4401,
      intent: "host_disconnected",
      error: {
        code: "transport",
        message: control.repeat(1000),
        operationId: control.repeat(128),
        sandboxId: control.repeat(128),
      },
      requestId: "r".repeat(128),
    });
    expect(frame.length).toBeGreaterThan(4096);
    const parsed = parseServerFrame(frame);
    expect(parsed).toMatchObject({ type: "close", intent: "host_disconnected" });
    expect(classifyClose(parsed as Parameters<typeof classifyClose>[0], 4401)).toEqual({
      kind: "hostDisconnected",
    });
  });
});

describe("classifyClose", () => {
  it("prefers the intent, then the error code, then the exit code", () => {
    expect(
      classifyClose(
        {
          type: "close",
          code: 4401,
          intent: "backpressure",
          error: { code: "rate_limited" },
        },
        4401,
      ),
    ).toEqual({ kind: "backpressure" });
    expect(
      classifyClose({ type: "close", code: 4401, error: { code: "host_capacity" } }, 4401),
    ).toEqual({ kind: "hostCapacity", code: "host_capacity" });
    expect(
      classifyClose({ type: "close", code: 4401, error: { code: "weird_new_code" } }, 4401),
    ).toEqual({ kind: "hostRefused", code: "weird_new_code" });
    expect(
      classifyClose(
        { type: "close", code: 4401, intent: "expired", error: { code: "timeout" } },
        4401,
      ),
    ).toEqual({ kind: "openTimedOut" });
    // C55-CO-6: the node daemon stopping is not "the server restarted".
    expect(
      classifyClose(
        { type: "close", code: 4401, intent: "shutdown", error: { code: "disconnected" } },
        4401,
      ),
    ).toEqual({ kind: "hostShutdown" });
    expect(classifyClose({ type: "close", code: 4401, intent: "shutdown" }, 4401)).toEqual({
      kind: "shutdown",
    });
    // C52-R2-1: a host whose credential went inactive is not the owner's sign-in.
    expect(
      classifyClose(
        {
          type: "close",
          code: 4401,
          intent: "host_disconnected",
          error: { code: "access_denied" },
        },
        4401,
      ),
    ).toEqual({ kind: "hostRevoked" });
    expect(classifyClose({ type: "close", code: 4401, intent: "host_disconnected" }, 4401)).toEqual(
      { kind: "hostDisconnected" },
    );
    expect(classifyClose({ type: "close", code: 4401, intent: "expired" }, 4401)).toEqual({
      kind: "expired",
    });
    expect(classifyClose({ type: "close", code: 4401, exitCode: 0 }, 4401)).toEqual({
      kind: "exited",
      exitCode: 0,
    });
    expect(classifyClose({ type: "close", code: 4401, intent: "unknown_future" }, 4401)).toEqual({
      kind: "ended",
    });
  });

  it("C54-F2: prototype keys never resolve to an inherited member", () => {
    for (const key of ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf"]) {
      expect(classifyClose({ type: "close", code: 4401, intent: key }, 4401)).toEqual({
        kind: "ended",
      });
      expect(classifyClose({ type: "close", code: 4401, error: { code: key } }, 4401)).toEqual({
        kind: "hostRefused",
        code: key,
      });
    }
  });

  it("without a frame, only the code is used", () => {
    expect(classifyClose(null, 4401)).toEqual({ kind: "ended" });
    expect(classifyClose(null, 1006)).toEqual({ kind: "connectionLost" });
    expect(classifyClose(null, 1000)).toEqual({ kind: "connectionLost" });
  });
});

describe("classifyCreateError", () => {
  it("reads the oRPC code or status", () => {
    expect(classifyCreateError({ code: "UNAUTHORIZED" })).toEqual({ kind: "signedOut" });
    expect(classifyCreateError({ status: 429 })).toEqual({ kind: "rateLimited" });
    expect(classifyCreateError(new Error("network"))).toEqual({ kind: "createFailed" });
    expect(classifyCreateError(null)).toEqual({ kind: "createFailed" });
  });
});

describe("G7 reviewer probes", () => {
  it("the worst-case server CloseIntent fits the cap; a browser-plane revoke is never relabelled", () => {
    const control = "\u0001";
    const frame = JSON.stringify({
      type: "close",
      code: 4401,
      intent: "host_disconnected",
      exitCode: -2147483648,
      error: {
        code: "access_denied",
        message: control.repeat(1000),
        operationId: control.repeat(128),
        sandboxId: control.repeat(128),
      },
      requestId: `a${"_".repeat(127)}`,
    });
    expect(frame.length).toBeGreaterThan(4096);
    expect(frame.length).toBeLessThanOrEqual(SERVER_FRAME_MAX_CHARS);
    const parsed = parseServerFrame(frame);
    if (parsed?.type !== "close") throw new Error("the close frame was dropped");
    expect(classifyClose(parsed, 4401)).toEqual({ kind: "hostRevoked" });
    // Still bounded.
    expect(
      parseServerFrame(" ".repeat(SERVER_FRAME_MAX_CHARS - frame.length + 1) + frame),
    ).toBeNull();
    // A browser-plane revocation carrying access_denied stays `revoked`.
    expect(
      classifyClose(
        { type: "close", code: 4401, intent: "revoked", error: { code: "access_denied" } },
        4401,
      ),
    ).toEqual({ kind: "revoked" });
  });
});

it.each([
  ["pool_access_removed", "poolAccessRemoved"],
  ["host_terminals_disabled", "hostTerminalsDisabled"],
] as const)("preserves specific browser close reason %s", (reason, kind) => {
  const frame = parseServerFrame(
    JSON.stringify({ type: "close", code: 4401, intent: "revoked", reason }),
  );
  expect(classifyClose(frame?.type === "close" ? frame : null, 4401)).toEqual({ kind });
});

it("a terminal ended from the Terminals page says so, not 'you disconnected'", () => {
  const frame = parseServerFrame(
    JSON.stringify({ type: "close", code: 4401, intent: "client", reason: "ended_elsewhere" }),
  );
  expect(classifyClose(frame?.type === "close" ? frame : null, 4401)).toEqual({
    kind: "endedElsewhere",
  });
  // A plain client close keeps its own notice.
  const own = parseServerFrame(JSON.stringify({ type: "close", code: 4401, intent: "client" }));
  expect(classifyClose(own?.type === "close" ? own : null, 4401)).toEqual({ kind: "client" });
});
