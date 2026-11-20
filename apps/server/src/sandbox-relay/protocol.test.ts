import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { relayDispatchKind } from "@wssp/api/sandbox/contracts";
import { CANCELLABLE_OPERATION_KINDS } from "@wssp/api/sandbox/state-transitions";
import {
  hostHelloV11Schema,
  parseCredentialSpec,
  redactCredentialFrame,
  validCredentialPath,
} from "@wssp/sandbox-contracts";
import { describe, expect, it } from "vitest";
import { capacityFixture, helloFixture } from "./capacity-fixtures";
import { sandboxErrorCodeSchema, sandboxLifecycleStateSchema } from "./protocol";
import {
  ALLOWED_HOST_DISPATCH_KINDS,
  CHANNEL_LIMITS,
  classifyRelayDispatchKind,
  encodeBinaryFrame,
  encodeChannelDataFrame,
  encodeServerControlMessage,
  encodeTerminalDataFrame,
  isDeterministicDispatchError,
  negotiatedCapabilities,
  parseBinaryFrame,
  parseChannelDataFrame,
  parseDaemonControlFrame,
  parseParsedDaemonControlFrame,
  parseSandboxRelaySubprotocolHeader,
  parseTerminalDataFrame,
  RECEIPT_LIMITS,
  SANDBOX_BINARY_CHUNK_MAX_BYTES,
  SANDBOX_JSON_CONTROL_MAX_BYTES,
  SANDBOX_RELAY_SUBPROTOCOL,
  SandboxRelayDispatchValidationError,
  type ServerControlMessage,
  TERMINAL_LIMITS,
} from "./protocol.js";

const protocolFixtures = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/sandbox-protocol/fixtures",
);

describe("host lease ceiling wire (shared fixture with crates/sandbox-protocol)", () => {
  const cases = JSON.parse(
    readFileSync(join(protocolFixtures, "control_host_lease_policy.json"), "utf8"),
  ) as {
    helloCeilings: { maxLeaseMs?: number | null; absent?: true; stored: number | null }[];
    invalidHelloCeilings: unknown[];
    reports: Record<string, unknown>[];
    invalidReports: Record<string, unknown>[];
  };
  const hello = JSON.parse(
    readFileSync(join(protocolFixtures, "control_hello_daemon.json"), "utf8"),
  ) as { daemon: { capabilities: Record<string, unknown> } };
  const withCeiling = (patch: (capabilities: Record<string, unknown>) => void) => {
    const frame = structuredClone(hello);
    patch(frame.daemon.capabilities);
    return JSON.stringify(frame);
  };
  it("parses finite, unlimited and absent hello ceilings and stores what the plan says", () => {
    for (const ceiling of cases.helloCeilings) {
      const frame = parseDaemonControlFrame(
        withCeiling((capabilities) => {
          if (ceiling.absent) delete capabilities.maxLeaseMs;
          else capabilities.maxLeaseMs = ceiling.maxLeaseMs;
        }),
      );
      if (frame.type !== "hello") throw new Error("not a hello");
      expect(frame.daemon.capabilities.maxLeaseMs).toBe(ceiling.stored);
    }
    for (const invalid of cases.invalidHelloCeilings)
      expect(() =>
        parseDaemonControlFrame(
          withCeiling((capabilities) => {
            capabilities.maxLeaseMs = invalid;
          }),
        ),
      ).toThrow();
  });
  it("accepts only bounded host.lease-policy reports", () => {
    for (const report of cases.reports)
      expect(parseDaemonControlFrame(JSON.stringify(report))).toEqual(report);
    for (const report of cases.invalidReports)
      expect(() => parseDaemonControlFrame(JSON.stringify(report))).toThrow();
  });
});

describe("WP7 quiesce wire (shared fixture with crates/sandbox-protocol)", () => {
  const cases = JSON.parse(
    readFileSync(join(protocolFixtures, "control_host_quiesce.json"), "utf8"),
  ) as {
    quiesce: Record<string, unknown>[];
    invalidQuiesce: Record<string, unknown>[];
    acks: Record<string, unknown>[];
    invalidAcks: Record<string, unknown>[];
    hellos: {
      case: string;
      capability: unknown;
      quiescing: unknown;
      valid: boolean;
      quiescingParsed?: boolean;
    }[];
    helloOk: Record<string, unknown>;
  };
  const hello = JSON.parse(
    readFileSync(join(protocolFixtures, "control_hello_daemon.json"), "utf8"),
  ) as Record<string, unknown> & { daemon: { capabilities: Record<string, unknown> } };
  it("parses bounded host.quiesce reports", () => {
    for (const frame of cases.quiesce)
      expect(parseDaemonControlFrame(JSON.stringify(frame), "1.0")).toEqual(frame);
    for (const frame of cases.invalidQuiesce)
      expect(() => parseDaemonControlFrame(JSON.stringify(frame), "1.0")).toThrow();
  });
  it("encodes only valid host.quiesce.ack frames", () => {
    for (const frame of cases.acks)
      expect(JSON.parse(encodeServerControlMessage(frame as never, "1.0"))).toEqual(frame);
    for (const frame of cases.invalidAcks)
      expect(() => encodeServerControlMessage(frame as never, "1.0")).toThrow(
        "Invalid quiesce ACK frame.",
      );
  });
  it("accepts hello.quiescing only with the quiesce capability", () => {
    for (const row of cases.hellos) {
      const frame = structuredClone(hello);
      if (row.capability !== null) frame.daemon.capabilities.quiesce = row.capability;
      if (row.quiescing !== null) frame.quiescing = row.quiescing;
      if (!row.valid) {
        expect(() => parseDaemonControlFrame(JSON.stringify(frame), "1.0"), row.case).toThrow();
        continue;
      }
      const parsed = parseDaemonControlFrame(JSON.stringify(frame), "1.0");
      if (parsed.type !== "hello") throw new Error("not a hello");
      expect(parsed.quiescing === true, row.case).toBe(row.quiescingParsed);
    }
  });
  it("encodes the shared hello.ok with the echoed capability", () => {
    expect(JSON.parse(encodeServerControlMessage(cases.helloOk as never, "1.0"))).toEqual(
      cases.helloOk,
    );
    const declined = structuredClone(cases.helloOk) as { capabilities: Record<string, unknown> };
    declined.capabilities.quiesce = false;
    expect(() => encodeServerControlMessage(declined as never, "1.0")).toThrow(
      "Invalid hello capabilities.",
    );
  });
});

describe("pre-parsed daemon control frames (terminal lane)", () => {
  const reports = (
    JSON.parse(readFileSync(join(protocolFixtures, "control_host_lease_policy.json"), "utf8")) as {
      reports: Record<string, unknown>[];
      invalidReports: Record<string, unknown>[];
    }
  ).reports;
  const parsedVariant = (frame: string, version?: string) =>
    parseParsedDaemonControlFrame(JSON.parse(frame), Buffer.byteLength(frame, "utf8"), version);
  it("matches the string parser for valid and invalid frames", () => {
    for (const report of reports) {
      const frame = JSON.stringify(report);
      expect(parsedVariant(frame)).toEqual(parseDaemonControlFrame(frame));
      expect(parsedVariant(frame, "1.0")).toEqual(parseDaemonControlFrame(frame, "1.0"));
    }
    const frame = JSON.stringify(reports[0]);
    expect(() => parsedVariant(frame, "0.0")).toThrow("Unknown negotiated protocol version.");
    expect(() => parseDaemonControlFrame(frame, "0.0")).toThrow(
      "Unknown negotiated protocol version.",
    );
    expect(() => parsedVariant(JSON.stringify({ type: "terminal.nope" }))).toThrow();
  });
  it("sizes frames in UTF-8 bytes, not UTF-16 units", () => {
    // Under the limit in string length, over it in bytes.
    const frame = JSON.stringify({
      type: "x",
      pad: "é".repeat(SANDBOX_JSON_CONTROL_MAX_BYTES / 2),
    });
    expect(frame.length).toBeLessThan(SANDBOX_JSON_CONTROL_MAX_BYTES + 32);
    expect(() => parseDaemonControlFrame(frame)).toThrow("JSON control frame exceeds 64 KiB.");
    expect(() => parsedVariant(frame)).toThrow("JSON control frame exceeds 64 KiB.");
  });
});

describe("sandboxRelayProtocol", () => {
  it("shares frozen 10.3 admission/availability fixtures and rejects unbounded replies", () => {
    const cases: { direction: string; frame: Record<string, unknown> }[] = JSON.parse(
      readFileSync(join(protocolFixtures, "control_admission_availability.json"), "utf8"),
    );
    for (const { direction, frame } of cases) {
      if (direction === "daemon")
        expect(parseDaemonControlFrame(JSON.stringify(frame))).toEqual(frame);
      else
        expect(
          JSON.parse(encodeServerControlMessage(frame as ServerControlMessage, "1.0")),
        ).toEqual(frame);
    }
    const result = cases[3]!.frame;
    for (const patch of [
      { connectionEpoch: 0 },
      { page: 100 },
      { requestId: "" },
      { entries: Array(101).fill((result.entries as unknown[])[0]) },
    ]) {
      expect(() => parseDaemonControlFrame(JSON.stringify({ ...result, ...patch }))).toThrow();
    }
  });
  it("accepts bounded reconciler telemetry and refuses malformed or authority-bearing fields", () => {
    const health = {
      enabled: true,
      lastPassUnixMs: 1,
      verified: 1,
      drift: 0,
      inconclusive: 0,
      foreign: 0,
      absent: 0,
      pending: 2,
    };
    const frame = { type: "heartbeat", id: "health", policyReconciler: health };
    expect(parseDaemonControlFrame(JSON.stringify(frame))).toEqual(frame);
    expect(parseDaemonControlFrame(JSON.stringify({ type: "heartbeat", id: "legacy" }))).toEqual({
      type: "heartbeat",
      id: "legacy",
    });
    for (const bad of [
      { ...health, drift: -1 },
      { ...health, pending: 0.5 },
      { ...health, verified: 2_147_483_648 },
      { ...health, lastPassUnixMs: Number.MAX_SAFE_INTEGER + 1 },
      { ...health, enabled: "yes" },
      { ...health, egressPolicy: true },
      { ...health, stop: true },
    ]) {
      expect(() =>
        parseDaemonControlFrame(JSON.stringify({ ...frame, policyReconciler: bad })),
      ).toThrow();
    }
  });
  it("classifies pre-send stdin validation by type, never message text", () => {
    expect(
      isDeterministicDispatchError(new SandboxRelayDispatchValidationError("validation")),
    ).toBe(true);
    expect(isDeterministicDispatchError(new Error("Empty stdin requires EOF."))).toBe(false);
    expect(isDeterministicDispatchError(new Error("socket write failed"))).toBe(false);
  });

  it("shares absent STOP and deleted KILL end states with Rust", () => {
    const cases = JSON.parse(
      readFileSync(join(protocolFixtures, "control_absent_cleanup_results.json"), "utf8"),
    );
    for (const { kind, frame } of cases) {
      const parsed = parseDaemonControlFrame(JSON.stringify(frame));
      expect(parsed).toEqual(frame);
      if (parsed.type !== "operation.result") throw new Error("expected result");
      expect(sandboxLifecycleStateSchema.parse(parsed.result?.state)).toBe(
        kind === "sandbox.stop" ? "absent" : "deleted",
      );
    }
  });

  it("keeps the host cancellation allowlist aligned with the API contract", () => {
    const authority = readFileSync(
      join(protocolFixtures, "../../../apps/cli/src/sandbox_relay/authority.rs"),
      "utf8",
    );
    const declaration = authority.match(/const CANCELLABLE_DISPATCH_KINDS[^=]*= &\[([^\]]+)\]/);
    expect(declaration).not.toBeNull();
    const hostKinds = [...declaration![1]!.matchAll(/"([^"]+)"/g)].map((match) => match[1]);
    expect(hostKinds.sort()).toEqual(
      [...CANCELLABLE_OPERATION_KINDS].map((kind) => relayDispatchKind(kind)!).sort(),
    );
  });

  it("accepts the current websocket subprotocol and rejects unsupported major versions", () => {
    expect(parseSandboxRelaySubprotocolHeader(SANDBOX_RELAY_SUBPROTOCOL)).toEqual({
      ok: true,
      supported: true,
      requestedMajorVersions: [1],
    });
    expect(parseSandboxRelaySubprotocolHeader("ws-sandbox-proxy.relay.v9")).toEqual({
      ok: true,
      supported: false,
      requestedMajorVersions: [9],
    });
  });

  it("rejects oversized JSON control frames", () => {
    expect(() => parseDaemonControlFrame("x".repeat(SANDBOX_JSON_CONTROL_MAX_BYTES + 1))).toThrow(
      "JSON control frame exceeds 64 KiB.",
    );
  });

  it("rejects oversized binary chunks", () => {
    const oversized = new Uint8Array(SANDBOX_BINARY_CHUNK_MAX_BYTES + 1);
    expect(() =>
      encodeBinaryFrame(
        {
          type: "stream.chunk",
          streamId: "stream-1",
          operationId: "op-1",
          generation: 1,
          attempt: 1,
          sequence: 0,
        },
        oversized,
      ),
    ).toThrow("Binary body chunk exceeds 1 MiB.");
  });

  it("round-trips binary frames without coercing bytes", () => {
    const body = new Uint8Array([0, 1, 2, 255]);
    const frame = encodeBinaryFrame(
      {
        type: "stream.chunk",
        streamId: "stream-1",
        operationId: "op-1",
        generation: 1,
        attempt: 1,
        sequence: 3,
        final: true,
      },
      body,
    );

    const parsed = parseBinaryFrame(frame);
    expect(parsed.metadata).toEqual({
      type: "stream.chunk",
      streamId: "stream-1",
      operationId: "op-1",
      generation: 1,
      attempt: 1,
      sequence: 3,
      final: true,
    });
    expect([...parsed.body]).toEqual([0, 1, 2, 255]);
  });

  it("parses a host hello control frame", () => {
    const message = parseDaemonControlFrame(JSON.stringify(helloFixture("host-1", false)));

    expect(message.type).toBe("hello");
    if (message.type === "hello") {
      expect(message.daemon.hostId).toBe("host-1");
    }
  });

  it("rejects an old 1.0 hello control frame", () => {
    expect(() =>
      parseDaemonControlFrame(
        JSON.stringify({ ...helloFixture("host-1", false), protocolVersion: "10.7" }),
      ),
    ).toThrow();
  });

  it("preserves the shared long script fixture through server encoding", () => {
    const frame = JSON.parse(
      readFileSync(join(protocolFixtures, "control_operation_dispatch_script.json"), "utf8"),
    );
    const encoded = encodeServerControlMessage(frame, "1.0");
    expect(frame.script.length).toBeGreaterThan(512);
    expect(JSON.parse(encoded).script).toBe(frame.script);
  });

  it("rejects command.run dispatches that exceed the 64 KiB control frame", () => {
    const env = Array.from({ length: 40 }, (_, index) => [
      `VAR_${index}`,
      "z".repeat(1500),
    ]) as Array<[string, string]>;
    expect(() =>
      encodeServerControlMessage(
        {
          sandboxOwnerId: "owner",
          type: "operation.dispatch",
          operationId: "op-big",
          sandboxId: "sbx-1",
          idempotencyKey: "key-big",
          kind: "command.run",
          generation: 1,
          attempt: 1,
          script: "s".repeat(8_000),
          env,
          timeoutMs: 120_000,
          bodyHash: "a".repeat(64),
        },
        "1.0",
      ),
    ).toThrow(/64 KiB/);
  });

  it("command.run dispatch JSON always includes timeoutMs", () => {
    const encoded = encodeServerControlMessage(
      {
        sandboxOwnerId: "owner",
        type: "operation.dispatch",
        operationId: "op-1",
        sandboxId: "sbx-1",
        idempotencyKey: "key-1",
        kind: "command.run",
        generation: 1,
        attempt: 1,
        argv: ["true"],
        timeoutMs: 120_000,
        bodyHash: "a".repeat(64),
      },
      "1.0",
    );
    const parsed = JSON.parse(encoded) as { timeoutMs?: unknown; kind: string };
    expect(parsed.kind).toBe("command.run");
    expect(parsed.timeoutMs).toBe(120_000);
    expect(encoded).toContain('"timeoutMs":120000');
  });

  it("refuses VM-launch dispatches without the recorded egress policy and hash", () => {
    const base = {
      sandboxOwnerId: "owner",
      type: "operation.dispatch" as const,
      operationId: "op-1",
      sandboxId: "sbx-1",
      idempotencyKey: "key-1",
      generation: 1,
      attempt: 1,
      bodyHash: "a".repeat(64),
      cpuCount: 1,
      memoryMiB: 1024,
    };
    const policy = { domains: ["example.com"], cidrs: ["128.66.0.0/24"] };
    const hash = "b".repeat(64);
    for (const kind of ["sandbox.create", "sandbox.reconnect"]) {
      expect(() => encodeServerControlMessage({ ...base, kind }, "1.0")).toThrow(
        SandboxRelayDispatchValidationError,
      );
      expect(() =>
        encodeServerControlMessage({ ...base, kind, egressPolicy: policy }, "1.0"),
      ).toThrow(SandboxRelayDispatchValidationError);
      expect(() =>
        encodeServerControlMessage(
          { ...base, kind, egressPolicy: policy, egressPolicyHash: "zz" },
          "1.0",
        ),
      ).toThrow(SandboxRelayDispatchValidationError);
      expect(() =>
        encodeServerControlMessage(
          {
            ...base,
            kind,
            egressPolicy: { domains: ["*bad"], cidrs: [] },
            egressPolicyHash: hash,
          },
          "1.0",
        ),
      ).toThrow(SandboxRelayDispatchValidationError);
      const encoded = encodeServerControlMessage(
        {
          ...base,
          allocation: {
            cpuCount: 1,
            memoryMiB: 1024,
            diskGiB: 32,
            storagePoolName: "default",
            storageMarker: "a".repeat(32),
            chargedMemoryMiB: 1280,
            chargedVcpu: 1,
            rootChargeGiB: 33,
          },
          kind,
          egressPolicy: policy,
          egressPolicyHash: hash,
        },
        "1.0",
      );
      expect(JSON.parse(encoded)).toMatchObject({
        kind,
        egressPolicy: policy,
        egressPolicyHash: hash,
      });
    }
    // Non-launch dispatches never require the policy.
    expect(() =>
      encodeServerControlMessage(
        { ...base, kind: "command.run", cpuCount: undefined, memoryMiB: undefined },
        "1.0",
      ),
    ).not.toThrow();
    // Deterministic, never retryable.
    try {
      encodeServerControlMessage({ ...base, kind: "sandbox.create" }, "1.0");
      expect.unreachable();
    } catch (error) {
      expect(isDeterministicDispatchError(error)).toBe(true);
    }
  });

  it("classifies snapshot restore and fork as unsupported capability", async () => {
    const {
      ALLOWED_RELAY_DISPATCH_KINDS,
      OPERATION_DISPATCH_KIND,
      UNSUPPORTED_RELAY_DISPATCH_KINDS,
    } = await import("@wssp/api/sandbox/contracts");
    expect(classifyRelayDispatchKind("snapshot.create")).toBe("unsupported_capability");
    expect(classifyRelayDispatchKind("snapshot.restore")).toBe("unsupported_capability");
    expect(classifyRelayDispatchKind("sandbox.fork")).toBe("unsupported_capability");
    expect(classifyRelayDispatchKind("command.run")).toBe("allowed");
    expect(classifyRelayDispatchKind("operation.cancel")).toBe("control");
    expect(classifyRelayDispatchKind("sandbox.explode")).toBe("unknown");
    for (const kind of Object.values(OPERATION_DISPATCH_KIND)) {
      expect(classifyRelayDispatchKind(kind)).toBe("allowed");
      expect(ALLOWED_RELAY_DISPATCH_KINDS.has(kind)).toBe(true);
    }
    expect(ALLOWED_RELAY_DISPATCH_KINDS.has("process.stdin")).toBe(true);
    expect(ALLOWED_RELAY_DISPATCH_KINDS.has("operation.cancel")).toBe(true);
    for (const kind of UNSUPPORTED_RELAY_DISPATCH_KINDS) {
      expect(classifyRelayDispatchKind(kind)).toBe("unsupported_capability");
    }
  });

  it("parses a well-formed unknown error code as internal without failing the frame", () => {
    const result = (code: string, reason?: string) =>
      JSON.stringify({
        type: "operation.result",
        id: "result-newer",
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        state: "failed",
        error: { code, message: code, ...(reason ? { reason } : {}) },
      });
    const message = parseDaemonControlFrame(result("host_disconnect_future"));
    if (message.type !== "operation.result") throw new Error("expected result");
    expect(message.error?.code).toBe("internal");
    expect(message.error?.message).toBe("host_disconnect_future");
    // A journaled receipt replayed by a newer daemon parses the same way.
    const fixture = JSON.parse(
      readFileSync(join(protocolFixtures, "control_operation_receipt.json"), "utf8"),
    );
    const receipt = parseDaemonControlFrame(
      JSON.stringify({ ...fixture, error: { code: "some_future_code", message: "" } }),
    );
    if (receipt.type !== "operation.receipt") throw new Error("expected receipt");
    expect(receipt.error?.code).toBe("internal");
    // Catalog codes are unchanged; malformed codes and typed reasons on an
    // unknown code are still protocol errors.
    const known = parseDaemonControlFrame(result("timeout"));
    if (known.type !== "operation.result") throw new Error("expected result");
    expect(known.error?.code).toBe("timeout");
    for (const bad of ["Upper_case", "dash-code", "", "x".repeat(65), "digit1"]) {
      expect(() => parseDaemonControlFrame(result(bad))).toThrow();
    }
    expect(() => parseDaemonControlFrame(result("future_code", "ram"))).toThrow();
  });

  it("parses guest_operation_failed on operation results", () => {
    const message = parseDaemonControlFrame(
      JSON.stringify({
        type: "operation.result",
        id: "result-guest-op",
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        state: "failed",
        error: {
          code: "guest_operation_failed",
          message: "guest push failed: Error: Failed to push file",
        },
      }),
    );
    expect(message.type).toBe("operation.result");
    if (message.type === "operation.result") {
      expect(message.error?.code).toBe("guest_operation_failed");
    }
  });

  it("parses guest_permission_denied on operation results", () => {
    const message = parseDaemonControlFrame(
      JSON.stringify({
        type: "operation.result",
        id: "result-guest-perm",
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        state: "failed",
        error: {
          code: "guest_permission_denied",
          message: "permission denied for guest path `/root/secret`",
        },
      }),
    );
    expect(message.type).toBe("operation.result");
    if (message.type === "operation.result") {
      expect(message.error?.code).toBe("guest_permission_denied");
    }
  });

  it("parses path_refused on operation results", () => {
    const message = parseDaemonControlFrame(
      JSON.stringify({
        type: "operation.result",
        id: "result-path-refused",
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        state: "failed",
        error: {
          code: "path_refused",
          message: "refusing to mutate the guest root path `/`",
        },
      }),
    );
    expect(message.type).toBe("operation.result");
    if (message.type === "operation.result") {
      expect(message.error?.code).toBe("path_refused");
    }
  });

  it("parses sandbox_not_running on operation results", () => {
    const message = parseDaemonControlFrame(
      JSON.stringify({
        type: "operation.result",
        id: "result-stopped",
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        state: "failed",
        error: {
          code: "sandbox_not_running",
          message: "incus instance `wssp-sbx-1` is not running",
        },
      }),
    );
    expect(message.type).toBe("operation.result");
    if (message.type === "operation.result") {
      expect(message.error?.code).toBe("sandbox_not_running");
    }
  });

  it("parses unsupported_capability on operation results", () => {
    const message = parseDaemonControlFrame(
      JSON.stringify({
        type: "operation.result",
        id: "result-1",
        operationId: "op-1",
        sandboxId: "sbx-1",
        generation: 1,
        attempt: 1,
        state: "failed",
        error: {
          code: "unsupported_capability",
          message: "Unsupported capability: snapshot.create",
        },
      }),
    );
    expect(message.type).toBe("operation.result");
    if (message.type === "operation.result") {
      expect(message.error?.code).toBe("unsupported_capability");
    }
  });

  it("encodes the paired dispatch fixture with persisted attempt stdin start", () => {
    const encoded = JSON.parse(
      encodeServerControlMessage(
        {
          sandboxOwnerId: "user-1",
          type: "operation.dispatch",
          operationId: "op-fixture-1",
          sandboxId: "sbx-fixture-1",
          idempotencyKey: "key-fixture-1",
          kind: "command.run",
          generation: 3,
          attempt: 2,
          argv: ["cat"],
          stdinSequence: 7,
          bodyHash: "a".repeat(64),
        },
        "1.0",
      ),
    );
    expect(encoded).toEqual(
      JSON.parse(readFileSync(join(protocolFixtures, "control_operation_dispatch.json"), "utf8")),
    );
  });
  it("parses paired protocol fixtures with generation and attempt", () => {
    const progress = parseDaemonControlFrame(
      readFileSync(join(protocolFixtures, "control_operation_progress.json"), "utf8"),
    );
    expect(progress).toMatchObject({
      type: "operation.progress",
      operationId: "op-fixture-1",
      sandboxId: "sbx-fixture-1",
      generation: 3,
      attempt: 2,
      state: "running",
    });
    const result = parseDaemonControlFrame(
      readFileSync(join(protocolFixtures, "control_operation_result.json"), "utf8"),
    );
    expect(result).toMatchObject({
      type: "operation.result",
      generation: 3,
      attempt: 2,
      state: "succeeded",
    });
    const metadata = JSON.parse(
      readFileSync(join(protocolFixtures, "stream_binary_metadata.json"), "utf8"),
    ) as { generation: number; attempt: number };
    expect(metadata.generation).toBe(1);
    expect(metadata.attempt).toBe(1);
  });
});

const receiptFixture = () =>
  JSON.parse(
    readFileSync(join(protocolFixtures, "control_operation_receipt.json"), "utf8"),
  ) as Record<string, unknown>;
it("shares v3 receipt bounds and reconciliation fixtures with Rust", () => {
  expect(RECEIPT_LIMITS.kinds).toEqual(ALLOWED_HOST_DISPATCH_KINDS);
  const cases = JSON.parse(
    readFileSync(join(protocolFixtures, "receipt_bound_cases.json"), "utf8"),
  ) as Array<{ field: string; value: string; valid: boolean }>;
  for (const test of cases) {
    const parse = () =>
      parseDaemonControlFrame(JSON.stringify({ ...receiptFixture(), [test.field]: test.value }));
    if (test.valid) expect(parse).not.toThrow();
    else expect(parse).toThrow();
  }
  expect(() =>
    parseDaemonControlFrame(
      JSON.stringify({ ...receiptFixture(), result: { data: "x".repeat(32768) } }),
    ),
  ).toThrow();
  expect(() =>
    parseDaemonControlFrame(JSON.stringify(receiptFixture()) + " ".repeat(40960)),
  ).toThrow();
  for (const name of ["control_operation_receipt", "control_reconcile_complete"]) {
    const raw = readFileSync(join(protocolFixtures, `${name}.json`), "utf8");
    expect(parseDaemonControlFrame(raw)).toEqual(JSON.parse(raw));
  }
  for (const name of [
    "control_receipt_ack",
    "control_receipt_confirmed",
    "control_receipt_settled",
  ]) {
    const parsed = JSON.parse(readFileSync(join(protocolFixtures, `${name}.json`), "utf8"));
    expect(JSON.parse(encodeServerControlMessage(parsed, "1.0"))).toEqual(parsed);
  }
});

it("shares the operation.adopt frames with Rust and rejects the same malformed ones", () => {
  const fixture = JSON.parse(
    readFileSync(join(protocolFixtures, "control_operation_adopt.json"), "utf8"),
  ) as {
    daemon: Array<Record<string, unknown>>;
    server: ServerControlMessage[];
    rejectedDaemon: Array<Record<string, unknown>>;
  };
  for (const message of fixture.daemon)
    expect(parseDaemonControlFrame(JSON.stringify(message))).toEqual(message);
  for (const message of fixture.server)
    expect(JSON.parse(encodeServerControlMessage(message, "1.0"))).toEqual(message);
  for (const patch of fixture.rejectedDaemon)
    expect(
      () => parseDaemonControlFrame(JSON.stringify({ ...fixture.daemon[0], ...patch })),
      JSON.stringify(patch),
    ).toThrow();
});

it("shares the dispatch audit frames with Rust", () => {
  const fixture = JSON.parse(
    readFileSync(join(protocolFixtures, "control_dispatch_audit.json"), "utf8"),
  ) as {
    daemon: Array<Record<string, unknown>>;
    server: ServerControlMessage[];
    rejectedDaemon: Array<Record<string, unknown>>;
  };
  for (const message of fixture.daemon)
    expect(parseDaemonControlFrame(JSON.stringify(message))).toEqual(message);
  for (const message of fixture.server)
    expect(JSON.parse(encodeServerControlMessage(message, "1.0"))).toEqual(message);
  for (const message of fixture.rejectedDaemon)
    expect(
      () => parseDaemonControlFrame(JSON.stringify(message)),
      JSON.stringify(message),
    ).toThrow();
});

it("shares the v10 inventory census fixtures with Rust and rejects malformed pages", () => {
  const raw = readFileSync(join(protocolFixtures, "control_sandbox_inventory.json"), "utf8");
  const page = parseDaemonControlFrame(raw);
  expect(page).toEqual(JSON.parse(raw));
  const ack = JSON.parse(
    readFileSync(join(protocolFixtures, "control_inventory_ack.json"), "utf8"),
  );
  expect(JSON.parse(encodeServerControlMessage(ack, "1.0"))).toEqual(ack);
  const base = JSON.parse(raw) as { entries: Array<Record<string, unknown>> };
  const entry = (sandboxId: string) => ({ root: null, sandboxId, state: "absent" });
  for (const invalid of [
    { ...base, entries: [...base.entries].reverse() },
    { ...base, entries: [entry("a"), entry("a")] },
    { ...base, entries: [entry("a/b")] },
    { ...base, page: 1024 },
    { ...base, page: -1 },
    {
      ...base,
      entries: Array.from({ length: 65 }, (_, i) => entry(`s${String(i).padStart(4, "0")}`)),
    },
    { ...base, entries: [{ ...entry("a"), extra: true }] },
    { ...base, complete: undefined },
  ]) {
    expect(() => parseDaemonControlFrame(JSON.stringify(invalid))).toThrow();
  }
});

it("shares the expiry status fixture with Rust and bounds the failure report", () => {
  const raw = readFileSync(join(protocolFixtures, "control_sandbox_expiry_status.json"), "utf8");
  expect(parseDaemonControlFrame(raw)).toEqual(JSON.parse(raw));
  const base = JSON.parse(raw) as {
    entries: Array<{ lease: Record<string, unknown> & { expiryFailure: object } }>;
  };
  const withLease = (patch: Record<string, unknown>) => ({
    ...base,
    entries: [{ ...base.entries[0], lease: { ...base.entries[0]?.lease, ...patch } }],
  });
  const failure = base.entries[0]?.lease.expiryFailure;
  for (const invalid of [
    { ...base, entries: [] },
    withLease({ expiryComplete: true }),
    withLease({ expired: false, timerExpired: false }),
    withLease({ expired: false }),
    withLease({ timerExpired: undefined }),
    withLease({ expiryFailure: { ...failure, reason: "x".repeat(161) } }),
    withLease({ expiryFailure: { ...failure, reason: "bad\nreason" } }),
    withLease({ expiryFailure: { ...failure, attempts: 0 } }),
  ]) {
    expect(() => parseDaemonControlFrame(JSON.stringify(invalid))).toThrow();
  }
});

describe("sandbox error code wire parity", () => {
  it("matches the shared Rust/TypeScript fixture list", () => {
    const fixturePath = join(
      dirname(fileURLToPath(import.meta.url)),
      "../../../../packages/config/src/sandbox-error-codes.json",
    );
    const codes = JSON.parse(readFileSync(fixturePath, "utf8")) as string[];
    expect([...sandboxErrorCodeSchema.options].sort()).toEqual([...codes].sort());
    const receipt = JSON.parse(
      readFileSync(join(protocolFixtures, "control_operation_receipt.json"), "utf8"),
    );
    // Every catalog code parses for an 1.0 peer; other versions are gated
    // separately (session-manager B1-K-3 test).
    for (const code of codes) {
      expect(() =>
        parseDaemonControlFrame(
          JSON.stringify({
            ...receipt,
            error: { code, message: "probe" },
          }),
          "1.0",
        ),
      ).not.toThrow();
    }
    expect(() =>
      parseDaemonControlFrame(
        JSON.stringify({
          ...receipt,
          error: { code: "host_effect_not_issued", message: "spawn failed" },
        }),
      ),
    ).not.toThrow();
    // A newer peer's well-formed code is fail-safe `internal`; a malformed
    // code still fails the frame.
    const drift = parseDaemonControlFrame(
      JSON.stringify({
        ...receipt,
        error: { code: "not_a_real_code", message: "drift" },
      }),
    );
    if (drift.type !== "operation.receipt") throw new Error("expected receipt");
    expect(drift.error?.code).toBe("internal");
    expect(() =>
      parseDaemonControlFrame(
        JSON.stringify({
          ...receipt,
          error: { code: "Not-A-Code", message: "drift" },
        }),
      ),
    ).toThrow();
  });
});

it("pairs image verification and sandbox probe messages with Rust", () => {
  const fixture = JSON.parse(
    readFileSync(join(protocolFixtures, "control_template_observations.json"), "utf8"),
  );
  for (const message of fixture.server)
    expect(JSON.parse(encodeServerControlMessage(message, "1.0"))).toEqual(message);
  for (const message of fixture.daemon)
    expect(parseDaemonControlFrame(JSON.stringify(message))).toEqual(message);
});

describe("C52 terminal frame parity", () => {
  const fixture = JSON.parse(readFileSync(join(protocolFixtures, "control_terminal.json"), "utf8"));

  it("round-trips every terminal control frame exactly like Rust", () => {
    for (const message of fixture.server as ServerControlMessage[])
      expect(JSON.parse(encodeServerControlMessage(message, "1.0"))).toEqual(message);
    for (const message of fixture.daemon)
      expect(parseDaemonControlFrame(JSON.stringify(message))).toEqual(message);
  });

  it("refuses the same malformed, oversized-dimension and identity-bearing frames as Rust", () => {
    for (const message of fixture.rejected.server)
      expect(() => encodeServerControlMessage(message, "1.0"), JSON.stringify(message)).toThrow();
    for (const message of fixture.rejected.daemon)
      expect(
        () => parseDaemonControlFrame(JSON.stringify(message)),
        JSON.stringify(message),
      ).toThrow();
  });

  it("encodes and parses the shared terminal data frame byte-exactly", () => {
    const body = Uint8Array.from(Buffer.from(fixture.dataFrame.bodyHex, "hex"));
    const frame = encodeTerminalDataFrame(fixture.dataFrame.metadata, body);
    const parsed = parseTerminalDataFrame(frame);
    expect(parsed?.metadata).toEqual(fixture.dataFrame.metadata);
    expect(Buffer.from(parsed!.body).toString("hex")).toBe(fixture.dataFrame.bodyHex);
    // Stream frames are not terminal frames; the stream parser is unaffected.
    const stream = encodeBinaryFrame(
      {
        type: "stream.chunk",
        streamId: "s",
        operationId: "op",
        generation: 1,
        attempt: 1,
        sequence: 0,
      },
      new Uint8Array([1]),
    );
    expect(parseTerminalDataFrame(stream)).toBeNull();
    expect(() => parseBinaryFrame(frame)).toThrow();
  });

  it("refuses empty, oversized, unfenced and extended terminal data frames", () => {
    const metadata = fixture.dataFrame.metadata;
    expect(() => encodeTerminalDataFrame(metadata, new Uint8Array())).toThrow();
    expect(() =>
      encodeTerminalDataFrame(metadata, new Uint8Array(TERMINAL_LIMITS.dataMaxBytes + 1)),
    ).toThrow();
    const raw = (meta: unknown, body: number) => {
      const bytes = new TextEncoder().encode(JSON.stringify(meta));
      const frame = new Uint8Array(4 + bytes.length + body);
      new DataView(frame.buffer).setUint32(0, bytes.length, false);
      frame.set(bytes, 4);
      return frame.buffer;
    };
    expect(() => parseTerminalDataFrame(raw(metadata, TERMINAL_LIMITS.dataMaxBytes + 1))).toThrow();
    expect(() => parseTerminalDataFrame(raw(metadata, 0))).toThrow();
    expect(() =>
      parseTerminalDataFrame(raw({ ...metadata, fence: { ...metadata.fence, generation: 0 } }, 1)),
    ).toThrow();
    expect(() => parseTerminalDataFrame(raw({ ...metadata, extra: 1 }, 1))).toThrow();
    expect(parseTerminalDataFrame(raw(metadata, TERMINAL_LIMITS.dataMaxBytes))).not.toBeNull();
  });
});

describe("channel frame parity", () => {
  const fixture = JSON.parse(readFileSync(join(protocolFixtures, "control_channel.json"), "utf8"));

  it("round-trips every channel control frame exactly like Rust", () => {
    for (const message of fixture.server as ServerControlMessage[])
      expect(JSON.parse(encodeServerControlMessage(message, "1.0"))).toEqual(message);
    for (const message of fixture.daemon)
      expect(parseDaemonControlFrame(JSON.stringify(message))).toEqual(message);
  });

  it("refuses the same malformed, wrong-direction and out-of-policy frames as Rust", () => {
    for (const message of fixture.rejected.server)
      expect(() => encodeServerControlMessage(message, "1.0"), JSON.stringify(message)).toThrow();
    for (const message of fixture.rejected.daemon)
      expect(
        () => parseDaemonControlFrame(JSON.stringify(message)),
        JSON.stringify(message),
      ).toThrow();
  });

  it("encodes and parses the shared channel data frame byte-exactly", () => {
    const body = Uint8Array.from(Buffer.from(fixture.dataFrame.bodyHex, "hex"));
    const frame = encodeChannelDataFrame(fixture.dataFrame.metadata, body);
    const parsed = parseChannelDataFrame(frame);
    expect(parsed?.metadata).toEqual(fixture.dataFrame.metadata);
    expect(Buffer.from(parsed!.body).toString("hex")).toBe(fixture.dataFrame.bodyHex);
    // Channel, terminal and stream frames never parse as one another.
    expect(parseTerminalDataFrame(frame)).toBeNull();
    expect(() => parseBinaryFrame(frame)).toThrow();
    const stream = encodeBinaryFrame(
      {
        type: "stream.chunk",
        streamId: "s",
        operationId: "op",
        generation: 1,
        attempt: 1,
        sequence: 0,
      },
      new Uint8Array([1]),
    );
    expect(parseChannelDataFrame(stream)).toBeNull();
  });

  it("refuses empty, oversized, unfenced and extended channel data frames", () => {
    const metadata = fixture.dataFrame.metadata;
    expect(() => encodeChannelDataFrame(metadata, new Uint8Array())).toThrow();
    expect(() =>
      encodeChannelDataFrame(metadata, new Uint8Array(CHANNEL_LIMITS.bulkDataMaxBytes + 1)),
    ).toThrow();
    const raw = (meta: unknown, body: number) => {
      const bytes = new TextEncoder().encode(JSON.stringify(meta));
      const frame = new Uint8Array(4 + bytes.length + body);
      new DataView(frame.buffer).setUint32(0, bytes.length, false);
      frame.set(bytes, 4);
      return frame.buffer;
    };
    expect(() =>
      parseChannelDataFrame(raw(metadata, CHANNEL_LIMITS.bulkDataMaxBytes + 1)),
    ).toThrow();
    expect(() => parseChannelDataFrame(raw(metadata, 0))).toThrow();
    expect(() =>
      parseChannelDataFrame(raw({ ...metadata, fence: { ...metadata.fence, epoch: 0 } }, 1)),
    ).toThrow();
    expect(() =>
      parseChannelDataFrame(
        raw({ ...metadata, fence: { ...metadata.fence, channelId: "a".repeat(65) } }, 1),
      ),
    ).toThrow();
    expect(() => parseChannelDataFrame(raw({ ...metadata, seq: 2 ** 53 }, 1))).toThrow();
    expect(() => parseChannelDataFrame(raw({ ...metadata, extra: 1 }, 1))).toThrow();
    expect(parseChannelDataFrame(raw(metadata, CHANNEL_LIMITS.bulkDataMaxBytes))).not.toBeNull();
  });

  it("accepts the optional channels hello offer and echoes it only when offered", () => {
    const hello = JSON.parse(
      readFileSync(join(protocolFixtures, "control_hello_daemon.json"), "utf8"),
    );
    const helloOk = JSON.parse(
      readFileSync(join(protocolFixtures, "control_hello_ok_server.json"), "utf8"),
    );
    expect(parseDaemonControlFrame(JSON.stringify(hello))).toMatchObject({ type: "hello" });
    expect(negotiatedCapabilities("1.0", hello.daemon.capabilities)).not.toHaveProperty("channels");
    hello.daemon.capabilities.channels = { kinds: ["pty", "exec"] };
    const parsed = parseDaemonControlFrame(JSON.stringify(hello));
    if (parsed.type !== "hello") throw new Error("not hello");
    const capabilities = negotiatedCapabilities("1.0", parsed.daemon.capabilities);
    expect(capabilities.channels).toEqual({ kinds: ["pty", "exec"] });
    const encoded = JSON.parse(
      encodeServerControlMessage({ ...helloOk, capabilities } as ServerControlMessage, "1.0"),
    );
    expect(encoded.capabilities.channels).toEqual({ kinds: ["pty", "exec"] });
    for (const bad of [{ kinds: [] }, { kinds: ["exec", "exec"] }, { kinds: ["shell"] }, null]) {
      hello.daemon.capabilities.channels = bad;
      expect(() => parseDaemonControlFrame(JSON.stringify(hello)), JSON.stringify(bad)).toThrow();
    }
  });
});

it("private config install and ACK are strict and never echo values in errors", () => {
  const frame: ServerControlMessage = {
    sandboxOwnerId: "owner",
    type: "private.config.install",
    refusalToken: "install-token",
    connectionEpoch: 1,
    server: "wss://server/ws/sandbox-host",
    hostOwnerId: "owner",
    hostId: "host",
    sandboxId: "sandbox",
    generation: 1,
    config: {
      configId: "config",
      bindingScheme: "hmac-sha256-v1",
      bindingKeyId: "d".repeat(32),
      bindingMac: "c".repeat(64),
    },
    env: [["K", "private-config-wire-sentinel"]],
  };
  expect(JSON.parse(encodeServerControlMessage(frame, "1.0"))).toEqual(frame);
  for (const patch of [
    { connectionEpoch: 0 },
    { env: [["K", "x".repeat(4097)]] },
    ...["HOME", "SHELL", "TERM"].map((name) => ({ env: [[name, "private-config-wire-sentinel"]] })),
    {
      env: [
        ["K", "a"],
        ["K", "b"],
      ],
    },
  ]) {
    try {
      encodeServerControlMessage({ ...frame, ...patch } as ServerControlMessage, "1.0");
      expect.unreachable("invalid config accepted");
    } catch (error) {
      expect(error).toBeInstanceOf(SandboxRelayDispatchValidationError);
      expect(String(error)).not.toContain("private-config-wire-sentinel");
    }
  }
  const ack = {
    sandboxOwnerId: "owner",
    type: "private.config.ack",
    connectionEpoch: 1,
    sandboxId: "sandbox",
    generation: 1,
    config: frame.config,
  };
  expect(parseDaemonControlFrame(JSON.stringify(ack))).toEqual(ack);
  for (const patch of [{ checksum: "c".repeat(64) }, { env: frame.env }, { connectionEpoch: 0 }])
    expect(() => parseDaemonControlFrame(JSON.stringify({ ...ack, ...patch }))).toThrow();
});

it("pruned receipts contain only safe identity and cannot carry a digest", () => {
  const frame = {
    sandboxOwnerId: "owner",
    type: "operation.receipt.pruned",
    operationId: "op",
    sandboxId: "sbx",
    generation: 1,
    attempt: 1,
    idempotencyKey: "key",
    kind: "sandbox.create",
  };
  expect(parseDaemonControlFrame(JSON.stringify(frame))).toEqual(frame);
  for (const patch of [
    { bodyHash: "a".repeat(64) },
    { result: {} },
    { kind: "unknown" },
    { generation: 0 },
    { attempt: 0 },
  ])
    expect(() => parseDaemonControlFrame(JSON.stringify({ ...frame, ...patch }))).toThrow();
});

it("shares frozen private config and digest-pruned 10.3 frames with Rust", () => {
  const cases: { direction: string; frame: Record<string, unknown> }[] = JSON.parse(
    readFileSync(join(protocolFixtures, "control_private_config.json"), "utf8"),
  );
  for (const { direction, frame } of cases) {
    if (direction === "daemon")
      expect(parseDaemonControlFrame(JSON.stringify(frame))).toEqual(frame);
    else
      expect(JSON.parse(encodeServerControlMessage(frame as ServerControlMessage, "1.0"))).toEqual(
        frame,
      );
  }
});

it("decodes the negotiated process.started fixture", async () => {
  const { processStartedSchema, SANDBOX_RELAY_PROTOCOL_VERSION } = await import("./protocol");
  const fixture = (
    await import("../../../../crates/sandbox-protocol/fixtures/process_started.json")
  ).default;
  expect(processStartedSchema.parse(fixture)).toEqual(fixture);
  expect(processStartedSchema.safeParse({ ...fixture, nonce: "private" }).success).toBe(false);
  expect(SANDBOX_RELAY_PROTOCOL_VERSION).toBe("1.0");
  // Rust `process_started_cases_match_typescript` consumes the same cases.
  const cases = (
    await import("../../../../crates/sandbox-protocol/fixtures/process_started_cases.json")
  ).default;
  expect(cases.some((entry) => !entry.valid)).toBe(true);
  for (const entry of cases)
    expect(processStartedSchema.safeParse(entry.value).success, entry.name).toBe(entry.valid);
});

it("shares the versioned host result codec with Rust and gates both wire carriers", async () => {
  const { hostOperationResultSchema } = await import("./protocol");
  const { operationResultSchema } = await import("@wssp/sandbox-contracts");
  const cases = (await import("../../../../crates/sandbox-protocol/fixtures/host_results.json"))
    .default;
  for (const c of cases) {
    const parsed = hostOperationResultSchema.safeParse(c.value);
    const valid =
      parsed.success &&
      (parsed.data.payload === null ||
        operationResultSchema.safeParse({
          operationId: "operation",
          sandboxId: "sandbox",
          generation: 1,
          kind: c.kind,
          outcome: "succeeded",
          observedAt: parsed.data.observedAt,
          expiresAt: ["STAT_PATH", "LIST_DIR", "MOVE_PATH", "LIST_PROCESSES"].includes(c.kind)
            ? "2026-10-28T00:00:00.000Z"
            : null,
          result: parsed.data.payload,
        }).success);
    expect(valid, c.name).toBe(c.valid);
    if (c.valid)
      for (const receipt of [false, true]) {
        const frame = receipt
          ? {
              sandboxOwnerId: "owner",
              type: "operation.receipt",
              operationId: "operation",
              sandboxId: "sandbox",
              generation: 1,
              attempt: 1,
              state: "succeeded",
              bodyHash: "a".repeat(64),
              idempotencyKey: "key",
              kind: "file.stat",
              result: c.value,
              error: null,
            }
          : {
              type: "operation.result",
              id: "result",
              operationId: "operation",
              sandboxId: "sandbox",
              generation: 1,
              attempt: 1,
              state: "succeeded",
              result: c.value,
            };
        for (const version of ["1.0"])
          expect(() => parseDaemonControlFrame(JSON.stringify(frame), version)).not.toThrow();
        for (const version of ["10.0", "10.4", "10.5", "10.6", "10.7", "11.1"])
          expect(() => parseDaemonControlFrame(JSON.stringify(frame), version)).toThrow();
      }
  }
});

it("decodes the shared size-wire fixtures with strict version boundaries", async () => {
  const { launchVmSizeForVersion } = await import("./protocol");
  const cases = JSON.parse(
    readFileSync(join(protocolFixtures, "vm_size_wire_cases.json"), "utf8"),
  ) as {
    name: string;
    kind: string;
    version: string;
    input: unknown;
    valid: boolean;
  }[];
  for (const fixture of cases) {
    let accepted = false;
    try {
      if (fixture.kind === "launch") launchVmSizeForVersion(fixture.input, fixture.version);
      else
        parseDaemonControlFrame(
          JSON.stringify({
            vmCapacity: { memoryBudgetMiB: 65536, maxCpuCount: 32, vcpuBudget: 64 },
            storagePools: capacityFixture("host-1").storagePools,
            journalId: "1234567890abcdef1234567890abcdef",
            type: "host.admission",
            connectionEpoch: 1,
            runtimeKind: "fake",
            schedulable: true,
            egressPolicy: true,
            terminal: true,
            ...(fixture.input as object),
          }),
          fixture.version,
        );
      accepted = true;
    } catch {
      /* Rejection is an assertion outcome, never logged request text. */
    }
    expect(accepted, fixture.name).toBe(fixture.valid);
  }
});

it("returns values-free deterministic launch-size failures", async () => {
  const { launchVmSizeForVersion } = await import("./protocol");
  const failure = () =>
    launchVmSizeForVersion(
      { diskGiB: 32, cpuCount: 2, memoryMiB: "private-input-sentinel" },
      "1.0",
    );
  expect(failure).toThrow(SandboxRelayDispatchValidationError);
  expect(failure).toThrow("Invalid VM size.");
  try {
    failure();
  } catch (error) {
    expect(String(error)).not.toContain("private-input-sentinel");
  }
});

it("targeted allocation wire fixtures have Rust/TS parity", () => {
  const cases = JSON.parse(
    readFileSync(join(protocolFixtures, "allocation_attestation_wire_cases.json"), "utf8"),
  ) as {
    name: string;
    kind: string;
    version: string;
    frame: unknown;
    valid: boolean;
  }[];
  for (const fixture of cases) {
    let accepted = false;
    try {
      if (fixture.kind === "server")
        encodeServerControlMessage(
          fixture.frame as import("./protocol.js").ServerControlMessage,
          fixture.version,
        );
      else parseDaemonControlFrame(JSON.stringify(fixture.frame), fixture.version);
      accepted = true;
    } catch {
      /* fixture rejection */
    }
    expect(accepted, fixture.name).toBe(fixture.valid);
  }
});

it("binds the typed egress refusal reason to unsupported_capability (shared fixture)", () => {
  const { errorReasons } = JSON.parse(
    readFileSync(join(protocolFixtures, "egress_blocklist_cases.json"), "utf8"),
  ) as {
    errorReasons: {
      base: Record<string, unknown>;
      valid: Record<string, string>[];
      invalid: Record<string, string>[];
    };
  };
  const frame = (error: Record<string, string>) =>
    JSON.stringify({ ...errorReasons.base, error: { ...error, message: "refused" } });
  for (const error of errorReasons.valid)
    expect(parseDaemonControlFrame(frame(error), "1.0"), JSON.stringify(error)).toMatchObject({
      error,
    });
  for (const error of errorReasons.invalid)
    expect(() => parseDaemonControlFrame(frame(error), "1.0"), JSON.stringify(error)).toThrow();
});

it("binds a bounded wire capacity reason to the capacity code", () => {
  const frame = {
    type: "operation.result",
    id: "result",
    operationId: "op",
    sandboxId: "sbx",
    generation: 1,
    attempt: 1,
    state: "failed",
    error: { code: "host_capacity", message: "Capacity", reason: "disk" },
  };
  expect(parseDaemonControlFrame(JSON.stringify(frame), "1.0")).toMatchObject({
    error: { reason: "disk" },
  });
  for (const error of [
    { ...frame.error, code: "timeout" },
    { ...frame.error, reason: "private/path" },
  ]) {
    expect(() => parseDaemonControlFrame(JSON.stringify({ ...frame, error }), "1.0")).toThrow();
  }
});

it("binds a readiness failure reason to guest_unavailable only", () => {
  const frame = {
    type: "operation.result",
    id: "result",
    operationId: "op",
    sandboxId: "sbx",
    generation: 1,
    attempt: 1,
    state: "unknown_outcome",
    error: { code: "guest_unavailable", message: "guest_unavailable", reason: "guest_home" },
  };
  expect(parseDaemonControlFrame(JSON.stringify(frame), "1.0")).toMatchObject({
    error: { reason: "guest_home" },
  });
  for (const error of [
    { ...frame.error, code: "host_capacity" },
    { ...frame.error, code: "unsupported_capability" },
    { ...frame.error, reason: "readiness failed: $HOME" },
  ]) {
    expect(() => parseDaemonControlFrame(JSON.stringify({ ...frame, error }), "1.0")).toThrow();
  }
});

// S0 pins final contracts; lifecycle/PTY activation belongs to S3/T1.
import sharingV11Cases from "../../../../crates/sandbox-protocol/fixtures/sharing_cases.json";
import {
  hostTerminalPolicyControlV11Schema,
  terminalControlV11Schema,
  terminalFenceV11Schema,
  transportBindingV11Schema,
  workloadBindingV11Schema,
} from "./protocol";

describe("final sharing 1.0 TS/Rust contracts", () => {
  const codecs = {
    transport: transportBindingV11Schema,
    workload: workloadBindingV11Schema,
    fence: terminalFenceV11Schema,
    terminal: terminalControlV11Schema,
    policy: hostTerminalPolicyControlV11Schema,
  };
  for (const fixture of sharingV11Cases) {
    it(fixture.name, () => {
      const result = codecs[fixture.kind as keyof typeof codecs].safeParse(fixture.input);
      expect(result.success).toBe(fixture.valid);
      if (result.success) expect(result.data).toEqual(fixture.input);
    });
  }
});

import { encodeTerminalDataFrameV11, parseTerminalDataFrameV11 } from "./protocol";

it("typed binary targets round trip and mixed targets deliver no body", () => {
  for (const fixture of sharingV11Cases.filter((c) => c.kind === "fence" && c.valid)) {
    const metadata = {
      type: "terminal.data" as const,
      fence: terminalFenceV11Schema.parse(fixture.input),
      sequence: 0,
    };
    const body = Buffer.from("x");
    expect(parseTerminalDataFrameV11(encodeTerminalDataFrameV11(metadata, body))).toEqual({
      metadata,
      body,
    });
    expect(() => encodeTerminalDataFrameV11(metadata, Buffer.alloc(0))).toThrow();
    expect(() =>
      encodeTerminalDataFrameV11(metadata, Buffer.alloc(TERMINAL_LIMITS.dataMaxBytes + 1)),
    ).toThrow();
    const mixed = {
      ...metadata,
      fence: { ...metadata.fence, target: { kind: "host", sandboxId: "sandbox-a", generation: 1 } },
    };
    const bytes = Buffer.from(JSON.stringify(mixed));
    const frame = Buffer.alloc(5 + bytes.length);
    frame.writeUInt32BE(bytes.length);
    bytes.copy(frame, 4);
    frame[frame.length - 1] = 120;
    expect(() => parseTerminalDataFrameV11(frame)).toThrow();
  }
});

it("shares the image frame fixture with Rust: daemon frames parse, server frames encode, malformed frames are refused", () => {
  const fixture = JSON.parse(
    readFileSync(join(protocolFixtures, "control_image.json"), "utf8"),
  ) as {
    daemon: Array<Record<string, unknown>>;
    server: ServerControlMessage[];
    rejectedDaemon: Array<Record<string, unknown>>;
    rejectedServer: ServerControlMessage[];
  };
  for (const message of fixture.daemon)
    expect(parseDaemonControlFrame(JSON.stringify(message))).toEqual(message);
  for (const message of fixture.server)
    expect(JSON.parse(encodeServerControlMessage(message, "1.0"))).toEqual(message);
  for (const message of fixture.rejectedDaemon)
    expect(
      () => parseDaemonControlFrame(JSON.stringify(message)),
      JSON.stringify(message),
    ).toThrow();
  for (const message of fixture.rejectedServer)
    expect(() => encodeServerControlMessage(message, "1.0"), JSON.stringify(message)).toThrow();
});

it("shares the credential frame fixture with Rust: daemon frames parse, server frames encode, malformed frames are refused", () => {
  const fixture = JSON.parse(
    readFileSync(join(protocolFixtures, "control_credentials.json"), "utf8"),
  ) as {
    daemon: Array<Record<string, unknown>>;
    server: ServerControlMessage[];
    rejectedDaemon: Array<Record<string, unknown>>;
    rejectedServer: ServerControlMessage[];
  };
  for (const message of fixture.daemon)
    expect(parseDaemonControlFrame(JSON.stringify(message)), JSON.stringify(message)).toEqual(
      message,
    );
  for (const message of fixture.server)
    expect(JSON.parse(encodeServerControlMessage(message, "1.0"))).toEqual(message);
  for (const message of fixture.rejectedDaemon)
    expect(
      () => parseDaemonControlFrame(JSON.stringify(message)),
      JSON.stringify(message),
    ).toThrow();
  for (const message of fixture.rejectedServer)
    expect(() => encodeServerControlMessage(message, "1.0"), JSON.stringify(message)).toThrow();
});

it("redacts credential chunk payloads and keeps credential references on key-free stop/kill frames", () => {
  const sentinel = Buffer.from("SENTINEL-PLAINTEXT-TOKEN").toString("base64url");
  for (const type of [
    "credential.bundle.chunk",
    "credential.capture.chunk",
    "credential.spec.chunk",
  ]) {
    const shown = JSON.stringify(
      redactCredentialFrame({ type, requestId: "r1", seq: 0, data: sentinel }),
    );
    expect(shown).not.toContain(sentinel);
    expect(shown).toContain("redacted");
  }
  const ack = { type: "credential.capture.ack", captureId: "c1", outcome: "committed" };
  expect(redactCredentialFrame(ack)).toBe(ack);
  const stop = JSON.parse(
    readFileSync(join(protocolFixtures, "control_expiry_stop_dispatch.json"), "utf8"),
  ) as ServerControlMessage;
  const withSpec = {
    ...stop,
    credentialSpec: { digest: "a".repeat(64), bytes: 1024 },
    credentialCapture: "skip",
  } as ServerControlMessage;
  const encoded = JSON.parse(encodeServerControlMessage(withSpec, "1.0"));
  expect(encoded.credentialSpec).toEqual({ digest: "a".repeat(64), bytes: 1024 });
  expect(encoded.credentialCapture).toBe("skip");
  expect(() =>
    encodeServerControlMessage(
      { ...stop, kind: "sandbox.probe", credentialCapture: "skip" } as ServerControlMessage,
      "1.0",
    ),
  ).toThrow();
});

it("accepts the credential hello capability strictly, like Rust", () => {
  const hello = JSON.parse(
    readFileSync(join(protocolFixtures, "control_hello_daemon.json"), "utf8"),
  );
  const credentials = {
    files: true,
    env: true,
    proxy: false,
    sealedReturn: true,
    checkpoint: true,
    specTransfer: true,
    maxBundleBytes: 4_823_129,
    returnKeyEpoch: 0,
  };
  hello.daemon.capabilities.credentials = credentials;
  expect(hostHelloV11Schema.safeParse(hello).success).toBe(true);
  for (const [key, bad] of [
    ["maxBundleBytes", 4_823_130],
    ["returnKeyEpoch", 9_007_199_254_740_992],
    ["extra", true],
  ] as const) {
    hello.daemon.capabilities.credentials = { ...credentials, [key]: bad };
    expect(hostHelloV11Schema.safeParse(hello).success, key).toBe(false);
  }
});

it("credential paths and the spec cap match the Rust rules", () => {
  for (const ok of [".config/gh/hosts.yml", "a", ".aws", "dir/.wssp", "a".repeat(255)])
    expect(validCredentialPath(ok), ok).toBe(true);
  for (const bad of [
    "",
    "/abs",
    "a/../b",
    "./a",
    "a//b",
    "a/",
    "a\\b",
    "a:b",
    "a\u0000b",
    "a\nb",
    ".wssp",
    ".wssp-journal/x",
    "a".repeat(256),
  ])
    expect(validCredentialPath(bad), JSON.stringify(bad)).toBe(false);
  const spec = {
    version: 1,
    sandboxId: "sbx-1",
    sandboxOwnerId: "owner-1",
    hostOwnerId: "owner-1",
    leases: [],
    residue: [],
  };
  const encoded = new TextEncoder().encode(JSON.stringify(spec));
  const atCap = new Uint8Array(1_179_648).fill(0x20);
  atCap.set(encoded);
  expect(parseCredentialSpec(atCap)).toEqual(spec);
  const over = new Uint8Array(1_179_649).fill(0x20);
  over.set(encoded);
  expect(() => parseCredentialSpec(over)).toThrow();
});

describe("egress relay wire (shared fixtures with crates/sandbox-protocol)", () => {
  const policies = JSON.parse(
    readFileSync(join(protocolFixtures, "egress_policy_cases.json"), "utf8"),
  ) as {
    normalize: { name: string; wire: Record<string, unknown> }[];
    wireInvalid: { name: string; wire: Record<string, unknown> }[];
  };
  const wire = JSON.parse(
    readFileSync(join(protocolFixtures, "control_host_egress_state.json"), "utf8"),
  ) as { reports: Record<string, unknown>[]; invalidReports: Record<string, unknown>[] };
  const launch = {
    sandboxOwnerId: "user-1",
    type: "operation.dispatch" as const,
    operationId: "op-egress-1",
    sandboxId: "sbx-egress-1",
    idempotencyKey: "key-egress-1",
    kind: "sandbox.create",
    generation: 1,
    attempt: 1,
    bodyHash: "a".repeat(64),
    cpuCount: 1,
    memoryMiB: 1024,
    allocation: {
      cpuCount: 1,
      memoryMiB: 1024,
      diskGiB: 32,
      storagePoolName: "default",
      storageMarker: "a".repeat(32),
      chargedMemoryMiB: 1280,
      chargedVcpu: 1,
      rootChargeGiB: 33,
    },
    egressPolicyHash: "b".repeat(64),
  };

  it("encodes every mode's launch policy exactly as recorded (allowlist omits mode)", () => {
    for (const { name, wire: policy } of policies.normalize) {
      const encoded = JSON.parse(
        encodeServerControlMessage(
          { ...launch, egressPolicy: policy } as unknown as ServerControlMessage,
          "1.0",
        ),
      ) as { egressPolicy: unknown };
      expect(encoded.egressPolicy, name).toEqual(policy);
    }
  });

  it("refuses non-canonical launch policies before they reach a daemon", () => {
    for (const { name, wire: policy } of policies.wireInvalid)
      expect(
        () =>
          encodeServerControlMessage(
            { ...launch, egressPolicy: policy } as unknown as ServerControlMessage,
            "1.0",
          ),
        name,
      ).toThrow(SandboxRelayDispatchValidationError);
  });

  it("guest privilege fields: true only, launches only, guestSudo only with guestRoot", () => {
    const base = { ...launch, egressPolicy: policies.normalize[0]!.wire };
    const encode = (frame: Record<string, unknown>) =>
      JSON.parse(
        encodeServerControlMessage(frame as unknown as ServerControlMessage, "1.0"),
      ) as Record<string, unknown>;
    expect(encode({ ...base, guestSudo: true, guestRoot: true })).toMatchObject({
      guestSudo: true,
      guestRoot: true,
    });
    expect(encode({ ...base, guestRoot: true })).not.toHaveProperty("guestSudo");
    const absent = encode(base);
    expect(absent).not.toHaveProperty("guestSudo");
    expect(absent).not.toHaveProperty("guestRoot");
    for (const bad of [
      { ...base, guestSudo: true },
      { ...base, guestSudo: false, guestRoot: true },
      { ...base, guestRoot: false },
      { ...base, guestSudo: true, guestRoot: true, build: { buildId: "b".repeat(24) } },
    ])
      expect(() => encode(bad)).toThrow(SandboxRelayDispatchValidationError);
  });

  it("parses host.egress-state reports to themselves and refuses invalid ones", () => {
    for (const report of wire.reports)
      expect(parseDaemonControlFrame(JSON.stringify(report))).toEqual(report);
    for (const report of wire.invalidReports)
      expect(() => parseDaemonControlFrame(JSON.stringify(report))).toThrow();
  });
});
