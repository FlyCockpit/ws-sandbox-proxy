import { expect, it } from "vitest";
import hello from "../../../../crates/sandbox-protocol/fixtures/control_hello_daemon.json";
import fixtures from "../../../../crates/sandbox-protocol/fixtures/control_host_access.json";
import { hostServerMessageSchema } from "./host-access-protocol";
import {
  encodeServerControlMessage,
  parseDaemonControlFrame,
  SANDBOX_RELAY_PROTOCOL_VERSION,
} from "./protocol";

it("parses and encodes every Rust host-access fixture, with strict unknown-field rejection", () => {
  for (const frame of fixtures.daemon) {
    expect(parseDaemonControlFrame(JSON.stringify(frame))).toEqual(frame);
    expect(() => parseDaemonControlFrame(JSON.stringify({ ...frame, undeclared: true }))).toThrow();
  }
  expect(() =>
    encodeServerControlMessage(
      { type: "host.policy.raise" } as never,
      SANDBOX_RELAY_PROTOCOL_VERSION,
    ),
  ).toThrow("Unsupported host policy request.");
  for (const frame of fixtures.server) {
    const parsed = hostServerMessageSchema.parse(frame);
    expect(JSON.parse(encodeServerControlMessage(parsed, SANDBOX_RELAY_PROTOCOL_VERSION))).toEqual(
      frame,
    );
    expect(hostServerMessageSchema.safeParse({ ...frame, undeclared: true }).success).toBe(false);
  }
  expect(
    hostServerMessageSchema.safeParse({
      type: "host.policy.raise",
      connectionEpoch: 1,
      requestId: "req",
      target: "hostCommands",
    }).success,
  ).toBe(false);
});
it("accepts agent capabilities only with a coherent policy and preserves large host-only frames", () => {
  const capabilities = {
    ...hello.daemon.capabilities,
    hostCommands: true,
    hostFiles: true,
    hostCommandMaxMs: 600000,
    agentPolicyRevision: 2,
  };
  expect(
    parseDaemonControlFrame(JSON.stringify({ ...hello, daemon: { ...hello.daemon, capabilities } }))
      .type,
  ).toBe("hello");
  expect(() =>
    parseDaemonControlFrame(
      JSON.stringify({
        ...hello,
        daemon: { ...hello.daemon, capabilities: { ...capabilities, hostCommands: false } },
      }),
    ),
  ).toThrow();
  const status = fixtures.daemon.find((f) => f.type === "host.exec.status")!;
  expect(
    parseDaemonControlFrame(
      JSON.stringify({
        ...status,
        stdout: { offset: 0, dropped: false, data: Buffer.alloc(65536).toString("base64") },
      }),
    ).type,
  ).toBe("host.exec.status");
});
