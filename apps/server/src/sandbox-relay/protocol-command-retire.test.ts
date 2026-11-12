import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { daemonCapabilitiesV11Schema } from "@wssp/sandbox-contracts";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({ env: {} }));

const { encodeServerControlMessage, negotiatedCapabilities, parseDaemonControlFrame } =
  await import("./protocol");

// Shared with `crates/sandbox-protocol/tests/command_retire_frames.rs`.
const fixtures = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/sandbox-protocol/fixtures",
);
const read = (name: string) => JSON.parse(readFileSync(join(fixtures, name), "utf8"));
const fixture = read("command_retire_frames.json") as {
  capability: "commandRetire";
  validOffers: unknown[];
  rejectedOffers: unknown[];
  helloOkCapabilities: Record<string, unknown>;
  retireConfirmation: Record<string, unknown>;
};
const hello = read("control_hello_daemon.json") as {
  daemon: { capabilities: Record<string, unknown> };
};
const helloOk = (capabilities: Record<string, unknown>) => ({
  type: "hello.ok" as const,
  id: "hello-1",
  protocolVersion: "1.0" as const,
  supportedProtocolVersions: ["1.0"],
  hostOwnerId: "owner-1",
  connectionEpoch: 1,
  capabilities,
});

describe("plan §10 commandRetire parity with Rust", () => {
  it("parses the offer only as an explicit true", () => {
    const caps = hello.daemon.capabilities;
    const name = fixture.capability;
    expect(daemonCapabilitiesV11Schema.parse(caps)[name]).toBe(true);
    for (const offer of fixture.validOffers) {
      const parsed = parseDaemonControlFrame(
        JSON.stringify({
          ...hello,
          daemon: { ...hello.daemon, capabilities: { ...caps, [name]: offer } },
        }),
        "1.0",
      );
      expect(parsed.type === "hello" && parsed.daemon.capabilities[name]).toBe(true);
    }
    for (const offer of fixture.rejectedOffers)
      expect(daemonCapabilitiesV11Schema.safeParse({ ...caps, [name]: offer }).success).toBe(false);
  });

  it("encodes the shared hello.ok answer and refuses a false one", () => {
    const answered = { ...negotiatedCapabilities("1.0"), commandRetire: true };
    expect(answered).toEqual(fixture.helloOkCapabilities);
    expect(
      JSON.parse(encodeServerControlMessage(helloOk(answered) as never, "1.0")).capabilities,
    ).toEqual(fixture.helloOkCapabilities);
    expect(() =>
      encodeServerControlMessage(
        helloOk({ ...negotiatedCapabilities("1.0"), commandRetire: false }) as never,
        "1.0",
      ),
    ).toThrow("Invalid hello capabilities.");
  });

  it("encodes receipt.confirmed retireCommand exactly as the shared frame", () => {
    expect(
      JSON.parse(encodeServerControlMessage(fixture.retireConfirmation as never, "1.0")),
    ).toEqual(fixture.retireConfirmation);
  });
});
