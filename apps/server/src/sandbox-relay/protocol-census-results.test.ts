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

// Shared with `crates/sandbox-protocol/tests/census_entry_results.rs`.
const fixtures = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/sandbox-protocol/fixtures",
);
const read = (name: string) => JSON.parse(readFileSync(join(fixtures, name), "utf8"));
const fixture = read("census_entry_results.json") as {
  validOffers: unknown[];
  rejectedOffers: unknown[];
  helloOkCapabilities: Record<string, unknown>;
  ack: { type: "inventory.ack"; page: number; entryResults: unknown[] };
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

describe("per-entry census results parity with Rust", () => {
  it("parses the offer only as an explicit true", () => {
    const caps = hello.daemon.capabilities;
    expect(daemonCapabilitiesV11Schema.parse(caps).censusEntryResults).toBe(true);
    for (const offer of fixture.validOffers) {
      const frame = {
        ...hello,
        daemon: { ...hello.daemon, capabilities: { ...caps, censusEntryResults: offer } },
      };
      const parsed = parseDaemonControlFrame(JSON.stringify(frame), "1.0");
      expect(parsed.type === "hello" && parsed.daemon.capabilities.censusEntryResults).toBe(true);
    }
    for (const offer of fixture.rejectedOffers)
      expect(
        daemonCapabilitiesV11Schema.safeParse({ ...caps, censusEntryResults: offer }).success,
        JSON.stringify(offer),
      ).toBe(false);
  });

  it("encodes the shared hello.ok answer and the shared judged inventory.ack", () => {
    const answered = { ...negotiatedCapabilities("1.0"), censusEntryResults: true };
    expect(answered).toEqual(fixture.helloOkCapabilities);
    expect(
      JSON.parse(encodeServerControlMessage(helloOk(answered) as never, "1.0")).capabilities,
    ).toEqual(fixture.helloOkCapabilities);
    expect(() =>
      encodeServerControlMessage(
        helloOk({ ...negotiatedCapabilities("1.0"), censusEntryResults: false }) as never,
        "1.0",
      ),
    ).toThrow("Invalid hello capabilities.");
    expect(JSON.parse(encodeServerControlMessage(fixture.ack as never, "1.0"))).toEqual(
      fixture.ack,
    );
  });
});
