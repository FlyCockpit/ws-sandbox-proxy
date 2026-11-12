import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { daemonCapabilitiesV11Schema } from "@wssp/sandbox-contracts";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({ env: {} }));

const {
  encodeServerControlMessage,
  negotiatedCapabilities,
  parseDaemonControlFrame,
  PENDING_RECEIPTS_MAX,
} = await import("./protocol");

// Shared with `crates/sandbox-protocol/tests/reconnect_wp2_frames.rs`.
const fixtures = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/sandbox-protocol/fixtures",
);
const read = (name: string) => JSON.parse(readFileSync(join(fixtures, name), "utf8"));
const fixture = read("reconnect_wp2_frames.json") as {
  capabilities: ("pendingReceipts" | "expiryStatusResults" | "observationFence")[];
  validOffers: unknown[];
  rejectedOffers: unknown[];
  helloOkCapabilities: Record<string, unknown>;
  reconcileComplete: unknown[];
  rejectedReconcileComplete: unknown[];
  expiryStatus: Record<string, unknown>;
  rejectedExpiryBatches: unknown[];
  rejectedObservations: unknown[];
  ack: { type: "sandbox.expiry_status.ack"; batch: number; entryResults: unknown[] };
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
const parse = (frame: unknown) => parseDaemonControlFrame(JSON.stringify(frame), "1.0");

describe("reconnect WP2 frames parity with Rust", () => {
  it("parses each offer only as an explicit true", () => {
    const caps = hello.daemon.capabilities;
    for (const name of fixture.capabilities) {
      expect(daemonCapabilitiesV11Schema.parse(caps)[name]).toBe(true);
      for (const offer of fixture.validOffers) {
        const frame = {
          ...hello,
          daemon: { ...hello.daemon, capabilities: { ...caps, [name]: offer } },
        };
        const parsed = parse(frame);
        expect(parsed.type === "hello" && parsed.daemon.capabilities[name]).toBe(true);
      }
      for (const offer of fixture.rejectedOffers)
        expect(
          daemonCapabilitiesV11Schema.safeParse({ ...caps, [name]: offer }).success,
          `${name}=${JSON.stringify(offer)}`,
        ).toBe(false);
    }
  });

  it("encodes the shared hello.ok answer and refuses a false one", () => {
    const answered = {
      ...negotiatedCapabilities("1.0"),
      pendingReceipts: true,
      expiryStatusResults: true,
      observationFence: true,
    };
    expect(answered).toEqual(fixture.helloOkCapabilities);
    expect(
      JSON.parse(encodeServerControlMessage(helloOk(answered) as never, "1.0")).capabilities,
    ).toEqual(fixture.helloOkCapabilities);
    for (const name of fixture.capabilities)
      expect(() =>
        encodeServerControlMessage(
          helloOk({ ...negotiatedCapabilities("1.0"), [name]: false }) as never,
          "1.0",
        ),
      ).toThrow("Invalid hello capabilities.");
  });

  it("bounds reconcile.complete pendingReceipts exactly like Rust", () => {
    expect(PENDING_RECEIPTS_MAX).toBe(4);
    for (const frame of fixture.reconcileComplete) expect(parse(frame)).toEqual(frame);
    for (const frame of fixture.rejectedReconcileComplete)
      expect(() => parse(frame), JSON.stringify(frame)).toThrow();
  });

  it("parses batched expiry status and encodes the shared ack", () => {
    expect(parse(fixture.expiryStatus)).toEqual(fixture.expiryStatus);
    const { batch: _batch, observation: _observation, ...unbatched } = fixture.expiryStatus;
    expect(parse(unbatched)).toEqual(unbatched);
    // A batch without an observation parses (the session refuses it once the
    // fence is negotiated); an observation without a batch never does.
    const { observation: _unfenced, ...unfenced } = fixture.expiryStatus;
    expect(parse(unfenced)).toEqual(unfenced);
    const { batch: _alone, ...alone } = fixture.expiryStatus;
    expect(() => parse(alone)).toThrow();
    for (const batch of fixture.rejectedExpiryBatches)
      expect(() => parse({ ...fixture.expiryStatus, batch }), JSON.stringify(batch)).toThrow();
    for (const observation of fixture.rejectedObservations)
      expect(
        () => parse({ ...fixture.expiryStatus, observation }),
        JSON.stringify(observation),
      ).toThrow();
    expect(JSON.parse(encodeServerControlMessage(fixture.ack as never, "1.0"))).toEqual(
      fixture.ack,
    );
  });
});
