import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { daemonCapabilitiesV11Schema, validHintDnsName } from "@wssp/sandbox-contracts";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({ env: {} }));

const { EgressHintThrottle } = await import("./egress-hints");
const { parseDaemonControlFrame } = await import("./protocol");

// Shared with `crates/sandbox-protocol/tests/egress_refused.rs` (B12).
const fixtures = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/sandbox-protocol/fixtures",
);
const fixture = JSON.parse(readFileSync(join(fixtures, "egress_refused.json"), "utf8")) as {
  frames: unknown[];
  rejectedFrames: unknown[];
  validNames: string[];
  invalidNames: string[];
  capabilities: unknown[];
  rejectedCapabilities: unknown[];
};
const helloCaps = (
  JSON.parse(readFileSync(join(fixtures, "control_hello_daemon.json"), "utf8")) as {
    daemon: { capabilities: Record<string, unknown> };
  }
).daemon.capabilities;

describe("egress.refused parity with Rust", () => {
  it("parses the shared valid frames and refuses the rejected ones", () => {
    for (const frame of fixture.frames)
      expect(parseDaemonControlFrame(JSON.stringify(frame), "1.0")).toEqual(frame);
    for (const frame of fixture.rejectedFrames)
      expect(
        () => parseDaemonControlFrame(JSON.stringify(frame), "1.0"),
        JSON.stringify(frame),
      ).toThrow();
  });

  it("shares the DNS name grammar", () => {
    for (const name of fixture.validNames) expect(validHintDnsName(name), name).toBe(true);
    for (const name of fixture.invalidNames)
      expect(validHintDnsName(name), JSON.stringify(name)).toBe(false);
  });

  it("treats egressRefusedHints as an optional strict boolean", () => {
    expect(daemonCapabilitiesV11Schema.parse(helloCaps).egressRefusedHints).toBeUndefined();
    for (const value of fixture.capabilities)
      expect(
        daemonCapabilitiesV11Schema.parse({ ...helloCaps, egressRefusedHints: value })
          .egressRefusedHints,
      ).toBe(value);
    for (const value of fixture.rejectedCapabilities)
      expect(
        daemonCapabilitiesV11Schema.safeParse({ ...helloCaps, egressRefusedHints: value }).success,
      ).toBe(false);
  });
});

describe("relay hint throttle", () => {
  it("holds a sandbox to one frame every 2 s in the long run", () => {
    const throttle = new EgressHintThrottle();
    let admitted = 0;
    for (let at = 0; at < 20_000; at += 100) if (throttle.admit("a", at)) admitted += 1;
    // 2 banked frames + one per 2 s over 20 s.
    expect(admitted).toBeLessThanOrEqual(12);
    expect(throttle.admit("b", 19_999)).toBe(true);
  });

  it("admits a frame that arrives early after a late one (E3B-01)", () => {
    const throttle = new EgressHintThrottle();
    // Daemon sends at 0 and 2250 ms; the first is handled late (300 ms) and
    // the second early (2100 ms): 1800 ms apart on arrival.
    expect(throttle.admit("a", 300)).toBe(true);
    expect(throttle.admit("a", 2100)).toBe(true);
  });

  it("refuses a third back-to-back frame", () => {
    const throttle = new EgressHintThrottle();
    expect(throttle.admit("a", 0)).toBe(true);
    expect(throttle.admit("a", 1)).toBe(true);
    expect(throttle.admit("a", 2)).toBe(false);
    expect(throttle.admit("a", 2002)).toBe(true);
  });
});
