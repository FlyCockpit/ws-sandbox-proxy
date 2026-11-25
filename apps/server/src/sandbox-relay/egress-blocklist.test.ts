import { egressBlocklistV11Schema } from "@wssp/sandbox-contracts";
import { describe, expect, it, vi } from "vitest";
import cases from "../../../../crates/sandbox-protocol/fixtures/egress_blocklist_cases.json";

const env = vi.hoisted(() => ({
  SANDBOX_EGRESS_BLOCKLIST: "203.0.113.1/24" as string | undefined,
}));
vi.mock("@wssp/env/server", () => ({ env }));

import {
  blocklistDigest,
  deploymentEgressBlocklist,
  egressBlocklistFrame,
  parseDeploymentBlocklist,
} from "./egress-blocklist";
import { encodeServerControlMessage } from "./protocol";

/**
 * E6 relay side, from the fixture the guard parser test
 * (`crates/sandbox-runtime/src/guard/tests/sources.rs`) also reads: the
 * relay accepts exactly what the guard accepts, normalized, and refuses
 * what it refuses at the same entry.
 */
describe("SANDBOX_EGRESS_BLOCKLIST (shared fixture with the guard parser)", () => {
  it.each(cases.env.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    const parsed = parseDeploymentBlocklist(c.raw ?? undefined);
    expect(parsed.state).toBe(c.state);
    if (parsed.state === "invalid") {
      expect("invalidEntry" in c ? c.invalidEntry : undefined).toBe(parsed.entry);
    } else {
      expect(parsed.entries).toEqual(c.entries);
      expect(parsed.digest).toBe("digest" in c ? c.digest : undefined);
    }
    const frame = egressBlocklistFrame(parsed);
    expect(egressBlocklistV11Schema.parse(frame)).toEqual(frame);
    expect(JSON.parse(encodeServerControlMessage(frame, "1.0"))).toEqual(frame);
    if (parsed.state === "invalid") {
      // M13: an invalid configured list is never sent as an empty one.
      expect(frame).toMatchObject({ configured: true, entries: [], invalid: true });
    }
  });

  it("digest is sha256 of JSON.stringify(entries)", () => {
    expect(blocklistDigest([])).toBe(cases.frames.valid[0]?.digest);
  });

  it("enforces the guard limits and the relay frame limit without throwing", () => {
    const cidrs = (n: number) =>
      Array.from({ length: n }, (_, i) => `${100 + (i >> 8)}.${i & 255}.200.128/25`).join(",");
    expect(parseDeploymentBlocklist(cidrs(4097))).toMatchObject({
      state: "invalid",
      reason: "more than 4096 CIDRs",
      entry: 4097,
    });
    // 4096 CIDRs are within the guard's limit but not one 64 KiB frame.
    expect(parseDeploymentBlocklist(cidrs(4096))).toMatchObject({
      state: "invalid",
      reason: expect.stringContaining("64 KiB"),
    });
    const fits = parseDeploymentBlocklist(cidrs(2000));
    expect(fits.state).toBe("valid");
    expect(
      Buffer.byteLength(encodeServerControlMessage(egressBlocklistFrame(fits), "1.0")),
    ).toBeLessThanOrEqual(65_536);
    const domains = Array.from({ length: 2049 }, (_, i) => `d${i}.example`).join(" ");
    expect(parseDeploymentBlocklist(domains)).toMatchObject({
      state: "invalid",
      reason: "more than 2048 domains",
    });
    const long = Array.from({ length: 900 }, (_, i) => `${"a".repeat(60)}.d${i}.example`).join(",");
    expect(parseDeploymentBlocklist(long)).toMatchObject({
      state: "invalid",
      reason: "rendered domain list exceeds 63 KiB",
    });
  });

  it("refuses to encode a malformed frame", () => {
    expect(() =>
      encodeServerControlMessage(
        { type: "egress.blocklist", configured: true, entries: [], digest: blocklistDigest([]) },
        "1.0",
      ),
    ).toThrow();
  });

  it("boot validation logs an invalid list once, without the list, and never throws", () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(deploymentEgressBlocklist()).toMatchObject({ state: "invalid", entry: 1 });
    env.SANDBOX_EGRESS_BLOCKLIST = undefined;
    expect(deploymentEgressBlocklist().state).toBe("invalid");
    expect(log).toHaveBeenCalledTimes(1);
    expect(String(log.mock.calls[0]?.[0])).toContain("at entry 1");
    expect(String(log.mock.calls[0]?.[0])).not.toContain("203.0.113");
    log.mockRestore();
  });
});
