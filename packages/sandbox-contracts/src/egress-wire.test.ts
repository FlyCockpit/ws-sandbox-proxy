import { describe, expect, it } from "vitest";
import admissions from "../../../crates/sandbox-protocol/fixtures/control_admission_availability.json";
import hello from "../../../crates/sandbox-protocol/fixtures/control_hello_daemon.json";
import cases from "../../../crates/sandbox-protocol/fixtures/control_host_egress_state.json";
import blocklistCases from "../../../crates/sandbox-protocol/fixtures/egress_blocklist_cases.json";
import {
  egressBlocklistV11Schema,
  egressCapabilitiesV11Schema,
  hostEgressStateV11Schema,
} from "./egress-wire";
import { hostAdmissionV11Schema, hostHelloV11Schema } from "./vm-size";

/**
 * Relay 1.0 egress wire, from the same fixture as
 * `crates/sandbox-protocol/tests/fixtures.rs`: every valid case parses to
 * exactly itself (so TS → Rust → TS is the identity on the fixture), every
 * invalid case is refused.
 */
describe("egress wire (shared fixture with crates/sandbox-protocol)", () => {
  it.each(cases.helloEgress.map((c) => [c.name, c] as const))("hello egress: %s", (_n, c) => {
    const frame = structuredClone(hello) as { daemon: { capabilities: Record<string, unknown> } };
    if ("egress" in c) frame.daemon.capabilities.egress = c.egress;
    const parsed = hostHelloV11Schema.parse(frame);
    expect(parsed).toEqual(frame);
    expect(parsed.daemon.capabilities.egress).toEqual("egress" in c ? c.egress : undefined);
  });

  it("refuses malformed hello egress capabilities", () => {
    for (const invalid of cases.invalidHelloEgress) {
      expect(egressCapabilitiesV11Schema.safeParse(invalid).success).toBe(false);
      const frame = structuredClone(hello) as { daemon: { capabilities: Record<string, unknown> } };
      frame.daemon.capabilities.egress = invalid;
      expect(hostHelloV11Schema.safeParse(frame).success, JSON.stringify(invalid)).toBe(false);
    }
  });

  const admission = admissions[0]?.frame as Record<string, unknown>;

  it("carries the egressOpen admission bit, omitted when false", () => {
    expect(admission.type).toBe("host.admission");
    for (const c of cases.admissionEgressOpen) {
      const frame = "egressOpen" in c ? { ...admission, egressOpen: c.egressOpen } : admission;
      const parsed = hostAdmissionV11Schema.parse(frame);
      expect(parsed).toEqual(frame);
      expect(parsed.egressOpen === true).toBe(c.stored);
    }
    for (const c of cases.admissionEgressOpenNonCanonical)
      expect(
        hostAdmissionV11Schema.parse({ ...admission, egressOpen: c.egressOpen }).egressOpen,
      ).toBe(c.stored);
    for (const invalid of cases.invalidAdmissionEgressOpen)
      expect(hostAdmissionV11Schema.safeParse({ ...admission, egressOpen: invalid }).success).toBe(
        false,
      );
  });

  it("parses every valid host.egress-state report to itself and refuses invalid ones", () => {
    for (const report of cases.reports)
      expect(hostEgressStateV11Schema.parse(report)).toEqual(report);
    for (const report of cases.invalidReports)
      expect(hostEgressStateV11Schema.safeParse(report).success, JSON.stringify(report)).toBe(
        false,
      );
  });
});

describe("egress.blocklist (shared fixture with crates/sandbox-protocol)", () => {
  it("parses every valid frame to itself and refuses every invalid one", () => {
    for (const frame of blocklistCases.frames.valid)
      expect(egressBlocklistV11Schema.parse(frame)).toEqual(frame);
    for (const c of blocklistCases.frames.invalid)
      expect(egressBlocklistV11Schema.safeParse(c.frame).success, c.name).toBe(false);
  });
});
