import { expect, it } from "vitest";
import { knownRelayProtocolVersion } from "./relay-version";

it("accepts only the current relay version", () => {
  expect(knownRelayProtocolVersion("1.0")).toBe(true);
  for (const version of ["0.1", "0.9", "1.1", "2.0", "", "1", "1.0.0", null, undefined]) {
    expect(knownRelayProtocolVersion(version)).toBe(false);
  }
});
