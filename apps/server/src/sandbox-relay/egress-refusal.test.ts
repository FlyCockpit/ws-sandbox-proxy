import { describe, expect, it } from "vitest";

import { createResultDeniedGrants, daemonEgressRefusal } from "./egress-refusal.js";

describe("daemonEgressRefusal (§1.5)", () => {
  it("maps a typed reason on unsupported_capability, and nothing else", () => {
    expect(
      daemonEgressRefusal({ code: "unsupported_capability", reason: "open_egress_not_permitted" }),
    ).toBe("open_egress_not_permitted");
    expect(
      daemonEgressRefusal({ code: "unsupported_capability", reason: "egress_guard_unavailable" }),
    ).toBe("egress_guard_unavailable");
    // Today's daemons send no reason: the generic code is kept.
    expect(daemonEgressRefusal({ code: "unsupported_capability" })).toBeUndefined();
    expect(daemonEgressRefusal({ code: "unsupported_capability", reason: "ram" })).toBeUndefined();
    // An egress reason on any other code is not a refusal.
    expect(
      daemonEgressRefusal({ code: "host_capacity", reason: "egress_guard_unavailable" }),
    ).toBeUndefined();
  });
});

describe("createResultDeniedGrants (M19)", () => {
  it("reads the bounded denied grants of a create result", () => {
    expect(createResultDeniedGrants({ state: "ready" })).toBeUndefined();
    expect(
      createResultDeniedGrants({
        state: "ready",
        egressDeniedGrants: ["bad.example", "api.bad.example", "bad.example"],
      }),
    ).toEqual(["api.bad.example", "bad.example"]);
    expect(createResultDeniedGrants({ state: "ready", egressDeniedGrants: [] })).toEqual([]);
  });

  it("ignores malformed or unbounded lists (display data never fails a result)", () => {
    for (const egressDeniedGrants of [
      "bad.example",
      ["Bad.Example"],
      ["no-dot"],
      [1],
      Array.from({ length: 129 }, (_, i) => `d${i}.example`),
    ])
      expect(createResultDeniedGrants({ egressDeniedGrants })).toBeUndefined();
    expect(createResultDeniedGrants(undefined)).toBeUndefined();
  });
});
