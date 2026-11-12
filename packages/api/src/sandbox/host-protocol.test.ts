vi.mock("@wssp/env/server", () => ({
  env: { SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4) },
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});

import { expect, it, vi } from "vitest";
import { fsProcessHostRefused, fsProcessHostSupported } from "./host-protocol";

it("requires exact 1.0 with the existing epoch and runtime fences", () => {
  const host = {
    relayProtocolVersion: "1.0",
    relayProtocolEpoch: 2,
    connectionEpoch: 2,
    admissionEpoch: 2,
    admissionRuntime: "FAKE",
  };
  expect(fsProcessHostSupported(host)).toBe(true);
  for (const relayProtocolVersion of [null, "10.0", "10.5", "10.6", "10.7", "11.1"])
    expect(fsProcessHostSupported({ ...host, relayProtocolVersion })).toBe(false);
  expect(fsProcessHostSupported({ ...host, relayProtocolEpoch: 1 })).toBe(false);
  expect(fsProcessHostSupported({ ...host, admissionEpoch: 1 })).toBe(false);
  expect(fsProcessHostSupported({ ...host, admissionRuntime: "UNSUPPORTED" })).toBe(false);
});

it("refuses admission only on positive current-epoch evidence of no support", () => {
  const host = {
    relayProtocolVersion: "1.0",
    relayProtocolEpoch: 2,
    connectionEpoch: 2,
    admissionEpoch: 2,
    admissionRuntime: "FAKE",
  };
  expect(fsProcessHostRefused(host)).toBe(false);
  expect(fsProcessHostRefused({ ...host, admissionRuntime: "INCUS_KVM" })).toBe(false);
  // Post-hello, pre-admission (every relay reconnect): nothing proven yet.
  const reconnecting = { ...host, connectionEpoch: 3, relayProtocolEpoch: 3 };
  expect(
    fsProcessHostRefused({ ...reconnecting, admissionEpoch: null, admissionRuntime: null }),
  ).toBe(false);
  expect(fsProcessHostRefused({ ...reconnecting, admissionRuntime: "UNSUPPORTED" })).toBe(false);
  expect(fsProcessHostSupported({ ...reconnecting, admissionEpoch: null })).toBe(false);
  // Stale protocol facts from another epoch prove nothing either.
  expect(
    fsProcessHostRefused({ ...host, relayProtocolVersion: "10.7", relayProtocolEpoch: 1 }),
  ).toBe(false);
  // Current-epoch evidence of an older protocol or unsupported runtime refuses.
  for (const relayProtocolVersion of ["10.0", "10.5", "10.7", "11.1"])
    expect(fsProcessHostRefused({ ...host, relayProtocolVersion })).toBe(true);
  expect(fsProcessHostRefused({ ...host, admissionRuntime: "UNSUPPORTED" })).toBe(true);
  expect(
    fsProcessHostRefused({ ...reconnecting, admissionEpoch: 3, admissionRuntime: "UNSUPPORTED" }),
  ).toBe(true);
});
