import { createHmac } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));

import {
  hashOperationRequestBody,
  hashRequestBody,
  hashRevisionDefaultsBody,
  hostJournalKey,
  privateConfigBinding,
  reconcileIdempotency,
  requestDigestMetadata,
} from "./idempotency";

describe("idempotency", () => {
  it("hashes bodies independently of key order", () => {
    const a = hashRequestBody({ b: 1, a: 2 });
    const b = hashRequestBody({ a: 2, b: 1 });
    expect(a).toBe(b);
  });

  it("throws on hash mismatch", () => {
    try {
      reconcileIdempotency({ requestBodyHash: "aaa", ...requestDigestMetadata() }, "bbb");
      expect.unreachable("expected conflict");
    } catch (error) {
      expect(error).toMatchObject({ code: "CONFLICT" });
    }
  });
});

it("binds Date values and prototype-named JSON keys without changing ordinary canonical ordering", () => {
  expect(hashRequestBody({ lease: new Date("2026-09-26T00:00:00Z") })).not.toBe(
    hashRequestBody({ lease: new Date("2026-09-27T00:00:00Z") }),
  );
  expect(hashRequestBody(JSON.parse('{"__proto__":{"x":1}}'))).not.toBe(hashRequestBody({}));
  expect(hashRequestBody({ b: false, a: null })).toBe(hashRequestBody({ a: null, b: false }));
});

it("checks the key ID before invoking the digest, for either body after rotation", async () => {
  const { env } = await import("@wssp/env/server");
  const original = env.SANDBOX_REQUEST_HMAC_SECRET;
  const prior = {
    requestBodyHash: hashRequestBody({ env: "private" }),
    ...requestDigestMetadata(),
  };
  Object.assign(env, { SANDBOX_REQUEST_HMAC_SECRET: "fedcba9876543210".repeat(4) });
  try {
    for (const body of [{ env: "private" }, { env: "different" }]) {
      const digest = vi.fn(() => hashRequestBody(body));
      expect(() => reconcileIdempotency(prior, digest)).toThrow("Digest key changed.");
      expect(digest).not.toHaveBeenCalled();
    }
  } finally {
    Object.assign(env, { SANDBOX_REQUEST_HMAC_SECRET: original });
  }
});
it("separates request/action/owner/host/principal domains and rejects unknown schemes", () => {
  const body = { env: "private" };
  const baseline = hashRequestBody(body);
  for (const context of [
    { domain: "wssp-action-v1" },
    { ownerId: "owner" },
    { hostId: "host" },
    { hostOwnerId: "transport-owner" },
    { authorizingKeyId: "key" },
  ]) {
    expect(hashRequestBody(body, context)).not.toBe(baseline);
  }
  const digest = vi.fn(() => baseline);
  expect(() =>
    reconcileIdempotency(
      {
        requestBodyHash: baseline,
        requestDigestScheme: "unknown-scheme",
        requestDigestKeyId: null,
      },
      digest,
    ),
  ).toThrow("Digest key changed.");
  expect(digest).not.toHaveBeenCalled();
});

it("derives stable per-server owner and enrolled-host keys with the specified LP domain", () => {
  const first = hostJournalKey("owner", "host");
  expect(hostJournalKey("owner", "host").keyHex === first.keyHex).toBe(true);
  expect(hostJournalKey("other", "host").keyHex === first.keyHex).toBe(false);
  expect(hostJournalKey("owner", "other").keyHex === first.keyHex).toBe(false);
  expect(first).toMatchObject({ server: "ws://localhost:3000/ws/sandbox-host", keyVersion: 1 });
});

it("request HMAC and host key derivation match independent LP vectors", () => {
  expect(requestDigestMetadata().requestDigestKeyId).toBe("8b5de811559de0500133031b29046644");
  expect(hashRequestBody({ env: { K: "private" } })).toBe(
    "8e3145ce71fc949b09d4ab20e8c3d98ebb8d9c47337afbee7a97836522b89f26",
  );
  const host = hostJournalKey("owner", "host");
  const proof = createHmac("sha256", Buffer.from(host.keyHex, "hex"))
    .update(Buffer.concat([Buffer.from([0, 0, 0, 14]), Buffer.from("host-key-proof")]))
    .digest("hex");
  expect(proof).toBe("43a24a275fac09cf2aac6a38d4c38610876390c82369467031abcbde72b89173");
});

it("private config server binding has a separate LP domain, identity and principal", () => {
  const input = {
    configId: "config",
    sandboxId: "sandbox",
    generation: 1,
    env: [
      ["B", "second"],
      ["A", "first"],
    ] as [string, string][],
  };
  const context = {
    ownerId: "owner",
    hostOwnerId: "host-owner",
    hostId: "host",
    authorizingKeyId: "sdk-key",
  };
  const binding = privateConfigBinding(input, context);
  expect(binding.bindingScheme).toBe("hmac-sha256-v1");
  expect(binding.bindingKeyId).toBe(requestDigestMetadata().requestDigestKeyId);
  expect(binding.bindingMac).toBe(
    "603cbad7b1e80d2cb329c84da22f25b505435b2e6064ce83b9dd10565adac17d",
  );
  expect(privateConfigBinding({ ...input, env: [...input.env].reverse() }, context)).toEqual(
    binding,
  );
  expect(binding.bindingMac).not.toBe(hashRequestBody(input, context));
  for (const patch of [
    { ownerId: "other" },
    { hostOwnerId: "other" },
    { hostId: "other" },
    { authorizingKeyId: null },
  ])
    expect(privateConfigBinding(input, { ...context, ...patch }).bindingMac).not.toBe(
      binding.bindingMac,
    );
  for (const patch of [
    { configId: "other" },
    { sandboxId: "other" },
    { generation: 2 },
    { env: [["A", "changed"]] as [string, string][] },
  ])
    expect(privateConfigBinding({ ...input, ...patch }, context).bindingMac).not.toBe(
      binding.bindingMac,
    );
});

it("3B bound request HMAC has independent LP owner/host/authorizer vectors and canonical determinism", () => {
  const body = { envs: { B: "second", A: "first" } };
  const context = {
    ownerId: "owner",
    hostOwnerId: "host-owner",
    hostId: "host",
    authorizingKeyId: "sdk-key",
  };
  const lp = (value: string) => {
    const bytes = Buffer.from(value);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    return Buffer.concat([length, bytes]);
  };
  const expected = createHmac("sha256", Buffer.from("0123456789abcdef".repeat(4), "hex"))
    .update(
      Buffer.concat(
        [
          "wssp-request-v2",
          "8b5de811559de0500133031b29046644",
          "http://localhost:3000",
          "owner",
          "host",
          "host-owner",
          "sdk-key",
          '{"envs":{"A":"first","B":"second"}}',
        ].map(lp),
      ),
    )
    .digest("hex");
  expect(hashOperationRequestBody(body, "RUN_COMMAND", context)).toBe(expected);
  expect(hashRequestBody({ envs: { A: "first", B: "second" } }, context)).toBe(expected);
  for (const changed of [
    { ownerId: "other" },
    { hostId: "other" },
    { hostOwnerId: "other-owner" },
    { authorizingKeyId: "other" },
    { authorizingKeyId: null },
    { domain: "wssp-action-v1" },
  ])
    expect(hashRequestBody(body, { ...context, ...changed })).not.toBe(expected);
});

it("hashes source defaults with the independent owner domain", () => {
  expect(
    hashRevisionDefaultsBody({ revisionId: "revision", env: [["A", "first"]] }, "creator"),
  ).toBe("1378eda30b86c95b200f1b25643adbd8c53edecdfa31a9c2dc500e131a1ec775");
});
