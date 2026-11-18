import { expect, it } from "vitest";
import { createWsspClient } from "./client";
import { WsspError } from "./errors";

const key = {
  id: "key_1",
  name: "wssp login",
  origin: "cliLogin",
  scopes: ["sandboxes:read"],
  resourceMode: "allOwned",
  poolMode: "selected",
  pools: [{ id: "pool_1", slug: "lab", label: "Lab" }],
  ownSandboxesOnly: true,
  expiresAt: "2026-12-18T00:00:00.000Z",
  maxLiveSandboxes: 3,
  liveSandboxes: 1,
} as const;

function client(respond: (request: Request) => Response, calls: Request[] = []) {
  return createWsspClient({
    baseUrl: "https://api.example.test",
    apiKey: "wssp_sdk_fixture",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      calls.push(request);
      return respond(request);
    },
  });
}

it("reads the calling key and revokes it with GET and DELETE /v1/key", async () => {
  const calls: Request[] = [];
  const sdk = client(
    (request) => Response.json(request.method === "GET" ? key : { id: key.id, revoked: true }),
    calls,
  );
  expect(await sdk.key.get()).toEqual(key);
  expect(await sdk.key.revokeSelf()).toEqual({ id: key.id, revoked: true });
  expect(calls.map((request) => `${request.method} ${new URL(request.url).pathname}`)).toEqual([
    "GET /v1/key",
    "DELETE /v1/key",
  ]);
});

it("rejects a key description outside the strict contract", async () => {
  const sdk = client(() => Response.json({ ...key, email: "owner@example.test" }));
  await expect(sdk.key.get()).rejects.toBeInstanceOf(WsspError);
});

it("types a dashboard key's refused self-revoke as an authorization error", async () => {
  const sdk = client(() =>
    Response.json(
      {
        error: {
          code: "key.self_revoke_forbidden",
          message: "Only a CLI login key can revoke itself; revoke this key on the dashboard.",
          requestId: "0b7c8f5e-2a4d-4c1e-9f3a-6d5e4c3b2a19",
        },
      },
      { status: 403 },
    ),
  );
  await expect(sdk.key.revokeSelf()).rejects.toMatchObject({
    kind: "authorization",
    code: "key.self_revoke_forbidden",
    status: 403,
  });
});

it("carries the key's limit on sandbox.key_limit_reached", async () => {
  const sdk = client(() =>
    Response.json(
      {
        error: {
          code: "sandbox.key_limit_reached",
          message: "This key's live sandbox limit is reached.",
          requestId: "0b7c8f5e-2a4d-4c1e-9f3a-6d5e4c3b2a19",
          data: { maxLiveSandboxes: 3, liveSandboxes: 3 },
        },
      },
      { status: 409 },
    ),
  );
  await expect(sdk.key.get()).rejects.toMatchObject({
    code: "sandbox.key_limit_reached",
    keyLimit: { maxLiveSandboxes: 3, liveSandboxes: 3 },
  });
});
