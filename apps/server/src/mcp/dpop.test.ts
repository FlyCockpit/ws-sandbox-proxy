import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { afterAll, expect, it, vi } from "vitest";

vi.mock("@wssp/api/lib/sdk-key-access", () => ({
  authenticateAgentTokenSecret: vi.fn(),
  principalForMcpGrant: vi.fn(),
}));
vi.mock("../mcp-rate-limit.js", () => ({ consumeMcpCredentialQuota: vi.fn() }));
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_URL: "https://dpop.example", CAPACITY_RETRY_AFTER_SECONDS: 5 },
}));

import { createMcpAuthenticator } from "./auth";

const resource = "https://dpop.example/mcp",
  issuer = "https://dpop.example/api/auth";
const accessKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const proofKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const accessJwk = {
  ...accessKeys.publicKey.export({ format: "jwk" }),
  kid: "mcp-dpop-test",
  alg: "ES256",
  use: "sig",
};
const proofJwk = proofKeys.publicKey.export({ format: "jwk" });
const thumbprint = createHash("sha256")
  .update(JSON.stringify({ crv: proofJwk.crv, kty: proofJwk.kty, x: proofJwk.x, y: proofJwk.y }))
  .digest("base64url");
function jwt(header: object, claims: object, key: typeof accessKeys.privateKey) {
  const input = [header, claims]
    .map((value) => Buffer.from(JSON.stringify(value)).toString("base64url"))
    .join(".");
  return `${input}.${sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}
const now = Math.floor(Date.now() / 1000);
const token = jwt(
  { typ: "at+jwt", alg: "ES256", kid: accessJwk.kid },
  {
    iss: issuer,
    aud: resource,
    sub: "owner",
    azp: "client",
    client_id: "client",
    scope: "hosts:read",
    wssp_grant_id: "grant",
    iat: now,
    exp: now + 600,
    cnf: { jkt: thumbprint },
  },
  accessKeys.privateKey,
);
function proof(htu = resource) {
  return jwt(
    { typ: "dpop+jwt", alg: "ES256", jwk: proofJwk },
    {
      jti: randomUUID(),
      htm: "POST",
      htu,
      iat: Math.floor(Date.now() / 1000),
      ath: createHash("sha256").update(token).digest("base64url"),
    },
    proofKeys.privateKey,
  );
}
const auth = betterAuth({
  baseURL: "https://dpop.example",
  secret: "dpop-test-secret-with-at-least-thirty-two-bytes",
  database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
  logger: { disabled: true },
});
const p: ServicePrincipal = {
  kind: "sdkKey",
  credentialKind: "OAUTH_GRANT",
  keyId: "key",
  ownerId: "owner",
  expiresAt: null,
  resourceMode: "ALL_OWNED",
  ownSandboxesOnly: true,
  scopes: new Set(["hosts:read"]),
  allowedHostIds: "allOwned",
  allowedRevisionIds: "allOwned",
  allowedPoolIds: "allUsable",
};
const transport = { fetch: vi.fn(async () => new Response("{}")) };
const authenticate = createMcpAuthenticator({
  authInstance: auth,
  transport,
  grantPrincipal: async () => p,
  quota: async () => {},
});
vi.stubGlobal(
  "fetch",
  vi.fn(async (url: string | URL | Request) => {
    expect(String(url)).toBe(`${issuer}/jwks`);
    return Response.json({ keys: [accessJwk] });
  }),
);
afterAll(() => vi.unstubAllGlobals());
function request(authorization: string, dpop?: string) {
  return new Request("http://dpop.example/mcp", {
    method: "POST",
    headers: { host: "dpop.example", authorization, ...(dpop ? { dpop } : {}) },
    body: "{}",
  });
}
// The memory adapter does not enforce SQL primary-key uniqueness. Model that
// one reservation primitive here; signatures, thumbprints, htu, ath and proof
// verification still run through the real installed verifier.
const context = await auth.$context;
const reservations = new Set<string>();
vi.spyOn(context.internalAdapter, "reserveVerificationValue").mockImplementation(
  async ({ identifier }) => {
    if (reservations.has(identifier)) return false;
    reservations.add(identifier);
    return true;
  },
);
it("verifies a real DPoP signature against canonical public htu and rejects missing, mismatched and replayed proofs", async () => {
  expect((await authenticate(request(`Bearer ${token}`))).status).toBe(401);
  expect((await authenticate(request(`DPoP ${token}`))).status).toBe(401);
  expect(
    (await authenticate(request(`DPoP ${token}`, proof("http://dpop.example/mcp")))).status,
  ).toBe(401);
  const validProof = proof();
  const valid = await authenticate(request(`DPoP ${token}`, validProof));
  expect(valid.status).toBe(200);
  expect(transport.fetch).toHaveBeenCalledOnce();
  expect((await authenticate(request(`DPoP ${token}`, validProof))).status).toBe(401);
  expect(transport.fetch).toHaveBeenCalledOnce();
});
