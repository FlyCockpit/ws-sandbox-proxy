import { createHash } from "node:crypto";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "https://wssp.example",
    BETTER_AUTH_SECRET: "test-secret-with-at-least-thirty-two-bytes",
  },
}));

import { bindMcpGrantServices } from "./mcp-grant";
import { resolveMcpPlugins } from "./mcp-plugins";

const BASE = "https://wssp.example",
  RESOURCE = `${BASE}/mcp`,
  CALLBACK = "https://client.example/callback";
const verifier = "v".repeat(43);
const record = vi.fn(),
  active = vi.fn();
beforeEach(() => {
  vi.clearAllMocks();
  record.mockResolvedValue(undefined);
  active.mockResolvedValue("grant-one");
  bindMcpGrantServices({ record, active, revoked: async () => false });
});
function fixture() {
  const memory: Record<string, Record<string, unknown>[]> = {
    user: [],
    session: [],
    account: [],
    verification: [],
    oauthAccessToken: [],
    oauthRefreshToken: [],
    oauthConsent: [],
    oauthClientAssertion: [],
    jwks: [],
    oauthResource: [
      {
        id: "resource",
        identifier: RESOURCE,
        disabled: false,
        allowedScopes: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ],
    oauthClientResource: [
      { id: "link", clientId: "client", resourceId: RESOURCE, createdAt: new Date() },
    ],
    oauthClient: [
      {
        id: "client-row",
        clientId: "client",
        tokenEndpointAuthMethod: "none",
        redirectUris: [CALLBACK],
        grantTypes: ["authorization_code", "refresh_token"],
        responseTypes: ["code"],
        scopes: ["sandboxes:read", "hosts:execute", "offline_access"],
        skipConsent: false,
        requirePKCE: true,
        disabled: false,
      },
    ],
  };
  const auth = betterAuth({
    baseURL: BASE,
    secret: "test-secret-with-at-least-thirty-two-bytes",
    database: memoryAdapter(memory),
    logger: { disabled: true },
    emailAndPassword: {
      enabled: true,
      password: {
        hash: async (p) => `test:${p}`,
        verify: async ({ hash, password }) => hash === `test:${password}`,
      },
    },
    advanced: { disableOriginCheck: false },
    plugins: [...resolveMcpPlugins({ enabled: true, baseUrl: BASE })],
  });
  const send = (
    path: string,
    body: Record<string, string | boolean | string[]>,
    cookie?: string,
    json = false,
  ) =>
    auth.handler(
      new Request(BASE + path, {
        method: "POST",
        headers: {
          "content-type": json ? "application/json" : "application/x-www-form-urlencoded",
          origin: BASE,
          ...(cookie ? { cookie } : {}),
        },
        body: json ? JSON.stringify(body) : new URLSearchParams(body as Record<string, string>),
      }),
    );
  async function consentQuery() {
    const signup = await auth.api.signUpEmail({
      body: { name: "User", email: "user@example.test", password: "strong-test-password" },
      asResponse: true,
    });
    const cookie = signup.headers
      .getSetCookie()
      .map((value) => value.split(";")[0])
      .join("; ");
    const response = await send(
      "/api/auth/oauth2/authorize",
      {
        response_type: "code",
        client_id: "client",
        redirect_uri: CALLBACK,
        scope: "sandboxes:read hosts:execute offline_access",
        resource: RESOURCE,
        code_challenge_method: "S256",
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      },
      cookie,
    );
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!, BASE);
    expect(location.pathname).toBe("/en-US/mcp-consent");
    return { cookie, oauth_query: location.search.slice(1) };
  }
  return { auth, send, consentQuery, memory };
}
it("keeps the kill switch, token lifetimes, PKCE, registration and service scope policy pinned", () => {
  expect(resolveMcpPlugins({ enabled: false, baseUrl: BASE })).toEqual([]);
  const plugins = resolveMcpPlugins({ enabled: true, baseUrl: BASE });
  const provider = plugins.find((plugin) => plugin.id === "oauth-provider")!;
  expect(provider.options).toMatchObject({
    accessTokenExpiresIn: 600,
    refreshTokenExpiresIn: 259200,
    refreshTokenReuseInterval: 30,
    clientRegistrationRequirePKCE: true,
    allowDynamicClientRegistration: true,
    allowUnauthenticatedClientRegistration: true,
    grantTypes: ["authorization_code", "refresh_token"],
    clientRegistrationDefaultScopes: ["sandboxes:read", "hosts:read", "offline_access"],
  });
});
it("records the chosen scopes/resources before returning the code, then stamps wssp_grant_id at exchange", async () => {
  const f = fixture(),
    { cookie, oauth_query } = await f.consentQuery();
  const response = await f.send(
    "/api/auth/oauth2/consent",
    {
      accept: true,
      scope: "sandboxes:read offline_access",
      resourceMode: "ALL_OWNED",
      ownSandboxesOnly: true,
      oauth_query,
    },
    cookie,
    true,
  );
  expect(response.status).toBe(200);
  expect(record).toHaveBeenCalledWith(
    expect.objectContaining({
      clientId: "client",
      sessionId: expect.any(String),
      referenceId: expect.stringMatching(/^[a-f0-9]{64}$/),
      choices: expect.objectContaining({
        scopes: ["sandboxes:read"],
        resourceMode: "ALL_OWNED",
        ownSandboxesOnly: true,
      }),
    }),
  );
  const { url } = await response.json();
  const code = new URL(url).searchParams.get("code")!;
  const token = await f.send("/api/auth/oauth2/token", {
    grant_type: "authorization_code",
    client_id: "client",
    code,
    code_verifier: verifier,
    redirect_uri: CALLBACK,
  });
  expect(token.status).toBe(200);
  const result = await token.json();
  const claims = JSON.parse(
    Buffer.from(result.access_token.split(".")[1], "base64url").toString("utf8"),
  );
  expect(claims.wssp_grant_id).toBe("grant-one");
  expect(claims.exp - claims.iat).toBe(600);
  expect(claims.scope).toBe("sandboxes:read offline_access");
  expect(result.refresh_token).toBeTruthy();
  active.mockResolvedValue(null);
  const refresh = await f.send("/api/auth/oauth2/token", {
    grant_type: "refresh_token",
    client_id: "client",
    refresh_token: result.refresh_token,
  });
  expect(refresh.status).toBeGreaterThanOrEqual(400);
});
it("rejects scope widening and withholds codes if persisting consent fails", async () => {
  const f = fixture(),
    { cookie, oauth_query } = await f.consentQuery();
  const widened = await f.send(
    "/api/auth/oauth2/consent",
    { accept: true, scope: "files:write", resourceMode: "ALL_OWNED", oauth_query },
    cookie,
    true,
  );
  expect(widened.status).toBe(400);
  expect(record).not.toHaveBeenCalled();
  record.mockRejectedValue(new Error("storage unavailable"));
  const failed = await f.send(
    "/api/auth/oauth2/consent",
    { accept: true, scope: "sandboxes:read", resourceMode: "ALL_OWNED", oauth_query },
    cookie,
    true,
  );
  expect(failed.status).toBe(500);
  expect(f.memory.oauthConsent).toEqual([]);
});

it("refuses a stale/revoked session before the provider changes remembered approval", async () => {
  const f = fixture(),
    { cookie, oauth_query } = await f.consentQuery();
  const approved = await f.send(
    "/api/auth/oauth2/consent",
    {
      accept: true,
      scope: "sandboxes:read",
      resourceMode: "ALL_OWNED",
      oauth_query,
    },
    cookie,
    true,
  );
  expect(approved.status).toBe(200);
  const remembered = structuredClone(f.memory.oauthConsent);
  record.mockRejectedValue(new Error("durable session revoked"));
  const response = await f.send(
    "/api/auth/oauth2/consent",
    {
      accept: true,
      scope: "sandboxes:read hosts:execute",
      resourceMode: "ALL_OWNED",
      oauth_query,
    },
    cookie,
    true,
  );
  expect(response.status).toBe(500);
  expect(f.memory.oauthConsent).toEqual(remembered);
  expect(record).toHaveBeenCalledWith(expect.objectContaining({ sessionId: expect.any(String) }));
  expect(JSON.stringify(await response.json())).not.toContain("durable session");
});
