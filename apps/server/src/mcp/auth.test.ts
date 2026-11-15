import { ORPCError } from "@orpc/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { beforeEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  claims: {} as Record<string, unknown>,
  options: {} as Record<string, unknown>,
  verified: 0,
}));
vi.mock("@better-auth/mcp", () => ({
  requireMcpAuth: (
    _auth: unknown,
    handler: (request: Request, claims: Record<string, unknown>) => Promise<Response>,
    options: Record<string, unknown>,
  ) => {
    state.options = options;
    return (request: Request) => {
      state.verified++;
      expect(request.headers.get("cookie")).toBeNull();
      expect(request.url).toBe("https://public.example/mcp");
      if (
        request.headers.get("authorization")?.startsWith("DPoP") &&
        request.headers.get("dpop") !== "verified-proof"
      )
        return new Response(null, { status: 401 });
      return handler(request, state.claims);
    };
  },
}));
vi.mock("@wssp/api/lib/sdk-key-access", () => ({
  AgentTokenPolicyBlockedError: class AgentTokenPolicyBlockedError extends Error {
    readonly code = "agent_token.no_expiry_blocked";
  },
  authenticateAgentTokenSecret: vi.fn(),
  principalForMcpGrant: vi.fn(),
}));
vi.mock("../mcp-rate-limit.js", () => ({ consumeMcpCredentialQuota: vi.fn() }));
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_URL: "https://public.example", CAPACITY_RETRY_AFTER_SECONDS: 5 },
}));

import { AgentTokenPolicyBlockedError } from "@wssp/api/lib/sdk-key-access";
import { createMcpAuthenticator } from "./auth";

const p: ServicePrincipal = {
  kind: "sdkKey",
  credentialKind: "AGENT_TOKEN",
  keyId: "key",
  ownerId: "owner",
  expiresAt: null,
  resourceMode: "ALL_OWNED",
  ownSandboxesOnly: true,
  scopes: new Set(["sandboxes:read", "hosts:execute"]),
  allowedHostIds: "allOwned",
  allowedRevisionIds: "allOwned",
  allowedPoolIds: "allUsable",
};
const agent = vi.fn(),
  grant = vi.fn(),
  fetch = vi.fn(),
  quota = vi.fn();
const authenticate = createMcpAuthenticator({
  authInstance: {} as Parameters<typeof createMcpAuthenticator>[0]["authInstance"],
  transport: { fetch },
  authenticateAgent: agent,
  grantPrincipal: grant,
  quota,
});
function request(authorization?: string, extra: Record<string, string> = {}) {
  return new Request("http://public.example/mcp", {
    method: "POST",
    headers: {
      host: "public.example",
      cookie: "never-read",
      ...(authorization ? { authorization } : {}),
      ...extra,
    },
    body: "{}",
  });
}
beforeEach(() => {
  vi.clearAllMocks();
  state.verified = 0;
  state.claims = {
    sub: "owner",
    client_id: "client",
    wssp_grant_id: "grant",
    scope: "sandboxes:read files:write",
  };
  agent.mockResolvedValue(p);
  grant.mockResolvedValue({ ...p, credentialKind: "OAUTH_GRANT" });
  fetch.mockResolvedValue(new Response("{}"));
  quota.mockResolvedValue(undefined);
});
it("rejects cookie-only requests and every other product credential plane before JWT verification", async () => {
  for (const auth of [
    undefined,
    "Bearer wssp_sdk_other",
    "Bearer wssp_host_other",
    "Bearer wssp_device_other",
  ]) {
    const response = await authenticate(request(auth));
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain("oauth-protected-resource/mcp");
  }
  expect(state.verified).toBe(0);
  expect(fetch).not.toHaveBeenCalled();
});
it("authenticates agent tokens, strips cookies, and preserves the stored credential authority", async () => {
  expect((await authenticate(request("Bearer wssp_agent_token"))).status).toBe(200);
  expect(agent).toHaveBeenCalledWith("wssp_agent_token");
  const sent = fetch.mock.calls[0]!;
  expect(sent[0].url).toBe("https://public.example/mcp");
  expect(sent[0].headers.get("cookie")).toBeNull();
  expect(sent[1].authInfo.extra.principal).toBe(p);
  expect(quota).toHaveBeenCalledWith("key");
});
it("audience-binds OAuth verification and intersects token scopes with the live stored grant", async () => {
  await authenticate(request("Bearer jwt"));
  expect(state.options).toMatchObject({
    resource: "https://public.example/mcp",
    issuer: "https://public.example/api/auth",
  });
  expect(grant).toHaveBeenCalledWith("grant", "owner", "client");
  expect([...fetch.mock.calls[0]![1].authInfo.extra.principal.scopes]).toEqual(["sandboxes:read"]);
  grant.mockResolvedValue(null);
  expect((await authenticate(request("Bearer jwt"))).status).toBe(401);
});
it("forwards DPoP proofs with canonical htu and refuses missing proofs", async () => {
  expect((await authenticate(request("DPoP jwt"))).status).toBe(401);
  expect(
    (
      await authenticate(
        request("DPoP jwt", { dpop: "verified-proof", "x-forwarded-host": "attacker.example" }),
      )
    ).status,
  ).toBe(200);
});
it("fails closed for missing grant binding and returns Retry-After on per-credential budget refusal", async () => {
  state.claims = { sub: "owner", client_id: "client" };
  expect((await authenticate(request("Bearer jwt"))).status).toBe(401);
  quota.mockRejectedValue(new ORPCError("TOO_MANY_REQUESTS", { data: { retryAfterSeconds: 11 } }));
  const response = await authenticate(request("Bearer wssp_agent_token"));
  expect(response.status).toBe(429);
  expect(response.headers.get("retry-after")).toBe("11");
  expect(await response.json()).toMatchObject({
    error: { data: { retryable: true, retryAfterSeconds: 11 } },
  });
});

it("refuses a policy-blocked no-expiry agent token with a typed 401, never reaching the transport", async () => {
  agent.mockRejectedValue(new AgentTokenPolicyBlockedError());
  const response = await authenticate(request("Bearer wssp_agent_token"));
  expect(response.status).toBe(401);
  expect(response.headers.get("www-authenticate")).toContain(
    'error_description="agent_token.no_expiry_blocked"',
  );
  const body = (await response.json()) as { error: { data: { code: string; retryable: boolean } } };
  expect(body.error.data).toMatchObject({
    code: "agent_token.no_expiry_blocked",
    retryable: false,
  });
  expect(fetch).not.toHaveBeenCalled();
  expect(quota).not.toHaveBeenCalled();
  // Switch back on: the same token is admitted again.
  agent.mockResolvedValue(p);
  expect((await authenticate(request("Bearer wssp_agent_token"))).status).toBe(200);
});
