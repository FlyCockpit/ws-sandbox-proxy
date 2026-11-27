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
const dispatchMock = vi.hoisted(() =>
  vi.fn<
    (_principal: unknown, _name: unknown, _input: unknown, signal?: AbortSignal) => Promise<unknown>
  >(async () => ({ items: [] })),
);
vi.mock("./tool-dispatch.js", () => ({ dispatchMcpTool: dispatchMock }));
vi.mock("../mcp-rate-limit.js", () => ({
  consumeMcpCredentialQuota: vi.fn(),
  consumeMcpCreateQuota: vi.fn(),
  consumeMcpHostCommandQuota: vi.fn(),
}));
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_URL: "https://public.example", CAPACITY_RETRY_AFTER_SECONDS: 5 },
}));

import { AgentTokenPolicyBlockedError } from "@wssp/api/lib/sdk-key-access";
import { withAuthorityChange, withGlobalAuthorityChange } from "@wssp/db/authority";
import { createMcpAuthenticator, releaseWhenBodyEnds } from "./auth";
import { createMcpTransport } from "./handler";

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

it("enforces stateless response headers and strips set-cookie and mcp-session-id", async () => {
  fetch.mockResolvedValueOnce(
    new Response("{}", {
      status: 200,
      headers: {
        "content-type": "application/json",
        "set-cookie": "session=leaked",
        "mcp-session-id": "session-123",
      },
    }),
  );
  const response = await authenticate(request("Bearer wssp_agent_token"));
  expect(response.headers.get("set-cookie")).toBeNull();
  expect(response.headers.get("mcp-session-id")).toBeNull();
  expect(response.headers.get("cache-control")).toBe("private, no-store");
  await response.text();
});

it("enforces legacy 2025-06-18 auth, grant scopes, revocation, batch rejection, and quota parity on the real transport", async () => {
  const realTransport = createMcpTransport();
  const realAuth = createMcpAuthenticator({
    authInstance: {} as Parameters<typeof createMcpAuthenticator>[0]["authInstance"],
    transport: realTransport,
    authenticateAgent: agent,
    grantPrincipal: grant,
    quota,
  });
  const legacyReq = (
    body: unknown,
    authorization?: string,
    extra: Record<string, string> = { "mcp-protocol-version": "2025-06-18" },
  ) =>
    new Request("http://public.example/mcp", {
      method: "POST",
      headers: {
        host: "public.example",
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        ...(authorization ? { authorization } : {}),
        ...extra,
      },
      body: JSON.stringify(body),
    });

  try {
    // No token -> 401 before batch parsing.
    const unauthBatch = await realAuth(
      legacyReq([{ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }]),
    );
    expect(unauthBatch.status).toBe(401);
    expect(unauthBatch.headers.get("www-authenticate")).toContain("oauth-protected-resource/mcp");

    // Authenticated JSON-RPC batch -> 400 -32600.
    const authBatch = await realAuth(
      legacyReq(
        [{ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }],
        "Bearer wssp_agent_token",
      ),
    );
    expect(authBatch.status).toBe(400);
    expect(await authBatch.json()).toMatchObject({ error: { code: -32600 } });

    // Valid agent token: initialize -> initialized -> tools/list -> tools/call.
    const init = await realAuth(
      legacyReq(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "codex-mcp-client", version: "0.172.0" },
          },
        },
        "Bearer wssp_agent_token",
        {},
      ),
    );
    expect(init.status).toBe(200);
    expect(init.headers.get("cache-control")).toBe("private, no-store, no-cache, no-transform");
    expect(init.headers.get("mcp-session-id")).toBeNull();
    expect(await init.text()).toContain('"protocolVersion":"2025-06-18"');

    const notif = await realAuth(
      legacyReq({ jsonrpc: "2.0", method: "notifications/initialized" }, "Bearer wssp_agent_token"),
    );
    expect(notif.status).toBe(202);
    expect(notif.headers.get("cache-control")).toBe("private, no-store");

    // Valid OAuth grant intersects token scopes with stored grant scopes on legacy tools/list & tools/call.
    state.claims = {
      sub: "owner",
      client_id: "client",
      wssp_grant_id: "grant",
      scope: "sandboxes:read",
    };
    const oauthList = await realAuth(
      legacyReq({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, "Bearer jwt"),
    );
    expect(oauthList.status).toBe(200);
    const listText = await oauthList.text();
    expect(listText).toContain('"sandbox_list"');
    expect(listText).not.toContain('"host_command_run"');

    // Calling a tool outside the OAuth grant's intersected scopes is refused identically to unknown.
    dispatchMock.mockClear();
    const deniedTool = await realAuth(
      legacyReq(
        {
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: { name: "host_command_run", arguments: { hostId: "h", script: "true" } },
        },
        "Bearer jwt",
      ),
    );
    expect(await deniedTool.text()).toContain("Tool host_command_run not found");
    expect(dispatchMock).not.toHaveBeenCalled();

    // Revoked agent token & revoked OAuth grant -> 401.
    agent.mockResolvedValueOnce(null);
    expect(
      (
        await realAuth(
          legacyReq(
            { jsonrpc: "2.0", id: 4, method: "tools/list", params: {} },
            "Bearer wssp_agent_token",
          ),
        )
      ).status,
    ).toBe(401);
    grant.mockResolvedValueOnce(null);
    expect(
      (
        await realAuth(
          legacyReq({ jsonrpc: "2.0", id: 5, method: "tools/list", params: {} }, "Bearer jwt"),
        )
      ).status,
    ).toBe(401);

    // Credential rate limit applies identically to legacy requests.
    quota.mockRejectedValueOnce(
      new ORPCError("TOO_MANY_REQUESTS", { data: { retryAfterSeconds: 9 } }),
    );
    const limited = await realAuth(
      legacyReq(
        { jsonrpc: "2.0", id: 6, method: "tools/list", params: {} },
        "Bearer wssp_agent_token",
      ),
    );
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("9");
  } finally {
    await realTransport.close();
  }
});

it("keeps authority-commit cancellation active for the full legacy SSE stream and cleans up on abort and completion", async () => {
  const realTransport = createMcpTransport({ keepAliveMs: 0 });
  const realAuth = createMcpAuthenticator({
    authInstance: {} as Parameters<typeof createMcpAuthenticator>[0]["authInstance"],
    transport: realTransport,
    authenticateAgent: agent,
    grantPrincipal: grant,
    quota,
  });

  const startPendingLegacyCall = () => {
    let toolStarted!: (signal: AbortSignal | undefined) => void;
    const started = new Promise<AbortSignal | undefined>((resolve) => {
      toolStarted = resolve;
    });
    let finishTool!: (value: unknown) => void;
    dispatchMock.mockImplementationOnce(
      (_principal: unknown, _name: unknown, _input: unknown, signal?: AbortSignal) => {
        toolStarted(signal);
        return new Promise((resolve) => {
          finishTool = resolve;
        });
      },
    );
    const req = new Request("http://public.example/mcp", {
      method: "POST",
      headers: {
        host: "public.example",
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: "Bearer wssp_agent_token",
        "mcp-protocol-version": "2025-06-18",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 77,
        method: "tools/call",
        params: { name: "host_command_run", arguments: { hostId: "h1", script: "sleep 60" } },
      }),
    });
    return { req, started, finishTool: (v: unknown) => finishTool(v) };
  };

  try {
    // 1. Credential revocation, owner-wide commit, and global commit each abort an in-flight legacy SSE tool call.
    for (const commit of [
      () => withAuthorityChange({ credentialId: p.keyId, ownerId: p.ownerId }, async () => {}),
      () => withAuthorityChange({ ownerId: p.ownerId }, async () => {}),
      () => withGlobalAuthorityChange(async () => {}),
    ]) {
      const pending = startPendingLegacyCall();
      const response = await realAuth(pending.req);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain("text/event-stream");
      const signal = await pending.started;
      expect(signal).toBeDefined();
      expect(signal?.aborted).toBe(false);

      await commit();
      await Promise.resolve();
      expect(signal?.aborted).toBe(true);
      await expect(response.text()).rejects.toThrow();
      pending.finishTool({ state: "cancelled" });
    }

    // 2. Cancelling the legacy SSE response body aborts the in-flight tool's signal immediately.
    const cancelled = startPendingLegacyCall();
    const cancelledResponse = await realAuth(cancelled.req);
    const cancelledSignal = await cancelled.started;
    expect(cancelledSignal?.aborted).toBe(false);
    await cancelledResponse.body?.cancel("client-closed");
    expect(cancelledSignal?.aborted).toBe(true);
    cancelled.finishTool({ state: "cancelled" });

    // 3. Normal completion delivers the SSE payload cleanly and detaches the authority listener.
    const normal = startPendingLegacyCall();
    const normalResponse = await realAuth(normal.req);
    const normalSignal = await normal.started;
    expect(normalSignal?.aborted).toBe(false);
    normal.finishTool({ state: "ok" });
    expect(await normalResponse.text()).toContain('"state":"ok"');
    await withAuthorityChange({ credentialId: p.keyId, ownerId: p.ownerId }, async () => {});
    await Promise.resolve();
    expect(normalSignal?.aborted).toBe(false);

    // 4. Authority commit during credential lookup denies the request before touching transport.
    agent.mockImplementationOnce(async () => {
      await withAuthorityChange({ credentialId: p.keyId, ownerId: p.ownerId }, async () => {});
      await Promise.resolve();
      return p;
    });
    dispatchMock.mockClear();
    const raced = await realAuth(
      new Request("http://public.example/mcp", {
        method: "POST",
        headers: {
          host: "public.example",
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: "Bearer wssp_agent_token",
          "mcp-protocol-version": "2025-06-18",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 78, method: "tools/list", params: {} }),
      }),
    );
    expect(raced.status).toBe(401);
    expect(dispatchMock).not.toHaveBeenCalled();
  } finally {
    await realTransport.close();
  }
});

it("releaseWhenBodyEnds invokes onDone immediately for null bodies and runs cancel/error hooks once", async () => {
  const doneNull = vi.fn();
  releaseWhenBodyEnds(new Response(null, { status: 202 }), doneNull);
  expect(doneNull).toHaveBeenCalledOnce();

  const doneCancel = vi.fn();
  const abortCancel = vi.fn();
  const stream = new ReadableStream<Uint8Array>({ start() {} });
  const wrapped = releaseWhenBodyEnds(new Response(stream), doneCancel, undefined, abortCancel);
  expect(doneCancel).not.toHaveBeenCalled();
  expect(abortCancel).not.toHaveBeenCalled();
  await wrapped.body?.cancel("client-closed");
  expect(abortCancel).toHaveBeenCalledOnce();
  expect(doneCancel).toHaveBeenCalledOnce();

  const doneErr = vi.fn();
  const abortErr = vi.fn();
  const failing = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.error(new Error("upstream-failed"));
    },
  });
  const wrappedErr = releaseWhenBodyEnds(new Response(failing), doneErr, undefined, abortErr);
  await expect(wrappedErr.text()).rejects.toThrow("upstream-failed");
  expect(abortErr).toHaveBeenCalledOnce();
  expect(doneErr).toHaveBeenCalledOnce();
});
