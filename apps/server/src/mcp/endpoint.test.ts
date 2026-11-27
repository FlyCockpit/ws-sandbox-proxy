import { ORPCError } from "@orpc/server";
import { beforeEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ authenticate: vi.fn(), quota: vi.fn(), enabled: true }));
vi.mock("./auth.js", () => ({ createMcpAuthenticator: () => mocks.authenticate }));
vi.mock("./handler.js", () => ({ createMcpTransport: () => ({}) }));
vi.mock("../mcp-rate-limit.js", () => ({ consumeMcpIpQuota: mocks.quota }));
vi.mock("../client-ip.js", () => ({ resolveClientIp: () => "192.0.2.1" }));
vi.mock("@wssp/env/server", () => ({
  env: {
    get MCP_ENABLED() {
      return mocks.enabled;
    },
    BETTER_AUTH_URL: "https://public.example",
  },
}));

import { createMcpApi } from "./endpoint";

const app = createMcpApi({} as Parameters<typeof createMcpApi>[0]);
beforeEach(() => {
  vi.clearAllMocks();
  mocks.enabled = true;
  mocks.quota.mockResolvedValue(undefined);
  mocks.authenticate.mockResolvedValue(new Response("{}"));
});
it("gates methods and pre-auth IP quota before authentication", async () => {
  for (const method of ["GET", "DELETE", "OPTIONS"])
    expect((await app.request("/mcp", { method })).status).toBe(405);
  expect(mocks.quota).not.toHaveBeenCalled();
  expect(
    (await app.request("/mcp", { method: "POST", headers: { cookie: "only-cookie" } })).status,
  ).toBe(401);
  expect(mocks.quota).toHaveBeenCalledOnce();
  expect(mocks.authenticate).not.toHaveBeenCalled();
});
it("enforces the 1 MiB JSON cap before the verifier and excludes lookalike media types", async () => {
  const headers = { authorization: "Bearer wssp_agent_token", "content-type": "application/json" };
  expect(
    (await app.request("/mcp", { method: "POST", headers, body: "x".repeat(1_048_577) })).status,
  ).toBe(413);
  expect(
    (
      await app.request("/mcp", {
        method: "POST",
        headers: { ...headers, "content-type": "application/json+evil" },
        body: "{}",
      })
    ).status,
  ).toBe(415);
  expect(mocks.authenticate).not.toHaveBeenCalled();
});
it("reserves every method while disabled and returns an IP Retry-After", async () => {
  mocks.enabled = false;
  expect((await app.request("/mcp", { method: "OPTIONS" })).status).toBe(404);
  mocks.enabled = true;
  mocks.quota.mockRejectedValue(
    new ORPCError("TOO_MANY_REQUESTS", { data: { retryAfterSeconds: 60 } }),
  );
  const response = await app.request("/mcp", { method: "POST" });
  expect(response.status).toBe(429);
  expect(response.headers.get("retry-after")).toBe("60");
  expect(response.headers.get("cache-control")).toBe("private, no-store");
});

it("sets Allow: POST on 405, rejects query strings, and enforces stateless cache/cookie hygiene", async () => {
  for (const method of ["GET", "DELETE"]) {
    const res = await app.request("/mcp", { method });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST");
    expect(res.headers.get("cache-control")).toBe("private, no-store");
  }
  const withQuery = await app.request("/mcp?session=1", {
    method: "POST",
    headers: { authorization: "Bearer wssp_agent_token", "content-type": "application/json" },
    body: "{}",
  });
  expect(withQuery.status).toBe(400);
  expect(withQuery.headers.get("cache-control")).toBe("private, no-store");

  mocks.authenticate.mockResolvedValueOnce(
    new Response("{}", {
      status: 200,
      headers: {
        "content-type": "application/json",
        "set-cookie": "x=1",
        "mcp-session-id": "s1",
      },
    }),
  );
  const ok = await app.request("/mcp", {
    method: "POST",
    headers: { authorization: "Bearer wssp_agent_token", "content-type": "application/json" },
    body: "{}",
  });
  expect(ok.status).toBe(200);
  expect(ok.headers.get("set-cookie")).toBeNull();
  expect(ok.headers.get("mcp-session-id")).toBeNull();
  expect(ok.headers.get("cache-control")).toBe("private, no-store");
});
