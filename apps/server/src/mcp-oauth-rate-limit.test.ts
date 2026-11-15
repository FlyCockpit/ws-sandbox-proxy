import { ORPCError } from "@orpc/server";
import { Hono } from "hono";
import { beforeEach, expect, it, vi } from "vitest";

const consume = vi.hoisted(() => vi.fn());
vi.mock("@wssp/env/server", () => ({ env: { MCP_ENABLED: true } }));
vi.mock("./client-ip.js", () => ({ resolveClientIp: () => "192.0.2.2" }));
vi.mock("./mcp-rate-limit.js", () => ({
  mcpBudget: (name: string, points: number) => (key: string) => consume(name, points, key),
}));

import { mcpOauthRateLimits } from "./mcp-oauth-rate-limit";

const app = new Hono();
app.onError(() => new Response(null, { status: 500 }));
app.use("/*", mcpOauthRateLimits);
app.all("/*", (c) => c.text("ok"));
beforeEach(() => {
  consume.mockReset().mockResolvedValue(undefined);
});
it("separates registration, consent and OAuth IP budgets and ignores encoded non-routes", async () => {
  for (const [path, name, points] of [
    ["register", "register", 5],
    ["consent", "consent", 30],
    ["token", "oauth", 120],
  ] as const) {
    expect((await app.request(`/api/auth/oauth2/${path}`, { method: "POST" })).status).toBe(200);
    expect(consume).toHaveBeenLastCalledWith(name, points, "192.0.2.2");
  }
  consume.mockClear();
  await app.request("/api/%61uth/oauth2/token", { method: "POST" });
  expect(consume).not.toHaveBeenCalled();
});
it("returns the actual retry delay and fails infrastructure errors closed", async () => {
  consume.mockRejectedValue(
    new ORPCError("TOO_MANY_REQUESTS", { data: { retryAfterSeconds: 12 } }),
  );
  const limited = await app.request("/api/auth/oauth2/token", { method: "POST" });
  expect(limited.status).toBe(429);
  expect(limited.headers.get("retry-after")).toBe("12");
  consume.mockRejectedValue(new Error("private"));
  expect((await app.request("/api/auth/oauth2/token", { method: "POST" })).status).toBe(503);
});
it("caps OAuth forms and consent bodies before provider parsing", async () => {
  expect(
    (
      await app.request("/api/auth/oauth2/token", {
        method: "POST",
        body: "x".repeat(16 * 1024 + 1),
      })
    ).status,
  ).toBe(413);
  expect(
    (
      await app.request("/api/auth/oauth2/consent", {
        method: "POST",
        body: "x".repeat(64 * 1024 + 1),
      })
    ).status,
  ).toBe(413);
});
