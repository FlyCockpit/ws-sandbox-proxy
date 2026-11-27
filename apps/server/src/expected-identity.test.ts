import { Hono } from "hono";
import { beforeEach, expect, it, vi } from "vitest";

const getSession = vi.hoisted(() => vi.fn());
vi.mock("@wssp/auth", () => ({ auth: { api: { getSession } } }));
const { sessionMiddleware } = await import("./session-middleware");
const { expectedIdentity } = await import("./expected-identity");

beforeEach(() => getSession.mockReset().mockResolvedValue({ user: { id: "b" } }));

it.each([false, true])("blocks a changed cookie before writes (resolved %s)", async (resolved) => {
  const write = vi.fn();
  const app = new Hono<{ Variables: { session: unknown } }>();
  if (resolved) app.use("*", sessionMiddleware);
  app.use("*", expectedIdentity);
  app.post("/", (c) => {
    write();
    return c.json({ ok: true });
  });
  const response = await app.request("/", {
    method: "POST",
    headers: { "X-Expected-User": "a", authorization: "Bearer ignored" },
  });
  expect(response.status).toBe(409);
  expect(await response.json()).toEqual({ code: "IDENTITY_CHANGED" });
  expect(write).not.toHaveBeenCalled();
  expect(getSession).toHaveBeenCalledTimes(1);
  expect(getSession.mock.calls[0]?.[0].headers.has("authorization")).toBe(false);
});

it("uses the raw owner if later policy removed the session", async () => {
  const app = new Hono<{ Variables: { session: unknown } }>();
  const write = vi.fn();
  app.use("*", sessionMiddleware);
  app.use("*", async (c, next) => {
    c.set("session", null);
    await next();
  });
  app.use("*", expectedIdentity);
  app.post("/", (c) => {
    write();
    return c.json({ ok: true });
  });
  const response = await app.request("/", { method: "POST", headers: { "X-Expected-User": "a" } });
  expect(response.status).toBe(409);
  expect(write).not.toHaveBeenCalled();
});

it("fails closed on lookup failure before downstream can re-resolve", async () => {
  getSession.mockRejectedValueOnce(new Error("offline"));
  const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  const write = vi.fn();
  const app = new Hono<{ Variables: { session: unknown } }>();
  app.use("*", sessionMiddleware);
  app.use("*", expectedIdentity);
  app.post("/", (c) => {
    write();
    return c.json({ ok: true });
  });
  const response = await app.request("/", { method: "POST", headers: { "X-Expected-User": "a" } });
  expect(response.status).toBe(503);
  expect(await response.json()).toEqual({ code: "SESSION_UNAVAILABLE" });
  expect(write).not.toHaveBeenCalled();
  expect(getSession).toHaveBeenCalledTimes(1);
  warn.mockRestore();
});

it("allows a matching cookie owner through exactly once", async () => {
  const write = vi.fn();
  const app = new Hono<{ Variables: { session: unknown } }>();
  app.use("*", sessionMiddleware);
  app.use("*", expectedIdentity);
  app.post("/", (c) => {
    write();
    return c.json({ ok: true });
  });
  const response = await app.request("/", { method: "POST", headers: { "X-Expected-User": "b" } });
  expect(response.status).toBe(200);
  expect(write).toHaveBeenCalledOnce();
  expect(getSession).toHaveBeenCalledOnce();
});

it("carries an identity marker on the bodyless HEAD response", async () => {
  const app = new Hono();
  const handler = vi.fn();
  app.use("*", expectedIdentity);
  app.get("/capture", (c) => {
    handler();
    return c.text("capture");
  });
  const response = await app.request("/capture", {
    method: "HEAD",
    headers: { "X-Expected-User": "a" },
  });
  expect(response.status).toBe(409);
  expect(await response.text()).toBe("");
  expect(response.headers.get("X-Identity-Changed")).toBe("1");
  expect(handler).not.toHaveBeenCalled();
});
