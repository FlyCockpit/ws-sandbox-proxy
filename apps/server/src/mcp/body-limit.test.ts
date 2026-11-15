import { Hono } from "hono";
import { expect, it, vi } from "vitest";

vi.mock("../client-ip.js", () => ({ resolveClientIp: () => "192.0.2.1" }));

import { mcpJsonBodyLimit } from "./body-limit";

function app() {
  const value = new Hono();
  value.use("/*", mcpJsonBodyLimit({ maxBytes: 16, deadlineMs: 10 }));
  value.post("/", async (c) => c.text(await c.req.text()));
  return value;
}
it("counts actual bytes even when Content-Length understates them", async () => {
  expect(
    (
      await app().request("/", {
        method: "POST",
        headers: { "content-length": "1" },
        body: "x".repeat(17),
      })
    ).status,
  ).toBe(413);
  expect(
    (await app().request("/", { method: "POST", headers: { "content-length": "1" }, body: "xx" }))
      .status,
  ).toBe(400);
  const response = await app().request("/", { method: "POST", body: "hello" });
  expect(response.status).toBe(200);
  expect(await response.text()).toBe("hello");
});
it("cancels stalled readers at their absolute deadline", async () => {
  const cancel = vi.fn();
  const stream = new ReadableStream({ pull: () => new Promise(() => {}), cancel });
  const request = new Request("http://localhost/", {
    method: "POST",
    body: stream,
    duplex: "half",
  } as RequestInit);
  expect((await app().request(request)).status).toBe(408);
  expect(cancel).toHaveBeenCalledOnce();
});
