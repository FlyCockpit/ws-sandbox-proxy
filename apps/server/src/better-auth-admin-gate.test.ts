import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import { betterAuthAdminGate } from "./better-auth-admin-gate";

describe("betterAuthAdminGate", () => {
  it("hides every plugin action for anonymous, bearer and cookie callers", async () => {
    const downstream = vi.fn();
    const app = new Hono();
    app.use("/api/auth/admin/*", betterAuthAdminGate);
    app.all("/api/auth/admin/*", (c) => {
      downstream();
      return c.json({ ok: true });
    });
    for (const headers of [
      {},
      { authorization: "Bearer wssp_sdk_fake" },
      { cookie: "better-auth.session_token=fake" },
    ]) {
      for (const path of [
        "set-role",
        "ban-user",
        "remove-user",
        "impersonate-user",
        "set-user-password",
        "list-user-sessions",
        "future-endpoint",
      ]) {
        const response = await app.request(`/api/auth/admin/${path}`, { method: "POST", headers });
        expect(response.status).toBe(404);
        expect(await response.json()).toEqual({
          error: "not_found",
          error_description: "Not found",
        });
      }
    }
    expect(downstream).not.toHaveBeenCalled();
  });
});
