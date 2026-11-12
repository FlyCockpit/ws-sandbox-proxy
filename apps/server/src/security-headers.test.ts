import { Hono } from "hono";
import { describe, expect, it } from "vitest";

import { mountSecurityHeaders } from "./security-headers";

function buildApp(cspConnectSrc: string[] = ["'self'"]) {
  const app = new Hono();
  mountSecurityHeaders(app, {
    cspConnectSrc,
    themeInitCspHash: "'sha256-test'",
  });
  app.get("/some-page", (c) => c.text("page"));
  return app;
}

describe("mountSecurityHeaders", () => {
  it("serves routes with the app CSP", async () => {
    const res = await buildApp().request("/some-page");
    const csp = res.headers.get("content-security-policy");
    expect(csp).toContain("default-src 'self'");
  });

  it("never allows 'unsafe-eval'", async () => {
    const res = await buildApp().request("/some-page");
    const csp = res.headers.get("content-security-policy") ?? "";
    const tokens = csp.split(/\s+/).map((t) => t.replace(/;$/, ""));
    expect(tokens).not.toContain("'unsafe-eval'");
  });

  it("allows neither blob: sources nor 'wasm-unsafe-eval' in any directive", async () => {
    const res = await buildApp().request("/some-page");
    const csp = res.headers.get("content-security-policy") ?? "";
    const tokens = csp.split(/\s+/).map((t) => t.replace(/;$/, ""));
    expect(tokens).not.toContain("blob:");
    expect(tokens).not.toContain("'wasm-unsafe-eval'");
  });

  it("keeps script-src to self, the per-request nonce and the theme-init hash only", async () => {
    const res = await buildApp().request("/some-page");
    const csp = res.headers.get("content-security-policy") ?? "";
    const scriptSrc = csp
      .split(";")
      .map((d) => d.trim())
      .find((d) => d.startsWith("script-src "));
    const tokens = scriptSrc?.split(/\s+/).slice(1) ?? [];
    expect(tokens).toHaveLength(3);
    expect(tokens).toContain("'self'");
    expect(tokens).toContain("'sha256-test'");
    expect(tokens.filter((t) => /^'nonce-[A-Za-z0-9+/=_-]+'$/.test(t))).toHaveLength(1);
    expect(tokens).not.toContain("'unsafe-inline'");
    expect(csp).not.toMatch(/script-src-elem|script-src-attr/);
  });

  it("emits the supplied connect-src origins", async () => {
    const res = await buildApp(["'self'", "https://api.example.com"]).request("/some-page");
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("connect-src 'self' https://api.example.com");
  });
});
