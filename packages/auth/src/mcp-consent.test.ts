import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "https://wssp.example",
    BETTER_AUTH_SECRET: "test-secret-with-at-least-thirty-two-bytes",
  },
}));

import { consentIssuedCode, validateConsentScopes } from "./mcp-consent";
import {
  bindMcpGrantServices,
  deriveMcpConsentReferenceId,
  issueMcpGrantClaims,
} from "./mcp-grant";

const active = vi.fn();
beforeEach(() => {
  active.mockReset();
  bindMcpGrantServices({ active, record: vi.fn(), revoked: async () => false });
});
describe("MCP consent", () => {
  it("only accepts an explicit subset of the signed request", () => {
    expect(
      validateConsentScopes(
        { scope: "sandboxes:read offline_access" },
        "scope=sandboxes:read+hosts:execute+offline_access",
      ),
    ).toEqual(["sandboxes:read", "offline_access"]);
    for (const body of [{ scope: "hosts:execute" }, {}, { scope: "" }, { scope: "mcp:write" }])
      expect(() => validateConsentScopes(body, "scope=sandboxes:read")).toThrow();
  });
  it("recognizes successful code issuance, not error redirects", () => {
    expect(consentIssuedCode({ redirect: true, url: "https://client.example/cb?code=one" })).toBe(
      true,
    );
    expect(
      consentIssuedCode({
        redirect: true,
        url: "https://client.example/cb?code=one&error=invalid_scope",
      }),
    ).toBe(false);
  });
  it("binds an exact consent generation to session and client without revealing the session", () => {
    const base = { secret: "secret", sessionId: "private-session", clientId: "client" };
    const reference = deriveMcpConsentReferenceId(base);
    expect(reference).toMatch(/^[a-f0-9]{64}$/);
    expect(deriveMcpConsentReferenceId({ ...base, clientId: "other" })).not.toBe(reference);
  });
  it("never creates a missing grant while exchanging or refreshing", async () => {
    active.mockResolvedValue(null);
    await expect(
      issueMcpGrantClaims({
        grantType: "refresh_token",
        userId: "user",
        clientId: "client",
        referenceId: "reference",
        secret: "secret",
      }),
    ).rejects.toThrow();
    active.mockResolvedValue("grant");
    await expect(
      issueMcpGrantClaims({
        grantType: "authorization_code",
        userId: "user",
        clientId: "client",
        referenceId: "reference",
        secret: "secret",
      }),
    ).resolves.toEqual({ wssp_grant_id: "grant" });
    await expect(
      issueMcpGrantClaims({
        grantType: "refresh_token",
        userId: "user",
        clientId: "client",
        sessionId: "session",
        secret: "secret",
      }),
    ).rejects.toThrow();
  });
});

it("sanitizes grant storage failures before they reach the provider logger", async () => {
  active.mockRejectedValue(new Error("private query client_id secret"));
  await expect(
    issueMcpGrantClaims({
      grantType: "refresh_token",
      userId: "user",
      clientId: "client",
      referenceId: "reference",
      secret: "secret",
    }),
  ).rejects.toThrow("MCP grant lookup unavailable");
});
