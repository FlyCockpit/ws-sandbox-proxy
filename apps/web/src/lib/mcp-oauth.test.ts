import { expect, it } from "vitest";
import { oauthRedirect, parseMcpRequest } from "./mcp-oauth";

it("accepts signed service scopes and rejects unknown scopes or unsigned requests", () => {
  expect(
    parseMcpRequest({
      client_id: "c",
      sig: "s",
      scope: "hosts:read sandboxes:create offline_access",
    }),
  ).toMatchObject({ usable: true, serviceScopes: ["hosts:read", "sandboxes:create"] });
  expect(parseMcpRequest({ client_id: "c", sig: "s", scope: "arbitrary:admin" }).usable).toBe(
    false,
  );
  expect(parseMcpRequest({ client_id: "c", scope: "hosts:read" }).usable).toBe(false);
});
it("navigates only for a server-issued redirect response with an HTTP URL", () => {
  expect(oauthRedirect({ redirect: true, url: "https://client.example/cb?code=one" })).toBe(
    "https://client.example/cb?code=one",
  );
  expect(oauthRedirect({ redirect: false, url: "https://client.example" })).toBeNull();
  expect(oauthRedirect({ redirect: true, url: "javascript:alert(1)" })).toBeNull();
  expect(oauthRedirect({ url: "https://client.example" })).toBeNull();
});
