import { describe, expect, it, vi } from "vitest";
import { createWsspClient } from "./client";
import { isWsspError } from "./errors";
import { createSandboxBody } from "./sandboxes";
import type { FetchLike } from "./transport";

const base = { template: "revision/tpl_1", sandboxHostId: "host_1" } as const;

describe("allowInternetAccess (default-open egress)", () => {
  it("omitted sends egress unchanged; omitting both requests open internet", () => {
    expect(createSandboxBody(base)).toEqual(base);
    expect("egress" in createSandboxBody(base)).toBe(false);
    // Grants without a mode stay an allowlist (the server's fail-safe inference).
    expect(createSandboxBody({ ...base, egress: { domains: ["example.com"] } })).toEqual({
      ...base,
      egress: { domains: ["example.com"] },
    });
  });

  it("true is open; grants ride along as fallback grants", () => {
    expect(createSandboxBody({ ...base, allowInternetAccess: true })).toEqual({
      ...base,
      egress: { mode: "open" },
    });
    expect(
      createSandboxBody({
        ...base,
        allowInternetAccess: true,
        egress: { domains: ["registry.npmjs.org"] },
      }),
    ).toEqual({ ...base, egress: { mode: "open", domains: ["registry.npmjs.org"] } });
  });

  it("false is an allowlist of the given grants (none is deny-all)", () => {
    expect(createSandboxBody({ ...base, allowInternetAccess: false })).toEqual({
      ...base,
      egress: { mode: "allowlist" },
    });
    expect(
      createSandboxBody({
        ...base,
        allowInternetAccess: false,
        egress: { domains: ["example.com"], cidrs: ["8.8.8.8/32"] },
      }),
    ).toEqual({
      ...base,
      egress: { mode: "allowlist", domains: ["example.com"], cidrs: ["8.8.8.8/32"] },
    });
  });

  it("a matching explicit mode is accepted", () => {
    expect(
      createSandboxBody({ ...base, allowInternetAccess: false, egress: { mode: "allowlist" } }),
    ).toEqual({ ...base, egress: { mode: "allowlist" } });
  });

  it.each([
    [false, "open"],
    [true, "allowlist"],
  ] as const)(
    "allowInternetAccess %s with egress.mode %s is refused locally before any network IO",
    async (allow, mode) => {
      const fetch = vi.fn<FetchLike>(async () => {
        throw new Error("no request may be sent");
      });
      const client = createWsspClient({
        baseUrl: "https://api.example.test",
        apiKey: "wssp_sdk_test",
        fetch,
      });
      const error = await client.sandboxes
        .create({ ...base, allowInternetAccess: allow, egress: { mode } })
        .then(
          () => null,
          (caught: unknown) => caught,
        );
      expect(isWsspError(error) && error.kind).toBe("invalid_request");
      expect(fetch).not.toHaveBeenCalled();
    },
  );
});
