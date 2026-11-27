import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SERVER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("@better-auth/oauth-provider bundle parity", () => {
  it("declares @better-auth/oauth-provider as a direct server dependency sharing one module instance with @wssp/auth", () => {
    const pkg = JSON.parse(readFileSync(join(SERVER_DIR, "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
    };
    expect(pkg.dependencies?.["@better-auth/oauth-provider"]).toBeTruthy();

    const serverRequire = createRequire(import.meta.url);
    const authRequire = createRequire(serverRequire.resolve("@wssp/auth"));
    expect(serverRequire.resolve("@better-auth/oauth-provider")).toBe(
      authRequire.resolve("@better-auth/oauth-provider"),
    );
    expect(serverRequire.resolve("@better-auth/oauth-provider/internal")).toBe(
      authRequire.resolve("@better-auth/oauth-provider/internal"),
    );
    expect(serverRequire.resolve("@better-auth/mcp")).toBe(authRequire.resolve("@better-auth/mcp"));
  });
});
