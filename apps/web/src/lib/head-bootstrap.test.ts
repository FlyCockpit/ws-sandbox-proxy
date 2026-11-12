import { THEME_INIT_SCRIPT } from "@wssp/config/theme-init";
import { describe, expect, it } from "vitest";

describe("head bootstrap", () => {
  it("turns zod jitless on before any zod module loads, so its eval probe never trips the CSP", async () => {
    // Run exactly what the document <head> runs (CSP-hashed inline script).
    new Function(THEME_INIT_SCRIPT)();
    const { z } = await import("zod");
    expect(z.config().jitless).toBe(true);
  });
});
